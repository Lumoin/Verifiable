using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The vendor-internal wire encoding <c>TPM2_ContextSave()</c> and <c>TPM2_ContextLoad()</c> use to reconstruct
/// a <see cref="TpmContextResource"/>'s full state inside a saved context blob (TPM 2.0 Library Part 1, clause
/// 27.2.1: "The encrypted data blob contains the data necessary to reconstruct the full object or session
/// context in the TPM. ... The internal structure TPMS_CONTEXT_DATA of the actual context is vendor
/// specific."). One write/read pair exists per <see cref="TpmContextResourceKind"/>; each writes and reads its
/// resource's fields in exactly the order the record declares them, omitting the <c>Handle</c> field — the
/// metadata (<see cref="Structures.TpmsContext.SavedHandle"/>) already carries the handle, and the load side
/// re-stamps it: the saved handle itself for a session, a freshly drawn handle for an object or sequence.
/// </summary>
/// <remarks>
/// <para>
/// Every octet a sensitive carrier (a private key, a session key) contributes is meant to land only in the
/// rental <see cref="SerializeAsync"/> returns, which the caller encrypts in place under the context protection
/// key and clears once the ciphertext has been produced — this class never encrypts, decrypts, or clears the
/// rental it returns. The one unavoidable exception is the sensitive carriers' own accessor: <c>PrivateKeyMemory</c>
/// and <c>SymmetricKeyMemory</c> expose their octets only through an async delegate
/// (<c>WithKeyBytesAsync</c>), which cannot be invoked while a <see cref="TpmWriter"/> — a <see langword="ref"/>
/// <see langword="struct"/> that cannot survive an <see langword="await"/> — is live; the octets are therefore
/// copied once into a short-lived scratch rental ahead of the writer pass, and that scratch is cleared and
/// released before the write returns, so no second copy of the key material survives the call.
/// </para>
/// <para>
/// Every <c>TPM2B</c>-shaped field is <c>UINT16 length ‖ octets</c>, written through the field's own
/// <c>WriteTo</c> and rebuilt through its own <c>Create(ReadOnlySpan&lt;byte&gt;, BaseMemoryPool)</c> — the
/// Empty sentinel for a zero-length run. <see cref="Tpm2bPublic"/> instead rides its own <c>WriteTo</c>/
/// <c>Parse(ref TpmReader, BaseMemoryPool)</c> pair, since its interior is itself a parseable <c>TPMT_PUBLIC</c>
/// rather than opaque octets. A private or session key is framed the same <c>UINT16 length ‖ octets</c> way and
/// rebuilt over a fresh rental through the carrier's raw constructor, tagged from the already-read
/// <c>KeyType</c>/<c>Curve</c> for a private key (<see cref="TpmSimulator.EccPrivateKeyTag"/>/
/// <see cref="TpmSimulator.RsaPrivateKeyTag"/>, the RSA modulus width carried as its own <c>UINT16</c> just
/// before the octets, because the backend's private-key encoding is not the modulus width) or the fixed
/// session-key tag for a session key, with the Empty sentinel for a zero-length run. A writer that fails part
/// way clears the partially written rental before releasing it.
/// <see cref="SessionBoundEntity"/> rides the same framing, rebuilt through
/// <see cref="SessionBoundEntity.FromMarshaled"/> (<see cref="SessionBoundEntity.Unbound"/> for a zero-length
/// run). <see cref="TpmtSymDef"/> rides its own <c>WriteTo</c>/<c>Parse</c>. Every <c>TPMI_*</c> selector and
/// small enum writes at its fixed width — <c>UINT16</c> for a <c>TPMI_ALG_*</c> selector or
/// <see cref="TpmiEccCurve"/>, <c>UINT32</c> for a hierarchy handle or <see cref="TpmaObject"/>, one octet for a
/// small model-only enum (<see cref="TpmSequenceKind"/>, <see cref="TpmSequenceFirstBlock"/>,
/// <see cref="TpmPolicyCpHashKind"/>) — and a nullable field (a signing or KDF scheme's optional presence, or a
/// policy session's latched command code) as one presence octet then the value. The exported public point rides
/// the same <c>UINT16 length ‖ octets</c> run as a private or session key — the raw SEC1 concatenation, not the
/// two-<c>TPM2B</c> <c>TPMS_ECC_POINT</c> shape <see cref="Structures.Tpm2bEccPoint"/> frames — rebuilt over a
/// fresh rental tagged from the already-read <c>Curve</c>
/// (<see cref="TpmCryptographicProjections.ToExchangePublicKeyTag"/>), with the Empty sentinel for a zero-length
/// (RSA) run; a sequence's retained segments ride a <c>UINT32</c> count then each segment's own framing; every
/// <see langword="bool"/> is one octet; every <see langword="ulong"/>/<see langword="uint"/> is big-endian.
/// </para>
/// </remarks>
internal static class TpmContextSerializer
{
    /// <summary>
    /// Serializes <paramref name="resource"/>'s wrapped record into a freshly rented buffer, dispatching on its
    /// <see cref="TpmContextResource.Kind"/>.
    /// </summary>
    /// <param name="resource">The resource to serialize; read only, never disposed here.</param>
    /// <param name="pool">The memory pool every rental is drawn from.</param>
    /// <param name="cancellationToken">The token each asynchronous writer checks before it copies any key material.</param>
    /// <returns>The written rental and the number of valid leading octets it holds; ownership transfers to the caller.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="resource"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static ValueTask<(IMemoryOwner<byte> Owner, int Length)> SerializeAsync(TpmContextResource resource, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(pool);

        return resource switch
        {
            TpmContextTransientKey transientKey => SerializeTransientKeyAsync(transientKey.Key, pool, cancellationToken),
            TpmContextKeyedHashObject keyedHash => new ValueTask<(IMemoryOwner<byte> Owner, int Length)>(SerializeKeyedHashObject(keyedHash.Object, pool)),
            TpmContextSequenceObject sequence => new ValueTask<(IMemoryOwner<byte> Owner, int Length)>(SerializeSequenceObject(sequence.Sequence, pool)),
            TpmContextHmacSession hmacSession => SerializeHmacSessionAsync(hmacSession.Session, pool, cancellationToken),
            TpmContextPolicySession policySession => SerializePolicySessionAsync(policySession.Session, pool, cancellationToken),
            _ => throw new InvalidOperationException($"No serialization is defined for context resource kind '{resource.Kind}'.")
        };
    }

    /// <summary>
    /// Rebuilds a <see cref="TpmContextResource"/> from the octets a decrypted, integrity-verified context blob
    /// carried, dispatching on the leading kind octet <see cref="SerializeAsync"/> wrote.
    /// </summary>
    /// <param name="octets">The decrypted resource octets, kind octet first.</param>
    /// <param name="handle">The saved-context handle to stamp on the rebuilt record: the saved handle itself for a session, a placeholder an object's or sequence's install feedback restamps.</param>
    /// <param name="pool">The memory pool every rebuilt carrier's storage is rented from.</param>
    /// <returns>The rebuilt resource; the caller owns it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="octets"/> is empty, or its leading octet names no known <see cref="TpmContextResourceKind"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the record each ReadXxx call builds transfers immediately to the TpmContextResource envelope wrapping it, which the caller owns from this method's return until an installing transition adopts the wrapped record or a refusal disposes the envelope; the analyzer cannot see the transfer through the envelope's positional construction.")]
    public static TpmContextResource Deserialize(ReadOnlySpan<byte> octets, TpmiDhContext handle, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(octets.IsEmpty)
        {
            throw new InvalidOperationException("A serialized context resource cannot be empty.");
        }

        var reader = new TpmReader(octets);
        var kind = (TpmContextResourceKind)reader.ReadByte();

        return kind switch
        {
            TpmContextResourceKind.TransientKey => new TpmContextTransientKey(ReadTransientKey(ref reader, handle, pool)),
            TpmContextResourceKind.KeyedHashObject => new TpmContextKeyedHashObject(ReadKeyedHashObject(ref reader, handle, pool)),
            TpmContextResourceKind.SequenceObject => new TpmContextSequenceObject(ReadSequenceObject(ref reader, handle, pool)),
            TpmContextResourceKind.HmacSession => new TpmContextHmacSession(ReadHmacSession(ref reader, handle, pool)),
            TpmContextResourceKind.PolicySession => new TpmContextPolicySession(ReadPolicySession(ref reader, handle, pool)),
            _ => throw new InvalidOperationException($"Unknown context resource kind octet '{(byte)kind}'.")
        };
    }

    /// <summary>Writes a <see cref="TransientKeyState"/> and reports its serialized size.</summary>
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> SerializeTransientKeyAsync(TransientKeyState state, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using TpmContextOctets privateKeyOctets = await ExtractPrivateKeyOctetsAsync(state.PrivateKey, pool).ConfigureAwait(false);

        //The RSA private key rides in the backend's own encoding (a PKCS#1 RSAPrivateKey DER), whose octet
        //length is not the modulus width, so the width the private-key tag needs is written beside the octets,
        //read from the public area's modulus; an ECC key's tag comes from its curve and writes zero here.
        ushort privateKeyBits = state.KeyType.Value == TpmAlgIdConstants.TPM_ALG_RSA
            ? (ushort)(state.PublicArea.PublicArea.Unique.GetRsaModulusMemory().Length * 8)
            : (ushort)0;

        int size = sizeof(byte)
            + sizeof(uint) //Hierarchy
            + sizeof(ushort) //KeyType
            + sizeof(ushort) //Curve
            + OptionalSize(state.SigningScheme.HasValue, sizeof(ushort))
            + OptionalSize(state.SigningSchemeHashAlg.HasValue, sizeof(ushort))
            + OptionalSize(state.KemKdfScheme.HasValue, sizeof(ushort))
            + OptionalSize(state.KemKdfHashAlg.HasValue, sizeof(ushort))
            + sizeof(ushort) //PrivateKey width in bits
            + sizeof(ushort) + privateKeyOctets.Length
            + state.Name.SerializedSize
            + sizeof(uint) //Attributes
            + sizeof(ushort) + state.PublicPoint.Length
            + state.PublicModulus.SerializedSize
            + state.AuthPolicy.SerializedSize
            + state.AuthValue.SerializedSize
            + state.SeedValue.SerializedSize
            + state.PublicArea.GetSerializedSize()
            + state.QualifiedName.SerializedSize;

        IMemoryOwner<byte> owner = pool.Rent(size, AllocationKind.Pinned);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..size]);
            writer.WriteByte((byte)TpmContextResourceKind.TransientKey);
            state.Hierarchy.WriteTo(ref writer);
            state.KeyType.WriteTo(ref writer);
            state.Curve.WriteTo(ref writer);
            WriteOptionalAlgSigScheme(ref writer, state.SigningScheme);
            WriteOptionalAlgHash(ref writer, state.SigningSchemeHashAlg);
            WriteOptionalAlgKdf(ref writer, state.KemKdfScheme);
            WriteOptionalAlgHash(ref writer, state.KemKdfHashAlg);
            writer.WriteUInt16(privateKeyBits);
            writer.WriteTpm2b(privateKeyOctets.Span);
            state.Name.WriteTo(ref writer);
            writer.WriteUInt32((uint)state.Attributes);
            writer.WriteTpm2b(state.PublicPoint.AsReadOnlySpan());
            state.PublicModulus.WriteTo(ref writer);
            state.AuthPolicy.WriteTo(ref writer);
            state.AuthValue.WriteTo(ref writer);
            state.SeedValue.WriteTo(ref writer);
            state.PublicArea.WriteTo(ref writer);
            state.QualifiedName.WriteTo(ref writer);

            return (owner, size);
        }
        catch
        {
            owner.Memory.Span[..size].Clear();
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Rebuilds a <see cref="TransientKeyState"/> from its serialized fields. Every pooled carrier is rented in
    /// wire order under a nested dispose-on-throw ladder — the <see cref="Structures.TpmsContext"/>/
    /// <c>TpmsCreationData.Parse</c> shape — so a later field's refusal disposes every earlier one before the
    /// exception leaves this method.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every rented carrier this method builds transfers to the returned TransientKeyState, which the installing ContextLoad transition adopts and a refusing load feedback disposes; the analyzer cannot see the transfer through the record's positional construction, and the nested dispose-on-throw ladder releases every already-built carrier if a later field's parse fails.")]
    private static TransientKeyState ReadTransientKey(ref TpmReader reader, TpmiDhContext handle, BaseMemoryPool pool)
    {
        TpmiRhHierarchy hierarchy = TpmiRhHierarchy.FromValue(reader.ReadUInt32());
        TpmiAlgPublic keyType = TpmiAlgPublic.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        TpmiEccCurve curve = TpmiEccCurve.FromValue((TpmEccCurveConstants)reader.ReadUInt16());
        TpmiAlgSigScheme? signingScheme = ReadOptionalAlgSigScheme(ref reader);
        TpmiAlgHash? signingSchemeHashAlg = ReadOptionalAlgHash(ref reader);
        TpmiAlgKdf? kemKdfScheme = ReadOptionalAlgKdf(ref reader);
        TpmiAlgHash? kemKdfHashAlg = ReadOptionalAlgHash(ref reader);

        ushort privateKeyBits = reader.ReadUInt16();
        PrivateKeyMemory privateKey = ReadPrivateKey(ref reader, keyType, curve, privateKeyBits, pool);
        try
        {
            Tpm2bName name = Tpm2bName.Create(reader.ReadTpm2b(), pool);
            try
            {
                var attributes = (TpmaObject)reader.ReadUInt32();
                EncodedEcPoint publicPoint = ReadPublicPoint(ref reader, curve, pool);
                try
                {
                    Tpm2bPublicKeyRsa publicModulus = Tpm2bPublicKeyRsa.Create(reader.ReadTpm2b(), pool);
                    try
                    {
                        Tpm2bDigest authPolicy = Tpm2bDigest.Create(reader.ReadTpm2b(), pool);
                        try
                        {
                            Tpm2bAuth authValue = Tpm2bAuth.Create(reader.ReadTpm2b(), pool);
                            try
                            {
                                Tpm2bDigest seedValue = Tpm2bDigest.Create(reader.ReadTpm2b(), pool);
                                try
                                {
                                    Tpm2bPublic publicArea = Tpm2bPublic.Parse(ref reader, pool);
                                    try
                                    {
                                        Tpm2bName qualifiedName = Tpm2bName.Create(reader.ReadTpm2b(), pool);

                                        return new TransientKeyState(
                                            TpmiDhObject.FromValue(handle.Value), hierarchy, keyType, curve, signingScheme, signingSchemeHashAlg, kemKdfScheme, kemKdfHashAlg,
                                            privateKey, name, attributes, publicPoint, publicModulus, authPolicy, authValue, seedValue, publicArea, qualifiedName);
                                    }
                                    catch
                                    {
                                        publicArea.Dispose();
                                        throw;
                                    }
                                }
                                catch
                                {
                                    seedValue.Dispose();
                                    throw;
                                }
                            }
                            catch
                            {
                                authValue.Dispose();
                                throw;
                            }
                        }
                        catch
                        {
                            authPolicy.Dispose();
                            throw;
                        }
                    }
                    catch
                    {
                        publicModulus.Dispose();
                        throw;
                    }
                }
                catch
                {
                    publicPoint.Dispose();
                    throw;
                }
            }
            catch
            {
                name.Dispose();
                throw;
            }
        }
        catch
        {
            privateKey.Dispose();
            throw;
        }
    }

    /// <summary>Writes a <see cref="KeyedHashObjectState"/> and reports its serialized size; no sensitive-carrier accessor needs an <see langword="await"/>, so this runs synchronously.</summary>
    private static (IMemoryOwner<byte> Owner, int Length) SerializeKeyedHashObject(KeyedHashObjectState state, BaseMemoryPool pool)
    {
        int size = sizeof(byte)
            + sizeof(uint) //Hierarchy
            + state.Name.SerializedSize
            + state.Data.SerializedSize
            + state.AuthPolicy.SerializedSize
            + state.UserAuth.SerializedSize
            + sizeof(byte) //NoDa
            + sizeof(byte) //UserWithAuth
            + sizeof(byte) //IsDuplicable
            + state.SeedValue.SerializedSize
            + state.PublicArea.GetSerializedSize()
            + state.QualifiedName.SerializedSize
            + sizeof(byte); //IsPublicOnly

        IMemoryOwner<byte> owner = pool.Rent(size, AllocationKind.Pinned);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..size]);
            writer.WriteByte((byte)TpmContextResourceKind.KeyedHashObject);
            state.Hierarchy.WriteTo(ref writer);
            state.Name.WriteTo(ref writer);
            state.Data.WriteTo(ref writer);
            state.AuthPolicy.WriteTo(ref writer);
            state.UserAuth.WriteTo(ref writer);
            WriteBool(ref writer, state.NoDa);
            WriteBool(ref writer, state.UserWithAuth);
            WriteBool(ref writer, state.IsDuplicable);
            state.SeedValue.WriteTo(ref writer);
            state.PublicArea.WriteTo(ref writer);
            state.QualifiedName.WriteTo(ref writer);
            WriteBool(ref writer, state.IsPublicOnly);

            return (owner, size);
        }
        catch
        {
            owner.Memory.Span[..size].Clear();
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Rebuilds a <see cref="KeyedHashObjectState"/> from its serialized fields, under the same nested
    /// dispose-on-throw ladder <see cref="ReadTransientKey"/> uses.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every rented carrier this method builds transfers to the returned KeyedHashObjectState, which the installing ContextLoad transition adopts and a refusing load feedback disposes; the analyzer cannot see the transfer through the record's positional construction, and the nested dispose-on-throw ladder releases every already-built carrier if a later field's parse fails.")]
    private static KeyedHashObjectState ReadKeyedHashObject(ref TpmReader reader, TpmiDhContext handle, BaseMemoryPool pool)
    {
        TpmiRhHierarchy hierarchy = TpmiRhHierarchy.FromValue(reader.ReadUInt32());

        Tpm2bName name = Tpm2bName.Create(reader.ReadTpm2b(), pool);
        try
        {
            Tpm2bSensitiveData data = Tpm2bSensitiveData.Create(reader.ReadTpm2b(), pool);
            try
            {
                Tpm2bDigest authPolicy = Tpm2bDigest.Create(reader.ReadTpm2b(), pool);
                try
                {
                    Tpm2bAuth userAuth = Tpm2bAuth.Create(reader.ReadTpm2b(), pool);
                    try
                    {
                        bool noDa = ReadBool(ref reader);
                        bool userWithAuth = ReadBool(ref reader);
                        bool isDuplicable = ReadBool(ref reader);
                        Tpm2bDigest seedValue = Tpm2bDigest.Create(reader.ReadTpm2b(), pool);
                        try
                        {
                            Tpm2bPublic publicArea = Tpm2bPublic.Parse(ref reader, pool);
                            try
                            {
                                Tpm2bName qualifiedName = Tpm2bName.Create(reader.ReadTpm2b(), pool);
                                try
                                {
                                    bool isPublicOnly = ReadBool(ref reader);

                                    return new KeyedHashObjectState(
                                        TpmiDhObject.FromValue(handle.Value), hierarchy, name, data, authPolicy, userAuth, noDa, userWithAuth, isDuplicable,
                                        seedValue, publicArea, qualifiedName, isPublicOnly);
                                }
                                catch
                                {
                                    qualifiedName.Dispose();
                                    throw;
                                }
                            }
                            catch
                            {
                                publicArea.Dispose();
                                throw;
                            }
                        }
                        catch
                        {
                            seedValue.Dispose();
                            throw;
                        }
                    }
                    catch
                    {
                        userAuth.Dispose();
                        throw;
                    }
                }
                catch
                {
                    authPolicy.Dispose();
                    throw;
                }
            }
            catch
            {
                data.Dispose();
                throw;
            }
        }
        catch
        {
            name.Dispose();
            throw;
        }
    }

    /// <summary>Writes a <see cref="SequenceObjectState"/> and reports its serialized size; no sensitive-carrier accessor needs an <see langword="await"/>, so this runs synchronously.</summary>
    private static (IMemoryOwner<byte> Owner, int Length) SerializeSequenceObject(SequenceObjectState state, BaseMemoryPool pool)
    {
        int segmentsSize = 0;
        foreach(Tpm2bMaxBuffer segment in state.Segments)
        {
            segmentsSize += segment.SerializedSize;
        }

        int size = sizeof(byte)
            + sizeof(byte) //Kind
            + state.StartingKeyName.SerializedSize
            + sizeof(ushort) //Scheme
            + sizeof(ushort) //HashAlg
            + state.AuthValue.SerializedSize
            + sizeof(uint) + segmentsSize //Segments: count + each buffer's own framing
            + sizeof(byte) //FirstBlock
            + state.HmacKey.SerializedSize;

        IMemoryOwner<byte> owner = pool.Rent(size, AllocationKind.Pinned);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..size]);
            writer.WriteByte((byte)TpmContextResourceKind.SequenceObject);
            writer.WriteByte((byte)state.Kind);
            state.StartingKeyName.WriteTo(ref writer);
            state.Scheme.WriteTo(ref writer);
            state.HashAlg.WriteTo(ref writer);
            state.AuthValue.WriteTo(ref writer);
            writer.WriteUInt32((uint)state.Segments.Count);
            foreach(Tpm2bMaxBuffer segment in state.Segments)
            {
                segment.WriteTo(ref writer);
            }

            writer.WriteByte((byte)state.FirstBlock);
            state.HmacKey.WriteTo(ref writer);

            return (owner, size);
        }
        catch
        {
            owner.Memory.Span[..size].Clear();
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Rebuilds a <see cref="SequenceObjectState"/> from its serialized fields, under the same nested
    /// dispose-on-throw ladder <see cref="ReadTransientKey"/> uses; the segment list additionally disposes every
    /// already-rented buffer it holds if a later field's parse fails.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every rented carrier this method builds transfers to the returned SequenceObjectState, which the installing ContextLoad transition adopts and a refusing load feedback disposes; the analyzer cannot see the transfer through the record's positional construction, and the nested dispose-on-throw ladder releases every already-built carrier if a later field's parse fails.")]
    private static SequenceObjectState ReadSequenceObject(ref TpmReader reader, TpmiDhContext handle, BaseMemoryPool pool)
    {
        var kind = (TpmSequenceKind)reader.ReadByte();

        Tpm2bName startingKeyName = Tpm2bName.Create(reader.ReadTpm2b(), pool);
        try
        {
            TpmiAlgSigScheme scheme = TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
            TpmiAlgHash hashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

            Tpm2bAuth authValue = Tpm2bAuth.Create(reader.ReadTpm2b(), pool);
            try
            {
                uint segmentCount = reader.ReadUInt32();
                reader.EnsureCount(segmentCount, minBytesPerElement: sizeof(ushort));
                ImmutableList<Tpm2bMaxBuffer>.Builder segments = ImmutableList.CreateBuilder<Tpm2bMaxBuffer>();
                try
                {
                    for(uint i = 0; i < segmentCount; i++)
                    {
                        segments.Add(Tpm2bMaxBuffer.Create(reader.ReadTpm2b(), pool));
                    }

                    var firstBlock = (TpmSequenceFirstBlock)reader.ReadByte();
                    Tpm2bSensitiveData hmacKey = Tpm2bSensitiveData.Create(reader.ReadTpm2b(), pool);

                    return new SequenceObjectState(TpmiDhObject.FromValue(handle.Value), kind, startingKeyName, scheme, hashAlg, authValue, segments.ToImmutable(), firstBlock, hmacKey);
                }
                catch
                {
                    foreach(Tpm2bMaxBuffer segment in segments)
                    {
                        segment.Dispose();
                    }

                    throw;
                }
            }
            catch
            {
                authValue.Dispose();
                throw;
            }
        }
        catch
        {
            startingKeyName.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Writes an <see cref="HmacSessionState"/> and reports its serialized size, including its audit status and
    /// audit digest (<see cref="HmacSessionState.IsAudit"/>, <see cref="HmacSessionState.AuditDigest"/>) — a
    /// saved-then-loaded audit session keeps its digest, its audit status and its lost bind (TPM 2.0 Library
    /// Part 1, clause 27.5).
    /// </summary>
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> SerializeHmacSessionAsync(HmacSessionState state, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using TpmContextOctets sessionKeyOctets = await ExtractSymmetricKeyOctetsAsync(state.SessionKey, pool).ConfigureAwait(false);
        ReadOnlySpan<byte> boundEntity = state.BoundEntity.AsReadOnlySpan();

        int size = sizeof(byte)
            + sizeof(ushort) //SessionAlg
            + state.Symmetric.SerializedSize
            + sizeof(ushort) + sessionKeyOctets.Length
            + state.NonceTpm.SerializedSize
            + sizeof(ushort) + boundEntity.Length
            + sizeof(byte) //IsBoundEntityDaProtected
            + sizeof(byte) //IsBoundToLockout
            + sizeof(byte) //IsAudit
            + state.AuditDigest.SerializedSize;

        IMemoryOwner<byte> owner = pool.Rent(size, AllocationKind.Pinned);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..size]);
            writer.WriteByte((byte)TpmContextResourceKind.HmacSession);
            state.SessionAlg.WriteTo(ref writer);
            state.Symmetric.WriteTo(ref writer);
            writer.WriteTpm2b(sessionKeyOctets.Span);
            state.NonceTpm.WriteTo(ref writer);
            writer.WriteTpm2b(boundEntity);
            WriteBool(ref writer, state.IsBoundEntityDaProtected);
            WriteBool(ref writer, state.IsBoundToLockout);
            WriteBool(ref writer, state.IsAudit);
            state.AuditDigest.WriteTo(ref writer);

            return (owner, size);
        }
        catch
        {
            owner.Memory.Span[..size].Clear();
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Rebuilds an <see cref="HmacSessionState"/> from its serialized fields, under the same nested
    /// dispose-on-throw ladder <see cref="ReadTransientKey"/> uses.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every rented carrier this method builds transfers to the returned HmacSessionState, which the installing ContextLoad transition reinstalls at the saved handle and a refusing load feedback disposes; the analyzer cannot see the transfer through the record's positional construction, and the nested dispose-on-throw ladder releases every already-built carrier if a later field's parse fails.")]
    private static HmacSessionState ReadHmacSession(ref TpmReader reader, TpmiDhContext handle, BaseMemoryPool pool)
    {
        TpmiAlgHash sessionAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        TpmtSymDef symmetric = TpmtSymDef.Parse(ref reader);

        SymmetricKeyMemory sessionKey = ReadSessionKey(ref reader, pool);
        try
        {
            Tpm2bNonce nonceTpm = Tpm2bNonce.Create(reader.ReadTpm2b(), pool);
            try
            {
                SessionBoundEntity boundEntity = SessionBoundEntity.FromMarshaled(reader.ReadTpm2b(), pool);
                try
                {
                    bool isBoundEntityDaProtected = ReadBool(ref reader);
                    bool isBoundToLockout = ReadBool(ref reader);
                    bool isAudit = ReadBool(ref reader);
                    Tpm2bDigest auditDigest = Tpm2bDigest.Parse(ref reader, pool);
                    try
                    {
                        return new HmacSessionState(TpmiShHmac.FromValue(handle.Value), sessionAlg, symmetric, sessionKey, nonceTpm, boundEntity, auditDigest, isBoundEntityDaProtected, isBoundToLockout, isAudit);
                    }
                    catch
                    {
                        auditDigest.Dispose();
                        throw;
                    }
                }
                catch
                {
                    boundEntity.Dispose();
                    throw;
                }
            }
            catch
            {
                nonceTpm.Dispose();
                throw;
            }
        }
        catch
        {
            sessionKey.Dispose();
            throw;
        }
    }

    /// <summary>Writes a <see cref="PolicySessionState"/> and reports its serialized size.</summary>
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> SerializePolicySessionAsync(PolicySessionState state, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using TpmContextOctets sessionKeyOctets = await ExtractSymmetricKeyOctetsAsync(state.SessionKey, pool).ConfigureAwait(false);

        int size = sizeof(byte)
            + sizeof(ushort) //PolicyHash
            + sizeof(byte) //IsTrial
            + state.PolicyDigest.SerializedSize
            + state.NonceTpm.SerializedSize
            + state.CpHash.SerializedSize
            + sizeof(ulong) //StartTime
            + sizeof(ushort) + sessionKeyOctets.Length
            + state.Symmetric.SerializedSize
            + sizeof(ulong) //Timeout
            + sizeof(byte) //IsAuthValueNeeded
            + sizeof(byte) //IsPasswordNeeded
            + OptionalSize(state.CommandCode.HasValue, sizeof(uint))
            + sizeof(byte) //IsBoundEntityDaProtected
            + sizeof(byte) //IsBoundToLockout
            + sizeof(byte) //CpHashKind
            + sizeof(byte) //CommandLocality
            + sizeof(byte) //IsNvWrittenChecked
            + sizeof(byte); //IsNvWrittenRequired

        IMemoryOwner<byte> owner = pool.Rent(size, AllocationKind.Pinned);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..size]);
            writer.WriteByte((byte)TpmContextResourceKind.PolicySession);
            state.PolicyHash.WriteTo(ref writer);
            WriteBool(ref writer, state.IsTrial);
            state.PolicyDigest.WriteTo(ref writer);
            state.NonceTpm.WriteTo(ref writer);
            state.CpHash.WriteTo(ref writer);
            writer.WriteUInt64(state.StartTime);
            writer.WriteTpm2b(sessionKeyOctets.Span);
            state.Symmetric.WriteTo(ref writer);
            writer.WriteUInt64(state.Timeout);
            WriteBool(ref writer, state.IsAuthValueNeeded);
            WriteBool(ref writer, state.IsPasswordNeeded);
            WriteOptionalCommandCode(ref writer, state.CommandCode);
            WriteBool(ref writer, state.IsBoundEntityDaProtected);
            WriteBool(ref writer, state.IsBoundToLockout);
            writer.WriteByte((byte)state.CpHashKind);
            writer.WriteByte(state.CommandLocality);
            WriteBool(ref writer, state.IsNvWrittenChecked);
            WriteBool(ref writer, state.IsNvWrittenRequired);

            return (owner, size);
        }
        catch
        {
            owner.Memory.Span[..size].Clear();
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Rebuilds a <see cref="PolicySessionState"/> from its serialized fields, under the same nested
    /// dispose-on-throw ladder <see cref="ReadTransientKey"/> uses.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every rented carrier this method builds transfers to the returned PolicySessionState, which the installing ContextLoad transition reinstalls at the saved handle and a refusing load feedback disposes; the analyzer cannot see the transfer through the record's positional construction, and the nested dispose-on-throw ladder releases every already-built carrier if a later field's parse fails.")]
    private static PolicySessionState ReadPolicySession(ref TpmReader reader, TpmiDhContext handle, BaseMemoryPool pool)
    {
        TpmiAlgHash policyHash = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        bool isTrial = ReadBool(ref reader);

        Tpm2bDigest policyDigest = Tpm2bDigest.Create(reader.ReadTpm2b(), pool);
        try
        {
            Tpm2bNonce nonceTpm = Tpm2bNonce.Create(reader.ReadTpm2b(), pool);
            try
            {
                Tpm2bDigest cpHash = Tpm2bDigest.Create(reader.ReadTpm2b(), pool);
                try
                {
                    ulong startTime = reader.ReadUInt64();

                    SymmetricKeyMemory sessionKey = ReadSessionKey(ref reader, pool);
                    try
                    {
                        TpmtSymDef symmetric = TpmtSymDef.Parse(ref reader);
                        ulong timeout = reader.ReadUInt64();
                        bool isAuthValueNeeded = ReadBool(ref reader);
                        bool isPasswordNeeded = ReadBool(ref reader);
                        TpmCcConstants? commandCode = ReadOptionalCommandCode(ref reader);
                        bool isBoundEntityDaProtected = ReadBool(ref reader);
                        bool isBoundToLockout = ReadBool(ref reader);
                        var cpHashKind = (TpmPolicyCpHashKind)reader.ReadByte();
                        byte commandLocality = reader.ReadByte();
                        bool isNvWrittenChecked = ReadBool(ref reader);
                        bool isNvWrittenRequired = ReadBool(ref reader);

                        return new PolicySessionState(
                            TpmiShPolicy.FromValue(handle.Value), policyHash, isTrial, policyDigest, nonceTpm, cpHash, startTime, sessionKey, symmetric,
                            timeout, isAuthValueNeeded, isPasswordNeeded, commandCode, isBoundEntityDaProtected, isBoundToLockout,
                            cpHashKind, commandLocality, isNvWrittenChecked, isNvWrittenRequired);
                    }
                    catch
                    {
                        sessionKey.Dispose();
                        throw;
                    }
                }
                catch
                {
                    cpHash.Dispose();
                    throw;
                }
            }
            catch
            {
                nonceTpm.Dispose();
                throw;
            }
        }
        catch
        {
            policyDigest.Dispose();
            throw;
        }
    }

    /// <summary>
    /// A short-lived copy of a sensitive carrier's octets, taken because <c>PrivateKeyMemory</c>/
    /// <c>SymmetricKeyMemory</c> expose their bytes only through an async delegate that a live
    /// <see cref="TpmWriter"/> cannot straddle (see this class's own remarks). <see cref="Length"/> is tracked
    /// separately from <see cref="Owner"/>'s own capacity because a pool rental may return more storage than
    /// requested. <see cref="Dispose"/> clears the copy before releasing it, so no second copy of the key
    /// material outlives the write that consumed it.
    /// </summary>
    /// <param name="Owner">The rented storage; <see cref="EmptyMemoryOwner"/> for a zero-length key.</param>
    /// <param name="Length">The number of valid leading octets in <see cref="Owner"/>.</param>
    private readonly record struct TpmContextOctets(IMemoryOwner<byte> Owner, int Length): IDisposable
    {
        /// <summary>Gets the valid octets.</summary>
        public ReadOnlySpan<byte> Span => Owner.Memory.Span[..Length];

        /// <summary>Clears the copied octets and releases the rental.</summary>
        public void Dispose()
        {
            Owner.Memory.Span[..Length].Clear();
            Owner.Dispose();
        }
    }

    /// <summary>
    /// Copies a private key's octets into a short-lived scratch rental — the one-time detour a
    /// <see cref="TpmWriter"/>-based write needs around <c>PrivateKeyMemory.WithKeyBytesAsync</c>'s async-shaped
    /// accessor (see this class's own remarks).
    /// </summary>
    /// <param name="key">The private key to copy from; <see cref="TpmSimulatorState.EmptyPrivateKey"/> yields a zero-length copy.</param>
    /// <param name="pool">The memory pool the copy is rented from.</param>
    /// <returns>The copied octets; the caller disposes them once the write has consumed them.</returns>
    private static ValueTask<TpmContextOctets> ExtractPrivateKeyOctetsAsync(PrivateKeyMemory key, BaseMemoryPool pool) =>
        key.WithKeyBytesAsync(static (octets, capturedPool) => CopyOctetsAsync(octets, capturedPool), pool);

    /// <summary>
    /// Copies a symmetric session key's octets into a short-lived scratch rental — the session-key counterpart
    /// of <see cref="ExtractPrivateKeyOctetsAsync"/>.
    /// </summary>
    /// <param name="key">The session key to copy from; <see cref="TpmSimulatorState.EmptySessionKey"/> yields a zero-length copy.</param>
    /// <param name="pool">The memory pool the copy is rented from.</param>
    /// <returns>The copied octets; the caller disposes them once the write has consumed them.</returns>
    private static ValueTask<TpmContextOctets> ExtractSymmetricKeyOctetsAsync(SymmetricKeyMemory key, BaseMemoryPool pool) =>
        key.WithKeyBytesAsync(static (octets, capturedPool) => CopyOctetsAsync(octets, capturedPool), pool);

    /// <summary>The synchronous copy both key-octet extractors share, wrapped as a completed <see cref="ValueTask{TResult}"/> to satisfy the delegate shape <c>WithKeyBytesAsync</c> requires.</summary>
    private static ValueTask<TpmContextOctets> CopyOctetsAsync(ReadOnlyMemory<byte> octets, BaseMemoryPool pool)
    {
        if(octets.IsEmpty)
        {
            return ValueTask.FromResult(new TpmContextOctets(EmptyMemoryOwner.Instance, 0));
        }

        IMemoryOwner<byte> copy = pool.Rent(octets.Length, AllocationKind.Pinned);
        octets.Span.CopyTo(copy.Memory.Span);

        return ValueTask.FromResult(new TpmContextOctets(copy, octets.Length));
    }

    /// <summary>
    /// Rebuilds a private key from its serialized octets, tagging it from the already-read <paramref name="keyType"/>
    /// (and, for RSA, the modulus width written beside the octets — the backend's private-key encoding is a
    /// PKCS#1 <c>RSAPrivateKey</c> DER whose length is not the modulus width) exactly as the creation effects
    /// that first produce such a key choose the tag (<see cref="TpmSimulator.EccPrivateKeyTag"/>/
    /// <see cref="TpmSimulator.RsaPrivateKeyTag"/>).
    /// </summary>
    /// <param name="reader">The reader positioned at the key's length-prefixed octets.</param>
    /// <param name="keyType">The already-read key algorithm, selecting the tagging rule.</param>
    /// <param name="curve">The already-read ECC curve, consulted only when <paramref name="keyType"/> is <c>TPM_ALG_ECC</c>.</param>
    /// <param name="keyBits">The already-read modulus width in bits, consulted only when <paramref name="keyType"/> is <c>TPM_ALG_RSA</c>.</param>
    /// <param name="pool">The memory pool the rebuilt carrier's storage is rented from.</param>
    /// <returns>The rebuilt key; <see cref="TpmSimulatorState.EmptyPrivateKey"/> for a zero-length run.</returns>
    /// <exception cref="InvalidOperationException"><paramref name="keyType"/> is neither <c>TPM_ALG_ECC</c> nor <c>TPM_ALG_RSA</c>.</exception>
    private static PrivateKeyMemory ReadPrivateKey(ref TpmReader reader, TpmiAlgPublic keyType, TpmiEccCurve curve, ushort keyBits, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> octets = reader.ReadTpm2b();
        if(octets.IsEmpty)
        {
            return TpmSimulatorState.EmptyPrivateKey;
        }

        Tag tag = keyType.Value switch
        {
            TpmAlgIdConstants.TPM_ALG_ECC => TpmSimulator.EccPrivateKeyTag(curve.Value),
            TpmAlgIdConstants.TPM_ALG_RSA => TpmSimulator.RsaPrivateKeyTag(keyBits),
            _ => throw new InvalidOperationException($"No private-key tag is defined for key type '{keyType.Value}'.")
        };

        IMemoryOwner<byte> storage = pool.Rent(octets.Length, AllocationKind.Pinned);
        octets.CopyTo(storage.Memory.Span);

        return new PrivateKeyMemory(storage, tag);
    }

    /// <summary>
    /// Rebuilds a public point from its serialized SEC1 octets, tagging it from the already-read
    /// <paramref name="curve"/> (<see cref="TpmCryptographicProjections.ToExchangePublicKeyTag"/>) — the same
    /// projection every ECC producer effect uses when it first adopts the point. The tag is computed before any
    /// pooled buffer is rented, mirroring <see cref="ReadPrivateKey"/>, so an unrecognized curve throws without
    /// ever orphaning a rental.
    /// </summary>
    /// <param name="reader">The reader positioned at the point's length-prefixed octets.</param>
    /// <param name="curve">The already-read ECC curve; consulted only for a non-empty run (an RSA object's point run is always empty).</param>
    /// <param name="pool">The memory pool the rebuilt carrier's storage is rented from.</param>
    /// <returns>The rebuilt point; <see cref="TpmSimulatorState.EmptyPublicPoint"/> for a zero-length run.</returns>
    private static EncodedEcPoint ReadPublicPoint(ref TpmReader reader, TpmiEccCurve curve, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> octets = reader.ReadTpm2b();
        if(octets.IsEmpty)
        {
            return TpmSimulatorState.EmptyPublicPoint;
        }

        Tag tag = curve.ToExchangePublicKeyTag();

        IMemoryOwner<byte> storage = pool.Rent(octets.Length);
        octets.CopyTo(storage.Memory.Span);

        return new EncodedEcPoint(storage, tag);
    }

    /// <summary>
    /// Rebuilds a session key from its serialized octets under the fixed session-key tag every
    /// <c>TPM2_StartAuthSession()</c> effect already uses.
    /// </summary>
    /// <param name="reader">The reader positioned at the key's length-prefixed octets.</param>
    /// <param name="pool">The memory pool the rebuilt carrier's storage is rented from.</param>
    /// <returns>The rebuilt key; <see cref="TpmSimulatorState.EmptySessionKey"/> for a zero-length run.</returns>
    private static SymmetricKeyMemory ReadSessionKey(ref TpmReader reader, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> octets = reader.ReadTpm2b();
        if(octets.IsEmpty)
        {
            return TpmSimulatorState.EmptySessionKey;
        }

        IMemoryOwner<byte> storage = pool.Rent(octets.Length, AllocationKind.Pinned);
        octets.CopyTo(storage.Memory.Span);

        return new SymmetricKeyMemory(storage, TpmTags.SessionKey);
    }

    /// <summary>Computes the wire size of a nullable field: one presence octet, plus <paramref name="valueSize"/> when present.</summary>
    private static int OptionalSize(bool isPresent, int valueSize) => sizeof(byte) + (isPresent ? valueSize : 0);

    /// <summary>Writes a nullable signing-scheme selector as one presence octet then the value.</summary>
    private static void WriteOptionalAlgSigScheme(ref TpmWriter writer, TpmiAlgSigScheme? value)
    {
        writer.WriteByte((byte)(value.HasValue ? 1 : 0));
        if(value.HasValue)
        {
            value.Value.WriteTo(ref writer);
        }
    }

    /// <summary>Reads a nullable signing-scheme selector written by <see cref="WriteOptionalAlgSigScheme"/>.</summary>
    private static TpmiAlgSigScheme? ReadOptionalAlgSigScheme(ref TpmReader reader) =>
        reader.ReadByte() != 0 ? TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16()) : null;

    /// <summary>Writes a nullable hash-algorithm selector as one presence octet then the value.</summary>
    private static void WriteOptionalAlgHash(ref TpmWriter writer, TpmiAlgHash? value)
    {
        writer.WriteByte((byte)(value.HasValue ? 1 : 0));
        if(value.HasValue)
        {
            value.Value.WriteTo(ref writer);
        }
    }

    /// <summary>Reads a nullable hash-algorithm selector written by <see cref="WriteOptionalAlgHash"/>.</summary>
    private static TpmiAlgHash? ReadOptionalAlgHash(ref TpmReader reader) =>
        reader.ReadByte() != 0 ? TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16()) : null;

    /// <summary>Writes a nullable KDF selector as one presence octet then the value.</summary>
    private static void WriteOptionalAlgKdf(ref TpmWriter writer, TpmiAlgKdf? value)
    {
        writer.WriteByte((byte)(value.HasValue ? 1 : 0));
        if(value.HasValue)
        {
            value.Value.WriteTo(ref writer);
        }
    }

    /// <summary>Reads a nullable KDF selector written by <see cref="WriteOptionalAlgKdf"/>.</summary>
    private static TpmiAlgKdf? ReadOptionalAlgKdf(ref TpmReader reader) =>
        reader.ReadByte() != 0 ? TpmiAlgKdf.FromValue((TpmAlgIdConstants)reader.ReadUInt16()) : null;

    /// <summary>Writes a policy session's nullable latched command code as one presence octet then the value.</summary>
    private static void WriteOptionalCommandCode(ref TpmWriter writer, TpmCcConstants? value)
    {
        writer.WriteByte((byte)(value.HasValue ? 1 : 0));
        if(value.HasValue)
        {
            writer.WriteUInt32((uint)value.Value);
        }
    }

    /// <summary>Reads a nullable latched command code written by <see cref="WriteOptionalCommandCode"/>.</summary>
    private static TpmCcConstants? ReadOptionalCommandCode(ref TpmReader reader) =>
        reader.ReadByte() != 0 ? (TpmCcConstants)reader.ReadUInt32() : null;

    /// <summary>Writes a <see langword="bool"/> field as one octet (TPM 2.0 Library Part 2's own <c>BYTE</c> encoding of a boolean field).</summary>
    private static void WriteBool(ref TpmWriter writer, bool value) => writer.WriteByte((byte)(value ? 1 : 0));

    /// <summary>Reads a <see langword="bool"/> field written by <see cref="WriteBool"/>.</summary>
    private static bool ReadBool(ref TpmReader reader) => reader.ReadByte() != 0;
}
