using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer containing a public area (TPM2B_PUBLIC).
/// </summary>
/// <remarks>
/// <para>
/// This structure wraps <see cref="TpmtPublic"/> with a size prefix.
/// It is used in commands like <c>TPM2_CreatePrimary()</c>, <c>TPM2_Create()</c>,
/// <c>TPM2_Load()</c>, and <c>TPM2_ReadPublic()</c>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of publicArea in bytes.
///     TPMT_PUBLIC publicArea;                  // The public area.
/// } TPM2B_PUBLIC;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.5, Table 236.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bPublic: IDisposable, ITpmWireType
{
    private IMemoryOwner<byte>? RawStorage { get; }
    private int RawLength { get; }
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the public area.
    /// </summary>
    public TpmtPublic PublicArea { get; }

    /// <summary>
    /// Initializes a new sized public buffer.
    /// </summary>
    private Tpm2bPublic(TpmtPublic publicArea, IMemoryOwner<byte>? rawStorage, int rawLength)
    {
        PublicArea = publicArea;
        this.RawStorage = rawStorage;
        this.RawLength = rawLength;
    }

    /// <summary>
    /// Gets the raw bytes of the public area (for Name computation).
    /// </summary>
    /// <returns>The raw public area bytes.</returns>
    /// <remarks>
    /// These bytes are used to compute the object's Name:
    /// Name = nameAlg || H_nameAlg(TPMT_PUBLIC bytes).
    /// </remarks>
    public ReadOnlySpan<byte> GetRawBytes()
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        if(RawStorage is null)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        return RawStorage.Memory.Span.Slice(0, RawLength);
    }

    /// <summary>
    /// Gets the raw public-area bytes as memory, for asynchronous consumers such as the registered digest
    /// seam. The memory aliases this instance's pooled storage — it is valid until <see cref="Dispose"/> and
    /// must not be copied out into untracked arrays.
    /// </summary>
    /// <returns>The raw public area bytes.</returns>
    public ReadOnlyMemory<byte> GetRawMemory()
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        if(RawStorage is null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return RawStorage.Memory.Slice(0, RawLength);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(Disposed, this);
        return sizeof(ushort) + PublicArea.GetSerializedSize();
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        int innerSize = PublicArea.GetSerializedSize();
        writer.WriteUInt16((ushort)innerSize);
        PublicArea.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a sized public buffer from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed public buffer.</returns>
    /// <exception cref="InvalidOperationException">The declared size is zero, or the public area inside is malformed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>; checked before any storage is rented, so a truncated frame orphans nothing.</exception>
    public static Tpm2bPublic Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            throw new InvalidOperationException("TPM2B_PUBLIC size cannot be zero.");
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), (int)size, $"TPM2B_PUBLIC size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        //The raw octets are retained for the Name computation.
        IMemoryOwner<byte> rawStorage = pool.Rent(size);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(size);
            source.CopyTo(rawStorage.Memory.Span.Slice(0, size));

            // Parse the structure from the raw bytes.
            var innerReader = new TpmReader(rawStorage.Memory.Span.Slice(0, size));
            var publicArea = TpmtPublic.Parse(ref innerReader, pool);

            return new Tpm2bPublic(publicArea, rawStorage, size);
        }
        catch
        {
            //A short buffer or an unmodelled inner public area must not leak the pooled raw-bytes rental.
            rawStorage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates a sized public buffer from a public area (for writing templates).
    /// </summary>
    /// <param name="publicArea">The public area.</param>
    /// <returns>The sized public buffer.</returns>
    /// <remarks>
    /// This method is used for writing templates to the TPM. The raw bytes
    /// are not stored (they can be computed if needed).
    /// </remarks>
    public static Tpm2bPublic FromTemplate(TpmtPublic publicArea)
    {
        return new Tpm2bPublic(publicArea, null, 0);
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for an ECC signing key template.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="curve">ECC curve.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccSigningTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmtEccScheme scheme)
    {
        var publicArea = TpmtPublic.CreateEccSigningTemplate(nameAlg, objectAttributes, curve, scheme);
        return FromTemplate(publicArea);
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for a generated ECC signing key, carrying the key's actual public point (the
    /// <c>outPublic</c> form), as opposed to the empty-unique template <see cref="CreateEccSigningTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="curve">ECC curve.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <param name="unique">The generated public point; ownership transfers to the returned buffer.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to re-emit into the exported public area, or empty (default) for none.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccSigningKey(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmtEccScheme scheme,
        TpmsEccPoint unique,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        return FromTemplate(TpmtPublic.CreateEccSigningKey(nameAlg, objectAttributes, curve, scheme, unique, pool, authPolicy));
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for an RSA signing key template.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="keyBits">Key size in bits.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateRsaSigningTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        ushort keyBits,
        TpmtRsaScheme scheme)
    {
        var publicArea = TpmtPublic.CreateRsaSigningTemplate(nameAlg, objectAttributes, keyBits, scheme);
        return FromTemplate(publicArea);
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for a generated RSA signing key, carrying the key's actual public modulus (the
    /// <c>outPublic</c> form), as opposed to the empty-unique template <see cref="CreateRsaSigningTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="keyBits">Key size in bits.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <param name="modulus">The generated public modulus (big-endian); copied into pooled storage the returned buffer owns.</param>
    /// <param name="pool">The memory pool for the modulus storage and the authPolicy digest.</param>
    /// <param name="authPolicy">The authorization policy digest to re-emit into the exported public area, or empty (default) for none.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateRsaSigningKey(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        ushort keyBits,
        TpmtRsaScheme scheme,
        ReadOnlySpan<byte> modulus,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        return FromTemplate(TpmtPublic.CreateRsaSigningKey(nameAlg, objectAttributes, keyBits, scheme, modulus, pool, authPolicy));
    }


    /// <summary>
    /// Creates a sized public buffer template for an ECC ECDH key agreement key.
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="curve">The ECC curve.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccKeyAgreementTemplate(
        TpmAlgIdConstants nameAlg,
        TpmEccCurveConstants curve)
    {
        return FromTemplate(TpmtPublic.CreateEccKeyAgreementTemplate(nameAlg, curve));
    }

    /// <summary>
    /// Creates a sized public buffer template for an unrestricted ECC decryption key usable with
    /// <c>TPM2_Encapsulate()</c> and <c>TPM2_Decapsulate()</c> (TPM 2.0 Library Part 2, Table 229's KEM
    /// admission gate; see <see cref="TpmtPublic.CreateEccKemKeyTemplate"/>).
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">The object attributes (an unrestricted decryption key: DECRYPT set, RESTRICTED and SIGN_ENCRYPT clear).</param>
    /// <param name="curve">The ECC curve — the DHKEM's <c>curveID</c>.</param>
    /// <param name="kdfHashAlg">The HKDF hash algorithm — the DHKEM's KDF hash.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccKemKeyTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmAlgIdConstants kdfHashAlg)
    {
        return FromTemplate(TpmtPublic.CreateEccKemKeyTemplate(nameAlg, objectAttributes, curve, kdfHashAlg));
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for a generated ECC KEM key, carrying the key's actual public point (the
    /// <c>outPublic</c> form), as opposed to the empty-unique template <see cref="CreateEccKemKeyTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">The object attributes (an unrestricted decryption key: DECRYPT set, RESTRICTED and SIGN_ENCRYPT clear).</param>
    /// <param name="curve">The ECC curve — the DHKEM's <c>curveID</c>.</param>
    /// <param name="schemeHashAlg">The <c>scheme.details.ecdh.hashAlg</c> the creating template carried — echoed unchanged (Part 3, clause 24.1.1), independently of <paramref name="kdfHashAlg"/>.</param>
    /// <param name="kdfHashAlg">The HKDF hash algorithm — the DHKEM's KDF hash.</param>
    /// <param name="unique">The generated public point; ownership transfers to the returned buffer.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to re-emit into the exported public area, or empty (default) for none.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccKemKey(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmAlgIdConstants schemeHashAlg,
        TpmAlgIdConstants kdfHashAlg,
        TpmsEccPoint unique,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        return FromTemplate(TpmtPublic.CreateEccKemKey(nameAlg, objectAttributes, curve, schemeHashAlg, kdfHashAlg, unique, pool, authPolicy));
    }

    /// <summary>
    /// Creates a sized public buffer template for an ECC restricted storage key, suitable as the parent
    /// of <c>TPM2_Create()</c>.
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the key do not advance the dictionary-attack lockout counter.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccStorageParentTemplate(
        TpmAlgIdConstants nameAlg,
        TpmEccCurveConstants curve,
        bool noDa = false)
    {
        return FromTemplate(TpmtPublic.CreateEccStorageParentTemplate(nameAlg, curve, noDa));
    }

    /// <summary>
    /// Creates a sized public buffer template for the standard ECC NIST P-256 endorsement key (TCG EK Credential
    /// Profile, Annex B.3.4, Template L-2).
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="curve">The ECC curve (<see cref="TpmEccCurveConstants.TPM_ECC_NIST_P256"/> for Template L-2).</param>
    /// <param name="pool">The memory pool backing the authPolicy digest and the all-zero unique point.</param>
    /// <param name="authPolicy">The 32-octet "PolicyA" digest (SHA-256 nameAlg).</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccEndorsementKeyTemplate(
        TpmAlgIdConstants nameAlg,
        TpmEccCurveConstants curve,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy)
    {
        return FromTemplate(TpmtPublic.CreateEccEndorsementKeyTemplate(nameAlg, curve, pool, authPolicy));
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for a generated ECC restricted storage key, carrying the key's actual public point
    /// (the <c>outPublic</c> form), as opposed to the empty-unique template <see cref="CreateEccStorageParentTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">The object attributes (a storage parent: RESTRICTED + DECRYPT).</param>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="unique">The generated public point; ownership transfers to the returned buffer.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">
    /// The authorization policy digest to re-emit into the exported public area (for example a standard
    /// endorsement key's "PolicyA"), or empty (default) for none.
    /// </param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccStorageParent(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmsEccPoint unique,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        return FromTemplate(TpmtPublic.CreateEccStorageParent(nameAlg, objectAttributes, curve, unique, pool, authPolicy));
    }

    /// <summary>
    /// Creates a sized public buffer template for the standard RSA 2048 endorsement key (TCG EK Credential
    /// Profile, Annex B.3.3, Template L-1).
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="keyBits">The RSA modulus size in bits (2048 for Template L-1).</param>
    /// <param name="pool">The memory pool backing the authPolicy digest and the all-zero unique modulus.</param>
    /// <param name="authPolicy">The 32-octet "PolicyA" digest (SHA-256 nameAlg).</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateRsaEndorsementKeyTemplate(
        TpmAlgIdConstants nameAlg,
        ushort keyBits,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy)
    {
        return FromTemplate(TpmtPublic.CreateRsaEndorsementKeyTemplate(nameAlg, keyBits, pool, authPolicy));
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for a generated RSA restricted storage key, carrying the key's actual public
    /// modulus (the <c>outPublic</c> form for a storage primary, including the standard RSA endorsement key).
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">The object attributes (a storage parent: RESTRICTED + DECRYPT).</param>
    /// <param name="keyBits">The RSA modulus size in bits.</param>
    /// <param name="modulus">The generated public modulus (big-endian); copied into pooled storage the returned buffer owns.</param>
    /// <param name="pool">The memory pool for the modulus storage and the authPolicy digest.</param>
    /// <param name="authPolicy">
    /// The authorization policy digest to re-emit into the exported public area (for example a standard RSA
    /// endorsement key's "PolicyA"), or empty (default) for none.
    /// </param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateRsaStorageParent(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        ushort keyBits,
        ReadOnlySpan<byte> modulus,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        return FromTemplate(TpmtPublic.CreateRsaStorageParent(nameAlg, objectAttributes, keyBits, modulus, pool, authPolicy));
    }

    /// <summary>
    /// Creates a sized public buffer template for an ordinary (password-authorizable) RSA restricted storage
    /// key — the RSA counterpart of <see cref="CreateEccStorageParentTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="keyBits">The RSA modulus size in bits.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the parent do not advance the dictionary-attack lockout counter.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateRsaStorageParentTemplate(
        TpmAlgIdConstants nameAlg,
        ushort keyBits,
        bool noDa = false)
    {
        return FromTemplate(TpmtPublic.CreateRsaStorageParentTemplate(nameAlg, keyBits, noDa));
    }

    /// <summary>
    /// Creates a sized public buffer template for a sealed data object (KEYEDHASH, null scheme), optionally
    /// gated on an authorization policy (for example a <c>TPM2_PolicyPCR</c> digest).
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to bind the object to, or empty (default) for none.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the sealed object do not advance the dictionary-attack lockout counter.</param>
    /// <param name="userWithAuth">
    /// When <see langword="true"/> (the default), sets TPMA_OBJECT.userWithAuth so a USER-role action (such as
    /// <c>TPM2_Unseal()</c>) may be authorized by an HMAC session or password as well as a policy session; when
    /// <see langword="false"/>, only a policy session may authorize it (TPM 2.0 Library Part 2, clause 8.3.3;
    /// Part 3, clause 5.6, check 7.1).
    /// </param>
    /// <returns>The sized public buffer.</returns>
    /// <param name="isDuplicable">
    /// When <see langword="true"/>, leaves TPMA_OBJECT.fixedTPM and fixedParent CLEAR so the created object may
    /// later leave its parent through <c>TPM2_Duplicate()</c>; when <see langword="false"/> (the default), both
    /// are SET and the object is bound to its parent and TPM for life (TPM 2.0 Library Part 2, clause 8.3.2,
    /// Table 37; Part 1, Clause 20).
    /// </param>
    public static Tpm2bPublic CreateSealedDataTemplate(
        TpmAlgIdConstants nameAlg,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default,
        bool noDa = false,
        bool userWithAuth = true,
        bool isDuplicable = false)
    {
        return FromTemplate(TpmtPublic.CreateSealedDataTemplate(nameAlg, pool, authPolicy, noDa, userWithAuth, isDuplicable));
    }

    /// <summary>
    /// Creates a sized public buffer template for an HMAC key (KEYEDHASH, HMAC scheme), optionally gated on an
    /// authorization policy, delegating to <see cref="TpmtPublic.CreateHmacKeyTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="hashAlg">The HMAC hash algorithm (TPMS_SCHEME_HMAC's <c>hashAlg</c>).</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to bind the object to, or empty (default) for none.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the key do not advance the dictionary-attack lockout counter.</param>
    /// <param name="userWithAuth">
    /// When <see langword="true"/> (the default), sets TPMA_OBJECT.userWithAuth so a USER-role action (such as
    /// <c>TPM2_HMAC()</c>) may be authorized by an HMAC session or password as well as a policy session; when
    /// <see langword="false"/>, only a policy session may authorize it (TPM 2.0 Library Part 2, clause 8.3.3;
    /// Part 3, clause 5.6, check 7.1).
    /// </param>
    /// <param name="isDuplicable">
    /// When <see langword="true"/>, leaves TPMA_OBJECT.fixedTPM and fixedParent CLEAR so the created key may
    /// later leave its parent through <c>TPM2_Duplicate()</c>; when <see langword="false"/> (the default), both
    /// are SET and the key is bound to its parent and TPM for life (TPM 2.0 Library Part 2, clause 8.3.2,
    /// Table 37; Part 1, Clause 20).
    /// </param>
    /// <param name="isRestricted">
    /// When <see langword="true"/>, sets TPMA_OBJECT.restricted, producing a restricted signing key rather than
    /// an ordinary HMAC key usable with <c>TPM2_HMAC_Start()</c>/<c>TPM2_HMAC()</c>; <see langword="false"/> is
    /// the default.
    /// </param>
    /// <param name="isSensitiveDataOrigin">
    /// When <see langword="true"/> (the default), sets TPMA_OBJECT.sensitiveDataOrigin for a TPM-generated key;
    /// set <see langword="false"/> when the caller supplies the key octets in <c>TPM2B_SENSITIVE_CREATE.data</c>.
    /// </param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateHmacKeyTemplate(
        TpmAlgIdConstants nameAlg,
        TpmAlgIdConstants hashAlg,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default,
        bool noDa = false,
        bool userWithAuth = true,
        bool isDuplicable = false,
        bool isRestricted = false,
        bool isSensitiveDataOrigin = true)
    {
        return FromTemplate(TpmtPublic.CreateHmacKeyTemplate(
            nameAlg, hashAlg, pool, authPolicy, noDa, userWithAuth, isDuplicable, isRestricted, isSensitiveDataOrigin));
    }

    /// <summary>
    /// Creates a sized public buffer for a KEYEDHASH object that echoes an exact attribute word and scheme, the
    /// form <c>TPM2_Create()</c> returns as <c>outPublic</c> (TPM 2.0 Library Part 3, clause 12.1). Delegates to
    /// <see cref="TpmtPublic.CreateKeyedHashTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">The object's name algorithm.</param>
    /// <param name="objectAttributes">The exact <c>TPMA_OBJECT</c> attribute word.</param>
    /// <param name="scheme">The keyed-hash scheme (NULL for a data object, HMAC for a signing key).</param>
    /// <param name="authPolicy">The authorization policy digest.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="unique">The <c>unique</c> value to carry — <c>H_nameAlg(seedValue ‖ sensitive)</c> per Part 2, clause 12.2.3.1, equation (8); Part 1, clause 24.5.3.2, equation (48) — or empty for the template form a caller sends.</param>
    /// <returns>The sized KEYEDHASH public buffer.</returns>
    public static Tpm2bPublic CreateKeyedHashTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmsKeyedHashParms scheme,
        ReadOnlySpan<byte> authPolicy,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> unique = default)
    {
        return FromTemplate(TpmtPublic.CreateKeyedHashTemplate(nameAlg, objectAttributes, scheme, authPolicy, pool, unique));
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!Disposed)
        {
            PublicArea.Dispose();
            RawStorage?.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPM2B_PUBLIC({PublicArea.Type}, {RawLength} bytes)";
}
