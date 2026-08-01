using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// The shipped default <see cref="DecodeCtapAuthenticatorSnapshotDelegate"/> implementation: parses the
/// versioned, definite-length-only CBOR array <see cref="CtapAuthenticatorSnapshotCborWriter"/> produces
/// back into a <see cref="CtapAuthenticatorSnapshot"/>.
/// </summary>
/// <remarks>
/// Every read is bounded (<see cref="CtapAuthenticatorSnapshotFormat"/>'s length/count caps) and this
/// reader never recurses — the schema's only nesting (a snapshot array containing credential-entry and
/// bio-template-entry arrays, and a credential entry containing a COSE_Key sub-array) is walked by a
/// fixed sequence of dedicated methods, never a generic depth-driven parser (R-5). On any parse failure,
/// every carrier already constructed for THIS call is disposed before the exception propagates — no
/// partially-parsed snapshot ever leaks pooled memory.
/// </remarks>
public static class CtapAuthenticatorSnapshotCborReader
{
    /// <summary>The fixed item count of the top-level snapshot array.</summary>
    private const int TopLevelItemCount = 16;

    /// <summary>The fixed item count of one credential entry array.</summary>
    private const int CredentialItemCount = 16;

    /// <summary>The fixed item count of one COSE_Key sub-array.</summary>
    private const int CoseKeyItemCount = 8;

    /// <summary>The fixed item count of one bio-enrollment-template entry array.</summary>
    private const int BioTemplateItemCount = 2;


    /// <summary>
    /// Parses <paramref name="snapshotCbor"/>. Has the <see cref="DecodeCtapAuthenticatorSnapshotDelegate"/> shape.
    /// </summary>
    /// <param name="snapshotCbor">The encoded snapshot payload.</param>
    /// <param name="pool">The memory pool the returned snapshot's owned carriers rent from.</param>
    /// <returns>The parsed, caller-owned snapshot.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="CtapAuthenticatorSnapshotException">
    /// The bytes are truncated, malformed, declare an unrecognized format version, or exceed one of
    /// <see cref="CtapAuthenticatorSnapshotFormat"/>'s bounds.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "currentStoredPin/serializedLargeBlobArray's ownership transfers to the returned CtapAuthenticatorSnapshot on the success path, and the catch block disposes them (plus every already-parsed credential/bio-template record) on any failure path; the analyzer cannot see either transfer through the try/catch.")]
    public static CtapAuthenticatorSnapshot Read(ReadOnlyMemory<byte> snapshotCbor, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        DigestValue? currentStoredPin = null;
        PooledMemory? serializedLargeBlobArray = null;
        List<CtapCredentialRecord> credentials = [];
        List<CtapBioEnrollmentTemplateRecord> bioTemplates = [];
        try
        {
            CborCursor cursor = new(snapshotCbor.Span);

            int topLevelCount = cursor.ReadArrayHeader(TopLevelItemCount);
            if(topLevelCount != TopLevelItemCount)
            {
                throw new CtapAuthenticatorSnapshotException($"Expected a {TopLevelItemCount}-item snapshot array but found {topLevelCount} items.");
            }

            ulong formatVersion = cursor.ReadUnsigned();
            if(formatVersion != CtapAuthenticatorSnapshotFormat.CurrentVersion)
            {
                throw new CtapAuthenticatorSnapshotException(
                    $"Unrecognized snapshot format version '{formatVersion}'; this codec understands only version '{CtapAuthenticatorSnapshotFormat.CurrentVersion}'.");
            }

            ReadOnlySpan<byte> aaguidBytes = cursor.ReadByteString(16);
            if(aaguidBytes.Length != 16)
            {
                throw new CtapAuthenticatorSnapshotException($"Expected a 16-byte AAGUID but found {aaguidBytes.Length} bytes.");
            }

            Guid aaguid = new(aaguidBytes, bigEndian: true);
            int firmwareVersion = checked((int)cursor.ReadUnsigned());
            ulong nextCredentialSequence = cursor.ReadUnsigned();

            if(cursor.TryReadNullableByteString(CtapAuthenticatorSnapshotFormat.MaxByteStringLength, out ReadOnlySpan<byte> pinBytes))
            {
                currentStoredPin = new DigestValue(RentCopy(pinBytes, pool), CryptoTags.Sha256Digest);
            }

            int pinCodePointLength = checked((int)cursor.ReadUnsigned());
            int pinRetries = checked((int)cursor.ReadUnsigned());
            int uvRetries = checked((int)cursor.ReadUnsigned());
            bool isForcePinChangeRequired = cursor.ReadBool();
            int minPinCodePointLength = checked((int)cursor.ReadUnsigned());

            int rpIdCount = cursor.ReadArrayHeader(CtapAuthenticatorSnapshotFormat.MaxArrayCount);
            string[] minPinLengthRpIds = new string[rpIdCount];
            for(int i = 0; i < rpIdCount; i++)
            {
                minPinLengthRpIds[i] = cursor.ReadTextString(CtapAuthenticatorSnapshotFormat.MaxTextStringLength);
            }

            bool isAlwaysUvEnabled = cursor.ReadBool();
            bool isEnterpriseAttestationEnabled = cursor.ReadBool();

            ReadOnlySpan<byte> largeBlobArrayBytes = cursor.ReadByteString(CtapAuthenticatorSnapshotFormat.MaxByteStringLength);
            serializedLargeBlobArray = PooledMemory.FromBytes(largeBlobArrayBytes, pool, Fido2BufferTags.CtapSerializedLargeBlobArrayPayload);

            int credentialCount = cursor.ReadArrayHeader(CtapAuthenticatorSnapshotFormat.MaxArrayCount);
            for(int i = 0; i < credentialCount; i++)
            {
                credentials.Add(ReadCredentialEntry(ref cursor, pool));
            }

            int bioTemplateCount = cursor.ReadArrayHeader(CtapAuthenticatorSnapshotFormat.MaxArrayCount);
            for(int i = 0; i < bioTemplateCount; i++)
            {
                bioTemplates.Add(ReadBioTemplateEntry(ref cursor, pool));
            }

            ImmutableDictionary<string, CtapCredentialRecord>.Builder credentialsById = ImmutableDictionary.CreateBuilder<string, CtapCredentialRecord>();
            foreach(CtapCredentialRecord credential in credentials)
            {
                //A duplicate credential id is malformed and fails closed: the ImmutableDictionary indexer
                //would silently OVERWRITE the earlier record, orphaning its pooled secret carriers (they
                //are held only by the `credentials` list the catch below disposes, never by the returned
                //snapshot) — so reject rather than leak. Throwing here routes through that same catch, which
                //disposes every record accumulated for this call.
                string credentialKey = Convert.ToHexStringLower(credential.CredentialId.AsReadOnlySpan());
                if(!credentialsById.TryAdd(credentialKey, credential))
                {
                    throw new CtapAuthenticatorSnapshotException($"The snapshot contains two credentials with the same credential id '{credentialKey}'.");
                }
            }

            ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord>.Builder templatesById = ImmutableDictionary.CreateBuilder<string, CtapBioEnrollmentTemplateRecord>();
            foreach(CtapBioEnrollmentTemplateRecord template in bioTemplates)
            {
                //Same fail-closed rule as the credential fold above: a duplicate template id would orphan
                //the shadowed template's pooled carriers.
                string templateKey = Convert.ToHexStringLower(template.TemplateId.AsReadOnlySpan());
                if(!templatesById.TryAdd(templateKey, template))
                {
                    throw new CtapAuthenticatorSnapshotException($"The snapshot contains two bio-enrollment templates with the same template id '{templateKey}'.");
                }
            }

            return new CtapAuthenticatorSnapshot(
                (int)formatVersion, aaguid, firmwareVersion, nextCredentialSequence, currentStoredPin, pinCodePointLength, pinRetries, uvRetries,
                isForcePinChangeRequired, minPinCodePointLength, minPinLengthRpIds, isAlwaysUvEnabled, isEnterpriseAttestationEnabled,
                serializedLargeBlobArray, credentialsById.ToImmutable(), templatesById.ToImmutable());
        }
        catch(Exception exception)
        {
            currentStoredPin?.Dispose();
            serializedLargeBlobArray?.Dispose();

            foreach(CtapCredentialRecord credential in credentials)
            {
                credential.Dispose();
            }

            foreach(CtapBioEnrollmentTemplateRecord template in bioTemplates)
            {
                template.Dispose();
            }

            //Fail closed with the documented type. A malformed snapshot reaches here as an already-shaped
            //CtapAuthenticatorSnapshotException (a bad count/version/duplicate id) OR as a lower-level parse
            //failure the bounded reader raises on adversarial bytes — an out-of-range integer field trips a
            //`checked` cast to OverflowException, a malformed Guid or CBOR item throws ArgumentException/
            //FormatException. The DecodeCtapAuthenticatorSnapshotDelegate contract and CreateWithCustodyAsync's
            //<exception> doc both promise CtapAuthenticatorSnapshotException for any malformed snapshot, so
            //wrap anything else rather than letting the raw framework type escape past a caller catching the
            //documented type.
            if(exception is CtapAuthenticatorSnapshotException)
            {
                throw;
            }

            throw new CtapAuthenticatorSnapshotException("The custody snapshot could not be decoded; it is malformed, truncated, or carries an out-of-range value.", exception);
        }
    }


    /// <summary>Parses one credential entry array into a fully restored, disposable <see cref="CtapCredentialRecord"/>.</summary>
    /// <param name="cursor">The cursor positioned immediately before the credential entry's array header.</param>
    /// <param name="pool">The memory pool the credential's owned carriers rent from.</param>
    /// <returns>The restored credential record.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every carrier constructed in the try block transfers ownership to the returned CtapCredentialRecord on the success path, and the catch block disposes each one (guarded by null-conditional access) on any failure path; the analyzer cannot see either transfer through the try/catch.")]
    private static CtapCredentialRecord ReadCredentialEntry(ref CborCursor cursor, BaseMemoryPool pool)
    {
        int itemCount = cursor.ReadArrayHeader(CredentialItemCount);
        if(itemCount != CredentialItemCount)
        {
            throw new CtapAuthenticatorSnapshotException($"Expected a {CredentialItemCount}-item credential array but found {itemCount} items.");
        }

        ReadOnlySpan<byte> credentialIdBytes = cursor.ReadByteString(CredentialId.MaxLength);
        string rpId = cursor.ReadTextString(CtapAuthenticatorSnapshotFormat.MaxTextStringLength);
        ReadOnlySpan<byte> userIdBytes = cursor.ReadByteString(UserHandle.MaxLength);
        string? userName = cursor.ReadNullableTextString(CtapAuthenticatorSnapshotFormat.MaxTextStringLength);
        string? userDisplayName = cursor.ReadNullableTextString(CtapAuthenticatorSnapshotFormat.MaxTextStringLength);
        int algorithm = checked((int)cursor.ReadInt());
        bool isResident = cursor.ReadBool();
        string credentialKeyId = cursor.ReadTextString(CtapAuthenticatorSnapshotFormat.MaxTextStringLength);
        ReadOnlySpan<byte> credentialKeyExportBytes = cursor.ReadByteString(CtapAuthenticatorSnapshotFormat.MaxByteStringLength);
        uint signCount = checked((uint)cursor.ReadUnsigned());
        ulong creationSequence = cursor.ReadUnsigned();
        CoseKey publicKey = ReadCoseKey(ref cursor);
        int credProtectLevel = checked((int)cursor.ReadUnsigned());
        ReadOnlySpan<byte> credRandomWithUVBytes = cursor.ReadByteString(CtapAuthenticatorSnapshotFormat.MaxByteStringLength);
        ReadOnlySpan<byte> credRandomWithoutUVBytes = cursor.ReadByteString(CtapAuthenticatorSnapshotFormat.MaxByteStringLength);
        bool hasLargeBlobKey = cursor.TryReadNullableByteString(CtapAuthenticatorSnapshotFormat.MaxByteStringLength, out ReadOnlySpan<byte> largeBlobKeyBytes);

        //Every read above is a zero-copy view into the ORIGINAL input, so a parse failure up to this
        //point never leaks a rented buffer. Only from here does construction rent/wrap pooled memory —
        //declare-null/try/dispose-on-catch, the same shape CtapAuthenticatorSimulator.GenerateCredentialAsync's
        //own mint path already uses.
        CredentialId? credentialId = null;
        UserHandle? userId = null;
        PooledMemory? credentialKeyCustodyExport = null;
        PrivateKey? credentialKey = null;
        IMemoryOwner<byte>? credRandomWithUV = null;
        IMemoryOwner<byte>? credRandomWithoutUV = null;
        IMemoryOwner<byte>? largeBlobKey = null;
        try
        {
            credentialId = CredentialId.Create(credentialIdBytes, pool);
            userId = UserHandle.Create(userIdBytes, pool);
            credentialKeyCustodyExport = PooledMemory.FromBytes(credentialKeyExportBytes, pool, CtapAuthenticatorCustodyBufferTags.CredentialKeyCustodyExportPayload);
            credentialKey = RestoreCredentialPrivateKey(algorithm, credentialKeyId, credentialKeyCustodyExport.AsReadOnlySpan(), pool);
            credRandomWithUV = RentCopy(credRandomWithUVBytes, pool);
            credRandomWithoutUV = RentCopy(credRandomWithoutUVBytes, pool);
            largeBlobKey = hasLargeBlobKey ? RentCopy(largeBlobKeyBytes, pool) : null;

            return new CtapCredentialRecord(
                credentialId, rpId, userId, userName, userDisplayName, algorithm, isResident, credentialKey,
                signCount, creationSequence, publicKey, credProtectLevel, credRandomWithUV, credRandomWithoutUV,
                largeBlobKey, credentialKeyCustodyExport);
        }
        catch
        {
            credentialId?.Dispose();
            userId?.Dispose();
            credentialKeyCustodyExport?.Dispose();
            credentialKey?.Dispose();
            credRandomWithUV?.Dispose();
            credRandomWithoutUV?.Dispose();
            largeBlobKey?.Dispose();
            throw;
        }
    }


    /// <summary>Parses one COSE_Key sub-array into a <see cref="CoseKey"/> — an ordinary array-backed model, never pooled (see its own type doc).</summary>
    private static CoseKey ReadCoseKey(ref CborCursor cursor)
    {
        int itemCount = cursor.ReadArrayHeader(CoseKeyItemCount);
        if(itemCount != CoseKeyItemCount)
        {
            throw new CtapAuthenticatorSnapshotException($"Expected a {CoseKeyItemCount}-item COSE_Key array but found {itemCount} items.");
        }

        int kty = checked((int)cursor.ReadInt());
        int? alg = cursor.TryReadNullableInt(out long algValue) ? checked((int)algValue) : null;
        int? curve = cursor.TryReadNullableInt(out long curveValue) ? checked((int)curveValue) : null;
        ReadOnlyMemory<byte>? x = ReadNullableArray(ref cursor);
        ReadOnlyMemory<byte>? y = ReadNullableArray(ref cursor);
        bool? encodedYCompressionSign = cursor.TryReadNullableBool(out bool signValue) ? signValue : null;
        ReadOnlyMemory<byte>? n = ReadNullableArray(ref cursor);
        ReadOnlyMemory<byte>? e = ReadNullableArray(ref cursor);

        return new CoseKey(kty, alg, curve, x, y, encodedYCompressionSign, n, e);


        //Deliberately an if/else, not a ternary: a ternary whose "present" branch is a byte[] (which
        //converts implicitly to ReadOnlyMemory<byte>) and whose "absent" branch is the null literal
        //infers a non-nullable ReadOnlyMemory<byte> as the conditional expression's own common type
        //before ever promoting to Nullable<ReadOnlyMemory<byte>> — null's implicit convertibility via
        //the array-accepting operator out-competes the Nullable promotion, so the "absent" case would
        //silently become HasValue=true (an empty span) instead of a genuinely absent value. Same trap
        //CtapMakeCredentialRequestCborReader's own credProtect handling documents.
        static ReadOnlyMemory<byte>? ReadNullableArray(ref CborCursor innerCursor)
        {
            if(innerCursor.TryReadNullableByteString(CtapAuthenticatorSnapshotFormat.MaxByteStringLength, out ReadOnlySpan<byte> bytes))
            {
                return bytes.ToArray();
            }

            return null;
        }
    }


    /// <summary>Parses one bio-enrollment-template entry array into a fully restored, disposable <see cref="CtapBioEnrollmentTemplateRecord"/>.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "templateId's ownership transfers to the returned CtapBioEnrollmentTemplateRecord immediately.")]
    private static CtapBioEnrollmentTemplateRecord ReadBioTemplateEntry(ref CborCursor cursor, BaseMemoryPool pool)
    {
        int itemCount = cursor.ReadArrayHeader(BioTemplateItemCount);
        if(itemCount != BioTemplateItemCount)
        {
            throw new CtapAuthenticatorSnapshotException($"Expected a {BioTemplateItemCount}-item bio-template array but found {itemCount} items.");
        }

        ReadOnlySpan<byte> templateIdBytes = cursor.ReadByteString(CtapAuthenticatorSnapshotFormat.MaxByteStringLength);
        string? friendlyName = cursor.ReadNullableTextString(CtapAuthenticatorSnapshotFormat.MaxTextStringLength);

        BioEnrollmentTemplateId templateId = BioEnrollmentTemplateId.Create(templateIdBytes, pool);

        return new CtapBioEnrollmentTemplateRecord(templateId, friendlyName);
    }


    /// <summary>
    /// Resolves the crypto-registry tag for <paramref name="coseAlgorithm"/> and reconstructs a signing-
    /// capable <see cref="PrivateKey"/> from its raw custody-exported scalar.
    /// </summary>
    /// <param name="coseAlgorithm">The credential's COSE algorithm identifier.</param>
    /// <param name="keyId">The private key's original identifier (<see cref="Verifiable.Cryptography.SensitiveMemoryKey.Id"/>).</param>
    /// <param name="rawKeyBytes">The raw custody-exported private-key-material bytes.</param>
    /// <param name="pool">The memory pool the reconstructed key material rents from.</param>
    /// <returns>The reconstructed private key, with its signing function bound exactly as it was at mint time.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">
    /// <paramref name="coseAlgorithm"/> has no registered custody key-material tag — currently only
    /// <see cref="WellKnownCoseAlgorithms.Es256"/>, the shipped
    /// <see cref="CtapCredentialSigningBackend.CreateEs256Default"/> backend's own sole supported
    /// algorithm; a caller composing a different signing backend must extend this mapping alongside it.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "privateKeyMemory's ownership transfers to CryptographicKeyFactory.CreatePrivateKey's returned PrivateKey on the success path; the catch block disposes it on failure.")]
    private static PrivateKey RestoreCredentialPrivateKey(int coseAlgorithm, string keyId, ReadOnlySpan<byte> rawKeyBytes, BaseMemoryPool pool)
    {
        Tag tag = coseAlgorithm switch
        {
            WellKnownCoseAlgorithms.Es256 => CryptoTags.P256PrivateKey,
            _ => throw new CtapAuthenticatorSnapshotException($"No custody key-material tag is registered for COSE algorithm '{coseAlgorithm}'.")
        };

        PrivateKeyMemory privateKeyMemory = new(RentCopy(rawKeyBytes, pool), tag);
        try
        {
            return CryptographicKeyFactory.CreatePrivateKey(privateKeyMemory, keyId, tag);
        }
        catch
        {
            privateKeyMemory.Dispose();
            throw;
        }
    }


    /// <summary>Copies <paramref name="source"/> into a freshly rented buffer, the general-purpose "restore an owned carrier" step every field above shares.</summary>
    private static IMemoryOwner<byte> RentCopy(ReadOnlySpan<byte> source, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(source.Length, 1));
        try
        {
            source.CopyTo(owner.Memory.Span);
            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }
}
