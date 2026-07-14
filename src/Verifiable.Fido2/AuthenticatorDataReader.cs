using System.Buffers;
using System.Buffers.Binary;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// Parses the binary <c>authData</c> wire format into an <see cref="AuthenticatorData"/> view.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
/// Parsing is fail-closed: every violation of the wire format — a truncated buffer, an
/// out-of-range length, or trailing bytes where none are permitted — is rejected with a
/// <see cref="Fido2FormatException"/> naming what failed, rather than being silently accepted
/// or surfaced as an unrelated exception type.
/// </remarks>
public static class AuthenticatorDataReader
{
    /// <summary>The length in bytes of the <c>rpIdHash</c> field.</summary>
    private const int RpIdHashLength = 32;

    /// <summary>The length in bytes of the <c>flags</c> field.</summary>
    private const int FlagsLength = 1;

    /// <summary>The length in bytes of the <c>signCount</c> field.</summary>
    private const int SignCountLength = 4;

    /// <summary>
    /// The minimum total length of <c>authData</c>: <c>rpIdHash</c> (32) + <c>flags</c> (1) +
    /// <c>signCount</c> (4).
    /// </summary>
    private const int MinimumLength = RpIdHashLength + FlagsLength + SignCountLength;

    /// <summary>The length in bytes of the <c>aaguid</c> field.</summary>
    private const int AaguidLength = 16;

    /// <summary>The length in bytes of the <c>credentialIdLength</c> field.</summary>
    private const int CredentialIdLengthFieldLength = 2;

    /// <summary>
    /// The combined length of <c>aaguid</c> and <c>credentialIdLength</c>, the fixed-size
    /// header preceding the variable-length <c>credentialId</c>.
    /// </summary>
    private const int AttestedCredentialDataHeaderLength = AaguidLength + CredentialIdLengthFieldLength;

    /// <summary>
    /// The largest permitted <c>credentialId</c> length.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3, section 7.1: Registering a New Credential.</see>
    /// step 25 bounds a returned credential ID to 1023 bytes.
    /// </remarks>
    private const int MaxCredentialIdLength = 1023;


    /// <summary>
    /// Parses <paramref name="authenticatorData"/> into an <see cref="AuthenticatorData"/> view.
    /// </summary>
    /// <param name="authenticatorData">The raw <c>authData</c> bytes.</param>
    /// <param name="readCredentialPublicKey">
    /// The COSE_Key codec applied to the bytes following <c>credentialId</c> when the <c>AT</c>
    /// flag is set.
    /// </param>
    /// <param name="pool">
    /// The memory pool the returned <see cref="AuthenticatorData.RpIdHash"/> and, when present, the
    /// attested credential data's <see cref="Fido2.AttestedCredentialData.CredentialId"/> carriers
    /// rent from.
    /// </param>
    /// <returns>
    /// The parsed <see cref="AuthenticatorData"/>. Its <see cref="AuthenticatorData.RpIdHash"/> and,
    /// when present, attested credential data are owned copies; its
    /// <see cref="AuthenticatorData.Extensions"/> remains a slice aliasing
    /// <paramref name="authenticatorData"/> (see the type-level remarks on lifetime). The caller
    /// owns and disposes the returned instance.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="readCredentialPublicKey"/> or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="authenticatorData"/> is truncated, carries an out-of-range length field, has
    /// trailing bytes not accounted for by its flags, or carries a credential public key that violates the
    /// WebAuthn L3 section 6.5.1 / 5.8.5 conformance clauses (a duplicate, missing, or disallowed COSE_Key
    /// label; an algorithm/curve mismatch; or a forbidden compressed EC point encoding).
    /// </exception>
    public static AuthenticatorData Read(ReadOnlyMemory<byte> authenticatorData, ReadCredentialPublicKeyDelegate readCredentialPublicKey, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(readCredentialPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        if(authenticatorData.Length < MinimumLength)
        {
            throw new Fido2FormatException($"Authenticator data is truncated: at least {MinimumLength} bytes were required but {authenticatorData.Length} were supplied.");
        }

        DigestValue rpIdHash = CopyRpIdHash(authenticatorData.Span[..RpIdHashLength], pool);
        try
        {
            var flags = new AuthenticatorDataFlags(authenticatorData.Span[RpIdHashLength]);
            uint signCount = BinaryPrimitives.ReadUInt32BigEndian(authenticatorData.Span.Slice(RpIdHashLength + FlagsLength, SignCountLength));

            ReadOnlyMemory<byte> remaining = authenticatorData[MinimumLength..];

            AttestedCredentialData? attestedCredentialData = null;
            if(flags.AttestedCredentialDataIncluded)
            {
                attestedCredentialData = ReadAttestedCredentialData(ref remaining, readCredentialPublicKey, pool);
            }

            ReadOnlyMemory<byte> extensions = ReadExtensions(remaining, flags.ExtensionDataIncluded);

            return new AuthenticatorData(rpIdHash, flags, signCount, attestedCredentialData, extensions);
        }
        catch
        {
            rpIdHash.Dispose();
            throw;
        }

        //Copies the wire rpIdHash slice into a pooled SHA-256-tagged carrier.
        static DigestValue CopyRpIdHash(ReadOnlySpan<byte> rpIdHash, MemoryPool<byte> pool)
        {
            IMemoryOwner<byte> owner = pool.Rent(rpIdHash.Length);
            try
            {
                rpIdHash.CopyTo(owner.Memory.Span);

                return new DigestValue(owner, CryptoTags.Sha256Digest);
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }

        //Parses the attested credential data structure at the start of `remaining` and advances
        //it past the consumed bytes, including the trailing COSE_Key the supplied delegate reads.
        static AttestedCredentialData ReadAttestedCredentialData(ref ReadOnlyMemory<byte> remaining, ReadCredentialPublicKeyDelegate readCredentialPublicKey, MemoryPool<byte> pool)
        {
            if(remaining.Length < AttestedCredentialDataHeaderLength)
            {
                throw new Fido2FormatException($"Attested credential data is truncated: {AttestedCredentialDataHeaderLength} bytes were required for the AAGUID and credential ID length but {remaining.Length} remain.");
            }

            var aaguid = new Guid(remaining.Span[..AaguidLength], bigEndian: true);
            int credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(remaining.Span.Slice(AaguidLength, CredentialIdLengthFieldLength));
            if(credentialIdLength > MaxCredentialIdLength)
            {
                throw new Fido2FormatException($"The credential ID length {credentialIdLength} exceeds the maximum of {MaxCredentialIdLength} bytes.");
            }

            remaining = remaining[AttestedCredentialDataHeaderLength..];
            if(remaining.Length < credentialIdLength)
            {
                throw new Fido2FormatException($"The credential ID is truncated: {credentialIdLength} bytes were required but {remaining.Length} remain.");
            }

            CredentialId credentialId = CredentialId.Create(remaining.Span[..credentialIdLength], pool);
            remaining = remaining[credentialIdLength..];

            try
            {
                CredentialPublicKeyReadResult keyResult = readCredentialPublicKey(remaining);
                if(keyResult.BytesConsumed <= 0 || keyResult.BytesConsumed > remaining.Length)
                {
                    throw new Fido2FormatException($"The credential public key reader reported an invalid consumed length of {keyResult.BytesConsumed} bytes against {remaining.Length} available.");
                }

                EnforceCredentialPublicKeyConformance(keyResult.CoseKey, keyResult.Labels);

                var attestedCredentialData = new AttestedCredentialData(aaguid, credentialId, keyResult.CoseKey);
                remaining = remaining[keyResult.BytesConsumed..];

                return attestedCredentialData;
            }
            catch
            {
                credentialId.Dispose();
                throw;
            }
        }

        //Enforces the WebAuthn L3 section 6.5.1 / 5.8.5 credential public key conformance clauses against
        //the parsed COSE_Key and the top-level labels the delegate reported, in clause order: no duplicate
        //label, exactly the allowed label set with every required label present, algorithm/curve
        //consistency, and the uncompressed-point requirement for the algorithms that carry it.
        static void EnforceCredentialPublicKeyConformance(CoseKey coseKey, IReadOnlyList<int> labels)
        {
            var seenLabels = new HashSet<int>();
            foreach(int label in labels)
            {
                if(!seenLabels.Add(label))
                {
                    throw new Fido2FormatException($"The credential public key carries the label {label} more than once.");
                }
            }

            IReadOnlyList<int> allowedLabels;
            IReadOnlyList<int> requiredLabels;
            try
            {
                allowedLabels = CoseKeyConformance.AllowedParameterLabels(coseKey.Kty);
                requiredLabels = CoseKeyConformance.RequiredParameterLabels(coseKey.Kty);
            }
            catch(ArgumentOutOfRangeException exception)
            {
                throw new Fido2FormatException($"The credential public key uses an unsupported key type {coseKey.Kty}.", exception);
            }

            foreach(int label in seenLabels)
            {
                if(!allowedLabels.Contains(label))
                {
                    throw new Fido2FormatException($"The credential public key carries the label {label}, which is not one of the parameters WebAuthn L3 section 6.5.1 permits for key type {coseKey.Kty}: only 'alg' plus the REQUIRED key-type parameters are allowed.");
                }
            }

            foreach(int requiredLabel in requiredLabels)
            {
                if(!seenLabels.Contains(requiredLabel))
                {
                    throw new Fido2FormatException($"The credential public key is missing the required label {requiredLabel} for key type {coseKey.Kty}.");
                }
            }

            if(coseKey.Alg is int alg)
            {
                if(!CoseKeyConformance.IsAlgorithmCurveConsistent(alg, coseKey.Kty, coseKey.Curve))
                {
                    string curveDescription = coseKey.Curve is int curve ? curve.ToString(System.Globalization.CultureInfo.InvariantCulture) : "(absent)";

                    throw new Fido2FormatException($"Algorithm {alg} is not consistent with key type {coseKey.Kty} and curve {curveDescription} per WebAuthn L3 section 5.8.5.");
                }

                if(RequiresUncompressedPoint(alg) && CoseKeyConformance.UsesCompressedPointEncoding(coseKey))
                {
                    throw new Fido2FormatException($"Algorithm {alg} MUST NOT use the compressed EC point form per WebAuthn L3 section 5.8.5.");
                }
            }

            //Determines whether the WebAuthn L3 section 5.8.5 algorithm/curve clause set requires
            //`algorithm` to use the uncompressed EC point form. EdDSA is exempt (it always uses a
            //compressed form in COSE); the RSA family and unrecognised algorithms carry no such
            //requirement here.
            static bool RequiresUncompressedPoint(int algorithm) => algorithm switch
            {
                WellKnownCoseAlgorithms.Es256 or WellKnownCoseAlgorithms.Es384 or WellKnownCoseAlgorithms.Es512
                    or WellKnownCoseAlgorithms.Esp256 or WellKnownCoseAlgorithms.Esp384 or WellKnownCoseAlgorithms.Esp512 => true,
                _ => false
            };
        }

        //Resolves the extensions slice from the unconsumed tail, enforcing that its presence
        //matches the ED flag: set requires at least one byte, clear forbids any trailing byte.
        static ReadOnlyMemory<byte> ReadExtensions(ReadOnlyMemory<byte> remaining, bool extensionDataIncluded)
        {
            if(extensionDataIncluded)
            {
                if(remaining.IsEmpty)
                {
                    throw new Fido2FormatException("The extension data flag is set but no extension bytes remain.");
                }

                return remaining;
            }

            if(!remaining.IsEmpty)
            {
                throw new Fido2FormatException($"Authenticator data has {remaining.Length} trailing byte(s) not accounted for by its flags.");
            }

            return ReadOnlyMemory<byte>.Empty;
        }
    }
}
