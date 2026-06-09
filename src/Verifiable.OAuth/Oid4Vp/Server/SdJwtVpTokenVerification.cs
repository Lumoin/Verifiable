using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Resolves an issuer's public key from its identifier.
/// The application provides the implementation based on its trust framework
/// (e.g., JWKS endpoint, OpenID Federation, X.509 trust list).
/// </summary>
/// <param name="issuerId">The <c>iss</c> claim from the credential.</param>
/// <returns>
/// The issuer's public key, or <see langword="null"/> if the issuer is not trusted.
/// </returns>
public delegate PublicKeyMemory? ResolveIssuerKeyDelegate(string issuerId);


/// <summary>
/// Parses and cryptographically verifies an SD-JWT VP token with Key Binding JWT
/// per <see href="https://www.rfc-editor.org/rfc/rfc9901#section-4.3">RFC 9901 §4.3</see>
/// and <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OID4VP 1.0 §8.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// This class contains no serialization dependencies. JSON field extraction uses
/// <see cref="JwkJsonReader"/> (span-based UTF-8 scanning). SD-JWT wire format
/// parsing and hash input computation are supplied via delegates that the application
/// wires to <c>SdJwtSerializer</c> implementations in <c>Verifiable.Json.Sd</c>.
/// </para>
/// <para>
/// The verification sequence:
/// </para>
/// <list type="number">
///   <item><description>Parse SD-JWT wire format via <see cref="ParseSdJwtTokenDelegate"/>.</description></item>
///   <item><description>Base64url-decode the issuer JWT payload segment.</description></item>
///   <item><description>Extract <c>iss</c> and resolve the issuer's public key via <see cref="ResolveIssuerKeyDelegate"/>.</description></item>
///   <item><description>Verify the issuer credential signature via <see cref="Jws.VerifyAsync"/>.</description></item>
///   <item><description>Extract <c>cnf.jwk</c> and reconstruct the holder's public key.</description></item>
///   <item><description>Verify the KB-JWT signature against the holder key.</description></item>
///   <item><description>Extract KB-JWT claims (<c>nonce</c>, <c>aud</c>, <c>iat</c>, <c>sd_hash</c>).</description></item>
///   <item><description>Recompute <c>sd_hash</c> via <see cref="ComputeSdJwtHashInputDelegate"/> and compare.</description></item>
///   <item><description>Collect disclosed claims from the parsed disclosures.</description></item>
/// </list>
/// </remarks>
public static class SdJwtVpTokenVerification
{
    /// <summary>
    /// Verifies an SD-JWT VP token and returns the extracted, verified contents.
    /// </summary>
    /// <param name="vpToken">The serialized SD-JWT with disclosures and KB-JWT.</param>
    /// <param name="credentialQueryId">
    /// The DCQL credential query identifier that matched this token.
    /// Used as the key in <see cref="VpTokenParsed.ExtractedClaims"/>.
    /// </param>
    /// <param name="parseSdJwtToken">
    /// Delegate for parsing the SD-JWT wire format.
    /// Wired to <c>SdJwtSerializer.ParseToken</c>.
    /// </param>
    /// <param name="computeHashInput">
    /// Delegate for computing the <c>sd_hash</c> input string.
    /// Wired to <c>SdJwtSerializer.GetSdJwtForHashing</c>.
    /// </param>
    /// <param name="resolveIssuerKey">
    /// Application-provided delegate that resolves the issuer's public key.
    /// </param>
    /// <param name="computeDigest">
    /// Computes a digest. Wired to a provider-side implementation registered on
    /// <see cref="CryptographicKeyFactory"/> such as
    /// <c>MicrosoftEntropyFunctions.ComputeDigestAsync</c>. The algorithm is carried in
    /// the <see cref="Tag"/> argument constructed per-call from the credential's
    /// <c>_sd_alg</c> claim.
    /// </param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed and crypto-verified VP token contents.</returns>
    public static async ValueTask<VpTokenParsed> VerifyAsync(
        string vpToken,
        string credentialQueryId,
        ParseSdJwtTokenDelegate parseSdJwtToken,
        ComputeSdJwtHashInputDelegate computeHashInput,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ComputeDigestDelegate computeDigest,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        CommitmentReuseDetectionSeam? saltReuseSeam,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vpToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialQueryId);
        ArgumentNullException.ThrowIfNull(parseSdJwtToken);
        ArgumentNullException.ThrowIfNull(computeHashInput);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        //Parse the SD-JWT wire format into issuer JWS, disclosures, and KB-JWT.
        SdToken<string> token = parseSdJwtToken(vpToken);

        //Decode the issuer JWT payload and extract all fields synchronously
        //before any await boundaries (ReadOnlySpan cannot cross await).
        string? iss;
        string? sdAlg;
        Dictionary<string, object>? jwkDict;
        string? statusObject;

        {
            string[] issuerParts = token.IssuerSigned.Split('.');
            using IMemoryOwner<byte> issuerPayloadBytes = decoder(issuerParts[1], pool);
            ReadOnlySpan<byte> issuerPayload = issuerPayloadBytes.Memory.Span;

            iss = JwkJsonReader.ExtractStringValue(issuerPayload, "iss"u8);
            sdAlg = JwkJsonReader.ExtractStringValue(issuerPayload, "_sd_alg"u8);
            jwkDict = JwkJsonReader.ExtractNestedObjectProperties(
                issuerPayload, "cnf"u8, "jwk"u8);

            //IETF Token Status List section 6: the Referenced Token MAY carry a status claim with a
            //status_list reference. Slice the status object span here; parsing happens off-span below.
            statusObject = JwkJsonReader.ExtractObjectAsString(issuerPayload, "status"u8);
        }

        //The credential's status reference (idx/uri), surfaced for the verifier's revocation gate.
        StatusListReference? credentialStatus = ParseStatusListReference(statusObject);

        //Resolve the issuer's public key from the trust framework.
        PublicKeyMemory? issuerPublicKey = iss is not null ? resolveIssuerKey(iss) : null;

        bool credentialSignatureValid = false;
        if(issuerPublicKey is not null)
        {
            credentialSignatureValid = await Jws.VerifyAsync(
                token.IssuerSigned, decoder,
                static (ReadOnlySpan<byte> _) => (object?)null, pool,
                issuerPublicKey, cancellationToken).ConfigureAwait(false);
        }

        bool kbJwtSignatureValid = false;
        string? kbNonce = null;
        string? kbAud = null;
        DateTimeOffset? kbIat = null;
        bool sdHashValid = false;
        IReadOnlyList<string>? kbTransactionDataHashes = null;
        string? kbTransactionDataHashesAlg = null;

        if(token.HasKeyBinding && jwkDict is not null)
        {
            //Extract KB-JWT payload fields synchronously before signature verification.
            string? claimedSdHash;

            {
                string[] kbParts = token.KeyBinding!.Split('.');
                using IMemoryOwner<byte> kbPayloadBytes = decoder(kbParts[1], pool);
                ReadOnlySpan<byte> kbPayload = kbPayloadBytes.Memory.Span;

                kbNonce = JwkJsonReader.ExtractStringValue(kbPayload, "nonce"u8);
                kbAud = JwkJsonReader.ExtractStringValue(kbPayload, "aud"u8);
                claimedSdHash = JwkJsonReader.ExtractStringValue(kbPayload, "sd_hash"u8);

                if(JwkJsonReader.TryExtractLongValue(kbPayload, "iat"u8, out long iatEpoch))
                {
                    kbIat = DateTimeOffset.FromUnixTimeSeconds(iatEpoch);
                }

                //OID4VP 1.0 §8.4: optional transaction_data_hashes array bound
                //into the KB-JWT when the Authorization Request carried a
                //transaction_data parameter.
                kbTransactionDataHashes = JwkJsonReader.ExtractStringArrayProperty(
                    kbPayload, "transaction_data_hashes"u8);
                kbTransactionDataHashesAlg = JwkJsonReader.ExtractStringValue(
                    kbPayload, "transaction_data_hashes_alg"u8);
            }

            //Reconstruct the holder's public key from the JWK dictionary.
            var (algorithm, purpose, scheme, keyBytesOwner) =
                CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                    jwkDict, pool, decoder);
            Tag holderTag = Tag.Create(
                (typeof(CryptoAlgorithm), algorithm),
                (typeof(Purpose), purpose),
                (typeof(EncodingScheme), scheme));
            using PublicKeyMemory holderPublicKey = new(keyBytesOwner, holderTag);

            //Verify KB-JWT signature against the holder key from cnf.
            kbJwtSignatureValid = await Jws.VerifyAsync(
                token.KeyBinding!, decoder,
                static (ReadOnlySpan<byte> _) => (object?)null, pool,
                holderPublicKey, cancellationToken).ConfigureAwait(false);

            //Verify sd_hash using the algorithm specified by _sd_alg.
            if(claimedSdHash is not null && sdAlg is not null)
            {
                HashAlgorithmName algorithmName = WellKnownHashAlgorithms.ToHashAlgorithmName(sdAlg);
                int digestByteLength = WellKnownHashAlgorithms.GetSizeBytes(algorithmName);
                Tag digestTag = new(new Dictionary<Type, object>
                {
                    [typeof(HashAlgorithmName)] = algorithmName,
                    [typeof(Purpose)] = Purpose.Digest
                });

                string hashInput = computeHashInput(token);
                int inputByteCount = Encoding.ASCII.GetByteCount(hashInput);
                using IMemoryOwner<byte> inputOwner = pool.Rent(inputByteCount);
                Span<byte> inputBytes = inputOwner.Memory.Span[..inputByteCount];
                Encoding.ASCII.GetBytes(hashInput, inputBytes);

                (DigestValue digest, _) = await computeDigest(
                    new ReadOnlySequence<byte>(inputOwner.Memory[..inputByteCount]),
                    digestByteLength, digestTag, pool, null, cancellationToken).ConfigureAwait(false);

                using(digest)
                {
                    string computedSdHash = encoder(digest.AsReadOnlySpan());
                    sdHashValid = string.Equals(
                        claimedSdHash, computedSdHash, StringComparison.Ordinal);
                }
            }
        }

        //Collect disclosed claims from the parsed disclosures, and observe the shortest salt length
        //(the verifier-side salt-length signal — RFC 9901 §9.3).
        var disclosedClaims = new Dictionary<string, string>();
        var disclosedByPath = new Dictionary<CredentialPath, object?>();
        int? minimumSaltLength = null;
        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            int saltLength = disclosure.Salt.Length;
            if(minimumSaltLength is null || saltLength < minimumSaltLength)
            {
                minimumSaltLength = saltLength;
            }

            if(disclosure.ClaimName is not null)
            {
                disclosedClaims[disclosure.ClaimName] = disclosure.ClaimValue?.ToString() ?? "";
                //Engine-facing view: full canonical path with the native disclosed value.
                disclosedByPath[CredentialPath.Root.Append(disclosure.ClaimName)] = disclosure.ClaimValue;
            }
        }

        //Salt-reuse detection (opt-in): commit to each disclosure salt and ask the application store.
        //Only true when a seam was wired and a reuse was found — the verifier mirror of DPoP-JTI replay.
        bool saltReused = false;
        if(saltReuseSeam is not null)
        {
            var commitments = new List<DigestValue>();
            try
            {
                foreach(SdDisclosure disclosure in token.Disclosures)
                {
                    commitments.Add(disclosure.Salt.ComputeCommitment(
                        saltReuseSeam.HashFunction, saltReuseSeam.HashOutputByteLength, saltReuseSeam.HashTag, pool));
                }

                IReadOnlyList<DigestValue> reused = await CommitmentReuseDetection.DetectAsync(
                    commitments, saltReuseSeam.IsSeen, saltReuseSeam.Record, cancellationToken).ConfigureAwait(false);
                saltReused = reused.Count > 0;
            }
            finally
            {
                foreach(DigestValue commitment in commitments)
                {
                    commitment.Dispose();
                }
            }
        }

        return new VpTokenParsed
        {
            KbJwtNonce = kbNonce,
            KbJwtAud = kbAud,
            KbJwtIat = kbIat,
            KbJwtSignatureValid = kbJwtSignatureValid,
            CredentialSignatureValid = credentialSignatureValid,
            CredentialIssuer = iss,
            CredentialStatus = credentialStatus,
            SdHashValid = sdHashValid,
            SessionTranscriptValid = true,
            KbJwtTransactionDataHashes = kbTransactionDataHashes,
            KbJwtTransactionDataHashesAlg = kbTransactionDataHashesAlg,
            ExtractedClaims = new Dictionary<string, IReadOnlyDictionary<string, string>>
            {
                [credentialQueryId] = disclosedClaims
            },
            DisclosedClaimPaths = new Dictionary<string, IReadOnlyDictionary<CredentialPath, object?>>(StringComparer.Ordinal)
            {
                [credentialQueryId] = disclosedByPath
            },
            MinimumDisclosureSaltLengthBytes = minimumSaltLength,
            SaltReused = saltReused
        };
    }


    //Parses the IETF Token Status List reference (status.status_list = {idx, uri}) from the
    //already-sliced status object JSON. Span-based throughout to keep this class serialization-free;
    //the two small re-encodes only run when a status claim is actually present.
    internal static StatusListReference? ParseStatusListReference(string? statusObjectJson)
    {
        if(statusObjectJson is null)
        {
            return null;
        }

        string? statusListObject = JwkJsonReader.ExtractObjectAsString(
            Encoding.UTF8.GetBytes(statusObjectJson), "status_list"u8);
        if(statusListObject is null)
        {
            return null;
        }

        ReadOnlySpan<byte> statusListBytes = Encoding.UTF8.GetBytes(statusListObject);
        string? uri = JwkJsonReader.ExtractStringValue(statusListBytes, "uri"u8);
        if(uri is null
            || !JwkJsonReader.TryExtractLongValue(statusListBytes, "idx"u8, out long index)
            || index < 0
            || index > int.MaxValue)
        {
            return null;
        }

        return new StatusListReference((int)index, uri);
    }
}
