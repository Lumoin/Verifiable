using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

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
/// Parses an SD-JWT from its wire format (tilde-separated) into the structured
/// <see cref="SdToken{T}"/> representation.
/// </summary>
/// <remarks>
/// Wired by the application to <c>SdJwtSerializer.ParseToken</c> from
/// <c>Verifiable.Json.Sd</c> with the appropriate decoder and pool.
/// </remarks>
/// <param name="sdJwt">The serialized SD-JWT string.</param>
/// <returns>The parsed token with issuer JWS, disclosures, and optional KB-JWT.</returns>
public delegate SdToken<string> ParseSdJwtTokenDelegate(string sdJwt);


/// <summary>
/// Computes the SD-JWT string that serves as input to the <c>sd_hash</c>
/// computation: the issuer JWS and disclosures with trailing tilde, but
/// without the KB-JWT.
/// </summary>
/// <remarks>
/// Wired by the application to <c>SdJwtSerializer.GetSdJwtForHashing</c> from
/// <c>Verifiable.Json.Sd</c> with the appropriate encoder.
/// </remarks>
/// <param name="token">The parsed SD-JWT token.</param>
/// <returns>The hash input string per RFC 9449 §4.3.</returns>
public delegate string ComputeSdJwtHashInputDelegate(SdToken<string> token);


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
    /// <param name="hashFunctionSelector">
    /// Selects the hash function based on the <c>_sd_alg</c> claim from the issuer payload.
    /// Wired to <see cref="DefaultHashFunctionSelector.Select"/>.
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
        HashFunctionSelector hashFunctionSelector,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vpToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialQueryId);
        ArgumentNullException.ThrowIfNull(parseSdJwtToken);
        ArgumentNullException.ThrowIfNull(computeHashInput);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(hashFunctionSelector);
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

        {
            string[] issuerParts = token.IssuerSigned.Split('.');
            using IMemoryOwner<byte> issuerPayloadBytes = decoder(issuerParts[1], pool);
            ReadOnlySpan<byte> issuerPayload = issuerPayloadBytes.Memory.Span;

            iss = JwkJsonReader.ExtractStringValue(issuerPayload, "iss"u8);
            sdAlg = JwkJsonReader.ExtractStringValue(issuerPayload, "_sd_alg"u8);
            jwkDict = JwkJsonReader.ExtractNestedObjectProperties(
                issuerPayload, "cnf"u8, "jwk"u8);
        }

        //Resolve the issuer's public key from the trust framework.
        PublicKeyMemory? issuerPublicKey = iss is not null ? resolveIssuerKey(iss) : null;

        bool credentialSignatureValid = false;
        if(issuerPublicKey is not null)
        {
            credentialSignatureValid = await Jws.VerifyAsync(
                token.IssuerSigned, decoder,
                static (ReadOnlySpan<byte> _) => (object?)null, pool,
                issuerPublicKey).ConfigureAwait(false);
        }

        bool kbJwtSignatureValid = false;
        string? kbNonce = null;
        string? kbAud = null;
        DateTimeOffset? kbIat = null;
        bool sdHashValid = false;

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
                holderPublicKey).ConfigureAwait(false);

            //Verify sd_hash using the algorithm specified by _sd_alg.
            if(claimedSdHash is not null && sdAlg is not null)
            {
                HashAlgorithmName algorithmName = WellKnownHashAlgorithms.ToHashAlgorithmName(sdAlg);
                HashFunction hashFunction = hashFunctionSelector(algorithmName);

                string hashInput = computeHashInput(token);
                byte[] hashBytes = hashFunction(Encoding.ASCII.GetBytes(hashInput));
                string computedSdHash = encoder(hashBytes);
                sdHashValid = string.Equals(
                    claimedSdHash, computedSdHash, StringComparison.Ordinal);
            }
        }

        //Collect disclosed claims from the parsed disclosures.
        var disclosedClaims = new Dictionary<string, string>();
        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            if(disclosure.ClaimName is not null)
            {
                disclosedClaims[disclosure.ClaimName] = disclosure.ClaimValue?.ToString() ?? "";
            }
        }

        return new VpTokenParsed
        {
            KbJwtNonce = kbNonce,
            KbJwtAud = kbAud,
            KbJwtIat = kbIat,
            KbJwtSignatureValid = kbJwtSignatureValid,
            CredentialSignatureValid = credentialSignatureValid,
            SdHashValid = sdHashValid,
            SessionTranscriptValid = true,
            ExtractedClaims = new Dictionary<string, IReadOnlyDictionary<string, string>>
            {
                [credentialQueryId] = disclosedClaims
            }
        };
    }
}
