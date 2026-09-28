using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The library's default <see cref="ValidateDpopProofDelegate"/>
/// implementation. Performs the pure-validation checks RFC 9449 §4.3
/// mandates: structural parse, header validation (<c>typ</c>, <c>alg</c>,
/// <c>jwk</c>), JWS signature verification, claim checks (<c>htm</c>,
/// <c>htu</c>, <c>iat</c> skew, <c>nonce</c>, <c>ath</c>).
/// </summary>
/// <remarks>
/// <c>jti</c> replay tracking is the AS-side handler's responsibility —
/// see the remark on <see cref="ValidateDpopProofDelegate"/>.
/// </remarks>
public static class DpopProofValidator
{
    /// <summary>
    /// Validates a DPoP proof against the receiver's expectations.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "PublicKeyMemory created via PublicKeyFromJwk is disposed in the finally block of the verification try; the analyzer does not trace the catch-then-finally path correctly here.")]
    public static async ValueTask<DpopProofValidationResult> ValidateAsync(
        DpopProofValidationRequest request,
        VerificationDelegate verificationDelegate,
        DpopJwsPartParser parser,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        BaseMemoryPool memoryPool,
        TimeSpan iatSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //The length bound the library's JWS verification applies (Jws.DefaultMaxJwsLength), checked
        //before any split or decode: a longer proof is malformed input, answered as a failure rather
        //than raised as an exception from the verification below.
        if(request.Proof.Length > Jws.DefaultMaxJwsLength)
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.Malformed);
        }

        //Structural parse first — reject obviously malformed input cheaply.
        string[] parts = request.Proof.Split('.');
        if(parts.Length != 3
            || string.IsNullOrEmpty(parts[0])
            || string.IsNullOrEmpty(parts[1])
            || string.IsNullOrEmpty(parts[2]))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.Malformed);
        }

        DpopProofHeader header;
        DpopProofClaims claims;
        try
        {
            using IMemoryOwner<byte> headerBytes = base64UrlDecoder(parts[0], memoryPool);
            using IMemoryOwner<byte> payloadBytes = base64UrlDecoder(parts[1], memoryPool);
            header = parser.ParseHeader(headerBytes.Memory);
            claims = parser.ParseClaims(payloadBytes.Memory);
        }
        catch
        {
            //The proof is client-supplied wire input, structurally unverified at this point; any
            //decode/parse failure is a malformed proof rather than an internal fault.
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.Malformed);
        }

        //Header checks. The typ compares as the RFC 7515 §4.1.9 media type it is: case insensitive,
        //and with the implicit "application/" prefix when the wire value carries no '/' of its own —
        //the same comparison every other typ check in this library shares.
        if(!WellKnownMediaTypes.Jwt.IsDpopJwt(header.Typ))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidTyp);
        }

        //RFC 9449 §4.2 — DPoP proofs may be signed with any asymmetric
        //digital signature algorithm registered in IANA JOSE Algorithms,
        //excepting "none" and symmetric algorithms. The accepted set is
        //ECDSA variants, RSA-SHA2 PKCS#1, RSA-PSS, and EdDSA; the underlying
        //Jws.VerifyAsync dispatches the actual signature verification path
        //per algorithm via the existing cryptographic backends.
        if(string.IsNullOrEmpty(header.Alg) || !IsDpopProofAlg(header.Alg))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidAlg);
        }

        if(header.Jwk is null || header.Jwk.Count == 0)
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidJwk);
        }

        //RFC 9449 §4.2, jti: "The value MUST be assigned such that there is a negligible probability
        //that the same value will be assigned to any other DPoP proof used in the same context during
        //the time window of validity." An empty jti is a value every such proof could carry; it
        //identifies nothing the replay guard can track, so the proof is malformed.
        if(string.IsNullOrEmpty(claims.Jti))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.Malformed);
        }

        //RFC 9449 §8.1: nonce = 1*NQCHAR. An empty nonce matches no nonce the server provided.
        if(claims.Nonce is { Length: 0 })
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.NonceMismatch);
        }

        //RFC 9449 §4.2: the embedded JWK MUST be a public key. Reject a proof whose jwk
        //leaks private/symmetric material before reconstructing the key or verifying.
        if(DpopJwkUtilities.ContainsPrivateKeyMaterial(header.Jwk))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.JwkContainsPrivateKey);
        }

        //Reconstruct the proving public key from the embedded JWK. The
        //validator owns this material and disposes it after the verify call;
        //distinct from the resolver-owned key path
        //in [[jws-access-token-validator]] where the caller retains the
        //reference.
        PublicKeyMemory publicKey;
        try
        {
            publicKey = DpopJwkUtilities.PublicKeyFromJwk(
                header.Jwk, header.Alg, base64UrlDecoder, memoryPool);
        }
        catch
        {
            //header.Jwk is client-supplied wire input; any failure to materialize a key from it is an
            //invalid JWK rather than an internal fault.
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidJwk);
        }

        //RFC 7515 §5.2 step 8: "Validate the JWS Signature against the JWS Signing Input ... in the
        //manner defined for the algorithm being used, which MUST be accurately represented by the value
        //of the "alg" (algorithm) Header Parameter". The key reconstructed from the jwk fixes the
        //algorithm the verification runs under, so a declared alg that is not an algorithm of that key
        //(an RSA alg over an EC key, a curve other than the key's) does not accurately represent it and
        //is refused before any verification.
        if(!IsAlgorithmOfKey(header.Alg, publicKey.Tag.Get<CryptoAlgorithm>()))
        {
            publicKey.Dispose();

            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidAlg);
        }

        //Signature verification via JCose's Jws.VerifyAsync — composes the
        //library's existing JWS verification primitive (including the pooled
        //signing-input construction and RFC 8725 §3.11 length bound) instead
        //of duplicating those mechanics here.
        bool signatureValid;
        using(publicKey)
        {
            signatureValid = await Jws.VerifyAsync(
                request.Proof,
                base64UrlDecoder,
                memoryPool,
                publicKey,
                verificationDelegate,
                cancellationToken).ConfigureAwait(false);
        }

        if(!signatureValid)
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.SignatureFailed);
        }

        //RFC 9449 §4.3 item 8: "The htm claim matches the HTTP method of the current request." RFC
        //9110 §9.1: "The method token is case-sensitive", so the comparison is ordinal.
        if(!string.Equals(claims.Htm, request.HttpMethod, StringComparison.Ordinal))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.HtmMismatch);
        }

        //RFC 9449 §4.3 item 9, compared after the normalization its SHOULD names.
        if(!IsSameTargetUri(claims.Htu, request.HttpUrl))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.HtuMismatch);
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        if(!JwtTemporalChecks.IsNotStale(claims.Iat, now, iatSkew)
            || !JwtTemporalChecks.IsNotInFuture(claims.Iat, now, iatSkew))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.IatOutOfWindow);
        }

        //Nonce check, dispatched per receiver policy.
        if(request.NonceRequired)
        {
            if(claims.Nonce is null)
            {
                return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.NonceMissing);
            }

            if(request.ExpectedNonce is null
                || !string.Equals(claims.Nonce, request.ExpectedNonce, StringComparison.Ordinal))
            {
                return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.NonceMismatch);
            }
        }
        else if(claims.Nonce is not null
            && request.ExpectedNonce is not null
            && !string.Equals(claims.Nonce, request.ExpectedNonce, StringComparison.Ordinal))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.NonceMismatch);
        }

        //Access-token binding check (resource-server calls).
        if(request.AccessToken is not null)
        {
            string expectedAth = await ComputeAthAsync(request.AccessToken, base64UrlEncoder, memoryPool, cancellationToken).ConfigureAwait(false);
            if(claims.Ath is null || !string.Equals(claims.Ath, expectedAth, StringComparison.Ordinal))
            {
                return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.AthMismatch);
            }
        }

        //Re-derive the thumbprint from the embedded JWK for the success result.
        //The receiver's downstream code compares this against an access token's
        //cnf.jkt binding.
        string thumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(
            header.Jwk, base64UrlEncoder, memoryPool);

        return DpopProofValidationResult.Success(claims, thumbprint);
    }


    /// <summary>
    /// Computes the base64url-encoded SHA-256 of <paramref name="accessToken"/>
    /// per RFC 9449 §4.3 — the value that must appear in a resource-call
    /// proof's <c>ath</c> claim.
    /// </summary>
    /// <remarks>
    /// Routes through the registered <see cref="ComputeDigestDelegate"/> via
    /// <see cref="CryptographicKeyEvents.ComputeDigest"/> so this operation picks up
    /// the same observability and CBOM provenance stamping as every other digest
    /// in the library.
    /// </remarks>
    public static async ValueTask<string> ComputeAthAsync(
        string accessToken,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] accessTokenBytes = Encoding.ASCII.GetBytes(accessToken);
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            accessTokenBytes,
            outputByteLength: SHA256.HashSizeInBytes,
            tag: CryptoTags.Sha256Digest,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return base64UrlEncoder(digest.AsReadOnlySpan());
    }


    /// <summary>
    /// True when <paramref name="alg"/> is any RFC 9449 §4.2-supported
    /// asymmetric signature algorithm: ECDSA variants, RSA-SHA2 PKCS#1,
    /// RSA-PSS, or EdDSA. Symmetric algorithms and <c>none</c> are
    /// rejected per the spec's exclusion clause.
    /// </summary>
    private static bool IsDpopProofAlg(string alg) =>
        WellKnownJwaValues.IsEcdsa(alg)
        || WellKnownJwaValues.IsRs256(alg)
        || WellKnownJwaValues.IsRs384(alg)
        || WellKnownJwaValues.IsRs512(alg)
        || WellKnownJwaValues.IsPs256(alg)
        || WellKnownJwaValues.IsPs384(alg)
        || WellKnownJwaValues.IsPs512(alg)
        || WellKnownJwaValues.IsEdDsa(alg);


    /// <summary>
    /// Whether the declared <paramref name="alg"/> is an algorithm of the key reconstructed from the
    /// proof's <c>jwk</c>: <c>ES256</c> over P-256, <c>ES384</c> over P-384, <c>ES512</c> over P-521,
    /// <c>ES256K</c> over secp256k1, <c>EdDSA</c> over Ed25519, and the RSA PKCS#1 and PSS algorithms
    /// over an RSA key. The verification the validator runs is selected by the key, so an alg outside
    /// the key's family would otherwise be declared without being the algorithm that verified.
    /// </summary>
    /// <param name="alg">The proof header's <c>alg</c>.</param>
    /// <param name="keyAlgorithm">The algorithm the reconstructed public key is tagged with.</param>
    /// <returns><see langword="true"/> when the declared algorithm belongs to the key.</returns>
    private static bool IsAlgorithmOfKey(string alg, CryptoAlgorithm keyAlgorithm) =>
        (keyAlgorithm.Equals(CryptoAlgorithm.P256) && WellKnownJwaValues.IsEs256(alg))
        || (keyAlgorithm.Equals(CryptoAlgorithm.P384) && WellKnownJwaValues.IsEs384(alg))
        || (keyAlgorithm.Equals(CryptoAlgorithm.P521) && WellKnownJwaValues.IsEs512(alg))
        || (keyAlgorithm.Equals(CryptoAlgorithm.Secp256k1) && WellKnownJwaValues.IsEs256K(alg))
        || (keyAlgorithm.Equals(CryptoAlgorithm.Ed25519) && WellKnownJwaValues.IsEdDsa(alg))
        || ((keyAlgorithm.Equals(CryptoAlgorithm.Rsa2048) || keyAlgorithm.Equals(CryptoAlgorithm.Rsa4096))
            && (WellKnownJwaValues.IsRs256(alg) || WellKnownJwaValues.IsRs384(alg) || WellKnownJwaValues.IsRs512(alg)
                || WellKnownJwaValues.IsPs256(alg) || WellKnownJwaValues.IsPs384(alg) || WellKnownJwaValues.IsPs512(alg)));


    /// <summary>
    /// The URI components the <c>htu</c> comparison covers: scheme, host, port and path, never query
    /// or fragment.
    /// </summary>
    private static UriComponents TargetUriComponents { get; } =
        UriComponents.Scheme | UriComponents.Host | UriComponents.Port | UriComponents.Path;


    /// <summary>
    /// Whether the proof's <paramref name="presentedHtu"/> names the same target as
    /// <paramref name="expectedHtu"/>, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see>: item 9 "The
    /// htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring
    /// any query and fragment parts.", and "To reduce the likelihood of false negatives, servers SHOULD
    /// employ syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization
    /// (Section 6.2.3 of [RFC3986]) before comparing the htu claim." Both values are parsed as absolute
    /// <c>http</c> or <c>https</c> URIs. The parser lowercases the scheme and host, drops a default
    /// port and any userinfo, removes dot segments and gives an empty path the root; the scheme, host,
    /// port and path are then read with <see cref="UriFormat.SafeUnescaped"/>, which keeps the
    /// percent-encoding of a reserved character (and of <c>%</c> itself) and decodes every other one.
    /// The hexadecimal digits of each percent-encoding kept are uppercased, per RFC 3986 §6.2.2.1: "For
    /// all URIs, the hexadecimal digits within a percent-encoding triplet (e.g., "%3a" versus "%3A") are
    /// case-insensitive and therefore should be normalized to use uppercase letters for the digits A-F." The two
    /// strings are then compared ordinally, so the path's case stays significant, an encoded reserved
    /// character never equals its literal form, a host in Unicode and in punycode compare as written,
    /// and the query and fragment take no part.
    /// </summary>
    /// <param name="presentedHtu">The proof's <c>htu</c> claim.</param>
    /// <param name="expectedHtu">The target URI of the request being served.</param>
    /// <returns><see langword="true"/> when the two name the same target.</returns>
    private static bool IsSameTargetUri(string presentedHtu, string expectedHtu)
    {
        if(!Uri.TryCreate(presentedHtu, UriKind.Absolute, out Uri? presented)
            || !Uri.TryCreate(expectedHtu, UriKind.Absolute, out Uri? expected)
            || !IsHttpScheme(presented)
            || !IsHttpScheme(expected))
        {
            return false;
        }

        return string.Equals(NormalizedTarget(presented), NormalizedTarget(expected), StringComparison.Ordinal);
    }


    /// <summary>
    /// The form of a target URI the <c>htu</c> comparison of <see cref="IsSameTargetUri"/> reads: the
    /// normalized scheme, host, port and path of an absolute <c>http</c> or <c>https</c> URI, so a replay
    /// record kept per target (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449
    /// §11.1</see>) names one target by one string whatever its spelling. A value that is not such a URI
    /// is returned unchanged and compared as written.
    /// </summary>
    /// <param name="targetUri">The target URI of a served request.</param>
    /// <returns>The normalized target.</returns>
    internal static string NormalizeTargetUri(string targetUri) =>
        Uri.TryCreate(targetUri, UriKind.Absolute, out Uri? uri) && IsHttpScheme(uri)
            ? NormalizedTarget(uri)
            : targetUri;


    /// <summary>
    /// The scheme, host, port and path of <paramref name="uri"/> read with
    /// <see cref="UriFormat.SafeUnescaped"/>, with the hexadecimal digits of every percent-encoding
    /// left in them uppercased (RFC 3986 §6.2.2.1).
    /// </summary>
    /// <param name="uri">The parsed absolute URI.</param>
    /// <returns>The normalized target.</returns>
    private static string NormalizedTarget(Uri uri)
    {
        string target = uri.GetComponents(TargetUriComponents, UriFormat.SafeUnescaped);
        if(!target.Contains('%', StringComparison.Ordinal))
        {
            return target;
        }

        return string.Create(target.Length, target, static (destination, source) =>
        {
            source.AsSpan().CopyTo(destination);
            for(int i = 0; i + 2 < destination.Length; i++)
            {
                if(destination[i] == '%'
                    && char.IsAsciiHexDigit(destination[i + 1])
                    && char.IsAsciiHexDigit(destination[i + 2]))
                {
                    destination[i + 1] = char.ToUpperInvariant(destination[i + 1]);
                    destination[i + 2] = char.ToUpperInvariant(destination[i + 2]);
                    i += 2;
                }
            }
        });
    }


    /// <summary>Whether <paramref name="uri"/> is an <c>http</c> or <c>https</c> URI, the schemes an <c>htu</c> names.</summary>
    /// <param name="uri">The parsed absolute URI.</param>
    /// <returns><see langword="true"/> for the two HTTP schemes.</returns>
    private static bool IsHttpScheme(Uri uri) =>
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
        || string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal);
}
