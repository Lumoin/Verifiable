using System.Buffers;
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
/// <c>htu</c>, <c>iat</c> skew, <c>nonce</c>, <c>ath</c>). The <c>alg</c> is held
/// to the identifiers a proof may be signed under and, when the request names
/// them, to the receiver's <see cref="DpopProofValidationRequest.AcceptedAlgorithms"/>;
/// a proof is accepted only under an identifier the validator binds to the family of
/// the public key its <c>jwk</c> carries. The signature is verified in one of two forms: through the
/// provider the cryptographic function registry serves for the tag of the public key reconstructed from
/// the <c>jwk</c> (the overload without a <see cref="VerificationDelegate"/>), or through the
/// <see cref="VerificationDelegate"/> the caller binds (the overload that takes one).
/// </summary>
/// <remarks>
/// <para>
/// The validator binds <c>ES256</c> to P-256, <c>ES384</c> to P-384, <c>ES512</c> to P-521,
/// <c>ES256K</c> to secp256k1, <c>EdDSA</c> and <c>Ed25519</c> to Ed25519, and the RSA PKCS#1 v1.5
/// and RSA-PSS identifiers to RSA. An identifier the policy names but no family is bound to, the
/// Brainpool ECDSA and the ML-DSA identifiers among them, is refused as
/// <see cref="DpopProofValidationFailureReason.InvalidAlg"/> for want of a binding.
/// </para>
/// <para>
/// An RSA public key reconstructed from a <c>jwk</c> is tagged by the proof's <c>alg</c>
/// (<see cref="DpopJwkUtilities.PublicKeyFromJwk"/>). Under the overload without a
/// <see cref="VerificationDelegate"/> the tag selects the registry's provider, so the scheme that verifies is the scheme
/// the <c>alg</c> names: under <c>RS256</c> the size tag the registry serves as RSASSA-PKCS1-v1_5 with SHA-256, under
/// each other RSA identifier the tag of its own scheme; a proof whose RSA <c>alg</c> names one scheme and whose
/// signature is of another does not verify through the registry. Under the overload that takes a
/// <see cref="VerificationDelegate"/> the bound primitive receives the public key's octets and no algorithm, so it
/// verifies under the scheme it implements, whatever the <c>alg</c> names.
/// </para>
/// <para>
/// The <c>jwk</c> is held to the public key that verifies. A <c>use</c> member other than the string <c>sig</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 Section 4.2</see>: "The "use" value is a
/// case-sensitive string."), of whatever JSON type the parser keeps it in, is an invalid JWK under either form;
/// <c>key_ops</c>, a JSON array the parser does not keep, is not read. The thumbprint of the presented
/// <c>jwk</c> must equal the thumbprint of the canonical JWK of the public key reconstructed from it
/// (<see href="https://www.rfc-editor.org/rfc/rfc7638#section-3">RFC 7638 Section 3</see>), so one public key carries
/// one thumbprint: a <c>jwk</c> re-spelled around that public key is refused as
/// <see cref="DpopProofValidationFailureReason.InvalidJwk"/> before the signature is verified, and the success result
/// carries that one thumbprint.
/// </para>
/// <para>
/// The two forms divide the hosts. A host whose providers are registered in
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> calls the overload without a
/// <see cref="VerificationDelegate"/>: the public key's tag (its <see cref="CryptoAlgorithm"/> and
/// <see cref="Purpose"/>) selects the provider, so one host verifies every key family it registered, and a family
/// the registry does not serve is refused as <see cref="DpopProofValidationFailureReason.SignatureFailed"/>. A host
/// that binds its own primitive calls the overload that takes a <see cref="VerificationDelegate"/>, which then
/// verifies every proof whatever its family, so that primitive must verify every family the host accepts. Both
/// overloads run the one body; only the verification function differs.
/// </para>
/// <para>
/// <c>jti</c> replay tracking is the AS-side handler's responsibility —
/// see the remark on <see cref="ValidateDpopProofDelegate"/>.
/// </para>
/// </remarks>
public static class DpopProofValidator
{
    /// <summary>
    /// Validates a DPoP proof against the receiver's expectations, verifying its signature with
    /// <paramref name="verificationDelegate"/>: the form for a host that binds its own primitive to every DPoP key
    /// family it accepts. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>,
    /// check 6: "The JWT signature verifies with the public key contained in the jwk JOSE Header Parameter."
    /// </summary>
    /// <remarks>
    /// <para>
    /// The delegate verifies every proof whatever the family of its public key, so a proof under a family the host's
    /// primitive does not verify is refused as <see cref="DpopProofValidationFailureReason.SignatureFailed"/>. A host
    /// whose providers are registered calls the overload without a delegate instead, which selects the provider by the
    /// public key's tag.
    /// </para>
    /// <para>
    /// The bound primitive receives the public key's octets only, never the proof's <c>alg</c> or the public key's tag,
    /// and verifies under the scheme it implements. An RSA <c>alg</c> names a scheme
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">RFC 7518 Section 3.3</see>, RSASSA-PKCS1-v1_5;
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Section 3.5</see>, RSASSA-PSS), and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see> holds the library to it:
    /// "The library MUST ensure that the "alg" or "enc" header specifies the same algorithm that is used for the
    /// cryptographic operation." This validator does not hold a bound primitive to the scheme the <c>alg</c> names, so
    /// a host binding one RSA primitive must accept only the one RSA identifier that primitive verifies: it narrows its
    /// list to that identifier through
    /// <see cref="Verifiable.OAuth.Server.AuthorizationServerCryptography.ResolveSupportedSigningAlgorithmsAsync"/>;
    /// otherwise a proof under another RSA identifier is verified under the primitive's scheme rather than the one its
    /// <c>alg</c> names.
    /// </para>
    /// </remarks>
    /// <param name="request">The proof and what the receiver expects of it.</param>
    /// <param name="verificationDelegate">The signature verification every proof is checked with.</param>
    /// <param name="parser">Reads the proof's header and claims.</param>
    /// <param name="base64UrlEncoder">Encodes the thumbprint and the <c>ath</c> digest.</param>
    /// <param name="base64UrlDecoder">Decodes the proof's segments and the <c>jwk</c> members.</param>
    /// <param name="timeProvider">The clock the <c>iat</c> window is checked against.</param>
    /// <param name="memoryPool">The pool decoded octets and the reconstructed public key are rented from.</param>
    /// <param name="iatSkew">How far the proof's <c>iat</c> may lie before or after the current instant.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validated claims and thumbprint, or the reason the proof is refused.</returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    public static ValueTask<DpopProofValidationResult> ValidateAsync(
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

        return ValidateCoreAsync(
            request, verificationDelegate, parser, base64UrlEncoder, base64UrlDecoder, timeProvider, memoryPool, iatSkew, cancellationToken);
    }


    /// <summary>
    /// Validates a DPoP proof against the receiver's expectations, verifying its signature through the provider
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> serves for the tag of the public key
    /// reconstructed from the proof's <c>jwk</c>: the form for a host whose providers are registered, so one host
    /// verifies every key family it registered. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449
    /// Section 4.3</see>, check 6: "The JWT signature verifies with the public key contained in the jwk JOSE Header
    /// Parameter."
    /// </summary>
    /// <remarks>
    /// The public key's <see cref="Tag"/> names its <see cref="CryptoAlgorithm"/> and <see cref="Purpose"/>, and that
    /// pair selects the verification function, as the registry overloads of <see cref="Jws"/>'s <c>VerifyAsync</c>
    /// select it. A pair the registry does not serve is a verification that fails, so the proof is refused as
    /// <see cref="DpopProofValidationFailureReason.SignatureFailed"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>: "If any of the listed
    /// steps fails, then the signature or MAC cannot be validated."). A registry that has not been initialized is the
    /// application's composition, never the presented proof, so it throws before any check runs.
    /// </remarks>
    /// <param name="request">The proof and what the receiver expects of it.</param>
    /// <param name="parser">Reads the proof's header and claims.</param>
    /// <param name="base64UrlEncoder">Encodes the thumbprint and the <c>ath</c> digest.</param>
    /// <param name="base64UrlDecoder">Decodes the proof's segments and the <c>jwk</c> members.</param>
    /// <param name="timeProvider">The clock the <c>iat</c> window is checked against.</param>
    /// <param name="memoryPool">The pool decoded octets and the reconstructed public key are rented from.</param>
    /// <param name="iatSkew">How far the proof's <c>iat</c> may lie before or after the current instant.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validated claims and thumbprint, or the reason the proof is refused.</returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.IsInitialized"/> is
    /// <see langword="false"/>, before any check runs.
    /// </exception>
    public static ValueTask<DpopProofValidationResult> ValidateAsync(
        DpopProofValidationRequest request,
        DpopJwsPartParser parser,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        BaseMemoryPool memoryPool,
        TimeSpan iatSkew,
        CancellationToken cancellationToken) =>
        ValidateCoreAsync(
            request, verificationDelegate: null, parser, base64UrlEncoder, base64UrlDecoder, timeProvider, memoryPool, iatSkew, cancellationToken);


    /// <summary>
    /// The one body both <c>ValidateAsync</c> overloads run: every check of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see> this validator holds a
    /// proof to, the signature verified with <paramref name="verificationDelegate"/> when the caller binds one and
    /// through the registry's provider for the reconstructed public key's tag when it is <see langword="null"/>.
    /// </summary>
    /// <param name="request">The proof and what the receiver expects of it.</param>
    /// <param name="verificationDelegate">The caller's verification, or <see langword="null"/> to resolve it by the public key's tag.</param>
    /// <param name="parser">Reads the proof's header and claims.</param>
    /// <param name="base64UrlEncoder">Encodes the thumbprint and the <c>ath</c> digest.</param>
    /// <param name="base64UrlDecoder">Decodes the proof's segments and the <c>jwk</c> members.</param>
    /// <param name="timeProvider">The clock the <c>iat</c> window is checked against.</param>
    /// <param name="memoryPool">The pool decoded octets and the reconstructed public key are rented from.</param>
    /// <param name="iatSkew">How far the proof's <c>iat</c> may lie before or after the current instant.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validated claims and thumbprint, or the reason the proof is refused.</returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument other than <paramref name="verificationDelegate"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="verificationDelegate"/> is <see langword="null"/> and the registry has not been initialized.
    /// </exception>
    private static async ValueTask<DpopProofValidationResult> ValidateCoreAsync(
        DpopProofValidationRequest request,
        VerificationDelegate? verificationDelegate,
        DpopJwsPartParser parser,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        BaseMemoryPool memoryPool,
        TimeSpan iatSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //The registry form resolves its verification from the registry, which is the application's composition: an
        //uninitialized registry throws before any check, so it is never answered as a property of the presented proof.
        if(verificationDelegate is null && !CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.IsInitialized)
        {
            throw new InvalidOperationException(
                "The cryptographic function registry has not been initialized. " +
                "Call CryptoFunctionRegistry.Initialize() during application startup.");
        }

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

        //RFC 9449 Section 4.2: the alg is "An identifier for a JWS asymmetric digital signature
        //algorithm from [IANA.JOSE.ALGS]. It MUST NOT be none or an identifier for a symmetric
        //algorithm (Message Authentication Code (MAC))." That structural rule is the one predicate
        //the DPoP header factory and the client's DPoP key are held to as well.
        if(string.IsNullOrEmpty(header.Alg) || !IsDpopProofAlg(header.Alg))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidAlg);
        }

        //RFC 9449 Section 4.3, check 5: the alg "is supported by the application, and is acceptable
        //per local policy". The receiver's list, when it names one, is that policy; each entry is
        //compared exactly, as a JWS alg value is case-sensitive (RFC 7515 Section 4.1.1), and an
        //empty list accepts no proof.
        if(request.AcceptedAlgorithms is IReadOnlyList<string> acceptedAlgorithms
            && !acceptedAlgorithms.Contains(header.Alg, StringComparer.Ordinal))
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
        //leaks private/symmetric material before reconstructing the public key or verifying.
        if(DpopJwkUtilities.ContainsPrivateKeyMaterial(header.Jwk))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.JwkContainsPrivateKey);
        }

        //RFC 7517 Section 4.2: "The "use" (public key use) parameter identifies the intended use of the public key."
        //A jwk whose use is present and is not the string "sig" (the library's parser keeps a use of another JSON type as
        //its raw JSON text) declares no public key for verifying the signature check 6 names, so it is an invalid JWK under either
        //form, before any public key is reconstructed from it.
        if(header.Jwk.TryGetValue(WellKnownJwkMemberNames.Use, out string? declaredUse) && !WellKnownJwkValues.IsUseSig(declaredUse))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidJwk);
        }

        //Reconstruct the proving public key from the embedded JWK. The validator owns this material and
        //disposes it after the verify call; a jwk no public key is reconstructed from is an invalid JWK.
        bool signatureValid;
        string thumbprint;
        using(PublicKeyMemory? publicKey = ReconstructPublicKey(
            header.Jwk, header.Alg, base64UrlEncoder, base64UrlDecoder, memoryPool, out string? canonicalThumbprint))
        {
            if(publicKey is null)
            {
                return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidJwk);
            }

            //RFC 7515 Section 5.2 step 8: "Validate the JWS Signature against the JWS Signing Input ... in the
            //manner defined for the algorithm being used, which MUST be accurately represented by the value
            //of the "alg" (algorithm) Header Parameter". The public key reconstructed from the jwk fixes the
            //algorithm the verification runs under, so a declared alg that is not an algorithm of that public key
            //(an RSA alg over an EC public key, a curve other than the public key's) does not accurately represent it
            //and is refused before any verification.
            if(!IsAlgorithmOfKey(header.Alg, publicKey.Tag.Get<CryptoAlgorithm>()))
            {
                return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidAlg);
            }

            //RFC 7638 Section 3: the thumbprint is computed over "a JSON object [RFC7159] containing only the required
            //members of a JWK representing the key", "itself a legal JWK representation of the key". The presented
            //jwk's thumbprint names the public key that verifies only when the jwk is that representation: a jwk
            //re-spelled around the same public key (crv absent, a y off the curve of the same parity, an n with a
            //leading zero octet, a coordinate or an x of another length) names it under a thumbprint of its own, so
            //it is an invalid JWK, refused before the signature is verified.
            thumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(header.Jwk, base64UrlEncoder, memoryPool);
            if(canonicalThumbprint is null || !string.Equals(canonicalThumbprint, thumbprint, StringComparison.Ordinal))
            {
                return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidJwk);
            }

            //Signature verification via JCose's Jws.VerifyAsync, which composes the pooled signing-input
            //construction and this library's own length bound: with the caller's verification when it binds
            //one, otherwise through the registry overload, which selects the provider by the public key's tag
            //and answers a pair the registry does not serve as not verified.
            signatureValid = verificationDelegate switch
            {
                VerificationDelegate boundVerification => await Jws.VerifyAsync(
                    request.Proof,
                    base64UrlDecoder,
                    memoryPool,
                    publicKey,
                    boundVerification,
                    cancellationToken).ConfigureAwait(false),
                null => await Jws.VerifyAsync(
                    request.Proof,
                    base64UrlDecoder,
                    memoryPool,
                    publicKey,
                    cancellationToken).ConfigureAwait(false)
            };
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

        //The success result carries the thumbprint of the public key that verified, the presented jwk's own, which
        //the check above held equal to the thumbprint of that public key's canonical JWK. The receiver's downstream
        //code compares it against an access token's cnf.jkt binding.
        return DpopProofValidationResult.Success(claims, thumbprint);
    }


    /// <summary>
    /// Reconstructs the public key a proof's <c>jwk</c> carries (<see cref="DpopJwkUtilities.PublicKeyFromJwk"/>),
    /// tagged with its algorithm and purpose, and the thumbprint of that public key's canonical JWK; or answers
    /// <see langword="null"/> when no public key is reconstructed from it: the <c>jwk</c> is the client's wire input, so a
    /// failure to reconstruct a public key from it is an invalid JWK, never an internal fault. The caller owns and
    /// disposes the public key it receives.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="DpopJwkUtilities.PublicKeyFromJwk"/> tags an RSA public key by the proof's <c>alg</c>: the size tag
    /// under <c>RS256</c>, and the tag of the scheme the <c>alg</c> names under each other RSA identifier
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">RFC 7518 Section 3.3</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Section 3.5</see>). Under the overload without a
    /// <see cref="VerificationDelegate"/> the tag selects the registry's provider, so the registry verifies under the
    /// scheme the <c>alg</c> names
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "The library MUST
    /// ensure that the "alg" or "enc" header specifies the same algorithm that is used for the cryptographic
    /// operation."); under the overload that takes one, the bound primitive receives the octets without the tag and
    /// verifies under the scheme it implements.
    /// </para>
    /// <para>
    /// The canonical thumbprint is computed from the public key as reconstructed and tagged, through
    /// <see cref="DpopJwkUtilities.ComputeThumbprint"/>, whose converter renders the P-256, P-384, P-521, secp256k1,
    /// Ed25519 and RSA public keys the validator binds, an RSA public key under its size tag or a scheme tag alike; it is
    /// <see langword="null"/> where no canonical JWK is rendered, and for an Ed25519 public key that is not 32 octets
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5">RFC 8032 Section 5.1.5</see>: "The 32-byte public
    /// key is generated by the following steps."), whose rendering would carry the presented octets unchanged.
    /// </para>
    /// </remarks>
    /// <param name="jwk">The proof header's <c>jwk</c> members.</param>
    /// <param name="alg">The proof header's <c>alg</c>.</param>
    /// <param name="base64UrlEncoder">Encodes the canonical JWK's members for its thumbprint.</param>
    /// <param name="base64UrlDecoder">Decodes the <c>jwk</c> members.</param>
    /// <param name="memoryPool">The pool the public key material is rented from.</param>
    /// <param name="canonicalThumbprint">The thumbprint of the reconstructed public key's canonical JWK, or <see langword="null"/>.</param>
    /// <returns>The reconstructed public key, or <see langword="null"/>.</returns>
    private static PublicKeyMemory? ReconstructPublicKey(
        IReadOnlyDictionary<string, string> jwk,
        string alg,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool memoryPool,
        out string? canonicalThumbprint)
    {
        canonicalThumbprint = null;
        PublicKeyMemory? reconstructed = null;
        try
        {
            reconstructed = DpopJwkUtilities.PublicKeyFromJwk(jwk, alg, base64UrlDecoder, memoryPool);
            canonicalThumbprint = ComputeCanonicalThumbprint(reconstructed, alg, base64UrlEncoder, memoryPool);

            return reconstructed;
        }
        catch
        {
            //Any failure to reconstruct the client's jwk is an invalid JWK; the material rented so far is returned to
            //the pool.
            reconstructed?.Dispose();
            canonicalThumbprint = null;

            return null;
        }
    }


    /// <summary>
    /// The thumbprint of <paramref name="publicKey"/>'s canonical JWK
    /// (<see cref="DpopJwkUtilities.ComputeThumbprint"/>), or <see langword="null"/> where its converter renders no JWK
    /// of that public key or where an Ed25519 public key is not of the 32 octets
    /// <see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5">RFC 8032 Section 5.1.5</see> gives one.
    /// </summary>
    /// <param name="publicKey">The public key as reconstructed from the <c>jwk</c> and tagged.</param>
    /// <param name="alg">The proof header's <c>alg</c>.</param>
    /// <param name="base64UrlEncoder">Encodes the canonical JWK's members.</param>
    /// <param name="memoryPool">The pool the digest is computed in.</param>
    /// <returns>The canonical thumbprint, or <see langword="null"/>.</returns>
    private static string? ComputeCanonicalThumbprint(
        PublicKeyMemory publicKey, string alg, EncodeDelegate base64UrlEncoder, BaseMemoryPool memoryPool)
    {
        if(publicKey.Tag.Get<CryptoAlgorithm>().Equals(CryptoAlgorithm.Ed25519)
            && publicKey.AsReadOnlySpan().Length != Ed25519PublicKeyOctetCount)
        {
            return null;
        }

        try
        {
            return DpopJwkUtilities.ComputeThumbprint(publicKey, alg, base64UrlEncoder, memoryPool);
        }
        catch
        {
            //A public key the converter renders no JWK of has no canonical thumbprint; the identity check then
            //refuses the jwk, after the alg check has answered a family the validator binds no identifier to.
            return null;
        }
    }


    /// <summary>
    /// The octet count of an Ed25519 public key,
    /// <see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5">RFC 8032 Section 5.1.5</see>: "The 32-byte public
    /// key is generated by the following steps."
    /// </summary>
    private static int Ed25519PublicKeyOctetCount => 32;


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
    /// True when <paramref name="alg"/> is an identifier a DPoP proof may be signed under: one of the JOSE catalogue's
    /// asymmetric JWS signature identifiers, the structural rule the validator holds a proof to from
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, "An identifier for a
    /// JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]. It MUST NOT be none or an identifier for a
    /// symmetric algorithm (Message Authentication Code (MAC))." It is
    /// <see cref="WellKnownJwaValues.IsAsymmetricSignatureAlgorithm(string)"/>, the one predicate the DPoP header factory
    /// (<see cref="JwtHeader"/>'s <c>ForDpop</c>), <see cref="DpopKey"/> and the servers' proof validation hold a proof's
    /// <c>alg</c> to, so what may be built and what may be received agree. Each identifier is sourced at its own
    /// catalogue entry; the Brainpool ECDSA and the ML-DSA identifiers come from the drafts their entries cite.
    /// </summary>
    /// <remarks>
    /// Which of these identifiers a server accepts is not this predicate's: it is the server's policy, carried to the
    /// validator as <see cref="DpopProofValidationRequest.AcceptedAlgorithms"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: "is supported
    /// by the application, and is acceptable per local policy"), and a proof is accepted only under an identifier the
    /// validator binds to the public key its <c>jwk</c> carries (<see cref="IsAlgorithmOfKey"/>). Each identifier is
    /// compared exactly, as a JWS <c>alg</c> value is case-sensitive
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>).
    /// </remarks>
    /// <param name="alg">The <c>alg</c> identifier.</param>
    /// <returns><see langword="true"/> when the identifier is one a DPoP proof may be signed under.</returns>
    internal static bool IsDpopProofAlg(string alg) => WellKnownJwaValues.IsAsymmetricSignatureAlgorithm(alg);


    /// <summary>
    /// Whether the declared <paramref name="alg"/> is an algorithm of the public key reconstructed from the
    /// proof's <c>jwk</c>: <c>ES256</c> over P-256, <c>ES384</c> over P-384, <c>ES512</c> over P-521,
    /// <c>ES256K</c> over secp256k1, <c>EdDSA</c> and the fully-specified <c>Ed25519</c> over Ed25519, and each RSA
    /// identifier over the RSA public key tagged with the scheme it names. The verification the validator runs is
    /// selected by the public key, so an alg outside the public key's family would otherwise be declared without being
    /// the algorithm that verified.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-5">RFC 9864 Section 5</see>: "the representation for
    /// a key used with the Ed25519 algorithm is the same as that specified in [RFC8037], except that the "alg" value
    /// would be Ed25519 rather than EdDSA, if included", so one Ed25519 public key carries either identifier.
    /// </summary>
    /// <remarks>
    /// The RSA arm is the library's one table, <see cref="JwsAlgorithmKeyBinding.IsAlgorithmOfKey(string?, CryptoAlgorithm)"/>:
    /// <c>RS256</c> over the size tags <see cref="CryptoAlgorithm.Rsa2048"/> and <see cref="CryptoAlgorithm.Rsa4096"/>,
    /// and each other RSA identifier over the scheme tag <see cref="DpopJwkUtilities.PublicKeyFromJwk"/> gives an RSA public key under
    /// it, so the scheme the registry serves for the public key is the scheme the <c>alg</c> names
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "each key MUST be
    /// used with exactly one algorithm, and this MUST be checked when the cryptographic operation is performed."). The
    /// elliptic curve and Ed25519 arms stay this validator's own: the shared table also binds the Brainpool ECDSA and the
    /// ML-DSA identifiers, which this validator binds to no public key family.
    /// </remarks>
    /// <param name="alg">The proof header's <c>alg</c>.</param>
    /// <param name="keyAlgorithm">The algorithm the reconstructed public key is tagged with.</param>
    /// <returns><see langword="true"/> when the declared algorithm belongs to the public key.</returns>
    private static bool IsAlgorithmOfKey(string alg, CryptoAlgorithm keyAlgorithm) =>
        (keyAlgorithm.Equals(CryptoAlgorithm.P256) && WellKnownJwaValues.IsEs256(alg))
        || (keyAlgorithm.Equals(CryptoAlgorithm.P384) && WellKnownJwaValues.IsEs384(alg))
        || (keyAlgorithm.Equals(CryptoAlgorithm.P521) && WellKnownJwaValues.IsEs512(alg))
        || (keyAlgorithm.Equals(CryptoAlgorithm.Secp256k1) && WellKnownJwaValues.IsEs256K(alg))
        || (keyAlgorithm.Equals(CryptoAlgorithm.Ed25519) && (WellKnownJwaValues.IsEdDsa(alg) || WellKnownJwaValues.IsEd25519(alg)))
        || (IsRsaAlgorithm(alg) && JwsAlgorithmKeyBinding.IsAlgorithmOfKey(alg, keyAlgorithm));


    /// <summary>
    /// Whether <paramref name="alg"/> is one of the RSA identifiers: <c>RS256</c>, <c>RS384</c>, <c>RS512</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">RFC 7518 Section 3.3</see>), <c>PS256</c>,
    /// <c>PS384</c> and <c>PS512</c> (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Section 3.5</see>).
    /// </summary>
    /// <param name="alg">The proof header's <c>alg</c>.</param>
    /// <returns><see langword="true"/> for an RSA identifier.</returns>
    private static bool IsRsaAlgorithm(string alg) =>
        WellKnownJwaValues.IsRs256(alg) || WellKnownJwaValues.IsRs384(alg) || WellKnownJwaValues.IsRs512(alg)
        || WellKnownJwaValues.IsPs256(alg) || WellKnownJwaValues.IsPs384(alg) || WellKnownJwaValues.IsPs512(alg);


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
