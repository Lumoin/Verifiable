using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Foundation;
using Verifiable.JCose;

namespace Verifiable.DidComm;

/// <summary>
/// Pack and unpack for DIDComm signed messages — a JWS over the plaintext JWM that adds a
/// non-repudiable sender signature, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#didcomm-signed-messages">DIDComm Messaging v2.1 §DIDComm Signed Messages</see>.
/// </summary>
/// <remarks>
/// <para>
/// The signature is computed over the raw <c>application/didcomm-plain+json</c> bytes of the
/// <see cref="DidCommPlaintextMessage"/> produced by <see cref="DidCommPlaintextExtensions.PackPlaintext"/>
/// — the payload is never re-serialized once signed, so the bytes the recipient verifies are exactly
/// the bytes the sender signed. The protected header carries
/// <c>{typ: application/didcomm-signed+json, alg}</c> and the signer's <c>kid</c> rides in the
/// per-signature unprotected header (DIDComm v2.1 Appendix C.2).
/// </para>
/// <para>
/// Verification is fail-closed and resolves the verifying key from the sender's DID document, never
/// from the attacker-controlled <c>alg</c> header: it enforces the plaintext <c>from</c> ↔ signer
/// <c>kid</c> addressing-consistency MUST, requires the <c>kid</c> be authorized for the
/// <c>authentication</c> verification relationship, and only then checks the signature with the key
/// the resolved verification method specifies.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "The caller owns and disposes the returned DidCommSignedMessage; the signature is owned by the JwsSignatureComponent owned by the JwsMessage disposed via 'using' once serialized.")]
public static class DidCommSignedExtensions
{
    //An upper bound on the signed-message wire size, checked before the JWS is parsed. The encrypted path
    //bounds its wire via the JWE parser; the signed path had no such bound, so an oversized envelope (e.g. an
    //attacker-padded `signatures` array) is rejected before driving an O(N) base64url decode.
    private const int MaximumSignedMessageBytes = 8 * 1024 * 1024;

    /// <summary>
    /// Signs <paramref name="message"/> as a DIDComm signed message, resolving the signing function
    /// from <paramref name="signingKey"/>'s <see cref="SensitiveData.Tag"/> via the
    /// <see cref="CryptoFunctionRegistry{TAlgorithm, TPurpose}"/>.
    /// </summary>
    /// <param name="message">The plaintext message to sign.</param>
    /// <param name="signingKey">The sender's signing key. Its tag selects both the signing function and the JWS <c>alg</c>.</param>
    /// <param name="keyId">The signer's <c>kid</c> — a DID URL whose base DID MUST equal the message <c>from</c>.</param>
    /// <param name="plaintextSerializer">Serializer producing the <see cref="DidCommPlaintextMessage"/> payload.</param>
    /// <param name="protectedHeaderEncoder">Encoder serializing the JWS protected header to its UTF-8 JSON bytes.</param>
    /// <param name="signedSerializer">Serializer producing the <see cref="DidCommSignedMessage"/> wire form.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder.</param>
    /// <param name="memoryPool">Memory pool for the signing-input buffer and the pooled artifacts.</param>
    /// <param name="format">The JWS JSON serialization to emit. Compact is rejected; defaults to General JSON.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed message wire artifact. The caller owns and disposes it.</returns>
    public static ValueTask<DidCommSignedMessage> PackSignedAsync(
        this DidCommMessage message,
        PrivateKeyMemory signingKey,
        string keyId,
        DidCommMessageSerializer plaintextSerializer,
        JwtPartEncoder<JwtHeader> protectedHeaderEncoder,
        JwsMessageSerializer signedSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        JoseSerializationFormat format = JoseSerializationFormat.GeneralJson,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signingKey);

        CryptoAlgorithm algorithm = signingKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = signingKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return message.PackSignedAsync(
            signingKey,
            keyId,
            plaintextSerializer,
            protectedHeaderEncoder,
            signedSerializer,
            base64UrlEncoder,
            signingDelegate,
            memoryPool,
            format,
            cancellationToken);
    }


    /// <summary>
    /// Signs <paramref name="message"/> as a DIDComm signed message using an explicit
    /// <see cref="SigningDelegate"/>. The registry-resolving overload above delegates here after
    /// resolving the function from <paramref name="signingKey"/>'s <see cref="SensitiveData.Tag"/>.
    /// </summary>
    /// <param name="message">The plaintext message to sign.</param>
    /// <param name="signingKey">The sender's signing key. Its tag selects the JWS <c>alg</c>.</param>
    /// <param name="keyId">The signer's <c>kid</c> — a DID URL whose base DID MUST equal the message <c>from</c>.</param>
    /// <param name="plaintextSerializer">Serializer producing the <see cref="DidCommPlaintextMessage"/> payload.</param>
    /// <param name="protectedHeaderEncoder">Encoder serializing the JWS protected header to its UTF-8 JSON bytes.</param>
    /// <param name="signedSerializer">Serializer producing the <see cref="DidCommSignedMessage"/> wire form.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder.</param>
    /// <param name="signingDelegate">The signing function to use.</param>
    /// <param name="memoryPool">Memory pool for the signing-input buffer and the pooled artifacts.</param>
    /// <param name="format">The JWS JSON serialization to emit. Compact is rejected; defaults to General JSON.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed message wire artifact. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="format"/> is compact serialization.</exception>
    /// <exception cref="FormatException">Thrown when the message violates a §Message Headers structural requirement.</exception>
    public static async ValueTask<DidCommSignedMessage> PackSignedAsync(
        this DidCommMessage message,
        PrivateKeyMemory signingKey,
        string keyId,
        DidCommMessageSerializer plaintextSerializer,
        JwtPartEncoder<JwtHeader> protectedHeaderEncoder,
        JwsMessageSerializer signedSerializer,
        EncodeDelegate base64UrlEncoder,
        SigningDelegate signingDelegate,
        MemoryPool<byte> memoryPool,
        JoseSerializationFormat format = JoseSerializationFormat.GeneralJson,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(keyId);
        ArgumentNullException.ThrowIfNull(plaintextSerializer);
        ArgumentNullException.ThrowIfNull(protectedHeaderEncoder);
        ArgumentNullException.ThrowIfNull(signedSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(format == JoseSerializationFormat.Compact)
        {
            throw new ArgumentException(
                "A DIDComm signed message MUST use the JSON serialization (General or Flattened), not compact (DIDComm v2.1 §DIDComm Signed Messages).",
                nameof(format));
        }

        //Addressing-consistency at the producer: a signed message's `from` MUST match the signer kid's
        //DID (DIDComm v2.1 §Message Layer Addressing Consistency). Enforcing it here keeps the sender
        //from emitting a message every conformant verifier would reject.
        if(string.IsNullOrEmpty(message.From))
        {
            throw new ArgumentException(
                "A DIDComm signed message MUST carry a 'from' header matching the signer kid (DIDComm v2.1 §Message Layer Addressing Consistency).",
                nameof(message));
        }

        if(!DidUrl.TryParse(keyId, out DidUrl? keyIdUrl) || keyIdUrl.BaseDid is not string keyIdDid)
        {
            throw new ArgumentException("The signer keyId MUST be a DID URL carrying a base DID.", nameof(keyId));
        }

        string fromDid = DidUrl.TryParse(message.From, out DidUrl? fromUrl) && fromUrl.BaseDid is string parsedFromDid
            ? parsedFromDid
            : message.From;

        if(!string.Equals(keyIdDid, fromDid, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The signer keyId's DID MUST equal the message 'from' (DIDComm v2.1 §Message Layer Addressing Consistency).",
                nameof(keyId));
        }

        //Sign the raw plaintext JWM bytes. PackPlaintext validates the §Message Headers structure and
        //produces the application/didcomm-plain+json artifact the JWS payload carries verbatim; the
        //signature MUST cover these exact bytes, so they are never re-serialized downstream.
        using DidCommPlaintextMessage plaintext = message.PackPlaintext(plaintextSerializer, memoryPool);

        //The alg is taken from the signing key's tag, never from caller input, so the protected
        //header faithfully describes the key that produced the signature.
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        var protectedHeader = new JwtHeader
        {
            [WellKnownJoseHeaderNames.Typ] = DidCommMediaTypes.Signed,
            [WellKnownJwkMemberNames.Alg] = algorithm
        };

        var unprotectedHeader = new Dictionary<string, object>
        {
            [WellKnownJwkMemberNames.Kid] = keyId
        };

        //Compose the JCose JWS facade rather than hand-assembling the signing input: Jws.SignAsync signs the raw
        //plaintext bytes verbatim and rides the signer kid in the per-signature unprotected header — the two
        //capabilities the typed-payload Jws.SignAsync overload cannot express (DIDComm v2.1 Appendix C.2).
        using JwsMessage jwsMessage = await Jws.SignAsync(
            protectedHeader,
            plaintext.AsReadOnlyMemory(),
            protectedHeaderEncoder,
            base64UrlEncoder,
            signingKey,
            signingDelegate,
            memoryPool,
            unprotectedHeader,
            cancellationToken).ConfigureAwait(false);

        //The leaf serializer copies the wire bytes into the returned pooled artifact, so it is
        //independent of the JwsMessage and plaintext disposed when this method returns.
        return signedSerializer(jwsMessage, format, base64UrlEncoder, memoryPool);
    }


    /// <summary>
    /// Verifies <paramref name="signedMessage"/> and, on success, returns the verified plaintext and signer.
    /// </summary>
    /// <remarks>
    /// The check sequence is, in order: parse the JWS JSON envelope (General or Flattened — both MUST
    /// be accepted); validate the inner plaintext; require a <c>from</c>, a signer <c>kid</c>, and the
    /// signed media type; enforce the <c>from</c> ↔ <c>kid</c> addressing-consistency MUST; resolve
    /// the signer DID and require the <c>kid</c> be authorized for the <c>authentication</c>
    /// relationship; and only then verify the signature with the key the resolved verification method
    /// specifies (the algorithm comes from that key, never from the claimed <c>alg</c>).
    /// </remarks>
    /// <param name="signedMessage">The DIDComm signed message wire artifact.</param>
    /// <param name="didResolver">Resolver for the signer DID. Reuses the app-side resolution seam.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="plaintextParser">Parser producing the message from the inner plaintext bytes.</param>
    /// <param name="signedParser">Parser producing the unverified JWS message from the wire bytes.</param>
    /// <param name="base64UrlDecoder">Base64Url decoder for the JWS envelope members.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder, used to reconstruct the JWS signing input.</param>
    /// <param name="memoryPool">Memory pool for parsing and the signing-input buffer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="fromPriorPayloadDeserializer">Deserializer for a <c>from_prior</c> JWT payload, supplied to verify a DID Rotation header; when <see langword="null"/> a present <c>from_prior</c> is rejected (fail closed).</param>
    /// <param name="fromPriorHeaderDeserializer">Deserializer for a <c>from_prior</c> JWT protected header, supplied to verify a DID Rotation header.</param>
    /// <returns>A fail-closed verification result.</returns>
    [SuppressMessage("Design", "CA1068:CancellationToken parameters must come last",
        Justification = "The from_prior rotation-verifier delegates are additive trailing optional parameters kept after the existing cancellationToken so every existing positional caller stays source-compatible (DID Rotation is an opt-in seam threaded only by the leaf serializer).")]
    public static async ValueTask<DidCommSignedVerificationResult> UnpackSignedAsync(
        this DidCommSignedMessage signedMessage,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        DidCommMessageParser plaintextParser,
        JwsMessageParser signedParser,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default,
        JwtClaimsDeserializer? fromPriorPayloadDeserializer = null,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>>? fromPriorHeaderDeserializer = null)
    {
        ArgumentNullException.ThrowIfNull(signedMessage);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);
        ArgumentNullException.ThrowIfNull(plaintextParser);
        ArgumentNullException.ThrowIfNull(signedParser);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        //Bound the wire before parsing so an oversized signed envelope (in particular a padded multi-signature
        //array) cannot drive an unbounded JWS parse + base64url decode before the single-signature check below
        //rejects it.
        if(signedMessage.AsReadOnlySpan().Length > MaximumSignedMessageBytes)
        {
            return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.MalformedEnvelope);
        }

        //A DIDComm signed message uses the JWS JSON serialization; a recipient MUST handle both the
        //General and Flattened forms (DIDComm v2.1 §DIDComm Signed Messages). The leaf parser throws
        //FormatException on anything that is not a JSON JWS (including the compact form).
        UnverifiedJwsMessage parsed;
        try
        {
            parsed = signedParser(signedMessage.AsReadOnlySpan(), base64UrlDecoder, memoryPool);
        }
        catch(Exception ex) when(ex is FormatException or System.Text.Json.JsonException)
        {
            //A non-JWS input or a JWS whose JSON is malformed (the leaf parser surfaces a wire-type
            //violation as JsonException) is a malformed envelope — fail closed, never throw to the caller.
            return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.MalformedEnvelope);
        }

        using(parsed)
        {
            //The DIDComm signed message conveys exactly the single sender signature.
            if(parsed.Signatures.Count != 1)
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.MultipleSignatures);
            }

            //A DIDComm signed message MUST carry its payload (the signed-over plaintext JWM). A detached-payload
            //JWS has no payload to recover and signs an externally-supplied one, so reject it explicitly as an
            //enforced invariant rather than relying on the empty-payload plaintext parse failing downstream
            //(DIDComm v2.1 §DIDComm Signed Messages).
            if(parsed.IsDetachedPayload)
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.MalformedEnvelope);
            }

            UnverifiedJwsSignature jwsSignature = parsed.Signatures[0];

            //The payload is the signed-over plaintext JWM; validating it also surfaces `from`.
            DidCommMessage message;
            try
            {
                message = DidCommPlaintextExtensions.UnpackPlaintext(parsed.Payload.Span, plaintextParser);
            }
            catch(Exception ex) when(ex is FormatException or System.Text.Json.JsonException)
            {
                //The signed-over payload is a structurally or wire-type-invalid plaintext JWM (the leaf
                //parser surfaces an integer/array/object wire-type violation as JsonException). Fail closed
                //rather than letting the exception escape — this guard also covers the nested unpack path,
                //where the recipient is the consumer of an attacker-supplied inner JWM.
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.InvalidPlaintext);
            }

            if(string.IsNullOrEmpty(message.From))
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.MissingFrom);
            }

            //The integrity-protected typ MUST identify a signed message. It is covered by the
            //signature, but reading it up front fails fast on an envelope not claiming to be signed.
            if(!(jwsSignature.ProtectedHeader.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typValue)
                && typValue is string typ
                && DidCommMediaTypes.IsSigned(typ)))
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.UnexpectedMediaType);
            }

            //The signer kid rides in the per-signature unprotected header (DIDComm v2.1 Appendix C.2).
            if(jwsSignature.UnprotectedHeader is null
                || !jwsSignature.UnprotectedHeader.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidValue)
                || kidValue is not string kid
                || string.IsNullOrEmpty(kid))
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.MissingKid);
            }

            //Addressing-consistency MUST: the plaintext `from` must match the signer kid's DID.
            if(!DidUrl.TryParse(kid, out DidUrl? kidUrl) || kidUrl.BaseDid is not string signerDid)
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.FromKidMismatch);
            }

            string fromDid = DidUrl.TryParse(message.From, out DidUrl? fromUrl) && fromUrl.BaseDid is string parsedFromDid
                ? parsedFromDid
                : message.From;

            if(!string.Equals(signerDid, fromDid, StringComparison.Ordinal))
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.FromKidMismatch);
            }

            //Resolve the signer DID and require the kid be authorized for authentication before
            //trusting the signature (DIDComm v2.1 §Verification).
            DidResolutionResult resolution = await didResolver
                .ResolveAsync(signerDid, exchangeContext, options: null, cancellationToken)
                .ConfigureAwait(false);

            if(!resolution.IsSuccessful || resolution.Document is null)
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.SignerResolutionFailed);
            }

            if(!TryResolveAuthenticationKey(resolution.Document, kid, out VerificationMethod? verificationMethod))
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.KidNotAuthenticated);
            }

            //Reconstruct the JWS signing input (ASCII(b64url(protected) "." b64url(payload))) and verify
            //with the key resolved from the verification method. The algorithm is taken from that key
            //via the registry, never from the claimed `alg`, defeating algorithm-substitution. This
            //mirrors VerificationMethodExtensions.VerifySignatureAsync, passing the parsed signature
            //bytes (already exact-sized by the decoder) directly rather than re-wrapping them.
            //The verifying key comes from the resolved verification method, which is reached via the
            //attacker-influenced signer kid; a structurally malformed or unsupported method makes the
            //converter (or the registry/verify) throw. Map that to a fail-closed result rather than letting
            //it escape, honouring the contract that every verification failure returns a result — this also
            //keeps the nested encrypted-unpack path that calls this method fail-closed. A cryptographically
            //wrong (but well-formed) signature is reported as not valid below, not as a thrown exception.
            //The signing-input reconstruction (RFC 7515 §5.1) drops out to the JCose facade Jws.VerifySignatureAsync.
            bool isValid;
            try
            {
                (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> KeyMaterial) keyMaterial =
                    VerificationMethodCryptoConversions.DefaultConverter(verificationMethod!, memoryPool);

                using(keyMaterial.KeyMaterial)
                {
                    VerificationDelegate verificationDelegate =
                        CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(keyMaterial.Algorithm, keyMaterial.Purpose);

                    isValid = await Jws.VerifySignatureAsync(
                        jwsSignature.Protected,
                        parsed.Payload,
                        jwsSignature.SignatureBytes.Memory,
                        base64UrlEncoder,
                        verificationDelegate,
                        keyMaterial.KeyMaterial.Memory,
                        memoryPool,
                        cancellationToken).ConfigureAwait(false);
                }
            }
            catch(Exception ex) when(ex is ArgumentException or FormatException or NotSupportedException or CryptographicException or IndexOutOfRangeException)
            {
                //A non-ASCII `publicKeyMultibase` makes the injected base58 decoder throw
                //IndexOutOfRangeException (SimpleBase), not FormatException; signer-key resolution MUST fail
                //closed for any malformed key material, never escape the verify.
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.SignerResolutionFailed);
            }

            if(!isValid)
            {
                return DidCommSignedVerificationResult.Failed(DidCommSignatureVerificationError.SignatureInvalid);
            }

            bool isToHeaderPresent = message.To is { Count: > 0 };

            //A from_prior header marks a DID Rotation: verify it and surface the prior DID. Reference-impl
            //parity — the recipient verifies from_prior in every unpack mode (DIDComm v2.1 §DID Rotation).
            if(!string.IsNullOrEmpty(message.FromPrior))
            {
                FromPriorVerificationOutcome rotation = await VerifyFromPriorOrFailAsync(
                    message, didResolver, exchangeContext, fromPriorPayloadDeserializer, fromPriorHeaderDeserializer,
                    base64UrlDecoder, base64UrlEncoder, memoryPool, cancellationToken).ConfigureAwait(false);

                if(!rotation.IsVerified)
                {
                    return DidCommSignedVerificationResult.Failed(MapRotationError(rotation.Error));
                }

                return DidCommSignedVerificationResult.Success(message, kid, isToHeaderPresent, isRotation: true, priorDid: rotation.PriorDid, rotationIat: rotation.Iat);
            }

            return DidCommSignedVerificationResult.Success(message, kid, isToHeaderPresent);
        }
    }


    //Verifies the from_prior header through the shared rotation helper, or returns a malformed-rotation
    //failure when the caller supplied no rotation deserializers despite a from_prior being present — a
    //from_prior MUST NOT be silently accepted unverified (fail closed, DIDComm v2.1 §DID Rotation).
    private static ValueTask<FromPriorVerificationOutcome> VerifyFromPriorOrFailAsync(
        DidCommMessage message,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        JwtClaimsDeserializer? fromPriorPayloadDeserializer,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>>? fromPriorHeaderDeserializer,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        if(fromPriorPayloadDeserializer is null || fromPriorHeaderDeserializer is null)
        {
            return ValueTask.FromResult(FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationJwtMalformed));
        }

        return DidCommFromPriorExtensions.VerifyFromPriorAsync(
            message, didResolver, exchangeContext, fromPriorPayloadDeserializer, fromPriorHeaderDeserializer,
            base64UrlDecoder, base64UrlEncoder, memoryPool, cancellationToken);
    }


    //Maps the canonical rotation rejection reason onto the signed-message verification error enum.
    private static DidCommSignatureVerificationError MapRotationError(DidCommRotationError error) => error switch
    {
        DidCommRotationError.RotationJwtMalformed => DidCommSignatureVerificationError.RotationJwtMalformed,
        DidCommRotationError.RotationSubjectMismatch => DidCommSignatureVerificationError.RotationSubjectMismatch,
        DidCommRotationError.RotationIssuerKidMismatch => DidCommSignatureVerificationError.RotationIssuerKidMismatch,
        DidCommRotationError.PriorDidResolutionFailed => DidCommSignatureVerificationError.PriorDidResolutionFailed,
        DidCommRotationError.RotationSignerNotAuthorized => DidCommSignatureVerificationError.RotationSignerNotAuthorized,
        DidCommRotationError.RotationSignatureInvalid => DidCommSignatureVerificationError.RotationSignatureInvalid,
        _ => DidCommSignatureVerificationError.RotationJwtMalformed
    };


    //Resolves the kid to a verification method that is authorized for the authentication relationship,
    //honouring both embedded methods and references into the document's verificationMethod array. The
    //kid is an absolute DID URL by this point; relative reference ids (e.g. "#key-1") are normalized
    //against the document's own DID before comparison. Returns false — fail closed — when the kid is
    //not present in the authentication relationship or its referenced method cannot be located.
    internal static bool TryResolveAuthenticationKey(DidDocument document, string kid, out VerificationMethod? verificationMethod)
    {
        verificationMethod = null;

        if(document.Authentication is null)
        {
            return false;
        }

        string? documentDid = document.Id?.Id;

        foreach(AuthenticationMethod authentication in document.Authentication)
        {
            if(!IsSameVerificationMethodId(authentication.Id, kid, documentDid))
            {
                continue;
            }

            //An embedded method is usable only for the relationship it appears in — authentication here.
            if(authentication.EmbeddedVerification is not null)
            {
                verificationMethod = authentication.EmbeddedVerification;

                return true;
            }

            //A reference resolves against the document's verificationMethod array.
            if(document.VerificationMethod is not null)
            {
                foreach(VerificationMethod candidate in document.VerificationMethod)
                {
                    if(IsSameVerificationMethodId(candidate.Id, kid, documentDid))
                    {
                        verificationMethod = candidate;

                        return true;
                    }
                }
            }

            //The kid is authorized for authentication but its verification method is not present.
            return false;
        }

        return false;
    }


    //Whether candidateId denotes the same verification method as the absolute kid, treating a leading
    //'#' as a reference relative to documentDid. Matching is exact — no suffix matching — so an entry
    //cannot be confused with a differently-scoped method that merely shares a fragment.
    private static bool IsSameVerificationMethodId(string? candidateId, string kid, string? documentDid)
    {
        if(string.IsNullOrEmpty(candidateId))
        {
            return false;
        }

        if(string.Equals(candidateId, kid, StringComparison.Ordinal))
        {
            return true;
        }

        if(candidateId.StartsWith('#') && documentDid is not null)
        {
            return string.Equals($"{documentDid}{candidateId}", kid, StringComparison.Ordinal);
        }

        return false;
    }


}
