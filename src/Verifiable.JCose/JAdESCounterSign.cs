using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// The <c>cSig</c> countersignature verbs of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.3.2</see> — the JAdES-side counterpart of
/// <see cref="CoseCounterSign"/>, transposed to the much simpler JWS shape clause 5.3.2 states.
/// </summary>
/// <remarks>
/// <para>
/// <strong>No Countersign_structure — the clause needs none.</strong> RFC 9338's own countersignature
/// mechanism builds a dedicated <c>Countersign_structure</c> (context string, protected headers, external AAD,
/// target signature bytes) as its ToBeSigned input. JA-5.3.2-03 states something far simpler: "the <c>cSig</c>
/// JSON object contains one JSON Web Signature ... that signs the JWS Signature Value of the embedding JAdES
/// signature." The countersignature's JWS Payload IS the target's raw JWS Signature Value octets — no wrapping
/// structure, no external AAD, no separate builder delegate. <see cref="CountersignAsync{TJwtPart}(ReadOnlyMemory{byte}, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, PrivateKeyMemory, SigningDelegate, BaseMemoryPool, IReadOnlyDictionary{string, object}?, CryptoEventSink?, CancellationToken)"/>
/// therefore composes the SHIPPED <see cref="Jws.SignAsync{TJwtPart}(TJwtPart, ReadOnlyMemory{byte}, JwtPartEncoder{TJwtPart}, EncodeDelegate, PrivateKeyMemory, SigningDelegate, BaseMemoryPool, IReadOnlyDictionary{string, object}?, CryptoEventSink?, CancellationToken)"/>
/// raw-payload overload directly, with the payload fixed to the target signature value — zero new crypto, a
/// thin, spec-documenting composition.
/// </para>
/// <para>
/// <strong>Either a plain JWS or a JAdES signature (JA-5.3.2-02/-04/-05).</strong> <typeparamref name="TJwtPart"/>
/// and <paramref name="protectedHeaderEncoder"/> are the caller's own choice: a plain RFC 7515 header (JA-5.3.2-04)
/// or a full <see cref="Verifiable.Cryptography.Pki.JAdESProtectedHeaders"/> aggregate with its own encoder
/// (JA-5.3.2-05) both flow through the identical call shape — this class asserts no opinion on which.
/// </para>
/// <para>
/// <strong><see cref="VerifyAsync(UnverifiedJwsMessage, ReadOnlyMemory{byte}, EncodeDelegate, PublicKeyMemory, VerificationDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
/// checks the binding before the cryptography.</strong> A countersignature whose payload does not byte-equal
/// the embedding signature's own JWS Signature Value is refused (<see langword="false"/>) before any
/// cryptographic verification runs — a countersignature that verifies against a DIFFERENT payload is not a
/// countersignature of THIS signature (JA-5.3.2-03's own "of the embedding JAdES signature"), regardless of
/// whether its own signature bytes are cryptographically sound. The check tolerates a detached-payload wire
/// form (RFC 7515 §7): the target value is what gets verified either way, since it is already known
/// out-of-band.
/// </para>
/// <para>
/// <strong>Scope: exactly one signature.</strong> Mirrors <see cref="TryParseJAdESMessageDelegate"/>'s own
/// scope — a <paramref name="counterSignature"/>/<see langword="counterSignature"/> carrying more than one
/// signature (a General JSON serialization with several signers) is out of scope and reported as a verification
/// failure, not silently narrowed to the first entry.
/// </para>
/// <para>
/// <strong>Untrusted input, typed refusals.</strong> <see cref="VerifyAsync(UnverifiedJwsMessage, ReadOnlyMemory{byte}, EncodeDelegate, PublicKeyMemory, BaseMemoryPool, CancellationToken)"/>
/// takes an <see cref="UnverifiedJwsMessage"/> (the countersignature is untrusted wire content until this
/// call promotes it) and returns a plain <see langword="bool"/>; a caller collecting typed reasons (decode
/// failure, unresolved key, binding mismatch, cryptographic failure) composes this verb through
/// <see cref="JAdESLevelRules.CheckCounterSignaturesAsync"/>, which reports
/// <see cref="JAdESCounterSignatureVerificationViolation"/>.
/// </para>
/// </remarks>
public static class JAdESCounterSign
{
    /// <summary>
    /// Creates a <c>cSig</c> countersignature over <paramref name="embeddingSignatureValue"/> using a
    /// registry-resolved signing function.
    /// </summary>
    /// <typeparam name="TJwtPart">The countersigner's own protected-header type.</typeparam>
    /// <param name="embeddingSignatureValue">The embedding JAdES signature's own JWS Signature Value octets (JA-5.3.2-03).</param>
    /// <param name="counterSignerProtectedHeader">The countersigner's own protected header — a plain JWS header (JA-5.3.2-04) or a JAdES header (JA-5.3.2-05).</param>
    /// <param name="protectedHeaderEncoder">Encodes <paramref name="counterSignerProtectedHeader"/> to its UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="privateKey">The countersigner's private key.</param>
    /// <param name="signaturePool">Memory pool for the signing-input buffer and the signature.</param>
    /// <param name="counterSignerUnprotectedHeader">Optional per-signature unprotected header, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The countersignature, unserialized. The caller owns and disposes it.</returns>
    public static ValueTask<JwsMessage> CountersignAsync<TJwtPart>(
        ReadOnlyMemory<byte> embeddingSignatureValue,
        TJwtPart counterSignerProtectedHeader,
        JwtPartEncoder<TJwtPart> protectedHeaderEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        BaseMemoryPool signaturePool,
        IReadOnlyDictionary<string, object>? counterSignerUnprotectedHeader,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return CountersignAsync(
            embeddingSignatureValue, counterSignerProtectedHeader, protectedHeaderEncoder, base64UrlEncoder,
            privateKey, signingDelegate, signaturePool, counterSignerUnprotectedHeader, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Creates a <c>cSig</c> countersignature over <paramref name="embeddingSignatureValue"/> using an explicit
    /// signing delegate — the direct <see cref="Jws.SignAsync{TJwtPart}(TJwtPart, ReadOnlyMemory{byte}, JwtPartEncoder{TJwtPart}, EncodeDelegate, PrivateKeyMemory, SigningDelegate, BaseMemoryPool, IReadOnlyDictionary{string, object}?, CryptoEventSink?, CancellationToken)"/>
    /// composition the type remarks describe.
    /// </summary>
    /// <typeparam name="TJwtPart">The countersigner's own protected-header type.</typeparam>
    /// <param name="embeddingSignatureValue">The embedding JAdES signature's own JWS Signature Value octets (JA-5.3.2-03).</param>
    /// <param name="counterSignerProtectedHeader">The countersigner's own protected header.</param>
    /// <param name="protectedHeaderEncoder">Encodes <paramref name="counterSignerProtectedHeader"/> to its UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="privateKey">The countersigner's private key.</param>
    /// <param name="signingDelegate">The signing delegate to use.</param>
    /// <param name="signaturePool">Memory pool for the signing-input buffer and the signature.</param>
    /// <param name="counterSignerUnprotectedHeader">Optional per-signature unprotected header, or <see langword="null"/>.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> the resolved <paramref name="signingDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The countersignature, unserialized. The caller owns and disposes it.</returns>
    public static ValueTask<JwsMessage> CountersignAsync<TJwtPart>(
        ReadOnlyMemory<byte> embeddingSignatureValue,
        TJwtPart counterSignerProtectedHeader,
        JwtPartEncoder<TJwtPart> protectedHeaderEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        BaseMemoryPool signaturePool,
        IReadOnlyDictionary<string, object>? counterSignerUnprotectedHeader,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        return Jws.SignAsync(
            counterSignerProtectedHeader,
            embeddingSignatureValue,
            protectedHeaderEncoder,
            base64UrlEncoder,
            privateKey,
            signingDelegate,
            signaturePool,
            counterSignerUnprotectedHeader,
            eventSink,
            cancellationToken);
    }


    /// <summary>
    /// Verifies <paramref name="counterSignature"/> against <paramref name="embeddingSignatureValue"/>, using a
    /// registry-resolved verification function.
    /// </summary>
    /// <param name="counterSignature">The decoded, untrusted countersignature (see the type remarks).</param>
    /// <param name="embeddingSignatureValue">The embedding JAdES signature's own JWS Signature Value octets (JA-5.3.2-03).</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="publicKey">The countersigner's public key.</param>
    /// <param name="pool">Memory pool for the signing-input buffer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when the payload binds to <paramref name="embeddingSignatureValue"/> AND the cryptographic signature verifies.</returns>
    public static ValueTask<bool> VerifyAsync(
        UnverifiedJwsMessage counterSignature,
        ReadOnlyMemory<byte> embeddingSignatureValue,
        EncodeDelegate base64UrlEncoder,
        PublicKeyMemory publicKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return VerifyAsync(
            counterSignature, embeddingSignatureValue, base64UrlEncoder, publicKey, verificationDelegate, pool, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Verifies <paramref name="counterSignature"/> against <paramref name="embeddingSignatureValue"/>, using an
    /// explicit verification delegate — see the type remarks for the binding-before-cryptography discipline.
    /// </summary>
    /// <param name="counterSignature">The decoded, untrusted countersignature.</param>
    /// <param name="embeddingSignatureValue">The embedding JAdES signature's own JWS Signature Value octets (JA-5.3.2-03).</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="publicKey">The countersigner's public key.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="pool">Memory pool for the signing-input buffer.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="VerificationCompletedEvent"/> the resolved <paramref name="verificationDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when the payload binds to <paramref name="embeddingSignatureValue"/> AND the cryptographic signature verifies.</returns>
    public static async ValueTask<bool> VerifyAsync(
        UnverifiedJwsMessage counterSignature,
        ReadOnlyMemory<byte> embeddingSignatureValue,
        EncodeDelegate base64UrlEncoder,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        BaseMemoryPool pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(counterSignature);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        if(counterSignature.Signatures.Count != 1)
        {
            return false;
        }

        UnverifiedJwsSignature signature = counterSignature.Signatures[0];

        //JA-5.3.2-03: an attached payload naming anything other than embeddingSignatureValue is not a
        //countersignature OF THIS signature -- refused before any cryptographic work runs. A detached wire
        //form carries no payload to compare; embeddingSignatureValue is what gets verified either way.
        if(!counterSignature.IsDetachedPayload && !counterSignature.Payload.Span.SequenceEqual(embeddingSignatureValue.Span))
        {
            return false;
        }

        return await Jws.VerifySignatureAsync(
            signature.Protected,
            embeddingSignatureValue,
            base64UrlPayload: true,
            signature.SignatureBytes.Memory,
            base64UrlEncoder,
            verificationDelegate,
            publicKey.AsReadOnlyMemory(),
            pool,
            eventSink,
            cancellationToken).ConfigureAwait(false);
    }
}
