using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// Encodes a JWT part to its byte representation, typically UTF-8 JSON.
/// </summary>
/// <typeparam name="TJwtPart">The type of JWT part.</typeparam>
/// <param name="part">The JWT part.</param>
/// <returns>Tagged memory containing the byte representation of the <paramref name="part"/>.</returns>
/// <remarks>
/// <para>
/// The returned <see cref="TaggedMemory{T}"/> wraps the serialized bytes along with
/// metadata identifying the buffer kind (header vs payload). This avoids copying
/// while providing context for the opaque bytes.
/// </para>
/// </remarks>
public delegate TaggedMemory<byte> JwtPartEncoder<in TJwtPart>(TJwtPart part);


/// <summary>
/// Decodes a JWT part's bytes (typically UTF-8 JSON) into its claim set. The
/// counterpart to <see cref="JwtPartEncoder{TJwtPart}"/> on the verification
/// side: the verifier applies the result positionally, wrapping the first
/// segment in a <see cref="JwtHeader"/> and the second in a
/// <see cref="JwtPayload"/>.
/// </summary>
/// <param name="partBytes">The decoded bytes of a single JWT part.</param>
/// <returns>The claim set carried by the part.</returns>
/// <remarks>
/// A decoder refuses part bytes it cannot decode with <see cref="FormatException"/>, as the library's own
/// default decoder <c>JwtPartJson.Default</c> does; a verify body of <see cref="Jws"/> answers that refusal of a
/// presented part as its not-verified value. Any other exception a decoder raises is the decoder's own fault,
/// not a property of the presented part, and propagates out of the verify body.
/// </remarks>
public delegate IReadOnlyDictionary<string, object> JwtPartDecoder(ReadOnlySpan<byte> partBytes);


/// <summary>
/// Context for JOSE key resolution containing header and payload information.
/// </summary>
/// <param name="Header">The JWT header containing algorithm and key identification (kid, jku, alg, x5c).</param>
/// <param name="Payload">The JWT payload containing claims (iss, sub, aud).</param>
/// <remarks>
/// <para>
/// This context provides all information needed to identify and locate a key for JOSE operations.
/// Resolvers can examine header fields (kid, jku, alg) and payload claims (iss) to determine
/// which key to load and from where.
/// </para>
/// </remarks>
public readonly record struct JoseKeyContext(JwtHeader Header, JwtPayload Payload);


/// <summary>
/// Result of JWS verification including decoded header and payload.
/// </summary>
/// <remarks>
/// <para>
/// Mint-only: the constructor is <see langword="internal"/>, so an instance with
/// <see cref="IsValid"/> <see langword="true"/> can only come out of this library's
/// verification — application code cannot fabricate a "verified" result around
/// hand-built parts. The <see langword="default"/> value is fail-closed
/// (<see cref="IsValid"/> is <see langword="false"/>).
/// </para>
/// <para>
/// This is the verification-state half of the JOSE part types' role story: building
/// a <see cref="JwtHeader"/>/<see cref="JwtPayload"/> to SIGN is free construction
/// (trusted because the caller authored it), while claims trusted because they were
/// VERIFIED arrive through this carrier or through a domain validator's own
/// mint-controlled result type.
/// </para>
/// </remarks>
public readonly record struct JwsVerificationResult
{
    internal JwsVerificationResult(bool isValid, JwtHeader header, JwtPayload payload)
    {
        IsValid = isValid;
        Header = header;
        Payload = payload;
    }

    /// <summary>Whether the signature is valid.</summary>
    public bool IsValid { get; }

    /// <summary>The decoded header.</summary>
    public JwtHeader Header { get; }

    /// <summary>The decoded payload.</summary>
    public JwtPayload Payload { get; }
}


// Note: JwtHeaderSerializer and JwtHeaderDeserializer are defined in
// Verifiable.Core.Model.Credentials.CredentialSerializationDelegates


/// <summary>
/// JWS (JSON Web Signature) operations using secure key memory abstractions.
/// </summary>
/// <remarks>
/// <para>
/// This implementation provides multiple API patterns:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Registry-based</strong>: Uses <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
/// to resolve signing/verification functions from the key's <see cref="Tag"/>.
/// </description></item>
/// <item><description>
/// <strong>Explicit function</strong>: Caller provides signing/verification functions directly,
/// useful for testing or custom cryptographic backends.
/// </description></item>
/// <item><description>
/// <strong>Resolver/Binder</strong>: Uses <see cref="KeyMaterialResolver{TResult, TContext, TState}"/>
/// and <see cref="KeyMaterialBinder{TInput, TResult, TState}"/> for complex key resolution scenarios.
/// </description></item>
/// </list>
/// <para>
/// All methods return <see cref="JwsMessage"/> POCOs that can be serialized to any format
/// using <see cref="JwsSerialization"/>.
/// </para>
/// <para>
/// <strong>Memory and security.</strong> Every sign and verify path constructs the
/// JWS signing input (ASCII octets of <c>"&lt;header&gt;.&lt;payload&gt;"</c> per
/// RFC 7515 §5.1) into a pooled buffer via <see cref="RentSigningInput(string, string, BaseMemoryPool, out int)"/> rather
/// than heap-allocating a <see cref="byte"/> array.
/// </para>
/// <para>
/// <strong>Verify overload pairs.</strong> Every <c>VerifyAsync</c> /
/// <c>VerifyAndDecodeAsync</c> path that accepts a compact JWS <see cref="string"/>
/// comes as a pair: a simple overload that applies <see cref="DefaultMaxJwsLength"/>
/// as the upper bound, and an explicit overload that takes a caller-supplied
/// <c>maxJwsLength</c>. Deployments that handle larger or smaller tokens than
/// the default opt in to the explicit overload; everyone else uses the simple
/// overload and gets this library's own default length guard for free.
/// </para>
/// <para>
/// <strong>A presented compact JWS is answered, never thrown.</strong> A compact JWS handed to a verify overload
/// is the presenter's input, and every way it fails to verify is the overload's not-verified value
/// (<see langword="false"/>, or a <see cref="JwsVerificationResult"/> whose
/// <see cref="JwsVerificationResult.IsValid"/> is <see langword="false"/>): a JWS longer than the accepted
/// bound, one that is not the three parts of
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.1">RFC 7515 Section 7.1</see>, a segment that
/// is empty where a part cannot be, that is not the canonical unpadded base64url
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> defines (padding, white
/// space, a character outside the alphabet, a length of 1 modulo 4, a set bit of the last character that carries
/// no octet; the library checks the form itself before the caller's decoder runs), or that the base64url decoder
/// refuses or decodes to no octets, a protected header that fails the JSON gate (octets that are not valid UTF-8,
/// no well-formed JSON object, a member name repeated at any depth, a document beyond this library's reader
/// bounds; for the repeated name
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515 Section 4</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519 Section 4</see> govern the names of the
/// JOSE Header and of the JWT Claims Set, <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259
/// Section 4</see> a repeat at a nested depth, and <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC
/// 7517 Section 4</see> the members of a header's <c>jwk</c>) or names a critical extension this consumer does not
/// understand, a protected header or claims set that the caller's part decoder refuses, a claims set that
/// fails the JSON gate where the body reads the payload as a JWT Claims Set, a signature the backend refuses or
/// that does not verify, a public key whose (algorithm, purpose) pair the registry serves no verification
/// function for (<see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.TryResolveVerification"/>),
/// and a resolver that answers no key material for the presented header and payload.
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see> says "If any of
/// the listed steps fails, then the signature or MAC cannot be validated.", and
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see> says "All
/// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
/// them fail to validate."
/// </para>
/// <para>
/// <strong>A refusal and a fault.</strong> A base64url decoder (<see cref="DecodeDelegate"/>) and a part decoder
/// (<see cref="JwtPartDecoder"/>) refuse presented input they cannot decode with <see cref="FormatException"/>,
/// and a verify body answers that refusal as not verified; a base64url decoder is handed only a segment whose
/// canonical form the library has checked. Any other exception of such a delegate is the
/// delegate's own fault and propagates. What throws, generally, is what the caller composes or a dependency
/// that faults: a <see langword="null"/> argument (<see cref="ArgumentNullException"/>), a bound that is zero
/// or negative (<see cref="ArgumentOutOfRangeException"/>), cancellation, a registry overload when
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.IsInitialized"/> is
/// <see langword="false"/> (<see cref="InvalidOperationException"/>), and every exception a caller's delegate
/// (a decoder, a resolver, a binder, a verification function) or the pool raises for its own fault, a
/// verification backend's exception outside the refusals a verify body answers as not verified included. The
/// <see cref="JwsMessage"/> overloads of <c>VerifyAsync</c> verify one signature and throw
/// <see cref="InvalidOperationException"/> for a message that carries several.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned JwsMessage.")]
public static class Jws
{
    /// <summary>
    /// Default maximum length, in characters, for an incoming JWS compact
    /// serialization accepted by the simple verification overloads. Bounds
    /// the size of the pooled signing-input buffer the verifier must
    /// allocate, mitigating large-allocation denial-of-service via
    /// attacker-supplied JWS tokens. Generous enough for typical
    /// OAuth/OIDC tokens, SD-JWTs, and verifiable credentials; deployments
    /// that need a different bound use the overloads taking an explicit
    /// <c>maxJwsLength</c>.
    /// </summary>
    /// <remarks>
    /// The bound is this library's own guard against a large allocation
    /// from a presenter-supplied token; no specification states it. The
    /// value of 1 MiB is a ceiling far above the size of the tokens named
    /// above.
    /// </remarks>
    public const int DefaultMaxJwsLength = 1 * 1024 * 1024;


    /// <summary>
    /// Builds an unsigned JWT (per RFC 7519 §6.1 / RFC 7515 §6.1 "Unsecured
    /// JWS") as a compact serialization of the shape
    /// <c>base64url(header).base64url(payload).</c> — the trailing dot is
    /// the empty signature segment mandated by the compact format. The
    /// header MUST carry <c>"alg": "none"</c>; this method emits no
    /// signature regardless.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used for OAuth profiles that explicitly mandate an unsigned
    /// Authorization Request Object: OID4VP 1.0 §5.9.3 with the
    /// <c>redirect_uri</c> client identifier prefix forbids signing — the
    /// trust model relies on the wallet POSTing the response back to the
    /// asserted redirect URI, not on a verifiable signature.
    /// </para>
    /// <para>
    /// Outside that narrow profile case, prefer
    /// <see cref="SignAsync{TJwtPart}(TJwtPart, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, Cryptography.PrivateKeyMemory, BaseMemoryPool, CancellationToken)"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.2">RFC 8725 Section 3.2</see>: "JWT
    /// libraries SHOULD NOT generate JWTs using "none" unless explicitly requested to do so by the caller.
    /// Similarly, JWT libraries SHOULD NOT consume JWTs using "none" unless explicitly requested by the
    /// caller." Consumers opt into accepting them only in the contexts the profile allows.
    /// </para>
    /// </remarks>
    public static string BuildUnsignedCompact<TJwtPart>(
        TJwtPart header,
        TJwtPart payload,
        JwtPartEncoder<TJwtPart> partEncoder,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(partEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        TaggedMemory<byte> headerBytes = partEncoder(header);
        TaggedMemory<byte> payloadBytes = partEncoder(payload);

        string headerSegment = base64UrlEncoder(headerBytes.Span);
        string payloadSegment = base64UrlEncoder(payloadBytes.Span);

        return $"{headerSegment}.{payloadSegment}.";
    }


    /// <summary>
    /// Creates a JWS using registry-resolved signing function.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <param name="header">The JWT header containing algorithm information.</param>
    /// <param name="payload">The JWT payload.</param>
    /// <param name="partEncoder">Encodes JWT parts to bytes.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The JWS message containing the signature.</returns>
    public static ValueTask<JwsMessage> SignAsync<TJwtPart>(
        TJwtPart header,
        TJwtPart payload,
        JwtPartEncoder<TJwtPart> partEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        BaseMemoryPool signaturePool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return SignAsync(
            header, payload, partEncoder, base64UrlEncoder,
            privateKey, signingDelegate, signaturePool, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Creates a JWS using an explicit signing function.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <param name="header">The JWT header containing algorithm information.</param>
    /// <param name="payload">The JWT payload.</param>
    /// <param name="partEncoder">Encodes JWT parts to bytes.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signingDelegate">The signing function to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> the resolved <paramref name="signingDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// This overload resolves and invokes <paramref name="signingDelegate"/> directly rather than through a
    /// bound <see cref="PrivateKey"/>, so a <see cref="CryptoEventSink"/> is this call site's route — see
    /// <see cref="CryptoEventSink"/>.
    /// </param>
    /// <returns>The JWS message containing the signature.</returns>
    public static async ValueTask<JwsMessage> SignAsync<TJwtPart>(
        TJwtPart header,
        TJwtPart payload,
        JwtPartEncoder<TJwtPart> partEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        BaseMemoryPool signaturePool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(partEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);

        cancellationToken.ThrowIfCancellationRequested();

        TaggedMemory<byte> headerBytes = partEncoder(header);
        TaggedMemory<byte> payloadBytes = partEncoder(payload);

        string headerSegment = base64UrlEncoder(headerBytes.Span);
        string payloadSegment = base64UrlEncoder(payloadBytes.Span);

        using IMemoryOwner<byte> dataToSignOwner = RentSigningInput(
            headerSegment, payloadSegment, signaturePool, out int signingInputLength);

        (Signature signature, CryptoEvent? evt) = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            dataToSignOwner.Memory[..signingInputLength],
            signaturePool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        var protectedHeader = BuildProtectedHeaderDictionary(header);

        var signatureComponent = new JwsSignatureComponent(
            headerSegment,
            protectedHeader,
            signature);

        return new JwsMessage(payloadBytes.Memory, signatureComponent);
    }


    /// <summary>
    /// Creates a JWS over a caller-supplied RAW payload — the exact <paramref name="payload"/> bytes are signed and
    /// carried verbatim, never re-encoded through a part encoder — with an optional per-signature
    /// <paramref name="unprotectedHeader"/>. This is the building block for serializations that must sign opaque
    /// bytes (for example a media-typed message body) and place a <c>kid</c> in the unprotected header — the two
    /// capabilities the typed-payload
    /// <see cref="SignAsync{TJwtPart}(TJwtPart, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, PrivateKeyMemory, SigningDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
    /// overload cannot express. The returned <see cref="JwsMessage"/> is serialized by the caller (compact or JSON).
    /// </summary>
    /// <typeparam name="TJwtPart">The protected-header type.</typeparam>
    /// <param name="protectedHeader">The protected header, which carries <c>alg</c>.</param>
    /// <param name="payload">The raw payload bytes, signed verbatim and carried as the JWS payload.</param>
    /// <param name="protectedHeaderEncoder">Encodes the protected header to its UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signingDelegate">The signing function to use.</param>
    /// <param name="signaturePool">Memory pool for the signing-input buffer and the signature.</param>
    /// <param name="unprotectedHeader">Optional per-signature unprotected header (for example <c>{ kid }</c>), or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> the resolved <paramref name="signingDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// This is the overload <c>Verifiable.DidComm</c>'s <c>PackSignedAsync</c> reaches; passing no explicit
    /// sink still publishes to the global stream via the default.
    /// </param>
    /// <returns>The unserialized JWS message owning the signature. The caller disposes it.</returns>
    public static async ValueTask<JwsMessage> SignAsync<TJwtPart>(
        TJwtPart protectedHeader,
        ReadOnlyMemory<byte> payload,
        JwtPartEncoder<TJwtPart> protectedHeaderEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        BaseMemoryPool signaturePool,
        IReadOnlyDictionary<string, object>? unprotectedHeader,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(protectedHeaderEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);

        cancellationToken.ThrowIfCancellationRequested();

        TaggedMemory<byte> headerBytes = protectedHeaderEncoder(protectedHeader);
        string headerSegment = base64UrlEncoder(headerBytes.Span);
        bool base64UrlPayload = IsPayloadBase64UrlEncoded(headerBytes.Span);

        using IMemoryOwner<byte> dataToSignOwner = RentSigningInput(
            headerSegment, payload.Span, base64UrlPayload, base64UrlEncoder, signaturePool, out int signingInputLength);

        (Signature signature, CryptoEvent? evt) = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            dataToSignOwner.Memory[..signingInputLength],
            signaturePool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return new JwsMessage(
            payload,
            new JwsSignatureComponent(
                headerSegment,
                BuildProtectedHeaderDictionary(protectedHeader),
                signature,
                unprotectedHeader));
    }


    /// <summary>
    /// Verifies a JWS message using registry-resolved verification function,
    /// allocating the pooled signing-input buffer from the caller-supplied
    /// <paramref name="pool"/>.
    /// </summary>
    /// <param name="message">The JWS message to verify.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="pool">Memory pool for the pooled signing-input buffer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see langword="true"/> if the signature is valid; otherwise <see langword="false"/>, which is also the
    /// answer when the registry serves no verification function for <paramref name="publicKey"/>'s pair.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> has not been
    /// initialized, before any resolution, or when the message has multiple signatures.
    /// </exception>
    public static ValueTask<bool> VerifyAsync(
        JwsMessage message,
        EncodeDelegate base64UrlEncoder,
        PublicKeyMemory publicKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        return VerifyAsync(
            message, base64UrlEncoder, publicKey, ResolveRegistryVerification(publicKey), pool, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Verifies a JWS message using an explicit
    /// <see cref="VerificationDelegate"/>. The registry-resolving overload
    /// above delegates here after resolving the function via
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// from <paramref name="publicKey"/>'s <see cref="Lumoin.Base.SensitiveData.Tag"/>.
    /// </summary>
    /// <param name="message">The JWS message to verify.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="pool">Memory pool for the pooled signing-input buffer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="VerificationCompletedEvent"/> the resolved <paramref name="verificationDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// This overload resolves and invokes <paramref name="verificationDelegate"/> directly rather than
    /// through a bound <see cref="PublicKey"/>, so a <see cref="CryptoEventSink"/> is this call site's
    /// route — see <see cref="CryptoEventSink"/>.
    /// </param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the message has multiple signatures.
    /// </exception>
    public static async ValueTask<bool> VerifyAsync(
        JwsMessage message,
        EncodeDelegate base64UrlEncoder,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        BaseMemoryPool pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        if(message.Signatures.Count != 1)
        {
            throw new InvalidOperationException(
                $"This method verifies a single signature. Message has {message.Signatures.Count} signatures.");
        }

        JwsSignatureComponent signature = message.Signatures[0];

        string payloadSegment = message.IsDetachedPayload
            ? string.Empty
            : base64UrlEncoder(message.Payload.Span);

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            signature.Protected, payloadSegment, pool, out int signingInputLength);

        //The backend's refusal of presented material is "does not verify" (IsVerificationRefusal).
        bool isVerified;
        CryptoEvent? evt;
        try
        {
            (isVerified, evt) = await verificationDelegate(
                dataToVerifyOwner.Memory[..signingInputLength],
                signature.SignatureBytes,
                publicKey.AsReadOnlyMemory(),
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex) when(IsVerificationRefusal(ex))
        {
            return false;
        }

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return isVerified;
    }


    /// <summary>
    /// Verifies a single JWS signature over an already-parsed (protected-segment, payload) pair using an explicit
    /// <see cref="VerificationDelegate"/> — the building block for verifying a JSON-serialized JWS whose components
    /// have been parsed out (so there is no <see cref="JwsMessage"/> to pass). Reconstructs the RFC 7515 §5.1 signing
    /// input (<c>ASCII(b64url(protected) "." b64url(payload))</c>) and checks <paramref name="signature"/> against it
    /// with <paramref name="publicKey"/>; the algorithm is the caller's resolved key, never the wire <c>alg</c>.
    /// </summary>
    /// <param name="protectedSegment">The Base64Url-encoded protected header exactly as it appeared on the wire.</param>
    /// <param name="payload">The raw payload bytes the signature covers.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings; used to re-encode the payload segment.</param>
    /// <param name="verificationDelegate">The verification function to use.</param>
    /// <param name="publicKey">The verifying public key material.</param>
    /// <param name="pool">Memory pool for the signing-input buffer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static ValueTask<bool> VerifySignatureAsync(
        string protectedSegment,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature,
        EncodeDelegate base64UrlEncoder,
        VerificationDelegate verificationDelegate,
        ReadOnlyMemory<byte> publicKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        return VerifySignatureAsync(
            protectedSegment, payload, base64UrlPayload: true, signature,
            base64UrlEncoder, verificationDelegate, publicKey, pool, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Verifies a single JWS signature over a (protected-segment, detached payload) pair, honoring the RFC 7797
    /// <c>b64</c> option: when <paramref name="base64UrlPayload"/> is <see langword="false"/> the JWS Signing
    /// Input is <c>ASCII(b64url(protected) ".")</c> followed by the RAW <paramref name="payload"/> bytes
    /// (RFC 7797 §3), the form a <c>did:webplus</c> proof and other unencoded-payload JWS use. The caller reads
    /// the flag from the protected header (<see cref="WellKnownJoseHeaderNames.B64"/>) and is responsible for
    /// <c>crit</c> validation declaring <c>b64</c> understood. The algorithm is the caller's resolved key, never
    /// the wire <c>alg</c>.
    /// </summary>
    /// <param name="protectedSegment">The Base64Url-encoded protected header exactly as it appeared on the wire.</param>
    /// <param name="payload">The raw payload bytes the signature covers (supplied out of band for a detached JWS).</param>
    /// <param name="base64UrlPayload">Whether the payload is base64url-encoded in the signing input (RFC 7797 <c>b64</c>): <see langword="false"/> for the unencoded-payload option.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings; used only when <paramref name="base64UrlPayload"/> is <see langword="true"/>.</param>
    /// <param name="verificationDelegate">The verification function to use.</param>
    /// <param name="publicKey">The verifying public key material.</param>
    /// <param name="pool">Memory pool for the signing-input buffer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="VerificationCompletedEvent"/> the resolved <paramref name="verificationDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// This is the overload <c>Verifiable.DidComm</c>'s <c>UnpackSignedAsync</c> reaches (via the
    /// <paramref name="publicKey"/>-and-signature overload above, which forwards here); passing no explicit
    /// sink still publishes to the global stream via the default, matching what
    /// <c>DidCommFromPriorExtensions.VerifyFromPriorAsync</c> already does through its own internal emit
    /// access — the two routes now agree.
    /// </param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> VerifySignatureAsync(
        string protectedSegment,
        ReadOnlyMemory<byte> payload,
        bool base64UrlPayload,
        ReadOnlyMemory<byte> signature,
        EncodeDelegate base64UrlEncoder,
        VerificationDelegate verificationDelegate,
        ReadOnlyMemory<byte> publicKey,
        BaseMemoryPool pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(protectedSegment);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            protectedSegment, payload.Span, base64UrlPayload, base64UrlEncoder, pool, out int signingInputLength);

        //The backend's refusal of presented material is "does not verify" (IsVerificationRefusal).
        bool isVerified;
        CryptoEvent? evt;
        try
        {
            (isVerified, evt) = await verificationDelegate(
                dataToVerifyOwner.Memory[..signingInputLength],
                signature,
                publicKey,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex) when(IsVerificationRefusal(ex))
        {
            return false;
        }

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return isVerified;
    }


    /// <summary>
    /// Verifies a JWS compact serialization using registry-resolved
    /// verification function, applying <see cref="DefaultMaxJwsLength"/>
    /// as the upper bound on the input.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see langword="true"/> if the signature is valid; otherwise <see langword="false"/>, which is also the
    /// answer for every presented shape the explicit-function overload answers <see langword="false"/> for and
    /// for a <paramref name="publicKey"/> whose pair the registry serves no verification function for.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> has not been
    /// initialized, before any resolution.
    /// </exception>
    public static ValueTask<bool> VerifyAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
        => VerifyAsync(jws, base64UrlDecoder, pool, publicKey, DefaultMaxJwsLength, cancellationToken);


    /// <summary>
    /// Verifies a JWS compact serialization using registry-resolved
    /// verification function, with a caller-supplied
    /// <paramref name="maxJwsLength"/> upper bound, this library's own guard
    /// against a large allocation, stated by no specification.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="maxJwsLength">Maximum accepted JWS length, this library's own guard against a large allocation, stated by no specification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see langword="true"/> if the signature is valid; otherwise <see langword="false"/>, which is also the
    /// answer for every presented shape the explicit-function overload answers <see langword="false"/> for and
    /// for a <paramref name="publicKey"/> whose pair the registry serves no verification function for
    /// (<see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.TryResolveVerification"/>).
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="maxJwsLength"/> is zero or negative.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> has not been
    /// initialized, before any resolution.
    /// </exception>
    public static ValueTask<bool> VerifyAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        PublicKeyMemory publicKey,
        int maxJwsLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        return VerifyAsync(
            jws, base64UrlDecoder, pool,
            publicKey, ResolveRegistryVerification(publicKey), maxJwsLength, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Verifies a JWS compact serialization using an explicit verification
    /// function, applying <see cref="DefaultMaxJwsLength"/> as the upper
    /// bound on the input.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification function to use.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see langword="true"/> if the signature is valid; otherwise <see langword="false"/>, which is also the
    /// answer for a <paramref name="jws"/> longer than <see cref="DefaultMaxJwsLength"/> and for every other
    /// presented shape the overload with an explicit bound answers <see langword="false"/> for.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    public static ValueTask<bool> VerifyAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CancellationToken cancellationToken)
        => VerifyAsync(jws, base64UrlDecoder, pool, publicKey, verificationDelegate, DefaultMaxJwsLength, cancellationToken: cancellationToken);


    /// <summary>
    /// Verifies a JWS compact serialization using an explicit verification
    /// function, with a caller-supplied <paramref name="maxJwsLength"/>
    /// upper bound, this library's own guard against a large allocation,
    /// stated by no specification.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification function to use.</param>
    /// <param name="maxJwsLength">Maximum accepted JWS length, this library's own guard against a large allocation, stated by no specification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="VerificationCompletedEvent"/> the resolved <paramref name="verificationDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the signature is valid; otherwise <see langword="false"/>. A
    /// <paramref name="jws"/> longer than <paramref name="maxJwsLength"/> and one that is not the three parts of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.1">RFC 7515 Section 7.1</see> answer
    /// <see langword="false"/> in that order before any decoding, as do a header or signature segment that is
    /// empty, that is not the canonical unpadded base64url
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> defines (padding,
    /// white space, a character outside the alphabet, a length of 1 modulo 4, a set bit of the last character
    /// that carries no octet) or that the decoder refuses or decodes to no octets, a non-empty payload segment of
    /// any of those kinds (checked before the backend is asked), a protected header that fails the JSON gate
    /// (octets that are not valid UTF-8, no well-formed JSON object, a member name repeated at any depth, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515 Section 4</see> governs for the
    /// names of the JOSE Header, <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section
    /// 4</see> for a repeat at a nested depth and <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC
    /// 7517 Section 4</see> for the members of a header's <c>jwk</c>, a document beyond this library's reader
    /// bounds) or names a critical extension this consumer does not understand, and a signature the backend
    /// refuses: the input is the presenter's, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see> says "If any of
    /// the listed steps fails, then the signature or MAC cannot be validated." The payload is not decoded
    /// further, since a JWS payload is any octet sequence.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="maxJwsLength"/> is zero or negative.</exception>
    public static async ValueTask<bool> VerifyAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        int maxJwsLength,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxJwsLength);

        if(!IsJwsLengthAccepted(jws, maxJwsLength))
        {
            return false;
        }

        cancellationToken.ThrowIfCancellationRequested();

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            return false;
        }

        //A malformed signature segment cannot verify (TryDecodeSegment: a form that is not canonical unpadded
        //base64url, the decoder's FormatException, or no octets); it is a clean "does not verify" rather than an
        //exception. Callers depend on VerifyAsync returning false, never throwing, on untrusted input.
        using DecodedSegment signature = TryDecodeSegment(base64UrlDecoder, parts[2], pool);
        if(!signature.IsDecoded)
        {
            return false;
        }

        //RFC 7515 Section 4 / Section 4.1.11 and Section 5.2 step 3: a JWS whose protected header is not a JSON object
        //in valid UTF-8, repeats a parameter name or names an unrecognized critical extension is invalid. Decode the header
        //and fail closed to false, like a malformed segment, rather than verifying a message we cannot fully
        //process.
        using DecodedSegment protectedHeader = TryDecodeSegment(base64UrlDecoder, parts[0], pool);
        if(!protectedHeader.IsDecoded || !IsProtectedHeaderAcceptable(protectedHeader.Memory.Span))
        {
            return false;
        }

        //RFC 7515 Section 5.2 step 6: the payload segment is base64url; a malformed one (TryDecodeSegment: a form
        //that is not canonical unpadded base64url, the decoder's FormatException, or no octets) cannot verify, so it
        //is refused before the backend is asked. An empty segment is the base64url of an empty payload.
        if(parts[1].Length != 0)
        {
            using DecodedSegment payloadSegment = TryDecodeSegment(base64UrlDecoder, parts[1], pool);
            if(!payloadSegment.IsDecoded)
            {
                return false;
            }
        }

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            parts[0], parts[1], pool, out int signingInputLength);

        //The backend's refusal of presented material is "does not verify" (IsVerificationRefusal).
        bool isVerified;
        CryptoEvent? evt;
        try
        {
            (isVerified, evt) = await verificationDelegate(
                dataToVerifyOwner.Memory[..signingInputLength],
                signature.Memory,
                publicKey.AsReadOnlyMemory(),
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex) when(IsVerificationRefusal(ex))
        {
            return false;
        }

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return isVerified;
    }


    /// <summary>
    /// Verifies a JWS and returns the decoded header and payload, applying
    /// <see cref="DefaultMaxJwsLength"/> as the upper bound on the input.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to a claims dictionary.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The verification result containing validity and decoded parts. Every presented shape the
    /// explicit-function overload answers with an empty header and payload is answered the same way; a
    /// <paramref name="publicKey"/> whose pair the registry serves no verification function for answers
    /// <see cref="JwsVerificationResult.IsValid"/> <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> has not been
    /// initialized, before any resolution.
    /// </exception>
    public static ValueTask<JwsVerificationResult> VerifyAndDecodeAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool pool,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
        => VerifyAndDecodeAsync(jws, base64UrlDecoder, partDecoder, pool, publicKey, DefaultMaxJwsLength, cancellationToken);


    /// <summary>
    /// Verifies a JWS and returns the decoded header and payload, with a
    /// caller-supplied <paramref name="maxJwsLength"/> upper bound, this
    /// library's own guard against a large allocation, stated by no
    /// specification.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to a claims dictionary.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="maxJwsLength">Maximum accepted JWS length, this library's own guard against a large allocation, stated by no specification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The verification result containing validity and decoded parts. Every presented shape the
    /// explicit-function overload answers with an empty header and payload is answered the same way; a
    /// <paramref name="publicKey"/> whose pair the registry serves no verification function for
    /// (<see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.TryResolveVerification"/>) answers
    /// <see cref="JwsVerificationResult.IsValid"/> <see langword="false"/> with the decoded parts.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="maxJwsLength"/> is zero or negative.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> has not been
    /// initialized, before any resolution.
    /// </exception>
    public static ValueTask<JwsVerificationResult> VerifyAndDecodeAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool pool,
        PublicKeyMemory publicKey,
        int maxJwsLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        return VerifyAndDecodeAsync(
            jws, base64UrlDecoder, partDecoder, pool,
            publicKey, ResolveRegistryVerification(publicKey), maxJwsLength, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Verifies a JWS and returns the decoded header and payload using an
    /// explicit <see cref="VerificationDelegate"/>, with a caller-supplied
    /// <paramref name="maxJwsLength"/> upper bound, this library's own guard
    /// against a large allocation, stated by no specification. The
    /// registry-resolving overload above delegates here after resolving the
    /// function via
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// from <paramref name="publicKey"/>'s <see cref="Lumoin.Base.SensitiveData.Tag"/>.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to a claims dictionary.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="maxJwsLength">Maximum accepted JWS length, this library's own guard against a large allocation, stated by no specification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="VerificationCompletedEvent"/> the resolved <paramref name="verificationDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <returns>
    /// The verification result containing validity and decoded parts. The body reads the payload as a JWT Claims
    /// Set (<see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519 Section 7.2</see>), so it
    /// binds callers verifying a JWT. A <paramref name="jws"/> longer than <paramref name="maxJwsLength"/>, one
    /// that is not three parts, one with a segment that is empty, is not
    /// canonical unpadded base64url or that the decoder refuses or decodes to no octets, one whose protected
    /// header or claims set fails the JSON gate before <paramref name="partDecoder"/> runs on either (octets
    /// that are not valid UTF-8, no well-formed JSON object, a member name repeated at any depth, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515 Section 4</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519 Section 4</see> govern for the names
    /// of the JOSE Header and of the JWT Claims Set,
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see> for a repeat at a
    /// nested depth and <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 Section 4</see> for
    /// the members of a header's <c>jwk</c>, or a document deeper, with more member names or longer than this
    /// library's reader bounds, a guard of this library whose values no specification states), and one whose header or claims set
    /// <paramref name="partDecoder"/> refuses with <see cref="FormatException"/> answer a result whose
    /// <see cref="JwsVerificationResult.IsValid"/> is <see langword="false"/> with an empty header and payload;
    /// a protected header naming a critical extension this consumer does not understand and a signature the
    /// backend refuses or that does not verify answer <see langword="false"/> with the decoded parts.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="maxJwsLength"/> is zero or negative.</exception>
    public static async ValueTask<JwsVerificationResult> VerifyAndDecodeAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool pool,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        int maxJwsLength,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxJwsLength);

        if(!IsJwsLengthAccepted(jws, maxJwsLength))
        {
            return NotVerifiedUndecoded;
        }

        cancellationToken.ThrowIfCancellationRequested();

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            return NotVerifiedUndecoded;
        }

        using DecodedSegment headerSegment = TryDecodeSegment(base64UrlDecoder, parts[0], pool);
        using DecodedSegment payloadSegment = TryDecodeSegment(base64UrlDecoder, parts[1], pool);
        using DecodedSegment signatureSegment = TryDecodeSegment(base64UrlDecoder, parts[2], pool);

        //A malformed segment cannot verify (TryDecodeSegment: a form that is not canonical unpadded base64url, the
        //decoder's FormatException, or no octets); answer not verified rather than an exception on untrusted input.
        if(!headerSegment.IsDecoded || !payloadSegment.IsDecoded || !signatureSegment.IsDecoded)
        {
            return NotVerifiedUndecoded;
        }

        //RFC 7515 Section 5.2 step 3 and RFC 7519 Section 7.2 step 10: the protected header and the claims
        //set are JSON objects in valid UTF-8. A presented segment that is not one is refused before the
        //caller's part decoder runs on it, so the decoder only ever reads a well-formed JSON object.
        if(!IsWellFormedJsonObject(headerSegment.Memory.Span) || !IsWellFormedJsonObject(payloadSegment.Memory.Span))
        {
            return NotVerifiedUndecoded;
        }

        if(!TryDecodeParts(partDecoder, headerSegment.Memory.Span, payloadSegment.Memory.Span, out JwtHeader? header, out JwtPayload? payload))
        {
            return NotVerifiedUndecoded;
        }

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            parts[0], parts[1], pool, out int signingInputLength);

        //RFC 7515 Section 4.1.11: a JWS that names an unrecognized critical extension is invalid; the decoded
        //header/payload are returned for inspection, with isValid false.
        bool isHeaderAcceptable = IsProtectedHeaderAcceptable(headerSegment.Memory.Span);
        bool isValid = false;

        if(isHeaderAcceptable)
        {
            //The backend's refusal of presented material is "does not verify" (IsVerificationRefusal).
            bool isVerified;
            CryptoEvent? evt;
            try
            {
                (isVerified, evt) = await verificationDelegate(
                    dataToVerifyOwner.Memory[..signingInputLength],
                    signatureSegment.Memory,
                    publicKey.AsReadOnlyMemory(),
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(IsVerificationRefusal(ex))
            {
                return new JwsVerificationResult(false, header, payload);
            }

            if(evt is not null)
            {
                (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
            }

            isValid = isVerified;
        }

        return new JwsVerificationResult(isValid, header, payload);
    }


    /// <summary>
    /// Creates a JWS using resolver/binder pattern for key resolution.
    /// </summary>
    /// <remarks>
    /// This is the second sanctioned route <see cref="CryptoEventSink"/> describes: <paramref name="binder"/>
    /// constructs a <see cref="PrivateKey"/> around the resolved material, so signing goes through
    /// <see cref="PrivateKey.SignAsync"/> — the choke point that always emits to
    /// <see cref="CryptographicKeyEvents.Events"/> — with no <see cref="CryptoEventSink"/> parameter needed
    /// here at all. A caller already holding (or able to cheaply construct) key material uses this route; a
    /// caller that only holds raw, disassembled key material uses one of the sink-threaded
    /// explicit-delegate <c>SignAsync</c> overloads instead. Both routes emit; neither discards.
    /// </remarks>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <param name="header">The JWT header containing algorithm information.</param>
    /// <param name="payload">The JWT payload.</param>
    /// <param name="partEncoder">Encodes JWT parts to bytes.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="pool">Memory pool for signature allocation.</param>
    /// <param name="resolverState">State for key material resolution.</param>
    /// <param name="resolver">Resolves and loads private key material from context.</param>
    /// <param name="binderState">State for key material binding.</param>
    /// <param name="binder">Binds signing function to key material.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The JWS message containing the signature.</returns>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static async ValueTask<JwsMessage> SignAsync<TResolverState, TBinderState>(
        JwtHeader header,
        JwtPayload payload,
        JwtPartEncoder<JoseDictionary> partEncoder,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool pool,
        TResolverState resolverState,
        KeyMaterialResolver<PrivateKeyMemory, JoseKeyContext, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PrivateKeyMemory, PrivateKey, TBinderState> binder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(partEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(binder);

        TaggedMemory<byte> headerBytes = partEncoder(header);
        TaggedMemory<byte> payloadBytes = partEncoder(payload);

        string headerSegment = base64UrlEncoder(headerBytes.Span);
        string payloadSegment = base64UrlEncoder(payloadBytes.Span);

        using IMemoryOwner<byte> dataToSignOwner = RentSigningInput(
            headerSegment, payloadSegment, pool, out int signingInputLength);

        var context = new JoseKeyContext(header, payload);

        PrivateKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false);

        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        using PrivateKey privateKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);
        Signature signature = await privateKey.SignAsync(
            dataToSignOwner.Memory[..signingInputLength], pool).ConfigureAwait(false);

        var protectedHeader = BuildProtectedHeaderDictionary(header);

        var signatureComponent = new JwsSignatureComponent(
            headerSegment,
            protectedHeader,
            signature);

        return new JwsMessage(payloadBytes.Memory, signatureComponent);
    }


    /// <summary>
    /// Verifies a JWS using resolver/binder pattern for key resolution,
    /// applying <see cref="DefaultMaxJwsLength"/> as the upper bound on the input.
    /// </summary>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <returns>
    /// <see langword="true"/> if the signature is valid; otherwise <see langword="false"/>, which is also the
    /// answer for a <paramref name="jws"/> longer than <see cref="DefaultMaxJwsLength"/> and for every other
    /// presented shape the overload with an explicit bound answers <see langword="false"/> for, a resolver that
    /// answers no key material included.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    public static ValueTask<bool> VerifyAsync<TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool pool,
        TResolverState resolverState,
        KeyMaterialResolver<PublicKeyMemory, JoseKeyContext, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PublicKeyMemory, PublicKey, TBinderState> binder,
        CancellationToken cancellationToken = default)
        => VerifyAsync(jws, base64UrlDecoder, partDecoder, pool, resolverState, resolver, binderState, binder, DefaultMaxJwsLength, cancellationToken);


    /// <summary>
    /// Verifies a JWS using resolver/binder pattern for key resolution,
    /// with a caller-supplied <paramref name="maxJwsLength"/> upper bound,
    /// this library's own guard against a large allocation, stated by no
    /// specification.
    /// </summary>
    /// <remarks>
    /// The verify-side counterpart of the resolver/binder <c>SignAsync</c> overload's remarks: <paramref name="binder"/>
    /// constructs a <see cref="PublicKey"/>, so verification goes through <see cref="PublicKey.VerifyAsync"/>
    /// and emits with no <see cref="CryptoEventSink"/> parameter needed — see <see cref="CryptoEventSink"/>
    /// for the two-route rationale.
    /// </remarks>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <returns>
    /// <see langword="true"/> if the signature is valid; otherwise <see langword="false"/>. The body reads the
    /// payload as a JWT Claims Set (<see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519
    /// Section 7.2</see>) for the resolver's context, so it binds callers verifying a JWT. It answers
    /// <see langword="false"/> for a <paramref name="jws"/> longer than <paramref name="maxJwsLength"/>, one that
    /// is not three parts, one with a segment that is empty, is not
    /// canonical unpadded base64url or that the decoder refuses or decodes to no octets, one whose protected
    /// header or claims set fails the JSON gate before <paramref name="partDecoder"/> runs on either (octets
    /// that are not valid UTF-8, no well-formed JSON object, a member name repeated at any depth, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515 Section 4</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519 Section 4</see> govern for the names
    /// of the JOSE Header and of the JWT Claims Set,
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see> for a repeat at a
    /// nested depth and <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 Section 4</see> for
    /// the members of a header's <c>jwk</c>, or a document deeper, with more member names or longer than this
    /// library's reader bounds, a guard of this library whose values no specification states), one whose header or claims set
    /// <paramref name="partDecoder"/> refuses with <see cref="FormatException"/>, one whose protected header
    /// names a critical extension this consumer does not understand, one for which <paramref name="resolver"/>
    /// answers no key material, and a signature the bound public key's backend refuses.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="maxJwsLength"/> is zero or negative.</exception>
    public static async ValueTask<bool> VerifyAsync<TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool pool,
        TResolverState resolverState,
        KeyMaterialResolver<PublicKeyMemory, JoseKeyContext, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PublicKeyMemory, PublicKey, TBinderState> binder,
        int maxJwsLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(binder);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxJwsLength);

        if(!IsJwsLengthAccepted(jws, maxJwsLength))
        {
            return false;
        }

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            return false;
        }

        using DecodedSegment headerSegment = TryDecodeSegment(base64UrlDecoder, parts[0], pool);
        using DecodedSegment payloadSegment = TryDecodeSegment(base64UrlDecoder, parts[1], pool);
        using DecodedSegment signatureSegment = TryDecodeSegment(base64UrlDecoder, parts[2], pool);

        //A malformed segment cannot verify (TryDecodeSegment: a form that is not canonical unpadded base64url, the
        //decoder's FormatException, or no octets); fail closed to false rather than an exception on untrusted input.
        if(!headerSegment.IsDecoded || !payloadSegment.IsDecoded || !signatureSegment.IsDecoded)
        {
            return false;
        }

        //RFC 7515 Section 4 / Section 4.1.11 and Section 5.2 step 3: fail closed to false on a protected header that is not
        //a JSON object in valid UTF-8, repeats a parameter or names an unrecognized critical extension. The payload is
        //decoded for the resolver's context, so it is a JSON object too (RFC 7519 Section 7.2 step 10)
        //before the caller's part decoder runs on it.
        if(!IsProtectedHeaderAcceptable(headerSegment.Memory.Span) || !IsWellFormedJsonObject(payloadSegment.Memory.Span))
        {
            return false;
        }

        if(!TryDecodeParts(partDecoder, headerSegment.Memory.Span, payloadSegment.Memory.Span, out JwtHeader? header, out JwtPayload? payload))
        {
            return false;
        }

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            parts[0], parts[1], pool, out int signingInputLength);

        var context = new JoseKeyContext(header, payload);

        //The resolver is handed the presented header and payload; it answers no key material when it holds none
        //for them (a kid it does not hold), and no signature can be validated without a public key.
        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false);

        if(material is null)
        {
            return false;
        }

        Tag signatureTag = material.Tag;
        using PublicKey publicKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> signatureMemory = pool.Rent(signatureSegment.Memory.Length);
        signatureSegment.Memory.Span.CopyTo(signatureMemory.Memory.Span);
        using var signature = new Signature(signatureMemory, signatureTag);

        //The backend's refusal of presented material is "does not verify" (IsVerificationRefusal), the same
        //boundary the explicit-function bodies apply.
        try
        {
            return await publicKey.VerifyAsync(
                dataToVerifyOwner.Memory[..signingInputLength], signature).ConfigureAwait(false);
        }
        catch(Exception ex) when(IsVerificationRefusal(ex))
        {
            return false;
        }
    }


    /// <summary>
    /// Verifies a JWS and returns the decoded payload using resolver/binder
    /// pattern, applying <see cref="DefaultMaxJwsLength"/> as the upper
    /// bound on the input.
    /// </summary>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <returns>
    /// The verification result containing validity and decoded parts. A <paramref name="jws"/> longer than
    /// <see cref="DefaultMaxJwsLength"/> and every other presented shape the overload with an explicit bound
    /// answers with an empty header and payload are answered the same way, and a resolver that answers no
    /// key material answers <see cref="JwsVerificationResult.IsValid"/> <see langword="false"/> with the decoded parts.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    public static ValueTask<JwsVerificationResult> VerifyAndDecodeAsync<TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool pool,
        TResolverState resolverState,
        KeyMaterialResolver<PublicKeyMemory, JoseKeyContext, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PublicKeyMemory, PublicKey, TBinderState> binder,
        CancellationToken cancellationToken = default)
        => VerifyAndDecodeAsync(jws, base64UrlDecoder, partDecoder, pool, resolverState, resolver, binderState, binder, DefaultMaxJwsLength, cancellationToken);


    /// <summary>
    /// Verifies a JWS and returns the decoded payload using resolver/binder
    /// pattern, with a caller-supplied <paramref name="maxJwsLength"/>
    /// upper bound, this library's own guard against a large allocation,
    /// stated by no specification.
    /// </summary>
    /// <remarks>
    /// The verify-and-decode counterpart of the resolver/binder <c>VerifyAsync</c> overload's remarks:
    /// <paramref name="binder"/> constructs a <see cref="PublicKey"/>, so verification goes through
    /// <see cref="PublicKey.VerifyAsync"/> and emits with no <see cref="CryptoEventSink"/> parameter
    /// needed — see <see cref="CryptoEventSink"/>.
    /// </remarks>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <returns>
    /// The verification result containing validity and decoded parts. The body reads the payload as a JWT Claims
    /// Set (<see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519 Section 7.2</see>), so it
    /// binds callers verifying a JWT. A <paramref name="jws"/> longer than <paramref name="maxJwsLength"/>, one
    /// that is not three parts, one with a segment that is empty, is not
    /// canonical unpadded base64url or that the decoder refuses or decodes to no octets, one whose protected
    /// header or claims set fails the JSON gate before <paramref name="partDecoder"/> runs on either (octets
    /// that are not valid UTF-8, no well-formed JSON object, a member name repeated at any depth, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515 Section 4</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519 Section 4</see> govern for the names
    /// of the JOSE Header and of the JWT Claims Set,
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see> for a repeat at a
    /// nested depth and <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 Section 4</see> for
    /// the members of a header's <c>jwk</c>, or a document deeper, with more member names or longer than this
    /// library's reader bounds, a guard of this library whose values no specification states), and one whose header or claims set
    /// <paramref name="partDecoder"/> refuses with <see cref="FormatException"/> answer a result whose
    /// <see cref="JwsVerificationResult.IsValid"/> is <see langword="false"/> with an empty header and payload;
    /// a protected header naming a critical extension this consumer does not understand, a
    /// <paramref name="resolver"/> that answers no key material, and a signature the bound public key's backend
    /// refuses or that does not verify answer <see langword="false"/> with the decoded parts.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="maxJwsLength"/> is zero or negative.</exception>
    public static async ValueTask<JwsVerificationResult> VerifyAndDecodeAsync<TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool pool,
        TResolverState resolverState,
        KeyMaterialResolver<PublicKeyMemory, JoseKeyContext, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PublicKeyMemory, PublicKey, TBinderState> binder,
        int maxJwsLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(binder);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxJwsLength);

        if(!IsJwsLengthAccepted(jws, maxJwsLength))
        {
            return NotVerifiedUndecoded;
        }

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            return NotVerifiedUndecoded;
        }

        using DecodedSegment headerSegment = TryDecodeSegment(base64UrlDecoder, parts[0], pool);
        using DecodedSegment payloadSegment = TryDecodeSegment(base64UrlDecoder, parts[1], pool);
        using DecodedSegment signatureSegment = TryDecodeSegment(base64UrlDecoder, parts[2], pool);

        //A malformed segment cannot verify (TryDecodeSegment: a form that is not canonical unpadded base64url, the
        //decoder's FormatException, or no octets); answer not verified rather than an exception on untrusted input.
        if(!headerSegment.IsDecoded || !payloadSegment.IsDecoded || !signatureSegment.IsDecoded)
        {
            return NotVerifiedUndecoded;
        }

        //RFC 7515 Section 5.2 step 3 and RFC 7519 Section 7.2 step 10: the protected header and the claims
        //set are JSON objects in valid UTF-8. A presented segment that is not one is refused before the
        //caller's part decoder runs on it, so the decoder only ever reads a well-formed JSON object.
        if(!IsWellFormedJsonObject(headerSegment.Memory.Span) || !IsWellFormedJsonObject(payloadSegment.Memory.Span))
        {
            return NotVerifiedUndecoded;
        }

        if(!TryDecodeParts(partDecoder, headerSegment.Memory.Span, payloadSegment.Memory.Span, out JwtHeader? header, out JwtPayload? payload))
        {
            return NotVerifiedUndecoded;
        }

        //RFC 7515 Section 4.1.11: an unrecognized critical extension makes the JWS invalid; return the
        //decoded header/payload for inspection but do not resolve keys or verify a message we cannot fully
        //process.
        if(!IsProtectedHeaderAcceptable(headerSegment.Memory.Span))
        {
            return new JwsVerificationResult(false, header, payload);
        }

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            parts[0], parts[1], pool, out int signingInputLength);

        var context = new JoseKeyContext(header, payload);

        //The resolver is handed the presented header and payload; it answers no key material when it holds none
        //for them (a kid it does not hold), and no signature can be validated without a public key.
        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false);

        if(material is null)
        {
            return new JwsVerificationResult(false, header, payload);
        }

        Tag signatureTag = material.Tag;
        using PublicKey publicKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> signatureMemory = pool.Rent(signatureSegment.Memory.Length);
        signatureSegment.Memory.Span.CopyTo(signatureMemory.Memory.Span);
        using var signature = new Signature(signatureMemory, signatureTag);

        //The backend's refusal of presented material is "does not verify" (IsVerificationRefusal), the same
        //boundary the explicit-function bodies apply.
        bool isValid;
        try
        {
            isValid = await publicKey.VerifyAsync(
                dataToVerifyOwner.Memory[..signingInputLength], signature).ConfigureAwait(false);
        }
        catch(Exception ex) when(IsVerificationRefusal(ex))
        {
            isValid = false;
        }

        return new JwsVerificationResult(isValid, header, payload);
    }


    /// <summary>
    /// The shared protected-header gate of every verify body: the decoded header passes
    /// <see cref="IsWellFormedJsonObject"/>, a well-formed JSON object in valid UTF-8
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 3: "Verify
    /// that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object
    /// conforming to RFC 7159 [RFC7159]; let the JWS Protected Header be this JSON object."), carries unique
    /// parameter names at every nesting depth (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515
    /// Section 4</see> for the names of the JOSE Header, <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC
    /// 8259 Section 4</see> for an object at a nested depth, <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC
    /// 7517 Section 4</see> for the members of a header's <c>jwk</c>), and names no
    /// critical extension this consumer does not understand
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11">RFC 7515 Section 4.1.11</see>). Each
    /// check reads the decoded bytes and never throws, so every verify body fails closed to its not-verified value.
    /// </summary>
    /// <param name="protectedHeaderJson">The decoded protected header octets.</param>
    /// <returns><see langword="true"/> when the header passes every check.</returns>
    private static bool IsProtectedHeaderAcceptable(ReadOnlySpan<byte> protectedHeaderJson) =>
        IsWellFormedJsonObject(protectedHeaderJson)
        && JoseCriticalHeaderValidation.IsSatisfied(protectedHeaderJson);


    /// <summary>
    /// The JSON gate a verify body runs over a presented protected header or claims set before a caller's part
    /// decoder reads it, so the decoder only ever reads a JSON object: the octets are valid UTF-8
    /// (<see cref="System.Text.Unicode.Utf8.IsValid(ReadOnlySpan{byte})"/>), the first octet after insignificant
    /// whitespace (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>) opens an
    /// object, and <see cref="JwkJsonReader.IsWellFormedJsonDocument"/> reads the whole as one well-formed JSON
    /// value. <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 3:
    /// "Verify that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON
    /// object conforming to RFC 7159 [RFC7159]; let the JWS Protected Header be this JSON object." That reader
    /// also refuses a member name repeated at any depth: a repeated name of the JOSE Header or of the JWT Claims
    /// Set, which <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515 Section 4</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519 Section 4</see> permit a parser to
    /// reject, a repeat in an object at a nested depth, of which
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see> says "The names within
    /// an object SHOULD be unique.", and a repeated member of a header's <c>jwk</c>, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 Section 4</see> permits a parser to
    /// reject. It refuses a document nested deeper, holding more live member names or longer than its bounds; those
    /// bounds are this library's own guard, whose values no specification states
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC 8259 Section 9</see>: "An implementation
    /// may set limits on the size of texts that it accepts.").
    /// </summary>
    /// <param name="json">The decoded segment octets.</param>
    /// <returns><see langword="true"/> when the octets pass the gate; never throws.</returns>
    private static bool IsWellFormedJsonObject(ReadOnlySpan<byte> json)
    {
        ReadOnlySpan<byte> value = json.TrimStart(" \t\n\r"u8);

        return !value.IsEmpty
            && value[0] == (byte)'{'
            && System.Text.Unicode.Utf8.IsValid(json)
            && JwkJsonReader.IsWellFormedJsonDocument(json);
    }


    /// <summary>
    /// The one boundary between a verify body and the caller's part decoder: decodes a protected header and a
    /// claims set that passed <see cref="IsWellFormedJsonObject"/> with <paramref name="partDecoder"/>, and answers
    /// <see langword="false"/> when the decoder refuses either with <see cref="FormatException"/>, the refusal a
    /// <see cref="JwtPartDecoder"/> raises for part bytes it cannot decode (the library's own default decoder
    /// <c>JwtPartJson.Default</c> refuses a number outside the range it reads, an empty member name and an
    /// escaped unpaired surrogate that way). A refused part is presented input, which the body answers with its
    /// not-verified value; every other exception of the decoder is its own fault and propagates.
    /// </summary>
    /// <param name="partDecoder">The caller's part decoder.</param>
    /// <param name="headerJson">The protected header octets.</param>
    /// <param name="payloadJson">The claims set octets.</param>
    /// <param name="header">The decoded header, or <see langword="null"/> when the decoder refused a part.</param>
    /// <param name="payload">The decoded claims set, or <see langword="null"/> when the decoder refused a part.</param>
    /// <returns><see langword="true"/> when both parts decoded.</returns>
    private static bool TryDecodeParts(
        JwtPartDecoder partDecoder,
        ReadOnlySpan<byte> headerJson,
        ReadOnlySpan<byte> payloadJson,
        [NotNullWhen(true)] out JwtHeader? header,
        [NotNullWhen(true)] out JwtPayload? payload)
    {
        IReadOnlyDictionary<string, object> headerClaims;
        IReadOnlyDictionary<string, object> payloadClaims;
        try
        {
            headerClaims = partDecoder(headerJson);
            payloadClaims = partDecoder(payloadJson);
        }
        catch(FormatException)
        {
            header = null;
            payload = null;

            return false;
        }

        header = new JwtHeader(headerClaims);
        payload = new JwtPayload(payloadClaims);

        return true;
    }


    /// <summary>
    /// Whether <paramref name="exception"/>, raised by a verification backend while it verified presented
    /// material, is that backend's refusal of the material, which every verify body answers as "does not
    /// verify". The public key can itself be presented content (a header <c>jwk</c>, a coordinate the caller
    /// read from a token), and the signature always is. The providers in this tree answer such material as
    /// follows, provider by provider. Microsoft ECDSA answers <see langword="false"/>, raising nothing, for public
    /// key octets that are no point of the curve the member names (a length or first octet that is neither SEC1
    /// encoding of that curve, a coordinate not below the field prime, a point not on the curve, each checked
    /// before the platform is asked), for a point the platform refuses to import with
    /// <see cref="CryptographicException"/> and for a signature the platform does not verify;
    /// <see cref="PlatformNotSupportedException"/> leaves it only when the platform does not serve the curve, and a
    /// verify body answers that as not verified too. The RSA verifiers of both providers read the public key
    /// octets by the one rule each provider's class documentation states (the remarks of
    /// <c>MicrosoftCryptographicFunctions</c>, the summary of <c>BouncyCastleCryptographicFunctions</c>), and hold
    /// every reading to <c>RsaUtilities.IsValidPublicKey</c> before it is used. Microsoft RSA answers
    /// <see langword="false"/>, raising nothing, for octets that are no public key by that rule, for a reading
    /// that is no valid RSA public key, for the platform's <see cref="CryptographicException"/> and for a signature
    /// the platform does not verify.
    /// Libsodium's Ed25519 raises <see cref="ArgumentException"/> for a public key that is not 32 octets or a
    /// signature that is not 64, which a verify body answers as not verified. Every BouncyCastle verifier (ECDSA,
    /// RSA, Ed25519, ML-DSA) answers <see langword="false"/>, raising nothing, for presented public key and
    /// signature octets it or BouncyCastle refuses, and reads only the encodings its algorithm defines (for RSA also
    /// the bare modulus, by that rule). A strict parser of encodings raises <see cref="FormatException"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." Every other exception, cancellation included, propagates.
    /// </summary>
    /// <param name="exception">The exception the backend raised.</param>
    /// <returns><see langword="true"/> when the exception is the backend's refusal of presented material.</returns>
    private static bool IsVerificationRefusal(Exception exception) =>
        exception is CryptographicException or ArgumentException or FormatException or PlatformNotSupportedException;


    /// <summary>
    /// The outcome of decoding one base64url segment of an inbound (untrusted) compact JWS. A decoded
    /// segment owns a pooled buffer; a malformed segment, one whose form <see cref="TryDecodeSegment"/> refuses or
    /// that the injected decoder rejects or decodes to no octets, carries
    /// none. Disposing releases the buffer (a no-op when malformed), so verify paths can <c>using</c>
    /// the outcome and branch on <see cref="IsDecoded"/> instead of threading a nullable owner and
    /// conflating "failed" with "null". A segment that cannot be decoded cannot verify, which is how
    /// the verify overloads honour the contract that verification of untrusted input never throws on
    /// malformed content.
    /// </summary>
    private readonly struct DecodedSegment: IDisposable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DecodedSegment"/> struct.
        /// </summary>
        /// <param name="owner">
        /// The pooled buffer owning the decoded bytes, or <see langword="null"/> when the segment was malformed.
        /// </param>
        private DecodedSegment(IMemoryOwner<byte>? owner) => Owner = owner;

        /// <summary>
        /// The pooled buffer owning the decoded bytes, or <see langword="null"/> when the segment could not be decoded.
        /// </summary>
        private IMemoryOwner<byte>? Owner { get; }

        /// <summary>
        /// Wraps a successfully decoded segment around the pooled buffer it owns. Ownership transfers to
        /// the returned value, which the caller disposes.
        /// </summary>
        /// <param name="owner">The pooled buffer holding the decoded bytes.</param>
        /// <returns>A decoded segment whose <see cref="IsDecoded"/> is <see langword="true"/>.</returns>
        public static DecodedSegment Decoded(IMemoryOwner<byte> owner) => new(owner);

        /// <summary>
        /// A segment that could not be decoded. It owns no buffer and its <see cref="IsDecoded"/> is
        /// <see langword="false"/>.
        /// </summary>
        public static DecodedSegment Malformed => default;

        /// <summary>
        /// <see langword="true"/> when the segment decoded to a pooled buffer; <see langword="false"/>
        /// when the segment was malformed.
        /// </summary>
        public bool IsDecoded => Owner is not null;

        /// <summary>
        /// The decoded bytes when <see cref="IsDecoded"/> is <see langword="true"/>; otherwise
        /// <see cref="ReadOnlyMemory{T}.Empty"/>.
        /// </summary>
        public ReadOnlyMemory<byte> Memory => Owner is null ? ReadOnlyMemory<byte>.Empty : Owner.Memory;

        /// <summary>
        /// Releases the pooled buffer. A no-op when the segment was malformed.
        /// </summary>
        public void Dispose() => Owner?.Dispose();
    }


    /// <summary>
    /// Decodes one base64url segment of a presented compact JWS, the one body every verify body decodes a segment
    /// through. The segment's form is this library's check, made before the caller's decoder is asked
    /// (<see cref="IsUnpaddedBase64UrlSegment"/>): a segment that is empty, holds a character outside the unpadded
    /// base64url alphabet (padding and white space included), has a length of 1 modulo 4, or sets a bit of its
    /// last character that carries no octet answers <see cref="DecodedSegment.Malformed"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> defines Base64url
    /// Encoding as "Base64 encoding using the URL- and filename-safe character set defined in Section 5 of RFC 4648
    /// [RFC4648], with all trailing '=' characters omitted (as permitted by Section 3.2) and without the inclusion of
    /// any line breaks, whitespace, or other additional characters."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">Section 5.2</see>, step 2: "Base64url-decode
    /// the encoded representation of the JWS Protected Header, following the restriction that no line breaks,
    /// whitespace, or other additional characters have been used." Steps 6 and 7 place the same restriction on the
    /// JWS Payload and the JWS Signature. The .NET <c>Base64Url</c> decoders accept padding and skip white space,
    /// so a caller's decoder is never relied on for either, and each segment is read only in the one canonical
    /// spelling of its encoding. That is a rule on each segment's encoding, not a claim that a token has one
    /// spelling: an ECDSA signature (r, s) has the twin (r, n - s), which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">RFC 7518 Section 3.4</see> does not forbid and
    /// this library does not refuse. An
    /// empty segment is malformed because every caller decodes a part that cannot be empty (a protected header, a
    /// claims set, a signature); the explicit compact <c>VerifyAsync</c> does not hand it an empty payload
    /// segment, which is the base64url of an empty payload. A segment the decoder refuses with
    /// <see cref="FormatException"/>, the refusal the <see cref="DecodeDelegate"/> contract names, answers
    /// <see cref="DecodedSegment.Malformed"/>, and so does a decoder's answer of no octets for the segment, which
    /// encodes at least one: the owner is disposed and no body rents a buffer of no octets whatever the decoder
    /// does. Every other exception of the caller's decoder or of <paramref name="pool"/> is a fault of that
    /// dependency, not a property of the presented input, and propagates.
    /// </summary>
    /// <param name="base64UrlDecoder">The caller's base64url decoder.</param>
    /// <param name="segment">The presented segment.</param>
    /// <param name="pool">The pool the decoded octets are rented from.</param>
    /// <returns>The decoded segment, or <see cref="DecodedSegment.Malformed"/>.</returns>
    private static DecodedSegment TryDecodeSegment(DecodeDelegate base64UrlDecoder, string segment, BaseMemoryPool pool)
    {
        if(!IsUnpaddedBase64UrlSegment(segment))
        {
            return DecodedSegment.Malformed;
        }

        IMemoryOwner<byte> decoded;
        try
        {
            decoded = base64UrlDecoder(segment, pool);
        }
        catch(FormatException)
        {
            return DecodedSegment.Malformed;
        }

        if(decoded.Memory.IsEmpty)
        {
            decoded.Dispose();

            return DecodedSegment.Malformed;
        }

        return DecodedSegment.Decoded(decoded);
    }


    /// <summary>
    /// Whether <paramref name="segment"/> is the canonical unpadded base64url encoding of some octets: it is not
    /// empty, every character is one of <c>A</c> to <c>Z</c>, <c>a</c> to <c>z</c>, <c>0</c> to <c>9</c>,
    /// <c>-</c> and <c>_</c> (the URL- and filename-safe alphabet
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> names, with no
    /// <c>=</c> and no white space), its length is not 1 modulo 4 (no octet sequence encodes to such a length),
    /// and its last character sets no bit beyond the octets the segment encodes: at a length of 2 modulo 4 the
    /// low four bits of the last character's value carry no octet, at 3 modulo 4 the low two. An encoder writes
    /// those bits as zero; a decoder that ignores them would read one octet sequence from several spellings, so
    /// this library refuses them, a rule of its own.
    /// </summary>
    /// <param name="segment">The presented segment.</param>
    /// <returns><see langword="true"/> when the segment is canonical unpadded base64url.</returns>
    private static bool IsUnpaddedBase64UrlSegment(ReadOnlySpan<char> segment)
    {
        if(segment.IsEmpty || segment.Length % 4 == 1 || segment.ContainsAnyExcept(Base64UrlAlphabet))
        {
            return false;
        }

        int unusedBits = (segment.Length % 4) switch
        {
            2 => 0x0F,
            3 => 0x03,
            _ => 0x00
        };

        return (Base64UrlValue(segment[^1]) & unusedBits) == 0;
    }


    /// <summary>
    /// The 64 characters of the unpadded base64url alphabet
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>), searched by
    /// <see cref="IsUnpaddedBase64UrlSegment"/>.
    /// </summary>
    private static SearchValues<char> Base64UrlAlphabet { get; } =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");


    /// <summary>
    /// The six-bit value of a base64url alphabet character: <c>A</c> to <c>Z</c> are 0 to 25, <c>a</c> to
    /// <c>z</c> 26 to 51, <c>0</c> to <c>9</c> 52 to 61, <c>-</c> 62 and <c>_</c> 63.
    /// </summary>
    /// <param name="character">A character of <see cref="Base64UrlAlphabet"/>.</param>
    /// <returns>The character's value.</returns>
    private static int Base64UrlValue(char character) => character switch
    {
        >= 'A' and <= 'Z' => character - 'A',
        >= 'a' and <= 'z' => character - 'a' + 26,
        >= '0' and <= '9' => character - '0' + 52,
        '-' => 62,
        _ => 63
    };


    /// <summary>
    /// Whether the length of <paramref name="jws"/> is within <paramref name="maxJwsLength"/>. The pooled
    /// signing-input buffer is sized from the JWS parts, so an unbounded JWS would translate to an unbounded
    /// pool rental, a large-allocation denial-of-service vector that this library's own bound, stated by no
    /// specification, guards against. A presented JWS over the bound is the presenter's input, so each verify
    /// path answers its own not-verified value for it before any split or decode; refusing early also makes the
    /// subsequent length arithmetic immune to integer overflow.
    /// </summary>
    /// <param name="jws">The presented compact serialization.</param>
    /// <param name="maxJwsLength">The accepted maximum length, in characters.</param>
    /// <returns><see langword="true"/> when the length is within the bound.</returns>
    private static bool IsJwsLengthAccepted(string jws, int maxJwsLength) => jws.Length <= maxJwsLength;


    /// <summary>
    /// The not-verified answer of a <c>VerifyAndDecodeAsync</c> path for a presented compact JWS it cannot
    /// decode: one longer than the accepted bound, one that is not three parts, one with a segment that is empty,
    /// is not canonical unpadded base64url or that the decoder refuses or decodes to no octets, or one whose
    /// protected header or claims set fails the JSON gate or the caller's part decoder refuses.
    /// <see cref="JwsVerificationResult.IsValid"/> is <see langword="false"/> and the header and
    /// payload are empty, a fresh pair per answer since both are mutable dictionaries.
    /// </summary>
    private static JwsVerificationResult NotVerifiedUndecoded => new(false, new JwtHeader(), new JwtPayload());


    /// <summary>
    /// The verification function a registry overload hands its explicit-function body when the registry
    /// serves no function for the public key's pair: it verifies nothing and answers not verified with no event, so
    /// the body keeps its argument checks and its shape checks and the presented input is refused as a value
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>).
    /// </summary>
    private static VerificationDelegate UnservedPairVerification { get; } =
        static (_, _, _, _, _) => ValueTask.FromResult<(bool IsVerified, CryptoEvent? Event)>((false, null));


    /// <summary>
    /// Resolves the verification function for <paramref name="publicKey"/>'s (algorithm, purpose) pair through
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.TryResolveVerification"/>, answering
    /// <see cref="UnservedPairVerification"/> for a pair the registry does not serve: the public key of a
    /// presented JWS can come from the presenter, so an unserved pair is a verification that fails, never a
    /// fault. When <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.IsInitialized"/> is
    /// <see langword="false"/>, the registry is the deployment's composition, never input, so this member throws
    /// before any resolution with a message that names the registry.
    /// </summary>
    /// <param name="publicKey">The public key whose tag names the pair.</param>
    /// <returns>The resolved function, or <see cref="UnservedPairVerification"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.IsInitialized"/> is
    /// <see langword="false"/>.
    /// </exception>
    private static VerificationDelegate ResolveRegistryVerification(PublicKeyMemory publicKey)
    {
        if(!CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.IsInitialized)
        {
            throw new InvalidOperationException(
                "The cryptographic function registry has not been initialized. " +
                "Call CryptoFunctionRegistry.Initialize() during application startup.");
        }

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();

        return CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.TryResolveVerification(
            algorithm, purpose, out VerificationDelegate? verification)
            ? verification
            : UnservedPairVerification;
    }


    /// <summary>
    /// Rents a pooled buffer and writes the JWS signing input (<c>"&lt;segment1&gt;.&lt;segment2&gt;"</c> as ASCII
    /// octets, <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.1">RFC 7515 Section 5.1</see>) directly
    /// into it without allocating an intermediate string or array. Both segments are base64url-encoded, so
    /// already ASCII, which means the byte length equals the character length. The <c>checked</c> sum makes the
    /// integer-overflow assumption explicit; verify bodies gate the input length up front through
    /// <see cref="IsJwsLengthAccepted"/>, and sign bodies take caller-controlled segments.
    /// </summary>
    /// <param name="segment1">The first segment, the protected header's base64url.</param>
    /// <param name="segment2">The second segment, the payload's base64url.</param>
    /// <param name="pool">The pool the buffer is rented from.</param>
    /// <param name="signingInputLength">The length of the signing input; the slice <c>[..signingInputLength]</c> holds it, since a rental can be oversized.</param>
    /// <returns>The rented buffer, which the caller disposes.</returns>
    private static IMemoryOwner<byte> RentSigningInput(
        string segment1,
        string segment2,
        BaseMemoryPool pool,
        out int signingInputLength)
    {
        signingInputLength = checked(segment1.Length + 1 + segment2.Length);
        IMemoryOwner<byte> owner = pool.Rent(signingInputLength);
        Span<byte> span = owner.Memory.Span[..signingInputLength];
        _ = Encoding.ASCII.GetBytes(segment1, span);
        span[segment1.Length] = (byte)'.';
        _ = Encoding.ASCII.GetBytes(segment2, span[(segment1.Length + 1)..]);
        return owner;
    }


    //Builds the JWS Signing Input honoring the RFC 7797 b64 option. When base64UrlPayload is true (the default,
    //b64 absent or true), the input is ASCII(b64url(protected) "." b64url(payload)) per RFC 7515 §5.1. When
    //false (b64:false), the input is ASCII(b64url(protected) ".") followed by the RAW payload bytes per RFC 7797
    //§3 — the payload may be arbitrary octets, so it is appended verbatim rather than encoded.
    internal static IMemoryOwner<byte> RentSigningInput(
        string protectedSegment,
        ReadOnlySpan<byte> payload,
        bool base64UrlPayload,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool pool,
        out int signingInputLength)
    {
        if(base64UrlPayload)
        {
            return RentSigningInput(protectedSegment, base64UrlEncoder(payload), pool, out signingInputLength);
        }

        signingInputLength = checked(protectedSegment.Length + 1 + payload.Length);
        IMemoryOwner<byte> owner = pool.Rent(signingInputLength);
        Span<byte> span = owner.Memory.Span[..signingInputLength];
        _ = Encoding.ASCII.GetBytes(protectedSegment, span);
        span[protectedSegment.Length] = (byte)'.';
        payload.CopyTo(span[(protectedSegment.Length + 1)..]);
        return owner;
    }


    //Whether the payload is base64url-encoded in the JWS Signing Input, per the RFC 7797 b64 header parameter:
    //true unless the protected header carries b64:false. A b64 value of true, an absent b64, or a non-Boolean
    //b64 all yield the default (encoded) behavior.
    internal static bool IsPayloadBase64UrlEncoded(ReadOnlySpan<byte> protectedHeaderJson)
    {
        return !(JwkJsonReader.TryExtractBooleanValue(protectedHeaderJson, WellKnownJoseHeaderNames.B64Utf8, out bool b64) && !b64);
    }


    private static IReadOnlyDictionary<string, object> BuildProtectedHeaderDictionary<TJwtPart>(TJwtPart header)
    {
        if(header is IReadOnlyDictionary<string, object> dict)
        {
            return dict;
        }

        if(header is IDictionary<string, object> mutableDict)
        {
            return new Dictionary<string, object>(mutableDict);
        }

        return new Dictionary<string, object>();
    }

}
