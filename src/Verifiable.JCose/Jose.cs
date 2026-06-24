using System.Buffers;
using System.Diagnostics.CodeAnalysis;
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
/// RFC 7515 §5.1) into a pooled buffer via <see cref="RentSigningInput"/> rather
/// than heap-allocating a <see cref="byte"/> array.
/// </para>
/// <para>
/// <strong>Verify overload pairs.</strong> Every <c>VerifyAsync</c> /
/// <c>VerifyAndDecodeAsync</c> path that accepts a compact JWS <see cref="string"/>
/// comes as a pair: a simple overload that applies <see cref="DefaultMaxJwsLength"/>
/// as the upper bound, and an explicit overload that takes a caller-supplied
/// <c>maxJwsLength</c>. Deployments that handle larger or smaller tokens than
/// the default opt in to the explicit overload; everyone else uses the simple
/// overload and gets the default RFC 8725 §3.11 guard for free.
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
    /// Per RFC 8725 §3.11, "JWT implementations should consider providing
    /// a way for applications to set a maximum size for incoming JWTs".
    /// 1 MiB matches the upper bound common JWT libraries use as a sane
    /// default.
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
    /// <see cref="SignAsync{TJwtPart}(TJwtPart, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, Cryptography.PrivateKeyMemory, MemoryPool{byte}, CancellationToken)"/>.
    /// RFC 8725 §3.1 reminds implementations that <c>alg=none</c> tokens are
    /// a classic attack vector when accepted indiscriminately — consumers
    /// must opt into accepting them and only in the contexts the profile
    /// allows.
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
        MemoryPool<byte> signaturePool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return SignAsync(
            header, payload, partEncoder, base64UrlEncoder,
            privateKey, signingDelegate, signaturePool, cancellationToken);
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
    /// <returns>The JWS message containing the signature.</returns>
    public static async ValueTask<JwsMessage> SignAsync<TJwtPart>(
        TJwtPart header,
        TJwtPart payload,
        JwtPartEncoder<TJwtPart> partEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        MemoryPool<byte> signaturePool,
        CancellationToken cancellationToken)
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

        Signature signature = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            dataToSignOwner.Memory[..signingInputLength],
            signaturePool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

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
    /// <see cref="SignAsync{TJwtPart}(TJwtPart, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, PrivateKeyMemory, SigningDelegate, MemoryPool{byte}, CancellationToken)"/>
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
    /// <returns>The unserialized JWS message owning the signature. The caller disposes it.</returns>
    public static async ValueTask<JwsMessage> SignAsync<TJwtPart>(
        TJwtPart protectedHeader,
        ReadOnlyMemory<byte> payload,
        JwtPartEncoder<TJwtPart> protectedHeaderEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        MemoryPool<byte> signaturePool,
        IReadOnlyDictionary<string, object>? unprotectedHeader,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(protectedHeaderEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);

        cancellationToken.ThrowIfCancellationRequested();

        TaggedMemory<byte> headerBytes = protectedHeaderEncoder(protectedHeader);
        string headerSegment = base64UrlEncoder(headerBytes.Span);
        string payloadSegment = base64UrlEncoder(payload.Span);

        using IMemoryOwner<byte> dataToSignOwner = RentSigningInput(
            headerSegment, payloadSegment, signaturePool, out int signingInputLength);

        Signature signature = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            dataToSignOwner.Memory[..signingInputLength],
            signaturePool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return new JwsMessage(
            payload,
            new JwsSignatureComponent(
                headerSegment,
                BuildProtectedHeaderDictionary(protectedHeader),
                signature,
                unprotectedHeader));
    }


    /// <summary>
    /// Verifies a JWS message using registry-resolved verification function.
    /// Allocates the signing-input buffer from
    /// <see cref="MemoryPool{T}.Shared"/>; the overload taking an explicit
    /// <c>pool</c> uses caller-supplied pooling instead.
    /// </summary>
    /// <param name="message">The JWS message to verify.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the message has multiple signatures.
    /// </exception>
    public static ValueTask<bool> VerifyAsync(
        JwsMessage message,
        EncodeDelegate base64UrlEncoder,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
        => VerifyAsync(message, base64UrlEncoder, publicKey, MemoryPool<byte>.Shared, cancellationToken);


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
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the message has multiple signatures.
    /// </exception>
    public static ValueTask<bool> VerifyAsync(
        JwsMessage message,
        EncodeDelegate base64UrlEncoder,
        PublicKeyMemory publicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return VerifyAsync(
            message, base64UrlEncoder, publicKey, verificationDelegate, pool, cancellationToken);
    }


    /// <summary>
    /// Verifies a JWS message using an explicit
    /// <see cref="VerificationDelegate"/>. The registry-resolving overload
    /// above delegates here after resolving the function via
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// from <paramref name="publicKey"/>'s <see cref="SensitiveMemory.Tag"/>.
    /// </summary>
    /// <param name="message">The JWS message to verify.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="pool">Memory pool for the pooled signing-input buffer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the message has multiple signatures.
    /// </exception>
    public static async ValueTask<bool> VerifyAsync(
        JwsMessage message,
        EncodeDelegate base64UrlEncoder,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        MemoryPool<byte> pool,
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

        return await verificationDelegate(
            dataToVerifyOwner.Memory[..signingInputLength],
            signature.SignatureBytes,
            publicKey.AsReadOnlyMemory(),
            cancellationToken: cancellationToken).ConfigureAwait(false);
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
    public static async ValueTask<bool> VerifySignatureAsync(
        string protectedSegment,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature,
        EncodeDelegate base64UrlEncoder,
        VerificationDelegate verificationDelegate,
        ReadOnlyMemory<byte> publicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(protectedSegment);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        string payloadSegment = base64UrlEncoder(payload.Span);

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            protectedSegment, payloadSegment, pool, out int signingInputLength);

        return await verificationDelegate(
            dataToVerifyOwner.Memory[..signingInputLength],
            signature,
            publicKey,
            cancellationToken: cancellationToken).ConfigureAwait(false);
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
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <see cref="DefaultMaxJwsLength"/> or does not have exactly three parts.</exception>
    public static ValueTask<bool> VerifyAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
        => VerifyAsync(jws, base64UrlDecoder, pool, publicKey, DefaultMaxJwsLength, cancellationToken);


    /// <summary>
    /// Verifies a JWS compact serialization using registry-resolved
    /// verification function, with a caller-supplied
    /// <paramref name="maxJwsLength"/> upper bound per RFC 8725 §3.11.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="maxJwsLength">Maximum accepted JWS length per RFC 8725 §3.11.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <paramref name="maxJwsLength"/> or does not have exactly three parts.</exception>
    public static ValueTask<bool> VerifyAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        int maxJwsLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return VerifyAsync(
            jws, base64UrlDecoder, pool,
            publicKey, verificationDelegate, maxJwsLength, cancellationToken);
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
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <see cref="DefaultMaxJwsLength"/> or does not have exactly three parts.</exception>
    public static ValueTask<bool> VerifyAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CancellationToken cancellationToken)
        => VerifyAsync(jws, base64UrlDecoder, pool, publicKey, verificationDelegate, DefaultMaxJwsLength, cancellationToken);


    /// <summary>
    /// Verifies a JWS compact serialization using an explicit verification
    /// function, with a caller-supplied <paramref name="maxJwsLength"/>
    /// upper bound per RFC 8725 §3.11.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification function to use.</param>
    /// <param name="maxJwsLength">Maximum accepted JWS length per RFC 8725 §3.11.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <paramref name="maxJwsLength"/> or does not have exactly three parts.</exception>
    public static async ValueTask<bool> VerifyAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        int maxJwsLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxJwsLength);
        EnsureJwsLengthAccepted(jws, maxJwsLength);

        cancellationToken.ThrowIfCancellationRequested();

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        //A malformed signature segment (base64url the injected decoder rejects) cannot verify; treat it
        //as a clean "does not verify" rather than letting the decoder's exception escape. Callers depend
        //on VerifyAsync returning false, never throwing, on untrusted input.
        using DecodedSegment signature = TryDecodeSegment(base64UrlDecoder, parts[2], pool);
        if(!signature.IsDecoded)
        {
            return false;
        }

        //RFC 7515 §4.1.11: a JWS whose protected header names an unrecognized critical extension (or
        //otherwise violates the crit producer rules) is invalid. Decode the header and fail closed to
        //false — like a malformed segment — rather than verifying a message we cannot fully process.
        using DecodedSegment protectedHeader = TryDecodeSegment(base64UrlDecoder, parts[0], pool);
        if(!protectedHeader.IsDecoded || !JoseCriticalHeaderValidation.IsSatisfied(protectedHeader.Memory.Span))
        {
            return false;
        }

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            parts[0], parts[1], pool, out int signingInputLength);

        return await verificationDelegate(
            dataToVerifyOwner.Memory[..signingInputLength],
            signature.Memory,
            publicKey.AsReadOnlyMemory(),
            cancellationToken: cancellationToken).ConfigureAwait(false);
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
    /// <returns>The verification result containing validity and decoded parts.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <see cref="DefaultMaxJwsLength"/> or does not have exactly three parts.</exception>
    public static ValueTask<JwsVerificationResult> VerifyAndDecodeAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
        => VerifyAndDecodeAsync(jws, base64UrlDecoder, partDecoder, pool, publicKey, DefaultMaxJwsLength, cancellationToken);


    /// <summary>
    /// Verifies a JWS and returns the decoded header and payload, with a
    /// caller-supplied <paramref name="maxJwsLength"/> upper bound per
    /// RFC 8725 §3.11.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to a claims dictionary.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="maxJwsLength">Maximum accepted JWS length per RFC 8725 §3.11.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity and decoded parts.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <paramref name="maxJwsLength"/> or does not have exactly three parts.</exception>
    public static ValueTask<JwsVerificationResult> VerifyAndDecodeAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        int maxJwsLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return VerifyAndDecodeAsync(
            jws, base64UrlDecoder, partDecoder, pool,
            publicKey, verificationDelegate, maxJwsLength, cancellationToken);
    }


    /// <summary>
    /// Verifies a JWS and returns the decoded header and payload using an
    /// explicit <see cref="VerificationDelegate"/>, with a caller-supplied
    /// <paramref name="maxJwsLength"/> upper bound per RFC 8725 §3.11. The
    /// registry-resolving overload above delegates here after resolving the
    /// function via
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// from <paramref name="publicKey"/>'s <see cref="SensitiveMemory.Tag"/>.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to a claims dictionary.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="maxJwsLength">Maximum accepted JWS length per RFC 8725 §3.11.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity and decoded parts.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <paramref name="maxJwsLength"/> or does not have exactly three parts.</exception>
    public static async ValueTask<JwsVerificationResult> VerifyAndDecodeAsync(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        int maxJwsLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxJwsLength);
        EnsureJwsLengthAccepted(jws, maxJwsLength);

        cancellationToken.ThrowIfCancellationRequested();

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> headerOwner = base64UrlDecoder(parts[0], pool);
        using IMemoryOwner<byte> payloadOwner = base64UrlDecoder(parts[1], pool);
        using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(parts[2], pool);

        JwtHeader header = new(partDecoder(headerOwner.Memory.Span));
        JwtPayload payload = new(partDecoder(payloadOwner.Memory.Span));

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            parts[0], parts[1], pool, out int signingInputLength);

        //RFC 7515 §4.1.11: a JWS naming an unrecognized critical extension is invalid; the decoded
        //header/payload are still returned so the caller can inspect them, but with isValid false.
        bool critSatisfied = JoseCriticalHeaderValidation.IsSatisfied(headerOwner.Memory.Span);

        bool isValid = critSatisfied && await verificationDelegate(
            dataToVerifyOwner.Memory[..signingInputLength],
            signatureOwner.Memory,
            publicKey.AsReadOnlyMemory(),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return new JwsVerificationResult(isValid, header, payload);
    }


    /// <summary>
    /// Creates a JWS using resolver/binder pattern for key resolution.
    /// </summary>
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
        MemoryPool<byte> pool,
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
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <see cref="DefaultMaxJwsLength"/> or does not have exactly three parts.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static ValueTask<bool> VerifyAsync<TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        MemoryPool<byte> pool,
        TResolverState resolverState,
        KeyMaterialResolver<PublicKeyMemory, JoseKeyContext, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PublicKeyMemory, PublicKey, TBinderState> binder,
        CancellationToken cancellationToken = default)
        => VerifyAsync(jws, base64UrlDecoder, partDecoder, pool, resolverState, resolver, binderState, binder, DefaultMaxJwsLength, cancellationToken);


    /// <summary>
    /// Verifies a JWS using resolver/binder pattern for key resolution,
    /// with a caller-supplied <paramref name="maxJwsLength"/> upper bound
    /// per RFC 8725 §3.11.
    /// </summary>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <paramref name="maxJwsLength"/> or does not have exactly three parts.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static async ValueTask<bool> VerifyAsync<TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        MemoryPool<byte> pool,
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
        EnsureJwsLengthAccepted(jws, maxJwsLength);

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using DecodedSegment headerSegment = TryDecodeSegment(base64UrlDecoder, parts[0], pool);
        using DecodedSegment payloadSegment = TryDecodeSegment(base64UrlDecoder, parts[1], pool);
        using DecodedSegment signatureSegment = TryDecodeSegment(base64UrlDecoder, parts[2], pool);

        //A malformed segment the decoder rejects cannot verify; fail closed to false rather than letting
        //the decoder's exception escape on untrusted input.
        if(!headerSegment.IsDecoded || !payloadSegment.IsDecoded || !signatureSegment.IsDecoded)
        {
            return false;
        }

        //RFC 7515 §4.1.11: fail closed to false on an unrecognized critical extension.
        if(!JoseCriticalHeaderValidation.IsSatisfied(headerSegment.Memory.Span))
        {
            return false;
        }

        JwtHeader header = new(partDecoder(headerSegment.Memory.Span));
        JwtPayload payload = new(partDecoder(payloadSegment.Memory.Span));

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            parts[0], parts[1], pool, out int signingInputLength);

        var context = new JoseKeyContext(header, payload);

        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false);

        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        Tag signatureTag = material.Tag;
        using PublicKey publicKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> signatureMemory = pool.Rent(signatureSegment.Memory.Length);
        signatureSegment.Memory.Span.CopyTo(signatureMemory.Memory.Span);
        using var signature = new Signature(signatureMemory, signatureTag);

        return await publicKey.VerifyAsync(
            dataToVerifyOwner.Memory[..signingInputLength], signature).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a JWS and returns the decoded payload using resolver/binder
    /// pattern, applying <see cref="DefaultMaxJwsLength"/> as the upper
    /// bound on the input.
    /// </summary>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <returns>The verification result containing validity and decoded parts.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <see cref="DefaultMaxJwsLength"/> or does not have exactly three parts.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static ValueTask<JwsVerificationResult> VerifyAndDecodeAsync<TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        MemoryPool<byte> pool,
        TResolverState resolverState,
        KeyMaterialResolver<PublicKeyMemory, JoseKeyContext, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PublicKeyMemory, PublicKey, TBinderState> binder,
        CancellationToken cancellationToken = default)
        => VerifyAndDecodeAsync(jws, base64UrlDecoder, partDecoder, pool, resolverState, resolver, binderState, binder, DefaultMaxJwsLength, cancellationToken);


    /// <summary>
    /// Verifies a JWS and returns the decoded payload using resolver/binder
    /// pattern, with a caller-supplied <paramref name="maxJwsLength"/>
    /// upper bound per RFC 8725 §3.11.
    /// </summary>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <returns>The verification result containing validity and decoded parts.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS exceeds <paramref name="maxJwsLength"/> or does not have exactly three parts.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static async ValueTask<JwsVerificationResult> VerifyAndDecodeAsync<TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        MemoryPool<byte> pool,
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
        EnsureJwsLengthAccepted(jws, maxJwsLength);

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> headerOwner = base64UrlDecoder(parts[0], pool);
        using IMemoryOwner<byte> payloadOwner = base64UrlDecoder(parts[1], pool);
        using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(parts[2], pool);

        JwtHeader header = new(partDecoder(headerOwner.Memory.Span));
        JwtPayload payload = new(partDecoder(payloadOwner.Memory.Span));

        using IMemoryOwner<byte> dataToVerifyOwner = RentSigningInput(
            parts[0], parts[1], pool, out int signingInputLength);

        var context = new JoseKeyContext(header, payload);

        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false) ?? throw new InvalidOperationException("Key material resolution failed.");
        Tag signatureTag = material.Tag;
        using PublicKey publicKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> signatureMemory = pool.Rent(signatureOwner.Memory.Length);
        signatureOwner.Memory.Span.CopyTo(signatureMemory.Memory.Span);
        using var signature = new Signature(signatureMemory, signatureTag);

        bool isValid = await publicKey.VerifyAsync(
            dataToVerifyOwner.Memory[..signingInputLength], signature).ConfigureAwait(false);

        return new JwsVerificationResult(isValid, header, payload);
    }


    /// <summary>
    /// The outcome of decoding one base64url segment of an inbound (untrusted) compact JWS. A decoded
    /// segment owns a pooled buffer; a malformed segment — one the injected decoder rejects — carries
    /// none. Disposing releases the buffer (a no-op when malformed), so verify paths can <c>using</c>
    /// the outcome and branch on <see cref="IsDecoded"/> instead of threading a nullable owner and
    /// conflating "failed" with "null". A segment that cannot be decoded cannot verify, which is how
    /// the verify overloads honour the contract that verification of untrusted input never throws on
    /// malformed content.
    /// </summary>
    private readonly struct DecodedSegment : IDisposable
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


    //Decodes a base64url segment of an untrusted compact JWS. A segment the injected decoder rejects
    //returns DecodedSegment.Malformed rather than letting the decoder's exception escape; cancellation
    //is propagated.
    private static DecodedSegment TryDecodeSegment(DecodeDelegate base64UrlDecoder, string segment, MemoryPool<byte> pool)
    {
        try
        {
            return DecodedSegment.Decoded(base64UrlDecoder(segment, pool));
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return DecodedSegment.Malformed;
        }
    }


    //Throws if <paramref name="jws"/> is longer than <paramref name="maxJwsLength"/>.
    //The pooled signing-input buffer is sized from the JWS parts, so an
    //unbounded JWS would translate to an unbounded pool rental — a
    //large-allocation DoS vector per RFC 8725 §3.11. Rejecting early also
    //makes the subsequent length arithmetic immune to integer overflow.
    private static void EnsureJwsLengthAccepted(string jws, int maxJwsLength)
    {
        if(jws.Length > maxJwsLength)
        {
            throw new ArgumentException(
                $"JWS length {jws.Length} exceeds the configured maximum of {maxJwsLength} characters.",
                nameof(jws));
        }
    }


    //Rents a pooled buffer and writes the JWS signing input
    //("<segment1>.<segment2>" as ASCII octets per RFC 7515 §5.1) directly
    //into it without allocating an intermediate string or byte[]. Both
    //segments are base64url-encoded (so already ASCII), which means byte
    //length equals char length. The returned owner must be disposed by the
    //caller; the slice [..signingInputLength] holds the actual content
    //(pool rentals may be oversized). The `checked` block makes the
    //int-overflow assumption explicit; verify paths gate input length
    //up-front via EnsureJwsLengthAccepted, sign paths are caller-controlled.
    private static IMemoryOwner<byte> RentSigningInput(
        string segment1,
        string segment2,
        MemoryPool<byte> pool,
        out int signingInputLength)
    {
        signingInputLength = checked(segment1.Length + 1 + segment2.Length);
        IMemoryOwner<byte> owner = pool.Rent(signingInputLength);
        Span<byte> span = owner.Memory.Span[..signingInputLength];
        Encoding.ASCII.GetBytes(segment1, span);
        span[segment1.Length] = (byte)'.';
        Encoding.ASCII.GetBytes(segment2, span[(segment1.Length + 1)..]);
        return owner;
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
