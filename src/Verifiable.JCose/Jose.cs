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
/// Context for JOSE key resolution containing header and payload information.
/// </summary>
/// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
/// <param name="Header">The JWT header containing algorithm and key identification (kid, jku, alg, x5c).</param>
/// <param name="Payload">The JWT payload containing claims (iss, sub, aud).</param>
/// <remarks>
/// <para>
/// This context provides all information needed to identify and locate a key for JOSE operations.
/// Resolvers can examine header fields (kid, jku, alg) and payload claims (iss) to determine
/// which key to load and from where.
/// </para>
/// </remarks>
public readonly record struct JoseKeyContext<TJwtPart>(TJwtPart Header, TJwtPart Payload);


/// <summary>
/// Result of JWS verification including decoded header and payload.
/// </summary>
/// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
/// <param name="IsValid">Whether the signature is valid.</param>
/// <param name="Header">The decoded header.</param>
/// <param name="Payload">The decoded payload.</param>
public readonly record struct JwsVerificationResult<TJwtPart>(bool IsValid, TJwtPart Header, TJwtPart Payload);


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
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned JwsMessage.")]
public static class Jws
{
    /// <summary>
    /// Default maximum length, in characters, for an incoming JWS compact
    /// serialization accepted by the verification overloads. Bounds the
    /// size of the pooled signing-input buffer the verifier must allocate,
    /// mitigating large-allocation denial-of-service via attacker-supplied
    /// JWS tokens. Generous enough for typical OAuth/OIDC tokens, SD-JWTs,
    /// and verifiable credentials; deployments that need a different bound
    /// pass an explicit <c>maxJwsLength</c> argument.
    /// </summary>
    /// <remarks>
    /// Per RFC 8725 §3.11, "JWT implementations should consider providing
    /// a way for applications to set a maximum size for incoming JWTs".
    /// 1 MiB matches the upper bound common JWT libraries use as a sane
    /// default.
    /// </remarks>
    public const int DefaultMaxJwsLength = 1 * 1024 * 1024;


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
    /// <returns>The JWS message containing the signature.</returns>    
    public static async ValueTask<JwsMessage> SignAsync<TJwtPart>(
        TJwtPart header,
        TJwtPart payload,
        JwtPartEncoder<TJwtPart> partEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        MemoryPool<byte> signaturePool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(partEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signaturePool);

        cancellationToken.ThrowIfCancellationRequested();

        TaggedMemory<byte> headerBytes = partEncoder(header);
        TaggedMemory<byte> payloadBytes = partEncoder(payload);

        string headerSegment = base64UrlEncoder(headerBytes.Span);
        string payloadSegment = base64UrlEncoder(payloadBytes.Span);
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.ASCII.GetBytes(signingInput);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        Signature signatureMemory = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            dataToSign,
            signaturePool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        var protectedHeader = BuildProtectedHeaderDictionary(header);

        var signatureComponent = new JwsSignatureComponent(
            headerSegment,
            protectedHeader,
            signatureMemory);

        return new JwsMessage(payloadBytes.Memory, signatureComponent);
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
    /// <param name="signingFunction">The signing function to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
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
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.UTF8.GetBytes(signingInput);

        Signature signature = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            dataToSign,
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
    /// Verifies a JWS message using registry-resolved verification function.
    /// </summary>
    /// <param name="message">The JWS message to verify.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the message has multiple signatures.
    /// </exception>
    public static async ValueTask<bool> VerifyAsync(
        JwsMessage message,
        EncodeDelegate base64UrlEncoder,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(publicKey);

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
        string signingInput = $"{signature.Protected}.{payloadSegment}";
        byte[] dataToVerify = Encoding.ASCII.GetBytes(signingInput);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return await verificationDelegate(
            dataToVerify,
            signature.SignatureBytes,
            publicKey.AsReadOnlyMemory(),
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a JWS compact serialization using registry-resolved verification function.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to the part type.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS does not have exactly three parts.</exception>
    public static async ValueTask<bool> VerifyAsync<TJwtPart>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, TJwtPart> partDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(publicKey);

        cancellationToken.ThrowIfCancellationRequested();

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(parts[2], pool);
        byte[] dataToVerify = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return await verificationDelegate(
            dataToVerify,
            signatureOwner.Memory,
            publicKey.AsReadOnlyMemory(),
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a JWS compact serialization using an explicit verification function.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to the part type.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationFunction">The verification function to use.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS does not have exactly three parts.</exception>
    public static async ValueTask<bool> VerifyAsync<TJwtPart>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, TJwtPart> partDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CancellationToken cancellationToken,
        int maxJwsLength = DefaultMaxJwsLength)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxJwsLength);

        //Bound input length up-front. The pooled signing-input buffer is
        //sized from the JWS parts, so an unbounded JWS would translate to an
        //unbounded pool rental — a large-allocation DoS vector per RFC 8725
        //§3.11. Rejecting early also makes the subsequent length arithmetic
        //immune to integer overflow.
        if(jws.Length > maxJwsLength)
        {
            throw new ArgumentException(
                $"JWS length {jws.Length} exceeds the configured maximum of {maxJwsLength} characters.",
                nameof(jws));
        }

        cancellationToken.ThrowIfCancellationRequested();

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(parts[2], pool);

        //JWS signing input per RFC 7515 §5.1 is ASCII octets of
        //"<header>.<payload>". Both segments are base64url-encoded (so already
        //ASCII), which means byte length equals char length and we can write
        //directly into pooled memory without an intermediate string allocation.
        //The `checked` block is belt-and-braces — the maxJwsLength gate above
        //already rules out overflow, but defense-in-depth makes the
        //assumption explicit.
        int signingInputLength = checked(parts[0].Length + 1 + parts[1].Length);
        using IMemoryOwner<byte> dataToVerifyOwner = pool.Rent(signingInputLength);
        Span<byte> dataToVerifySpan = dataToVerifyOwner.Memory.Span[..signingInputLength];
        Encoding.ASCII.GetBytes(parts[0], dataToVerifySpan);
        dataToVerifySpan[parts[0].Length] = (byte)'.';
        Encoding.ASCII.GetBytes(parts[1], dataToVerifySpan[(parts[0].Length + 1)..]);

        return await verificationDelegate(
            dataToVerifyOwner.Memory[..signingInputLength],
            signatureOwner.Memory,
            publicKey.AsReadOnlyMemory(),
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a JWS and returns the decoded header and payload.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to the part type.</param>
    /// <param name="pool">Memory pool for decoding allocation.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <returns>The verification result containing validity and decoded parts.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS does not have exactly three parts.</exception>
    public static async ValueTask<JwsVerificationResult<TJwtPart>> VerifyAndDecodeAsync<TJwtPart>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, TJwtPart> partDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(publicKey);

        cancellationToken.ThrowIfCancellationRequested();

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> headerOwner = base64UrlDecoder(parts[0], pool);
        using IMemoryOwner<byte> payloadOwner = base64UrlDecoder(parts[1], pool);
        using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(parts[2], pool);

        TJwtPart header = partDecoder(headerOwner.Memory.Span);
        TJwtPart payload = partDecoder(payloadOwner.Memory.Span);

        byte[] dataToVerify = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        bool isValid = await verificationDelegate(
            dataToVerify,
            signatureOwner.Memory,
            publicKey.AsReadOnlyMemory(),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return new JwsVerificationResult<TJwtPart>(isValid, header, payload);
    }


    /// <summary>
    /// Creates a JWS using resolver/binder pattern for key resolution.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
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
    public static async ValueTask<JwsMessage> SignAsync<TJwtPart, TResolverState, TBinderState>(
        TJwtPart header,
        TJwtPart payload,
        JwtPartEncoder<TJwtPart> partEncoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool,
        TResolverState resolverState,
        KeyMaterialResolver<PrivateKeyMemory, JoseKeyContext<TJwtPart>, TResolverState> resolver,
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
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.UTF8.GetBytes(signingInput);

        var context = new JoseKeyContext<TJwtPart>(header, payload);

        PrivateKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false);

        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        using PrivateKey privateKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);
        Signature signature = await privateKey.SignAsync(dataToSign, pool).ConfigureAwait(false);

        var protectedHeader = BuildProtectedHeaderDictionary(header);

        var signatureComponent = new JwsSignatureComponent(
            headerSegment,
            protectedHeader,
            signature);

        return new JwsMessage(payloadBytes.Memory, signatureComponent);
    }


    /// <summary>
    /// Verifies a JWS using resolver/binder pattern for key resolution.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to the part type.</param>
    /// <param name="pool">Memory pool for key material allocation.</param>
    /// <param name="resolverState">State for key material resolution.</param>
    /// <param name="resolver">Resolves and loads public key material from context.</param>
    /// <param name="binderState">State for key material binding.</param>
    /// <param name="binder">Binds verification function to key material.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS does not have exactly three parts.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static async ValueTask<bool> VerifyAsync<TJwtPart, TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, TJwtPart> partDecoder,
        MemoryPool<byte> pool,
        TResolverState resolverState,
        KeyMaterialResolver<PublicKeyMemory, JoseKeyContext<TJwtPart>, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PublicKeyMemory, PublicKey, TBinderState> binder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(binder);
        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> headerOwner = base64UrlDecoder(parts[0], pool);
        using IMemoryOwner<byte> payloadOwner = base64UrlDecoder(parts[1], pool);
        using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(parts[2], pool);

        TJwtPart header = partDecoder(headerOwner.Memory.Span);
        TJwtPart payload = partDecoder(payloadOwner.Memory.Span);

        byte[] dataToVerify = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");

        var context = new JoseKeyContext<TJwtPart>(header, payload);

        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false);

        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        Tag signatureTag = material.Tag;
        using PublicKey publicKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> signatureMemory = pool.Rent(signatureOwner.Memory.Length);
        signatureOwner.Memory.Span.CopyTo(signatureMemory.Memory.Span);
        using var signature = new Signature(signatureMemory, signatureTag);

        return await publicKey.VerifyAsync(dataToVerify, signature).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a JWS and returns the decoded payload using resolver/binder pattern.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="base64UrlDecoder">Decodes Base64Url strings to bytes with pooled memory.</param>
    /// <param name="partDecoder">Decodes JWT part bytes to the part type.</param>
    /// <param name="pool">Memory pool for key material allocation.</param>
    /// <param name="resolverState">State for key material resolution.</param>
    /// <param name="resolver">Resolves and loads public key material from context.</param>
    /// <param name="binderState">State for key material binding.</param>
    /// <param name="binder">Binds verification function to key material.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity and decoded parts.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS does not have exactly three parts.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static async ValueTask<JwsVerificationResult<TJwtPart>> VerifyAndDecodeAsync<TJwtPart, TResolverState, TBinderState>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, TJwtPart> partDecoder,
        MemoryPool<byte> pool,
        TResolverState resolverState,
        KeyMaterialResolver<PublicKeyMemory, JoseKeyContext<TJwtPart>, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PublicKeyMemory, PublicKey, TBinderState> binder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(binder);
        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> headerOwner = base64UrlDecoder(parts[0], pool);
        using IMemoryOwner<byte> payloadOwner = base64UrlDecoder(parts[1], pool);
        using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(parts[2], pool);

        TJwtPart header = partDecoder(headerOwner.Memory.Span);
        TJwtPart payload = partDecoder(payloadOwner.Memory.Span);

        byte[] dataToVerify = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");

        var context = new JoseKeyContext<TJwtPart>(header, payload);

        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false) ?? throw new InvalidOperationException("Key material resolution failed.");
        Tag signatureTag = material.Tag;
        using PublicKey publicKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> signatureMemory = pool.Rent(signatureOwner.Memory.Length);
        signatureOwner.Memory.Span.CopyTo(signatureMemory.Memory.Span);
        using var signature = new Signature(signatureMemory, signatureTag);

        bool isValid = await publicKey.VerifyAsync(dataToVerify, signature).ConfigureAwait(false);

        return new JwsVerificationResult<TJwtPart>(isValid, header, payload);
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
