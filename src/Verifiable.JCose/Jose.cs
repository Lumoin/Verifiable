using System.Buffers;
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
public static class Jws
{
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
        MemoryPool<byte> signaturePool)
    {
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
            signaturePool);

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
        MemoryPool<byte> signaturePool)
    {
        TaggedMemory<byte> headerBytes = partEncoder(header);
        TaggedMemory<byte> payloadBytes = partEncoder(payload);

        string headerSegment = base64UrlEncoder(headerBytes.Span);
        string payloadSegment = base64UrlEncoder(payloadBytes.Span);
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.UTF8.GetBytes(signingInput);

        Signature signature = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            dataToSign,
            signaturePool);

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
        PublicKeyMemory publicKey)
    {
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
            publicKey.AsReadOnlyMemory());
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
        PublicKeyMemory publicKey)
    {
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
            publicKey.AsReadOnlyMemory());
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
        VerificationDelegate verificationDelegate)
    {
        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(parts[2], pool);
        byte[] dataToVerify = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

        return await verificationDelegate(
            dataToVerify,
            signatureOwner.Memory,
            publicKey.AsReadOnlyMemory());
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
        PublicKeyMemory publicKey)
    {
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
            publicKey.AsReadOnlyMemory());

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
        TaggedMemory<byte> headerBytes = partEncoder(header);
        TaggedMemory<byte> payloadBytes = partEncoder(payload);

        string headerSegment = base64UrlEncoder(headerBytes.Span);
        string payloadSegment = base64UrlEncoder(payloadBytes.Span);
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.UTF8.GetBytes(signingInput);

        var context = new JoseKeyContext<TJwtPart>(header, payload);

        PrivateKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken);

        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        using PrivateKey privateKey = await binder(material, binderState, cancellationToken);
        Signature signature = await privateKey.SignAsync(dataToSign, pool);

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

        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken);

        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        Tag signatureTag = material.Tag;
        using PublicKey publicKey = await binder(material, binderState, cancellationToken);

        IMemoryOwner<byte> signatureMemory = pool.Rent(signatureOwner.Memory.Length);
        signatureOwner.Memory.Span.CopyTo(signatureMemory.Memory.Span);
        using var signature = new Signature(signatureMemory, signatureTag);

        return await publicKey.VerifyAsync(dataToVerify, signature);
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

        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken);

        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        Tag signatureTag = material.Tag;
        using PublicKey publicKey = await binder(material, binderState, cancellationToken);

        IMemoryOwner<byte> signatureMemory = pool.Rent(signatureOwner.Memory.Length);
        signatureOwner.Memory.Span.CopyTo(signatureMemory.Memory.Span);
        using var signature = new Signature(signatureMemory, signatureTag);

        bool isValid = await publicKey.VerifyAsync(dataToVerify, signature);

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