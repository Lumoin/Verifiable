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
/// <returns>Byte representation of the <paramref name="part"/>.</returns>
public delegate ReadOnlySpan<byte> JwtPartEncoder<in TJwtPart>(TJwtPart part);


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
/// JWS (JSON Web Signature) operations using secure key memory abstractions.
/// </summary>
/// <remarks>
/// <para>
/// This implementation provides multiple API patterns:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Registry-based</strong> - Uses <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
/// to resolve signing/verification functions from the key's <see cref="Tag"/>.
/// </description></item>
/// <item><description>
/// <strong>Explicit function</strong> - Caller provides signing/verification functions directly,
/// useful for testing or custom cryptographic backends.
/// </description></item>
/// <item><description>
/// <strong>Resolver/Binder</strong> - Uses <see cref="KeyMaterialResolver{TResult, TContext, TState}"/>
/// and <see cref="KeyMaterialBinder{TInput, TResult, TState}"/> for complex key resolution scenarios.
/// </description></item>
/// </list>
/// <para>
/// All patterns use <see cref="PrivateKeyMemory"/> and <see cref="PublicKeyMemory"/> to ensure
/// key material is never directly exposed, supporting both software keys and hardware security
/// modules (HSM/TPM) where keys cannot be extracted.
/// </para>
/// </remarks>
public static class Jws
{
    /// <summary>
    /// Creates a JWS compact serialization using registry-resolved signing function.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <param name="header">The JWT header containing algorithm information.</param>
    /// <param name="payload">The JWT payload.</param>
    /// <param name="partEncoder">Encodes JWT parts to bytes.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <returns>The JWS compact serialization string.</returns>
    /// <remarks>
    /// The signing function is resolved from <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// based on the <see cref="CryptoAlgorithm"/> and <see cref="Purpose"/> in the key's <see cref="Tag"/>.
    /// </remarks>
    public static async ValueTask<string> SignAsync<TJwtPart>(
        TJwtPart header,
        TJwtPart payload,
        JwtPartEncoder<TJwtPart> partEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        MemoryPool<byte> signaturePool)
    {
        string headerSegment = base64UrlEncoder(partEncoder(header));
        string payloadSegment = base64UrlEncoder(partEncoder(payload));
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.ASCII.GetBytes(signingInput);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        using IMemoryOwner<byte> signatureMemory = await signingDelegate(
            privateKey.AsReadOnlySpan(),
            dataToSign,
            signaturePool);

        string signatureSegment = base64UrlEncoder(signatureMemory.Memory.Span);

        return $"{signingInput}.{signatureSegment}";
    }


    /// <summary>
    /// Creates a JWS compact serialization using an explicit signing function.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <param name="header">The JWT header containing algorithm information.</param>
    /// <param name="payload">The JWT payload.</param>
    /// <param name="partEncoder">Encodes JWT parts to bytes.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signingFunction">The signing function to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <returns>The JWS compact serialization string.</returns>
    /// <remarks>
    /// This overload is useful when you need to provide a custom signing function,
    /// such as for testing or when using a cryptographic backend not registered in the
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>.
    /// </remarks>
    public static async ValueTask<string> SignAsync<TJwtPart>(
        TJwtPart header,
        TJwtPart payload,
        JwtPartEncoder<TJwtPart> partEncoder,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        SigningFunction<byte, byte, ValueTask<Signature>> signingFunction,
        MemoryPool<byte> signaturePool)
    {
        string headerSegment = base64UrlEncoder(partEncoder(header));
        string payloadSegment = base64UrlEncoder(partEncoder(payload));
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.UTF8.GetBytes(signingInput);

        using Signature signature = await privateKey.WithKeyBytesAsync(signingFunction, dataToSign, signaturePool);
        string signatureSegment = base64UrlEncoder(signature.AsReadOnlySpan());

        return $"{signingInput}.{signatureSegment}";
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
    /// <remarks>
    /// The verification function is resolved from <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// based on the <see cref="CryptoAlgorithm"/> and <see cref="Purpose"/> in the key's <see cref="Tag"/>.
    /// </remarks>
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
            signatureOwner.Memory.Span,
            publicKey.AsReadOnlySpan());
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
    /// <remarks>
    /// This overload is useful when you need to provide a custom verification function,
    /// such as for testing or when using a cryptographic backend not registered in the
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>.
    /// </remarks>
    public static ValueTask<bool> VerifyAsync<TJwtPart>(
        string jws,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, TJwtPart> partDecoder,
        MemoryPool<byte> pool,
        PublicKeyMemory publicKey,
        VerificationFunctionWithBytes<byte, byte, byte, bool> verificationFunction)
    {
        string[] parts = jws.Split('.');
        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(parts[2], pool);
        byte[] dataToVerify = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");

        bool isValid = verificationFunction(publicKey.AsReadOnlyMemory(), dataToVerify, signatureOwner.Memory);
        return ValueTask.FromResult(isValid);
    }


    /// <summary>
    /// Verifies a JWS and returns the decoded header and payload using registry-resolved verification.
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
            signatureOwner.Memory.Span,
            publicKey.AsReadOnlySpan());

        return new JwsVerificationResult<TJwtPart>(isValid, header, payload);
    }


    /// <summary>
    /// Creates a JWS compact serialization using resolver/binder pattern.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <param name="header">The JWT header containing algorithm information.</param>
    /// <param name="payload">The JWT payload.</param>
    /// <param name="partEncoder">Encodes JWT parts to bytes.</param>
    /// <param name="base64UrlEncoder">Encodes bytes to Base64Url strings.</param>
    /// <param name="pool">Memory pool for key material and signature allocation.</param>
    /// <param name="resolverState">State for key material resolution.</param>
    /// <param name="resolver">Resolves and loads private key material from context.</param>
    /// <param name="binderState">State for key material binding.</param>
    /// <param name="binder">Binds signing function to key material.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The JWS compact serialization string.</returns>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static async ValueTask<string> SignAsync<TJwtPart, TResolverState, TBinderState>(
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
        string headerSegment = base64UrlEncoder(partEncoder(header));
        string payloadSegment = base64UrlEncoder(partEncoder(payload));
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.UTF8.GetBytes(signingInput);

        var context = new JoseKeyContext<TJwtPart>(header, payload);

        PrivateKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken);
        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        using PrivateKey privateKey = await binder(material, binderState, cancellationToken);
        using Signature signature = await privateKey.SignAsync(dataToSign, pool);
        string signatureSegment = base64UrlEncoder(signature.AsReadOnlySpan());

        return $"{signingInput}.{signatureSegment}";
    }


    /// <summary>
    /// Verifies a JWS compact serialization using resolver/binder pattern.
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
}


/// <summary>
/// Result of JWS verification including decoded header and payload.
/// </summary>
/// <typeparam name="TJwtPart">The type of JWT header and payload.</typeparam>
/// <param name="IsValid">Whether the signature is valid.</param>
/// <param name="Header">The decoded header.</param>
/// <param name="Payload">The decoded payload.</param>
public readonly record struct JwsVerificationResult<TJwtPart>(bool IsValid, TJwtPart Header, TJwtPart Payload);