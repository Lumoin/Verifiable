using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// Serializes a <see cref="JwtHeader"/> to UTF-8 JSON bytes.
/// </summary>
/// <param name="header">The JWT protected header.</param>
/// <returns>UTF-8 JSON bytes of the header.</returns>
public delegate ReadOnlySpan<byte> JwtHeaderSerializer(JwtHeader header);


/// <summary>
/// Serializes a <see cref="JwtPayload"/> to UTF-8 JSON bytes.
/// </summary>
/// <param name="payload">The JWT payload claims.</param>
/// <returns>UTF-8 JSON bytes of the payload.</returns>
/// <remarks>
/// This delegate has the same shape as <see cref="JwtHeaderSerializer"/> but operates
/// on <see cref="JwtPayload"/>, preventing accidental argument swapping at compile time.
/// </remarks>
public delegate ReadOnlySpan<byte> JwtPayloadSerializer(JwtPayload payload);


/// <summary>
/// Extension methods for signing <see cref="UnsignedJwt"/> instances as JWS.
/// </summary>
/// <remarks>
/// <para>
/// Provides <see cref="SignAsync"/> which takes an <see cref="UnsignedJwt"/> containing
/// the header and payload pair, serializes them via caller-supplied delegates, and signs
/// using the <see cref="CryptoFunctionRegistry{TAlgorithm, TPurpose}"/> dispatch pattern.
/// </para>
/// <para>
/// The result is a <see cref="JwsMessage"/> that can be serialized to compact, flattened,
/// or general JSON format via <see cref="JwsSerialization"/>.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller takes ownership of the returned JwsMessage and is responsible for disposing it.")]
public static class JwtSigningExtensions
{
    /// <summary>
    /// Signs the unsigned JWT, producing a <see cref="JwsMessage"/>.
    /// </summary>
    /// <param name="unsignedJwt">The unsigned JWT containing header and payload.</param>
    /// <param name="privateKey">
    /// The signing key. The key's <see cref="Tag"/> is used to resolve the signing
    /// delegate via <see cref="CryptoFunctionRegistry{TAlgorithm, TPurpose}"/>.
    /// </param>
    /// <param name="headerSerializer">Delegate for serializing the header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Delegate for serializing the payload to UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="memoryPool">Memory pool for signature allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A <see cref="JwsMessage"/> containing the signed JWT. The caller owns
    /// the returned message and must dispose it.
    /// </returns>
    public static async ValueTask<JwsMessage> SignAsync(
        this UnsignedJwt unsignedJwt,
        PrivateKeyMemory privateKey,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(unsignedJwt);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //Copy header span into pooled memory since spans cannot cross await boundaries.
        //Header bytes are transient and disposed after base64url encoding.
        //The pool must return exact-size allocations (e.g. SensitiveMemoryPool).
        ReadOnlySpan<byte> headerSpan = headerSerializer(unsignedJwt.Header);
        using IMemoryOwner<byte> headerOwner = memoryPool.Rent(headerSpan.Length);
        Debug.Assert(headerOwner.Memory.Length == headerSpan.Length, "Pool must return exact-size allocations.");
        headerSpan.CopyTo(headerOwner.Memory.Span);

        //Payload bytes are kept as an array because JwsMessage stores them
        //as ReadOnlyMemory<byte> that must outlive this method.
        ReadOnlySpan<byte> payloadSpan = payloadSerializer(unsignedJwt.Payload);
        byte[] payloadBytes = payloadSpan.ToArray();

        string headerSegment = base64UrlEncoder(headerOwner.Memory.Span);
        string payloadSegment = base64UrlEncoder(payloadBytes);

        //Encode the signing input into pooled memory instead of allocating via GetBytes.
        string signingInput = $"{headerSegment}.{payloadSegment}";
        int signingInputByteCount = Encoding.ASCII.GetByteCount(signingInput);
        using IMemoryOwner<byte> dataToSignOwner = memoryPool.Rent(signingInputByteCount);
        Debug.Assert(dataToSignOwner.Memory.Length == signingInputByteCount, "Pool must return exact-size allocations.");
        Encoding.ASCII.GetBytes(signingInput, dataToSignOwner.Memory.Span);

        CryptoAlgorithm cryptoAlgorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(cryptoAlgorithm, purpose);

        Signature signature = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            dataToSignOwner.Memory,
            memoryPool).ConfigureAwait(false);

        var signatureComponent = new JwsSignatureComponent(
            headerSegment,
            unsignedJwt.Header,
            signature);

        return new JwsMessage(payloadBytes, signatureComponent);
    }
}