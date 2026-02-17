using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Jose;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Extension methods for securing and verifying Verifiable Credentials using JWS.
/// </summary>
/// <remarks>
/// <para>
/// These extensions provide the credential-level API for JOSE enveloping as defined by
/// <see href="https://www.w3.org/TR/vc-jose-cose/">Securing Verifiable Credentials using JOSE and COSE</see>.
/// </para>
/// <para>
/// Per the W3C specification, the unsecured verifiable credential is the unencoded JWS payload.
/// The entire VC JSON-LD document becomes the JWT payload directly, without wrapping in a
/// <c>vc</c> claim or mapping to JWT registered claims. This differs from SD-JWT VCs, which
/// use flat JWT claim maps with <c>_sd</c> digests and are handled by
/// <c>SdJwtIssuance</c> via the <see cref="UnsignedJwt"/> pipeline.
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Signing</strong>: Serializes a <see cref="VerifiableCredential"/> to JSON bytes,
/// uses those as the raw JWS payload, constructs a <see cref="JwtHeader"/> with <c>alg</c>,
/// <c>typ</c>, <c>kid</c>, and <c>cty</c>, and returns a <see cref="JwsMessage"/> POCO.
/// </description></item>
/// <item><description>
/// <strong>Verification</strong>: Verifies a JWS-secured credential from either compact
/// serialization or a <see cref="JwsMessage"/> POCO, returning a
/// <see cref="JwsCredentialVerificationResult"/> with validity status and the decoded credential.
/// </description></item>
/// </list>
/// <para>
/// Serialization to wire format (compact, flattened JSON, general JSON) is a separate concern
/// handled by <see cref="JwsSerialization"/>.
/// </para>
/// </remarks>
public static class CredentialJwsExtensions
{
    /// <summary>
    /// Signs the credential as a JWS.
    /// </summary>
    /// <param name="credential">The credential to sign.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="verificationMethodId">The DID URL for the <c>kid</c> header.</param>
    /// <param name="credentialSerializer">Delegate for serializing the credential to UTF-8 JSON bytes.</param>
    /// <param name="headerSerializer">Delegate for serializing the JWT header to UTF-8 bytes.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <param name="mediaType">Optional media type for the <c>typ</c> header. Defaults to <c>vc+jwt</c>.</param>
    /// <param name="contentType">
    /// Optional content type for the <c>cty</c> header. Defaults to
    /// <see cref="WellKnownMediaTypes.Application.Vc"/> (<c>vc</c>) as recommended
    /// by the W3C VC-JOSE-COSE specification.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The JWS message containing the signed credential.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller takes ownership of the returned JwsMessage and is responsible for disposing it.")]
    public static async ValueTask<JwsMessage> SignJwsAsync(
        this VerifiableCredential credential,
        PrivateKeyMemory privateKey,
        string verificationMethodId,
        CredentialToJsonBytesDelegate credentialSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        string? mediaType = null,
        string? contentType = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId);
        ArgumentNullException.ThrowIfNull(credentialSerializer);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

        var header = new JwtHeader
        {
            [JwkProperties.Alg] = algorithm,
            [JwkProperties.Typ] = mediaType ?? WellKnownMediaTypes.Jwt.VcJwt,
            [JwkProperties.Kid] = verificationMethodId,
            [JwkProperties.Cty] = contentType ?? WellKnownMediaTypes.Application.Vc
        };

        string headerSegment = base64UrlEncoder(headerSerializer(header));

        //The payload bytes must survive into the returned JwsMessage.
        byte[] payloadBytes = credentialSerializer(credential).ToArray();
        string payloadSegment = base64UrlEncoder(payloadBytes);

        //Per RFC 7515 Section 5.1, the JWS signing input is the ASCII representation
        //of the base64url-encoded header and payload joined by a period character.
        int signingInputLength = headerSegment.Length + 1 + payloadSegment.Length;
        using IMemoryOwner<byte> signingInputOwner = memoryPool.Rent(signingInputLength);
        Memory<byte> signingInputMemory = signingInputOwner.Memory[..signingInputLength];

        int written = Encoding.ASCII.GetBytes(headerSegment, signingInputMemory.Span);
        signingInputMemory.Span[written] = (byte)'.';
        written += 1;
        written += Encoding.ASCII.GetBytes(payloadSegment, signingInputMemory.Span[written..]);

        Debug.Assert(written == signingInputLength, "Signing input length must match the expected size.");

        CryptoAlgorithm cryptoAlgorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(cryptoAlgorithm, purpose);

        Signature signature = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            signingInputMemory,
            memoryPool).ConfigureAwait(false);

        var signatureComponent = new JwsSignatureComponent(
            headerSegment,
            header,
            signature);

        return new JwsMessage(payloadBytes, signatureComponent);
    }


    /// <summary>
    /// Verifies a JWS-secured credential from compact serialization.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the JWT header.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and the decoded credential.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS does not have exactly three parts.</exception>
    public static async ValueTask<JwsCredentialVerificationResult> VerifyJwsAsync(
        string jws,
        PublicKeyMemory publicKey,
        DecodeDelegate base64UrlDecoder,
        JwtHeaderDeserializer headerDeserializer,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jws);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> headerBytesOwner = base64UrlDecoder(parts[0], memoryPool);
        Dictionary<string, object>? header = headerDeserializer(headerBytesOwner.Memory.Span);

        using IMemoryOwner<byte> payloadBytesOwner = base64UrlDecoder(parts[1], memoryPool);
        VerifiableCredential credential = credentialDeserializer(payloadBytesOwner.Memory.Span);

        using IMemoryOwner<byte> signatureBytesOwner = base64UrlDecoder(parts[2], memoryPool);

        //Per RFC 7515 Section 5.2, verification uses the same ASCII signing input.
        int verifyInputLength = parts[0].Length + 1 + parts[1].Length;
        using IMemoryOwner<byte> verifyInputOwner = memoryPool.Rent(verifyInputLength);
        Memory<byte> verifyInputMemory = verifyInputOwner.Memory[..verifyInputLength];

        int written = Encoding.ASCII.GetBytes(parts[0], verifyInputMemory.Span);
        verifyInputMemory.Span[written] = (byte)'.';
        written += 1;
        written += Encoding.ASCII.GetBytes(parts[1], verifyInputMemory.Span[written..]);

        Debug.Assert(written == verifyInputLength, "Verification input length must match the expected size.");

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        bool isValid = await verificationDelegate(
            verifyInputMemory,
            signatureBytesOwner.Memory,
            publicKey.AsReadOnlyMemory()).ConfigureAwait(false);

        return new JwsCredentialVerificationResult(isValid, header, credential);
    }


    /// <summary>
    /// Verifies a JWS message directly.
    /// </summary>
    /// <param name="message">The JWS message to verify.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and the decoded credential.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the message has more than one signature.</exception>
    public static async ValueTask<JwsCredentialVerificationResult> VerifyJwsAsync(
        JwsMessage message,
        PublicKeyMemory publicKey,
        EncodeDelegate base64UrlEncoder,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(message.Signatures.Count != 1)
        {
            throw new InvalidOperationException(
                $"This method verifies a single signature. Message has {message.Signatures.Count} signatures.");
        }

        JwsSignatureComponent signature = message.Signatures[0];

        string payloadSegment = base64UrlEncoder(message.Payload.Span);

        //Per RFC 7515 Section 5.2, verification uses the same ASCII signing input.
        int verifyInputLength = signature.Protected.Length + 1 + payloadSegment.Length;
        using IMemoryOwner<byte> verifyInputOwner = memoryPool.Rent(verifyInputLength);
        Memory<byte> verifyInputMemory = verifyInputOwner.Memory[..verifyInputLength];

        int written = Encoding.ASCII.GetBytes(signature.Protected, verifyInputMemory.Span);
        verifyInputMemory.Span[written] = (byte)'.';
        written += 1;
        written += Encoding.ASCII.GetBytes(payloadSegment, verifyInputMemory.Span[written..]);

        Debug.Assert(written == verifyInputLength, "Verification input length must match the expected size.");

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        bool isValid = await verificationDelegate(
            verifyInputMemory,
            signature.Signature.AsReadOnlyMemory(),
            publicKey.AsReadOnlyMemory()).ConfigureAwait(false);

        VerifiableCredential credential = credentialDeserializer(message.Payload.Span);
        var header = new Dictionary<string, object>(signature.ProtectedHeader);

        return new JwsCredentialVerificationResult(isValid, header, credential);
    }
}