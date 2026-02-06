using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Verification methods for JWS-secured Verifiable Credentials.
/// </summary>
public static class JwsCredentialVerification
{
    /// <summary>
    /// Verifies a JWS-secured credential from compact serialization.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the JWT header.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and decoded credential.</returns>
    /// <exception cref="ArgumentException">Thrown when the JWS does not have exactly three parts.</exception>
    public static async ValueTask<JwsCredentialVerificationResult> VerifyAsync(
        string jws,
        PublicKeyMemory publicKey,
        DecodeDelegate base64UrlDecoder,
        JwtHeaderDeserializer headerDeserializer,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jws);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);

        string[] parts = jws.Split('.');

        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        using IMemoryOwner<byte> headerBytesOwner = base64UrlDecoder(parts[0], SensitiveMemoryPool<byte>.Shared);
        Dictionary<string, object>? header = headerDeserializer(headerBytesOwner.Memory.Span);

        using IMemoryOwner<byte> payloadBytesOwner = base64UrlDecoder(parts[1], SensitiveMemoryPool<byte>.Shared);
        VerifiableCredential credential = credentialDeserializer(payloadBytesOwner.Memory.Span);

        using IMemoryOwner<byte> signatureBytesOwner = base64UrlDecoder(parts[2], SensitiveMemoryPool<byte>.Shared);

        byte[] dataToVerify = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        bool isValid = await verificationDelegate(
            dataToVerify,
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
    /// <param name="credentialDeserializer">Delegate for deserializing the credential.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and decoded credential.</returns>
    public static async ValueTask<JwsCredentialVerificationResult> VerifyAsync(
        JwsMessage message,
        PublicKeyMemory publicKey,
        EncodeDelegate base64UrlEncoder,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);

        if(message.Signatures.Count != 1)
        {
            throw new InvalidOperationException(
                $"This method verifies a single signature. Message has {message.Signatures.Count} signatures.");
        }

        JwsSignatureComponent signature = message.Signatures[0];

        string payloadSegment = base64UrlEncoder(message.Payload.Span);
        string signingInput = $"{signature.Protected}.{payloadSegment}";
        byte[] dataToVerify = Encoding.ASCII.GetBytes(signingInput);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        bool isValid = await verificationDelegate(
            dataToVerify,
            signature.Signature.AsReadOnlyMemory(),
            publicKey.AsReadOnlyMemory()).ConfigureAwait(false);

        VerifiableCredential credential = credentialDeserializer(message.Payload.Span);
        var header = new Dictionary<string, object>(signature.ProtectedHeader);

        return new JwsCredentialVerificationResult(isValid, header, credential);
    }
}