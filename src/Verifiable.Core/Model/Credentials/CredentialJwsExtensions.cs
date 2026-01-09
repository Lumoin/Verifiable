using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Jose;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Extension methods for securing Verifiable Credentials using JOSE.
/// </summary>
/// <remarks>
/// <para>
/// These extensions enable signing credentials as JWS (JSON Web Signature),
/// producing <see cref="JwsMessage"/> POCOs that can be serialized to any format
/// using <see cref="JwsSerialization"/>.
/// </para>
/// <para>
/// Unlike Data Integrity proofs which embed the signature within the credential JSON,
/// JOSE enveloping wraps the entire credential as the JWT payload, providing an external
/// securing mechanism.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-jose-cose/">Securing Verifiable Credentials using JOSE and COSE</see>.
/// </para>
/// </remarks>
public static class CredentialJwsExtensions
{
    /// <summary>
    /// Signs the credential as a JWS.
    /// </summary>
    /// <param name="credential">The credential to sign.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="verificationMethodId">The DID URL for the kid header.</param>
    /// <param name="credentialSerializer">Delegate for serializing the credential.</param>
    /// <param name="headerSerializer">Delegate for serializing the header.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <param name="mediaType">Optional media type for typ header.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The JWS message containing the signed credential.</returns>
    public static async ValueTask<JwsMessage> SignJwsAsync(
        this VerifiableCredential credential,
        PrivateKeyMemory privateKey,
        string verificationMethodId,
        CredentialToJsonBytesDelegate credentialSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        string? mediaType = null,
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

        var header = new Dictionary<string, object>
        {
            [JwkProperties.Alg] = algorithm,
            [JwkProperties.Typ] = mediaType ?? WellKnownMediaTypes.Jwt.VcLdJwt,
            [JwkProperties.Kid] = verificationMethodId
        };

        //Copy to arrays immediately since spans cannot cross await boundaries.
        byte[] headerBytes = headerSerializer(header).ToArray();
        byte[] payloadBytes = credentialSerializer(credential).ToArray();

        string headerSegment = base64UrlEncoder(headerBytes);
        string payloadSegment = base64UrlEncoder(payloadBytes);

        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.ASCII.GetBytes(signingInput);

        CryptoAlgorithm cryptoAlgorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(cryptoAlgorithm, purpose);

        Signature signatureMemory = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            dataToSign,
            memoryPool);

        var signatureComponent = new JwsSignatureComponent(
            headerSegment,
            header,
            signatureMemory);

        return new JwsMessage(payloadBytes, signatureComponent);
    }
}