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
/// Extension methods for securing Verifiable Credentials using JOSE (JSON Object Signing and Encryption).
/// </summary>
/// <remarks>
/// <para>
/// These extensions enable signing credentials as JWS (JSON Web Signature) compact serializations,
/// producing tokens like <c>header.payload.signature</c> that can be transmitted and verified
/// according to RFC 7515 and the VC-JOSE-COSE specification.
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
    /// Signs the credential as a JWS compact serialization.
    /// </summary>
    /// <param name="credential">The credential to sign.</param>
    /// <param name="privateKey">The private key for signing. The key's <see cref="Tag"/> determines the algorithm.</param>
    /// <param name="verificationMethodId">
    /// The DID URL identifying the verification method (e.g., <c>"did:web:example.com#key-1"</c>).
    /// This becomes the <c>kid</c> header parameter.
    /// </param>
    /// <param name="credentialSerializer">Delegate for serializing the credential to JSON bytes.</param>
    /// <param name="headerSerializer">Delegate for serializing the JWT header to JSON bytes.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="memoryPool">Memory pool for signature allocation.</param>
    /// <param name="mediaType">
    /// Optional media type for the <c>typ</c> header. Defaults to <see cref="WellKnownMediaTypes.Jwt.VcLdJwt"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The JWS compact serialization string.</returns>
    /// <remarks>
    /// <para>
    /// The resulting JWS has the structure <c>BASE64URL(header).BASE64URL(payload).BASE64URL(signature)</c> where:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Header contains <c>alg</c> (derived from key), <c>typ</c>, and <c>kid</c>.</description></item>
    /// <item><description>Payload is the complete credential JSON.</description></item>
    /// <item><description>Signature is computed over the ASCII bytes of <c>header.payload</c>.</description></item>
    /// </list>
    /// <para>
    /// The signing function is resolved from the <see cref="CryptoFunctionRegistry{TAlgorithm, TPurpose}"/>
    /// based on the algorithm and purpose in the private key's tag.
    /// </para>
    /// </remarks>
    public static async ValueTask<string> SignJwsAsync(
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
        ArgumentNullException.ThrowIfNull(credential, nameof(credential));
        ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));
        ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId, nameof(verificationMethodId));
        ArgumentNullException.ThrowIfNull(credentialSerializer, nameof(credentialSerializer));
        ArgumentNullException.ThrowIfNull(headerSerializer, nameof(headerSerializer));
        ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));
        ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

        //Derive the JWA algorithm from the key's tag.
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

        //Build the protected header.
        var header = new Dictionary<string, object>
        {
            [JwkProperties.Alg] = algorithm,
            [JwkProperties.Typ] = mediaType ?? WellKnownMediaTypes.Jwt.VcLdJwt,
            [JwkProperties.Kid] = verificationMethodId
        };

        //Serialize header and payload.
        ReadOnlySpan<byte> headerBytes = headerSerializer(header);
        ReadOnlySpan<byte> payloadBytes = credentialSerializer(credential);

        string headerSegment = base64UrlEncoder(headerBytes);
        string payloadSegment = base64UrlEncoder(payloadBytes);

        //Create signing input per RFC 7515.
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.ASCII.GetBytes(signingInput);

        //Sign using the registry-resolved signing function based on key's tag.
        CryptoAlgorithm cryptoAlgorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(cryptoAlgorithm, purpose);

        using IMemoryOwner<byte> signatureMemory = await signingDelegate(
            privateKey.AsReadOnlySpan(),
            dataToSign,
            memoryPool);

        string signatureSegment = base64UrlEncoder(signatureMemory.Memory.Span);

        return $"{signingInput}.{signatureSegment}";
    }


    /// <summary>
    /// Signs the credential as a JWS compact serialization with additional header claims.
    /// </summary>
    /// <param name="credential">The credential to sign.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="verificationMethodId">The DID URL for the <c>kid</c> header.</param>
    /// <param name="additionalHeaderClaims">Additional claims to include in the protected header.</param>
    /// <param name="credentialSerializer">Delegate for serializing the credential to JSON bytes.</param>
    /// <param name="headerSerializer">Delegate for serializing the JWT header to JSON bytes.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="memoryPool">Memory pool for signature allocation.</param>
    /// <param name="mediaType">Optional media type for the <c>typ</c> header.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The JWS compact serialization string.</returns>
    public static async ValueTask<string> SignJwsAsync(
        this VerifiableCredential credential,
        PrivateKeyMemory privateKey,
        string verificationMethodId,
        IReadOnlyDictionary<string, object> additionalHeaderClaims,
        CredentialToJsonBytesDelegate credentialSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        string? mediaType = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential, nameof(credential));
        ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));
        ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId, nameof(verificationMethodId));
        ArgumentNullException.ThrowIfNull(additionalHeaderClaims, nameof(additionalHeaderClaims));
        ArgumentNullException.ThrowIfNull(credentialSerializer, nameof(credentialSerializer));
        ArgumentNullException.ThrowIfNull(headerSerializer, nameof(headerSerializer));
        ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));
        ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

        //Derive the JWA algorithm from the key's tag.
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

        //Build the protected header with additional claims.
        var header = new Dictionary<string, object>
        {
            [JwkProperties.Alg] = algorithm,
            [JwkProperties.Typ] = mediaType ?? WellKnownMediaTypes.Jwt.VcLdJwt,
            [JwkProperties.Kid] = verificationMethodId
        };

        foreach(var claim in additionalHeaderClaims)
        {
            header[claim.Key] = claim.Value;
        }

        //Serialize header and payload.
        ReadOnlySpan<byte> headerBytes = headerSerializer(header);
        ReadOnlySpan<byte> payloadBytes = credentialSerializer(credential);

        string headerSegment = base64UrlEncoder(headerBytes);
        string payloadSegment = base64UrlEncoder(payloadBytes);

        //Create signing input per RFC 7515.
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] dataToSign = Encoding.ASCII.GetBytes(signingInput);

        //Sign using the registry-resolved signing function based on key's tag.
        CryptoAlgorithm cryptoAlgorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(cryptoAlgorithm, purpose);

        using IMemoryOwner<byte> signatureMemory = await signingDelegate(
            privateKey.AsReadOnlySpan(),
            dataToSign,
            memoryPool);

        string signatureSegment = base64UrlEncoder(signatureMemory.Memory.Span);

        return $"{signingInput}.{signatureSegment}";
    }
}


/// <summary>
/// Verification methods for JWS-secured Verifiable Credentials.
/// </summary>
public static class JwsCredentialVerification
{
    /// <summary>
    /// Verifies a JWS-secured credential and returns the decoded credential if valid.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the JWT header from JSON bytes.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from JSON bytes.</param>
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
        ArgumentException.ThrowIfNullOrWhiteSpace(jws, nameof(jws));
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));
        ArgumentNullException.ThrowIfNull(base64UrlDecoder, nameof(base64UrlDecoder));
        ArgumentNullException.ThrowIfNull(headerDeserializer, nameof(headerDeserializer));
        ArgumentNullException.ThrowIfNull(credentialDeserializer, nameof(credentialDeserializer));

        string[] parts = jws.Split('.');
        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        //Decode header.
        using IMemoryOwner<byte> headerBytesOwner = base64UrlDecoder(parts[0], SensitiveMemoryPool<byte>.Shared);
        Dictionary<string, object>? header = headerDeserializer(headerBytesOwner.Memory.Span);

        //Decode payload to get the credential.
        using IMemoryOwner<byte> payloadBytesOwner = base64UrlDecoder(parts[1], SensitiveMemoryPool<byte>.Shared);
        VerifiableCredential credential = credentialDeserializer(payloadBytesOwner.Memory.Span);

        //Decode signature.
        using IMemoryOwner<byte> signatureBytesOwner = base64UrlDecoder(parts[2], SensitiveMemoryPool<byte>.Shared);

        //Compute data to verify (ASCII bytes of header.payload).
        byte[] dataToVerify = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

        //Get verification function from the registry based on public key's tag.
        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        //Verify signature.
        bool isValid = await verificationDelegate(
            dataToVerify,
            signatureBytesOwner.Memory.Span,
            publicKey.AsReadOnlySpan());

        return new JwsCredentialVerificationResult(isValid, header, credential);
    }


    /// <summary>
    /// Verifies a JWS-secured credential using a public key resolved from the header's kid claim.
    /// </summary>
    /// <param name="jws">The JWS compact serialization to verify.</param>
    /// <param name="publicKeyResolver">Delegate that resolves the public key from the <c>kid</c> header.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the JWT header from JSON bytes.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from JSON bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and decoded credential.</returns>
    public static async ValueTask<JwsCredentialVerificationResult> VerifyAsync(
        string jws,
        Func<string, ValueTask<PublicKeyMemory>> publicKeyResolver,
        DecodeDelegate base64UrlDecoder,
        JwtHeaderDeserializer headerDeserializer,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jws, nameof(jws));
        ArgumentNullException.ThrowIfNull(publicKeyResolver, nameof(publicKeyResolver));
        ArgumentNullException.ThrowIfNull(base64UrlDecoder, nameof(base64UrlDecoder));
        ArgumentNullException.ThrowIfNull(headerDeserializer, nameof(headerDeserializer));
        ArgumentNullException.ThrowIfNull(credentialDeserializer, nameof(credentialDeserializer));

        string[] parts = jws.Split('.');
        if(parts.Length != 3)
        {
            throw new ArgumentException("JWS compact serialization must have exactly three parts.", nameof(jws));
        }

        //Decode header to get kid for public key resolution.
        using IMemoryOwner<byte> headerBytesOwner = base64UrlDecoder(parts[0], SensitiveMemoryPool<byte>.Shared);
        Dictionary<string, object>? header = headerDeserializer(headerBytesOwner.Memory.Span);

        if(header == null || !header.TryGetValue(JwkProperties.Kid, out object? kidObj) || kidObj is not string kid)
        {
            return new JwsCredentialVerificationResult(false, header, null);
        }

        //Resolve the public key from the kid.
        using PublicKeyMemory publicKey = await publicKeyResolver(kid);

        //Decode payload to get the credential.
        using IMemoryOwner<byte> payloadBytesOwner = base64UrlDecoder(parts[1], SensitiveMemoryPool<byte>.Shared);
        VerifiableCredential credential = credentialDeserializer(payloadBytesOwner.Memory.Span);

        //Decode signature.
        using IMemoryOwner<byte> signatureBytesOwner = base64UrlDecoder(parts[2], SensitiveMemoryPool<byte>.Shared);

        //Compute data to verify.
        byte[] dataToVerify = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

        //Get verification function from the registry.
        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        //Verify signature.
        bool isValid = await verificationDelegate(
            dataToVerify,
            signatureBytesOwner.Memory.Span,
            publicKey.AsReadOnlySpan());

        return new JwsCredentialVerificationResult(isValid, header, credential);
    }
}


/// <summary>
/// Result of verifying a JWS-secured Verifiable Credential.
/// </summary>
/// <param name="IsValid">Whether the signature is valid.</param>
/// <param name="Header">The decoded JWT header, or null if parsing failed.</param>
/// <param name="Credential">The decoded credential, or null if parsing failed or signature is invalid.</param>
public readonly record struct JwsCredentialVerificationResult(
    bool IsValid,
    Dictionary<string, object>? Header,
    VerifiableCredential? Credential);