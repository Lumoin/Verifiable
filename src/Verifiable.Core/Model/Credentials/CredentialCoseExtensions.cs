using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Extension methods for securing and verifying Verifiable Credentials using COSE_Sign1.
/// </summary>
/// <remarks>
/// <para>
/// These extensions provide the credential-level API for COSE enveloping as defined by
/// <see href="https://www.w3.org/TR/vc-jose-cose/">Securing Verifiable Credentials using JOSE and COSE</see>.
/// </para>
/// <para>
/// Per the W3C specification, the unsecured verifiable credential is the COSE payload.
/// The credential is CBOR-serialized and placed directly as the payload of a COSE_Sign1
/// structure, parallel to how the JWS envelope uses the JSON-serialized credential as
/// the raw JWT payload.
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Signing</strong>: Serializes a <see cref="VerifiableCredential"/> to CBOR bytes,
/// constructs a protected header with algorithm and content type parameters, signs via
/// <see cref="Cose.SignAsync"/>, and returns a <see cref="CoseSign1Message"/> POCO.
/// </description></item>
/// <item><description>
/// <strong>Verification</strong>: Verifies a COSE_Sign1-secured credential and
/// returns a <see cref="CoseCredentialVerificationResult"/> with validity status,
/// the decoded credential, and extracted header parameters.
/// </description></item>
/// </list>
/// <para>
/// CBOR wire format serialization is a separate concern handled by <c>CoseSerialization</c>
/// in <c>Verifiable.Cbor</c>.
/// </para>
/// </remarks>
public static class CredentialCoseExtensions
{
    /// <summary>
    /// Signs the credential as a COSE_Sign1 message.
    /// </summary>
    /// <param name="credential">The credential to sign.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="verificationMethodId">
    /// The identifier for the <c>kid</c> (key ID) header parameter. Per the W3C specification,
    /// this is typically a DID URL pointing to the public key material used for verification.
    /// </param>
    /// <param name="credentialSerializer">Delegate for serializing the credential to CBOR bytes.</param>
    /// <param name="headerSerializer">Delegate for serializing the protected header to CBOR bytes.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="contentType">
    /// Optional content type for the protected header. Defaults to
    /// <see cref="WellKnownMediaTypes.Application.ApplicationVc"/> (<c>application/vc</c>)
    /// as recommended by the W3C VC-JOSE-COSE specification.
    /// </param>
    /// <param name="mediaType">
    /// Optional <c>typ</c> (type) header parameter. Defaults to
    /// <see cref="WellKnownMediaTypes.Application.VcCose"/> (<c>application/vc+cose</c>)
    /// as recommended by the W3C VC-JOSE-COSE specification.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE_Sign1 message containing the signed credential.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller takes ownership of the returned CoseSign1Message.")]
    public static ValueTask<CoseSign1Message> SignCoseAsync(
        this VerifiableCredential credential,
        PrivateKeyMemory privateKey,
        string verificationMethodId,
        CredentialToCborBytesDelegate credentialSerializer,
        CoseProtectedHeaderSerializer headerSerializer,
        BuildSigStructureDelegate buildSigStructure,
        MemoryPool<byte> signaturePool,
        string? contentType = null,
        string? mediaType = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return credential.SignCoseAsync(
            privateKey,
            verificationMethodId,
            credentialSerializer,
            headerSerializer,
            buildSigStructure,
            signingDelegate,
            signaturePool,
            contentType,
            mediaType,
            cancellationToken);
    }


    /// <summary>
    /// Signs the credential as a COSE_Sign1 message using an explicit
    /// <see cref="SigningDelegate"/>. The registry-resolving overload above
    /// delegates here after resolving the function via
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// from <paramref name="privateKey"/>'s <see cref="SensitiveMemory.Tag"/>.
    /// </summary>
    /// <param name="credential">The credential to sign.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="verificationMethodId">
    /// The identifier for the <c>kid</c> (key ID) header parameter. Per the W3C specification,
    /// this is typically a DID URL pointing to the public key material used for verification.
    /// </param>
    /// <param name="credentialSerializer">Delegate for serializing the credential to CBOR bytes.</param>
    /// <param name="headerSerializer">Delegate for serializing the protected header to CBOR bytes.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="signingDelegate">The signing function to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="contentType">
    /// Optional content type for the protected header. Defaults to
    /// <see cref="WellKnownMediaTypes.Application.ApplicationVc"/>
    /// as recommended by the W3C VC-JOSE-COSE specification.
    /// </param>
    /// <param name="mediaType">
    /// Optional <c>typ</c> (type) header parameter. Defaults to
    /// <see cref="WellKnownMediaTypes.Application.VcCose"/>
    /// as recommended by the W3C VC-JOSE-COSE specification.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE_Sign1 message containing the signed credential.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller takes ownership of the returned CoseSign1Message.")]
    public static async ValueTask<CoseSign1Message> SignCoseAsync(
        this VerifiableCredential credential,
        PrivateKeyMemory privateKey,
        string verificationMethodId,
        CredentialToCborBytesDelegate credentialSerializer,
        CoseProtectedHeaderSerializer headerSerializer,
        BuildSigStructureDelegate buildSigStructure,
        SigningDelegate signingDelegate,
        MemoryPool<byte> signaturePool,
        string? contentType = null,
        string? mediaType = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId);
        ArgumentNullException.ThrowIfNull(credentialSerializer);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);

        int coseAlgorithm = CryptoFormatConversions.DefaultTagToCoseConverter(privateKey.Tag);

        var protectedHeader = new Dictionary<int, object>
        {
            [CoseHeaderParameters.Alg] = coseAlgorithm,
            [CoseHeaderParameters.Kid] = verificationMethodId,
            [CoseHeaderParameters.ContentType] = contentType ?? WellKnownMediaTypes.Application.ApplicationVc,
            [CoseHeaderParameters.Typ] = mediaType ?? WellKnownMediaTypes.Application.VcCose
        };

        //Pool-route the protected header bytes so they carry CBOM provenance
        //(CryptoTags.CoseEncodedProtectedHeader) and are observable to the
        //OTel allocation pipeline. The CoseSign1Message takes ownership and
        //disposes the carrier.
        ReadOnlySpan<byte> protectedHeaderSerialized = headerSerializer(protectedHeader);
        IMemoryOwner<byte> protectedHeaderOwner = signaturePool.Rent(protectedHeaderSerialized.Length);
        protectedHeaderSerialized.CopyTo(protectedHeaderOwner.Memory.Span);
        EncodedCoseProtectedHeader protectedHeaderCarrier = new(protectedHeaderOwner, CryptoTags.CoseEncodedProtectedHeader);

        //Payload bytes are borrowed by the message; the caller controls
        //lifetime. A future chunk lifts the payload to a semantic carrier
        //per the same pool-routing rule.
        byte[] payloadBytes = credentialSerializer(credential).ToArray();

        return await Cose.SignAsync(
            protectedHeaderCarrier,
            unprotectedHeader: null,
            payloadBytes,
            buildSigStructure,
            privateKey,
            signingDelegate,
            signaturePool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a COSE_Sign1-secured credential.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from the payload.</param>
    /// <param name="headerParser">Delegate for parsing the protected header bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and decoded credential.</returns>
    public static ValueTask<CoseCredentialVerificationResult> VerifyCoseAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        ParseProtectedHeaderDelegate headerParser,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return VerifyCoseAsync(
            message,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            credentialDeserializer,
            headerParser,
            cancellationToken);
    }


    /// <summary>
    /// Verifies a COSE_Sign1-secured credential using an explicit
    /// <see cref="VerificationDelegate"/>. The registry-resolving overload
    /// above delegates here after resolving the function via
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// from <paramref name="publicKey"/>'s <see cref="SensitiveMemory.Tag"/>.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from the payload.</param>
    /// <param name="headerParser">Delegate for parsing the protected header bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and decoded credential.</returns>
    public static async ValueTask<CoseCredentialVerificationResult> VerifyCoseAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        ParseProtectedHeaderDelegate headerParser,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);
        ArgumentNullException.ThrowIfNull(headerParser);

        bool isValid = await Cose.VerifyAsync(
            message,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            cancellationToken).ConfigureAwait(false);

        if(!isValid)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        Dictionary<int, object> header = new(headerParser(message.ProtectedHeader.AsReadOnlySpan()));
        VerifiableCredential credential = credentialDeserializer(message.Payload.Span);

        int? alg = header.TryGetValue(CoseHeaderParameters.Alg, out object? algValue) && algValue is int a ? a : null;
        string? kid = header.TryGetValue(CoseHeaderParameters.Kid, out object? kidValue) && kidValue is string k ? k : null;

        var verifiedCredential = new Verified<VerifiableCredential>(credential, VerificationContextTag.Create(kid));

        return CoseCredentialVerificationResult.Success(header, verifiedCredential, alg, kid);
    }


    /// <summary>
    /// Verifies a COSE_Sign1-secured credential using an explicit verification function.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationFunction">The verification function to use.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from the payload.</param>
    /// <param name="headerParser">Delegate for parsing the protected header bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and decoded credential.</returns>
    public static async ValueTask<CoseCredentialVerificationResult> VerifyCoseAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction,
        MemoryPool<byte> pool,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        ParseProtectedHeaderDelegate headerParser,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationFunction);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);
        ArgumentNullException.ThrowIfNull(headerParser);

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeader.AsReadOnlySpan(),
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        bool isValid = await verificationFunction(publicKey.AsReadOnlyMemory(), toBeSigned, message.Signature).ConfigureAwait(false);

        if(!isValid)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        Dictionary<int, object> header = new(headerParser(message.ProtectedHeader.AsReadOnlySpan()));
        VerifiableCredential credential = credentialDeserializer(message.Payload.Span);

        int? alg = header.TryGetValue(CoseHeaderParameters.Alg, out object? algValue) && algValue is int a ? a : null;
        string? kid = header.TryGetValue(CoseHeaderParameters.Kid, out object? kidValue) && kidValue is string k ? k : null;

        var verifiedCredential = new Verified<VerifiableCredential>(credential, VerificationContextTag.Create(kid));

        return CoseCredentialVerificationResult.Success(header, verifiedCredential, alg, kid);
    }
}
