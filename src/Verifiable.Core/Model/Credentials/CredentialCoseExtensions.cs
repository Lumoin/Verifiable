using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
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
        BaseMemoryPool signaturePool,
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
        BaseMemoryPool signaturePool,
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
        //lifetime. The payload is not yet lifted to a semantic carrier
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
            cancellationToken: cancellationToken).ConfigureAwait(false);
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
    /// <remarks>
    /// This is a bring-your-own-key primitive: <paramref name="publicKey"/> is a plain parameter
    /// this method never resolves or cross-checks against anything, so the <c>kid</c> recorded onto
    /// the result's <see cref="Verified{T}"/> context is a wire label the check never tied to
    /// <paramref name="publicKey"/> — an <see cref="AssertedProvenance"/>, never a principal
    /// authentication. It exists for callers whose key trust is established out of band. The
    /// resolving overload below — taking a <see cref="DidResolver"/> instead of a key — is the
    /// recommended default.
    /// </remarks>
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
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!isValid)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        Dictionary<int, object> header = new(headerParser(message.ProtectedHeader.AsReadOnlySpan()));
        VerifiableCredential credential = credentialDeserializer(message.Payload.Span);

        int? alg = header.TryGetValue(CoseHeaderParameters.Alg, out object? algValue) && algValue is int a ? a : null;
        string? kid = header.TryGetValue(CoseHeaderParameters.Kid, out object? kidValue) && kidValue is string k ? k : null;

        var verifiedCredential = Verified<VerifiableCredential>.CreateAsserted(credential, AssertedProvenance.OfLabel(kid));

        return CoseCredentialVerificationResult.Success(header, verifiedCredential, alg, kid);
    }


    /// <summary>
    /// Verifies a COSE_Sign1-secured credential by RESOLVING the signer's verification method — the
    /// recommended default shape.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Implements the DIDComm Tier-A recipe (<c>DidCommSignedExtensions.UnpackSignedAsync</c>)
    /// adapted to a credential's own signed <c>issuer</c> claim, every gate a fail-closed
    /// short-circuit before the cryptographic check:
    /// </para>
    /// <list type="number">
    /// <item><description>Extract <c>kid</c> from the COSE protected header. Absent → refuse.</description></item>
    /// <item><description><c>kid</c>'s base DID MUST equal the credential's own signed <c>issuer</c> claim. Mismatch/unparseable → refuse.</description></item>
    /// <item><description>Resolve INSIDE this method via <paramref name="didResolver"/> — never a caller-handed document. Resolution failure → refuse.</description></item>
    /// <item><description>The method MUST be listed under the resolved document's <c>assertionMethod</c> relationship, not merely the flat array. Not listed → refuse.</description></item>
    /// <item><description>Key material and algorithm come from the RESOLVED method only — never the wire COSE <c>alg</c>, defeating algorithm substitution — via <see cref="VerificationMethodExtensions.VerifySignatureAsync"/>.</description></item>
    /// <item><description>Only past every gate does <see cref="BoundProvenance.TryBindByResolvedMethod"/> mint a <see cref="Verified{T}"/> whose <see cref="Verified{T}.IsIdentityBound"/> is <see langword="true"/>.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="didResolver">The resolver this method calls to resolve the signer's DID.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from the payload.</param>
    /// <param name="headerParser">Delegate for parsing the protected header bytes.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The verification result. <see cref="CoseCredentialVerificationResult.Credential"/> is non-null
    /// and identity-bound only when every gate above holds and the signature verifies; a caught
    /// malformed header/payload also refuses rather than escaping as an exception.
    /// </returns>
    public static async ValueTask<CoseCredentialVerificationResult> VerifyCoseAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        ParseProtectedHeaderDelegate headerParser,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);
        ArgumentNullException.ThrowIfNull(headerParser);
        ArgumentNullException.ThrowIfNull(memoryPool);

        Dictionary<int, object> header;
        VerifiableCredential credential;
        try
        {
            header = new Dictionary<int, object>(headerParser(message.ProtectedHeader.AsReadOnlySpan()));

            //The credential must be decoded before the signature is checked -- its signed `issuer`
            //claim is the identity the kid is bound to (gate 2). A malformed payload cannot verify
            //either way, so a decode failure here fails closed rather than escaping as an exception.
            credential = credentialDeserializer(message.Payload.Span);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return CoseCredentialVerificationResult.Failed();
        }

        int? alg = header.TryGetValue(CoseHeaderParameters.Alg, out object? algValue) && algValue is int a ? a : null;
        string? kid = header.TryGetValue(CoseHeaderParameters.Kid, out object? kidValue) && kidValue is string k ? k : null;

        (VerificationMethod Method, DidDocument Document)? resolved = await CredentialEnvelopeIdentityBinding
            .TryResolveAssertionMethodAsync(kid, credential.Issuer?.Id, didResolver, exchangeContext, cancellationToken)
            .ConfigureAwait(false);

        if(resolved is not { } binding)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeader.AsReadOnlySpan(),
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        bool isValid = await binding.Method.VerifySignatureAsync(toBeSigned, message.Signature, memoryPool).ConfigureAwait(false);
        if(!isValid)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        string absoluteMethodId = CredentialEnvelopeIdentityBinding.ExpandMethodId(binding.Method, binding.Document) ?? kid!;
        BoundProvenance? provenance = BoundProvenance.TryBindByResolvedMethod(
            new KeyId(kid!), absoluteMethodId, VerificationRelationship.AssertionMethod, credential);

        if(provenance is null
            || Verified<VerifiableCredential>.TryCreateBound(credential, provenance) is not { } verifiedCredential)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        return CoseCredentialVerificationResult.Success(header, verifiedCredential, alg, kid);
    }


    /// <summary>
    /// Verifies a COSE_Sign1-secured credential using an explicit verification function.
    /// </summary>
    /// <remarks>
    /// This is a bring-your-own-key primitive: <paramref name="publicKey"/> is a plain parameter
    /// this method never resolves or cross-checks against anything, so the <c>kid</c> recorded onto
    /// the result's <see cref="Verified{T}"/> context is a wire label the check never tied to
    /// <paramref name="publicKey"/> — an <see cref="AssertedProvenance"/>, never a principal
    /// authentication. It exists for callers whose key trust is established out of band. The
    /// resolving "explicit-fn" overload below — taking a <see cref="DidResolver"/> instead of a key
    /// — is the recommended default for callers who still need to supply their own verification
    /// function (for example an HSM-bound verify callback).
    /// </remarks>
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
        BaseMemoryPool pool,
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

        var verifiedCredential = Verified<VerifiableCredential>.CreateAsserted(credential, AssertedProvenance.OfLabel(kid));

        return CoseCredentialVerificationResult.Success(header, verifiedCredential, alg, kid);
    }


    /// <summary>
    /// Verifies a COSE_Sign1-secured credential by RESOLVING the signer's verification method and
    /// running the caller's own explicit verification function against the RESOLVED key material —
    /// the "explicit-fn" resolving shape, for callers whose crypto engine is not
    /// registry-resolvable (for example an HSM-bound verify callback). Implements the same six-gate
    /// DIDComm Tier-A recipe as the registry-flavored resolving overload above.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="didResolver">The resolver this method calls to resolve the signer's DID.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="verificationFunction">The verification function invoked against the RESOLVED method's own key material — never a caller-supplied key.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from the payload.</param>
    /// <param name="headerParser">Delegate for parsing the protected header bytes.</param>
    /// <param name="pool">Memory pool for allocations, including the resolved key material extraction.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The verification result. <see cref="CoseCredentialVerificationResult.Credential"/> is non-null
    /// and identity-bound only when every gate holds and the signature verifies.
    /// </returns>
    public static async ValueTask<CoseCredentialVerificationResult> VerifyCoseAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        ParseProtectedHeaderDelegate headerParser,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);
        ArgumentNullException.ThrowIfNull(verificationFunction);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);
        ArgumentNullException.ThrowIfNull(headerParser);
        ArgumentNullException.ThrowIfNull(pool);

        Dictionary<int, object> header;
        VerifiableCredential credential;
        try
        {
            header = new Dictionary<int, object>(headerParser(message.ProtectedHeader.AsReadOnlySpan()));
            credential = credentialDeserializer(message.Payload.Span);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            //The header and credential are untrusted bytes not yet signature-checked; a decode failure
            //fails closed rather than escaping as an exception, cancellation excepted above.
            return CoseCredentialVerificationResult.Failed();
        }

        int? alg = header.TryGetValue(CoseHeaderParameters.Alg, out object? algValue) && algValue is int a ? a : null;
        string? kid = header.TryGetValue(CoseHeaderParameters.Kid, out object? kidValue) && kidValue is string k ? k : null;

        (VerificationMethod Method, DidDocument Document)? resolved = await CredentialEnvelopeIdentityBinding
            .TryResolveAssertionMethodAsync(kid, credential.Issuer?.Id, didResolver, exchangeContext, cancellationToken)
            .ConfigureAwait(false);

        if(resolved is not { } binding)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeader.AsReadOnlySpan(),
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        //Key material extracted from the RESOLVED method only -- never a caller-supplied key -- fed
        //into the caller's own verification function.
        var rawKeyMaterial = VerificationMethodCryptoConversions.DefaultConverter(binding.Method, pool);
        bool isValid;
        using(rawKeyMaterial.keyMaterial)
        {
            isValid = await verificationFunction(rawKeyMaterial.keyMaterial.Memory, toBeSigned, message.Signature).ConfigureAwait(false);
        }

        if(!isValid)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        string absoluteMethodId = CredentialEnvelopeIdentityBinding.ExpandMethodId(binding.Method, binding.Document) ?? kid!;
        BoundProvenance? provenance = BoundProvenance.TryBindByResolvedMethod(
            new KeyId(kid!), absoluteMethodId, VerificationRelationship.AssertionMethod, credential);

        if(provenance is null
            || Verified<VerifiableCredential>.TryCreateBound(credential, provenance) is not { } verifiedCredential)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        return CoseCredentialVerificationResult.Success(header, verifiedCredential, alg, kid);
    }
}
