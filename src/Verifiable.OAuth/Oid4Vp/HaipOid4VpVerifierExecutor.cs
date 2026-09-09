using System.Buffers;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Creates a pre-wired <see cref="OAuthActionExecutor"/> for the HAIP 1.0
/// OID4VP Verifier server flow.
/// </summary>
/// <remarks>
/// <para>
/// Two factory methods are provided:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="Create"/> — full control. The caller supplies the three ECDH-ES
///       crypto delegates explicitly. Use in tests and in applications where the crypto
///       backend must be auditable at the call site.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="CreateWithRegistry"/> — convenient. The three crypto delegates
///       are resolved from
///       <see cref="KeyAgreementFunctionRegistry{TAlgorithm,TPurpose}"/> at decrypt time
///       using the decryption key's <see cref="Tag"/>. Use when the registry is
///       guaranteed to be populated at startup.
///     </description>
///   </item>
/// </list>
/// <para>
/// Key resolvers (<see cref="AuthorizationServerCryptography.SigningKeyResolver"/>,
/// <see cref="AuthorizationServerCryptography.DecryptionKeyResolver"/>),
/// client registration lookup (<see cref="AuthorizationServerIntegration.LoadClientRegistrationAsync"/>),
/// and the Base64url encoder (<see cref="AuthorizationServerCodecs.Encoder"/>) are
/// read from the <see cref="EndpointServer"/> instance at call time — they
/// are not captured at construction.
/// </para>
/// </remarks>
public static class HaipOid4VpVerifierExecutor
{
    /// <summary>
    /// Creates a pre-wired <see cref="OAuthActionExecutor"/> with the three ECDH-ES
    /// crypto delegates supplied explicitly by the caller.
    /// </summary>
    /// <param name="headerSerializer">Delegate for serializing JWT headers.</param>
    /// <param name="payloadSerializer">Delegate for serializing JWT payloads.</param>
    /// <param name="dcqlQuerySerializer">Delegate for serializing DCQL queries.</param>
    /// <param name="clientMetadataSerializer">Delegate for serializing client metadata.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="resolveIssuerKey">
    /// Resolves an issuer public key from its identifier for credential signature verification.
    /// </param>
    /// <param name="parseSdJwtToken">
    /// Parses an SD-JWT from its wire format. Wired to <c>SdJwtSerializer.ParseToken</c>.
    /// </param>
    /// <param name="computeSdJwtHashInput">
    /// Computes the <c>sd_hash</c> input string. Wired to <c>SdJwtSerializer.GetSdJwtForHashing</c>.
    /// </param>
    /// <param name="keyAgreementDecryptDelegate">
    /// ECDH-ES key agreement decryption delegate per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">RFC 7518 §4.6</see>.
    /// </param>
    /// <param name="keyDerivationDelegate">
    /// Concat KDF key derivation delegate per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6.2">RFC 7518 §4.6.2</see>.
    /// </param>
    /// <param name="aeadDecryptDelegate">AES-GCM content decryption delegate.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="keyAgreementEncryptDelegate">
    /// Optional ECDH-ES encryption delegate used by the
    /// <see cref="SignJarAction"/> handler to JWE-wrap the signed JAR per OID4VP
    /// 1.0 §5.10 when the Wallet supplies <c>wallet_metadata.jwks</c>. Required
    /// alongside <paramref name="aeadEncryptDelegate"/> when JAR encryption is
    /// to be supported; pass <see langword="null"/> for signed-JAR-only deployments.
    /// </param>
    /// <param name="aeadEncryptDelegate">
    /// Optional AES-GCM content encryption delegate paired with
    /// <paramref name="keyAgreementEncryptDelegate"/>. <see langword="null"/>
    /// when JAR encryption is not supported.
    /// </param>
    /// <param name="tagToEpkCrvConverter">
    /// Optional <see cref="Tag"/> → JWK <c>crv</c> converter used by the JAR
    /// encryption path to populate the EPK header. <see langword="null"/>
    /// when JAR encryption is not supported.
    /// </param>
    /// <param name="parseX5c">
    /// Optional parser for a <c>dc+sd-jwt</c> issuer JWS's <c>x5c</c> header (RFC 7515 §4.1.6), the
    /// <c>aki</c>/<c>etsi_tl</c> evidence source for <paramref name="resolveTrustedAuthorityEvidence"/>.
    /// <see langword="null"/> when no <c>dc+sd-jwt</c> credential in this deployment carries one.
    /// </param>
    /// <param name="resolveTrustedAuthorityEvidence">
    /// Optional resolver of the OID4VP 1.0 §6.1.1 trust evidence for a <c>dc+sd-jwt</c> credential
    /// from its <paramref name="parseX5c"/>-parsed certificate chain and verified <c>iss</c>, wired
    /// to e.g. <see cref="TrustedAuthorityEvidenceResolution.Build"/>, surfaced on
    /// <see cref="VpTokenParsed.TrustedAuthorityEvidence"/>. <see langword="null"/> surfaces no
    /// evidence, so a <c>trusted_authorities</c> constraint on a <c>dc+sd-jwt</c> query fails closed
    /// (<see cref="Verifiable.Core.Dcql.DcqlFailureReasons.TrustedAuthorityEvidenceAbsent"/>).
    /// </param>
    /// <param name="credentialStatusPolicy">
    /// The relying party's verdict over a presentation's surfaced <see cref="CredentialStatusOutcome"/> map,
    /// applied once per presentation over the complete map after every presented credential has verified.
    /// Defaults to <see cref="CredentialStatusPolicies.Surface"/> (never refuses — SD-JWT VC -18's "Verifier
    /// policy decides"); pass <see cref="CredentialStatusPolicies.RefuseNotValid"/> or a deployment-specific
    /// delegate to refuse a determinable revoked or suspended status as
    /// <see cref="VerifierFlowRefusalKind.PolicyRefused"/> (<c>access_denied</c>).
    /// </param>
    /// <param name="statusListFreshnessPolicy">
    /// The Section 8.3 step 4.b freshness policy applied to a resolved Status List Token's <c>iat</c>, or
    /// <see langword="null"/> to skip the check (today's behavior). Threaded to
    /// <see cref="Oid4Vp.Server.VpTokenCredentialStatus.CheckAsync"/>.
    /// </param>
    /// <param name="statusListCachingBounds">
    /// The Section 11.5 refresh-interval floor and ceiling applied to a resolved Status List Token's
    /// <c>ttl</c>, or <see langword="null"/> to leave it unclamped (today's behavior). Threaded to
    /// <see cref="Oid4Vp.Server.VpTokenCredentialStatus.CheckAsync"/>.
    /// </param>
    /// <param name="unsupportedStatusMechanisms">
    /// What to do with a presented credential whose <c>status</c> claim names only status mechanisms this
    /// library does not evaluate. Defaults to <see cref="UnsupportedStatusMechanismDisposition.Refuse"/> —
    /// Token Status List §8.3's "no statement about the status of the Referenced Token can be made and the
    /// Referenced Token SHOULD be rejected"; pass <see cref="UnsupportedStatusMechanismDisposition.Surface"/>
    /// to accept the presentation instead and read the mechanism names off
    /// <see cref="Oid4Vp.Server.VpCredentialClaims.Status"/>.
    /// </param>
    public static OAuthActionExecutor Create(
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
        JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ParseSdJwtTokenDelegate parseSdJwtToken,
        ComputeSdJwtHashInputDelegate computeSdJwtHashInput,
        ComputeDigestDelegate computeDigest,
        IReadOnlyDictionary<string, ClaimIssuer<ValidationContext>> vpValidators,
        KeyAgreementDecryptDelegate keyAgreementDecryptDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        BaseMemoryPool pool,
        KeyAgreementEncryptDelegate? keyAgreementEncryptDelegate = null,
        AeadEncryptDelegate? aeadEncryptDelegate = null,
        TagToEpkCrvDelegate? tagToEpkCrvConverter = null,
        MdocVpVerificationSeams? mdocSeams = null,
        SdCwtVpVerificationSeams? sdCwtSeams = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        AssessVpDisclosureDelegate? assessDisclosure = null,
        ResolveVerifiedStatusListTokenDelegate? resolveVerifiedStatusListToken = null,
        ParseX5cDelegate? parseX5c = null,
        ResolveTrustedAuthorityEvidenceDelegate? resolveTrustedAuthorityEvidence = null,
        CredentialStatusPolicy? credentialStatusPolicy = null,
        StatusListFreshnessPolicy? statusListFreshnessPolicy = null,
        StatusListCachingBounds? statusListCachingBounds = null,
        UnsupportedStatusMechanismDisposition unsupportedStatusMechanisms = UnsupportedStatusMechanismDisposition.Refuse)
    {
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(dcqlQuerySerializer);
        ArgumentNullException.ThrowIfNull(clientMetadataSerializer);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(parseSdJwtToken);
        ArgumentNullException.ThrowIfNull(computeSdJwtHashInput);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(vpValidators);
        ArgumentNullException.ThrowIfNull(keyAgreementDecryptDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(aeadDecryptDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        return BuildExecutor(
            headerSerializer,
            payloadSerializer,
            dcqlQuerySerializer,
            clientMetadataSerializer,
            decoder,
            encoder,
            resolveIssuerKey,
            parseSdJwtToken,
            computeSdJwtHashInput,
            computeDigest,
            vpValidators,
            keyAgreementDecryptDelegate,
            keyDerivationDelegate,
            aeadDecryptDelegate,
            pool,
            useRegistry: false,
            keyAgreementEncryptDelegate: keyAgreementEncryptDelegate,
            aeadEncryptDelegate: aeadEncryptDelegate,
            tagToEpkCrvConverter: tagToEpkCrvConverter,
            mdocSeams: mdocSeams,
            sdCwtSeams: sdCwtSeams,
            saltReuseSeam: saltReuseSeam,
            assessDisclosure: assessDisclosure,
            resolveVerifiedStatusListToken: resolveVerifiedStatusListToken,
            parseX5c: parseX5c,
            resolveTrustedAuthorityEvidence: resolveTrustedAuthorityEvidence,
            credentialStatusPolicy: credentialStatusPolicy,
            statusListFreshnessPolicy: statusListFreshnessPolicy,
            statusListCachingBounds: statusListCachingBounds,
            unsupportedStatusMechanisms: unsupportedStatusMechanisms);
    }


    /// <summary>
    /// Creates a pre-wired <see cref="OAuthActionExecutor"/> that resolves the three
    /// crypto delegates from
    /// <see cref="KeyAgreementFunctionRegistry{TAlgorithm,TPurpose}"/> at decrypt time.
    /// </summary>
    /// <remarks>
    /// The registry must be populated before the first <c>direct_post</c> request
    /// arrives. Delegates are resolved from the decryption key's <see cref="Tag"/>.
    /// </remarks>
    /// <param name="headerSerializer">Delegate for serializing JWT headers.</param>
    /// <param name="payloadSerializer">Delegate for serializing JWT payloads.</param>
    /// <param name="dcqlQuerySerializer">Delegate for serializing DCQL queries.</param>
    /// <param name="clientMetadataSerializer">Delegate for serializing client metadata.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="resolveIssuerKey">
    /// Resolves an issuer public key from its identifier for credential signature verification.
    /// </param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="parseX5c">
    /// Optional parser for a <c>dc+sd-jwt</c> issuer JWS's <c>x5c</c> header (RFC 7515 §4.1.6), the
    /// <c>aki</c>/<c>etsi_tl</c> evidence source for <paramref name="resolveTrustedAuthorityEvidence"/>.
    /// <see langword="null"/> when no <c>dc+sd-jwt</c> credential in this deployment carries one.
    /// </param>
    /// <param name="resolveTrustedAuthorityEvidence">
    /// Optional resolver of the OID4VP 1.0 §6.1.1 trust evidence for a <c>dc+sd-jwt</c> credential
    /// from its <paramref name="parseX5c"/>-parsed certificate chain and verified <c>iss</c>, wired
    /// to e.g. <see cref="TrustedAuthorityEvidenceResolution.Build"/>, surfaced on
    /// <see cref="VpTokenParsed.TrustedAuthorityEvidence"/>. <see langword="null"/> surfaces no
    /// evidence, so a <c>trusted_authorities</c> constraint on a <c>dc+sd-jwt</c> query fails closed
    /// (<see cref="Verifiable.Core.Dcql.DcqlFailureReasons.TrustedAuthorityEvidenceAbsent"/>).
    /// </param>
    /// <param name="credentialStatusPolicy">
    /// The relying party's verdict over a presentation's surfaced <see cref="CredentialStatusOutcome"/> map,
    /// applied once per presentation over the complete map after every presented credential has verified.
    /// Defaults to <see cref="CredentialStatusPolicies.Surface"/> (never refuses — SD-JWT VC -18's "Verifier
    /// policy decides"); pass <see cref="CredentialStatusPolicies.RefuseNotValid"/> or a deployment-specific
    /// delegate to refuse a determinable revoked or suspended status as
    /// <see cref="VerifierFlowRefusalKind.PolicyRefused"/> (<c>access_denied</c>).
    /// </param>
    /// <param name="statusListFreshnessPolicy">
    /// The Section 8.3 step 4.b freshness policy applied to a resolved Status List Token's <c>iat</c>, or
    /// <see langword="null"/> to skip the check (today's behavior). Threaded to
    /// <see cref="Oid4Vp.Server.VpTokenCredentialStatus.CheckAsync"/>.
    /// </param>
    /// <param name="statusListCachingBounds">
    /// The Section 11.5 refresh-interval floor and ceiling applied to a resolved Status List Token's
    /// <c>ttl</c>, or <see langword="null"/> to leave it unclamped (today's behavior). Threaded to
    /// <see cref="Oid4Vp.Server.VpTokenCredentialStatus.CheckAsync"/>.
    /// </param>
    /// <param name="unsupportedStatusMechanisms">
    /// What to do with a presented credential whose <c>status</c> claim names only status mechanisms this
    /// library does not evaluate. Defaults to <see cref="UnsupportedStatusMechanismDisposition.Refuse"/> —
    /// Token Status List §8.3's "no statement about the status of the Referenced Token can be made and the
    /// Referenced Token SHOULD be rejected"; pass <see cref="UnsupportedStatusMechanismDisposition.Surface"/>
    /// to accept the presentation instead and read the mechanism names off
    /// <see cref="Oid4Vp.Server.VpCredentialClaims.Status"/>.
    /// </param>
    public static OAuthActionExecutor CreateWithRegistry(
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
        JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ParseSdJwtTokenDelegate parseSdJwtToken,
        ComputeSdJwtHashInputDelegate computeSdJwtHashInput,
        ComputeDigestDelegate computeDigest,
        IReadOnlyDictionary<string, ClaimIssuer<ValidationContext>> vpValidators,
        BaseMemoryPool pool,
        MdocVpVerificationSeams? mdocSeams = null,
        SdCwtVpVerificationSeams? sdCwtSeams = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        AssessVpDisclosureDelegate? assessDisclosure = null,
        ResolveVerifiedStatusListTokenDelegate? resolveVerifiedStatusListToken = null,
        ParseX5cDelegate? parseX5c = null,
        ResolveTrustedAuthorityEvidenceDelegate? resolveTrustedAuthorityEvidence = null,
        CredentialStatusPolicy? credentialStatusPolicy = null,
        StatusListFreshnessPolicy? statusListFreshnessPolicy = null,
        StatusListCachingBounds? statusListCachingBounds = null,
        UnsupportedStatusMechanismDisposition unsupportedStatusMechanisms = UnsupportedStatusMechanismDisposition.Refuse)
    {
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(dcqlQuerySerializer);
        ArgumentNullException.ThrowIfNull(clientMetadataSerializer);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(parseSdJwtToken);
        ArgumentNullException.ThrowIfNull(computeSdJwtHashInput);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(vpValidators);
        ArgumentNullException.ThrowIfNull(pool);

        return BuildExecutor(
            headerSerializer,
            payloadSerializer,
            dcqlQuerySerializer,
            clientMetadataSerializer,
            decoder,
            encoder,
            resolveIssuerKey,
            parseSdJwtToken,
            computeSdJwtHashInput,
            computeDigest,
            vpValidators,
            keyAgreementDecryptDelegate: null!,
            keyDerivationDelegate: null!,
            aeadDecryptDelegate: null!,
            pool,
            useRegistry: true,
            keyAgreementEncryptDelegate: null,
            aeadEncryptDelegate: null,
            tagToEpkCrvConverter: null,
            mdocSeams: mdocSeams,
            sdCwtSeams: sdCwtSeams,
            saltReuseSeam: saltReuseSeam,
            assessDisclosure: assessDisclosure,
            resolveVerifiedStatusListToken: resolveVerifiedStatusListToken,
            parseX5c: parseX5c,
            resolveTrustedAuthorityEvidence: resolveTrustedAuthorityEvidence,
            credentialStatusPolicy: credentialStatusPolicy,
            statusListFreshnessPolicy: statusListFreshnessPolicy,
            statusListCachingBounds: statusListCachingBounds,
            unsupportedStatusMechanisms: unsupportedStatusMechanisms);
    }


    private static OAuthActionExecutor BuildExecutor(
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
        JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ParseSdJwtTokenDelegate parseSdJwtToken,
        ComputeSdJwtHashInputDelegate computeSdJwtHashInput,
        ComputeDigestDelegate computeDigest,
        IReadOnlyDictionary<string, ClaimIssuer<ValidationContext>> vpValidators,
        KeyAgreementDecryptDelegate keyAgreementDecryptDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        BaseMemoryPool pool,
        bool useRegistry,
        KeyAgreementEncryptDelegate? keyAgreementEncryptDelegate,
        AeadEncryptDelegate? aeadEncryptDelegate,
        TagToEpkCrvDelegate? tagToEpkCrvConverter,
        MdocVpVerificationSeams? mdocSeams,
        SdCwtVpVerificationSeams? sdCwtSeams,
        CommitmentReuseDetectionSeam? saltReuseSeam,
        AssessVpDisclosureDelegate? assessDisclosure,
        ResolveVerifiedStatusListTokenDelegate? resolveVerifiedStatusListToken,
        ParseX5cDelegate? parseX5c,
        ResolveTrustedAuthorityEvidenceDelegate? resolveTrustedAuthorityEvidence,
        CredentialStatusPolicy? credentialStatusPolicy,
        StatusListFreshnessPolicy? statusListFreshnessPolicy,
        StatusListCachingBounds? statusListCachingBounds,
        UnsupportedStatusMechanismDisposition unsupportedStatusMechanisms)
    {
        CredentialStatusPolicy statusPolicy = credentialStatusPolicy ?? CredentialStatusPolicies.Surface;

        var executor = new OAuthActionExecutor();

        executor.Register<SignJarAction>(async (action, context, ct) =>
        {
            EndpointServer server = context.Server!;
            var oauth = server.OAuth();

            TenantId tenantId = context.TenantId
                ?? throw new InvalidOperationException(
                    "Tenant identifier not found in context.");

            PrivateKeyMemory? signingKey = await oauth.Cryptography.SigningKeyResolver!(
                action.SigningKeyId, tenantId, context, ct).ConfigureAwait(false);

            if(signingKey is null)
            {
                throw new InvalidOperationException(
                    $"Signing key '{action.SigningKeyId}' not found.");
            }

            ClientRecord? registration = (ClientRecord?)await oauth.LoadClientRegistrationAsync!(
                tenantId, context, ct).ConfigureAwait(false);

            if(registration is null)
            {
                throw new InvalidOperationException(
                    $"Client registration for tenant '{tenantId.Value}' not found.");
            }

            if(registration.ResponseUri is null)
            {
                throw new InvalidOperationException(
                    $"ClientRecord for tenant '{tenantId.Value}' has no ResponseUri.");
            }

            if(registration.ClientMetadata is null)
            {
                throw new InvalidOperationException(
                    $"ClientRecord for tenant '{tenantId.Value}' has no ClientMetadata.");
            }

            //Stamp JAR timing claims using the dispatcher's per-request VerifiedAt
            //when available so all effectful work in this request shares one
            //instant; fall back to the active TimeProvider otherwise. The window
            //size is policy, sourced from oauth.Timings per FAPI 2.0 §5.2.2
            //Clause 13.
            DateTimeOffset now = context.VerifiedAt ?? server.TimeProvider.GetUtcNow();
            TimeSpan requestObjectLifetime = oauth.Timings.Oid4VpRequestObjectLifetime;

            //SignJarAction carries the per-flow response_mode (captured at
            //PAR time onto VerifierParReceivedState and propagated through
            //the action). Null lets HaipProfile default to direct_post.jwt
            //— the HAIP 1.0 §5.1 mandated path.
            (JarSigned jarInput, string compactJar) = await HaipProfile.BuildJarAsync(
                now: now,
                requestObjectLifetime: requestObjectLifetime,
                state: action.ParHandle,
                nonce: action.Nonce,
                dcqlQuery: action.Query,
                clientId: registration.ClientId,
                responseUri: registration.ResponseUri,
                clientMetadata: registration.ClientMetadata,
                signingKey: signingKey,
                headerSerializer: headerSerializer,
                payloadSerializer: payloadSerializer,
                dcqlQuerySerializer: dcqlQuerySerializer,
                clientMetadataSerializer: clientMetadataSerializer,
                encoder: oauth.Codecs.Encoder!,
                pool: pool,
                transactionData: action.TransactionData,
                walletNonce: action.WalletNonce,
                additionalHeaderClaims: action.AdditionalHeaderClaims,
                responseMode: action.ResponseMode,
                cancellationToken: ct).ConfigureAwait(false);

            //OID4VP 1.0 §5.10 JAR encryption: when the Wallet POSTed
            //wallet_metadata containing a jwks object to request_uri, the
            //library transition extracted the jwks JSON text and put it on
            //SignJarAction.WalletEncryptionJwksJson; JWE-wrap the signed JWS
            //using the wallet's public exchange key from that JWKS. The wire
            //body becomes a compact JWE; the wallet decrypts before
            //signature verification. Absent the JWKS this branch is skipped
            //and the signed JWS is served as-is.
            if(action.WalletEncryptionJwksJson is { } walletJwksJson)
            {
                //Recover the wallet's exchange key for any supported ECDH-ES curve
                //(P-256 — the HAIP 1.0 §5.1 default — or an RFC 5639 Brainpool curve).
                //The recovered key carries the matching exchange tag, which drives both
                //the epk crv emission and, in registry mode, the curve-specific delegate
                //resolution below.
                using PublicKeyMemory walletExchangePublicKey =
                    JwksEpkExtractor.ExtractEcdhEncryptionKey(walletJwksJson, decoder, pool);

                //Resolve the encrypt-side delegates. Registry mode dispatches them from
                //the wallet key's curve so any supported curve works without the caller
                //pinning a single curve at construction. Explicit mode uses the delegates
                //the caller wired (P-256 in practice).
                KeyAgreementEncryptDelegate encryptAgreement;
                KeyDerivationDelegate deriveKey;
                AeadEncryptDelegate encryptAead;
                TagToEpkCrvDelegate crvConverter;

                if(useRegistry)
                {
                    CryptoAlgorithm walletAlg = walletExchangePublicKey.Tag.Get<CryptoAlgorithm>();
                    Purpose walletPurpose = walletExchangePublicKey.Tag.Get<Purpose>();

                    encryptAgreement = KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>
                        .ResolveAgreementEncrypt(walletAlg, walletPurpose);
                    deriveKey = KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>
                        .ResolveKeyDerivation(walletAlg, walletPurpose);
                    encryptAead = KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>
                        .ResolveAeadEncrypt(walletAlg, walletPurpose);
                    crvConverter = CryptoFormatConversions.DefaultTagToEpkCrvConverter;
                }
                else
                {
                    if(keyAgreementEncryptDelegate is null
                        || aeadEncryptDelegate is null
                        || tagToEpkCrvConverter is null)
                    {
                        throw new InvalidOperationException(
                            "Wallet supplied wallet_metadata.jwks for JAR encryption " +
                            "per OID4VP 1.0 §5.10 but the executor was constructed " +
                            "without the encrypt-side delegates. Pass " +
                            "keyAgreementEncryptDelegate, aeadEncryptDelegate, and " +
                            "tagToEpkCrvConverter to HaipOid4VpVerifierExecutor.Create.");
                    }

                    encryptAgreement = keyAgreementEncryptDelegate;
                    deriveKey = keyDerivationDelegate;
                    encryptAead = aeadEncryptDelegate;
                    crvConverter = tagToEpkCrvConverter;
                }

                //Rent from the executor's pool rather than allocating a managed
                //array with Encoding.UTF8.GetBytes — keeps the JAR plaintext
                //inside the pool's accounting until JWE-wrapped, matching the
                //rest of the executor's buffer discipline.
                int jarByteCount = Encoding.UTF8.GetByteCount(compactJar);
                using IMemoryOwner<byte> jarBytes = pool.Rent(jarByteCount);
                int written = Encoding.UTF8.GetBytes(
                    compactJar, jarBytes.Memory.Span);

                //Default to A128GCM for JAR encryption — OID4VP §5.10 does
                //not pin an algorithm; production deployments should select
                //from the wallet_metadata-advertised set. The action's
                //JarEncryptionEnc carries the wallet's
                //authorization_encrypted_response_enc choice when supplied.
                string selectedEnc = action.JarEncryptionEnc
                    ?? WellKnownJweEncryptionAlgorithms.A128Gcm;

                compactJar = await HaipProfile.EncryptResponseAsync(
                    walletExchangePublicKey,
                    selectedEnc,
                    jarBytes.Memory[..written],
                    headerSerializer,
                    crvConverter,
                    encryptAgreement,
                    deriveKey,
                    encryptAead,
                    oauth.Codecs.Encoder!,
                    pool,
                    cancellationToken: ct).ConfigureAwait(false);
            }

            //Write the (signed-then-optionally-encrypted) JAR to context so the
            //application skin can serve it in the HTTP response body at the
            //JAR-fetch endpoint.
            context.SetJar(compactJar);

            DateTimeOffset servedAt = context.VerifiedAt
                ?? throw new InvalidOperationException(
                    "Request timestamp not found in context.");

            return new ServerJarSigned(jarInput.Jar, compactJar, servedAt);
        });

        executor.Register<DecryptResponseAction>(async (action, context, ct) =>
        {
            EndpointServer server = context.Server!;
            var oauth = server.OAuth();

            PrivateKeyMemory? decryptionKey = await oauth.Cryptography.DecryptionKeyResolver!(
                action.DecryptionKeyId, context, ct).ConfigureAwait(false);

            if(decryptionKey is null)
            {
                throw new InvalidOperationException(
                    $"Decryption key '{action.DecryptionKeyId}' not found.");
            }

            string vpTokenObjectJson;

            //Wallet-attributable malformed-response detection: an undecodable compact JWE (no dot
            //separator), a JWE 'enc' the deployment does not advertise, an unparseable JWE structure
            //(JweParsing.ParseCompact), or a decrypted payload carrying no 'vp_token' claim are all shapes
            //no conformant Wallet would produce — RFC 6749 §4.1.2.1 invalid_request via Malformed, not a
            //500 fault. Cryptographic decrypt failure itself (a bad AEAD tag) is left on the fault path:
            //FormatException is the library's own parse-exception type for every throw in this block, so
            //the catch below is exception-type-targeted, never a blanket Exception catch.
            try
            {
                DecryptedContent decrypted;

                //Wallet-attributable malformed-response detection ahead of any parse: an over-long
                //compact JWE is a shape no conformant Wallet would produce for this deployment's
                //advertised bound, on either branch below — the registry branch reaches
                //JweParsing.ParseCompact directly, the other through HaipProfile.DecryptResponseAsync.
                //ParseCompact's own oversize rejection is ArgumentException (a caller-contract
                //violation, not a wire-shape one), so the bound is checked here and raised as
                //FormatException to route through this method's own Malformed catch below.
                if(action.EncryptedResponseJwt.Length > JweParsing.MaxCompactJweByteCount)
                {
                    throw new FormatException(
                        $"The response JWE exceeds the {JweParsing.MaxCompactJweByteCount}-byte " +
                        "compact-serialization bound.");
                }

                if(useRegistry)
                {
                    //Peek enc from the JWE header before any cryptographic operation.
                    //This is an early validation — not yet authenticated. The header is
                    //authenticated by AES-GCM tag verification inside DecryptAsync.
                    int firstDot = action.EncryptedResponseJwt.IndexOf(
                        '.', StringComparison.Ordinal);

                    if(firstDot < 0)
                    {
                        throw new FormatException(
                            "Compact JWE must contain at least one dot-separated segment.");
                    }

                    using IMemoryOwner<byte> headerBytes = decoder(
                        action.EncryptedResponseJwt.AsSpan(0, firstDot).ToString(), pool);

                    string? enc = JwkJsonReader.ExtractStringValue(
                        headerBytes.Memory.Span, "enc"u8);

                    if(enc is null)
                    {
                        throw new FormatException(
                            "JWE protected header does not contain the 'enc' parameter.");
                    }

                    bool encAllowed = false;
                    foreach(string allowed in action.AllowedEncAlgorithms)
                    {
                        if(string.Equals(enc, allowed, StringComparison.Ordinal))
                        {
                            encAllowed = true;
                            break;
                        }
                    }

                    if(!encAllowed)
                    {
                        throw new FormatException(
                            $"JWE 'enc' value '{enc}' is not in the advertised " +
                            $"encrypted_response_enc_values_supported list.");
                    }

                    using AeadMessage message = JweParsing.ParseCompact(
                        action.EncryptedResponseJwt,
                        WellKnownJweAlgorithms.EcdhEs,
                        enc,
                        decoder,
                        pool);

                    decrypted = await message.DecryptAsync(
                        decryptionKey, pool, ct).ConfigureAwait(false);
                }
                else
                {
                    decrypted = await HaipProfile.DecryptResponseAsync(
                        compactJwe: action.EncryptedResponseJwt,
                        ephemeralPrivateKey: decryptionKey,
                        allowedEncAlgorithms: action.AllowedEncAlgorithms,
                        decoder: decoder,
                        keyAgreementDecryptDelegate: keyAgreementDecryptDelegate,
                        keyDerivationDelegate: keyDerivationDelegate,
                        aeadDecryptDelegate: aeadDecryptDelegate,
                        pool: pool,
                        cancellationToken: ct).ConfigureAwait(false);
                }

                using DecryptedContent ownedDecrypted = decrypted;

                //OID4VP 1.0 §8.3.1: the direct_post.jwt JWE plaintext is the response JWT
                //payload carrying the Authorization Response parameters as NAMED CLAIMS, so
                //the §8.1 DCQL-keyed vp_token object is under the "vp_token" claim — not at
                //the top level of the decrypted plaintext. Extract it once; every
                //per-credential presentation is read from this nested object.
                vpTokenObjectJson =
                    JwkJsonReader.ExtractObjectAsString(ownedDecrypted.AsReadOnlySpan(), "vp_token"u8)
                    ?? throw new FormatException(
                        "The decrypted direct_post.jwt response carries no 'vp_token' claim; per " +
                        "OID4VP 1.0 §8.3.1 the response JWT payload must be {\"vp_token\": {...}, \"state\": ...}.");
            }
            catch(FormatException exception)
            {
                DateTimeOffset malformedAt = context.VerifiedAt
                    ?? throw new InvalidOperationException(
                        "Request timestamp not found in context.");

                return new VerifierPresentationRefused(
                    VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed),
                    $"Malformed direct_post.jwt Authorization Response: {exception.Message}",
                    malformedAt);
            }

            //Pool the vp_token object bytes (no naked byte[]). The owner is held across
            //the per-credential await loop; each read takes a fresh span off the Memory.
            using IMemoryOwner<byte> vpTokenObjectOwner =
                pool.Rent(Encoding.UTF8.GetByteCount(vpTokenObjectJson));
            int vpTokenObjectLength =
                Encoding.UTF8.GetBytes(vpTokenObjectJson, vpTokenObjectOwner.Memory.Span);
            ReadOnlyMemory<byte> vpTokenObject = vpTokenObjectOwner.Memory[..vpTokenObjectLength];

            context.SetTransactionNonce(action.Nonce);

            ClientRecord registration = context.ClientRegistration
                ?? throw new InvalidOperationException(
                    "Client registration not found in context.");

            TenantId tenantId = context.TenantId
                ?? throw new InvalidOperationException(
                    "Tenant identifier not found in context.");

            DateTimeOffset now = server.TimeProvider.GetUtcNow();

            //OID4VP 1.0 §8.4 — when the Verifier sent transaction_data, recompute
            //the expected hashes and surface them on the validation context so
            //ValidationChecks.CheckKbJwtTransactionDataHashes can compare against
            //the KB-JWT echo. Computed once and reused across per-credential
            //validation contexts.
            IReadOnlyList<string>? expectedTransactionDataHashes = null;
            if(action.TransactionData is { Count: > 0 } txData)
            {
                expectedTransactionDataHashes =
                    await TransactionDataHasher.ComputeSha256Async(
                        txData,
                        oauth.Codecs.Encoder!,
                        pool,
                        ct).ConfigureAwait(false);
            }

            //OID4VP 1.0 §8.1: vp_token is a JSON object whose keys are DCQL
            //credential query identifiers and whose values are arrays of one
            //or more compact presentations. Multi-credential presentations
            //carry several entries; single-credential is the trivial case
            //with one entry. The handler extracts and verifies each in turn
            //and aggregates the verified credentials keyed by credential query id.
            Dictionary<CredentialQueryId, VpCredentialClaims> aggregatedCredentials = new();

            //IETF Token Status List outcomes per credential, keyed by DCQL credential query id.
            //Populated only when a status resolver was wired AND the credential carried a
            //status.status_list reference; surfaced on VerificationSucceeded so the relying party
            //can act on revocation/suspension without re-parsing the verified vp_token.
            Dictionary<CredentialQueryId, CredentialStatusOutcome> credentialStatuses = new();

            //OID4VP 1.0 Appendix B.2.6.1: an mso_mdoc presentation's SessionTranscript
            //binds the wallet's fresh mdoc_generated_nonce, which the wallet carries in
            //the response JWE's 'apu' protected-header parameter (ISO/IEC 18013-7 §B.4.4).
            //Recover it once here from the same compact JWE the decrypt step consumed; the
            //per-credential mdoc branch reconstructs the transcript from it. SD-JWT-only
            //responses carry no mso_mdoc query and skip this entirely.
            //
            //Wallet-attributable malformed-response detection: an mso_mdoc response whose encrypted
            //JWE protected header carries no 'apu' (the wallet's mdoc_generated_nonce) is a shape no
            //conformant Wallet would produce — Malformed, not a 500 fault. Only FormatException —
            //ExtractMdocGeneratedNonce's own parse-exception type — is targeted; the mdocSeams-is-null
            //InvalidOperationException it also throws is a configuration fault and stays on the fault path.
            IMemoryOwner<byte>? mdocGeneratedNonce = null;
            if(action.CredentialQueries.Any(static q =>
                string.Equals(q.Format, DcqlCredentialFormats.MsoMdoc, StringComparison.Ordinal)))
            {
                try
                {
                    mdocGeneratedNonce = ExtractMdocGeneratedNonce(
                        action.EncryptedResponseJwt, mdocSeams, decoder, pool);
                }
                catch(FormatException exception)
                {
                    DateTimeOffset malformedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    return new VerifierPresentationRefused(
                        VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed),
                        $"Malformed direct_post.jwt Authorization Response: {exception.Message}",
                        malformedAt);
                }
            }

            //Scopes mdocGeneratedNonce's disposal to the remainder of this handler, the same lifetime
            //the prior using declaration gave it — the extraction above runs inside a try block, so it
            //cannot itself be a using initializer.
            using IMemoryOwner<byte>? mdocGeneratedNonceScope = mdocGeneratedNonce;

            foreach(CredentialQuery credentialQuery in action.CredentialQueries)
            {
                //A DCQL credential query id that fails OID4VP 1.0 §6.1 is a shape no conformant
                //Authorization Request would carry (the request is the Verifier's own, but a
                //malformed id reaching this far is still never a wire answer to fabricate) —
                //Malformed, the same classification a malformed vp_token presentation gets below.
                if(!CredentialQueryId.TryCreate(credentialQuery.Id, out CredentialQueryId? credentialQueryId))
                {
                    DateTimeOffset malformedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    return new VerifierPresentationRefused(
                        VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed),
                        $"DCQL credential query carries an id that is not a valid OID4VP 1.0 §6.1 " +
                        $"identifier: '{credentialQuery.Id}'.",
                        malformedAt);
                }

                //OID4VP 1.0 §8.1 keys the vp_token object by the credential query id, so every
                //presentation lookup in this iteration searches for the same member name. The UTF-8
                //bytes of that name are encoded once per credential query rather than once per lookup.
                byte[] credentialQueryIdUtf8 = Encoding.UTF8.GetBytes(credentialQueryId.Value);

                //Multi-format dispatch: the parse step differs per DCQL Format (SD-JWT
                //KB-JWT vs mdoc DeviceResponse), but the validate step below is uniform —
                //each format's VpTokenParsed flows through the format-keyed ClaimIssuer, so
                //every credential is checked on the same pipeline. A format with no
                //registered validator is a verifier-capability error.
                if(credentialQuery.Format is not { } credentialFormat
                    || !vpValidators.TryGetValue(credentialFormat, out ClaimIssuer<ValidationContext>? formatValidator))
                {
                    throw new NotSupportedException(
                        $"VP-token verification for credential format '{credentialQuery.Format}' is not wired " +
                        $"(credential query '{credentialQueryId}'); no validator is registered for that format.");
                }

                VpTokenParsed parsed;

                //The mdoc trust delegate transfers ownership of the key it resolves, and that key has to
                //outlive the parse: the credential-status step below reads it as the Referenced Token's
                //issuer key. The resolution is therefore held here and released at the end of this
                //credential's step, which is what keeps VpTokenParsed.CredentialIssuerKey a borrowed
                //reference. The other two formats resolve through borrow-only seams and hand back nothing.
                MdocVpVerificationResult? mdocResult = null;

                //Wallet-attributable malformed-presentation detection: a vp_token whose credential-query
                //array is missing or empty, or an unparseable SD-JWT/KB-JWT/mdoc/SD-CWT presentation, is a
                //shape no conformant Wallet would produce — Malformed, not a 500 fault. The per-format
                //VerifyAsync calls throw many exception types for many reasons (a wrong issuer key, a bad
                //signature); only FormatException — the library's own parse-exception type, thrown directly
                //by the two extraction calls in this block — is targeted here, so a non-format failure deep
                //in a format verifier is left on the fault path rather than mis-attributed to the Wallet.
                try
                {
                    if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.SdJwt, StringComparison.Ordinal))
                    {
                        string compactPresentation =
                            JwkJsonReader.ExtractFirstStringFromArrayProperty(
                                vpTokenObject.Span,
                                credentialQueryIdUtf8)
                            ?? throw new FormatException(
                                $"vp_token does not contain a non-empty array of presentations " +
                                $"under credential query identifier '{credentialQueryId}'.");

                        parsed = await SdJwtVpTokenVerification.VerifyAsync(
                            compactPresentation, credentialQueryId, parseSdJwtToken, computeSdJwtHashInput,
                            resolveIssuerKey, computeDigest, decoder, encoder, pool, saltReuseSeam, ct,
                            parseX5c, resolveTrustedAuthorityEvidence)
                            .ConfigureAwait(false);
                    }
                    else if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.MsoMdoc, StringComparison.Ordinal))
                    {
                        //client_id / response_uri / nonce are the verifier's own JAR inputs from
                        //persisted state; response_uri must be the byte-exact OriginalString the
                        //JAR emitted (the codebase serialises URIs via Uri.OriginalString) so the
                        //reconstructed transcript hashes identically to the wallet's.
                        string responseUri = registration.ResponseUri?.OriginalString
                            ?? throw new InvalidOperationException(
                                $"ClientRecord for the flow has no ResponseUri; it is required to reconstruct " +
                                $"the mdoc SessionTranscript for credential query '{credentialQueryId}'.");

                        string compactPresentation =
                            JwkJsonReader.ExtractFirstStringFromArrayProperty(
                                vpTokenObject.Span,
                                credentialQueryIdUtf8)
                            ?? throw new FormatException(
                                $"vp_token does not contain a non-empty array of presentations " +
                                $"under credential query identifier '{credentialQueryId}'.");

                        //mdocGeneratedNonce is non-null here: ExtractMdocGeneratedNonce ran above
                        //because this response carries an mso_mdoc query, and it also asserted the
                        //mdoc seams were supplied.
                        mdocResult = await MdocVpTokenVerification.VerifyAsync(
                            compactPresentation, credentialQueryId, mdocSeams!.ResolveIssuerKey,
                            mdocSeams.ExtractTrustedAuthorityEvidence,
                            registration.ClientId, responseUri, action.Nonce.Value, mdocGeneratedNonce!.Memory,
                            mdocSeams.ParseDeviceResponse, mdocSeams.EncodeSessionTranscript, mdocSeams.DecodeElementValue,
                            mdocSeams.ParseCoseSign1, mdocSeams.ParseCoseSign1AllowingNilPayload,
                            mdocSeams.EncodeDeviceAuthenticationBytes, mdocSeams.BuildSigStructure,
                            decoder, pool, ct).ConfigureAwait(false);
                        parsed = mdocResult.Parsed;
                    }
                    else if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.SdCwt, StringComparison.Ordinal))
                    {
                        SdCwtVpVerificationSeams seams = sdCwtSeams
                            ?? throw new InvalidOperationException(
                                "The vp_token contains a dc+sd-cwt credential query but the executor was " +
                                "constructed without SD-CWT verification seams. Pass SdCwtVpVerificationSeams to " +
                                "HaipOid4VpVerifierExecutor.Create / CreateWithRegistry to enable dc+sd-cwt verification.");

                        string compactPresentation =
                            JwkJsonReader.ExtractFirstStringFromArrayProperty(
                                vpTokenObject.Span,
                                credentialQueryIdUtf8)
                            ?? throw new FormatException(
                                $"vp_token does not contain a non-empty array of presentations " +
                                $"under credential query identifier '{credentialQueryId}'.");

                        parsed = await SdCwtVpTokenVerification.VerifyAsync(
                            compactPresentation, credentialQueryId, seams, decoder, saltReuseSeam, pool, ct)
                            .ConfigureAwait(false);
                    }
                    else
                    {
                        throw new NotSupportedException(
                            $"VP-token verification for credential format '{credentialQuery.Format}' is not yet " +
                            $"supported (credential query '{credentialQueryId}').");
                    }
                }
                catch(FormatException exception)
                {
                    DateTimeOffset malformedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    return new VerifierPresentationRefused(
                        VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed),
                        $"Malformed vp_token presentation for credential query '{credentialQueryId}': {exception.Message}",
                        malformedAt);
                }

                //Scopes the mdoc trust resolution's disposal to the remainder of this credential's step —
                //the assignment above runs inside a try block, so it cannot itself be a using initializer.
                //Every exit from here on, refusal returns included, releases the resolved key.
                using MdocVpVerificationResult? mdocResultScope = mdocResult;

                (bool dcqlSatisfied, bool dcqlOverDisclosed) = await AssessDcqlAsync(
                    assessDisclosure, credentialQuery, parsed, ct).ConfigureAwait(false);

                ValidationContext validationContext = new()
                {
                    Context = context,
                    Now = now,
                    ExpectedNonce = action.Nonce.Value,
                    ExpectedClientId = registration.ClientId,
                    KbJwtNonce = parsed.KbJwtNonce,
                    KbJwtAud = parsed.KbJwtAud,
                    KbJwtIat = parsed.KbJwtIat,
                    KbJwtSignatureValid = parsed.KbJwtSignatureValid,
                    CredentialSignatureValid = parsed.CredentialSignatureValid,
                    SdHashValid = parsed.SdHashValid,
                    SessionTranscriptValid = parsed.SessionTranscriptValid,
                    KbJwtTransactionDataHashes = parsed.KbJwtTransactionDataHashes,
                    ExpectedTransactionDataHashes = expectedTransactionDataHashes,
                    DcqlSatisfied = dcqlSatisfied,
                    DcqlOverDisclosed = dcqlOverDisclosed,
                    MinimumDisclosureSaltLengthBytes = parsed.MinimumDisclosureSaltLengthBytes,
                    SaltReused = parsed.SaltReused,
                    CredentialTypePresent = parsed.Credential.CredentialType is not null,
                };

                ClaimIssueResult verificationResult = await formatValidator.GenerateClaimsAsync(
                    validationContext, tenantId.Value, ct).ConfigureAwait(false);

                context.AddValidationResult(verificationResult);

                if(!verificationResult.IsComplete
                    || verificationResult.Claims.Any(static c => c.Outcome != ClaimOutcome.Success))
                {
                    DateTimeOffset failedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    //The presentation did not satisfy the Authorization Request's DCQL query (type, claims,
                    //over-disclosure or an unmet trusted_authorities constraint) — an unverifiable presentation,
                    //RFC 6749 §4.1.2.1 invalid_request.
                    return new VerifierPresentationRefused(
                        VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable),
                        $"VP token verification failed for credential query '{credentialQueryId}'.",
                        failedAt);
                }

                //The credential's signature and holder binding verified above; now read its IETF Token
                //Status List entry (the "is it still valid now?" step) when a resolver was wired and the
                //credential references a status list. VpTokenCredentialStatus.CheckAsync either records the
                //determinable outcome, finds nothing to check, or fails closed on an undeterminable status.
                CredentialStatusCheck statusCheck = await VpTokenCredentialStatus.CheckAsync(
                    parsed, credentialQueryId, resolveVerifiedStatusListToken, now,
                    statusListFreshnessPolicy, statusListCachingBounds, unsupportedStatusMechanisms, ct)
                    .ConfigureAwait(false);

                if(statusCheck.Kind == CredentialStatusCheckKind.Undeterminable)
                {
                    DateTimeOffset statusFailedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    return new VerifierPresentationRefused(
                        statusCheck.Refusal!.Value, statusCheck.LogReason!, statusFailedAt);
                }

                if(statusCheck.Kind == CredentialStatusCheckKind.Determined)
                {
                    credentialStatuses[credentialQueryId] = statusCheck.Outcome!;
                }

                //Multi-credential vp_token: record this credential under its own query id.
                //parsed.CredentialQueryId is the same id the caller minted above, by construction.
                aggregatedCredentials[credentialQueryId] = parsed.Credential;
            }

            DateTimeOffset verifiedAt = context.VerifiedAt
                ?? throw new InvalidOperationException(
                    "Request timestamp not found in context.");

            if(ApplyCredentialStatusPolicy(statusPolicy, credentialStatuses, verifiedAt) is { } policyRefusal)
            {
                return policyRefusal;
            }

            return new VerificationSucceeded(
                aggregatedCredentials,
                VerifiedAt: verifiedAt,
                RedirectUri: context.Oid4VpRedirectUri)
            {
                CredentialStatuses = credentialStatuses.Count > 0 ? credentialStatuses : null
            };
        });

        //Sibling handler for the unencrypted direct_post path per OID4VP 1.0
        //§8.2. Same verification pipeline as DecryptResponseAction above; the
        //only structural difference is the source of vp_token bytes — the
        //wallet POSTed them plaintext rather than wrapping them in a JWE so
        //the handler skips the JWE parse / decrypt / enc-allowlist gate.
        executor.Register<ProcessVpTokenAction>(async (action, context, ct) =>
        {
            EndpointServer server = context.Server!;
            var oauth = server.OAuth();

            context.SetTransactionNonce(action.Nonce);

            ClientRecord registration = context.ClientRegistration
                ?? throw new InvalidOperationException(
                    "Client registration not found in context.");

            TenantId tenantId = context.TenantId
                ?? throw new InvalidOperationException(
                    "Tenant identifier not found in context.");

            DateTimeOffset now = server.TimeProvider.GetUtcNow();

            IReadOnlyList<string>? expectedTransactionDataHashes = null;
            if(action.TransactionData is { Count: > 0 } txData)
            {
                expectedTransactionDataHashes =
                    await TransactionDataHasher.ComputeSha256Async(
                        txData,
                        oauth.Codecs.Encoder!,
                        pool,
                        ct).ConfigureAwait(false);
            }

            //OID4VP 1.0 §8.1: vp_token is a JSON object whose keys are DCQL
            //credential query identifiers and whose values are arrays of one
            //or more compact presentations. Multi-credential parity with the
            //encrypted-path handler above — extract, verify, aggregate. The
            //vp_token bytes are plaintext (no JWE), so they're materialised
            //once into a byte[] and re-scanned per credential query id.
            byte[] vpTokenBytes = Encoding.UTF8.GetBytes(action.VpTokenJson);

            Dictionary<CredentialQueryId, VpCredentialClaims> aggregatedCredentials = new();

            //IETF Token Status List outcomes per credential (see the encrypted-path handler above).
            Dictionary<CredentialQueryId, CredentialStatusOutcome> credentialStatuses = new();

            foreach(CredentialQuery credentialQuery in action.CredentialQueries)
            {
                //A DCQL credential query id that fails OID4VP 1.0 §6.1 is a shape no conformant
                //Authorization Request would carry — Malformed, the same classification a
                //malformed vp_token presentation gets below.
                if(!CredentialQueryId.TryCreate(credentialQuery.Id, out CredentialQueryId? credentialQueryId))
                {
                    DateTimeOffset malformedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    return new VerifierPresentationRefused(
                        VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed),
                        $"DCQL credential query carries an id that is not a valid OID4VP 1.0 §6.1 " +
                        $"identifier: '{credentialQuery.Id}'.",
                        malformedAt);
                }

                //OID4VP 1.0 §8.1 keys the vp_token object by the credential query id, so every
                //presentation lookup in this iteration searches for the same member name. The UTF-8
                //bytes of that name are encoded once per credential query rather than once per lookup.
                byte[] credentialQueryIdUtf8 = Encoding.UTF8.GetBytes(credentialQueryId.Value);

                //mso_mdoc has no plaintext direct_post representation: its SessionTranscript
                //binds the wallet's mdoc_generated_nonce, carried only in an encrypted
                //response's JWE 'apu' header. HAIP never sends plaintext mdoc, so reject it
                //here rather than silently mis-binding.
                if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.MsoMdoc, StringComparison.Ordinal))
                {
                    throw new NotSupportedException(
                        $"mso_mdoc verification requires an encrypted response (direct_post.jwt); the wallet's " +
                        $"mdoc_generated_nonce is carried in the JWE 'apu' header and is absent from a plaintext " +
                        $"direct_post body (credential query '{credentialQueryId}').");
                }

                //Multi-format dispatch through the format-keyed ClaimIssuer — the same
                //pipeline as the encrypted path. Only dc+sd-jwt has a parse branch on the
                //plaintext path today.
                if(credentialQuery.Format is not { } credentialFormat
                    || !vpValidators.TryGetValue(credentialFormat, out ClaimIssuer<ValidationContext>? formatValidator))
                {
                    throw new NotSupportedException(
                        $"VP-token verification for credential format '{credentialQuery.Format}' is not wired " +
                        $"(credential query '{credentialQueryId}'); no validator is registered for that format.");
                }

                VpTokenParsed parsed;

                //Wallet-attributable malformed-presentation detection (see the encrypted-path handler
                //above): a missing/empty credential-query array or an unparseable SD-JWT/KB-JWT/SD-CWT
                //presentation is a shape no conformant Wallet would produce — Malformed, not a 500 fault.
                //Only FormatException is targeted; a non-format failure deep in a format verifier is left
                //on the fault path.
                try
                {
                    string compactPresentation =
                        JwkJsonReader.ExtractFirstStringFromArrayProperty(
                            vpTokenBytes, credentialQueryIdUtf8)
                        ?? throw new FormatException(
                            $"vp_token does not contain a non-empty array of presentations " +
                            $"under credential query identifier '{credentialQueryId}'.");

                    if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.SdJwt, StringComparison.Ordinal))
                    {
                        parsed = await SdJwtVpTokenVerification.VerifyAsync(
                            compactPresentation, credentialQueryId, parseSdJwtToken, computeSdJwtHashInput,
                            resolveIssuerKey, computeDigest, decoder, encoder, pool, saltReuseSeam, ct,
                            parseX5c, resolveTrustedAuthorityEvidence)
                            .ConfigureAwait(false);
                    }
                    else if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.SdCwt, StringComparison.Ordinal))
                    {
                        SdCwtVpVerificationSeams seams = sdCwtSeams
                            ?? throw new InvalidOperationException(
                                "The vp_token contains a dc+sd-cwt credential query but the executor was " +
                                "constructed without SD-CWT verification seams. Pass SdCwtVpVerificationSeams to " +
                                "HaipOid4VpVerifierExecutor.Create / CreateWithRegistry to enable dc+sd-cwt verification.");

                        parsed = await SdCwtVpTokenVerification.VerifyAsync(
                            compactPresentation, credentialQueryId, seams, decoder, saltReuseSeam, pool, ct)
                            .ConfigureAwait(false);
                    }
                    else
                    {
                        throw new NotSupportedException(
                            $"VP-token verification for credential format '{credentialQuery.Format}' is not yet " +
                            $"supported on the unencrypted direct_post path (credential query '{credentialQueryId}').");
                    }
                }
                catch(FormatException exception)
                {
                    DateTimeOffset malformedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    return new VerifierPresentationRefused(
                        VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed),
                        $"Malformed vp_token presentation for credential query '{credentialQueryId}': {exception.Message}",
                        malformedAt);
                }

                (bool dcqlSatisfied, bool dcqlOverDisclosed) = await AssessDcqlAsync(
                    assessDisclosure, credentialQuery, parsed, ct).ConfigureAwait(false);

                ValidationContext validationContext = new()
                {
                    Context = context,
                    Now = now,
                    ExpectedNonce = action.Nonce.Value,
                    ExpectedClientId = registration.ClientId,
                    KbJwtNonce = parsed.KbJwtNonce,
                    KbJwtAud = parsed.KbJwtAud,
                    KbJwtIat = parsed.KbJwtIat,
                    KbJwtSignatureValid = parsed.KbJwtSignatureValid,
                    CredentialSignatureValid = parsed.CredentialSignatureValid,
                    SdHashValid = parsed.SdHashValid,
                    SessionTranscriptValid = parsed.SessionTranscriptValid,
                    KbJwtTransactionDataHashes = parsed.KbJwtTransactionDataHashes,
                    ExpectedTransactionDataHashes = expectedTransactionDataHashes,
                    DcqlSatisfied = dcqlSatisfied,
                    DcqlOverDisclosed = dcqlOverDisclosed,
                    MinimumDisclosureSaltLengthBytes = parsed.MinimumDisclosureSaltLengthBytes,
                    SaltReused = parsed.SaltReused,
                    CredentialTypePresent = parsed.Credential.CredentialType is not null,
                };

                ClaimIssueResult verificationResult = await formatValidator.GenerateClaimsAsync(
                    validationContext, tenantId.Value, ct).ConfigureAwait(false);

                context.AddValidationResult(verificationResult);

                if(!verificationResult.IsComplete
                    || verificationResult.Claims.Any(static c => c.Outcome != ClaimOutcome.Success))
                {
                    DateTimeOffset failedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    //The presentation did not satisfy the Authorization Request's DCQL query (type, claims,
                    //over-disclosure or an unmet trusted_authorities constraint) — an unverifiable presentation,
                    //RFC 6749 §4.1.2.1 invalid_request.
                    return new VerifierPresentationRefused(
                        VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable),
                        $"VP token verification failed for credential query '{credentialQueryId}'.",
                        failedAt);
                }

                //IETF Token Status List check (see the encrypted-path handler) — read the credential's status
                //when a resolver is wired; fail closed on an undeterminable one.
                CredentialStatusCheck statusCheck = await VpTokenCredentialStatus.CheckAsync(
                    parsed, credentialQueryId, resolveVerifiedStatusListToken, now,
                    statusListFreshnessPolicy, statusListCachingBounds, unsupportedStatusMechanisms, ct)
                    .ConfigureAwait(false);

                if(statusCheck.Kind == CredentialStatusCheckKind.Undeterminable)
                {
                    DateTimeOffset statusFailedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    return new VerifierPresentationRefused(
                        statusCheck.Refusal!.Value, statusCheck.LogReason!, statusFailedAt);
                }

                if(statusCheck.Kind == CredentialStatusCheckKind.Determined)
                {
                    credentialStatuses[credentialQueryId] = statusCheck.Outcome!;
                }

                aggregatedCredentials[credentialQueryId] = parsed.Credential;
            }

            DateTimeOffset verifiedAt = context.VerifiedAt
                ?? throw new InvalidOperationException(
                    "Request timestamp not found in context.");

            if(ApplyCredentialStatusPolicy(statusPolicy, credentialStatuses, verifiedAt) is { } policyRefusal)
            {
                return policyRefusal;
            }

            return new VerificationSucceeded(
                aggregatedCredentials,
                VerifiedAt: verifiedAt,
                RedirectUri: context.Oid4VpRedirectUri)
            {
                CredentialStatuses = credentialStatuses.Count > 0 ? credentialStatuses : null
            };
        });

        return executor;
    }


    /// <summary>
    /// Recovers the wallet's <c>mdoc_generated_nonce</c> from the
    /// <c>apu</c> protected-header parameter of the response JWE per
    /// <see href="https://www.iso.org/standard/82772.html">ISO/IEC 18013-7 §B.4.4</see>
    /// and OID4VP 1.0 Appendix B.2.6.1. Called only when the response carries an
    /// <c>mso_mdoc</c> credential query; doubles as the guard that the executor was
    /// constructed with mdoc verification seams.
    /// </summary>
    //Verifier-side DCQL satisfaction + no-over-disclosure, derived by dropping out
    //to the application-wired disclosure engine — the mirror of the wallet's
    //ProduceVpTokenPresentations seam. Behind AssessVpDisclosureDelegate the
    //application runs DcqlDisclosure.ComputeStrategyAsync over the disclosed claims
    //and returns graph.Satisfied (-> DcqlSatisfied) and whether any disclosed path
    //fell outside the engine's selected set (-> DcqlOverDisclosed). The library does
    //not run the engine itself. A query with no specific claims requests the whole
    //credential — satisfied, nothing extra — and needs no assessor. A claims-bearing
    //query with no assessor wired is a fail-closed configuration error: the
    //CheckDcqlSatisfaction / CheckNoOverDisclosure rules cannot be honoured.
    private static async ValueTask<(bool Satisfied, bool OverDisclosed)> AssessDcqlAsync(
        AssessVpDisclosureDelegate? assessDisclosure,
        CredentialQuery credentialQuery,
        VpTokenParsed parsed,
        CancellationToken cancellationToken)
    {
        if(credentialQuery.Claims is not { Count: > 0 })
        {
            return (Satisfied: true, OverDisclosed: false);
        }

        if(assessDisclosure is null)
        {
            throw new InvalidOperationException(
                "A DCQL credential query requests specific claims but the verifier executor was " +
                "constructed without a disclosure assessor. Pass assessDisclosure to " +
                "HaipOid4VpVerifierExecutor.Create / CreateWithRegistry (wiring DcqlDisclosure behind it) " +
                "to enable DCQL satisfaction / no-over-disclosure enforcement.");
        }

        Oid4VpDisclosureAssessment assessment = await assessDisclosure(
            new Oid4VpDisclosureAssessmentContext
            {
                CredentialQuery = credentialQuery,
                Credential = parsed.Credential
            },
            cancellationToken).ConfigureAwait(false);

        return (assessment.Satisfied, assessment.OverDisclosed);
    }


    /// <summary>
    /// Applies <paramref name="credentialStatusPolicy"/> once over the complete
    /// <paramref name="credentialStatuses"/> map, after every presented credential in this response has
    /// already verified. SD-JWT VC -18: "Verifier policy decides whether to reject or accept a presentation
    /// of a SD-JWT VC based on the status of the Verifiable Digital Credential." Skipped entirely when the
    /// map is empty — nothing was surfaced to judge.
    /// </summary>
    /// <returns>
    /// A <see cref="VerifierPresentationRefused"/> carrying <see cref="VerifierFlowRefusalKind.PolicyRefused"/>
    /// and the policy's typed <see cref="CredentialStatusRefusal"/> when the policy refuses; otherwise
    /// <see langword="null"/> to let the presentation stand.
    /// </returns>
    private static VerifierPresentationRefused? ApplyCredentialStatusPolicy(
        CredentialStatusPolicy credentialStatusPolicy,
        Dictionary<CredentialQueryId, CredentialStatusOutcome> credentialStatuses,
        DateTimeOffset failedAt)
    {
        if(credentialStatuses.Count == 0)
        {
            return null;
        }

        CredentialStatusRefusal? refusal = credentialStatusPolicy(credentialStatuses);
        if(refusal is null)
        {
            return null;
        }

        return new VerifierPresentationRefused(
            VerifierFlowRefusal.For(VerifierFlowRefusalKind.PolicyRefused),
            refusal.Description,
            failedAt)
        {
            CredentialStatusRefusal = refusal
        };
    }


    private static IMemoryOwner<byte> ExtractMdocGeneratedNonce(
        string encryptedResponseJwt,
        MdocVpVerificationSeams? mdocSeams,
        DecodeDelegate decoder,
        BaseMemoryPool pool)
    {
        if(mdocSeams is null)
        {
            throw new InvalidOperationException(
                "The vp_token contains an mso_mdoc credential query but the executor was " +
                "constructed without mdoc verification seams. Pass MdocVpVerificationSeams to " +
                "HaipOid4VpVerifierExecutor.Create / CreateWithRegistry to enable mso_mdoc verification.");
        }

        int firstDot = encryptedResponseJwt.IndexOf('.', StringComparison.Ordinal);
        if(firstDot < 0)
        {
            throw new FormatException(
                "Compact JWE must contain at least one dot-separated segment to carry the 'apu' header.");
        }

        using IMemoryOwner<byte> headerBytes = decoder(
            encryptedResponseJwt.AsSpan(0, firstDot).ToString(), pool);

        string apu = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "apu"u8)
            ?? throw new FormatException(
                "An mso_mdoc Authorization Response JWE must carry the wallet's mdoc_generated_nonce " +
                "in the 'apu' protected-header parameter per ISO/IEC 18013-7 §B.4.4; none was present.");

        return decoder(apu, pool);
    }
}
