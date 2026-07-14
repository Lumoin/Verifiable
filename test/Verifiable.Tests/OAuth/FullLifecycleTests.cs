using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Server.Routing;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The full life of one credential, in one test, with every feature this branch built doing
/// real work in sequence: Credential Offer → Pre-Authorized Code grant → Nonce Endpoint →
/// encrypted Credential Request with a verified holder key proof → §8.3 deferral → encrypted
/// Deferred delivery of a genuinely issued SD-JWT VC → Notification — then presentation of
/// that same credential with a KB-JWT plus a SIOPv2 Self-Issued ID Token bound to one verifier
/// transaction — then RFC 9701 signed introspection of the access token that drove issuance.
/// Each step consumes the previous step's real output; nothing is stubbed past the seams the
/// application owns in production.
/// </summary>
[TestClass]
internal sealed class FullLifecycleTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string WalletClientId = "https://wallet.client.test";
    private static readonly Uri WalletBaseUri = new("https://wallet.client.test");
    private const string EndUserSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "eu.europa.ec.eudi.pid.1";
    private const string PreAuthorizedCode = "SplxlOBeZQQYbYS6WxSbIA";
    private const string TransactionId = "8xLOxBtZp8";
    private const string NotificationIdValue = "3fwe98js";

    private const string VerifierClientId = "https://verifier.example.com";
    private const string VerifierNonce = "n-presentation-01";

    private const string SdJwtIssuerId = "https://issuer.example.com";
    private const string SdJwtIssuerKeyId = "did:web:issuer.example.com#key-1";

    private static readonly ImmutableHashSet<CapabilityIdentifier> AllIssuerCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint,
            WellKnownCapabilityIdentifiers.OAuthTokenIntrospection);

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task OneCredentialLivesThroughIssuancePresentationAndIntrospection()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            WalletClientId, WalletBaseUri, PolicyProfile.Rfc6749WithPkce, AllIssuerCapabilities);
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." This lifecycle mints a plain-bearer credential token;
        //keep it within the long-lived threshold (lifetimes longer than 5 minutes are long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));
        //RFC 9701: the introspection response is signed with a dedicated usage slot.
        host.UpdateSigningKeys(
            material.Registration.TenantId.Value,
            material.Registration.SigningKeys.ToImmutableDictionary().Add(
                KeyUsageContext.IntrospectionResponseSigning,
                new SigningKeySet { Current = [material.SigningKeyId] }));
        string tenant = material.Registration.TenantId.Value;

        //=== The wallet's long-lived key material. ===
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var responseEncryptionKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory encryptionPublic = responseEncryptionKeys.PublicKey;
        using PrivateKeyMemory encryptionPrivate = responseEncryptionKeys.PrivateKey;

        //=== The issuer's request-decryption key: §8.2 requires a request carrying
        //credential_response_encryption to itself be encrypted, so the wallet wraps each request
        //to this key (advertised via credential_request_encryption.jwks in a real deployment). ===
        var requestEncryptionKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory requestEncryptionPublic = requestEncryptionKeys.PublicKey;
        using PrivateKeyMemory requestEncryptionPrivate = requestEncryptionKeys.PrivateKey;

        //=== The issuer's SD-JWT VC signing key (the credential issuer trust root). ===
        var sdJwtIssuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory sdJwtIssuerPublic = sdJwtIssuerKeys.PublicKey;
        using PrivateKeyMemory sdJwtIssuerPrivate = sdJwtIssuerKeys.PrivateKey;

        WireIssuerSeams(host, sdJwtIssuerPrivate, out LifecycleIssuerState issuerState);
        host.Server.OAuth().DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, requestEncryptionPrivate).ConfigureAwait(false);

        //=== Act 1, step 1: the Issuer hands the Wallet a Credential Offer (§4). ===
        CredentialOffer offer = new()
        {
            CredentialIssuer = material.Registration.IssuerUri!,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode
            }
        };
        string deepLink = CredentialOfferSerializer.ToByValueDeepLink(offer);
        Assert.StartsWith("openid-credential-offer://", deepLink);

        //The wallet "scans" the deep link and reads the grant out of the offer JSON.
        string offerJson = Uri.UnescapeDataString(
            deepLink[(deepLink.IndexOf("credential_offer=", StringComparison.Ordinal) + "credential_offer=".Length)..]);
        using JsonDocument offerDoc = JsonDocument.Parse(offerJson);
        string scannedCode = offerDoc.RootElement
            .GetProperty("grants")
            .GetProperty(WellKnownGrantTypes.PreAuthorizedCode)
            .GetProperty("pre-authorized_code").GetString()!;
        Assert.AreEqual(PreAuthorizedCode, scannedCode);

        //=== Step 2: the §6 Pre-Authorized Code grant mints the access token. ===
        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            tenant, WellKnownEndpointNames.Oid4VciPreAuthorizedToken, "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = scannedCode
            },
            new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument tokenDoc = JsonDocument.Parse(tokenResponse.Body);
        string accessToken = tokenDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //=== Step 3: the §7 Nonce Endpoint issues the proof challenge. ===
        ServerHttpResponse nonceResponse = await host.DispatchAtEndpointAsync(
            tenant, WellKnownEndpointNames.Oid4VciNonce, "POST",
            new RequestFields(), new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, nonceResponse.StatusCode, nonceResponse.Body);

        using JsonDocument nonceDoc = JsonDocument.Parse(nonceResponse.Body);
        string credentialNonce = nonceDoc.RootElement.GetProperty("c_nonce").GetString()!;

        //=== Step 4: the §8 Credential Request — a SIGNED holder key proof carrying the
        //c_nonce, plus §10 response encryption — and the Issuer defers (§8.3). ===
        string proofJwt = await BuildHolderProofAsync(
            holderPrivate, holderPublic, material.Registration.IssuerUri!.OriginalString, credentialNonce)
            .ConfigureAwait(false);
        string credentialRequest = "{\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"proofs\":{\"jwt\":[\"" + proofJwt + "\"]},"
            + "\"credential_response_encryption\":{\"jwk\":" + EcJwkJson(encryptionPublic)
            + ",\"enc\":\"" + WellKnownJweEncryptionAlgorithms.A256Gcm + "\"}}";

        //§8.2: the request carries credential_response_encryption, so it MUST itself be encrypted.
        string encryptedCredentialRequest = await EncryptToIssuerAsync(
            credentialRequest, requestEncryptionPublic).ConfigureAwait(false);
        ServerHttpResponse deferred = await DispatchWithBearerAsync(
            host, tenant, WellKnownEndpointNames.Oid4VciCredential, accessToken, encryptedCredentialRequest)
            .ConfigureAwait(false);

        Assert.AreEqual(202, deferred.StatusCode, deferred.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, deferred.ContentType,
            "The §8.3 deferral must be encrypted too — §10 applies regardless of content.");

        string deferredJson = await DecryptAsync(deferred.Body, encryptionPrivate).ConfigureAwait(false);
        using JsonDocument deferredDoc = JsonDocument.Parse(deferredJson);
        string transactionId = deferredDoc.RootElement.GetProperty("transaction_id").GetString()!;
        Assert.AreEqual(TransactionId, transactionId);
        Assert.IsTrue(issuerState.IsProofVerified,
            "The issuance seam must have verified the holder proof signature and its c_nonce.");

        //=== Step 5: the §9 Deferred Credential Endpoint delivers the encrypted credential. ===
        string deferredRequest = "{\"transaction_id\":\"" + transactionId + "\","
            + "\"credential_response_encryption\":{\"jwk\":" + EcJwkJson(encryptionPublic)
            + ",\"enc\":\"" + WellKnownJweEncryptionAlgorithms.A256Gcm + "\"}}";

        //§9.1: the deferred request carries credential_response_encryption, so it too MUST be encrypted.
        string encryptedDeferredRequest = await EncryptToIssuerAsync(
            deferredRequest, requestEncryptionPublic).ConfigureAwait(false);
        ServerHttpResponse delivered = await DispatchWithBearerAsync(
            host, tenant, WellKnownEndpointNames.Oid4VciDeferredCredential, accessToken, encryptedDeferredRequest)
            .ConfigureAwait(false);

        Assert.AreEqual(200, delivered.StatusCode, delivered.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, delivered.ContentType);

        string deliveredJson = await DecryptAsync(delivered.Body, encryptionPrivate).ConfigureAwait(false);
        using JsonDocument deliveredDoc = JsonDocument.Parse(deliveredJson);
        string issuedSdJwtVc = deliveredDoc.RootElement
            .GetProperty("credentials")[0].GetProperty("credential").GetString()!;
        Assert.AreEqual(NotificationIdValue,
            deliveredDoc.RootElement.GetProperty("notification_id").GetString());

        //=== Step 6: the §11 Notification reports successful storage. ===
        ServerHttpResponse acknowledged = await DispatchWithBearerAsync(
            host, tenant, WellKnownEndpointNames.Oid4VciNotification, accessToken,
            "{\"notification_id\":\"" + NotificationIdValue + "\",\"event\":\"credential_accepted\"}")
            .ConfigureAwait(false);
        Assert.AreEqual(204, acknowledged.StatusCode, acknowledged.Body);
        Assert.AreEqual(NotificationIdValue, issuerState.AcknowledgedNotificationId,
            "The notification seam must have received the wallet's report.");

        //=== Act 2: the wallet presents the JUST-ISSUED credential to a verifier — a KB-JWT
        //presentation plus a SIOPv2 Self-Issued ID Token, both bound to one transaction. ===
        string presentation = await PresentWithKeyBindingAsync(
            issuedSdJwtVc, holderPrivate, VerifierNonce, VerifierClientId).ConfigureAwait(false);

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;
        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, VerifierClientId, VerifierNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        PublicKeyMemory? IssuerLookup(string iss) =>
            string.Equals(iss, SdJwtIssuerId, StringComparison.Ordinal) ? sdJwtIssuerPublic : null;

        VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
            presentation, "pid",
            static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestSalts.TestSaltTag),
            static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            IssuerLookup,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            saltReuseSeam: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(parsed.CredentialSignatureValid, "The issued credential must verify at the verifier.");
        Assert.IsTrue(parsed.KbJwtSignatureValid, "The KB-JWT must verify against the cnf key the ISSUER bound.");
        Assert.IsTrue(parsed.SdHashValid);
        Assert.AreEqual(VerifierNonce, parsed.KbJwtNonce);
        Assert.AreEqual(VerifierClientId, parsed.KbJwtAud);

        string[] allowedSiopAlgorithms = [WellKnownJwaValues.Es256];
        SelfIssuedIdTokenValidationResult siopResult = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, VerifierClientId, VerifierNonce, allowedSiopAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(siopResult.IsValid, "The Self-Issued ID Token must validate per SIOPv2 §11.1.");

        //=== Act 3: a resource server introspects the issuance access token — signed per
        //RFC 9701 so the verdict itself is attestable. ===
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().IntrospectTokenAsync = (token, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult
            {
                IsActive = string.Equals(token, accessToken, StringComparison.Ordinal),
                Subject = EndUserSubject,
                Scope = WellKnownScopes.OpenId
            });

        ServerHttpResponse introspection = await host.DispatchAtEndpointAsync(
            tenant, WellKnownEndpointNames.AuthCodeIntrospect, "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = accessToken },
            new RequestHeaders(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [WellKnownHttpHeaderNames.Accept] = [WellKnownMediaTypes.Application.TokenIntrospectionJwt]
            }),
            new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, introspection.StatusCode, introspection.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.TokenIntrospectionJwt, introspection.ContentType);

        bool isIntrospectionSignatureValid = await Jws.VerifyAsync(
            introspection.Body, TestSetup.Base64UrlDecoder,
            Pool,
            material.SigningPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isIntrospectionSignatureValid);

        string introspectionPayload = DecodeSegment(introspection.Body, segmentIndex: 1);
        using JsonDocument introspectionDoc = JsonDocument.Parse(introspectionPayload);
        JsonElement verdict = introspectionDoc.RootElement.GetProperty("token_introspection");
        Assert.IsTrue(verdict.GetProperty("active").GetBoolean(),
            "The access token that drove the whole lifecycle must introspect as active.");
        Assert.AreEqual(EndUserSubject, verdict.GetProperty("sub").GetString());
    }


    /// <summary>Mutable cross-step observations the issuer seams record.</summary>
    private sealed class LifecycleIssuerState
    {
        public bool IsProofVerified { get; set; }
        public string? PendingCredential { get; set; }
        public string? AcknowledgedNotificationId { get; set; }
    }


    /// <summary>
    /// Wires every issuer seam with REAL work: pre-authorized-code validation, c_nonce
    /// minting, holder-proof signature + nonce verification, deferral, SD-JWT VC issuance
    /// bound to the proven holder key, deferred delivery, notification acknowledgement, and
    /// §10 response encryption with real ECDH-ES + AES-GCM.
    /// </summary>
    private void WireIssuerSeams(
        TestHostShell host, PrivateKeyMemory sdJwtIssuerPrivate, out LifecycleIssuerState state)
    {
        LifecycleIssuerState issuerState = new();
        state = issuerState;
        string? mintedNonce = null;

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync = (code, txCode, clientId, _, _, _) =>
            ValueTask.FromResult(string.Equals(code, PreAuthorizedCode, StringComparison.Ordinal)
                ? PreAuthorizedCodeDecision.Grant(EndUserSubject, WellKnownScopes.OpenId)
                : PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.InvalidCode));

        host.Server.OAuth().IssueCredentialNonceAsync = (_, _) =>
        {
            mintedNonce = $"c-nonce-{Guid.NewGuid():N}";

            return ValueTask.FromResult(mintedNonce);
        };

        host.Server.OAuth().IssueCredentialAsync = async (request, accessTokenPayload, _, _, ct) =>
        {
            //Verify the holder proof: signature against the header jwk, c_nonce freshness.
            string proof = request.Proofs[Oid4VciCredentialParameterNames.JwtProofType][0];
            (PublicKeyMemory proofKey, string? proofNonce) = await ReadProofAsync(proof).ConfigureAwait(false);

            using(proofKey)
            {
                bool isProofSignatureValid = await Jws.VerifyAsync(
                    proof, TestSetup.Base64UrlDecoder,
                    Pool,
                    proofKey, cancellationToken: ct).ConfigureAwait(false);

                if(!isProofSignatureValid
                    || mintedNonce is null
                    || !string.Equals(proofNonce, mintedNonce, StringComparison.Ordinal))
                {
                    return CredentialIssuanceDecision.Deny(CredentialRequestError.InvalidProof);
                }

                issuerState.IsProofVerified = true;

                //Mint the real SD-JWT VC bound to the proven holder key NOW; deliver it
                //later through the deferred transaction (manual-review simulation).
                issuerState.PendingCredential = await IssueSdJwtVcAsync(
                    sdJwtIssuerPrivate, proof, cancellationToken: ct).ConfigureAwait(false);
            }

            return CredentialIssuanceDecision.Defer(TransactionId, 60);
        };

        host.Server.OAuth().ResolveDeferredCredentialAsync = (transactionId, _, _, _, _) =>
            ValueTask.FromResult(
                string.Equals(transactionId, TransactionId, StringComparison.Ordinal)
                    && issuerState.PendingCredential is string credential
                ? DeferredCredentialDecision.Issue([credential], NotificationIdValue)
                : DeferredCredentialDecision.Refuse(DeferredCredentialError.InvalidTransactionId));

        host.Server.OAuth().ProcessCredentialNotificationAsync = (notification, _, _, _, _) =>
        {
            issuerState.AcknowledgedNotificationId = notification.NotificationId;

            return ValueTask.FromResult(
                string.Equals(notification.NotificationId, NotificationIdValue, StringComparison.Ordinal)
                    ? CredentialNotificationDecision.Accept
                    : CredentialNotificationDecision.RejectUnknownId());
        };

        host.Server.OAuth().EncryptCredentialResponseAsync = async (responseJson, encryption, _, _, ct) =>
        {
            Dictionary<string, object> jwkDict = new(StringComparer.Ordinal);
            foreach(KeyValuePair<string, object> member in encryption.Jwk!)
            {
                jwkDict[member.Key] = member.Value;
            }

            var (algorithm, purpose, scheme, keyBytes) = CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                jwkDict, Pool, TestSetup.Base64UrlDecoder);
            Tag recipientTag = Tag.Create(algorithm).With(purpose).With(scheme);
            using PublicKeyMemory recipientKey = new(keyBytes, recipientTag);

            return await HaipProfile.EncryptResponseAsync(
                recipientKey, encryption.Enc!,
                Encoding.UTF8.GetBytes(responseJson).AsMemory(),
                HeaderSerializer,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                TestSetup.Base64UrlEncoder, Pool,
                cancellationToken: ct).ConfigureAwait(false);
        };
    }


    /// <summary>
    /// Issues the real EUDI PID SD-JWT VC bound to the holder key proven in
    /// <paramref name="proofJwt"/> — the <c>cnf.jwk</c> is read off the proof header, so the
    /// presented KB-JWT later verifies against exactly the key the wallet proved.
    /// </summary>
    private async ValueTask<string> IssueSdJwtVcAsync(
        PrivateKeyMemory sdJwtIssuerPrivate, string proofJwt, CancellationToken cancellationToken)
    {
        string headerJson = DecodeSegment(proofJwt, segmentIndex: 0);
        Dictionary<string, object>? holderJwk = JwkJsonReader.ExtractObjectProperties(
            Encoding.UTF8.GetBytes(headerJson), "jwk"u8);
        Assert.IsNotNull(holderJwk, "The proof header must carry the holder jwk.");

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: SdJwtIssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: TimeProvider.GetUtcNow(),
            holderConfirmation: holderJwk!,
            claims:
            [
                new(EudiPid.SdJwt.GivenName, "Alice"),
                new(EudiPid.SdJwt.FamilyName, "Smith")
            ]);

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        };

        SdTokenResult result = await payload.IssueSdJwtAsync(
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths, TestSalts.DefaultGenerator(),
            sdJwtIssuerPrivate, SdJwtIssuerKeyId, Pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());

        return SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// The wallet's §7.2.1 <c>jwt</c> key proof: typ <c>openid4vci-proof+jwt</c>, the holder
    /// public key in the header <c>jwk</c>, the Credential Issuer as <c>aud</c>, and the
    /// <c>c_nonce</c> in the <c>nonce</c> claim.
    /// </summary>
    private async ValueTask<string> BuildHolderProofAsync(
        PrivateKeyMemory holderPrivate, PublicKeyMemory holderPublic, string audience, string credentialNonce)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(holderPrivate.Tag);
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublic.Tag.Get<CryptoAlgorithm>(),
            holderPublic.Tag.Get<Purpose>(),
            holderPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        JwtHeader header = new(capacity: 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = "openid4vci-proof+jwt",
            ["jwk"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwkMemberNames.Kty] = jwk.Kty!,
                [WellKnownJwkMemberNames.Crv] = jwk.Crv!,
                [WellKnownJwkMemberNames.X] = jwk.X!,
                [WellKnownJwkMemberNames.Y] = jwk.Y!
            }
        };

        JwtPayload payload = new(capacity: 3)
        {
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Nonce] = credentialNonce,
            [WellKnownJwtClaimNames.Iat] = TimeProvider.GetUtcNow().ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            holderPrivate, HeaderSerializer, PayloadSerializer,
            TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>Reads the holder key (header <c>jwk</c>) and <c>nonce</c> claim off a proof JWT.</summary>
    private static async ValueTask<(PublicKeyMemory ProofKey, string? Nonce)> ReadProofAsync(string proofJwt)
    {
        await Task.CompletedTask.ConfigureAwait(false);

        string headerJson = DecodeSegment(proofJwt, segmentIndex: 0);
        Dictionary<string, object>? jwk = JwkJsonReader.ExtractObjectProperties(
            Encoding.UTF8.GetBytes(headerJson), "jwk"u8);
        Assert.IsNotNull(jwk);

        var (algorithm, purpose, scheme, keyBytes) = CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
            jwk!, Pool, TestSetup.Base64UrlDecoder);
        Tag proofTag = Tag.Create(algorithm).With(purpose).With(scheme);
        PublicKeyMemory proofKey = new(keyBytes, proofTag);

        string payloadJson = DecodeSegment(proofJwt, segmentIndex: 1);
        string? nonce = JwkJsonReader.ExtractStringValue(Encoding.UTF8.GetBytes(payloadJson), "nonce"u8);

        return (proofKey, nonce);
    }


    /// <summary>The wallet-side presentation: KB-JWT over the issued SD-JWT bound to the verifier transaction.</summary>
    private async ValueTask<string> PresentWithKeyBindingAsync(
        string sdJwtWithoutKb, PrivateKeyMemory holderPrivate, string nonce, string audience)
    {
        using SdToken<string> token = SdJwtSerializer.ParseToken(
            sdJwtWithoutKb, TestSetup.Base64UrlDecoder, Pool, TestSalts.TestSaltTag);

        string hashInput = SdJwtSerializer.GetSdJwtForHashing(token, TestSetup.Base64UrlEncoder);

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            Encoding.UTF8.GetBytes(hashInput),
            holderPrivate, nonce, audience,
            TimeProvider.GetUtcNow(),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<string> tokenWithKb = token.WithKeyBinding(compactKbJwt, Pool);

        return SdJwtSerializer.SerializeToken(tokenWithKb, TestSetup.Base64UrlEncoder);
    }


    private async Task<string> EncryptToIssuerAsync(string requestBody, PublicKeyMemory issuerPublic)
    {
        return await HaipProfile.EncryptResponseAsync(
            issuerPublic,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            Encoding.UTF8.GetBytes(requestBody).AsMemory(),
            HeaderSerializer,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<string> DecryptAsync(string compactJwe, PrivateKeyMemory recipientPrivate)
    {
        string headerSegment = compactJwe[..compactJwe.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerSegment, Pool);
        string? enc = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "enc"u8);
        Assert.IsNotNull(enc);

        using AeadMessage parsedJwe = JweParsing.ParseCompact(
            compactJwe, WellKnownJweAlgorithms.EcdhEs, enc!, TestSetup.Base64UrlDecoder, Pool);
        using DecryptedContent decrypted = await parsedJwe.DecryptAsync(
            recipientPrivate,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return Encoding.UTF8.GetString(decrypted.AsReadOnlySpan());
    }


    private static string EcJwkJson(PublicKeyMemory recipientPublic)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            recipientPublic.Tag.Get<CryptoAlgorithm>(),
            recipientPublic.Tag.Get<Purpose>(),
            recipientPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        return "{\"kty\":\"" + jwk.Kty + "\",\"crv\":\"" + jwk.Crv + "\",\"x\":\"" + jwk.X
            + "\",\"y\":\"" + jwk.Y + "\",\"alg\":\"" + WellKnownJweAlgorithms.EcdhEs + "\"}";
    }


    private static string DecodeSegment(string compactJwt, int segmentIndex)
    {
        string[] parts = compactJwt.Split('.');
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[segmentIndex], Pool);

        return Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');
    }


    private async Task<ServerHttpResponse> DispatchWithBearerAsync(
        TestHostShell host, string tenant, string endpointName, string accessToken, string jsonBody)
    {
        return await host.DispatchAtEndpointAsync(
            tenant, endpointName, "POST",
            new RequestFields(),
            new RequestHeaders(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [WellKnownHttpHeaderNames.Authorization] = ["Bearer " + accessToken]
            }),
            jsonBody,
            new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }
}
