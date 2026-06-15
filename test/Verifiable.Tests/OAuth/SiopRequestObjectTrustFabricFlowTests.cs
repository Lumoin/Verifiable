using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Security;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The convergence proof that the SIOPv2 §9 by-reference Request Object path resolves the Relying
/// Party's signing key through the SAME <see cref="CompositeClientIdSigningKeyResolver"/> trust
/// fabric (federation / x509 / DID / verifier_attestation) that OID4VP already uses — not a bespoke
/// direct-key path. The SIOP §9 Request Object and the OID4VP JAR are the same RFC 9101
/// <c>oauth-authz-req+jwt</c> artifact, so <see cref="JarVerification.VerifyAsync"/> and the
/// composite resolver already apply.
/// </summary>
/// <remarks>
/// <para>
/// The Relying Party's <c>client_id</c> carries the <c>x509_san_dns:</c> prefix. The host sets the
/// §9 Request Object additional JOSE header claims to a header carrying the matching <c>x5c</c>
/// chain (the shared X.509 test ring), so the served Request Object's JOSE header now advertises
/// <c>x5c</c> exactly as the OID4VP JAR does. The WALLET side then parses the header, places the CA
/// trust anchors and the validation instant on the <see cref="ExchangeContext"/>, calls the
/// composite resolver to recover the RP <see cref="PublicKeyMemory"/>, verifies the Request Object
/// through <see cref="JarVerification.VerifyAsync"/>, asserts the §9.1 <c>aud</c>, and completes the
/// flow by minting and POSTing the bound id_token — driving the RP to
/// <see cref="SelfIssuedAuthenticationVerifiedState"/> exactly as <see cref="SiopRequestUriFlowTests"/>.
/// </para>
/// <para>
/// The adversarial case proves the fabric rejects a SAN mismatch: a <c>client_id</c> whose
/// <c>x509_san_dns:</c> DNS name does not match the served <c>x5c</c> leaf SAN makes the resolver
/// throw <see cref="SecurityException"/> — the wallet treats the request as untrusted. This mirrors
/// the OID4VP SAN-mismatch rejection in <see cref="Oid4VpX509SanDnsResolverTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SiopRequestObjectTrustFabricFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string SiopNonce = "n-siop-trust-fabric-01";

    private static readonly Uri RelyingPartyBaseUri = new("https://verifier.example.com");

    private static readonly ImmutableHashSet<CapabilityIdentifier> SiopCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.SiopSelfIssuedOp);

    private static readonly string[] AllowedSiopAlgorithms = [WellKnownJwaValues.Es256];

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);

    //JarVerification.VerifyAsync materialises the protected header and payload through these
    //deserializers, the same JSON stack the OID4VP wallet flows wire.
    private static readonly JwtHeaderDeserializer JarHeaderDeserializer =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)!;

    private static readonly JwtPayloadDeserializer JarPayloadDeserializer =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)!;


    [TestMethod]
    public async Task ByReferenceFlowResolvesRpKeyThroughX509SanDnsFabricAndCompletes()
    {
        await using TestHostShell host = new(TimeProvider);

        //The shared x509_san_dns scheme material: the RP's client_id (x509_san_dns:verifier.example.com),
        //the leaf-cert JAR-signing key the AS signs the §9 Request Object with, the JOSE header carrying
        //the [leaf, ca] x5c chain, the composite resolver, and the CA trust anchors the wallet evaluates
        //the chain against. The same fixture the OID4VP x509 flows reuse.
        using SchemeMaterial scheme = await Oid4VpSchemeFixtures.X509.CreateAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);

        //Register the RP so the AS signs its §9 Request Object with the leaf cert key — the key the
        //wallet must recover from x5c through the fabric.
        using VerifierKeyMaterial rpKeys = host.RegisterJarSigningClient(
            scheme.ClientId, RelyingPartyBaseUri, scheme.JarSigningKeyPair, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        //=== Step 1: the RP prepares the transaction, setting the §9 Request Object header to carry the
        //x5c chain — the SIOP parallel of OID4VP setting jarAdditionalHeaderClaims at PAR time. ===
        (string requestHandle, Uri requestUri) = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, scheme.ClientId, AllowedSiopAlgorithms,
            useStaticDiscoveryAudience: false,
            encryptionKeyId: null, allowedEncAlgorithms: null,
            requestObjectAdditionalHeaderClaims: scheme.JarHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(requestUri.OriginalString.Contains(requestHandle, StringComparison.Ordinal),
            "The composed request_uri must carry the per-flow handle.");
        Assert.IsInstanceOfType<SiopRequestPreparedState>(host.GetFlowState(requestHandle).State);

        //=== Step 2: the Wallet GETs the request_uri and receives the signed §9 Request Object whose
        //JOSE header now advertises x5c. ===
        string requestObjectJws = await host.HandleSiopRequestObjectAsync(
            rpKeys, requestHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, requestObjectJws.Split('.'),
            "The §9 Request Object must be a compact JWS with three dot-separated segments.");
        Assert.IsInstanceOfType<SiopRequestObjectServedState>(host.GetFlowState(requestHandle).State);

        //The served header carries the x5c the fabric resolves the RP key from — not present on the
        //bespoke direct-key path.
        UnverifiedJwtHeader servedHeader = ParseHeader(requestObjectJws);
        Assert.IsTrue(servedHeader.ContainsKey(WellKnownJwkMemberNames.X5c),
            "The served §9 Request Object header must carry x5c so the wallet resolves the RP key " +
            "through the same client-id trust fabric as OID4VP.");

        //=== Step 3: the WALLET resolves the RP key through the composite resolver, then verifies the
        //Request Object via JarVerification.VerifyAsync — the EXACT resolve+verify composition the
        //OID4VP x509 flow performs. ===
        DateTimeOffset now = TimeProvider.GetUtcNow();
        ExchangeContext walletContext = new();
        scheme.PlaceTrustMaterial(walletContext);
        walletContext.SetValidationTime(now);

        using PublicKeyMemory resolvedRpKey = await scheme.Resolver(
            walletContext, scheme.ClientId, servedHeader, TestContext.CancellationToken)
            .ConfigureAwait(false);

        JarVerificationResult verification = await JarVerification.VerifyAsync(
            requestObjectJws,
            resolvedRpKey,
            now,
            clockSkew: TimeSpan.FromMinutes(2),
            maximumLifetime: TimeSpan.FromHours(24),
            TestSetup.Base64UrlDecoder,
            JarHeaderDeserializer,
            JarPayloadDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        JarVerified verified = Assert.IsInstanceOfType<JarVerified>(verification,
            "The §9 Request Object must verify under the RP key resolved through the x509_san_dns " +
            "fabric — proving the SIOP by-reference path uses the SAME trust fabric as OID4VP.");

        //The §9 claims, including the §9.1 aud (dynamic discovery: the RP's own issuer here).
        Assert.AreEqual(
            SiopAuthorizationRequestParameterValues.ResponseTypeIdToken,
            GetString(verified.Claims, OAuthRequestParameterNames.ResponseType));
        Assert.AreEqual(scheme.ClientId, GetString(verified.Claims, WellKnownJwtClaimNames.ClientId));
        Assert.AreEqual(SiopNonce, GetString(verified.Claims, WellKnownJwtClaimNames.Nonce));
        Assert.AreEqual(requestHandle, GetString(verified.Claims, OAuthRequestParameterNames.State));
        Assert.AreEqual(
            rpKeys.Registration.IssuerUri!.OriginalString,
            GetString(verified.Claims, WellKnownJwtClaimNames.Aud),
            "The §9.1 aud must be the dynamically discovered issuer.");

        //=== Step 4: the Wallet mints a JWK-Thumbprint Self-Issued ID Token bound to the transaction
        //and POSTs it — completing the flow exactly as SiopRequestUriFlowTests. ===
        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, scheme.ClientId, SiopNonce,
            issuedAt: now, lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string expectedSubject = SelfIssuedSubjectThumbprint(siopPublic);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            tenant,
            WellKnownEndpointNames.SiopResponse,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.IdToken] = idToken,
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

        (FlowState state, _) = host.GetFlowState(requestHandle);
        SelfIssuedAuthenticationVerifiedState authenticated =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
        Assert.AreEqual(expectedSubject, authenticated.Subject);
        Assert.AreEqual(SiopNonce, authenticated.Nonce);
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, authenticated.SubjectSyntaxType);
    }


    [TestMethod]
    public async Task SanMismatchedClientIdIsRejectedByTheFabric()
    {
        await using TestHostShell host = new(TimeProvider);

        //The RP serves a correctly signed §9 Request Object chaining to a trusted anchor, but the
        //wallet resolves under a client_id asserting a DNS name the leaf SAN does not carry. The
        //DNS-SAN binding is the whole point of the prefix, so the fabric must reject it.
        using SchemeMaterial scheme = await Oid4VpSchemeFixtures.X509.CreateAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);

        using VerifierKeyMaterial rpKeys = host.RegisterJarSigningClient(
            scheme.ClientId, RelyingPartyBaseUri, scheme.JarSigningKeyPair, SiopCapabilities);

        (string requestHandle, _) = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, scheme.ClientId, AllowedSiopAlgorithms,
            useStaticDiscoveryAudience: false,
            encryptionKeyId: null, allowedEncAlgorithms: null,
            requestObjectAdditionalHeaderClaims: scheme.JarHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        string requestObjectJws = await host.HandleSiopRequestObjectAsync(
            rpKeys, requestHandle, TestContext.CancellationToken).ConfigureAwait(false);
        UnverifiedJwtHeader servedHeader = ParseHeader(requestObjectJws);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        ExchangeContext walletContext = new();
        scheme.PlaceTrustMaterial(walletContext);
        walletContext.SetValidationTime(now);

        //A client_id whose x509_san_dns: DNS name does NOT match the served x5c leaf SAN. The wallet
        //treats this as an untrusted request — the fabric throws before any key is handed back.
        string spoofedClientId = $"{WellKnownClientIdPrefixes.X509SanDns}:attacker.example.com";

        await Assert.ThrowsExactlyAsync<SecurityException>(
            async () => await scheme.Resolver(
                walletContext, spoofedClientId, servedHeader, TestContext.CancellationToken)
                .ConfigureAwait(false));
    }


    private static UnverifiedJwtHeader ParseHeader(string compactJws)
    {
        using UnverifiedJwsMessage unverified = JwsParsing.ParseCompact(
            compactJws,
            TestSetup.Base64UrlDecoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool);

        return new UnverifiedJwtHeader(unverified.Signatures[0].ProtectedHeader);
    }


    private static string GetString(IReadOnlyDictionary<string, object> claims, string claim)
    {
        Assert.IsTrue(claims.TryGetValue(claim, out object? value),
            $"The §9 Request Object payload is missing the '{claim}' claim.");

        return value switch
        {
            JsonElement element => element.GetString()
                ?? throw new FormatException($"Claim '{claim}' is not a JSON string."),
            string s => s,
            _ => value!.ToString()!
        };
    }


    //The RFC 9278 sha-256 JWK Thumbprint URI the validator confirms the sub against — the same
    //projection SelfIssuedIdTokenIssuance uses, recomputed from the public key alone.
    private static string SelfIssuedSubjectThumbprint(PublicKeyMemory publicKey)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(publicKey.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, algorithm, TestSetup.Base64UrlEncoder);
        string thumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(
            jwk, TestSetup.Base64UrlEncoder, Pool);

        return SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix + thumbprint;
    }
}
