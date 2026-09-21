using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests that <see cref="SdJwtVpTokenVerification.VerifyAsync"/> reads the Issuer-signed JWT's own
/// <c>kid</c> and <c>x5c</c> header members and passes them to <see cref="ResolveIssuerKeyDelegate"/>,
/// per <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#section-2.5">
/// SD-JWT VC draft-19, Section 2.5</see>'s two key discovery and validation mechanisms.
/// </summary>
[TestClass]
internal sealed class SdJwtVpTokenVerificationIssuerKeySeamTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "jwt-vc-issuer-key-1";
    private const string IdentityCredentialQueryId = "identity";


    /// <summary>
    /// A recording <see cref="ResolveIssuerKeyDelegate"/> asserts the Issuer-signed JWT's own
    /// <c>kid</c> header reaches the delegate as-is; the header carries no <c>x5c</c>, so the
    /// delegate must receive <see langword="null"/> for it rather than an empty non-null list.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncPassesTheHeaderKidToTheDelegateAndNullX5cWhenAbsent()
    {
        using PrivateKeyMemory issuerPrivateKey = TestKeyMaterialProvider.CreateP256KeyMaterial().PrivateKey;

        string serializedSdJwt = await IssueIssuerOnlyCredentialAsync(
            issuerPrivateKey, IssuerKeyId, x5c: null, TestContext.CancellationToken).ConfigureAwait(false);

        string? capturedIssuerId = null;
        string? capturedKeyId = null;
        IReadOnlyList<string>? capturedX5c = null;

        ValueTask<PublicKeyMemory?> RecordingResolver(string issuerId, string? keyId, IReadOnlyList<string>? x5c, ExchangeContext context, CancellationToken cancellationToken)
        {
            capturedIssuerId = issuerId;
            capturedKeyId = keyId;
            capturedX5c = x5c;

            return ValueTask.FromResult<PublicKeyMemory?>(null);
        }

        _ = await SdJwtVpTokenVerification.VerifyAsync(
            serializedSdJwt,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: RecordingResolver,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            context: new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(IssuerId, capturedIssuerId);
        Assert.AreEqual(IssuerKeyId, capturedKeyId, "The delegate must receive the Issuer-signed JWT's own kid header.");
        Assert.IsNull(capturedX5c, "The delegate must receive null when the header carries no x5c.");
    }


    /// <summary>A recording delegate asserts the Issuer-signed JWT's own <c>x5c</c> header chain reaches the delegate, leaf first.</summary>
    [TestMethod]
    public async Task VerifyAsyncPassesTheHeaderX5cToTheDelegate()
    {
        using PrivateKeyMemory issuerPrivateKey = TestKeyMaterialProvider.CreateP256KeyMaterial().PrivateKey;

        string[] x5c = ["bGVhZg==", "cm9vdA=="];
        string serializedSdJwt = await IssueIssuerOnlyCredentialAsync(
            issuerPrivateKey, IssuerKeyId, x5c, TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<string>? capturedX5c = null;

        ValueTask<PublicKeyMemory?> RecordingResolver(string issuerId, string? keyId, IReadOnlyList<string>? capturedX5cChain, ExchangeContext context, CancellationToken cancellationToken)
        {
            capturedX5c = capturedX5cChain;

            return ValueTask.FromResult<PublicKeyMemory?>(null);
        }

        _ = await SdJwtVpTokenVerification.VerifyAsync(
            serializedSdJwt,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: RecordingResolver,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            context: new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(capturedX5c);
        Assert.AreSequenceEqual(x5c, capturedX5c);
    }


    /// <summary>
    /// An application's <see cref="ResolveIssuerKeyDelegate"/> composing <see cref="SdJwtX5cTrustResolver.ResolveAsync"/>
    /// against the Issuer-signed JWT's own <c>x5c</c> header resolves the issuer's public key, and the
    /// credential's signature verifies, when the chain's root reaches a configured trust anchor.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncVerifiesCredentialSignatureThroughX5cTrustResolverWithConfiguredAnchor()
    {
        using CertificateChainMaterial chain = TestCertificateChainProvider.CreateP256ChainMaterial(TimeProvider);

        string[] x5c =
        [
            Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlySpan()),
            Convert.ToBase64String(chain.CaDerBytes.AsReadOnlySpan())
        ];

        string serializedSdJwt = await IssueIssuerOnlyCredentialAsync(
            chain.LeafSigningKey, IssuerKeyId, x5c, TestContext.CancellationToken).ConfigureAwait(false);

        ValueTask<PublicKeyMemory?> ResolveIssuerKeyThroughX5c(
            string issuerId, string? keyId, IReadOnlyList<string>? headerX5c, ExchangeContext context, CancellationToken cancellationToken) =>
            headerX5c is null
                ? ValueTask.FromResult<PublicKeyMemory?>(null)
                : SdJwtX5cTrustResolver.ResolveAsync(
                    headerX5c,
                    MicrosoftX509Functions.ParseX5c,
                    MicrosoftX509Functions.ValidateChainAsync,
                    [chain.CaDerBytes],
                    TimeProvider.GetUtcNow(),
                    Pool,
                    cancellationToken);

        VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
            serializedSdJwt,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: ResolveIssuerKeyThroughX5c,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            context: new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(parsed.CredentialSignatureValid, "A chain reaching a configured trust anchor must resolve the issuer key and verify the credential signature.");
    }


    /// <summary>
    /// The same composition as <see cref="VerifyAsyncVerifiesCredentialSignatureThroughX5cTrustResolverWithConfiguredAnchor"/>,
    /// except the trust anchor configured does not match the presented chain's root: the resolver answers
    /// <see langword="null"/>, and the credential's signature is reported unverified rather than thrown.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncReportsCredentialSignatureUnverifiedWithNoMatchingAnchor()
    {
        using CertificateChainMaterial chain = TestCertificateChainProvider.CreateP256ChainMaterial(TimeProvider);
        using CertificateChainMaterial unrelatedChain = TestCertificateChainProvider.CreateFreshP256ChainMaterial(
            "unrelated.example.com", TimeProvider);

        string[] x5c =
        [
            Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlySpan()),
            Convert.ToBase64String(chain.CaDerBytes.AsReadOnlySpan())
        ];

        string serializedSdJwt = await IssueIssuerOnlyCredentialAsync(
            chain.LeafSigningKey, IssuerKeyId, x5c, TestContext.CancellationToken).ConfigureAwait(false);

        ValueTask<PublicKeyMemory?> ResolveIssuerKeyThroughX5c(
            string issuerId, string? keyId, IReadOnlyList<string>? headerX5c, ExchangeContext context, CancellationToken cancellationToken) =>
            headerX5c is null
                ? ValueTask.FromResult<PublicKeyMemory?>(null)
                : SdJwtX5cTrustResolver.ResolveAsync(
                    headerX5c,
                    MicrosoftX509Functions.ParseX5c,
                    MicrosoftX509Functions.ValidateChainAsync,
                    [unrelatedChain.CaDerBytes],
                    TimeProvider.GetUtcNow(),
                    Pool,
                    cancellationToken);

        VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
            serializedSdJwt,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: ResolveIssuerKeyThroughX5c,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            context: new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(parsed.CredentialSignatureValid, "A chain reaching no configured trust anchor must leave the credential signature unverified.");
    }


    /// <summary>
    /// The <see cref="ExchangeContext"/> the caller hands to <see cref="SdJwtVpTokenVerification.VerifyAsync"/>
    /// must reach <see cref="ResolveIssuerKeyDelegate"/> unchanged, so an implementation that fetches JWT VC
    /// Issuer Metadata is policed by the request's own outbound-fetch policy rather than a fresh, empty one.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncPassesTheCallersContextToTheDelegate()
    {
        using PrivateKeyMemory issuerPrivateKey = TestKeyMaterialProvider.CreateP256KeyMaterial().PrivateKey;

        string serializedSdJwt = await IssueIssuerOnlyCredentialAsync(
            issuerPrivateKey, IssuerKeyId, x5c: null, TestContext.CancellationToken).ConfigureAwait(false);

        ExchangeContext callerContext = new();
        ExchangeContext? capturedContext = null;

        ValueTask<PublicKeyMemory?> RecordingResolver(string issuerId, string? keyId, IReadOnlyList<string>? x5c, ExchangeContext context, CancellationToken cancellationToken)
        {
            capturedContext = context;

            return ValueTask.FromResult<PublicKeyMemory?>(null);
        }

        _ = await SdJwtVpTokenVerification.VerifyAsync(
            serializedSdJwt,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: RecordingResolver,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            context: callerContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSame(callerContext, capturedContext, "The delegate must receive the same ExchangeContext instance the caller handed to VerifyAsync.");
    }


    /// <summary>
    /// The house's real-wire E2E for the defect this composes
    /// <see cref="JwtVcIssuerMetadataDocuments.SelectKeyAsync"/> against: a resolver built exactly as
    /// an application composes it, fetching the JWT VC Issuer Metadata's inline <c>jwks</c> over a
    /// real HTTPS loopback socket and selecting the verification key from it. A published JWK Set
    /// that carries a private member alongside the issuer's real public key is refused SET-WIDE, so
    /// the credential's signature is not accepted, even though the requested <c>kid</c> matches only
    /// the clean key. A selection by <c>kid</c> alone accepts this key set.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncRefusesTheCredentialWhenTheMatchingPublishedKeyCarriesPrivateMaterial()
    {
        await using StaticContentHost issuerHost = await StaticContentHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        string serializedSdJwt = await IssueIssuerOnlyCredentialAsync(
            issuerPrivateKey, IssuerKeyId, x5c: null, TestContext.CancellationToken,
            issuerId: issuerHost.BaseAddress.OriginalString.TrimEnd('/')).ConfigureAwait(false);

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId);
        issuerJwk[WellKnownJwkMemberNames.D] = "a-private-scalar-that-must-refuse-the-whole-set";

        (System.Net.Http.HttpClient issuerHttpClient, ResolveIssuerKeyDelegate resolveIssuerKey) = PublishJwksAndBuildResolver(issuerHost, [issuerJwk]);
        using System.Net.Http.HttpClient _ = issuerHttpClient;

        VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
            serializedSdJwt,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: resolveIssuerKey,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            context: new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(parsed.CredentialSignatureValid,
            "A JWK Set that publishes private material alongside the matching key must resolve no verification key.");
        Assert.IsTrue(issuerHost.WasRequested("/.well-known/jwt-vc-issuer"),
            "The refusal must be reached over the real HTTPS loopback socket, not skipped in-process.");
    }


    /// <summary>
    /// The paired positive control for
    /// <see cref="VerifyAsyncRefusesTheCredentialWhenTheMatchingPublishedKeyCarriesPrivateMaterial"/>:
    /// the same wiring, over the same kind of real HTTPS loopback socket, with no private member on
    /// the published key, verifies the credential's signature.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncAcceptsTheCredentialWhenTheResolvedJwksPublishesOnlyTheCleanMatchingKey()
    {
        await using StaticContentHost issuerHost = await StaticContentHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        string serializedSdJwt = await IssueIssuerOnlyCredentialAsync(
            issuerPrivateKey, IssuerKeyId, x5c: null, TestContext.CancellationToken,
            issuerId: issuerHost.BaseAddress.OriginalString.TrimEnd('/')).ConfigureAwait(false);

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId);

        (System.Net.Http.HttpClient issuerHttpClient, ResolveIssuerKeyDelegate resolveIssuerKey) = PublishJwksAndBuildResolver(issuerHost, [issuerJwk]);
        using System.Net.Http.HttpClient _ = issuerHttpClient;

        VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
            serializedSdJwt,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: resolveIssuerKey,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            context: new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(parsed.CredentialSignatureValid,
            "A JWK Set carrying only the clean, matching key must resolve it and verify the credential's signature.");
    }


    /// <summary>
    /// The set-wide refusal is distinct from the SELECTED key's own check: an UNRELATED element (a
    /// different <c>kid</c>) that carries a private member refuses the selection of the clean,
    /// requested key too — <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517
    /// §5.1</see> makes the whole array the unit this library judges, not the one element a
    /// <c>kid</c> lookup would otherwise narrow to. A selection by <c>kid</c> alone
    /// accepts this key set: it counts only the elements whose <c>kid</c> matches, and the private
    /// member sits on one that does not.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncRefusesTheCredentialWhenAnUnrelatedPublishedElementCarriesPrivateMaterial()
    {
        await using StaticContentHost issuerHost = await StaticContentHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> unrelatedKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory unrelatedPrivateKey = unrelatedKeys.PrivateKey;
        using PublicKeyMemory unrelatedPublicKey = unrelatedKeys.PublicKey;

        string serializedSdJwt = await IssueIssuerOnlyCredentialAsync(
            issuerPrivateKey, IssuerKeyId, x5c: null, TestContext.CancellationToken,
            issuerId: issuerHost.BaseAddress.OriginalString.TrimEnd('/')).ConfigureAwait(false);

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId);
        Dictionary<string, object> unrelatedJwk = BuildIssuerJwk(unrelatedPublicKey, "an-unrelated-key-id");
        unrelatedJwk[WellKnownJwkMemberNames.D] = "a-private-scalar-on-a-key-nobody-requested";

        (System.Net.Http.HttpClient issuerHttpClient, ResolveIssuerKeyDelegate resolveIssuerKey) = PublishJwksAndBuildResolver(issuerHost, [issuerJwk, unrelatedJwk]);
        using System.Net.Http.HttpClient _ = issuerHttpClient;

        VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
            serializedSdJwt,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: resolveIssuerKey,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            context: new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(parsed.CredentialSignatureValid,
            "An unrelated element carrying private material must refuse the whole set, even though the requested kid matches only the clean key.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// <c>kid</c> optional: an Issuer-signed JWT with no <c>kid</c> header resolves through the sole-key
    /// branch, and a clean, sole published key verifies it.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncAcceptsTheCredentialWhenTheSolePublishedKeyIsCleanWithoutATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId);

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, tokenKeyId: null, [issuerJwk], expectAccepted: true,
            "A sole, clean published key must verify a kid-less credential.").ConfigureAwait(false);
    }


    /// <summary>
    /// The sole-key branch's own set-wide refusal: the sole published key carries a private member
    /// alongside its real public coordinates, so no verification key is resolved and the credential's
    /// signature is not accepted, even though the Issuer-signed JWT carries no <c>kid</c> to narrow
    /// selection at all. A selection by <c>kid</c> alone accepts this key set: with
    /// exactly one element in the set, it selects that element whatever its members are.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncRefusesTheCredentialWhenTheSolePublishedKeyCarriesPrivateMaterialWithoutATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId);
        issuerJwk[WellKnownJwkMemberNames.D] = "a-private-scalar-that-must-refuse-the-whole-set";

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, tokenKeyId: null, [issuerJwk], expectAccepted: false,
            "A sole published key carrying private material must refuse a kid-less credential too.").ConfigureAwait(false);
    }


    /// <summary>
    /// The set-wide refusal reaches the sole-key branch too: an UNRELATED element carrying a private
    /// member refuses the whole set even with no <c>kid</c> to narrow selection to the clean,
    /// verifiable key. A selection by <c>kid</c> alone refuses this key set too: with no
    /// <c>kid</c> to select by, it requires the set to hold exactly one element, and this one holds
    /// two.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncRefusesTheCredentialWhenAnUnrelatedPublishedElementCarriesPrivateMaterialWithoutATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> unrelatedKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory unrelatedPrivateKey = unrelatedKeys.PrivateKey;
        using PublicKeyMemory unrelatedPublicKey = unrelatedKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId);
        Dictionary<string, object> unrelatedJwk = BuildIssuerJwk(unrelatedPublicKey, "an-unrelated-key-id");
        unrelatedJwk[WellKnownJwkMemberNames.D] = "a-private-scalar-on-a-key-nobody-requested";

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, tokenKeyId: null, [issuerJwk, unrelatedJwk], expectAccepted: false,
            "An unrelated element carrying private material must refuse a kid-less credential too.").ConfigureAwait(false);
    }


    /// <summary>
    /// The paired positive control for
    /// <see cref="VerifyAsyncRefusesTheCredentialWhenAnUnrelatedPublishedElementCarriesPrivateMaterialWithoutATokenKid"/>
    /// and the sole-key branch's own demonstration of RFC 7517 §4.2 eligibility: a set holding the
    /// real, <c>sig</c>-marked issuer key beside an unrelated <c>enc</c>-marked key selects the
    /// <c>sig</c> key, and the kid-less credential's signature verifies — where a set with no
    /// eligibility distinction between two keys would be refused as ambiguous. A selection that
    /// ignores <c>use</c> refuses this key set, because it holds two keys and the token names none.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncAcceptsTheCredentialWhenTheSoleEligibleKeyIsSelectedBesideAnIneligibleEncKeyWithoutATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> unrelatedKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory unrelatedPrivateKey = unrelatedKeys.PrivateKey;
        using PublicKeyMemory unrelatedPublicKey = unrelatedKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId, use: WellKnownJwkValues.UseSig);
        Dictionary<string, object> unrelatedJwk = BuildIssuerJwk(unrelatedPublicKey, "an-unrelated-key-id", use: WellKnownJwkValues.UseEnc);

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, tokenKeyId: null, [issuerJwk, unrelatedJwk], expectAccepted: true,
            "The sole sig-eligible key beside an ineligible enc key must verify the kid-less credential.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: the
    /// matching published key is marked <c>"use":"enc"</c>. The selector's <c>sig</c>-eligibility
    /// filter excludes it — the credential's signature is not accepted, even with the token's own
    /// <c>kid</c> matching this key precisely. This uses an Ed25519 key, whose algorithm-to-key
    /// mapping ignores <c>use</c> downstream (always resolving to signature verification), so this
    /// negative isolates the SELECTION filter rather than the downstream purpose mapping a P-256 key
    /// would also exercise. A selection by <c>kid</c> alone accepts this key set.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncRefusesTheCredentialWhenTheMatchingPublishedKeyIsMarkedForEncryptionWithATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId, use: WellKnownJwkValues.UseEnc);

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, IssuerKeyId, [issuerJwk], expectAccepted: false,
            "An enc-marked matching Ed25519 key must not verify the credential.").ConfigureAwait(false);
    }


    /// <summary>
    /// The paired positive control for
    /// <see cref="VerifyAsyncRefusesTheCredentialWhenTheMatchingPublishedKeyIsMarkedForEncryptionWithATokenKid"/>:
    /// the same Ed25519 key, published with no <c>use</c> member, verifies the credential.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncAcceptsTheCredentialWhenTheMatchingPublishedEd25519KeyCarriesNoUseMemberWithATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId);

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, IssuerKeyId, [issuerJwk], expectAccepted: true,
            "An Ed25519 matching key with no use member must verify the credential.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>'s <c>use</c>
    /// filter reaches the sole-key branch too: the sole published Ed25519 key is marked
    /// <c>"use":"enc"</c>, so it is no longer eligible and no key is selected for the kid-less
    /// credential. Ed25519's mapping ignores <c>use</c> downstream, so this isolates the selection
    /// filter. A selection by <c>kid</c> alone accepts this key set: with exactly one
    /// element in the set, it selects that element whatever its <c>use</c> is.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncRefusesTheCredentialWhenTheSolePublishedKeyIsMarkedForEncryptionWithoutATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId, use: WellKnownJwkValues.UseEnc);

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, tokenKeyId: null, [issuerJwk], expectAccepted: false,
            "An enc-marked sole Ed25519 key must not verify a kid-less credential.").ConfigureAwait(false);
    }


    /// <summary>
    /// The paired positive control for
    /// <see cref="VerifyAsyncRefusesTheCredentialWhenTheSolePublishedKeyIsMarkedForEncryptionWithoutATokenKid"/>:
    /// the same sole Ed25519 key, published with no <c>use</c> member, verifies the kid-less
    /// credential.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncAcceptsTheCredentialWhenTheSolePublishedEd25519KeyCarriesNoUseMemberWithoutATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId);

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, tokenKeyId: null, [issuerJwk], expectAccepted: true,
            "A sole Ed25519 key with no use member must verify a kid-less credential.").ConfigureAwait(false);
    }


    /// <summary>
    /// A P-256 issuer key published with <c>"use":"enc"</c> does not verify the credential: RFC 7517
    /// §4.2 (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>) makes
    /// <c>use</c> the key's intended use, and a key marked for encryption is not eligible for signature
    /// verification, whatever its key type. A selection by <c>kid</c> alone selects this key;
    /// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/> tags it for
    /// <see cref="Purpose.Exchange"/>, the function registry holds no verification function for that
    /// purpose, and the verification ends in an escaping <see cref="ArgumentException"/> where a
    /// refusal belongs. The selection's <c>use</c> filter answers with the refusal.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncRefusesTheCredentialWhenTheMatchingPublishedP256KeyIsMarkedForEncryptionWithATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId, use: WellKnownJwkValues.UseEnc);

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, IssuerKeyId, [issuerJwk], expectAccepted: false,
            "An enc-marked matching P-256 key must not verify the credential.").ConfigureAwait(false);
    }


    /// <summary>
    /// The sole-key twin of
    /// <see cref="VerifyAsyncRefusesTheCredentialWhenTheMatchingPublishedP256KeyIsMarkedForEncryptionWithATokenKid"/>:
    /// the sole published P-256 key is marked <c>"use":"enc"</c> and the token names no <c>kid</c>;
    /// the key is not eligible for signature verification and the credential does not verify. A
    /// selection that ignores <c>use</c> selects this key, and the verification then throws for want
    /// of a verification function for <see cref="Purpose.Exchange"/> where a refusal belongs.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncRefusesTheCredentialWhenTheSolePublishedP256KeyIsMarkedForEncryptionWithoutATokenKid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;

        Dictionary<string, object> issuerJwk = BuildIssuerJwk(issuerPublicKey, IssuerKeyId, use: WellKnownJwkValues.UseEnc);

        await RunIssuerKeyScenarioAsync(
            issuerPrivateKey, tokenKeyId: null, [issuerJwk], expectAccepted: false,
            "An enc-marked sole P-256 key must not verify a kid-less credential.").ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the same real-wire seam <see cref="PublishJwksAndBuildResolver"/> composes — a JWT VC
    /// Issuer Metadata document with the JWK Set <paramref name="keys"/> published inline, served over
    /// a real HTTPS loopback listener — and asserts the credential's signature verification outcome
    /// against <paramref name="expectAccepted"/>.
    /// </summary>
    private async Task RunIssuerKeyScenarioAsync(
        PrivateKeyMemory issuerPrivateKey, string? tokenKeyId, IReadOnlyList<Dictionary<string, object>> keys,
        bool expectAccepted, string context)
    {
        await using StaticContentHost issuerHost = await StaticContentHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string serializedSdJwt = await IssueIssuerOnlyCredentialAsync(
            issuerPrivateKey, tokenKeyId, x5c: null, TestContext.CancellationToken,
            issuerId: issuerHost.BaseAddress.OriginalString.TrimEnd('/')).ConfigureAwait(false);

        (System.Net.Http.HttpClient issuerHttpClient, ResolveIssuerKeyDelegate resolveIssuerKey) = PublishJwksAndBuildResolver(issuerHost, keys);
        using System.Net.Http.HttpClient _ = issuerHttpClient;

        VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
            serializedSdJwt,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: resolveIssuerKey,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            context: new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectAccepted, parsed.CredentialSignatureValid, context);
    }


    /// <summary>
    /// Builds the JWK Set document carrying <paramref name="keys"/> and publishes it as the JWT VC
    /// Issuer Metadata document's inline <c>jwks</c> at <paramref name="issuerHost"/>, returning the
    /// pinned <see cref="System.Net.Http.HttpClient"/> the caller must keep alive and dispose
    /// alongside a <see cref="ResolveIssuerKeyDelegate"/> composed exactly as an application composes
    /// <see cref="JwtVcIssuerMetadataDocuments.ResolveAsync"/> and
    /// <see cref="JwtVcIssuerMetadataDocuments.SelectKeyAsync"/> over the real HTTPS loopback wire —
    /// the <c>jwks_uri</c> seam is never called, since the document always carries <c>jwks</c> inline.
    /// </summary>
    private static (System.Net.Http.HttpClient IssuerHttpClient, ResolveIssuerKeyDelegate Resolve) PublishJwksAndBuildResolver(
        StaticContentHost issuerHost, IReadOnlyList<Dictionary<string, object>> keys)
    {
        System.Net.Http.HttpClient issuerHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(issuerHost.Certificate);
        OutboundTransportDelegate issuerTransport = GuardedHttpClientTransport.BuildSingleHopTransport(issuerHttpClient);
        string issuerId = issuerHost.BaseAddress.OriginalString.TrimEnd('/');

        Dictionary<string, object> jwksObject = new() { ["keys"] = keys.Cast<object>().ToArray() };
        string inlineDocumentJson = JsonSerializer.Serialize(
            new Dictionary<string, object> { ["issuer"] = issuerId, ["jwks"] = jwksObject },
            TestSetup.DefaultSerializationOptions);
        issuerHost.Publish(
            "/.well-known/jwt-vc-issuer", Encoding.UTF8.GetBytes(inlineDocumentJson), "application/json");

        ValueTask<PublicKeyMemory?> Resolve(string candidateIssuerId, string? keyId, IReadOnlyList<string>? x5c, ExchangeContext context, CancellationToken cancellationToken) =>
            ResolveCoreAsync(candidateIssuerId, keyId, context, issuerTransport, cancellationToken);

        return (issuerHttpClient, Resolve);
    }


    /// <summary>The body of <see cref="PublishJwksAndBuildResolver"/>'s returned delegate, factored out so it stays an <see langword="async"/> method rather than an async lambda capturing a disposed closure.</summary>
    private static async ValueTask<PublicKeyMemory?> ResolveCoreAsync(
        string candidateIssuerId, string? keyId, ExchangeContext context, OutboundTransportDelegate issuerTransport, CancellationToken cancellationToken)
    {
        context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

        JwtVcIssuerMetadataResolution resolution = await JwtVcIssuerMetadataDocuments.ResolveAsync(
            new Uri(candidateIssuerId), context, issuerTransport,
            new JwtVcIssuerMetadataDocumentResolverOptions(), cancellationToken).ConfigureAwait(false);

        return await JwtVcIssuerMetadataDocuments.SelectKeyAsync(
            resolution, keyId,
            (_, _, _) => throw new InvalidOperationException(
                "The document always carries jwks inline; jwks_uri must not be consulted."),
            context, Pool, TestSetup.Base64UrlDecoder, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the JWK for <paramref name="publicKey"/>, carrying <paramref name="keyId"/> and, when
    /// supplied, a <c>use</c> member.
    /// </summary>
    private static Dictionary<string, object> BuildIssuerJwk(PublicKeyMemory publicKey, string keyId, string? use = null)
    {
        Dictionary<string, object> jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            publicKey.Tag.Get<CryptoAlgorithm>(), publicKey.Tag.Get<Purpose>(),
            publicKey.AsReadOnlySpan(), TestSetup.Base64UrlEncoder);
        jwk[WellKnownJwkMemberNames.Kid] = keyId;
        if(use is not null)
        {
            jwk[WellKnownJwkMemberNames.Use] = use;
        }

        return jwk;
    }


    /// <summary>
    /// Issues a minimal, disclosure-free SD-JWT VC (no KB-JWT — this seam is about the issuer's own
    /// header) whose protected header carries <paramref name="keyId"/> as <c>kid</c> when supplied —
    /// <see langword="null"/> omits the header member entirely, exercising the sole-key selection
    /// branch — and, when supplied, <paramref name="x5c"/> as the RFC 7515 §4.1.6 certificate chain.
    /// The <c>iss</c> claim is <paramref name="issuerId"/> when supplied, or this class's fixed
    /// <see cref="IssuerId"/> otherwise — a real-wire test resolving JWT VC Issuer Metadata needs the
    /// credential's issuer identity to be the loopback host it published the document at.
    /// </summary>
    private async ValueTask<string> IssueIssuerOnlyCredentialAsync(
        PrivateKeyMemory issuerPrivateKey, string? keyId, string[]? x5c, CancellationToken cancellationToken, string? issuerId = null)
    {
        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: issuerId ?? IssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: TimeProvider.GetUtcNow(),
            holderConfirmation: [],
            claims: [new(EudiPid.SdJwt.FamilyName, "Mustermann")]);

        byte[] payloadBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(
            payload, TestSetup.DefaultSerializationOptions);

        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(
            issuerPrivateKey.Tag.Get<CryptoAlgorithm>(), issuerPrivateKey.Tag.Get<Purpose>());

        (SdTokenResult result, ReadOnlyMemory<byte> _) = await SdIssuance.IssueVerboseAsync(
            payloadBytes,
            disclosablePaths: new HashSet<CredentialPath>(),
            SdJwtPipeline.Redact,
            BuildIssuerSign(x5c, keyId),
            TestSalts.DefaultGenerator(),
            issuerPrivateKey,
            keyId ?? "unused-signing-key-id-placeholder",
            Pool,
            signingDelegate,
            hashAlgorithm: null,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());

        return SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// Builds a <see cref="SignPayloadDelegate"/> that signs the redacted SD-JWT payload as a compact
    /// JWS whose protected header carries <c>alg</c>, <c>typ</c>, <c>kid</c> = <paramref name="headerKeyId"/>
    /// when supplied — <see langword="null"/> omits the header member (RFC 7517 §4.5 makes <c>kid</c>
    /// optional), rather than the placeholder identifier <see cref="IssueIssuerOnlyCredentialAsync"/>
    /// hands <see cref="SdIssuance.IssueVerboseAsync"/> to satisfy that method's own non-empty check —
    /// and, when <paramref name="x5c"/> is supplied, the RFC 7515 §4.1.6 <c>x5c</c> chain — the header
    /// shape <see cref="SdJwtIssuerHeader"/> reads on the verifier side.
    /// </summary>
    private static SignPayloadDelegate BuildIssuerSign(string[]? x5c, string? headerKeyId)
    {
        return async (signingDelegate, redactedPayload, hashAlgorithm, mediaType, privateKey, keyId, memoryPool, cancellationToken) =>
        {
            string resolvedMediaType = string.IsNullOrEmpty(mediaType) ? WellKnownMediaTypes.Jwt.SdJwt : mediaType;
            string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

            JwtHeader header = new()
            {
                [WellKnownJwkMemberNames.Alg] = algorithm,
                [WellKnownJoseHeaderNames.Typ] = resolvedMediaType
            };

            if(headerKeyId is not null)
            {
                header[WellKnownJwkMemberNames.Kid] = headerKeyId;
            }

            if(x5c is not null)
            {
                header[WellKnownJwkMemberNames.X5c] = x5c;
            }

            byte[] headerBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);
            EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

            string headerSegment = encoder(headerBytes);
            string payloadSegment = encoder(redactedPayload.Span);

            int signingInputLength = headerSegment.Length + 1 + payloadSegment.Length;
            using IMemoryOwner<byte> signingInputOwner = memoryPool.Rent(signingInputLength);
            Memory<byte> signingInputMemory = signingInputOwner.Memory[..signingInputLength];

            int written = Encoding.ASCII.GetBytes(headerSegment, signingInputMemory.Span);
            signingInputMemory.Span[written] = (byte)'.';
            written += 1;
            _ = Encoding.ASCII.GetBytes(payloadSegment, signingInputMemory.Span[written..]);

            (Signature signature, CryptoEvent? cryptoEvent) = await signingDelegate(
                privateKey.AsReadOnlyMemory(),
                signingInputMemory,
                memoryPool,
                context: null,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            if(cryptoEvent is not null)
            {
                CryptographicKeyEvents.DefaultSink(cryptoEvent);
            }

            string signatureSegment = encoder(signature.AsReadOnlyMemory().Span);
            string compactJws = $"{headerSegment}.{payloadSegment}.{signatureSegment}";

            return Encoding.UTF8.GetBytes(compactJws);
        };
    }
}
