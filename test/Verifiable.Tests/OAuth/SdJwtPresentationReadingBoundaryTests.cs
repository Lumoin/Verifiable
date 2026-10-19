using Microsoft.Extensions.Time.Testing;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.StatusLists;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json.Sd;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusLists.StatusList;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the reading of an SD-JWT presentation (<see cref="SdJwtVpTokenVerification.VerifyAsync"/>) at its input boundary over
/// presentations the rows' Issuer and Wallet write by hand and sign once: the Issuer-signed claims set's <c>status</c> claim read
/// by its decoded name (RFC 8259 section 8.3), its <c>status_list</c> likewise, and a compact serialization, a payload segment or
/// a confirmation key the reading refuses answered as the reading's refusal, never thrown out of it.
/// </summary>
[TestClass]
internal sealed class SdJwtPresentationReadingBoundaryTests
{
    /// <summary>The per-test context, source of the cancellation token every asynchronous call takes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The issuer identifier the presentations' credentials are issued under.</summary>
    private const string IssuerId = "https://issuer.example.com";

    /// <summary>The Status List Token URI the credentials reference.</summary>
    private const string StatusListUri = "https://issuer.example.com/statuslists/1";

    /// <summary>The credential query the presentations answer.</summary>
    private static CredentialQueryId QueryId { get; } = new("pid");

    /// <summary>The clock the presentations' instants and the status check read.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The pool every reading rents from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// RFC 8259 section 8.3: a member name written with an escape is the name it decodes to, so a claims set whose <c>status</c>
    /// claim is so written carries the status claim. One whose value is no object, or an object naming no mechanism, fails Token
    /// Status List section 6.1 and refuses the presentation, never read as a credential carrying no status claim.
    /// </summary>
    /// <param name="statusValue">The escaped status claim's value, as the Issuer writes it.</param>
    /// <returns>A task completing once the presentation is read.</returns>
    [TestMethod]
    [DataRow(/*lang=json,strict*/ "{}", DisplayName = "An object naming no mechanism")]
    [DataRow(/*lang=json,strict*/ "\"revoked\"", DisplayName = "A string")]
    public async Task AnEscapedStatusClaimOutsideItsRulesRefusesThePresentation(string statusValue)
    {
        var issued = await IssueAsync("\"sta\\u0074us\":" + statusValue).ConfigureAwait(false);
        using var issuerKey = issued.IssuerPublicKey;

        var read = await ReadAsync(issued.Presentation, issuerKey).ConfigureAwait(false);

        Assert.IsFalse(read.IsSuccess, "The escaped status claim is the status claim, and it is malformed.");
        Assert.AreEqual(SdJwtPresentationDefect.StatusClaimMalformed, read.Error);
    }


    /// <summary>
    /// The escaped <c>status</c> claim carrying a <c>status_list</c> reference that meets Token Status List section 6.2 is read
    /// as that reference, and the status check resolves the Status List Token it names, the URI and the index the Issuer wrote.
    /// </summary>
    /// <returns>A task completing once the status is checked.</returns>
    [TestMethod]
    public async Task AnEscapedStatusClaimCarryingAReferenceReachesTheStatusResolver()
    {
        var issued = await IssueAsync("\"sta\\u0074us\":{\"status_list\":{\"idx\":3,\"uri\":\"" + StatusListUri + "\"}}").ConfigureAwait(false);
        using var issuerKey = issued.IssuerPublicKey;

        await AssertTheReferenceReachesTheResolverAsync(issued.Presentation, issuerKey).ConfigureAwait(false);
    }


    /// <summary>
    /// The same holds a level down: a <c>status</c> claim whose <c>status_list</c> mechanism name is written with an escape names
    /// the Token Status List mechanism, never an unevaluable one, and its reference reaches the resolver.
    /// </summary>
    /// <returns>A task completing once the status is checked.</returns>
    [TestMethod]
    public async Task AnEscapedStatusListMechanismNameReachesTheStatusResolver()
    {
        var issued = await IssueAsync("\"status\":{\"status_\\u006cist\":{\"idx\":3,\"uri\":\"" + StatusListUri + "\"}}").ConfigureAwait(false);
        using var issuerKey = issued.IssuerPublicKey;

        await AssertTheReferenceReachesTheResolverAsync(issued.Presentation, issuerKey).ConfigureAwait(false);
    }


    /// <summary>
    /// RFC 9901 section 4: a presentation is the compact serialization of an SD-JWT with its Key Binding JWT. A presentation the
    /// wire format's parse refuses, and one whose Key Binding JWT carries a payload segment that is no base64url text, are
    /// refused by the reading as presentations no conformant Wallet produces, answered rather than thrown. The credential binds a holder key, so the Key Binding JWT is read.
    /// </summary>
    /// <param name="presentationCase">The name of the presentation the row reads.</param>
    /// <returns>A task completing once the presentation is read.</returns>
    [TestMethod]
    [DataRow("no-separator", DisplayName = "No SD-JWT separator")]
    [DataRow("key-binding-payload-no-base64url", DisplayName = "A Key Binding JWT payload segment that is no base64url text")]
    public async Task ACorruptCompactPresentationIsRefusedByTheReading(string presentationCase)
    {
        using var holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = holderKey.ExportParameters(includePrivateParameters: false).Q;
        var x = point.X ?? throw new InvalidOperationException("An exported P-256 key carries its x coordinate.");
        var y = point.Y ?? throw new InvalidOperationException("An exported P-256 key carries its y coordinate.");
        var jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + Base64Url.EncodeToString(x) + "\",\"y\":\"" + Base64Url.EncodeToString(y) + "\"}";
        var issued = await IssueWithConfirmationKeyAsync(jwk).ConfigureAwait(false);
        using var issuerKey = issued.IssuerPublicKey;

        var presentation = presentationCase switch
        {
            "no-separator" => issued.IssuerSignedJwt,
            "key-binding-payload-no-base64url" => issued.IssuerSignedJwt + "~" + KeyBindingHeaderSegment() + ".A." + Base64Url.EncodeToString("signature"u8),
            _ => throw new ArgumentOutOfRangeException(nameof(presentationCase), presentationCase, "No presentation is named so.")
        };

        var read = await ReadAsync(presentation, issuerKey).ConfigureAwait(false);

        Assert.IsFalse(read.IsSuccess, presentationCase);
        Assert.AreEqual(SdJwtPresentationDefect.CompactSerializationMalformed, read.Error, presentationCase);
    }


    /// <summary>
    /// RFC 7800 section 3.2 and NIST SP 800-186 appendix D.1.1.1: a <c>cnf.jwk</c> whose coordinates are of the curve's width but
    /// name no point of it states no holder key, so the reading refuses the presentation rather than verifying its Key Binding
    /// JWT under a key the coordinates do not state.
    /// </summary>
    /// <returns>A task completing once the presentation is read.</returns>
    [TestMethod]
    public async Task AConfirmationKeyNamingNoPointOfTheCurveRefusesThePresentation()
    {
        using var holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = holderKey.ExportParameters(includePrivateParameters: false).Q;
        var x = point.X ?? throw new InvalidOperationException("An exported P-256 key carries its x coordinate.");
        var y = point.Y ?? throw new InvalidOperationException("An exported P-256 key carries its y coordinate.");
        y[^1] ^= 0x01;

        var offCurveJwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + Base64Url.EncodeToString(x) + "\",\"y\":\"" + Base64Url.EncodeToString(y) + "\"}";
        var issued = await IssueWithConfirmationKeyAsync(offCurveJwk).ConfigureAwait(false);
        using var issuerKey = issued.IssuerPublicKey;
        var presentation = issued.IssuerSignedJwt + "~" + KeyBindingHeaderSegment() + "." + Base64Url.EncodeToString(/*lang=json,strict*/ """{"nonce":"n","aud":"a","iat":1}"""u8) + "." + Base64Url.EncodeToString(new byte[64]);

        var read = await ReadAsync(presentation, issuerKey).ConfigureAwait(false);

        Assert.IsFalse(read.IsSuccess, "A confirmation key naming no point of its curve states no holder key.");
        Assert.AreEqual(SdJwtPresentationDefect.ConfirmationKeyNotAPublicKey, read.Error);
    }


    /// <summary>
    /// Reads a presentation whose credential references the Status List Token at <see cref="StatusListUri"/>, index three, then
    /// runs the status check over it and asserts the resolver was asked for exactly that reference.
    /// </summary>
    /// <param name="presentation">The presentation.</param>
    /// <param name="issuerKey">The issuer key the trust framework resolves.</param>
    /// <returns>A task completing once the status is checked.</returns>
    private async Task AssertTheReferenceReachesTheResolverAsync(string presentation, PublicKeyMemory issuerKey)
    {
        var read = await ReadAsync(presentation, issuerKey).ConfigureAwait(false);

        Assert.IsTrue(read.IsSuccess, "The presentation reads.");
        Assert.AreEqual(StatusListUri, read.Value.Credential.Status?.StatusList?.Uri, "The status claim's reference is read.");

        using var statusList = StatusListType.Create(16, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var (resolve, contexts) = StatusListFixtures.RecordingResolverFor(StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider));

        _ = await VpTokenCredentialStatus.CheckAsync(
            read.Value, QueryId, resolve, TimeProvider.GetUtcNow(), null, null,
            UnsupportedStatusMechanismDisposition.Refuse, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, contexts, "The status check resolves the Status List Token the reference names.");
        Assert.AreEqual(StatusListUri, contexts[0].Reference.Uri);
        Assert.AreEqual(3, contexts[0].Reference.Index);
    }


    /// <summary>Reads a presentation with the library's own seams and a trust framework resolving the issuer key given.</summary>
    /// <param name="presentation">The presentation.</param>
    /// <param name="issuerKey">The issuer key.</param>
    /// <returns>The reading.</returns>
    private async Task<Result<VpTokenParsed, SdJwtPresentationDefect>> ReadAsync(string presentation, PublicKeyMemory issuerKey) =>
        await SdJwtVpTokenVerification.VerifyAsync(
            presentation,
            QueryId,
            static serialized => SdJwtSerializer.ParseToken(serialized, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag, WellKnownHashAlgorithms.Sha256Iana),
            static token => SdJwtSerializer.GetSdJwtForHashing(token, TestSetup.Base64UrlEncoder),
            (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(issuerKey),
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// The Issuer writes a credential's claims set by hand - its <c>iss</c>, <c>vct</c>, <c>iat</c> and the further members given,
    /// written as given - and signs it once under a fresh P-256 key; the credential carries no disclosure, so the presentation is
    /// the Issuer-signed JWT and its separator.
    /// </summary>
    /// <param name="furtherMembers">The further members' JSON text.</param>
    /// <returns>The issued credential.</returns>
    private Task<HandIssuedCredential> IssueAsync(string furtherMembers) =>
        IssueClaimsAsync("\"iss\":\"" + IssuerId + "\",\"vct\":\"urn:eudi:pid:1\",\"iat\":1700000000," + furtherMembers);


    /// <summary>The Issuer writes a credential whose <c>cnf.jwk</c> is the JWK text given and signs it once.</summary>
    /// <param name="jwkJson">The confirmation key's JSON text.</param>
    /// <returns>The issued credential.</returns>
    private Task<HandIssuedCredential> IssueWithConfirmationKeyAsync(string jwkJson) =>
        IssueClaimsAsync("\"iss\":\"" + IssuerId + "\",\"vct\":\"urn:eudi:pid:1\",\"iat\":1700000000,\"_sd_alg\":\"sha-256\",\"cnf\":{\"jwk\":" + jwkJson + "}");


    /// <summary>Signs a claims set of the members given under a fresh P-256 Issuer key, over its exact bytes.</summary>
    /// <param name="members">The claims set's members' JSON text.</param>
    /// <returns>The issued credential.</returns>
    private async Task<HandIssuedCredential> IssueClaimsAsync(string members)
    {
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var issuerPrivateKey = issuerKeys.PrivateKey;

        var header = Base64Url.EncodeToString(/*lang=json,strict*/ """{"alg":"ES256","typ":"dc+sd-jwt"}"""u8);
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes("{" + members + "}"));
        var signingInput = header + "." + payload;

        using var signature = await issuerPrivateKey.SignAsync(Encoding.ASCII.GetBytes(signingInput), Pool, TestContext.CancellationToken).ConfigureAwait(false);
        var issuerSignedJwt = signingInput + "." + Base64Url.EncodeToString(signature.AsReadOnlySpan());

        return new HandIssuedCredential(issuerSignedJwt, issuerSignedJwt + "~", issuerKeys.PublicKey);
    }


    /// <summary>The protected header segment of a Key Binding JWT (RFC 9901 section 4.3): <c>typ</c> <c>kb+jwt</c> under ES256.</summary>
    /// <returns>The segment.</returns>
    private static string KeyBindingHeaderSegment() => Base64Url.EncodeToString(/*lang=json,strict*/ """{"alg":"ES256","typ":"kb+jwt"}"""u8);
}


/// <summary>A credential an Issuer wrote by hand and signed once.</summary>
/// <param name="IssuerSignedJwt">The Issuer-signed JWT.</param>
/// <param name="Presentation">The presentation of it carrying no disclosure and no Key Binding JWT.</param>
/// <param name="IssuerPublicKey">The Issuer's public key, which the caller disposes.</param>
internal sealed record HandIssuedCredential(string IssuerSignedJwt, string Presentation, PublicKeyMemory IssuerPublicKey);
