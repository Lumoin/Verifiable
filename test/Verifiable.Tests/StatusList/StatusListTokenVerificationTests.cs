using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.StatusList;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// The Relying Party's read of a Status List Token in JWT format — Section 8.3 step 3 ("Validate the Status
/// List Token") over the Section 5.1 rules. Every input here is a JWT this class composes by hand through the
/// JOSE signing seams from a header and a claims set it writes itself, so no expectation is borrowed from the
/// composition or the claims mapping the read shares; the Section 5.1 example
/// ({"alg":"ES256","kid":"12","typ":"statuslist+jwt"} over a <c>status_list</c> of <c>{"bits":1,"lst":
/// "eNrbuRgAAhcBXQ"}</c>) is the shape they are written to.
/// </summary>
/// <remarks>
/// Section 8.3 splits into two layers and so do these tests: steps 3.a/3.b and the Section 5.1 value rules —
/// the compact shape, the header, the signature, the required claims, and <c>sub</c> — are the read's, while
/// steps 4.b through 7 (freshness, expiry, caching, the index lookup) belong to the format-independent status
/// gate and are proved in its own tests. See
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
/// List, Section 8.3</see>.
/// </remarks>
[TestClass]
internal sealed class StatusListTokenVerificationTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The pool every pooled carrier in this class is rented from and returned to.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The Status List Token's URI, the Section 5.1 example's <c>sub</c>.</summary>
    private const string Subject = StatusListTestConstants.ExampleTokenSubject;

    /// <summary>The <c>kid</c> every hand-composed header of this class carries, from the Section 5.1 example.</summary>
    private const string KeyId = "12";

    /// <summary>The Section 5.1 example's <c>iat</c>, seconds since the epoch.</summary>
    private const long ExampleIssuedAt = 1686920170;

    /// <summary>The Section 5.1 example's <c>exp</c>, seconds since the epoch.</summary>
    private const long ExampleExpiration = 2291720170;

    /// <summary>The Section 5.1 example's <c>ttl</c>, in seconds.</summary>
    private const long ExampleTimeToLive = 43200;

    /// <summary>
    /// The Section 5.1 example's <c>lst</c>: the base64url-encoded, compressed one-bit Status List whose
    /// statuses are [1,0,0,1,1,1,0,1, 1,1,0,0,0,1,0,1].
    /// </summary>
    private const string ExampleList = "eNrbuRgAAhcBXQ";

    /// <summary>The Section 5.1 example's <c>bits</c>: a one-bit Status List.</summary>
    private const long ExampleBits = 1;

    /// <summary>An index the Section 5.1 example's Status List sets to <see cref="StatusTypes.Invalid"/>.</summary>
    private const int RevokedIndex = 0;

    /// <summary>An index the Section 5.1 example's Status List leaves at <see cref="StatusTypes.Valid"/>.</summary>
    private const int ValidIndex = 1;

    /// <summary>The <c>typ</c> of the CWT sibling format, which the JWT read refuses.</summary>
    private const string StatusListCwtType = "statuslist+cwt";

    /// <summary>A payload that is deliberately not JSON at all, used to order the signature check against the claims read.</summary>
    private static ReadOnlySpan<byte> NotJsonPayload => "not-json"u8;

    /// <summary>The read's own exit for a token that satisfies every Section 5.1 rule.</summary>
    private const string VerifiedPath = "verified";

    /// <summary>The read's exit for a token whose signature does not check out under the resolved key.</summary>
    private const string SignatureInvalidPath = "signature-invalid";

    /// <summary>The read's exit for a header <c>alg</c> that does not match the resolved key's own algorithm.</summary>
    private const string AlgorithmMismatchPath = "algorithm-mismatch";

    /// <summary>The read's exit for a token that verifies but withholds a Section 5.1 REQUIRED claim.</summary>
    private const string ClaimsFailurePath = "claims-failure";


    /// <summary>
    /// "3.  Validate the Status List Token: a. Validate the Status List Token by following the rules defined
    /// in Section 7.2 of [RFC7519] for JWTs … b.  Check for the existence of the required claims as defined in
    /// Section 5.1" — a Status List Token that satisfies every one of those rules verifies, and the claims it
    /// carries come back as read.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task WellFormedStatusListTokenVerifiesAndCarriesItsClaims()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(
            BuildHeader(),
            BuildPayload(expiration: ExampleExpiration, timeToLive: ExampleTimeToLive),
            issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"A Section 5.1-conforming Status List Token MUST verify; the read reported '{result.Defect}'.");
        using StatusListType statusList = result.Token!.StatusList;

        Assert.AreEqual(Subject, result.Token.Subject, "Section 5.1's sub claim is the URI of the Status List Token.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(ExampleIssuedAt), result.Token.IssuedAt, "Section 5.1's iat claim is the issuance instant.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(ExampleExpiration), result.Token.ExpirationTime, "Section 5.1's exp claim is read when present.");
        Assert.AreEqual(ExampleTimeToLive, result.Token.TimeToLive, "Section 5.1's ttl claim is read when present.");
    }


    /// <summary>
    /// "typ: REQUIRED.  The JWT type MUST be statuslist+jwt." — a Status List Token whose header omits the
    /// type declares no type at all and is refused.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWithoutATypeHeaderIsRefused()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeaderWithType(null), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A Status List Token without a typ header MUST be refused.");
        Assert.AreEqual(StatusListTokenVerificationFailure.TypeMismatch, result.Failure, "Section 5.1 makes typ REQUIRED.");
    }


    /// <summary>
    /// "typ: REQUIRED.  The JWT type MUST be statuslist+jwt." — the generic <c>JWT</c> type RFC 7519 §5.1
    /// recommends for a plain JWT is not the type Section 5.1 requires, so a token carrying it is refused
    /// rather than read as a Status List Token.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-5.1">RFC 7519, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenTypedAsAPlainJwtIsRefused()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeaderWithType("JWT"), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A typ of 'JWT' is not the statuslist+jwt type Section 5.1 requires.");
        Assert.AreEqual(StatusListTokenVerificationFailure.TypeMismatch, result.Failure, "Section 5.1 pins the JWT type to statuslist+jwt.");
    }


    /// <summary>
    /// "typ: REQUIRED.  The JWT type MUST be statuslist+jwt." read together with RFC 7515's own rule for the
    /// header parameter that carries it — "Per RFC 2045 [RFC2045], all media type values, subtype values, and
    /// parameter names are case insensitive." — so an issuer that spells the media type in upper case still
    /// declares the type Section 5.1 requires and the token is accepted.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515, Section 4.1.9</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenTypedInUpperCaseIsAccepted()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeaderWithType("STATUSLIST+JWT"), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"Media type values are case insensitive, so 'STATUSLIST+JWT' is the required type; the read reported '{result.Defect}'.");
        result.Token!.StatusList.Dispose();
    }


    /// <summary>
    /// "typ: REQUIRED.  The JWT type MUST be statuslist+jwt." — the CWT format's own type belongs to Section
    /// 5.2, and an SD-JWT VC's status reference resolves a JWT-format token only: "When the status claim is
    /// present and using the status_list mechanism, the associated Status List Token MUST be in JWT format."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-3.2.2.2">SD-JWT VC, the status claim</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenTypedAsTheCwtFormIsRefused()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeaderWithType(StatusListCwtType), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A statuslist+cwt type is not the JWT format this read establishes.");
        Assert.AreEqual(StatusListTokenVerificationFailure.TypeMismatch, result.Failure, "Section 5.1 pins the JWT type to statuslist+jwt.");
    }


    /// <summary>
    /// "typ: REQUIRED.  The JWT type MUST be statuslist+jwt." is checked against the protected header
    /// before any key is resolved and before the payload is ever decoded: a token typed as a plain
    /// <c>JWT</c> whose payload is not even JSON is refused on its <c>typ</c>, not on unreadable
    /// claims, and the resolver this read would otherwise ask for a key is never invoked.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWithTheWrongTypeIsRefusedBeforeAnyClaimIsRead()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignRawPayloadAsync(BuildHeaderWithType("JWT"), NotJsonPayload.ToArray(), issuerPrivate).ConfigureAwait(false);

        int resolverCalls = 0;
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
        {
            resolverCalls++;

            return ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(issuerPublic));
        };

        StatusListTokenVerificationResult result = await VerifyAsync(compact, resolveIssuerKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A 'typ' of plain JWT is not the statuslist+jwt type Section 5.1 requires.");
        Assert.AreEqual(StatusListTokenVerificationFailure.TypeMismatch, result.Failure, "The refusal is TypeMismatch, not ClaimsUnreadable — typ is checked before the payload is ever decoded.");
        Assert.AreEqual(0, resolverCalls, "The header is refused before any key is resolved for it.");
    }


    /// <summary>
    /// "2.  The JWT MUST be secured using a cryptographic signature or MAC algorithm." — the unsecured
    /// <c>none</c> algorithm secures nothing, so the token is refused before the Relying Party is even asked
    /// to name a key for it: the resolver records no invocation.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWithTheNoneAlgorithmIsRefusedBeforeTheIssuerKeyIsResolved()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeaderWithAlgorithm(WellKnownJwaValues.None), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        int resolverCalls = 0;
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
        {
            resolverCalls++;

            return ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(issuerPublic));
        };

        StatusListTokenVerificationResult result = await VerifyAsync(compact, resolveIssuerKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "An 'alg' of 'none' secures nothing and MUST be refused.");
        Assert.AreEqual(StatusListTokenVerificationFailure.AlgorithmUnsupported, result.Failure, "Section 5.1 rule 2 requires a signature or MAC algorithm.");
        Assert.AreEqual(0, resolverCalls, "No key is resolved for a token that is already refused on its algorithm.");
    }


    /// <summary>
    /// "3.  Relying Parties MUST reject JWTs that are not valid in all other respects per "JSON Web Token
    /// (JWT)" [RFC7519]." — RFC 7519's own validation says "5.  Verify that the resulting JOSE Header includes
    /// only parameters and values whose syntax and semantics are both understood and supported or that are
    /// specified as being ignored when not understood." and "If any of the listed steps fail, then the JWT
    /// MUST be rejected", so an <c>alg</c> the algorithm registry does not know is a refusal even when a key
    /// resolves and its own signature checks out.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519, Section 7.2</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWithAnUnknownAlgorithmIsRefused()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeaderWithAlgorithm("NOT-A-REGISTERED-ALG"), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        if(result.IsVerified)
        {
            result.Token!.StatusList.Dispose();
        }

        Assert.IsFalse(result.IsVerified, "An 'alg' whose semantics are not understood MUST be rejected per RFC 7519 Section 7.2 step 5.");
        Assert.AreEqual(StatusListTokenVerificationFailure.AlgorithmUnsupported, result.Failure, "An unknown algorithm is an unsupported algorithm.");
    }


    /// <summary>
    /// "3.  Relying Parties MUST reject JWTs that are not valid in all other respects per "JSON Web
    /// Token (JWT)" [RFC7519]." — an <c>alg</c> the resolved issuer key does not itself carry is
    /// algorithm confusion: a header naming a MAC algorithm over a token actually signed by an EC
    /// private key must be refused on the mismatch, and the signature — which would in fact verify
    /// under the real ES256 bytes if it were reached — is never checked.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWhoseAlgorithmNamesAMacOverTheResolvedEcKeyIsRefused()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        //The token is genuinely signed with the P-256 private key (ES256 bytes); only the header's own
        //'alg' claims HS256 over it.
        string compact = await SignAsync(BuildHeaderWithAlgorithm(WellKnownJwaValues.Hs256), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        int resolverCalls = 0;
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
        {
            resolverCalls++;

            return ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(issuerPublic));
        };

        StatusListTokenVerificationResult result = await VerifyAsync(compact, resolveIssuerKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A header 'alg' that does not match the resolved key's own algorithm MUST be refused.");
        Assert.AreEqual(StatusListTokenVerificationFailure.AlgorithmUnsupported, result.Failure, "Algorithm confusion is an unsupported-algorithm refusal.");
        Assert.AreEqual(1, resolverCalls, "The issuer key is resolved once — the mismatch is only detectable once a key is in hand.");
    }


    /// <summary>
    /// "Relying Parties MUST reject JWTs with an invalid signature." — the refusal lands before a single claim
    /// is read: the payload of this token is not JSON at all, and the read still reports the signature, not
    /// the unreadable claims, because it never reached them.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519, Section 7.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AnInvalidSignatureIsRefusedBeforeAnyClaimIsRead()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> otherKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory otherPublic = otherKeys.PublicKey;
        using PrivateKeyMemory otherPrivate = otherKeys.PrivateKey;

        string compact = await SignRawPayloadAsync(BuildHeader(), NotJsonPayload.ToArray(), otherPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A JWT with an invalid signature MUST be rejected.");
        Assert.AreEqual(
            StatusListTokenVerificationFailure.SignatureInvalid,
            result.Failure,
            "The signature is checked before the payload, so a signature failure — not an unreadable claims set — is what a token signed by a foreign key reports.");
    }


    /// <summary>
    /// "10.  Verify that the resulting octet sequence is a UTF-8-encoded representation of a completely valid
    /// JSON object conforming to RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object." and "If any
    /// of the listed steps fail, then the JWT MUST be rejected" — the same non-JSON payload, this time
    /// correctly signed, gets past the signature and is refused on the claims set instead. Together with its
    /// sibling above this pins the order: signature first, claims second.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519, Section 7.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ACorrectlySignedNonJsonPayloadIsRefusedAsAnUnreadableClaimsSet()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignRawPayloadAsync(BuildHeader(), NotJsonPayload.ToArray(), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A payload that is not a valid JSON object MUST be rejected.");
        Assert.AreEqual(
            StatusListTokenVerificationFailure.ClaimsUnreadable,
            result.Failure,
            "With the signature valid the read reaches the claims set and refuses there.");
    }


    /// <summary>
    /// "a.  Validate the Status List Token by following the rules defined in Section 7.2 of [RFC7519] for
    /// JWTs … This step might require the resolution of a public key as described in Section 11.3." — when the
    /// Relying Party trusts no key for this Status List Token there is nothing to validate the signature
    /// against, so the read stops there: the resolver is asked exactly once and the token is unverifiable.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AResolverThatNamesNoKeyLeavesTheTokenUnverifiable()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeader(), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        int resolverCalls = 0;
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
        {
            resolverCalls++;

            return ValueTask.FromResult<ResolvedStatusListIssuerKey?>(null);
        };

        StatusListTokenVerificationResult result = await VerifyAsync(compact, resolveIssuerKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A Status List Token whose issuer key the Relying Party does not trust MUST NOT verify.");
        Assert.AreEqual(StatusListTokenVerificationFailure.IssuerKeyUnresolved, result.Failure, "There is no key to check the signature against.");
        Assert.AreEqual(1, resolverCalls, "The read asks for the issuer key exactly once.");
    }


    /// <summary>
    /// "a.  Validate the Status List Token … This step might require the resolution of a public key as
    /// described in Section 11.3." — the Relying Party's key resolution is keyed on the URI the token was
    /// fetched for and on the token's own protected header, so both reach the resolver, the header carrying
    /// the <c>kid</c> the Status Issuer wrote.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TheResolverReceivesTheFetchedUriAndTheProtectedHeader()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeader(), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        string? seenUri = null;
        object? seenKeyId = null;
        bool isKeyIdPresent = false;
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (context, cancellationToken) =>
        {
            seenUri = context.StatusListUri;
            isKeyIdPresent = context.Header.TryGetValue(WellKnownJwkMemberNames.Kid, out seenKeyId);

            return ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(issuerPublic));
        };

        StatusListTokenVerificationResult result = await VerifyAsync(compact, resolveIssuerKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"The token is otherwise conforming; the read reported '{result.Defect}'.");
        result.Token!.StatusList.Dispose();

        Assert.AreEqual(Subject, seenUri, "The URI the Status List Token was fetched for is what the key resolution is keyed on.");
        Assert.IsTrue(isKeyIdPresent, "The protected header the resolver sees carries the Status Issuer's kid.");
        Assert.AreEqual(KeyId, seenKeyId, "The kid the resolver sees is the one the Status Issuer wrote.");
    }


    /// <summary>
    /// "sub: REQUIRED. … The value MUST be equal to that of the uri claim contained in the status_list claim
    /// of the Referenced Token." — a token published at one URI but claiming another subject is refused, which
    /// is what stops a valid Status List Token being replayed as the answer for a different list.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWhoseSubjectDiffersFromTheFetchedUriIsRefused()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(
            BuildHeader(),
            BuildPayload(subject: StatusListTestConstants.MismatchedSubject),
            issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A sub that is not the URI the token was fetched for MUST be refused.");
        Assert.AreEqual(StatusListTokenVerificationFailure.SubjectMismatch, result.Failure, "Section 5.1 pins sub to the Status List Token's own URI.");
    }


    /// <summary>
    /// A subject-mismatch refusal reaches this method only after <c>TryFromPayload</c> already
    /// decoded and rented the Status List <c>status_list.lst</c> carries; the pooled buffer that read
    /// minted must be released on this refusal path, not held onto by a result the caller never gets a
    /// reference to.
    /// </summary>
    [TestMethod]
    public async Task ASubjectMismatchRefusalReleasesTheAlreadyDecodedStatusList()
    {
        using var metered = new MeteredHousePool();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(
            BuildHeader(),
            BuildPayload(subject: StatusListTestConstants.MismatchedSubject),
            issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await StatusListTokenVerification.VerifyAsync(
            compact, ContextFor(Subject), KeyFor(issuerPublic), TestSetup.Base64UrlDecoder, JwtPartJson.Default, metered.Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A sub that is not the URI the token was fetched for MUST be refused.");
        Assert.AreEqual(0L, metered.OutstandingCount, "The Status List TryFromPayload already decoded must be released on the subject-mismatch refusal.");
    }


    /// <summary>
    /// "b.  Check for the existence of the required claims as defined in Section 5.1" for "sub: REQUIRED. …
    /// The sub (subject) claim MUST specify the URI of the Status List Token." — the refusal names the claim
    /// so the Relying Party can say what was wrong with the token it fetched.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWithoutTheSubjectClaimIsRefusedNamingIt()
    {
        await AssertRequiredClaimRefusedAsync(WellKnownJwtClaimNames.Sub).ConfigureAwait(false);
    }


    /// <summary>
    /// "b.  Check for the existence of the required claims as defined in Section 5.1" for "iat: REQUIRED. …
    /// The iat (issued at) claim MUST specify the time at which the Status List Token was issued." — without
    /// it the freshness policy of step 4.b would have nothing to check.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWithoutTheIssuedAtClaimIsRefusedNamingIt()
    {
        await AssertRequiredClaimRefusedAsync(WellKnownJwtClaimNames.Iat).ConfigureAwait(false);
    }


    /// <summary>
    /// "b.  Check for the existence of the required claims as defined in Section 5.1" for "status_list:
    /// REQUIRED.  The status_list (status list) claim MUST specify the Status List conforming to the structure
    /// defined in Section 4.2." — a Status List Token with no Status List states nothing about any index.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWithoutTheStatusListClaimIsRefusedNamingIt()
    {
        await AssertRequiredClaimRefusedAsync(WellKnownJwtClaimNames.StatusList).ConfigureAwait(false);
    }


    /// <summary>
    /// "ttl: RECOMMENDED. … The value of the claim MUST be a positive number encoded in JSON as a number." — a
    /// zero or negative caching duration is not a positive number, so the token is refused on the value rather
    /// than silently cached for no time at all.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    /// <param name="timeToLive">The non-positive <c>ttl</c> value under test.</param>
    [TestMethod]
    [DataRow(0)]
    [DataRow(-1)]
    public async Task TokenWithANonPositiveTimeToLiveIsRefused(int timeToLive)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeader(), BuildPayload(timeToLive: timeToLive), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A ttl that is not a positive number MUST be refused.");
        Assert.AreEqual(StatusListTokenVerificationFailure.ClaimValueInvalid, result.Failure, "Section 5.1 requires ttl to be a positive number.");
    }


    /// <summary>
    /// "1.  The JWT MAY contain other claims." — the Section 5.1 example itself carries an <c>iss</c> claim
    /// the section does not list, so claims beyond the five named ones are carried, not refused.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ClaimsBeyondTheSectionsOwnAreTolerated()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        JwtPayload payload = BuildPayload();
        payload[WellKnownJwtClaimNames.Iss] = "https://example.com";

        string compact = await SignAsync(BuildHeader(), payload, issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"A Status List Token MAY contain other claims; the read reported '{result.Defect}'.");
        result.Token!.StatusList.Dispose();
    }


    /// <summary>
    /// "1.   Verify that the JWT contains at least one period ('.') character." through "If any of the listed
    /// steps fail, then the JWT MUST be rejected -- that is, treated by the application as an invalid input."
    /// — a compact serialization that is not three non-empty segments never reaches a key, a signature, or a
    /// claim.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519, Section 7.2</see>.
    /// </summary>
    /// <param name="compact">The malformed compact serialization under test.</param>
    [TestMethod]
    [DataRow("aaaa.bbbb")]
    [DataRow("aaaa.bbbb.cccc.dddd")]
    [DataRow("aaaa..cccc")]
    public async Task MalformedCompactSerializationIsRefused(string compact)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        int resolverCalls = 0;
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
        {
            resolverCalls++;

            return ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(issuerPublic));
        };

        StatusListTokenVerificationResult result = await VerifyAsync(compact, resolveIssuerKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "An input that is not a compact JWS MUST be rejected.");
        Assert.AreEqual(StatusListTokenVerificationFailure.MalformedCompactSerialization, result.Failure, "RFC 7519 Section 7.2 rejects the input on its shape.");
        Assert.AreEqual(0, resolverCalls, "A structurally malformed input never reaches the Relying Party's key resolution.");
    }


    /// <summary>
    /// "3.   Base64url decode the Encoded JOSE Header following the restriction that no line breaks,
    /// whitespace, or other additional characters have been used." and "If any of the listed steps fail, then
    /// the JWT MUST be rejected" — a protected header segment that is not base64url decodes to nothing, so the
    /// token is refused on its unreadable header.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519, Section 7.2</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenWithANonBase64UrlHeaderSegmentIsRefused()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        StatusListTokenVerificationResult result = await VerifyAsync("!!!!.eyJhIjoxfQ.c2lnbmF0dXJl", KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A JOSE Header segment that does not base64url-decode MUST be rejected.");
        Assert.AreEqual(
            StatusListTokenVerificationFailure.HeaderUnreadable,
            result.Failure,
            "The shape check passes on three non-empty segments, so the refusal lands where the decode fails.");
    }


    /// <summary>
    /// "1.   Verify that the JWT contains at least one period ('.') character." — an empty input is not a JWT
    /// at all but a caller passing nothing, and is refused as such rather than reported as a token defect.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519, Section 7.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyCompactSerializationIsRefusedAsAnArgument()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await VerifyAsync(string.Empty, KeyFor(issuerPublic)).ConfigureAwait(false),
            "An empty string carries no JWT to validate.").ConfigureAwait(false);
    }


    /// <summary>
    /// Per RFC 8725 §3.11, an input beyond the accepted maximum length is refused on its length alone,
    /// before any base64url decode is attempted — a Status Provider that ignores the fetch's size hint
    /// cannot make the Relying Party decode an attacker-sized input first.
    /// </summary>
    [TestMethod]
    public async Task AnInputLongerThanTheAcceptedMaximumIsRefused()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeader(), BuildPayload(), issuerPrivate).ConfigureAwait(false);
        string[] segments = compact.Split('.');
        string oversized = string.Concat(
            segments[0],
            ".",
            segments[1],
            new string('A', Jws.DefaultMaxJwsLength),
            ".",
            segments[2]);

        StatusListTokenVerificationResult result = await VerifyAsync(oversized, KeyFor(issuerPublic)).ConfigureAwait(false);

        if(result.IsVerified)
        {
            result.Token!.StatusList.Dispose();
        }

        Assert.IsFalse(result.IsVerified, "An oversized input MUST be rejected rather than verified.");
        Assert.AreEqual(
            StatusListTokenVerificationFailure.InputTooLong,
            result.Failure,
            "The length bound is checked before any decode is attempted, ahead of the signature check.");
    }


    /// <summary>
    /// "c.  If the expiration time is defined (exp or 4), it MUST be checked if the Status List Token is
    /// expired" is step 4.c — the format-independent evaluation against a Referenced Token's reference, not
    /// step 3's validation of the token itself. A Status List Token whose <c>exp</c> has passed is therefore
    /// still a valid Status List Token in JWT format; it is the status gate that refuses to state a status
    /// from it.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AnExpiredTokenStillVerifiesBecauseExpiryIsTheStatusGatesCheck()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        long expiredAt = ExampleIssuedAt + ExampleTimeToLive;
        string compact = await SignAsync(BuildHeader(), BuildPayload(expiration: expiredAt), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"Expiry is step 4.c's, not step 3's; the read reported '{result.Defect}'.");
        using StatusListType statusList = result.Token!.StatusList;

        Assert.AreEqual(
            DateTimeOffset.FromUnixTimeSeconds(expiredAt),
            result.Token.ExpirationTime,
            "The elapsed expiration time is read and carried for the status gate to act on.");
    }


    /// <summary>
    /// "5.  Decompress the Status List with a decompressor that is compatible with DEFLATE [RFC1951] and ZLIB
    /// [RFC1950]" / "6.  Retrieve the status value of the index specified in the Referenced Token as described
    /// in Section 4." — the Status List that survives the read is the Section 5.1 example's own, whose first
    /// entry is set and whose second is not.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TheVerifiedTokenCarriesTheStatusListBits()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeader(), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"The Section 5.1 example's own claims set MUST verify; the read reported '{result.Defect}'.");
        using StatusListType statusList = result.Token!.StatusList;

        Assert.AreEqual(StatusListBitSize.OneBit, statusList.BitSize, "Section 4.2's bits member states the Status List is one bit per entry.");
        Assert.AreEqual(StatusTypes.Invalid, statusList[RevokedIndex], "The example Status List's first entry is set.");
        Assert.AreEqual(StatusTypes.Valid, statusList[ValidIndex], "The example Status List's second entry is unset.");
    }


    /// <summary>
    /// Signs and verifies a Status List Token whose claims set omits <paramref name="omittedClaim"/>, and
    /// asserts the read refuses it naming that claim.
    /// </summary>
    /// <param name="omittedClaim">The REQUIRED Section 5.1 claim left out of the claims set.</param>
    private async Task AssertRequiredClaimRefusedAsync(string omittedClaim)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeader(), BuildPayload(omittedClaim: omittedClaim), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, $"A Status List Token without the REQUIRED '{omittedClaim}' claim MUST be refused.");
        Assert.AreEqual(StatusListTokenVerificationFailure.RequiredClaimMissing, result.Failure, "Section 8.3 step 3.b checks for the existence of the required claims.");
        Assert.Contains(omittedClaim, result.Defect!, StringComparison.Ordinal, "The refusal names the claim that was missing.");
    }


    /// <summary>
    /// "a.  Validate the Status List Token … This step might require the resolution of a public key as
    /// described in Section 11.3." — Section 11.3's first recommendation, "If the Issuer of the Referenced
    /// Token is the same entity as the Status Issuer, then the same key that is embedded into the Referenced
    /// Token may be used for the Status List Token.", is a decision only a key resolution that knows the
    /// Referenced Token can make, so the Referenced Token's verified issuer identity and the very key its own
    /// issuer signature verified under reach the resolution alongside the list URI, the key as the borrowed
    /// carrier the caller stated rather than a copy.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Section 11.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TheKeyResolutionSeesTheReferencedTokensIssuerAndVerifiedKey()
    {
        const string referencedTokenIssuer = "https://issuer.example/pid";

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> referencedTokenKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory referencedTokenIssuerKey = referencedTokenKeys.PublicKey;
        using PrivateKeyMemory unusedReferencedTokenPrivate = referencedTokenKeys.PrivateKey;

        string compact = await SignAsync(BuildHeader(), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        (ResolveStatusListIssuerKeyDelegate resolveIssuerKey, IReadOnlyList<StatusListKeyResolutionContext> seen) =
            StatusListFixtures.RecordingKeyResolverFor(KeyFor(issuerPublic));

        StatusListTokenVerificationResult result = await StatusListTokenVerification.VerifyAsync(
            compact,
            StatusListFixtures.ContextFor(new StatusListReference(RevokedIndex, Subject), referencedTokenIssuer, referencedTokenIssuerKey),
            resolveIssuerKey,
            TestSetup.Base64UrlDecoder,
            JwtPartJson.Default,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"The token is otherwise conforming; the read reported '{result.Defect}'.");
        result.Token!.StatusList.Dispose();

        Assert.HasCount(1, seen, "The read asks for the issuer key exactly once.");
        Assert.AreEqual(Subject, seen[0].StatusListUri,
            "The uri the Status List Token was fetched for is the reference's own uri, which step 4.a compares the verified sub against.");
        Assert.AreEqual(referencedTokenIssuer, seen[0].ReferencedTokenIssuer,
            "Section 11.3's alternative — 'the Status Issuer may use the same web-based key resolution that is used for the Referenced Token' — is keyed on the Referenced Token's issuer.");
        Assert.AreSame(referencedTokenIssuerKey, seen[0].ReferencedTokenIssuerKey,
            "Section 11.3's first recommendation answers 'the same key that is embedded into the Referenced Token', so the resolution borrows that very carrier.");
    }


    /// <summary>
    /// "When validating a JWT, the following steps are performed. … 5.  Verify that the resulting JOSE Header
    /// includes only parameters and values whose syntax and semantics are both understood and supported …
    /// 7.  … If the JWT is a JWS, follow the steps specified in [JWS] for validating a JWS." — the header is
    /// read at steps 2 through 5 and the signature is only checked at step 7, so everything the key resolution
    /// decides from is still attacker-controlled wire data at the moment it decides. It therefore arrives as an
    /// unverified header carrying exactly the <c>alg</c>, <c>typ</c> and <c>kid</c> the Status Issuer wrote,
    /// and nothing in it is a trust statement.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519, Section 7.2</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TheHeaderTheKeyResolutionSeesIsTheUnverifiedWireHeader()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeader(), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        (ResolveStatusListIssuerKeyDelegate resolveIssuerKey, IReadOnlyList<StatusListKeyResolutionContext> seen) =
            StatusListFixtures.RecordingKeyResolverFor(KeyFor(issuerPublic));

        StatusListTokenVerificationResult result = await VerifyAsync(compact, resolveIssuerKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"The token is otherwise conforming; the read reported '{result.Defect}'.");
        result.Token!.StatusList.Dispose();

        Assert.HasCount(1, seen, "The read asks for the issuer key exactly once.");

        UnverifiedJwtHeader header = seen[0].Header;

        Assert.IsTrue(header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algorithm),
            "RFC 7519 step 5 reads the JOSE Header's parameters, so the alg the token declares is what the key resolution sees.");
        Assert.AreEqual(WellKnownJwaValues.Es256, algorithm,
            "The Section 5.1 example's alg of ES256 reaches the resolution as the Status Issuer wrote it.");
        Assert.IsTrue(header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? type),
            "Section 5.1 makes typ REQUIRED, so it is part of the header the resolution decides from.");
        Assert.AreEqual(WellKnownMediaTypes.Jwt.StatusListJwt, type,
            "The Section 5.1 typ of statuslist+jwt reaches the resolution as the Status Issuer wrote it.");
        Assert.IsTrue(header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? keyId),
            "Section 11.3 names 'a kid parameter referencing to the same key as used in the Referenced Token', so the kid is what a resolution selects on.");
        Assert.AreEqual(KeyId, keyId,
            "The kid the resolution sees is the one the Status Issuer wrote.");
    }


    /// <summary>
    /// "sub: REQUIRED. … The value MUST be equal to that of the uri claim contained in the status_list claim
    /// of the Referenced Token." — the uri the comparison runs against is the Referenced Token's own
    /// <c>status_list</c> reference, which is what step 1 read out of the credential and step 2 resolved for.
    /// One and the same token therefore verifies for the reference naming its subject and is refused for a
    /// reference naming any other list, which is what stops a genuine Status List Token being answered for a
    /// list the credential never pointed at.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TheSubjectIsCheckedAgainstTheReferencedStatusListUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string compact = await SignAsync(BuildHeader(), BuildPayload(), issuerPrivate).ConfigureAwait(false);

        StatusListTokenVerificationResult matching = await VerifyAsync(compact, KeyFor(issuerPublic)).ConfigureAwait(false);

        Assert.IsTrue(matching.IsVerified, $"The token's sub is the referenced uri; the read reported '{matching.Defect}'.");
        matching.Token!.StatusList.Dispose();

        StatusListTokenVerificationResult mismatched = await StatusListTokenVerification.VerifyAsync(
            compact,
            ContextFor(StatusListTestConstants.MismatchedSubject),
            KeyFor(issuerPublic),
            TestSetup.Base64UrlDecoder,
            JwtPartJson.Default,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(mismatched.IsVerified, "A token whose sub is not the referenced list's uri MUST be refused.");
        Assert.AreEqual(StatusListTokenVerificationFailure.SubjectMismatch, mismatched.Failure,
            "Section 5.1 pins sub to the uri the Referenced Token's status_list claim carries, which the resolution context is what states.");
    }


    /// <summary>
    /// A key resolution that mints a key per call — a <c>did:web</c> document fetched and decoded on the spot,
    /// an X.509 chain validated into a fresh leaf key — hands the read a key nothing else holds, so the read is
    /// what releases it. Every exit past the resolution does, which is what keeps a Status List Token
    /// evaluation from leaking a pooled key buffer for each credential a relying party checks: a token that
    /// verifies, one whose signature does not check out, one whose <c>alg</c> does not match the resolved key,
    /// and one that verifies but withholds a Section 5.1 REQUIRED claim all end with the pool balanced.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> step 3.a.
    /// </summary>
    /// <param name="path">The verification exit the token under test is built to take.</param>
    [TestMethod]
    [DataRow(VerifiedPath)]
    [DataRow(SignatureInvalidPath)]
    [DataRow(AlgorithmMismatchPath)]
    [DataRow(ClaimsFailurePath)]
    public async Task AnOwnedIssuerKeyIsReleasedOnEveryVerificationPath(string path)
    {
        using var metered = new MeteredHousePool();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> strangerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory unusedStrangerPublic = strangerKeys.PublicKey;
        using PrivateKeyMemory strangerPrivate = strangerKeys.PrivateKey;

        (string compact, StatusListTokenVerificationFailure? expectedFailure) =
            await TokenTakingAsync(path, issuerPrivate, strangerPrivate).ConfigureAwait(false);

        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
            ValueTask.FromResult<ResolvedStatusListIssuerKey?>(StatusListFixtures.OwnedKeyOver(issuerPublic, metered.Pool));

        StatusListTokenVerificationResult result = await VerifyAsync(compact, resolveIssuerKey).ConfigureAwait(false);

        if(result.IsVerified)
        {
            result.Token!.StatusList.Dispose();
        }

        AssertTookThePath(path, expectedFailure, result);

        Assert.IsGreaterThan(0L, metered.RentedCount, "The resolution rented the key it answered with, so there is a release to observe.");
        Assert.AreEqual(0L, metered.OutstandingCount,
            $"An owned key MUST be released on the '{path}' exit, since Section 8.3 step 3.a's key resolution is the only thing holding it.");
    }


    /// <summary>
    /// The mirror: a key resolution answering from a key set it keeps alive itself — a tenant record, a trust
    /// list, the Referenced Token's own issuer key — only lends the key for the signature check, so the read
    /// must leave it alone on every exit. Releasing a borrowed key would return a buffer the resolver still
    /// holds and hand the next credential's evaluation a key over reclaimed memory.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> step 3.a.
    /// </summary>
    /// <param name="path">The verification exit the token under test is built to take.</param>
    [TestMethod]
    [DataRow(VerifiedPath)]
    [DataRow(SignatureInvalidPath)]
    [DataRow(AlgorithmMismatchPath)]
    [DataRow(ClaimsFailurePath)]
    public async Task ABorrowedIssuerKeyIsLeftAloneOnEveryVerificationPath(string path)
    {
        using var metered = new MeteredHousePool();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> strangerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory unusedStrangerPublic = strangerKeys.PublicKey;
        using PrivateKeyMemory strangerPrivate = strangerKeys.PrivateKey;

        (string compact, StatusListTokenVerificationFailure? expectedFailure) =
            await TokenTakingAsync(path, issuerPrivate, strangerPrivate).ConfigureAwait(false);

        //The resolver, not the read, owns this carrier for the whole evaluation, exactly as a key set does.
        ResolvedStatusListIssuerKey lent = StatusListFixtures.BorrowedKeyOver(issuerPublic, metered.Pool);
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
            ValueTask.FromResult<ResolvedStatusListIssuerKey?>(lent);

        StatusListTokenVerificationResult result = await VerifyAsync(compact, resolveIssuerKey).ConfigureAwait(false);

        if(result.IsVerified)
        {
            result.Token!.StatusList.Dispose();
        }

        AssertTookThePath(path, expectedFailure, result);

        Assert.AreEqual(1L, metered.OutstandingCount,
            $"A borrowed key MUST survive the '{path}' exit untouched, because the resolver that lent it is still holding it.");
        Assert.IsTrue(lent.Key.AsReadOnlySpan().SequenceEqual(issuerPublic.AsReadOnlySpan()),
            "The lent key is still readable after the read returned, which is what 'borrowed' means.");

        lent.Key.Dispose();

        Assert.AreEqual(0L, metered.OutstandingCount, "The resolver's own release is what returns a borrowed key's buffer.");
    }


    /// <summary>
    /// Builds the Status List Token that takes <paramref name="path"/> through the read, and the refusal that
    /// exit reports, so a case proving what happens on every exit states each token's shape once.
    /// </summary>
    /// <param name="path">The verification exit to build for.</param>
    /// <param name="issuerPrivate">The private half of the key the read resolves.</param>
    /// <param name="strangerPrivate">A private key the read does not resolve, for the invalid-signature exit.</param>
    /// <returns>The compact serialization, and the refusal expected from it, or <see langword="null"/> when it verifies.</returns>
    private async Task<(string Compact, StatusListTokenVerificationFailure? ExpectedFailure)> TokenTakingAsync(
        string path, PrivateKeyMemory issuerPrivate, PrivateKeyMemory strangerPrivate)
    {
        return path switch
        {
            VerifiedPath =>
                (await SignAsync(BuildHeader(), BuildPayload(), issuerPrivate).ConfigureAwait(false), null),
            SignatureInvalidPath =>
                (await SignAsync(BuildHeader(), BuildPayload(), strangerPrivate).ConfigureAwait(false),
                    StatusListTokenVerificationFailure.SignatureInvalid),
            AlgorithmMismatchPath =>
                (await SignAsync(BuildHeaderWithAlgorithm(WellKnownJwaValues.Hs256), BuildPayload(), issuerPrivate).ConfigureAwait(false),
                    StatusListTokenVerificationFailure.AlgorithmUnsupported),
            ClaimsFailurePath =>
                (await SignAsync(BuildHeader(), BuildPayload(omittedClaim: WellKnownJwtClaimNames.Sub), issuerPrivate).ConfigureAwait(false),
                    StatusListTokenVerificationFailure.RequiredClaimMissing),
            _ => throw new ArgumentOutOfRangeException(nameof(path), path, "The read has no such exit.")
        };
    }


    /// <summary>
    /// Asserts the read left by the exit its input was built for, so an ownership assertion is never read as
    /// evidence about a path the token never took.
    /// </summary>
    /// <param name="path">The exit the token was built to take.</param>
    /// <param name="expectedFailure">The refusal that exit reports, or <see langword="null"/> when it verifies.</param>
    /// <param name="result">The read's outcome.</param>
    private static void AssertTookThePath(
        string path, StatusListTokenVerificationFailure? expectedFailure, StatusListTokenVerificationResult result)
    {
        if(expectedFailure is null)
        {
            Assert.IsTrue(result.IsVerified, $"The '{path}' token satisfies every Section 5.1 rule; the read reported '{result.Defect}'.");

            return;
        }

        Assert.IsFalse(result.IsVerified, $"The '{path}' token breaks a Section 5.1 rule and MUST be refused.");
        Assert.AreEqual(expectedFailure, result.Failure, $"The '{path}' token is refused on that exit, so the ownership assertion is about it.");
    }


    /// <summary>
    /// Builds the conforming Section 5.1 protected header: the example's <c>alg</c> of <c>ES256</c>, its
    /// <c>kid</c> of <c>12</c>, and the <c>typ</c> of <c>statuslist+jwt</c>.
    /// </summary>
    /// <returns>The protected header.</returns>
    private static JwtHeader BuildHeader()
    {
        return BuildHeader(WellKnownJwaValues.Es256, WellKnownMediaTypes.Jwt.StatusListJwt);
    }


    /// <summary>
    /// Builds the conforming Section 5.1 protected header with its <c>typ</c> replaced or dropped.
    /// </summary>
    /// <param name="type">The <c>typ</c> value, or <see langword="null"/> to omit the parameter entirely.</param>
    /// <returns>The protected header.</returns>
    private static JwtHeader BuildHeaderWithType(string? type)
    {
        return BuildHeader(WellKnownJwaValues.Es256, type);
    }


    /// <summary>
    /// Builds the conforming Section 5.1 protected header with its <c>alg</c> replaced or dropped.
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> value, or <see langword="null"/> to omit the parameter entirely.</param>
    /// <returns>The protected header.</returns>
    private static JwtHeader BuildHeaderWithAlgorithm(string? algorithm)
    {
        return BuildHeader(algorithm, WellKnownMediaTypes.Jwt.StatusListJwt);
    }


    /// <summary>
    /// Builds a protected header carrying the Section 5.1 example's <c>kid</c> plus whichever of <c>alg</c>
    /// and <c>typ</c> are supplied; a <see langword="null"/> value omits that header parameter.
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> value, or <see langword="null"/> to omit the parameter.</param>
    /// <param name="type">The <c>typ</c> value, or <see langword="null"/> to omit the parameter.</param>
    /// <returns>The protected header.</returns>
    private static JwtHeader BuildHeader(string? algorithm, string? type)
    {
        var header = new JwtHeader
        {
            [WellKnownJwkMemberNames.Kid] = KeyId
        };

        if(algorithm is not null)
        {
            header[WellKnownJwkMemberNames.Alg] = algorithm;
        }

        if(type is not null)
        {
            header[WellKnownJoseHeaderNames.Typ] = type;
        }

        return header;
    }


    /// <summary>
    /// Builds the Section 5.1 claims set by hand — <c>sub</c>, <c>iat</c> and a <c>status_list</c> of the
    /// example's own <c>bits</c>/<c>lst</c>, plus <c>exp</c>/<c>ttl</c> when asked — so no test input is
    /// produced by the mapping the read itself uses.
    /// </summary>
    /// <param name="omittedClaim">A REQUIRED claim to leave out, or <see langword="null"/> to write them all.</param>
    /// <param name="subject">The <c>sub</c> value.</param>
    /// <param name="expiration">The <c>exp</c> value, or <see langword="null"/> to omit it.</param>
    /// <param name="timeToLive">The <c>ttl</c> value, or <see langword="null"/> to omit it.</param>
    /// <returns>The claims set.</returns>
    private static JwtPayload BuildPayload(
        string? omittedClaim = null,
        string subject = Subject,
        long? expiration = null,
        long? timeToLive = null)
    {
        var payload = new JwtPayload(5);

        if(!string.Equals(omittedClaim, WellKnownJwtClaimNames.Sub, StringComparison.Ordinal))
        {
            payload[WellKnownJwtClaimNames.Sub] = subject;
        }

        if(!string.Equals(omittedClaim, WellKnownJwtClaimNames.Iat, StringComparison.Ordinal))
        {
            payload[WellKnownJwtClaimNames.Iat] = ExampleIssuedAt;
        }

        if(!string.Equals(omittedClaim, WellKnownJwtClaimNames.StatusList, StringComparison.Ordinal))
        {
            payload[WellKnownJwtClaimNames.StatusList] = new Dictionary<string, object>(2)
            {
                [StatusListMemberNames.Bits] = ExampleBits,
                [StatusListMemberNames.List] = ExampleList
            };
        }

        if(expiration.HasValue)
        {
            payload[WellKnownJwtClaimNames.Exp] = expiration.Value;
        }

        if(timeToLive.HasValue)
        {
            payload[WellKnownJwtClaimNames.TimeToLive] = timeToLive.Value;
        }

        return payload;
    }


    /// <summary>
    /// Signs a hand-built header and claims set into a compact JWS through the JOSE signing seams, the same
    /// primitives a Status Issuer's own composition rests on.
    /// </summary>
    /// <param name="header">The protected header to sign under.</param>
    /// <param name="payload">The claims set to sign.</param>
    /// <param name="signingKey">The key to sign with.</param>
    /// <returns>The compact serialization.</returns>
    private async Task<string> SignAsync(JwtHeader header, JwtPayload payload, PrivateKeyMemory signingKey)
    {
        var unsigned = new UnsignedJwt(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            JwtClaimsJson.HeaderSerializer,
            JwtClaimsJson.PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// Signs <paramref name="payloadBytes"/> verbatim as the JWS payload, bypassing any JSON claims shape, so
    /// a token can carry a payload that is not a JSON object at all.
    /// </summary>
    /// <param name="header">The protected header to sign under.</param>
    /// <param name="payloadBytes">The raw payload octets.</param>
    /// <param name="signingKey">The key to sign with.</param>
    /// <returns>The compact serialization.</returns>
    private async Task<string> SignRawPayloadAsync(JwtHeader header, byte[] payloadBytes, PrivateKeyMemory signingKey)
    {
        JwtPayloadSerializer rawSerializer = _ => payloadBytes;
        var unsigned = new UnsignedJwt(header, new JwtPayload());
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            JwtClaimsJson.HeaderSerializer,
            rawSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// Reads <paramref name="compact"/> as a Status List Token published at <see cref="Subject"/>, with this
    /// project's own base64url decoder and the JSON leaf's JWT part decoder.
    /// </summary>
    /// <param name="compact">The compact serialization to read.</param>
    /// <param name="resolveIssuerKey">The Relying Party's issuer-key resolution.</param>
    /// <returns>The verification outcome.</returns>
    private async Task<StatusListTokenVerificationResult> VerifyAsync(
        string compact, ResolveStatusListIssuerKeyDelegate resolveIssuerKey)
    {
        return await StatusListTokenVerification.VerifyAsync(
            compact,
            ContextFor(Subject),
            resolveIssuerKey,
            TestSetup.Base64UrlDecoder,
            JwtPartJson.Default,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The resolution context a read of a token published at <paramref name="subject"/> carries — the
    /// reference whose <c>uri</c> is checked against the verified <c>sub</c> claim, at the example Status
    /// List's revoked index.
    /// </summary>
    /// <param name="subject">The URI the token was fetched for.</param>
    /// <returns>The resolution context.</returns>
    private static Verifiable.Core.StatusList.StatusListResolutionContext ContextFor(string subject) =>
        StatusListFixtures.ContextFor(RevokedIndex, subject);


    /// <summary>
    /// A Relying Party that trusts exactly one key for every Status List Token URI.
    /// </summary>
    /// <param name="issuerPublic">The trusted key.</param>
    /// <returns>The issuer-key resolution.</returns>
    private static ResolveStatusListIssuerKeyDelegate KeyFor(PublicKeyMemory issuerPublic)
    {
        return (_, _) => ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(issuerPublic));
    }
}
