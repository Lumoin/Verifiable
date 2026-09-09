using System;
using System.Buffers.Text;
using System.Text.Json;
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
/// The Status List Token JWT composition: "The Status List Token MUST be encoded as a "JSON Web Token
/// (JWT)" according to [RFC7519]." Every assertion here reads the wire artifact itself — the compact
/// serialization's own segments, base64url-decoded and parsed with <see cref="Utf8JsonReader"/> — so the
/// expectation is stated independently of the claims mapping and the verification the composition shares.
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
/// Status List, Section 5.1</see>.
/// </summary>
[TestClass]
internal sealed class StatusListTokenIssuanceTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The pool every pooled carrier in this class is rented from and returned to.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The subject URI the composed tokens are published at, from the Section 5.1 example.</summary>
    private const string Subject = StatusListTestConstants.ExampleTokenSubject;

    /// <summary>The <c>kid</c> the composition is asked to write, from the Section 5.1 example header.</summary>
    private const string KeyId = "12";

    /// <summary>The bit-array capacity of the composed Status Lists.</summary>
    private const int Capacity = 16;

    /// <summary>An index set to <see cref="StatusTypes.Invalid"/> in the composed Status Lists.</summary>
    private const int RevokedIndex = 3;

    /// <summary>The <c>ttl</c> the Section 5.1 example carries, in seconds.</summary>
    private const long ExampleTimeToLive = 43200;


    /// <summary>
    /// "The Status List Token MUST be encoded as a "JSON Web Token (JWT)" according to [RFC7519]." — the
    /// composed artifact is the JWS Compact Serialization of Section 8.2's "raw Status List Token", three
    /// non-empty dot-separated segments.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposedTokenIsThreeNonEmptyCompactSegments()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = CreateStatusList();
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList);

        string compact = await ComposeAsync(token, issuerPrivate).ConfigureAwait(false);
        string[] segments = compact.Split('.');

        Assert.HasCount(3, segments, "Section 5.1's JWT encoding is the compact serialization: header.payload.signature.");
        Assert.IsFalse(Array.Exists(segments, string.IsNullOrEmpty), "No compact segment of a signed Status List Token may be empty.");
    }


    /// <summary>
    /// "typ: REQUIRED.  The JWT type MUST be statuslist+jwt." — read off the decoded protected header bytes,
    /// not off any header object the composition kept.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposedHeaderCarriesTheStatusListJwtType()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = CreateStatusList();
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList);

        string compact = await ComposeAsync(token, issuerPrivate).ConfigureAwait(false);
        byte[] header = DecodeSegment(compact.Split('.')[0]);

        Assert.AreEqual(
            "statuslist+jwt",
            ReadStringMember(header, WellKnownJoseHeaderNames.Typ, depth: 1),
            "Section 5.1 requires the JWT type to be statuslist+jwt.");
    }


    /// <summary>
    /// "The Status List Token MUST be encoded as a "JSON Web Token (JWT)" according to [RFC7519]." — RFC 7515's
    /// <c>alg</c> names the signing algorithm and is taken from the signing key's own tag, and the <c>kid</c>
    /// the Status Issuer supplies is written verbatim, so a Relying Party's key resolver can key on it (the
    /// Section 5.1 example header is {"alg":"ES256","kid":"12","typ":"statuslist+jwt"}).
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposedHeaderCarriesTheSigningKeysAlgorithmAndTheGivenKeyIdentifier()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = CreateStatusList();
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList);

        string compact = await ComposeAsync(token, issuerPrivate).ConfigureAwait(false);
        byte[] header = DecodeSegment(compact.Split('.')[0]);

        Assert.AreEqual(
            WellKnownJwaValues.Es256,
            ReadStringMember(header, WellKnownJwkMemberNames.Alg, depth: 1),
            "A P-256 signing key composes an ES256 Status List Token.");
        Assert.AreEqual(
            KeyId,
            ReadStringMember(header, WellKnownJwkMemberNames.Kid, depth: 1),
            "The Status Issuer's supplied key identifier is what the header carries.");
    }


    /// <summary>
    /// "sub: REQUIRED. … The sub (subject) claim MUST specify the URI of the Status List Token." / "iat:
    /// REQUIRED. … The iat (issued at) claim MUST specify the time at which the Status List Token was issued."
    /// / "status_list: REQUIRED.  The status_list (status list) claim MUST specify the Status List conforming
    /// to the structure defined in Section 4.2." — the <c>lst</c> member is compared against the Status List
    /// model's own compressed bytes, base64url-encoded by the test rather than by the composition.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposedPayloadCarriesTheRequiredClaimsAndTheCompressedStatusList()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = CreateStatusList();
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList);
        string expectedList = TestSetup.Base64UrlEncoder(statusList.Compress());

        string compact = await ComposeAsync(token, issuerPrivate).ConfigureAwait(false);
        byte[] payload = DecodeSegment(compact.Split('.')[1]);

        Assert.AreEqual(
            Subject,
            ReadStringMember(payload, WellKnownJwtClaimNames.Sub, depth: 1),
            "Section 5.1's sub claim MUST specify the URI of the Status List Token.");
        Assert.AreEqual(
            StatusListTestConstants.BaseTime.ToUnixTimeSeconds(),
            ReadNumberMember(payload, WellKnownJwtClaimNames.Iat, depth: 1),
            "Section 5.1's iat claim MUST specify the time at which the Status List Token was issued.");
        Assert.IsTrue(
            HasMember(payload, WellKnownJwtClaimNames.StatusList, depth: 1),
            "Section 5.1's status_list claim is REQUIRED.");
        Assert.AreEqual(
            (long)StatusListBitSize.OneBit,
            ReadNumberMember(payload, StatusListMemberNames.Bits, depth: 2),
            "Section 4.2's bits member states the Status List's bit size.");
        Assert.AreEqual(
            expectedList,
            ReadStringMember(payload, StatusListMemberNames.List, depth: 2),
            "Section 4.2's lst member is the base64url-encoded compressed byte array of the Status List.");
    }


    /// <summary>
    /// "exp: RECOMMENDED. … The exp (expiration time) claim, if present, MUST specify the time at which the
    /// Status List Token is considered expired by the Status Issuer." / "ttl: RECOMMENDED.  The ttl (time to
    /// live) claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List
    /// Token can be cached by a consumer before a fresh copy SHOULD be retrieved." — "Both ttl and exp are
    /// RECOMMENDED to be used by the Status Issuer.", so a token carrying both composes both.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-13.7">Section 13.7</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposedPayloadCarriesExpirationAndTimeToLiveWhenTheTokenDoes()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = CreateStatusList();
        DateTimeOffset expiration = StatusListTestConstants.BaseTime.AddHours(12);
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList)
        {
            ExpirationTime = expiration,
            TimeToLive = ExampleTimeToLive
        };

        string compact = await ComposeAsync(token, issuerPrivate).ConfigureAwait(false);
        byte[] payload = DecodeSegment(compact.Split('.')[1]);

        Assert.AreEqual(
            expiration.ToUnixTimeSeconds(),
            ReadNumberMember(payload, WellKnownJwtClaimNames.Exp, depth: 1),
            "A Status List Token carrying an expiration time composes Section 5.1's exp claim.");
        Assert.AreEqual(
            ExampleTimeToLive,
            ReadNumberMember(payload, WellKnownJwtClaimNames.TimeToLive, depth: 1),
            "A Status List Token carrying a time to live composes Section 5.1's ttl claim.");
    }


    /// <summary>
    /// "exp: RECOMMENDED. … if present" / "ttl: RECOMMENDED. … if present" — RECOMMENDED is not REQUIRED, so a
    /// Status List Token that carries neither composes neither claim rather than a placeholder value.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposedPayloadOmitsExpirationAndTimeToLiveWhenTheTokenCarriesNeither()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = CreateStatusList();
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList);

        string compact = await ComposeAsync(token, issuerPrivate).ConfigureAwait(false);
        byte[] payload = DecodeSegment(compact.Split('.')[1]);

        Assert.IsFalse(
            HasMember(payload, WellKnownJwtClaimNames.Exp, depth: 1),
            "Section 5.1's exp claim is written only when the Status List Token carries an expiration time.");
        Assert.IsFalse(
            HasMember(payload, WellKnownJwtClaimNames.TimeToLive, depth: 1),
            "Section 5.1's ttl claim is written only when the Status List Token carries a time to live.");
    }


    /// <summary>
    /// "2.  The JWT MUST be secured using a cryptographic signature or MAC algorithm." — the composed
    /// signature verifies under the Status Issuer's public key through the shipped JWS verification, so the
    /// artifact a Status Provider serves is one a Relying Party can actually check.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposedSignatureVerifiesUnderTheIssuersPublicKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = CreateStatusList();
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList);

        string compact = await ComposeAsync(token, issuerPrivate).ConfigureAwait(false);
        bool isSignatureValid = await Jws.VerifyAsync(
            compact, TestSetup.Base64UrlDecoder, Pool, issuerPublic, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isSignatureValid, "The composed Status List Token MUST be secured by a signature the issuer's key verifies.");
    }


    /// <summary>
    /// "3.  Relying Parties MUST reject JWTs that are not valid in all other respects per "JSON Web Token
    /// (JWT)" [RFC7519]." — the converse of the refusals: a Status List Token this composition produced passes
    /// the whole Section 8.3 step 3 read and yields back the very claims that went in.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposedTokenVerifiesIntoAnEqualToken()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = CreateStatusList();
        DateTimeOffset expiration = StatusListTestConstants.BaseTime.AddHours(12);
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList)
        {
            ExpirationTime = expiration,
            TimeToLive = ExampleTimeToLive
        };

        string compact = await ComposeAsync(token, issuerPrivate).ConfigureAwait(false);
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
            ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(issuerPublic));

        StatusListTokenVerificationResult result = await StatusListTokenVerification.VerifyAsync(
            compact,
            StatusListFixtures.ContextFor(RevokedIndex, Subject),
            resolveIssuerKey,
            TestSetup.Base64UrlDecoder,
            JwtPartJson.Default,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"A composed Status List Token MUST verify; the read reported '{result.Defect}'.");
        using StatusListType verifiedList = result.Token!.StatusList;

        Assert.AreEqual(token.Subject, result.Token.Subject, "The verified sub claim is the composed subject URI.");
        Assert.AreEqual(token.IssuedAt, result.Token.IssuedAt, "The verified iat claim is the composed issuance instant.");
        Assert.AreEqual(token.ExpirationTime, result.Token.ExpirationTime, "The verified exp claim is the composed expiration time.");
        Assert.AreEqual(token.TimeToLive, result.Token.TimeToLive, "The verified ttl claim is the composed time to live.");
        Assert.AreEqual(StatusTypes.Invalid, verifiedList[RevokedIndex], "The revoked index survives the composition and the read.");
    }


    /// <summary>
    /// "sub: REQUIRED. … The sub (subject) claim MUST specify the URI of the Status List Token." — there is no
    /// Status List Token to compose without a Status List Token, so the absence is a caller defect rather than
    /// an empty artifact on the wire.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposingWithoutATokenIsRefused()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        _ = await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            async () => await StatusListTokenIssuance.ComposeAsync(
                null!,
                issuerPrivate,
                KeyId,
                TestSetup.Base64UrlEncoder,
                JwtClaimsJson.HeaderSerializer,
                JwtClaimsJson.PayloadSerializer,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false),
            "A Status List Token is what the composition encodes; there is no default.").ConfigureAwait(false);
    }


    /// <summary>
    /// "2.  The JWT MUST be secured using a cryptographic signature or MAC algorithm." — a composition without
    /// a signing key could only produce an unsecured token, which this rule forbids outright.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposingWithoutASigningKeyIsRefused()
    {
        using StatusListType statusList = CreateStatusList();
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList);

        _ = await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            async () => await StatusListTokenIssuance.ComposeAsync(
                token,
                null!,
                KeyId,
                TestSetup.Base64UrlEncoder,
                JwtClaimsJson.HeaderSerializer,
                JwtClaimsJson.PayloadSerializer,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false),
            "An unsecured Status List Token is not a composition Section 5.1 rule 2 permits.").ConfigureAwait(false);
    }


    /// <summary>
    /// "a.  Validate the Status List Token by following the rules defined in Section 7.2 of [RFC7519] for
    /// JWTs. … This step might require the resolution of a public key as described in Section 11.3." — the
    /// <c>kid</c> is how a Relying Party finds that key, so a blank one is refused at composition rather than
    /// published as an unresolvable header.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    /// <param name="keyId">The blank key identifier under test.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow(" ")]
    public async Task ComposingWithABlankKeyIdentifierIsRefused(string keyId)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = CreateStatusList();
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList);

        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await StatusListTokenIssuance.ComposeAsync(
                token,
                issuerPrivate,
                keyId,
                TestSetup.Base64UrlEncoder,
                JwtClaimsJson.HeaderSerializer,
                JwtClaimsJson.PayloadSerializer,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false),
            "A blank kid names no key a Relying Party could resolve.").ConfigureAwait(false);
    }


    /// <summary>
    /// "Each index identifies a contiguous block of bits in the byte array, with the blocks being packed into
    /// bytes from the least significant bit ("0") to the most significant bit ("7")." — a Status List packed
    /// <see cref="BitOrder.MostSignificantFirst"/> (the W3C Bitstring Status List's order) is refused rather
    /// than composed under Section 5.1's <c>status_list</c> claim with its bytes copied as-is.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.1">Token
    /// Status List, Section 4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ComposingRefusesAListPackedMostSignificantFirst()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = StatusListType.Create(Capacity, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        statusList[RevokedIndex] = StatusTypes.Invalid;
        var token = new StatusListToken(Subject, StatusListTestConstants.BaseTime, statusList);

        ArgumentException thrown = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await StatusListTokenIssuance.ComposeAsync(
                token,
                issuerPrivate,
                KeyId,
                TestSetup.Base64UrlEncoder,
                JwtClaimsJson.HeaderSerializer,
                JwtClaimsJson.PayloadSerializer,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false),
            "A most-significant-bit-first Status List must never be composed as a Token Status List.").ConfigureAwait(false);

        Assert.AreEqual("token", thrown.ParamName, "The refusal must name the parameter carrying the wrongly ordered list.");
    }


    /// <summary>
    /// Composes <paramref name="token"/> through the library's own composition with this project's base64url
    /// encoder and the JSON leaf's JWT part serializers.
    /// </summary>
    /// <param name="token">The Status List Token to compose.</param>
    /// <param name="signingKey">The Status Issuer's signing key.</param>
    /// <returns>The compact-serialized Status List Token JWT.</returns>
    private async Task<string> ComposeAsync(StatusListToken token, PrivateKeyMemory signingKey)
    {
        return await StatusListTokenIssuance.ComposeAsync(
            token,
            signingKey,
            KeyId,
            TestSetup.Base64UrlEncoder,
            JwtClaimsJson.HeaderSerializer,
            JwtClaimsJson.PayloadSerializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Creates the one-bit Status List every composed token in this class carries, with
    /// <see cref="RevokedIndex"/> set to <see cref="StatusTypes.Invalid"/>.
    /// </summary>
    /// <returns>The pooled Status List; the caller disposes it.</returns>
    private static StatusListType CreateStatusList()
    {
        StatusListType statusList = StatusListType.Create(Capacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[RevokedIndex] = StatusTypes.Invalid;

        return statusList;
    }


    /// <summary>
    /// Base64url-decodes one compact serialization segment into its raw bytes, the form every assertion in
    /// this class reads.
    /// </summary>
    /// <param name="segment">The base64url segment exactly as it appears in the compact serialization.</param>
    /// <returns>The decoded bytes.</returns>
    private static byte[] DecodeSegment(string segment)
    {
        return Base64Url.DecodeFromChars(segment);
    }


    /// <summary>
    /// Whether <paramref name="utf8Json"/> carries a member named <paramref name="memberName"/> at
    /// <paramref name="depth"/>. Depth 1 is a member of the root object, depth 2 a member of an object nested
    /// directly inside it; the composed payloads of this class carry each name at exactly one depth.
    /// </summary>
    /// <param name="utf8Json">The decoded segment's UTF-8 JSON bytes.</param>
    /// <param name="memberName">The member name to look for.</param>
    /// <param name="depth">The object nesting depth the member is expected at.</param>
    /// <returns><see langword="true"/> when the member is present.</returns>
    private static bool HasMember(ReadOnlySpan<byte> utf8Json, string memberName, int depth)
    {
        var reader = new Utf8JsonReader(utf8Json);

        return TryPositionOnValue(ref reader, memberName, depth);
    }


    /// <summary>
    /// Reads the string value of the member named <paramref name="memberName"/> at <paramref name="depth"/>.
    /// </summary>
    /// <param name="utf8Json">The decoded segment's UTF-8 JSON bytes.</param>
    /// <param name="memberName">The member name to read.</param>
    /// <param name="depth">The object nesting depth the member is expected at.</param>
    /// <returns>The string value, or <see langword="null"/> when the member is absent or not a string.</returns>
    private static string? ReadStringMember(ReadOnlySpan<byte> utf8Json, string memberName, int depth)
    {
        var reader = new Utf8JsonReader(utf8Json);
        if(!TryPositionOnValue(ref reader, memberName, depth) || reader.TokenType != JsonTokenType.String)
        {
            return null;
        }

        return reader.GetString();
    }


    /// <summary>
    /// Reads the integer value of the member named <paramref name="memberName"/> at <paramref name="depth"/>.
    /// </summary>
    /// <param name="utf8Json">The decoded segment's UTF-8 JSON bytes.</param>
    /// <param name="memberName">The member name to read.</param>
    /// <param name="depth">The object nesting depth the member is expected at.</param>
    /// <returns>The value, or <see langword="null"/> when the member is absent or not a JSON number.</returns>
    private static long? ReadNumberMember(ReadOnlySpan<byte> utf8Json, string memberName, int depth)
    {
        var reader = new Utf8JsonReader(utf8Json);
        if(!TryPositionOnValue(ref reader, memberName, depth) || reader.TokenType != JsonTokenType.Number)
        {
            return null;
        }

        return reader.GetInt64();
    }


    /// <summary>
    /// Advances <paramref name="reader"/> to the value of the member named <paramref name="memberName"/> at
    /// <paramref name="depth"/>.
    /// </summary>
    /// <param name="reader">The reader over the decoded segment.</param>
    /// <param name="memberName">The member name to look for.</param>
    /// <param name="depth">The object nesting depth the member is expected at.</param>
    /// <returns><see langword="true"/> when the reader now sits on the member's value.</returns>
    private static bool TryPositionOnValue(ref Utf8JsonReader reader, string memberName, int depth)
    {
        while(reader.Read())
        {
            bool isWantedMember = reader.TokenType == JsonTokenType.PropertyName
                && reader.CurrentDepth == depth
                && reader.ValueTextEquals(memberName);

            if(isWantedMember)
            {
                return reader.Read();
            }
        }

        return false;
    }
}
