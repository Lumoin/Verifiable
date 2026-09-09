using System.Buffers;
using Lumoin.Veritas.Cbor;
using System.Text;
using System.Text.Json;
using Verifiable.Cbor;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.StatusList;
using Verifiable.Json.StatusList;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusListTokenJsonConverter"/>, the JSON tier's reader and writer for the
/// JWT Claims Set of a Status List Token: "The following content applies to the JWT Claims Set: sub:
/// REQUIRED. … iat: REQUIRED. … exp: RECOMMENDED. … ttl: RECOMMENDED. … status_list: REQUIRED."
/// The converter is exercised directly over <see cref="Utf8JsonReader"/> and
/// <see cref="Utf8JsonWriter"/>, the way <c>StatusListCborConverterTests</c> exercises its CWT twin,
/// so a read is always driven from hand-written JSON and a write is always inspected as raw members
/// rather than by reading it back through the same converter.
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
/// </summary>
[TestClass]
internal sealed class StatusListTokenJsonConverterTests
{
    /// <summary>
    /// The Status List Token subject shared with the sibling Status List tests. It is also the
    /// <c>sub</c> value of the Section 5.1 non-normative example.
    /// </summary>
    private const string ExampleTokenSubject = StatusListTestConstants.ExampleTokenSubject;

    /// <summary>
    /// The Section 4.2 one-bit Status List example object, <c>{"bits":1,"lst":"eNrbuRgAAhcBXQ"}</c>,
    /// encoding the byte array <c>[0xb9, 0xa3]</c>.
    /// </summary>
    private const string OneBitStatusListJson = StatusListTestConstants.OneBitJson;

    /// <summary>
    /// The Section 4.2 two-bit Status List example object, encoding the byte array
    /// <c>[0xc9, 0x44, 0xf9]</c>.
    /// </summary>
    private const string TwoBitStatusListJson = StatusListTestConstants.TwoBitJson;

    /// <summary>
    /// The Section 5.1 non-normative example claims set, member for member and value for value as the
    /// specification prints it beside the header <c>{"alg":"ES256","kid":"12","typ":"statuslist+jwt"}</c>.
    /// </summary>
    private const string SpecificationExampleClaimsSet = /*lang=json,strict*/
        """{"exp":2291720170,"iat":1686920170,"status_list":{"bits":1,"lst":"eNrbuRgAAhcBXQ"},"sub":"https://example.com/statuslists/1","ttl":43200}""";

    /// <summary>The <c>iat</c> value of the Section 5.1 example, in seconds since the epoch.</summary>
    private const long ExampleIssuedAtSeconds = 1686920170L;

    /// <summary>The <c>exp</c> value of the Section 5.1 example, in seconds since the epoch.</summary>
    private const long ExampleExpirationSeconds = 2291720170L;

    /// <summary>The <c>ttl</c> value of the Section 5.1 example, in seconds.</summary>
    private const long ExampleTimeToLiveSeconds = 43200L;

    /// <summary>The instant the round-tripped tokens are issued at.</summary>
    private static DateTimeOffset BaseTime { get; } = StatusListTestConstants.BaseTime;

    /// <summary>The pool every Status List decoded by these tests is allocated from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>
    /// The serializer options handed to the converter. The Status List Token converter resolves its
    /// nested Status List converter itself, so these carry no Status List specific configuration; they
    /// are the project defaults so the call shape matches how a serializer would invoke the converter.
    /// </summary>
    private static JsonSerializerOptions Options { get; } = new JsonSerializerOptions().ApplyVerifiableDefaults();

    /// <summary>Gets or sets the context for the current test run.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// "The following is a non-normative example of a Status List Token in JWT format (in the form
    /// header.payload)" — the claims set the specification prints under the header
    /// <c>{"alg":"ES256","kid":"12","typ":"statuslist+jwt"}</c> must read into exactly the token it
    /// describes: the subject URI, the issuance instant, the expiry, the cache lifetime, and the
    /// one-bit Status List whose first four entries are <c>1, 0, 0, 1</c>.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void SpecificationExampleClaimsSetReadsIntoTheTokenItDescribes()
    {
        StatusListToken decoded = ReadToken(SpecificationExampleClaimsSet);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(ExampleTokenSubject, decoded.Subject, "'sub' must carry the URI of the Status List Token.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(ExampleIssuedAtSeconds), decoded.IssuedAt, "'iat' must carry the time at which the Status List Token was issued.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(ExampleExpirationSeconds), decoded.ExpirationTime, "'exp' must carry the time at which the Status List Token is considered expired.");
        Assert.AreEqual(ExampleTimeToLiveSeconds, decoded.TimeToLive, "'ttl' must carry the maximum number of seconds the Status List Token may be cached.");
        Assert.AreEqual(StatusListBitSize.OneBit, decodedList.BitSize, "'status_list' must carry the Status List conforming to the structure defined in Section 4.2.");
        Assert.AreEqual(StatusTypes.Invalid, decodedList[0], "The example's first status value is 1.");
        Assert.AreEqual(StatusTypes.Valid, decodedList[1], "The example's second status value is 0.");
        Assert.AreEqual(StatusTypes.Valid, decodedList[2], "The example's third status value is 0.");
        Assert.AreEqual(StatusTypes.Invalid, decodedList[3], "The example's fourth status value is 1.");
    }


    /// <summary>
    /// "exp: RECOMMENDED. … the exp (expiration time) claim, if present, MUST specify the time at
    /// which the Status List Token is considered expired by the Status Issuer." / "ttl: RECOMMENDED.
    /// The ttl (time to live) claim, if present, MUST specify the maximum amount of time, in seconds,
    /// that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved."
    /// A token carrying both must survive a write and a read with every claim and every status bit
    /// intact.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TokenCarryingTheRecommendedClaimsRoundTripsThroughTheConverter()
    {
        //Hand-written, member for member as Section 5.1's example spells it, with the Section 4.2
        //two-bit Status List example in place of status_list — never the converter's own Write.
        string claimsSet = $$"""
            {"sub":"{{ExampleTokenSubject}}","iat":{{ExampleIssuedAtSeconds}},"exp":{{ExampleExpirationSeconds}},
             "ttl":{{ExampleTimeToLiveSeconds}},"status_list":{{TwoBitStatusListJson}}}
            """;

        StatusListToken decoded = ReadToken(claimsSet);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(ExampleTokenSubject, decoded.Subject, "'sub' must be read as written.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(ExampleIssuedAtSeconds), decoded.IssuedAt, "'iat' must be read as written.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(ExampleExpirationSeconds), decoded.ExpirationTime, "'exp' must be read as written.");
        Assert.AreEqual(ExampleTimeToLiveSeconds, decoded.TimeToLive, "'ttl' must be read as written.");
        Assert.AreEqual(StatusListBitSize.TwoBits, decodedList.BitSize, "The Section 4.2 two-bit example's bit size must be read.");
        Assert.AreEqual(StatusTypes.Invalid, decodedList[0], "The two-bit example's status value at index 0 is 1.");
        Assert.AreEqual(StatusTypes.Suspended, decodedList[1], "The two-bit example's status value at index 1 is 2.");
    }


    /// <summary>
    /// <c>exp</c> and <c>ttl</c> are RECOMMENDED, not REQUIRED, so a token carrying neither must
    /// round-trip on its three required claims alone and read back with no expiry and no cache
    /// lifetime.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TokenWithoutTheRecommendedClaimsRoundTripsThroughTheConverter()
    {
        //Hand-written, the three REQUIRED claims alone, with the Section 4.2 one-bit example as
        //status_list — never the converter's own Write.
        string claimsSet = $$"""{"sub":"{{ExampleTokenSubject}}","iat":{{ExampleIssuedAtSeconds}},"status_list":{{OneBitStatusListJson}}}""";

        StatusListToken decoded = ReadToken(claimsSet);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(ExampleTokenSubject, decoded.Subject, "'sub' must be read as written.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(ExampleIssuedAtSeconds), decoded.IssuedAt, "'iat' must be read as written.");
        Assert.IsNull(decoded.ExpirationTime, "An absent 'exp' must read back as no expiry.");
        Assert.IsNull(decoded.TimeToLive, "An absent 'ttl' must read back as no cache lifetime.");
        Assert.AreEqual(StatusTypes.Invalid, decodedList[0], "The one-bit example's status value at index 0 is 1.");
    }


    /// <summary>
    /// "status_list: REQUIRED. The status_list (status list) claim MUST specify the Status List
    /// conforming to the structure defined in Section 4.2." The Section 4.2 one-bit example object
    /// carried as the claim's value must decode to the byte array <c>[0xb9, 0xa3]</c> it encodes.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void OneBitStatusListExampleReadsAsTheStatusListInsideTheToken()
    {
        StatusListToken decoded = ReadToken(ClaimsSetWithStatusList(OneBitStatusListJson));
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(StatusListBitSize.OneBit, decodedList.BitSize, "'bits' must be read as the number of bits per Referenced Token.");
        Assert.AreEqual(StatusTypes.Invalid, decodedList[0], "The one-bit example's status value at index 0 is 1.");
        Assert.AreEqual(StatusTypes.Valid, decodedList[1], "The one-bit example's status value at index 1 is 0.");
        Assert.AreEqual(StatusTypes.Valid, decodedList[2], "The one-bit example's status value at index 2 is 0.");
        Assert.AreEqual(StatusTypes.Invalid, decodedList[3], "The one-bit example's status value at index 3 is 1.");
    }


    /// <summary>
    /// The same REQUIRED <c>status_list</c> rule at two bits per Referenced Token: the Section 4.2
    /// two-bit example object carried as the claim's value must decode to the byte array
    /// <c>[0xc9, 0x44, 0xf9]</c> it encodes.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TwoBitStatusListExampleReadsAsTheStatusListInsideTheToken()
    {
        StatusListToken decoded = ReadToken(ClaimsSetWithStatusList(TwoBitStatusListJson));
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(StatusListBitSize.TwoBits, decodedList.BitSize, "'bits' must be read as the number of bits per Referenced Token.");
        Assert.AreEqual(StatusTypes.Invalid, decodedList[0], "The two-bit example's status value at index 0 is 1.");
        Assert.AreEqual(StatusTypes.Suspended, decodedList[1], "The two-bit example's status value at index 1 is 2.");
        Assert.AreEqual(StatusTypes.Valid, decodedList[2], "The two-bit example's status value at index 2 is 0.");
        Assert.AreEqual(StatusTypes.ApplicationSpecific03, decodedList[3], "The two-bit example's status value at index 3 is 3.");
    }


    /// <summary>
    /// "bits: REQUIRED. JSON Integer specifying the number of bits per Referenced Token in the
    /// compressed byte array (lst). The allowed values for bits are 1, 2, 4, and 8." The JSON tier and
    /// the CBOR tier encode one and the same Status List Token claims set, so at every allowed bit
    /// width the two must be readable as the very same status values — the JSON converter reads the
    /// bits the CBOR converter writes and the other way round.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    /// <param name="bits">The number of bits per Referenced Token.</param>
    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(4)]
    [DataRow(8)]
    public void TheJsonAndCborTokenConvertersCarryIdenticalStatusBits(int bits)
    {
        var bitSize = (StatusListBitSize)bits;
        int capacity = 64 / bits;
        byte maximumStatus = (byte)((1 << bits) - 1);

        using StatusListType list = StatusListType.Create(capacity, bitSize, Pool, BitOrder.LeastSignificantFirst);
        list[0] = 1;
        list[1] = maximumStatus;
        list[capacity / 2] = (byte)(maximumStatus / 2);
        list[capacity - 1] = maximumStatus;

        var original = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            ExpirationTime = BaseTime.AddHours(1),
            TimeToLive = ExampleTimeToLiveSeconds
        };

        StatusListToken fromJson = ReadToken(Encoding.UTF8.GetString(WriteToken(original)));
        using StatusListType listFromJson = fromJson.StatusList;

        StatusListToken fromCbor = ReadTokenFromCbor(WriteTokenToCbor(original));
        using StatusListType listFromCbor = fromCbor.StatusList;

        Assert.AreEqual(bitSize, listFromJson.BitSize, "The JSON tier must carry the number of bits per Referenced Token.");
        Assert.AreEqual(bitSize, listFromCbor.BitSize, "The CBOR tier must carry the number of bits per Referenced Token.");
        Assert.AreEqual(capacity, listFromJson.Capacity, "The JSON tier must carry every entry of the compressed byte array.");
        Assert.AreEqual(capacity, listFromCbor.Capacity, "The CBOR tier must carry every entry of the compressed byte array.");

        for(int index = 0; index < capacity; ++index)
        {
            Assert.AreEqual(list[index], listFromJson[index], $"The JSON tier must carry the status value written at index {index}.");
            Assert.AreEqual(list[index], listFromCbor[index], $"The CBOR tier must carry the status value written at index {index}.");
        }

        Assert.IsTrue(listFromJson.AsSpan().SequenceEqual(listFromCbor.AsSpan()),
            "The two tiers meet on the bytes: the JSON lst's base64url+zlib decode is the same raw byte array the CBOR lst carries, not merely the same values read back through each tier's own indexer.");
    }


    /// <summary>
    /// "sub: REQUIRED. As generally defined in [RFC7519]. The sub (subject) claim MUST specify the URI
    /// of the Status List Token." A claims set without it carries no Status List Token, so the read
    /// must refuse and name the claim it missed.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void AClaimsSetMissingTheSubjectClaimIsRefused()
    {
        const string claimsSet = /*lang=json,strict*/
            """{"iat":1686920170,"status_list":{"bits":1,"lst":"eNrbuRgAAhcBXQ"}}""";

        JsonException refusal = Assert.ThrowsExactly<JsonException>(() => ReadToken(claimsSet));

        Assert.Contains("sub", refusal.Message, StringComparison.Ordinal, "The refusal must name the REQUIRED claim that was missing.");
    }


    /// <summary>
    /// "iat: REQUIRED. As generally defined in [RFC7519]. The iat (issued at) claim MUST specify the
    /// time at which the Status List Token was issued." A claims set without it must be refused with
    /// the claim named.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void AClaimsSetMissingTheIssuedAtClaimIsRefused()
    {
        const string claimsSet = /*lang=json,strict*/
            """{"sub":"https://example.com/statuslists/1","status_list":{"bits":1,"lst":"eNrbuRgAAhcBXQ"}}""";

        JsonException refusal = Assert.ThrowsExactly<JsonException>(() => ReadToken(claimsSet));

        Assert.Contains("iat", refusal.Message, StringComparison.Ordinal, "The refusal must name the REQUIRED claim that was missing.");
    }


    /// <summary>
    /// "status_list: REQUIRED. The status_list (status list) claim MUST specify the Status List
    /// conforming to the structure defined in Section 4.2." A claims set without it must be refused
    /// with the claim named.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void AClaimsSetMissingTheStatusListClaimIsRefused()
    {
        const string claimsSet = /*lang=json,strict*/
            """{"sub":"https://example.com/statuslists/1","iat":1686920170}""";

        JsonException refusal = Assert.ThrowsExactly<JsonException>(() => ReadToken(claimsSet));

        Assert.Contains("status_list", refusal.Message, StringComparison.Ordinal, "The refusal must name the REQUIRED claim that was missing.");
    }


    /// <summary>
    /// "The value of the claim MUST be a positive number encoded in JSON as a number." A zero, a
    /// negative value, a fractional value and a numeric string all violate that sentence, so each must
    /// be refused rather than silently cached against.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    /// <param name="timeToLiveLiteral">The JSON literal written as the value of the <c>ttl</c> claim.</param>
    [TestMethod]
    [DataRow("0")]
    [DataRow("-1")]
    [DataRow("-43200")]
    [DataRow("43200.5")]
    [DataRow("\"43200\"")]
    public void ATimeToLiveThatIsNotAPositiveJsonNumberIsRefused(string timeToLiveLiteral)
    {
        string claimsSet = $$"""{"sub":"{{ExampleTokenSubject}}","iat":1686920170,"ttl":{{timeToLiveLiteral}},"status_list":{{OneBitStatusListJson}}}""";

        JsonException refusal = Assert.ThrowsExactly<JsonException>(() => ReadToken(claimsSet));

        Assert.Contains("positive number", refusal.Message, StringComparison.Ordinal, "The refusal must state that 'ttl' MUST be a positive number encoded in JSON as a number.");
    }


    /// <summary>
    /// The other side of the same sentence: a positive JSON number is the conforming <c>ttl</c>, and it
    /// must be read as the maximum number of seconds the Status List Token can be cached before a fresh
    /// copy is retrieved.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void APositiveTimeToLiveIsReadAsTheCacheLifetimeItNames()
    {
        string claimsSet = $$"""{"sub":"{{ExampleTokenSubject}}","iat":1686920170,"ttl":43200,"status_list":{{OneBitStatusListJson}}}""";

        StatusListToken decoded = ReadToken(claimsSet);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(ExampleTimeToLiveSeconds, decoded.TimeToLive, "A positive 'ttl' must be read as the cache lifetime in seconds.");
        Assert.AreEqual(StatusListBitSize.OneBit, decodedList.BitSize, "The Status List must still be read beside a conforming 'ttl'.");
    }


    /// <summary>
    /// "exp: RECOMMENDED." — a claims set without it is conforming, and the token must report no
    /// expiry rather than an invented one.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void AnAbsentExpirationTimeReadsAsNoExpiry()
    {
        string claimsSet = $$"""{"sub":"{{ExampleTokenSubject}}","iat":1686920170,"status_list":{{OneBitStatusListJson}}}""";

        StatusListToken decoded = ReadToken(claimsSet);
        using StatusListType decodedList = decoded.StatusList;

        Assert.IsNull(decoded.ExpirationTime, "An absent 'exp' must leave the token with no expiry.");
        Assert.AreEqual(StatusListBitSize.OneBit, decodedList.BitSize, "The Status List must still be read when 'exp' is absent.");
    }


    /// <summary>
    /// "The exp (expiration time) claim, if present, MUST specify the time at which the Status List
    /// Token is considered expired by the Status Issuer." A present <c>exp</c> must be read as exactly
    /// that instant.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void APresentExpirationTimeReadsAsTheInstantItNames()
    {
        string claimsSet = $$"""{"sub":"{{ExampleTokenSubject}}","iat":1686920170,"exp":2291720170,"status_list":{{OneBitStatusListJson}}}""";

        StatusListToken decoded = ReadToken(claimsSet);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(ExampleExpirationSeconds), decoded.ExpirationTime, "A present 'exp' must be read as the instant it names.");
        Assert.AreEqual(StatusListBitSize.OneBit, decodedList.BitSize, "The Status List must still be read beside a present 'exp'.");
    }


    /// <summary>
    /// "The following additional rules apply: 1. The JWT MAY contain other claims." Claims the Status
    /// List Token does not define — including nested objects and arrays — must be skipped rather than
    /// refused, so an issuer extending its claims set never breaks a conforming reader.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void ClaimsTheStatusListTokenDoesNotDefineAreToleratedAndSkipped()
    {
        const string claimsSet = /*lang=json,strict*/
            """
            {"iss":"https://issuer.example","aud":["https://verifier.example","https://other.example"],
             "sub":"https://example.com/statuslists/1","cnf":{"jwk":{"kty":"EC","crv":"P-256"},"nested":{"deeper":[1,2,3]}},
             "iat":1686920170,"custom_flag":true,"custom_absent":null,"status_list":{"bits":1,"lst":"eNrbuRgAAhcBXQ"},
             "trailing_extra":{"a":{"b":[{"c":1}]}}}
            """;

        StatusListToken decoded = ReadToken(claimsSet);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(ExampleTokenSubject, decoded.Subject, "'sub' must be read across the other claims.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(ExampleIssuedAtSeconds), decoded.IssuedAt, "'iat' must be read across the other claims.");
        Assert.AreEqual(StatusListBitSize.OneBit, decodedList.BitSize, "'status_list' must be read across the other claims.");
        Assert.AreEqual(StatusTypes.Invalid, decodedList[0], "The Status List's status values must be read across the other claims.");
    }


    /// <summary>
    /// The <c>status_list</c> claim "MUST specify the Status List conforming to the structure defined
    /// in Section 4.2", and "The StatusList structure is a JSON Object" — a string in its place is not
    /// that structure and must be refused.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    [TestMethod]
    public void AStatusListClaimThatIsNotAJsonObjectIsRefused()
    {
        string claimsSet = $$"""{"sub":"{{ExampleTokenSubject}}","iat":1686920170,"status_list":"eNrbuRgAAhcBXQ"}""";

        _ = Assert.ThrowsExactly<JsonException>(() => ReadToken(claimsSet), "A 'status_list' that is not a JSON Object does not conform to the Section 4.2 structure.");
    }


    /// <summary>
    /// "bits: REQUIRED. JSON Integer specifying the number of bits per Referenced Token in the
    /// compressed byte array (lst)." Without it the compressed array cannot be read, so the claim must
    /// be refused and <c>bits</c> named.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    [TestMethod]
    public void AStatusListClaimMissingBitsIsRefused()
    {
        const string claimsSet = /*lang=json,strict*/
            """{"sub":"https://example.com/statuslists/1","iat":1686920170,"status_list":{"lst":"eNrbuRgAAhcBXQ"}}""";

        JsonException refusal = Assert.ThrowsExactly<JsonException>(() => ReadToken(claimsSet));

        Assert.Contains("bits", refusal.Message, StringComparison.Ordinal, "The refusal must name the REQUIRED member that was missing.");
    }


    /// <summary>
    /// "lst: REQUIRED. JSON String that contains the status values for all the Referenced Tokens it
    /// conveys statuses for." Without it there are no status values at all, so the claim must be
    /// refused and <c>lst</c> named.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    [TestMethod]
    public void AStatusListClaimMissingTheCompressedListIsRefused()
    {
        const string claimsSet = /*lang=json,strict*/
            """{"sub":"https://example.com/statuslists/1","iat":1686920170,"status_list":{"bits":1}}""";

        JsonException refusal = Assert.ThrowsExactly<JsonException>(() => ReadToken(claimsSet));

        Assert.Contains("lst", refusal.Message, StringComparison.Ordinal, "The refusal must name the REQUIRED member that was missing.");
    }


    /// <summary>
    /// The written claims set must carry exactly the three REQUIRED claims when the token holds
    /// nothing else: "sub: REQUIRED." / "iat: REQUIRED." / "status_list: REQUIRED.", with the
    /// RECOMMENDED <c>exp</c> and <c>ttl</c> absent because the token carries neither. The members are
    /// read straight off the written bytes, never back through the converter that wrote them.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void WritingATokenWithoutTheRecommendedClaimsEmitsOnlyTheRequiredOnes()
    {
        using StatusListType list = StatusListType.Create(StatusListTestConstants.SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);

        byte[] written = WriteToken(token);
        List<string> claimNames = ReadMemberNamesAtDepth(written, 1);
        List<string> statusListMemberNames = ReadMemberNamesAtDepth(written, 2);

        Assert.AreEqual("sub,iat,status_list", string.Join(',', claimNames), "A token without 'exp' and 'ttl' must be written as exactly the three REQUIRED claims.");
        Assert.AreEqual("bits,lst", string.Join(',', statusListMemberNames), "The Status List must be written as exactly the two REQUIRED Section 4.2 members.");
        Assert.AreEqual(ExampleTokenSubject, ReadStringMember(written, "sub"), "'sub' must be written as the URI of the Status List Token.");
        Assert.AreEqual(BaseTime.ToUnixTimeSeconds(), ReadNumberMember(written, "iat"), "'iat' must be written as the issuance time in seconds since the epoch.");
    }


    /// <summary>
    /// When the token carries the RECOMMENDED claims, the written claims set must add exactly
    /// <c>exp</c> and <c>ttl</c> beside the three REQUIRED ones, each as a JSON number — <c>ttl</c>
    /// because "The value of the claim MUST be a positive number encoded in JSON as a number", and
    /// <c>exp</c> as the RFC 7519 NumericDate the claim is defined as.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void WritingATokenCarryingTheRecommendedClaimsEmitsThemBesideTheRequiredOnes()
    {
        using StatusListType list = StatusListType.Create(StatusListTestConstants.SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, DateTimeOffset.FromUnixTimeSeconds(ExampleIssuedAtSeconds), list)
        {
            ExpirationTime = DateTimeOffset.FromUnixTimeSeconds(ExampleExpirationSeconds),
            TimeToLive = ExampleTimeToLiveSeconds
        };

        byte[] written = WriteToken(token);
        List<string> claimNames = ReadMemberNamesAtDepth(written, 1);

        Assert.AreEqual("sub,iat,exp,ttl,status_list", string.Join(',', claimNames), "A token carrying both RECOMMENDED claims must be written as exactly those five claims.");
        Assert.AreEqual(ExampleIssuedAtSeconds, ReadNumberMember(written, "iat"), "'iat' must be written as the issuance time in seconds since the epoch.");
        Assert.AreEqual(ExampleExpirationSeconds, ReadNumberMember(written, "exp"), "'exp' must be written as the expiry time in seconds since the epoch.");
        Assert.AreEqual(ExampleTimeToLiveSeconds, ReadNumberMember(written, "ttl"), "'ttl' must be written as a positive number of seconds.");
    }


    /// <summary>
    /// A claims set can carry <c>status_list</c> before the REQUIRED claim that turns out missing
    /// (JSON member order is arbitrary, and the missing-claim check runs only once every member has
    /// been read) — the pooled Status List the read already decoded for <c>status_list</c> must be
    /// released on that later refusal, not held onto by a token the caller never gets a reference to.
    /// </summary>
    [TestMethod]
    public void AStatusListDecodedBeforeAMissingSubjectIsReleasedOnTheRefusal()
    {
        using var metered = new MeteredHousePool();
        string claimsSet = $$"""{"status_list":{{OneBitStatusListJson}},"iat":1686920170}""";

        var converter = new StatusListTokenJsonConverter(metered.Pool);
        byte[] utf8ClaimsSet = Encoding.UTF8.GetBytes(claimsSet);
        var reader = new Utf8JsonReader(utf8ClaimsSet);
        _ = reader.Read();

        //Utf8JsonReader is a ref struct: it cannot be captured by a lambda, so the refusal is caught
        //directly rather than through Assert.ThrowsExactly.
        JsonException? refusal = null;
        try
        {
            _ = converter.Read(ref reader, typeof(StatusListToken), Options);
        }
        catch(JsonException exception)
        {
            refusal = exception;
        }

        Assert.IsNotNull(refusal, "A claims set missing the REQUIRED 'sub' claim must be refused.");
        Assert.Contains("sub", refusal.Message, StringComparison.Ordinal, "The refusal must still name the missing REQUIRED claim.");
        Assert.AreEqual(0L, metered.OutstandingCount, "The Status List decoded for 'status_list' before the missing 'sub' was discovered must be released.");
    }


    /// <summary>
    /// Reads a Status List Token from a hand-written JSON claims set by driving the converter under
    /// test directly, exactly as a serializer would once it has positioned the reader on the object.
    /// </summary>
    /// <param name="claimsSetJson">The JSON claims set to read.</param>
    /// <returns>The decoded token; the caller owns the pooled Status List inside it.</returns>
    private static StatusListToken ReadToken(string claimsSetJson)
    {
        var converter = new StatusListTokenJsonConverter(Pool);
        byte[] utf8ClaimsSet = Encoding.UTF8.GetBytes(claimsSetJson);
        var reader = new Utf8JsonReader(utf8ClaimsSet);
        _ = reader.Read();

        return converter.Read(ref reader, typeof(StatusListToken), Options);
    }


    /// <summary>
    /// Writes a Status List Token through the converter under test and returns the raw UTF-8 bytes it
    /// produced, so the wire shape can be inspected without reading it back through the converter.
    /// </summary>
    /// <param name="token">The token to write.</param>
    /// <returns>The written UTF-8 JSON.</returns>
    private static byte[] WriteToken(StatusListToken token)
    {
        var converter = new StatusListTokenJsonConverter(Pool);
        var buffer = new ArrayBufferWriter<byte>();
        using(var writer = new Utf8JsonWriter(buffer))
        {
            converter.Write(writer, token, Options);
        }

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Writes a Status List Token through the CWT tier's converter, the twin this JSON converter is
    /// symmetric with, so the two tiers can be compared on the status bits they carry.
    /// </summary>
    /// <param name="token">The token to write.</param>
    /// <returns>The CBOR encoding of the token's claims set.</returns>
    private static byte[] WriteTokenToCbor(StatusListToken token)
    {
        var converter = new StatusListTokenCborConverter(Pool);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        converter.Write(writer, token);

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Reads a Status List Token from a CBOR-encoded claims set through the CWT tier's converter.
    /// </summary>
    /// <param name="encoded">The CBOR encoding to read.</param>
    /// <returns>The decoded token; the caller owns the pooled Status List inside it.</returns>
    private static StatusListToken ReadTokenFromCbor(byte[] encoded)
    {
        var converter = new StatusListTokenCborConverter(Pool);
        var reader = new CborReader(encoded, CborOptions.Lax);

        return converter.Read(reader);
    }


    /// <summary>
    /// Builds a minimal conforming claims set — the two other REQUIRED claims plus the given Status
    /// List object as the value of <c>status_list</c>.
    /// </summary>
    /// <param name="statusListJson">The Section 4.2 Status List object to carry.</param>
    /// <returns>The JSON claims set.</returns>
    private static string ClaimsSetWithStatusList(string statusListJson)
    {
        return $$$"""{"sub":"{{{ExampleTokenSubject}}}","iat":{{{ExampleIssuedAtSeconds}}},"status_list":{{{statusListJson}}}}""";
    }


    /// <summary>
    /// Collects the property names of the written JSON at one nesting depth, in the order they were
    /// written — the independent statement of which members the wire carries.
    /// </summary>
    /// <param name="utf8Json">The written UTF-8 JSON.</param>
    /// <param name="depth">The nesting depth to collect at: 1 for the claims set, 2 for the Status List object.</param>
    /// <returns>The property names in written order.</returns>
    private static List<string> ReadMemberNamesAtDepth(byte[] utf8Json, int depth)
    {
        var names = new List<string>();
        var reader = new Utf8JsonReader(utf8Json);
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.PropertyName && reader.CurrentDepth == depth)
            {
                names.Add(reader.GetString()!);
            }
        }

        return names;
    }


    /// <summary>
    /// Reads one top-level string member out of the written JSON without going through the converter.
    /// </summary>
    /// <param name="utf8Json">The written UTF-8 JSON.</param>
    /// <param name="memberName">The member to read.</param>
    /// <returns>The member's string value.</returns>
    private static string ReadStringMember(byte[] utf8Json, string memberName)
    {
        var reader = new Utf8JsonReader(utf8Json);
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.PropertyName && reader.CurrentDepth == 1 && reader.GetString() == memberName)
            {
                _ = reader.Read();

                return reader.GetString()!;
            }
        }

        throw new InvalidOperationException($"The written JSON carries no '{memberName}' member.");
    }


    /// <summary>
    /// Reads one top-level JSON number member out of the written JSON without going through the
    /// converter, refusing anything that is not a number so the "encoded in JSON as a number" rule is
    /// proved rather than assumed.
    /// </summary>
    /// <param name="utf8Json">The written UTF-8 JSON.</param>
    /// <param name="memberName">The member to read.</param>
    /// <returns>The member's numeric value.</returns>
    private static long ReadNumberMember(byte[] utf8Json, string memberName)
    {
        var reader = new Utf8JsonReader(utf8Json);
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.PropertyName && reader.CurrentDepth == 1 && reader.GetString() == memberName)
            {
                _ = reader.Read();
                if(reader.TokenType != JsonTokenType.Number)
                {
                    throw new InvalidOperationException($"The '{memberName}' member is not encoded in JSON as a number.");
                }

                return reader.GetInt64();
            }
        }

        throw new InvalidOperationException($"The written JSON carries no '{memberName}' member.");
    }
}
