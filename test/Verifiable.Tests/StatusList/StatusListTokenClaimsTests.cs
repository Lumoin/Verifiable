using System.Buffers.Text;
using System.Collections.Generic;
using Verifiable.Core.StatusList;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusListTokenClaims"/>, the one mapping between a
/// <see cref="StatusListToken"/> and the JWT Claims Set of Section 5.1 — <c>sub</c>, <c>iat</c>,
/// <c>exp</c>, <c>ttl</c> and <c>status_list</c> — used by both the JWT composition and the JWT
/// verification. Every claims set a read is driven from is built here by hand as the wire spells it,
/// never by calling the write side, and every expectation the write side is measured against names
/// the wire member and its type directly.
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
/// </summary>
[TestClass]
internal sealed class StatusListTokenClaimsTests
{
    /// <summary>The Status List Token subject, the <c>sub</c> value of the Section 5.1 example.</summary>
    private const string ExampleTokenSubject = StatusListTestConstants.ExampleTokenSubject;

    /// <summary>
    /// The <c>lst</c> value of the Section 4.2 one-bit example: the base64url-encoded compressed byte
    /// array of <c>[0xb9, 0xa3]</c>.
    /// </summary>
    private const string OneBitEncodedList = "eNrbuRgAAhcBXQ";

    /// <summary>
    /// The issuance time used wherever the numeric value itself is not the subject of the test. It is
    /// small enough to fit every integer family a JSON number may be handed back as, including
    /// <see cref="sbyte"/>.
    /// </summary>
    private const long SmallIssuedAtSeconds = 10L;

    /// <summary>The expiry time used beside <see cref="SmallIssuedAtSeconds"/>, likewise small enough for every integer family.</summary>
    private const long SmallExpirationSeconds = 20L;

    /// <summary>The cache lifetime used beside <see cref="SmallIssuedAtSeconds"/>, likewise small enough for every integer family.</summary>
    private const long SmallTimeToLiveSeconds = 30L;

    /// <summary>The instant the composed tokens are issued at.</summary>
    private static DateTimeOffset BaseTime { get; } = StatusListTestConstants.BaseTime;

    /// <summary>The pool the decoded Status Lists are allocated from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>Gets or sets the context for the current test run.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// "sub: REQUIRED. … The sub (subject) claim MUST specify the URI of the Status List Token." /
    /// "iat: REQUIRED. … The iat (issued at) claim MUST specify the time at which the Status List
    /// Token was issued." / "status_list: REQUIRED. The status_list (status list) claim MUST specify
    /// the Status List conforming to the structure defined in Section 4.2." — plus the RECOMMENDED
    /// <c>exp</c> and <c>ttl</c> the token carries. Each temporal claim is a JWT NumericDate and
    /// <c>ttl</c> "MUST be a positive number encoded in JSON as a number", so all four numeric values
    /// must be written as integers, not as text.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void ToPayloadWritesEveryRequiredClaimAndTheRecommendedOnesTheTokenCarries()
    {
        using StatusListType list = StatusListType.Create(StatusListTestConstants.SmallListCapacity, StatusListBitSize.TwoBits, Pool, BitOrder.LeastSignificantFirst);
        list[0] = StatusTypes.Invalid;

        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            ExpirationTime = BaseTime.AddHours(1),
            TimeToLive = 43200L
        };

        JwtPayload payload = StatusListTokenClaims.ToPayload(token, TestSetup.Base64UrlEncoder);

        Assert.AreEqual(ExampleTokenSubject, payload["sub"], "'sub' must carry the URI of the Status List Token.");
        Assert.AreEqual(BaseTime.ToUnixTimeSeconds(), payload["iat"], "'iat' must carry the issuance time as a NumericDate.");
        Assert.AreEqual(BaseTime.AddHours(1).ToUnixTimeSeconds(), payload["exp"], "'exp' must carry the expiry time as a NumericDate.");
        Assert.AreEqual(43200L, payload["ttl"], "'ttl' must carry the cache lifetime in seconds.");
        Assert.IsInstanceOfType<long>(payload["iat"], "'iat' must be a whole number, not text.");
        Assert.IsInstanceOfType<long>(payload["exp"], "'exp' must be a whole number, not text.");
        Assert.IsInstanceOfType<long>(payload["ttl"], "'ttl' must be a number, not text.");

        var statusListClaim = (IReadOnlyDictionary<string, object>)payload["status_list"];
        Assert.AreEqual(2L, statusListClaim["bits"], "'bits' must carry the number of bits per Referenced Token.");
        Assert.IsInstanceOfType<long>(statusListClaim["bits"], "'bits' is a JSON Integer, not text.");
        Assert.AreEqual(Base64Url.EncodeToString(list.Compress()), statusListClaim["lst"], "'lst' MUST be the base64url-encoded compressed byte array.");
    }


    /// <summary>
    /// <c>exp</c> and <c>ttl</c> are RECOMMENDED and qualified by "if present", so a token carrying
    /// neither must produce a claims set of exactly the three REQUIRED claims — never a placeholder
    /// expiry or a zero cache lifetime.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void ToPayloadOmitsTheRecommendedClaimsTheTokenDoesNotCarry()
    {
        using StatusListType list = StatusListType.Create(StatusListTestConstants.SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);

        JwtPayload payload = StatusListTokenClaims.ToPayload(token, TestSetup.Base64UrlEncoder);

        Assert.HasCount(3, payload, "A token without 'exp' and 'ttl' must produce exactly the three REQUIRED claims.");
        Assert.IsFalse(payload.ContainsKey("exp"), "An absent expiry must not be written as 'exp'.");
        Assert.IsFalse(payload.ContainsKey("ttl"), "An absent cache lifetime must not be written as 'ttl'.");
        Assert.IsTrue(payload.ContainsKey("sub"), "'sub' is REQUIRED.");
        Assert.IsTrue(payload.ContainsKey("iat"), "'iat' is REQUIRED.");
        Assert.IsTrue(payload.ContainsKey("status_list"), "'status_list' is REQUIRED.");
    }


    /// <summary>
    /// "Each index identifies a contiguous block of bits in the byte array, with the blocks being
    /// packed into bytes from the least significant bit (&quot;0&quot;) to the most significant bit
    /// (&quot;7&quot;)." A <see cref="BitOrder.LeastSignificantFirst"/> list with index 0 set must
    /// therefore pack that bit at bit 0 of the first decompressed byte, proving Section 4.1's packing
    /// on the bytes <see cref="StatusListTokenClaims.ToPayload"/> actually writes.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.1">Token Status List, Section 4.1</see>.
    /// </summary>
    [TestMethod]
    public void ToPayloadPacksAnIetfOrderedListWithIndexZeroAtBitZero()
    {
        using StatusListType list = StatusListType.Create(StatusListTestConstants.SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        list[0] = StatusTypes.Invalid;
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);

        JwtPayload payload = StatusListTokenClaims.ToPayload(token, TestSetup.Base64UrlEncoder);
        var statusListClaim = (IReadOnlyDictionary<string, object>)payload["status_list"];
        byte[] compressed = Base64Url.DecodeFromChars((string)statusListClaim["lst"]);
        byte[] decompressed = Decompressed(compressed);

        Assert.AreEqual(0x01, decompressed[0], "Index 0 must occupy bit 0 (the least significant bit) of the first byte.");
    }


    /// <summary>
    /// <see cref="StatusList.EnsureIetfBitOrder"/> refuses a <see cref="BitOrder.MostSignificantFirst"/>
    /// Status List — the W3C Bitstring Status List's packing — rather than let its bytes ship as-is
    /// under the Section 5.1 <c>status_list</c> claim, where every reader (hard-coded to
    /// <see cref="BitOrder.LeastSignificantFirst"/>) would decode the wrong bit for indices under 8 bits.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.1">Token Status List, Section 4.1</see>.
    /// </summary>
    [TestMethod]
    public void ToPayloadRefusesAListPackedMostSignificantFirst()
    {
        using StatusListType list = StatusListType.Create(StatusListTestConstants.SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        list[0] = StatusTypes.Invalid;
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);

        var thrown = Assert.ThrowsExactly<ArgumentException>(
            () => StatusListTokenClaims.ToPayload(token, TestSetup.Base64UrlEncoder),
            "A most-significant-bit-first Status List must never be written as a Token Status List's 'status_list' claim.");

        Assert.AreEqual("token", thrown.ParamName, "The refusal must name the parameter carrying the wrongly ordered list.");
        Assert.Contains("section-4.1", thrown.Message, StringComparison.OrdinalIgnoreCase, "The refusal must anchor to Section 4.1.");
    }


    /// <summary>
    /// "aggregation_uri: OPTIONAL. JSON String that contains a URI to retrieve the Status List
    /// Aggregation for this type of Referenced Token or Issuer." When the Status List carries one it
    /// belongs inside the <c>status_list</c> claim beside <c>bits</c> and <c>lst</c>.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    [TestMethod]
    public void ToPayloadWritesTheOptionalAggregationUriInsideTheStatusListClaim()
    {
        using StatusListType list = StatusListType.Create(StatusListTestConstants.SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        list.AggregationUri = StatusListTestConstants.ExampleAggregationUri;
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);

        JwtPayload payload = StatusListTokenClaims.ToPayload(token, TestSetup.Base64UrlEncoder);
        var statusListClaim = (IReadOnlyDictionary<string, object>)payload["status_list"];

        Assert.AreEqual(StatusListTestConstants.ExampleAggregationUri, statusListClaim["aggregation_uri"], "An aggregation URI must be written inside the Status List object.");
        Assert.HasCount(3, statusListClaim, "The Status List object carries 'bits', 'lst' and the optional 'aggregation_uri'.");
    }


    /// <summary>
    /// The composition and the verification share this one mapping, so what the write side produced
    /// must read back as the same token: the same subject, the same instants, the same cache lifetime
    /// and the same status values.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TryFromPayloadReadsBackWhatToPayloadWrote()
    {
        using StatusListType list = StatusListType.Create(StatusListTestConstants.MediumListCapacity, StatusListBitSize.TwoBits, Pool, BitOrder.LeastSignificantFirst);
        list[0] = StatusTypes.Invalid;
        list[StatusListTestConstants.SuspendedCredentialIndex] = StatusTypes.Suspended;

        var original = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            ExpirationTime = BaseTime.AddHours(1),
            TimeToLive = 43200L
        };

        JwtPayload payload = StatusListTokenClaims.ToPayload(original, TestSetup.Base64UrlEncoder);
        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsTrue(isRead, "A claims set carrying every REQUIRED claim must be read.");
        Assert.IsNull(reason, "A conforming claims set has nothing to report.");
        Assert.IsNotNull(decoded);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(original.Subject, decoded.Subject, "'sub' must survive the mapping.");
        Assert.AreEqual(original.IssuedAt, decoded.IssuedAt, "'iat' must survive the mapping.");
        Assert.AreEqual(original.ExpirationTime, decoded.ExpirationTime, "'exp' must survive the mapping.");
        Assert.AreEqual(original.TimeToLive, decoded.TimeToLive, "'ttl' must survive the mapping.");
        Assert.AreEqual(StatusListBitSize.TwoBits, decodedList.BitSize, "'bits' must survive the mapping.");
        Assert.AreEqual(StatusTypes.Invalid, decodedList[0], "The status value at index 0 must survive the mapping.");
        Assert.AreEqual(StatusTypes.Suspended, decodedList[StatusListTestConstants.SuspendedCredentialIndex], "The status value at the suspended index must survive the mapping.");
    }


    /// <summary>
    /// "bits: REQUIRED. JSON Integer" and the JWT NumericDate claims are JSON numbers, and a claims
    /// deserializer is free to hand a whole JSON number back boxed as any of the .NET integer families
    /// or as a <see cref="decimal"/>. Every one of those must be read as the same integer, so a
    /// conforming token is never refused over the deserializer's choice of box.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    /// <param name="family">Names the .NET integer family the JSON numbers are boxed as.</param>
    [TestMethod]
    [DataRow("Int64")]
    [DataRow("Int32")]
    [DataRow("Int16")]
    [DataRow("SByte")]
    [DataRow("Byte")]
    [DataRow("UInt16")]
    [DataRow("UInt32")]
    [DataRow("UInt64")]
    [DataRow("Decimal")]
    public void TryFromPayloadAcceptsEveryIntegerFamilyAJsonNumberMayArriveAs(string family)
    {
        JwtPayload payload = HandBuiltClaimsSet();
        payload["iat"] = Boxed(SmallIssuedAtSeconds, family);
        payload["exp"] = Boxed(SmallExpirationSeconds, family);
        payload["ttl"] = Boxed(SmallTimeToLiveSeconds, family);
        ((Dictionary<string, object>)payload["status_list"])["bits"] = Boxed(1L, family);

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsTrue(isRead, $"A whole JSON number boxed as {family} must be read as the integer it is: {reason}");
        Assert.IsNotNull(decoded);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(SmallIssuedAtSeconds), decoded.IssuedAt, "'iat' must be read as the NumericDate it carries.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(SmallExpirationSeconds), decoded.ExpirationTime, "'exp' must be read as the NumericDate it carries.");
        Assert.AreEqual(SmallTimeToLiveSeconds, decoded.TimeToLive, "'ttl' must be read as the number of seconds it carries.");
        Assert.AreEqual(StatusListBitSize.OneBit, decodedList.BitSize, "'bits' must be read as the number of bits per Referenced Token.");
    }


    /// <summary>
    /// A JWT NumericDate is "a JSON numeric value representing the number of seconds", <c>ttl</c>
    /// "MUST be a positive number", and <c>bits</c> is a "JSON Integer" — none of them admits a
    /// fractional value, and truncating one would silently move an instant or a cache boundary. Each
    /// must therefore be refused, with the reported reason naming the claim.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    /// <param name="claimName">The claim carrying the fractional value.</param>
    [TestMethod]
    [DataRow("iat")]
    [DataRow("exp")]
    [DataRow("ttl")]
    public void TryFromPayloadRefusesAFractionalValueForANumericClaim(string claimName)
    {
        JwtPayload payload = HandBuiltClaimsSet();
        payload["exp"] = SmallExpirationSeconds;
        payload["ttl"] = SmallTimeToLiveSeconds;
        payload[claimName] = 10.5m;

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsFalse(isRead, $"A fractional '{claimName}' is not the whole number the claim is defined as.");
        Assert.IsNull(decoded, "A refused claims set yields no token.");
        Assert.IsNotNull(reason);
        Assert.Contains(claimName, reason, StringComparison.Ordinal, "The reported reason must name the claim that was malformed.");
    }


    /// <summary>
    /// The same refusal for the Status List object's own "bits: REQUIRED. JSON Integer" member: a
    /// fractional number is not an integer and must be refused with <c>bits</c> named.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    [TestMethod]
    public void TryFromPayloadRefusesAFractionalBitsMember()
    {
        JwtPayload payload = HandBuiltClaimsSet();
        ((Dictionary<string, object>)payload["status_list"])["bits"] = 1.5m;

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsFalse(isRead, "A fractional 'bits' is not the JSON Integer the member is defined as.");
        Assert.IsNull(decoded, "A refused claims set yields no token.");
        Assert.IsNotNull(reason);
        Assert.Contains("bits", reason, StringComparison.Ordinal, "The reported reason must name the member that was malformed.");
    }


    /// <summary>
    /// "Check for the existence of the required claims as defined in Section 5.1" — a REQUIRED claim
    /// that is absent, or present with a value of the wrong shape, leaves the claims set unable to
    /// stand for a Status List Token, so the read must refuse and name what is wrong instead of
    /// inventing a value.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// </summary>
    /// <param name="claimName">The REQUIRED claim or member the reported reason must name.</param>
    /// <param name="shape">Names the malformation applied to the hand-built claims set.</param>
    [TestMethod]
    [DataRow("sub", "absent")]
    [DataRow("sub", "number")]
    [DataRow("sub", "blank")]
    [DataRow("iat", "absent")]
    [DataRow("iat", "text")]
    [DataRow("status_list", "absent")]
    [DataRow("status_list", "text")]
    [DataRow("bits", "absent")]
    [DataRow("bits", "text")]
    [DataRow("lst", "absent")]
    [DataRow("lst", "number")]
    public void TryFromPayloadRefusesAMissingOrWronglyTypedRequiredClaim(string claimName, string shape)
    {
        JwtPayload payload = HandBuiltClaimsSet();
        IDictionary<string, object> claims = claimName is "bits" or "lst"
            ? (Dictionary<string, object>)payload["status_list"]
            : payload;

        _ = shape switch
        {
            "absent" => claims.Remove(claimName),
            "number" => Replaced(claims, claimName, 42L),
            "text" => Replaced(claims, claimName, "not-a-number"),
            "blank" => Replaced(claims, claimName, "   "),
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "Unknown malformation.")
        };

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsFalse(isRead, $"A claims set whose '{claimName}' is {shape} carries no Status List Token.");
        Assert.IsNull(decoded, "A refused claims set yields no token.");
        Assert.IsNotNull(reason);
        Assert.Contains(claimName, reason, StringComparison.Ordinal, "The reported reason must name the REQUIRED claim that was missing or malformed.");
    }


    /// <summary>
    /// "The value of the claim MUST be a positive number encoded in JSON as a number." Zero and every
    /// negative value fail that sentence, so neither may be read as a cache lifetime.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    /// <param name="timeToLiveSeconds">The non-positive value carried as <c>ttl</c>.</param>
    [TestMethod]
    [DataRow(0L)]
    [DataRow(-1L)]
    [DataRow(-43200L)]
    public void TryFromPayloadRefusesATimeToLiveThatIsNotPositive(long timeToLiveSeconds)
    {
        JwtPayload payload = HandBuiltClaimsSet();
        payload["ttl"] = timeToLiveSeconds;

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsFalse(isRead, "A 'ttl' that is not a positive number must be refused.");
        Assert.IsNull(decoded, "A refused claims set yields no token.");
        Assert.IsNotNull(reason);
        Assert.Contains("ttl", reason, StringComparison.Ordinal, "The reported reason must name the claim that was malformed.");
    }


    /// <summary>
    /// "The allowed values for bits are 1, 2, 4, and 8." Any other width leaves the compressed byte
    /// array unreadable — an unpacking at the wrong stride would report the status of the wrong
    /// Referenced Token — so it must be refused rather than approximated.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    /// <param name="bits">The disallowed number of bits per Referenced Token.</param>
    [TestMethod]
    [DataRow(-1L)]
    [DataRow(0L)]
    [DataRow(3L)]
    [DataRow(5L)]
    [DataRow(6L)]
    [DataRow(7L)]
    [DataRow(9L)]
    [DataRow(16L)]
    public void TryFromPayloadRefusesABitsValueOutsideTheAllowedSet(long bits)
    {
        JwtPayload payload = HandBuiltClaimsSet();
        ((Dictionary<string, object>)payload["status_list"])["bits"] = bits;

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsFalse(isRead, $"{bits} is not one of the allowed values 1, 2, 4 and 8.");
        Assert.IsNull(decoded, "A refused claims set yields no token.");
        Assert.IsNotNull(reason);
        Assert.Contains("bits", reason, StringComparison.Ordinal, "The reported reason must name the member that was out of its allowed set.");
    }


    /// <summary>
    /// "lst: REQUIRED. … The value MUST be the base64url-encoded compressed byte array as specified in
    /// Section 4.1." Decoded at each allowed width, every status value the encoder packed must come
    /// back at the very index it was written to.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    /// <param name="bits">The number of bits per Referenced Token.</param>
    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(4)]
    [DataRow(8)]
    public void TryFromPayloadDecodesTheCompressedListSoEveryStatusBitMatches(int bits)
    {
        var bitSize = (StatusListBitSize)bits;
        int capacity = 64 / bits;
        byte maximumStatus = (byte)((1 << bits) - 1);

        using StatusListType list = StatusListType.Create(capacity, bitSize, Pool, BitOrder.LeastSignificantFirst);
        list[0] = 1;
        list[1] = maximumStatus;
        list[capacity / 2] = (byte)(maximumStatus / 2);
        list[capacity - 1] = maximumStatus;

        JwtPayload payload = HandBuiltClaimsSet(Base64Url.EncodeToString(list.Compress()), bits);

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsTrue(isRead, $"A conforming Status List at {bits} bits must be read: {reason}");
        Assert.IsNotNull(decoded);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(bitSize, decodedList.BitSize, "The decoded list must carry the number of bits it was encoded at.");
        Assert.AreEqual(capacity, decodedList.Capacity, "The decoded list must carry every entry of the compressed byte array.");

        for(int index = 0; index < capacity; ++index)
        {
            Assert.AreEqual(list[index], decodedList[index], $"The status value at index {index} must survive the encoding.");
        }
    }


    /// <summary>
    /// "The following additional rules apply: 1. The JWT MAY contain other claims." A claims set
    /// carrying registered and private claims beside the Status List Token's own must still be read,
    /// so an issuer extending its claims set never makes the token unreadable.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TryFromPayloadToleratesClaimsItDoesNotRead()
    {
        JwtPayload payload = HandBuiltClaimsSet();
        payload["iss"] = "https://issuer.example";
        payload["jti"] = "e2f7a1c0";
        payload["nbf"] = 5L;
        payload["cnf"] = new Dictionary<string, object> { ["jwk"] = new Dictionary<string, object> { ["kty"] = "EC" } };
        payload["aud"] = new List<object> { "https://verifier.example" };

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsTrue(isRead, $"Claims the Status List Token does not define must be tolerated: {reason}");
        Assert.IsNotNull(decoded);
        using StatusListType decodedList = decoded.StatusList;

        Assert.AreEqual(ExampleTokenSubject, decoded.Subject, "'sub' must be read across the other claims.");
        Assert.AreEqual(StatusListBitSize.OneBit, decodedList.BitSize, "'status_list' must be read across the other claims.");
    }


    /// <summary>
    /// "If any of these checks fails, no statement about the status of the Referenced Token can be
    /// made and the Referenced Token SHOULD be rejected." A Status List Token arrives from the
    /// network, so every malformation of its claims set — including a <c>lst</c> that is not
    /// base64url, or is base64url of something that was never compressed — must be reported as a
    /// refusal the caller can act on, never raised as a fault that escapes the read.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// </summary>
    /// <param name="shape">Names the malformation applied to the hand-built claims set.</param>
    [TestMethod]
    [DataRow("empty-claims-set")]
    [DataRow("subject-is-a-number")]
    [DataRow("issued-at-is-text")]
    [DataRow("status-list-is-text")]
    [DataRow("status-list-is-empty")]
    [DataRow("expiry-is-text")]
    [DataRow("time-to-live-is-text")]
    [DataRow("list-is-empty")]
    [DataRow("list-is-not-base64url")]
    [DataRow("list-is-not-compressed")]
    public void TryFromPayloadNeverThrowsOnAMalformedClaimsSet(string shape)
    {
        JwtPayload payload = MalformedClaimsSet(shape);

        Exception? thrown = null;
        bool isRead = false;
        StatusListToken? decoded = null;
        string? reason = null;
        try
        {
            isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out decoded, out reason, out _);
        }
        catch(Exception exception)
        {
            thrown = exception;
        }

        Assert.IsNull(thrown, $"A claims set whose shape is '{shape}' must be reported as a refusal, not raised as {thrown?.GetType().Name}: {thrown?.Message}");
        Assert.IsFalse(isRead, $"A claims set whose shape is '{shape}' carries no Status List Token.");
        Assert.IsNull(decoded, "A refused claims set yields no token.");
        Assert.IsNotNull(reason, "A refusal must say what was wrong with the claims set.");
    }


    /// <summary>
    /// The decoded Status List is a pooled carrier the caller owns: it must come from the pool the
    /// read was handed, and disposing it must return every buffer the read rented.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TryFromPayloadAllocatesTheDecodedListFromTheSuppliedPool()
    {
        using var metered = new MeteredHousePool();
        JwtPayload payload = HandBuiltClaimsSet();

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, metered.Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsTrue(isRead, $"A conforming claims set must be read: {reason}");
        Assert.IsNotNull(decoded);
        Assert.IsGreaterThan(0L, metered.RentedCount, "The decoded Status List must be allocated from the supplied pool.");

        decoded.StatusList.Dispose();

        Assert.AreEqual(0L, metered.OutstandingCount, "Disposing the decoded Status List must return every buffer the read rented.");
    }


    /// <summary>
    /// A decompression bomb — an <c>lst</c> engineered to inflate past
    /// <see cref="StatusListType.DefaultMaxDecompressedByteCount"/> — is reported the same way every other
    /// malformed <c>lst</c> is: a refusal naming the claim, never an <see cref="InvalidDataException"/>
    /// escaping the read.
    /// </summary>
    [TestMethod]
    public void TryFromPayloadRefusesAListThatInflatesPastTheDefaultCeiling()
    {
        JwtPayload payload = HandBuiltClaimsSet();
        ((Dictionary<string, object>)payload["status_list"])["lst"] = Base64Url.EncodeToString(CompressedZeros(StatusListType.DefaultMaxDecompressedByteCount + 1024));

        bool isRead = StatusListTokenClaims.TryFromPayload(payload, TestSetup.Base64UrlDecoder, Pool, out StatusListToken? decoded, out string? reason, out _);

        Assert.IsFalse(isRead, "An 'lst' that inflates past the default ceiling must be refused.");
        Assert.IsNull(decoded, "A refused claims set yields no token.");
        Assert.IsNotNull(reason);
        Assert.Contains("lst", reason, StringComparison.Ordinal, "The reported reason must name the claim that inflated past the ceiling.");
    }


    /// <summary>
    /// Builds a ZLIB-compressed run of <paramref name="decompressedByteCount"/> zero bytes — cheap to
    /// construct and highly compressible, the same decompression-bomb shape a hostile Status Provider
    /// would publish.
    /// </summary>
    /// <param name="decompressedByteCount">How many zero bytes the compressed stream inflates to.</param>
    /// <returns>The compressed bytes.</returns>
    private static byte[] CompressedZeros(int decompressedByteCount)
    {
        using var output = new System.IO.MemoryStream();
        using(var zlib = new System.IO.Compression.ZLibStream(output, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
        {
            zlib.Write(new byte[decompressedByteCount]);
        }

        return output.ToArray();
    }


    /// <summary>
    /// Inflates a ZLIB-compressed byte array, standing in for the wire-independent decompression a
    /// test proves Section 4.1's bit packing against, without going through
    /// <see cref="StatusListType.FromCompressed(ReadOnlySpan{byte}, StatusListBitSize, BaseMemoryPool, BitOrder)"/>.
    /// </summary>
    /// <param name="compressed">The ZLIB-compressed byte array.</param>
    /// <returns>The inflated bytes.</returns>
    private static byte[] Decompressed(byte[] compressed)
    {
        using var input = new System.IO.MemoryStream(compressed);
        using var zlib = new System.IO.Compression.ZLibStream(input, System.IO.Compression.CompressionMode.Decompress);
        using var output = new System.IO.MemoryStream();
        zlib.CopyTo(output);

        return output.ToArray();
    }


    /// <summary>
    /// Builds a conforming Section 5.1 claims set by hand, member for member as the wire spells it:
    /// the three REQUIRED claims, with the Section 4.2 one-bit example as the Status List.
    /// </summary>
    /// <returns>The hand-built claims set.</returns>
    private static JwtPayload HandBuiltClaimsSet()
    {
        return HandBuiltClaimsSet(OneBitEncodedList, 1);
    }


    /// <summary>
    /// Builds a conforming Section 5.1 claims set by hand around a given compressed list.
    /// </summary>
    /// <param name="encodedList">The base64url-encoded compressed byte array carried as <c>lst</c>.</param>
    /// <param name="bits">The number of bits per Referenced Token carried as <c>bits</c>.</param>
    /// <returns>The hand-built claims set.</returns>
    private static JwtPayload HandBuiltClaimsSet(string encodedList, int bits)
    {
        return new JwtPayload
        {
            ["sub"] = ExampleTokenSubject,
            ["iat"] = SmallIssuedAtSeconds,
            ["status_list"] = new Dictionary<string, object>
            {
                ["bits"] = (long)bits,
                ["lst"] = encodedList
            }
        };
    }


    /// <summary>
    /// Builds a claims set malformed in one named way, each shape standing for something a hostile or
    /// non-conforming Status Provider could put on the wire.
    /// </summary>
    /// <param name="shape">Names the malformation.</param>
    /// <returns>The malformed claims set.</returns>
    private static JwtPayload MalformedClaimsSet(string shape)
    {
        if(shape == "empty-claims-set")
        {
            return new JwtPayload();
        }

        JwtPayload payload = HandBuiltClaimsSet();
        var statusListClaim = (Dictionary<string, object>)payload["status_list"];

        _ = shape switch
        {
            "subject-is-a-number" => Replaced(payload, "sub", 42L),
            "issued-at-is-text" => Replaced(payload, "iat", "1686920170"),
            "status-list-is-text" => Replaced(payload, "status_list", "eNrbuRgAAhcBXQ"),
            "status-list-is-empty" => Replaced(payload, "status_list", new Dictionary<string, object>()),
            "expiry-is-text" => Replaced(payload, "exp", "2291720170"),
            "time-to-live-is-text" => Replaced(payload, "ttl", "43200"),
            "list-is-empty" => Replaced(statusListClaim, "lst", string.Empty),
            "list-is-not-base64url" => Replaced(statusListClaim, "lst", "!!! not base64url !!!"),
            "list-is-not-compressed" => Replaced(statusListClaim, "lst", "AAAAAAAAAAAA"),
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "Unknown malformation.")
        };

        return payload;
    }


    /// <summary>
    /// Boxes a whole number as one named .NET integer family, standing for the choices a claims
    /// deserializer makes when it hands a JSON number back as <see cref="object"/>.
    /// </summary>
    /// <param name="value">The whole number to box.</param>
    /// <param name="family">Names the integer family.</param>
    /// <returns>The boxed value.</returns>
    private static object Boxed(long value, string family) => family switch
    {
        "Int64" => (object)value,
        "Int32" => (int)value,
        "Int16" => (short)value,
        "SByte" => (sbyte)value,
        "Byte" => (byte)value,
        "UInt16" => (ushort)value,
        "UInt32" => (uint)value,
        "UInt64" => (ulong)value,
        "Decimal" => (decimal)value,
        _ => throw new ArgumentOutOfRangeException(nameof(family), family, "Unknown integer family.")
    };


    /// <summary>
    /// Replaces one entry of a claims dictionary, returning <see langword="true"/> so the call reads as
    /// an arm of a switch expression beside <see cref="Dictionary{TKey, TValue}.Remove(TKey)"/>.
    /// </summary>
    /// <param name="claims">The dictionary to change.</param>
    /// <param name="name">The member to replace.</param>
    /// <param name="value">The replacement value.</param>
    /// <returns>Always <see langword="true"/>.</returns>
    private static bool Replaced(IDictionary<string, object> claims, string name, object value)
    {
        claims[name] = value;

        return true;
    }
}
