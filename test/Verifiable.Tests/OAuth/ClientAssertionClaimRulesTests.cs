using System.Globalization;
using System.Text;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the one judgement of a client assertion's claims (<see cref="ClientAssertionClaimRules"/>) every key source and every
/// assertion method shares, against RFC 7523 Section 3 and RFC 7519 Sections 2 and 4.1 as their text reads: each rule refused
/// under its own name and in the order the rules are judged, the NumericDate read as a JSON number alone with a fraction kept to
/// the tick and a finer remainder taken on the side that never widens the window, one identifier contract, the audience rule refusing a foreign value beside this server's, the instant an
/// assertion stops being accepted, and the replay guard consulted only for claims every other rule accepts.
/// </summary>
[TestClass]
internal sealed class ClientAssertionClaimRulesTests
{
    /// <summary>The test context, carrying the cancellation token every call observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The client the assertions authenticate.</summary>
    private const string ClientId = "https://client.example.com/app";

    /// <summary>The authorization server's issuer identifier.</summary>
    private const string Issuer = "https://as.example.com/realm";

    /// <summary>The authorization server's token endpoint.</summary>
    private const string TokenEndpoint = "https://as.example.com/realm/token";

    /// <summary>The identities an assertion's audience may name.</summary>
    private static string[] Audiences { get; } = [Issuer, TokenEndpoint];

    /// <summary>The instant every judgement is made at.</summary>
    private static DateTimeOffset Now { get; } = TestClock.CanonicalEpoch;

    /// <summary>The clock-skew tolerance every judgement is made under, in ticks: a minute.</summary>
    private const long ToleranceTicks = 60 * TimeSpan.TicksPerSecond;

    /// <summary>The clock-skew tolerance every judgement is made under.</summary>
    private static TimeSpan Skew { get; } = TimeSpan.FromTicks(ToleranceTicks);


    /// <summary>Claims every rule accepts: the client as issuer and subject, the issuer as audience, a minute's lifetime and a jti.</summary>
    /// <returns>The claims, fresh for each row to change.</returns>
    private static Dictionary<string, object> ValidClaims() => new(StringComparer.Ordinal)
    {
        [WellKnownJwtClaimNames.Iss] = ClientId,
        [WellKnownJwtClaimNames.Sub] = ClientId,
        [WellKnownJwtClaimNames.Aud] = Issuer,
        [WellKnownJwtClaimNames.Iat] = Now.ToUnixTimeSeconds(),
        [WellKnownJwtClaimNames.Exp] = Now.AddMinutes(1).ToUnixTimeSeconds(),
        [WellKnownJwtClaimNames.Jti] = "assertion-jti"
    };


    /// <summary>
    /// Claims every rule accepts are accepted, naming the jti, the exp as written, and the record of the first use kept until an
    /// instant within the clock, exclusive: exp plus the tolerance.
    /// </summary>
    [TestMethod]
    public void ClaimsEveryRuleAcceptsAreAccepted()
    {
        var judged = ClientAssertionClaimRules.Judge(ValidClaims(), ClientId, Audiences, Now, Skew);

        Assert.IsTrue(judged.IsAccepted, judged.Refusal?.ToString());
        Assert.AreEqual("assertion-jti", judged.Jti);
        Assert.AreEqual(0, judged.Expiry!.CompareTo(Now.AddMinutes(1)), "The exp is carried as written.");
        Assert.AreEqual(new ReplayRecordKeptUntil(Now.AddMinutes(1) + Skew), judged.Retention, "A minute's window ends within the clock.");
    }


    /// <summary>Each rule is refused under its own name when its claim alone breaks it.</summary>
    /// <param name="claim">The claim the row changes.</param>
    /// <param name="change">How it changes it: <c>remove</c>, or the name of the value it writes.</param>
    /// <param name="expected">The rule refused.</param>
    [TestMethod]
    [DataRow("iss", "remove", ClientAssertionClaimRefusal.NotTheClient)]
    [DataRow("iss", "foreign", ClientAssertionClaimRefusal.NotTheClient)]
    [DataRow("sub", "foreign", ClientAssertionClaimRefusal.NotTheClient)]
    [DataRow("sub", "number", ClientAssertionClaimRefusal.NotTheClient)]
    [DataRow("aud", "remove", ClientAssertionClaimRefusal.AudienceNotThisServer)]
    [DataRow("aud", "foreign", ClientAssertionClaimRefusal.AudienceNotThisServer)]
    [DataRow("aud", "mixed", ClientAssertionClaimRefusal.AudienceNotThisServer)]
    [DataRow("aud", "empty-array", ClientAssertionClaimRefusal.AudienceNotThisServer)]
    [DataRow("aud", "number", ClientAssertionClaimRefusal.AudienceNotThisServer)]
    [DataRow("exp", "remove", ClientAssertionClaimRefusal.ExpiryNotPresented)]
    [DataRow("exp", "digits", ClientAssertionClaimRefusal.ExpiryNotANumericDate)]
    [DataRow("exp", "past", ClientAssertionClaimRefusal.Expired)]
    [DataRow("iat", "digits", ClientAssertionClaimRefusal.IssuedAtNotANumericDate)]
    [DataRow("iat", "after-exp", ClientAssertionClaimRefusal.ExpiryNotAfterIssuedAt)]
    [DataRow("iat", "future", ClientAssertionClaimRefusal.IssuedInTheFuture)]
    [DataRow("nbf", "digits", ClientAssertionClaimRefusal.NotBeforeNotANumericDate)]
    [DataRow("nbf", "after-exp", ClientAssertionClaimRefusal.ExpiryNotAfterNotBefore)]
    [DataRow("nbf", "future", ClientAssertionClaimRefusal.NotYetValid)]
    [DataRow("jti", "remove", ClientAssertionClaimRefusal.IdentifierNotPresented)]
    [DataRow("jti", "empty", ClientAssertionClaimRefusal.IdentifierNotPresented)]
    [DataRow("jti", "blank", ClientAssertionClaimRefusal.IdentifierNotPresented)]
    public void EachRuleIsRefusedUnderItsOwnName(string claim, string change, ClientAssertionClaimRefusal expected)
    {
        var claims = ValidClaims();

        if(string.Equals(change, "remove", StringComparison.Ordinal))
        {
            _ = claims.Remove(claim);
        }
        else
        {
            claims[claim] = ValueOf(claim, change);
        }

        //An instant ahead of the tolerance and still before exp, and an exp passed while iat stays before it, each break the one
        //rule the row names.
        if(string.Equals(change, "future", StringComparison.Ordinal))
        {
            claims[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(5).ToUnixTimeSeconds();
        }

        if(string.Equals(change, "past", StringComparison.Ordinal))
        {
            claims[WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-3).ToUnixTimeSeconds();
        }

        var judged = ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, Now, Skew);

        Assert.AreEqual(expected, judged.Refusal, $"{claim} {change}");
        Assert.IsNull(judged.Jti, "A refused judgement names no jti.");
    }


    /// <summary>
    /// The rules are judged in order and the first broken is named: claims breaking the identity, the audience and the expiry at
    /// once are refused for the identity; breaking the audience and the jti, for the audience.
    /// </summary>
    [TestMethod]
    public void TheFirstRuleBrokenIsNamed()
    {
        var claims = ValidClaims();
        claims[WellKnownJwtClaimNames.Iss] = "https://impostor.example";
        claims[WellKnownJwtClaimNames.Aud] = "https://other-as.example";
        _ = claims.Remove(WellKnownJwtClaimNames.Exp);

        Assert.AreEqual(ClientAssertionClaimRefusal.NotTheClient, ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, Now, Skew).Refusal);

        claims = ValidClaims();
        claims[WellKnownJwtClaimNames.Aud] = "https://other-as.example";
        _ = claims.Remove(WellKnownJwtClaimNames.Jti);

        Assert.AreEqual(ClientAssertionClaimRefusal.AudienceNotThisServer, ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, Now, Skew).Refusal);
    }


    /// <summary>
    /// RFC 7523 Section 3 item 3 with RFC 9126 Section 2: the audience is one of the server's identities or a non-empty array of
    /// them alone, held as a sequence of strings or of values, compared exactly.
    /// </summary>
    [TestMethod]
    public void TheAudienceNamesThisServerAndNothingElse()
    {
        Assert.IsTrue(ClientAssertionClaimRules.AudienceNamesOnly(TokenEndpoint, Audiences));
        Assert.IsTrue(ClientAssertionClaimRules.AudienceNamesOnly(new[] { Issuer, TokenEndpoint }, Audiences));
        Assert.IsTrue(ClientAssertionClaimRules.AudienceNamesOnly(new List<object> { TokenEndpoint }, Audiences));
        Assert.IsFalse(ClientAssertionClaimRules.AudienceNamesOnly(new List<object> { TokenEndpoint, 7 }, Audiences), "A value that is no string refuses the array.");
        Assert.IsFalse(ClientAssertionClaimRules.AudienceNamesOnly(new[] { TokenEndpoint, "https://evil.example" }, Audiences), "A foreign value refuses the array.");
        Assert.IsFalse(ClientAssertionClaimRules.AudienceNamesOnly(Issuer.ToUpperInvariant(), Audiences), "The comparison is exact.");
        Assert.IsFalse(ClientAssertionClaimRules.AudienceNamesOnly(Issuer + "/", Audiences), "The comparison is exact.");
        Assert.IsFalse(ClientAssertionClaimRules.AudienceNamesOnly(string.Empty, [string.Empty]), "An empty value names nothing.");
        Assert.IsFalse(ClientAssertionClaimRules.AudienceNamesOnly(null, Audiences));
    }


    /// <summary>
    /// The assertion is accepted until exp plus the tolerance and refused from that instant on; the record of an exp the tolerance
    /// would carry past the last instant a clock represents is kept to the clock's end, never thrown on.
    /// </summary>
    [TestMethod]
    public void TheAssertionIsAcceptedUntilExpPlusTheTolerance()
    {
        var claims = ValidClaims();
        var expiry = Now.AddMinutes(1);

        Assert.IsTrue(ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, expiry + Skew - TimeSpan.FromTicks(1), Skew).IsAccepted);
        Assert.AreEqual(ClientAssertionClaimRefusal.Expired, ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, expiry + Skew, Skew).Refusal);
        Assert.AreEqual(new ReplayRecordKeptToTheClocksEnd(), ClientAssertionClaimRules.ReplayRecordRetentionOf(DateTimeOffset.MaxValue.AddSeconds(-1), Skew));
    }


    /// <summary>
    /// RFC 7519 Section 4.1.4 at the clock's end: the present must lie before exp extended by the tolerance, judged against the
    /// exp as written, never against an instant the clock's end clips. An assertion whose exp is the clock's last tick is accepted
    /// at that tick and at the tick before it, as is one whose exp a tick earlier or whose window ends a tick past the clock; one
    /// whose window ends exactly at the clock's last tick is refused at that tick and accepted at the tick before it.
    /// </summary>
    /// <param name="expiryTicksBeforeTheEnd">How many ticks the exp lies before the clock's last tick.</param>
    /// <param name="nowTicksBeforeTheEnd">How many ticks the present lies before the clock's last tick.</param>
    /// <param name="accepted">Whether the assertion is accepted.</param>
    [TestMethod]
    [DataRow(0L, 0L, true)]
    [DataRow(0L, 1L, true)]
    [DataRow(1L, 0L, true)]
    [DataRow(ToleranceTicks - 1, 0L, true)]
    [DataRow(ToleranceTicks, 0L, false)]
    [DataRow(ToleranceTicks, 1L, true)]
    public void AnExpiryAtTheClocksEndIsJudgedExactlyUnderTheTolerance(long expiryTicksBeforeTheEnd, long nowTicksBeforeTheEnd, bool accepted)
    {
        var claims = ValidClaims();
        claims[WellKnownJwtClaimNames.Exp] = NumericDate.FromInstant(DateTimeOffset.MaxValue.AddTicks(-expiryTicksBeforeTheEnd));

        var expected = accepted ? (ClientAssertionClaimRefusal?)null : ClientAssertionClaimRefusal.Expired;
        var judged = ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, DateTimeOffset.MaxValue.AddTicks(-nowTicksBeforeTheEnd), Skew);

        Assert.AreEqual(expected, judged.Refusal, $"exp {expiryTicksBeforeTheEnd} ticks and now {nowTicksBeforeTheEnd} ticks before the clock's end.");
    }


    /// <summary>
    /// RFC 7523 Section 3 item 7 at the clock's end, before a store that drops a record once the window it is kept for has ended:
    /// an assertion whose exp is the clock's last tick, first used at that tick, is accepted and its first use recorded as kept to
    /// the clock's end, and the same assertion presented again at that tick is refused as a replay, the store keeping the record
    /// by the carried fact. A store handed only the clock's last instant as the record's end would drop it at that very tick, so
    /// the replay would read as a first use; the contrast row shows that store answering so, which the carried fact prevents.
    /// </summary>
    /// <param name="storeReadsTheRetention">Whether the store drops by the retention the guard is handed, or by its last instant alone.</param>
    /// <param name="replayRefused">Whether the replay at the clock's last tick is refused.</param>
    /// <returns>A task completing once both presentations are judged.</returns>
    [TestMethod]
    [DataRow(true, true)]
    [DataRow(false, false)]
    public async Task AFirstUseAtTheClocksLastTickIsKeptToTheClocksEndAndItsReplayRefused(bool storeReadsTheRetention, bool replayRefused)
    {
        var claims = ValidClaims();
        claims[WellKnownJwtClaimNames.Exp] = NumericDate.FromInstant(DateTimeOffset.MaxValue);
        var store = new ExpiringReplayStore(storeReadsTheRetention);

        var firstUse = await ClientAssertionClaimRules.JudgeAsync(
            claims, ClientId, Audiences, DateTimeOffset.MaxValue, Skew, store.ConsultAt(DateTimeOffset.MaxValue), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(firstUse.IsAccepted, $"A first use at the clock's last tick is accepted; got {firstUse.Refusal}.");
        Assert.AreEqual(new ReplayRecordKeptToTheClocksEnd(), store.RetentionOf("assertion-jti"), "The first use is recorded as kept to the clock's end.");

        var replay = await ClientAssertionClaimRules.JudgeAsync(
            claims, ClientId, Audiences, DateTimeOffset.MaxValue, Skew, store.ConsultAt(DateTimeOffset.MaxValue), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            replayRefused ? ClientAssertionClaimRefusal.IdentifierReplayed : null,
            replay.Refusal,
            storeReadsTheRetention
                ? "The record kept to the clock's end is kept at its last tick, so the replay is refused."
                : "A store dropping by the last instant alone drops the record at that tick, so the replay reads as a first use.");
    }


    /// <summary>
    /// RFC 7523 Section 3 item 7 for a window that ends exactly at the clock's last tick, exclusive: the record is kept until that
    /// instant, so the assertion first used a tick before it is refused as a replay at that tick before, before a store that drops
    /// records when their exclusive end is reached; at the clock's last tick the assertion itself is refused as expired, and the
    /// store may drop its record.
    /// </summary>
    /// <returns>A task completing once the presentations are judged.</returns>
    [TestMethod]
    public async Task AWindowEndingAtTheClocksLastTickKeepsItsRecordUntilThatTickExclusive()
    {
        var expiry = DateTimeOffset.MaxValue.AddTicks(-ToleranceTicks);
        var claims = ValidClaims();
        claims[WellKnownJwtClaimNames.Exp] = NumericDate.FromInstant(expiry);
        var store = new ExpiringReplayStore(readsRetention: true);
        var tickBefore = DateTimeOffset.MaxValue.AddTicks(-1);

        var firstUse = await ClientAssertionClaimRules.JudgeAsync(
            claims, ClientId, Audiences, tickBefore, Skew, store.ConsultAt(tickBefore), TestContext.CancellationToken).ConfigureAwait(false);
        var replay = await ClientAssertionClaimRules.JudgeAsync(
            claims, ClientId, Audiences, tickBefore, Skew, store.ConsultAt(tickBefore), TestContext.CancellationToken).ConfigureAwait(false);
        var atTheEnd = await ClientAssertionClaimRules.JudgeAsync(
            claims, ClientId, Audiences, DateTimeOffset.MaxValue, Skew, store.ConsultAt(DateTimeOffset.MaxValue), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(firstUse.IsAccepted, $"A first use a tick before the window's end is accepted; got {firstUse.Refusal}.");
        Assert.AreEqual(new ReplayRecordKeptUntil(DateTimeOffset.MaxValue), store.RetentionOf("assertion-jti"), "The record is kept until the clock's last tick, exclusive.");
        Assert.AreEqual(ClientAssertionClaimRefusal.IdentifierReplayed, replay.Refusal, "The replay before the window's end is refused.");
        Assert.AreEqual(ClientAssertionClaimRefusal.Expired, atTheEnd.Refusal, "At the window's exclusive end the assertion is expired.");
    }


    /// <summary>
    /// The judgement states whether the window reaches the clock's end, never an instant clipped to the clock standing for it: an
    /// exp at the clock's last tick, or whose window ends a tick past the clock, reaches it, its record kept to the clock's end;
    /// one whose window ends exactly at the clock's last tick, or a tick before it, does not, its record kept until that instant,
    /// exclusive.
    /// </summary>
    /// <param name="expiryTicksBeforeTheEnd">How many ticks the exp lies before the clock's last tick.</param>
    /// <param name="reachesTheEnd">Whether the window reaches the clock's end.</param>
    /// <param name="recordTicksBeforeTheEnd">How many ticks before the clock's last tick the record is kept until, where it does not.</param>
    [TestMethod]
    [DataRow(0L, true, 0L)]
    [DataRow(ToleranceTicks - 1, true, 0L)]
    [DataRow(ToleranceTicks, false, 0L)]
    [DataRow(ToleranceTicks + 1, false, 1L)]
    public void TheJudgementStatesWhetherTheWindowReachesTheClocksEnd(long expiryTicksBeforeTheEnd, bool reachesTheEnd, long recordTicksBeforeTheEnd)
    {
        var expiry = DateTimeOffset.MaxValue.AddTicks(-expiryTicksBeforeTheEnd);
        var claims = ValidClaims();
        claims[WellKnownJwtClaimNames.Exp] = NumericDate.FromInstant(expiry);

        var judged = ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, expiry, Skew);

        Assert.IsTrue(judged.IsAccepted, judged.Refusal?.ToString());
        var expected = reachesTheEnd
            ? (ReplayRecordRetention)new ReplayRecordKeptToTheClocksEnd()
            : new ReplayRecordKeptUntil(DateTimeOffset.MaxValue.AddTicks(-recordTicksBeforeTheEnd));

        Assert.AreEqual(expected, judged.Retention, $"exp {expiryTicksBeforeTheEnd} ticks before the clock's end.");
    }


    /// <summary>
    /// RFC 7519 Section 4.1.6 with the tolerance read exactly: an iat at the current instant plus the tolerance is accepted, and
    /// one a fraction of a second past it - 0.75 s, as a decimal and as a floating count - is refused as issued in the future,
    /// since the fraction names an instant past the window and is never taken back into it.
    /// </summary>
    /// <param name="fraction">The fraction of a second past the tolerance, as the claims set holds it.</param>
    [TestMethod]
    [DataRow("decimal")]
    [DataRow("double")]
    public void AnIssuanceAFractionPastTheToleranceIsRefused(string fraction)
    {
        var edge = Now.ToUnixTimeSeconds() + (long)Skew.TotalSeconds;
        var claims = ValidClaims();
        claims[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(5).ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Iat] = edge;

        Assert.IsTrue(ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, Now, Skew).IsAccepted, "An iat at the tolerance's edge is accepted.");

        claims[WellKnownJwtClaimNames.Iat] = string.Equals(fraction, "decimal", StringComparison.Ordinal) ? edge + 0.75m : edge + 0.75d;

        Assert.AreEqual(ClientAssertionClaimRefusal.IssuedInTheFuture, ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, Now, Skew).Refusal,
            "An iat 0.75 s past the tolerance is issued in the future.");
    }


    /// <summary>
    /// A fractional exp names its own instant: an exp a quarter second after the instant the tolerance reaches back to is still
    /// accepted until that quarter second, and refused from it on.
    /// </summary>
    [TestMethod]
    public void AFractionalExpiryIsAcceptedUntilItsOwnInstant()
    {
        var claims = ValidClaims();
        claims[WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-3).ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Exp] = Now.ToUnixTimeSeconds() - (long)Skew.TotalSeconds + 0.25m;

        var judged = ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, Now, Skew);

        Assert.IsTrue(judged.IsAccepted, judged.Refusal?.ToString());
        Assert.AreEqual(new ReplayRecordKeptUntil(Now.AddMilliseconds(250)), judged.Retention);
        Assert.AreEqual(ClientAssertionClaimRefusal.Expired, ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, Now.AddMilliseconds(250), Skew).Refusal);
    }


    /// <summary>
    /// One identifier contract: a jti of white space alone names nothing a replay guard could hold the assertion to, so the
    /// judgement refuses it before any success is built, and the private_key_jwt validator judging by it answers a refusal
    /// rather than throwing from its success factory.
    /// </summary>
    [TestMethod]
    public void AWhiteSpaceIdentifierIsRefusedBeforeAnySuccessIsBuilt()
    {
        var claims = ValidClaims();
        claims[WellKnownJwtClaimNames.Jti] = " ";

        Assert.AreEqual(ClientAssertionClaimRefusal.IdentifierNotPresented, ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, Now, Skew).Refusal);

        var validated = PrivateKeyJwtClientAuthentication.Validate(new JwtPayload(claims), ClientId, Audiences, Now, Skew);

        Assert.IsFalse(validated.IsValid, "The validator refuses a white-space jti.");
        Assert.IsNull(validated.Jti);
    }


    /// <summary>
    /// RFC 7523 Section 3 item 7: claims every other rule accepts are accepted only on the first use of their jti, the guard handed
    /// the jti and the retention until the instant the assertion stops being accepted; every other outcome is refused under its own name; and claims
    /// another rule refuses never reach the guard.
    /// </summary>
    /// <returns>A task completing once every outcome is judged.</returns>
    [TestMethod]
    public async Task TheReplayGuardIsConsultedLastAndEveryOutcomeButAFirstUseRefuses()
    {
        var consulted = new List<string>();

        var cases = new[]
        {
            new ReplayCase(JtiReplayOutcome.FirstUse, null),
            new ReplayCase(JtiReplayOutcome.Replayed, ClientAssertionClaimRefusal.IdentifierReplayed),
            new ReplayCase(JtiReplayOutcome.Unacceptable, ClientAssertionClaimRefusal.IdentifierNotTrackable),
            new ReplayCase(JtiReplayOutcome.StoreUnavailable, ClientAssertionClaimRefusal.ReplayRecordUnavailable),
            new ReplayCase((JtiReplayOutcome)99, ClientAssertionClaimRefusal.ReplayOutcomeNotRecognised)
        };

        foreach(var replayCase in cases)
        {
            var outcome = replayCase.Outcome;

            var judged = await ClientAssertionClaimRules.JudgeAsync(
                ValidClaims(), ClientId, Audiences, Now, Skew,
                (jti, retention, cancellationToken) =>
                {
                    consulted.Add($"{jti}|{retention}");

                    return ValueTask.FromResult(outcome);
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(replayCase.Expected, judged.Refusal, outcome.ToString());
        }

        Assert.HasCount(5, consulted);
        Assert.IsTrue(consulted.All(entry => string.Equals(entry, $"assertion-jti|{new ReplayRecordKeptUntil(Now.AddMinutes(1) + Skew)}", StringComparison.Ordinal)),
            "The guard is handed the jti and the instant the assertion stops being accepted.");

        var foreign = ValidClaims();
        foreign[WellKnownJwtClaimNames.Aud] = "https://other-as.example";

        var refused = await ClientAssertionClaimRules.JudgeAsync(
            foreign, ClientId, Audiences, Now, Skew,
            (jti, retention, cancellationToken) => throw new AssertFailedException("Claims another rule refuses never reach the guard."),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClientAssertionClaimRefusal.AudienceNotThisServer, refused.Refusal);
    }


    /// <summary>
    /// RFC 7519 Section 7.2 step 10 and Section 4: a verified assertion's payload is read as its claims set only when it is one
    /// JSON object naming each claim once; an array, a repeated claim, bytes that are no JSON and a value with no payload segment
    /// are read as none, without throwing.
    /// </summary>
    [TestMethod]
    public void TheClaimsSetIsOneJsonObjectNamingEachClaimOnce()
    {
        var read = ReadClaimsSet(/*lang=json*/ "{\"iss\":\"a\",\"exp\":1}");

        Assert.IsNotNull(read);
        Assert.AreEqual("a", read[WellKnownJwtClaimNames.Iss]);

        foreach(var payload in new[] { "[1]", "\"text\"", /*lang=json*/ "{\"iss\":\"a\",\"iss\":\"b\"}", "{\"iss\":" })
        {
            Assert.IsNull(ReadClaimsSet(payload), payload);
        }

        Assert.IsNull(ClientAssertionClaimRules.ReadClaimsSet("no-segments", TestSetup.Base64UrlDecoder, PayloadDeserializer, BaseMemoryPool.Shared));
    }


    /// <summary>Reads the claims set of a compact value whose payload segment is the base64url of the JSON text given.</summary>
    /// <param name="payload">The payload's JSON text.</param>
    /// <returns>The claims, or <see langword="null"/>.</returns>
    private static IReadOnlyDictionary<string, object>? ReadClaimsSet(string payload) =>
        ClientAssertionClaimRules.ReadClaimsSet(
            $"eyJhbGciOiJIUzI1NiJ9.{TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payload))}.c2ln", TestSetup.Base64UrlDecoder, PayloadDeserializer, BaseMemoryPool.Shared);


    /// <summary>Reads a claims set.</summary>
    private static JwtPayloadDeserializer PayloadDeserializer { get; } =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("The payload parsed to null.");

    /// <summary>The value a row writes into a claim.</summary>
    /// <param name="claim">The claim.</param>
    /// <param name="change">The name of the value.</param>
    /// <returns>The value.</returns>
    private static object ValueOf(string claim, string change) => change switch
    {
        "foreign" => "https://impostor.example/app",
        "number" => 42L,
        "mixed" => new List<object> { Issuer, "https://evil.example" },
        "empty-array" => new List<object>(),
        "empty" => string.Empty,
        "blank" => " \t",
        "digits" => Now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
        "past" => Now.AddMinutes(-2).ToUnixTimeSeconds(),
        "after-exp" => Now.AddMinutes(2).ToUnixTimeSeconds(),
        "future" => Now.AddMinutes(2).ToUnixTimeSeconds(),
        _ => throw new ArgumentOutOfRangeException(nameof(change), $"{claim}: no value is named {change}.")
    };


    /// <summary>
    /// A replay store that drops a record once the window it is kept for has ended by the instant it is consulted at: by the
    /// retention it was handed (<see cref="ReplayRecordRetention.IsDueAt"/>), or, for the contrast, by the record's last instant
    /// alone, the instant a store holding one expiry per record is left with, the clock's last instant for a record kept to the
    /// clock's end.
    /// </summary>
    private sealed class ExpiringReplayStore
    {
        /// <summary>Creates a store.</summary>
        /// <param name="readsRetention">Whether the store drops by the retention, or by the last instant alone.</param>
        public ExpiringReplayStore(bool readsRetention)
        {
            ReadsRetention = readsRetention;
        }


        /// <summary>Whether the store drops by the retention, or by the last instant alone.</summary>
        private bool ReadsRetention { get; }

        /// <summary>The records kept, each under its jti with the retention it was handed.</summary>
        private Dictionary<string, ReplayRecordRetention> Records { get; } = new(StringComparer.Ordinal);


        /// <summary>The retention the record of a jti is kept under.</summary>
        /// <param name="jti">The jti.</param>
        /// <returns>The retention.</returns>
        public ReplayRecordRetention RetentionOf(string jti) => Records[jti];


        /// <summary>The consultation of the store at an instant, as the judgement's replay guard.</summary>
        /// <param name="instant">The instant the store's clock reads.</param>
        /// <returns>The consultation.</returns>
        public ConsultClientAssertionFirstUseDelegate ConsultAt(DateTimeOffset instant) => (jti, retention, cancellationToken) =>
        {
            foreach(var ended in Records.Where(record => IsDueAt(record.Value, instant)).Select(static record => record.Key).ToList())
            {
                _ = Records.Remove(ended);
            }

            return ValueTask.FromResult(Records.TryAdd(jti, retention) ? JtiReplayOutcome.FirstUse : JtiReplayOutcome.Replayed);
        };


        /// <summary>Whether a record kept under a retention has ended by an instant, as this store judges it.</summary>
        /// <param name="retention">The retention.</param>
        /// <param name="instant">The instant.</param>
        /// <returns><see langword="true"/> when the store drops the record.</returns>
        private bool IsDueAt(ReplayRecordRetention retention, DateTimeOffset instant) => ReadsRetention
            ? retention.IsDueAt(instant)
            : instant >= (retention is ReplayRecordKeptUntil { End: var end } ? end : DateTimeOffset.MaxValue);
    }


    /// <summary>A replay guard's outcome and the rule a judgement under it names, or none for a first use.</summary>
    /// <param name="Outcome">The guard's outcome.</param>
    /// <param name="Expected">The rule refused, or <see langword="null"/>.</param>
    private sealed record ReplayCase(JtiReplayOutcome Outcome, ClientAssertionClaimRefusal? Expected);
}
