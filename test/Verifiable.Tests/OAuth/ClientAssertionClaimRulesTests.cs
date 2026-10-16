using System.Text;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the one judgement of a client assertion's claims (<see cref="ClientAssertionClaimRules"/>) every key source and every
/// assertion method shares, against RFC 7523 Section 3 and RFC 7519 Sections 2 and 4.1 as their text reads: each rule refused
/// under its own name and in the order the rules are judged, the NumericDate read as a JSON number alone with a fraction taken
/// on the side that never widens the window, the audience rule refusing a foreign value beside this server's, the instant an
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

    /// <summary>The clock-skew tolerance every judgement is made under.</summary>
    private static TimeSpan Skew { get; } = TimeSpan.FromSeconds(60);


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


    /// <summary>Claims every rule accepts are accepted, naming the jti and the instant the assertion stops being accepted: exp plus the tolerance.</summary>
    [TestMethod]
    public void ClaimsEveryRuleAcceptsAreAccepted()
    {
        var judged = ClientAssertionClaimRules.Judge(ValidClaims(), ClientId, Audiences, Now, Skew);

        Assert.IsTrue(judged.IsAccepted, judged.Refusal?.ToString());
        Assert.AreEqual("assertion-jti", judged.Jti);
        Assert.AreEqual(Now.AddMinutes(1) + Skew, judged.AcceptedUntil);
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
    /// RFC 7519 Section 2: a NumericDate is a JSON number, which may carry a fraction. Whole numbers of every width read as their
    /// instant; a fraction is taken down for exp and iat and up for nbf, so the window never widens; a string of digits, a count no
    /// instant represents, and a value of any other kind read as none.
    /// </summary>
    [TestMethod]
    public void ANumericDateIsAJsonNumberTakenOnTheSideThatNeverWidensTheWindow()
    {
        var second = Now.ToUnixTimeSeconds();

        Assert.AreEqual(Now, ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, second));
        Assert.AreEqual(Now, ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, (int)second));
        Assert.AreEqual(Now, ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, (ulong)second));
        Assert.AreEqual(Now, ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, second + 0.75m));
        Assert.AreEqual(Now, ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Iat, second + 0.75d));
        Assert.AreEqual(Now.AddSeconds(1), ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Nbf, second + 0.25m));
        Assert.AreEqual(Now, ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Nbf, second + 0m));
        Assert.IsNull(ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, second.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        Assert.IsNull(ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, long.MaxValue));
        Assert.IsNull(ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, double.NaN));
        Assert.IsNull(ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, decimal.MaxValue));
        Assert.IsNull(ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, true));
        Assert.IsNull(ClientAssertionClaimRules.NumericDateOf(WellKnownJwtClaimNames.Exp, null));
    }


    /// <summary>
    /// The assertion is accepted until exp plus the tolerance and refused from that instant on; an exp the tolerance would carry
    /// past the last instant a clock represents is accepted until that instant, never thrown on.
    /// </summary>
    [TestMethod]
    public void TheAssertionIsAcceptedUntilExpPlusTheTolerance()
    {
        var claims = ValidClaims();
        var expiry = Now.AddMinutes(1);

        Assert.IsTrue(ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, expiry + Skew - TimeSpan.FromTicks(1), Skew).IsAccepted);
        Assert.AreEqual(ClientAssertionClaimRefusal.Expired, ClientAssertionClaimRules.Judge(claims, ClientId, Audiences, expiry + Skew, Skew).Refusal);
        Assert.AreEqual(DateTimeOffset.MaxValue, ClientAssertionClaimRules.AcceptedUntil(DateTimeOffset.MaxValue.AddSeconds(-1), Skew));
    }


    /// <summary>
    /// RFC 7523 Section 3 item 7: claims every other rule accepts are accepted only on the first use of their jti, the guard handed
    /// the jti and the instant the assertion stops being accepted; every other outcome is refused under its own name; and claims
    /// another rule refuses never reach the guard.
    /// </summary>
    /// <returns>A task completing once every outcome is judged.</returns>
    [TestMethod]
    public async Task TheReplayGuardIsConsultedLastAndEveryOutcomeButAFirstUseRefuses()
    {
        var consulted = new List<string>();

        ReplayCase[] cases =
        [
            new(JtiReplayOutcome.FirstUse, null),
            new(JtiReplayOutcome.Replayed, ClientAssertionClaimRefusal.IdentifierReplayed),
            new(JtiReplayOutcome.Unacceptable, ClientAssertionClaimRefusal.IdentifierNotTrackable),
            new(JtiReplayOutcome.StoreUnavailable, ClientAssertionClaimRefusal.ReplayRecordUnavailable),
            new((JtiReplayOutcome)99, ClientAssertionClaimRefusal.ReplayOutcomeNotRecognised)
        ];

        foreach(var replayCase in cases)
        {
            var outcome = replayCase.Outcome;

            var judged = await ClientAssertionClaimRules.JudgeAsync(
                ValidClaims(), ClientId, Audiences, Now, Skew,
                (jti, acceptedUntil, cancellationToken) =>
                {
                    consulted.Add($"{jti}|{acceptedUntil:O}");

                    return ValueTask.FromResult(outcome);
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(replayCase.Expected, judged.Refusal, outcome.ToString());
        }

        Assert.HasCount(5, consulted);
        Assert.IsTrue(consulted.All(entry => string.Equals(entry, $"assertion-jti|{Now.AddMinutes(1) + Skew:O}", StringComparison.Ordinal)),
            "The guard is handed the jti and the instant the assertion stops being accepted.");

        var foreign = ValidClaims();
        foreign[WellKnownJwtClaimNames.Aud] = "https://other-as.example";

        var refused = await ClientAssertionClaimRules.JudgeAsync(
            foreign, ClientId, Audiences, Now, Skew,
            (jti, acceptedUntil, cancellationToken) => throw new AssertFailedException("Claims another rule refuses never reach the guard."),
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
    private static Verifiable.OAuth.JwtPayloadDeserializer PayloadDeserializer { get; } =
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
        "digits" => Now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
        "past" => Now.AddMinutes(-2).ToUnixTimeSeconds(),
        "after-exp" => Now.AddMinutes(2).ToUnixTimeSeconds(),
        "future" => Now.AddMinutes(2).ToUnixTimeSeconds(),
        _ => throw new ArgumentOutOfRangeException(nameof(change), $"{claim}: no value is named {change}.")
    };


    /// <summary>A replay guard's outcome and the rule a judgement under it names, or none for a first use.</summary>
    /// <param name="Outcome">The guard's outcome.</param>
    /// <param name="Expected">The rule refused, or <see langword="null"/>.</param>
    private sealed record ReplayCase(JtiReplayOutcome Outcome, ClientAssertionClaimRefusal? Expected);
}
