using Microsoft.Extensions.Time.Testing;
using System.Collections.Frozen;
using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.OAuth.Contributors;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Server;

/// <summary>
/// Unit rows for <see cref="TokenLifetimes.TryResolve"/>: the order in which a token's lifetime is read (the
/// registration's override, else the request's policy value of that kind, else the server's
/// <see cref="TimingPolicy"/>, else <see cref="TimingPolicy.Default"/> when no server is on the context) and the
/// typed answer for a kind the library issues no token of. The wire rows that show each order take effect on an
/// issued token are in <see cref="Verifiable.Tests.OAuth.AuthCodeParPkceRealWireFlowTests"/>,
/// <see cref="Verifiable.Tests.OAuth.IdJagGrantTests"/> and <see cref="Verifiable.Tests.OAuth.TokenExchangeGrantTests"/>.
/// </summary>
[TestClass]
internal sealed class TokenLifetimesTests
{
    /// <summary>
    /// The row value naming the access token. A constant because <see cref="DataRowAttribute"/> takes compile-time
    /// constants only.
    /// </summary>
    private const string AccessTokenKind = "access_token";

    /// <summary>
    /// The row value naming the ID Token. A constant because <see cref="DataRowAttribute"/> takes compile-time
    /// constants only.
    /// </summary>
    private const string IdTokenKind = "id_token";

    /// <summary>
    /// The row value naming the refresh token. A constant because <see cref="DataRowAttribute"/> takes compile-time
    /// constants only.
    /// </summary>
    private const string RefreshTokenKind = "refresh_token";

    /// <summary>
    /// The row value naming the Identity Assertion JWT Authorization Grant. A constant because
    /// <see cref="DataRowAttribute"/> takes compile-time constants only.
    /// </summary>
    private const string IdJagKind = "id_jag";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC 8693 Section 3</see> lists token type
    /// identifiers the library issues no token of, a SAML 2.0 assertion among them. The library's rule:
    /// <see cref="TokenLifetimes.TryResolve"/> answers <see langword="false"/> for such a kind and states no lifetime,
    /// even when the registration's lifetime map holds an entry under a name of that kind.
    /// </summary>
    [TestMethod]
    public void TryResolveAnswersFalseForAKindWithoutALifetime()
    {
        ClientRecord registration = ContributorTestFixtures.BuildRegistration() with
        {
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty.Add("saml2", TimeSpan.FromMinutes(7))
        };

        bool isResolved = TokenLifetimes.TryResolve(registration, TokenType.Saml2, new ExchangeContext(), out TimeSpan lifetime);

        Assert.IsFalse(isResolved);
        Assert.AreEqual(TimeSpan.Zero, lifetime);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "expires_in
    /// RECOMMENDED. The lifetime in seconds of the access token." The library's rule for the source of that lifetime:
    /// a registration's own override for the kind wins over a policy value of the same kind on the request.
    /// </summary>
    /// <param name="kind">The token kind the row resolves.</param>
    [TestMethod]
    [DataRow(AccessTokenKind)]
    [DataRow(IdTokenKind)]
    [DataRow(RefreshTokenKind)]
    [DataRow(IdJagKind)]
    public void TryResolveReadsTheRegistrationsOverrideFirst(string kind)
    {
        ClientRecord registration = ContributorTestFixtures.BuildRegistration() with
        {
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty.Add(WireNameOf(kind), TimeSpan.FromMinutes(7))
        };
        ExchangeContext context = new();
        SetPolicyValue(context, kind, TimeSpan.FromMinutes(9));

        bool isResolved = TokenLifetimes.TryResolve(registration, TokenTypeOf(kind), context, out TimeSpan lifetime);

        Assert.IsTrue(isResolved);
        Assert.AreEqual(TimeSpan.FromMinutes(7), lifetime);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "expires_in
    /// RECOMMENDED. The lifetime in seconds of the access token." The library's rule for the source of that lifetime:
    /// with no registration override, the request's policy value of the kind is the lifetime.
    /// </summary>
    /// <param name="kind">The token kind the row resolves.</param>
    [TestMethod]
    [DataRow(AccessTokenKind)]
    [DataRow(IdTokenKind)]
    [DataRow(RefreshTokenKind)]
    public void TryResolveReadsThePolicyValueWhenTheRegistrationSetsNone(string kind)
    {
        ExchangeContext context = new();
        SetPolicyValue(context, kind, TimeSpan.FromMinutes(9));

        bool isResolved = TokenLifetimes.TryResolve(
            ContributorTestFixtures.BuildRegistration(), TokenTypeOf(kind), context, out TimeSpan lifetime);

        Assert.IsTrue(isResolved);
        Assert.AreEqual(TimeSpan.FromMinutes(9), lifetime);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "expires_in
    /// RECOMMENDED. The lifetime in seconds of the access token." The library's rule for the source of that lifetime:
    /// with no registration override, no policy value and no server on the context, the lifetime is
    /// <see cref="TimingPolicy.Default"/>'s value of the kind (an hour, an hour, 30 days, five minutes).
    /// </summary>
    /// <param name="kind">The token kind the row resolves.</param>
    /// <param name="expectedSeconds">The default lifetime of the kind, in seconds.</param>
    [TestMethod]
    [DataRow(AccessTokenKind, 3600)]
    [DataRow(IdTokenKind, 3600)]
    [DataRow(RefreshTokenKind, 2592000)]
    [DataRow(IdJagKind, 300)]
    public void TryResolveReadsTheDefaultTimingPolicyWhenNothingIsSet(string kind, int expectedSeconds)
    {
        bool isResolved = TokenLifetimes.TryResolve(
            ContributorTestFixtures.BuildRegistration(), TokenTypeOf(kind), new ExchangeContext(), out TimeSpan lifetime);

        Assert.IsTrue(isResolved);
        Assert.AreEqual(TimeSpan.FromSeconds(expectedSeconds), lifetime);
    }


    /// <summary>
    /// The library's rule for a caller's own argument: <see cref="TokenLifetimes.TryResolve"/> throws
    /// <see cref="ArgumentNullException"/> for a null registration.
    /// </summary>
    [TestMethod]
    public void TryResolveRefusesANullRegistration()
    {
        _ = Assert.ThrowsExactly<ArgumentNullException>(
            () => TokenLifetimes.TryResolve(null!, TokenType.AccessToken, new ExchangeContext(), out _));
    }


    /// <summary>
    /// The library's rule for a caller's own argument: <see cref="TokenLifetimes.TryResolve"/> throws
    /// <see cref="ArgumentNullException"/> for a null exchange context.
    /// </summary>
    [TestMethod]
    public void TryResolveRefusesANullContext()
    {
        _ = Assert.ThrowsExactly<ArgumentNullException>(
            () => TokenLifetimes.TryResolve(ContributorTestFixtures.BuildRegistration(), TokenType.AccessToken, null!, out _));
    }


    /// <summary>
    /// Maps a row's kind to the <see cref="TokenType"/> the resolution takes.
    /// </summary>
    /// <param name="kind">The row value.</param>
    /// <returns>The token kind.</returns>
    private static TokenType TokenTypeOf(string kind) => kind switch
    {
        AccessTokenKind => TokenType.AccessToken,
        IdTokenKind => TokenType.IdToken,
        RefreshTokenKind => TokenType.RefreshToken,
        IdJagKind => TokenType.IdJag,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown token kind.")
    };


    /// <summary>
    /// Maps a row's kind to the <see cref="WellKnownTokenTypes"/> name a registration's
    /// <see cref="ClientRecord.TokenLifetimes"/> is keyed by.
    /// </summary>
    /// <param name="kind">The row value.</param>
    /// <returns>The lifetime map's name of the kind.</returns>
    private static string WireNameOf(string kind) => kind switch
    {
        AccessTokenKind => WellKnownTokenTypes.AccessToken,
        IdTokenKind => WellKnownTokenTypes.IdToken,
        RefreshTokenKind => WellKnownTokenTypes.RefreshToken,
        IdJagKind => WellKnownTokenTypes.IdJag,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown token kind.")
    };


    /// <summary>
    /// Sets the request's policy value of <paramref name="kind"/> on <paramref name="context"/> through the
    /// policy setter an application's resolver calls. The ID-JAG has no policy value, so its row sets nothing.
    /// </summary>
    /// <param name="context">The exchange context the policy value is set on.</param>
    /// <param name="kind">The row value.</param>
    /// <param name="lifetime">The policy value.</param>
    private static void SetPolicyValue(ExchangeContext context, string kind, TimeSpan lifetime)
    {
        Action set = kind switch
        {
            AccessTokenKind => () => context.SetAccessTokenLifetime(lifetime),
            IdTokenKind => () => context.SetIdTokenLifetime(lifetime),
            RefreshTokenKind => () => context.SetRefreshTokenLifetime(lifetime),
            _ => static () => { }
        };

        set();
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "expires_in
    /// RECOMMENDED. The lifetime in seconds of the access token." A lifetime that is not positive states no lifetime a
    /// token can be issued with: <see cref="TokenLifetimes.TryResolve"/> answers <see langword="false"/> with
    /// <see cref="TimeSpan.Zero"/> for a zero or negative value set as the request's policy value.
    /// </summary>
    /// <param name="seconds">The value, in seconds.</param>
    [TestMethod]
    [DataRow(0)]
    [DataRow(-60)]
    public void TryResolveAnswersFalseForANonPositiveLifetime(int seconds)
    {
        ExchangeContext context = new();
        context.SetAccessTokenLifetime(TimeSpan.FromSeconds(seconds));

        bool isResolved = TokenLifetimes.TryResolve(
            ContributorTestFixtures.BuildRegistration(), TokenType.AccessToken, context, out TimeSpan lifetime);

        Assert.IsFalse(isResolved);
        Assert.AreEqual(TimeSpan.Zero, lifetime);
    }


    /// <summary>
    /// The library's rule for the application's own argument: a registration's token lifetime override
    /// (<see cref="ClientRecord.TokenLifetimes"/>) is a lifetime the token is issued with, so every value it holds is at
    /// least one and at most <see cref="int.MaxValue"/> whole seconds, the library's own bound: the library writes
    /// <c>iat</c>, <c>exp</c> and a 32-bit <c>expires_in</c> in whole seconds. The <c>init</c> accessor refuses zero,
    /// 500 milliseconds, minus one minute and <see cref="int.MaxValue"/> plus one seconds with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    /// <param name="ticks">The override, in ticks.</param>
    [TestMethod]
    [DataRow(0L, DisplayName = "zero")]
    [DataRow(5_000_000L, DisplayName = "500 milliseconds")]
    [DataRow(-600_000_000L, DisplayName = "minus one minute")]
    [DataRow(21_474_836_480_000_000L, DisplayName = "int.MaxValue plus one seconds")]
    public void ARegistrationLifetimeOutsideTheWholeSecondBoundIsRefused(long ticks)
    {
        ClientRecord registration = ContributorTestFixtures.BuildRegistration();

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => registration with
        {
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty.Add(WellKnownTokenTypes.AccessToken, TimeSpan.FromTicks(ticks))
        });
    }


    /// <summary>
    /// The library's rule for the application's own argument: a registration's token lifetime override
    /// (<see cref="ClientRecord.TokenLifetimes"/>) accepts the two ends of the library's own whole-second bound, one
    /// second and <see cref="int.MaxValue"/> seconds, and holds each as it was set.
    /// </summary>
    /// <param name="ticks">The override, in ticks.</param>
    [TestMethod]
    [DataRow(10_000_000L, DisplayName = "one second")]
    [DataRow(21_474_836_470_000_000L, DisplayName = "int.MaxValue seconds")]
    public void ARegistrationLifetimeWithinTheWholeSecondBoundIsAccepted(long ticks)
    {
        TimeSpan value = TimeSpan.FromTicks(ticks);

        ClientRecord registration = ContributorTestFixtures.BuildRegistration() with
        {
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty.Add(WellKnownTokenTypes.AccessToken, value)
        };

        Assert.AreEqual(value, registration.GetTokenLifetime(WellKnownTokenTypes.AccessToken));
    }


    /// <summary>
    /// The library's rule for the application's own argument: a registration's token lifetime override
    /// (<see cref="ClientRecord.TokenLifetimes"/>) holds the map as it was when the record was constructed. A change the
    /// application makes afterwards to the map it passed in, an access-token lifetime replaced with zero and an ID Token
    /// lifetime of zero added, does not reach the record: the record still answers seven minutes for the access token
    /// and no override for the ID Token, and <see cref="TokenLifetimes.TryResolve"/> resolves the record's seven
    /// minutes.
    /// </summary>
    [TestMethod]
    public void ARegistrationHoldsItsLifetimeMapAsConstructed()
    {
        Dictionary<string, TimeSpan> applicationMap = new(StringComparer.Ordinal)
        {
            [WellKnownTokenTypes.AccessToken] = TimeSpan.FromMinutes(7)
        };
        ClientRecord registration = ContributorTestFixtures.BuildRegistration() with { TokenLifetimes = applicationMap };

        applicationMap[WellKnownTokenTypes.AccessToken] = TimeSpan.Zero;
        applicationMap[WellKnownTokenTypes.IdToken] = TimeSpan.Zero;
        bool isResolved = TokenLifetimes.TryResolve(registration, TokenType.AccessToken, new ExchangeContext(), out TimeSpan lifetime);

        Assert.AreEqual(TimeSpan.FromMinutes(7), registration.GetTokenLifetime(WellKnownTokenTypes.AccessToken));
        Assert.IsNull(registration.GetTokenLifetime(WellKnownTokenTypes.IdToken));
        Assert.IsTrue(isResolved);
        Assert.AreEqual(TimeSpan.FromMinutes(7), lifetime);
    }


    /// <summary>
    /// The library's rule for the application's own argument: a registration's token lifetime override
    /// (<see cref="ClientRecord.TokenLifetimes"/>) is held under the comparer of the map the application passed in, the
    /// one a <see cref="Dictionary{TKey, TValue}"/>, a <see cref="FrozenDictionary{TKey, TValue}"/> or an
    /// <see cref="ImmutableDictionary{TKey, TValue}"/> exposes. A map of each kind keyed by
    /// <see cref="StringComparer.OrdinalIgnoreCase"/> that holds seven minutes under <c>Access_Token</c> answers that
    /// override for the access token, and <see cref="TokenLifetimes.TryResolve"/> resolves seven minutes.
    /// </summary>
    /// <param name="mapKind">The kind of map the application passes in.</param>
    [TestMethod]
    [DataRow("Dictionary")]
    [DataRow("FrozenDictionary")]
    [DataRow("ImmutableDictionary")]
    public void ARegistrationHoldsItsLifetimeMapUnderTheMapsOwnComparer(string mapKind)
    {
        KeyValuePair<string, TimeSpan>[] entries = [new("Access_Token", TimeSpan.FromMinutes(7))];
        IReadOnlyDictionary<string, TimeSpan> applicationMap = mapKind switch
        {
            "Dictionary" => new Dictionary<string, TimeSpan>(entries, StringComparer.OrdinalIgnoreCase),
            "FrozenDictionary" => entries.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase),
            "ImmutableDictionary" => ImmutableDictionary.CreateRange(StringComparer.OrdinalIgnoreCase, entries),
            _ => throw new ArgumentOutOfRangeException(nameof(mapKind), mapKind, "Unknown map kind.")
        };
        ClientRecord registration = ContributorTestFixtures.BuildRegistration() with { TokenLifetimes = applicationMap };

        bool isResolved = TokenLifetimes.TryResolve(registration, TokenType.AccessToken, new ExchangeContext(), out TimeSpan lifetime);

        Assert.AreEqual(TimeSpan.FromMinutes(7), registration.GetTokenLifetime(WellKnownTokenTypes.AccessToken));
        Assert.IsTrue(isResolved);
        Assert.AreEqual(TimeSpan.FromMinutes(7), lifetime);
    }


    /// <summary>
    /// The library's rule for the application's own argument: the library looks a registration's override up by the
    /// token type names of <see cref="WellKnownTokenTypes"/>, so under an ordinal map a key that differs from the name by
    /// case names no token type: a map keyed by <see cref="StringComparer.Ordinal"/> that holds seven minutes under
    /// <c>Access_Token</c> answers no access-token override, and <see cref="TokenLifetimes.TryResolve"/> resolves
    /// <see cref="TimingPolicy.Default"/>'s access-token lifetime.
    /// </summary>
    [TestMethod]
    public void AnOrdinalLifetimeMapHoldsNoOverrideUnderAKeyThatDiffersByCase()
    {
        Dictionary<string, TimeSpan> applicationMap = new(StringComparer.Ordinal)
        {
            ["Access_Token"] = TimeSpan.FromMinutes(7)
        };
        ClientRecord registration = ContributorTestFixtures.BuildRegistration() with { TokenLifetimes = applicationMap };

        bool isResolved = TokenLifetimes.TryResolve(registration, TokenType.AccessToken, new ExchangeContext(), out TimeSpan lifetime);

        Assert.IsNull(registration.GetTokenLifetime(WellKnownTokenTypes.AccessToken));
        Assert.IsTrue(isResolved);
        Assert.AreEqual(TimingPolicy.Default.AccessTokenLifetime, lifetime);
    }


    /// <summary>
    /// The library's rule for the application's own argument: a registration's token lifetime override
    /// (<see cref="ClientRecord.TokenLifetimes"/>) holds one lifetime per token type under the comparer of the map the
    /// application passed in, so a map that holds two keys equal under that comparer, <c>access_token</c> and
    /// <c>Access_Token</c> under a case-insensitive comparison, names two lifetimes for one token type: the
    /// <c>init</c> accessor refuses it with <see cref="ArgumentException"/> naming <c>TokenLifetimes</c>.
    /// </summary>
    [TestMethod]
    public void ALifetimeMapHoldingTwoKeysEqualUnderItsComparerIsRefused()
    {
        CaseComparisonSwitch comparer = new();
        Dictionary<string, TimeSpan> applicationMap = new(comparer)
        {
            [WellKnownTokenTypes.AccessToken] = TimeSpan.FromMinutes(7),
            ["Access_Token"] = TimeSpan.FromMinutes(9)
        };
        comparer.IsCaseIgnored = true;
        ClientRecord registration = ContributorTestFixtures.BuildRegistration();

        ArgumentException refusal = Assert.ThrowsExactly<ArgumentException>(
            () => registration with { TokenLifetimes = applicationMap });

        Assert.Contains(nameof(ClientRecord.TokenLifetimes), refusal.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A string comparer that compares ordinally until <see cref="IsCaseIgnored"/> is set, and ignores case after it:
    /// it lets a map hold two keys that differ by case and then expose a comparer under which they are equal.
    /// </summary>
    private sealed class CaseComparisonSwitch: IEqualityComparer<string>
    {
        /// <summary>Whether the comparer ignores case.</summary>
        public bool IsCaseIgnored { get; set; }

        /// <summary>The comparison in effect: ordinal, or ordinal ignoring case once <see cref="IsCaseIgnored"/> is set.</summary>
        private StringComparer Current => IsCaseIgnored ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

        /// <inheritdoc/>
        public bool Equals(string? x, string? y) => Current.Equals(x, y);

        /// <inheritdoc/>
        public int GetHashCode(string obj) => Current.GetHashCode(obj);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "expires_in
    /// RECOMMENDED. The lifetime in seconds of the access token." The library's own bound: the library writes
    /// <c>expires_in</c> as a 32-bit number, so a lifetime whose whole seconds equal <see cref="int.MaxValue"/>
    /// resolves.
    /// </summary>
    [TestMethod]
    public void TryResolveResolvesALifetimeOfIntMaxValueSeconds()
    {
        TimeSpan value = TimeSpan.FromSeconds(int.MaxValue);
        ClientRecord registration = ContributorTestFixtures.BuildRegistration() with
        {
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty.Add(WellKnownTokenTypes.AccessToken, value)
        };

        bool isResolved = TokenLifetimes.TryResolve(registration, TokenType.AccessToken, new ExchangeContext(), out TimeSpan lifetime);

        Assert.IsTrue(isResolved);
        Assert.AreEqual(value, lifetime);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "expires_in
    /// RECOMMENDED. The lifetime in seconds of the access token." The library's own bound: the library writes
    /// <c>expires_in</c> as a 32-bit number, so a lifetime of <see cref="int.MaxValue"/> plus one seconds, set as the
    /// request's policy value, is one it does not issue: <see cref="TokenLifetimes.TryResolve"/> answers
    /// <see langword="false"/> with <see cref="TimeSpan.Zero"/>.
    /// </summary>
    [TestMethod]
    public void TryResolveAnswersFalseForALifetimeBeyondIntMaxValueSeconds()
    {
        ExchangeContext context = new();
        context.SetAccessTokenLifetime(TimeSpan.FromSeconds((long)int.MaxValue + 1));

        bool isResolved = TokenLifetimes.TryResolve(
            ContributorTestFixtures.BuildRegistration(), TokenType.AccessToken, context, out TimeSpan lifetime);

        Assert.IsFalse(isResolved);
        Assert.AreEqual(TimeSpan.Zero, lifetime);
    }


    /// <summary>
    /// The library's own rule for a lifetime it issues: the library writes <c>iat</c>, <c>exp</c> and a 32-bit
    /// <c>expires_in</c> in whole seconds, so every lifetime is held as its whole seconds, and a lifetime under one
    /// second would issue a token whose <c>exp</c> equals its <c>iat</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see> states the response's
    /// <c>expires_in</c> as "The lifetime in seconds of the access token." <see cref="TokenLifetimes.TryResolve"/> answers
    /// <see langword="false"/> with <see cref="TimeSpan.Zero"/> for 999 milliseconds set as the request's policy value.
    /// </summary>
    [TestMethod]
    public void TryResolveAnswersFalseForALifetimeUnderOneSecond()
    {
        ExchangeContext context = new();
        context.SetAccessTokenLifetime(TimeSpan.FromTicks(999 * TimeSpan.TicksPerMillisecond));

        bool isResolved = TokenLifetimes.TryResolve(
            ContributorTestFixtures.BuildRegistration(), TokenType.AccessToken, context, out TimeSpan lifetime);

        Assert.IsFalse(isResolved);
        Assert.AreEqual(TimeSpan.Zero, lifetime);
    }


    /// <summary>
    /// The library's own rule for a lifetime it issues: the library writes <c>iat</c>, <c>exp</c> and a 32-bit
    /// <c>expires_in</c> in whole seconds, so every lifetime is held as its whole seconds, and one second is the shortest
    /// lifetime that issues a token whose <c>exp</c> lies after its <c>iat</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see> states the response's
    /// <c>expires_in</c> as "The lifetime in seconds of the access token." <see cref="TokenLifetimes.TryResolve"/>
    /// resolves one second.
    /// </summary>
    [TestMethod]
    public void TryResolveResolvesALifetimeOfOneSecond()
    {
        ClientRecord registration = ContributorTestFixtures.BuildRegistration() with
        {
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty.Add(WellKnownTokenTypes.AccessToken, TimeSpan.FromSeconds(1))
        };

        bool isResolved = TokenLifetimes.TryResolve(registration, TokenType.AccessToken, new ExchangeContext(), out TimeSpan lifetime);

        Assert.IsTrue(isResolved);
        Assert.AreEqual(TimeSpan.FromSeconds(1), lifetime);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "expires_in
    /// RECOMMENDED. The lifetime in seconds of the access token." The response states the lifetime in whole seconds, so
    /// the token is issued with whole seconds: <see cref="TokenLifetimes.TryResolve"/> resolves 90.7 seconds as 90
    /// seconds, and <see cref="int.MaxValue"/> seconds and a half as <see cref="int.MaxValue"/> seconds, the fraction
    /// dropped.
    /// </summary>
    /// <param name="ticks">The value set, in ticks.</param>
    /// <param name="expectedSeconds">The lifetime resolved, in whole seconds.</param>
    [TestMethod]
    [DataRow(907_000_000L, 90L)]
    [DataRow(21_474_836_475_000_000L, 2_147_483_647L)]
    public void TryResolveDropsTheFractionOfASecond(long ticks, long expectedSeconds)
    {
        ClientRecord registration = ContributorTestFixtures.BuildRegistration() with
        {
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty.Add(WellKnownTokenTypes.AccessToken, TimeSpan.FromTicks(ticks))
        };

        bool isResolved = TokenLifetimes.TryResolve(registration, TokenType.AccessToken, new ExchangeContext(), out TimeSpan lifetime);

        Assert.IsTrue(isResolved);
        Assert.AreEqual(TimeSpan.FromSeconds(expectedSeconds), lifetime);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "expires_in
    /// RECOMMENDED. The lifetime in seconds of the access token." A value present under a lifetime's policy name that is
    /// not a <see cref="TimeSpan"/> (a number, a string, a null) states no lifetime, never an absent value:
    /// <see cref="TokenLifetimes.TryResolve"/> answers <see langword="false"/> with <see cref="TimeSpan.Zero"/> rather
    /// than the server's longer default.
    /// </summary>
    /// <param name="kind">The token kind the row resolves.</param>
    /// <param name="valueShape">The stored value: <c>int</c>, <c>string</c> or <c>null</c>.</param>
    [TestMethod]
    [DataRow(AccessTokenKind, "int")]
    [DataRow(AccessTokenKind, "string")]
    [DataRow(AccessTokenKind, "null")]
    [DataRow(IdTokenKind, "int")]
    [DataRow(IdTokenKind, "string")]
    [DataRow(IdTokenKind, "null")]
    [DataRow(RefreshTokenKind, "int")]
    [DataRow(RefreshTokenKind, "string")]
    [DataRow(RefreshTokenKind, "null")]
    public void TryResolveAnswersFalseForAMistypedPolicyValue(string kind, string valueShape)
    {
        string policyName = kind switch
        {
            AccessTokenKind => PolicyContextKeys.AccessTokenLifetime,
            IdTokenKind => PolicyContextKeys.IdTokenLifetime,
            RefreshTokenKind => PolicyContextKeys.RefreshTokenLifetime,
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown token kind.")
        };
        object? stored = valueShape switch
        {
            "int" => 300,
            "string" => "PT5M",
            "null" => null,
            _ => throw new ArgumentOutOfRangeException(nameof(valueShape), valueShape, "Unknown value shape.")
        };
        ExchangeContext context = new()
        {
            [policyName] = stored!
        };

        bool isResolved = TokenLifetimes.TryResolve(
            ContributorTestFixtures.BuildRegistration(), TokenTypeOf(kind), context, out TimeSpan lifetime);

        Assert.IsFalse(isResolved);
        Assert.AreEqual(TimeSpan.Zero, lifetime);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "expires_in
    /// RECOMMENDED. The lifetime in seconds of the access token." The library's rule for the source of that lifetime:
    /// with no registration override and no policy value, the lifetime is the request server's own
    /// <see cref="TimingPolicy"/> value of the kind, not <see cref="TimingPolicy.Default"/>'s.
    /// </summary>
    /// <param name="kind">The token kind the row resolves.</param>
    /// <param name="expectedSeconds">The request server's lifetime of the kind, in seconds.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow(AccessTokenKind, 420)]
    [DataRow(IdTokenKind, 480)]
    [DataRow(RefreshTokenKind, 32400)]
    [DataRow(IdJagKind, 120)]
    public async Task TryResolveReadsTheRequestServersTimingPolicyWhenNothingIsSetAsync(string kind, int expectedSeconds)
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.Timings = TimingPolicy.Default with
            {
                AccessTokenLifetime = TimeSpan.FromSeconds(420),
                IdTokenLifetime = TimeSpan.FromSeconds(480),
                RefreshTokenLifetime = TimeSpan.FromSeconds(32400),
                IdJagLifetime = TimeSpan.FromSeconds(120)
            };
        }).ConfigureAwait(false);
        ExchangeContext context = new();
        context.SetServer(app.Server);

        bool isResolved = TokenLifetimes.TryResolve(
            ContributorTestFixtures.BuildRegistration(), TokenTypeOf(kind), context, out TimeSpan lifetime);

        Assert.IsTrue(isResolved);
        Assert.AreEqual(TimeSpan.FromSeconds(expectedSeconds), lifetime);
    }
}
