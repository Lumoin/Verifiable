using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth.Server;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Server;

/// <summary>
/// Unit rows for <see cref="TimingPolicy"/>: every lifetime it holds is whole seconds between one and
/// <see cref="int.MaxValue"/>, its tolerances and its threshold refuse values that would fail every request, the values
/// the FAPI 2.0 profile derives from it are held to that profile's ceilings, and the request's policy-bag lifetime
/// getters fall back to the request server's own record. The wire rows that show the derived values on issued
/// artifacts are in <see cref="AuthCodeParPkceRealWireFlowTests"/>.
/// </summary>
[TestClass]
internal sealed class TimingPolicyTests
{
    /// <summary>
    /// 999 milliseconds, the largest value of whole milliseconds under the one-second floor.
    /// A constant because <see cref="DataRowAttribute"/> takes compile-time constants only.
    /// </summary>
    private const long UnderOneSecondTicks = 9_990_000L;

    /// <summary>
    /// One second, the smallest lifetime a record holds. A constant because <see cref="DataRowAttribute"/> takes
    /// compile-time constants only.
    /// </summary>
    private const long OneSecondTicks = 10_000_000L;

    /// <summary>
    /// <see cref="int.MaxValue"/> seconds, the largest lifetime a record holds. A constant because
    /// <see cref="DataRowAttribute"/> takes compile-time constants only.
    /// </summary>
    private const long IntMaxValueSecondsTicks = 21_474_836_470_000_000L;

    /// <summary>
    /// <see cref="int.MaxValue"/> plus one seconds, one second over the largest lifetime a record holds. A constant
    /// because <see cref="DataRowAttribute"/> takes compile-time constants only.
    /// </summary>
    private const long BeyondIntMaxValueSecondsTicks = 21_474_836_480_000_000L;


    /// <summary>
    /// The library's rule for the deployment's own argument: every lifetime <see cref="TimingPolicy"/> holds refuses a
    /// zero or negative value at its <c>init</c> accessor with <see cref="ArgumentOutOfRangeException"/>, since an
    /// artifact issued with it would be born expired.
    /// </summary>
    /// <param name="member">The <see cref="TimingPolicy"/> member the row sets.</param>
    /// <param name="seconds">The value, in seconds.</param>
    [TestMethod]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestUriLifetime), 0)]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestUriLifetime), -1)]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestObjectLifetime), 0)]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestObjectLifetime), -1)]
    [DataRow(nameof(TimingPolicy.AuthCodeParLifetime), 0)]
    [DataRow(nameof(TimingPolicy.AuthCodeParLifetime), -1)]
    [DataRow(nameof(TimingPolicy.AuthCodeRequestObjectLifetime), 0)]
    [DataRow(nameof(TimingPolicy.AuthCodeRequestObjectLifetime), -1)]
    [DataRow(nameof(TimingPolicy.AuthorizationCodeLifetime), 0)]
    [DataRow(nameof(TimingPolicy.AuthorizationCodeLifetime), -1)]
    [DataRow(nameof(TimingPolicy.AccessTokenLifetime), 0)]
    [DataRow(nameof(TimingPolicy.AccessTokenLifetime), -1)]
    [DataRow(nameof(TimingPolicy.IdTokenLifetime), 0)]
    [DataRow(nameof(TimingPolicy.IdTokenLifetime), -1)]
    [DataRow(nameof(TimingPolicy.RefreshTokenLifetime), 0)]
    [DataRow(nameof(TimingPolicy.RefreshTokenLifetime), -1)]
    [DataRow(nameof(TimingPolicy.IdJagLifetime), 0)]
    [DataRow(nameof(TimingPolicy.IdJagLifetime), -1)]
    [DataRow(nameof(TimingPolicy.FederationEntityConfigurationLifetime), 0)]
    [DataRow(nameof(TimingPolicy.FederationEntityConfigurationLifetime), -1)]
    public void ALifetimeThatIsNotPositiveIsRefused(string member, int seconds)
    {
        TimeSpan value = TimeSpan.FromSeconds(seconds);

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WithLifetime(member, value));
    }


    /// <summary>
    /// The library's rule for the deployment's own argument: the library writes <c>iat</c>, <c>exp</c> and a 32-bit
    /// <c>expires_in</c> in whole seconds, so every lifetime <see cref="TimingPolicy"/> holds refuses, at
    /// its <c>init</c> accessor with <see cref="ArgumentOutOfRangeException"/>, a value under one second (999
    /// milliseconds) and a value of more whole seconds than <see cref="int.MaxValue"/> (<see cref="int.MaxValue"/> plus
    /// one seconds).
    /// </summary>
    /// <param name="member">The <see cref="TimingPolicy"/> member the row sets.</param>
    /// <param name="ticks">The value, in ticks.</param>
    [TestMethod]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestUriLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestUriLifetime), BeyondIntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestObjectLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestObjectLifetime), BeyondIntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.AuthCodeParLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.AuthCodeParLifetime), BeyondIntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.AuthCodeRequestObjectLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.AuthCodeRequestObjectLifetime), BeyondIntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.AuthorizationCodeLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.AuthorizationCodeLifetime), BeyondIntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.AccessTokenLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.AccessTokenLifetime), BeyondIntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.IdTokenLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.IdTokenLifetime), BeyondIntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.RefreshTokenLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.RefreshTokenLifetime), BeyondIntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.IdJagLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.IdJagLifetime), BeyondIntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.FederationEntityConfigurationLifetime), UnderOneSecondTicks)]
    [DataRow(nameof(TimingPolicy.FederationEntityConfigurationLifetime), BeyondIntMaxValueSecondsTicks)]
    public void ALifetimeOutsideTheWholeSecondBoundIsRefused(string member, long ticks)
    {
        TimeSpan value = TimeSpan.FromTicks(ticks);

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WithLifetime(member, value));
    }


    /// <summary>
    /// The library's rule for the deployment's own argument: every lifetime <see cref="TimingPolicy"/> holds accepts
    /// the two ends of the whole-second bound, one second and <see cref="int.MaxValue"/> seconds, and holds the value
    /// as it was set.
    /// </summary>
    /// <param name="member">The <see cref="TimingPolicy"/> member the row sets.</param>
    /// <param name="ticks">The value, in ticks.</param>
    [TestMethod]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestUriLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestUriLifetime), IntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestObjectLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestObjectLifetime), IntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.AuthCodeParLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.AuthCodeParLifetime), IntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.AuthCodeRequestObjectLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.AuthCodeRequestObjectLifetime), IntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.AuthorizationCodeLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.AuthorizationCodeLifetime), IntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.AccessTokenLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.AccessTokenLifetime), IntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.IdTokenLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.IdTokenLifetime), IntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.RefreshTokenLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.RefreshTokenLifetime), IntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.IdJagLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.IdJagLifetime), IntMaxValueSecondsTicks)]
    [DataRow(nameof(TimingPolicy.FederationEntityConfigurationLifetime), OneSecondTicks)]
    [DataRow(nameof(TimingPolicy.FederationEntityConfigurationLifetime), IntMaxValueSecondsTicks)]
    public void ALifetimeWithinTheWholeSecondBoundIsAccepted(string member, long ticks)
    {
        TimeSpan value = TimeSpan.FromTicks(ticks);

        TimingPolicy policy = WithLifetime(member, value);

        Assert.AreEqual(value, ReadLifetime(policy, member));
    }


    /// <summary>
    /// The library's rule for the deployment's own argument: the library writes <c>iat</c>, <c>exp</c> and a 32-bit
    /// <c>expires_in</c> in whole seconds, so every lifetime <see cref="TimingPolicy"/> holds is held as its whole
    /// seconds, the lifetime
    /// <see cref="TokenLifetimes.TryResolve"/> issues with: 90.7 seconds set through the <c>init</c> accessor is held as
    /// 90 seconds, so every reader of the record issues 90 seconds.
    /// </summary>
    /// <param name="member">The <see cref="TimingPolicy"/> member the row sets.</param>
    [TestMethod]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestUriLifetime))]
    [DataRow(nameof(TimingPolicy.Oid4VpRequestObjectLifetime))]
    [DataRow(nameof(TimingPolicy.AuthCodeParLifetime))]
    [DataRow(nameof(TimingPolicy.AuthCodeRequestObjectLifetime))]
    [DataRow(nameof(TimingPolicy.AuthorizationCodeLifetime))]
    [DataRow(nameof(TimingPolicy.AccessTokenLifetime))]
    [DataRow(nameof(TimingPolicy.IdTokenLifetime))]
    [DataRow(nameof(TimingPolicy.RefreshTokenLifetime))]
    [DataRow(nameof(TimingPolicy.IdJagLifetime))]
    [DataRow(nameof(TimingPolicy.FederationEntityConfigurationLifetime))]
    public void AFractionalLifetimeIsHeldAsItsWholeSeconds(string member)
    {
        TimingPolicy policy = WithLifetime(member, TimeSpan.FromTicks(907_000_000L));

        Assert.AreEqual(TimeSpan.FromSeconds(90), ReadLifetime(policy, member));
    }


    /// <summary>
    /// The library's rule for the deployment's own argument: a negative clock skew tolerance or a negative key binding
    /// <c>iat</c> age would refuse every fresh JWT, so <see cref="TimingPolicy.ClockSkewTolerance"/> and
    /// <see cref="TimingPolicy.KbJwtIatMaxAge"/> refuse a negative value at their <c>init</c> accessors with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    /// <param name="member">The <see cref="TimingPolicy"/> member the row sets.</param>
    [TestMethod]
    [DataRow(nameof(TimingPolicy.ClockSkewTolerance))]
    [DataRow(nameof(TimingPolicy.KbJwtIatMaxAge))]
    public void ANegativeTimingToleranceIsRefused(string member)
    {
        TimeSpan value = TimeSpan.FromSeconds(-1);
        Func<TimingPolicy> build = member switch
        {
            nameof(TimingPolicy.ClockSkewTolerance) => () => TimingPolicy.Default with { ClockSkewTolerance = value },
            nameof(TimingPolicy.KbJwtIatMaxAge) => () => TimingPolicy.Default with { KbJwtIatMaxAge = value },
            _ => throw new ArgumentOutOfRangeException(nameof(member), member, "Unknown member.")
        };

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => build());
    }


    /// <summary>
    /// The library's rule for the deployment's own argument: a strict deployment may allow no clock skew at all, so a
    /// <see cref="TimingPolicy.ClockSkewTolerance"/> of zero is accepted and held as it was set.
    /// </summary>
    [TestMethod]
    public void AZeroClockSkewToleranceIsAccepted()
    {
        TimingPolicy policy = TimingPolicy.Default with { ClockSkewTolerance = TimeSpan.Zero };

        Assert.AreEqual(TimeSpan.Zero, policy.ClockSkewTolerance);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.10">OID4VCI 1.0
    /// Section 13.10</see>: "Access Tokens with lifetimes longer than 5 minutes are, in general, considered long lived."
    /// A threshold of zero or less would call every access token long lived; the library refuses it as the deployment's
    /// own argument: <see cref="TimingPolicy.CredentialAccessTokenSenderConstraintThreshold"/> throws
    /// <see cref="ArgumentOutOfRangeException"/> at its <c>init</c> accessor for a value that is not positive.
    /// </summary>
    /// <param name="seconds">The value, in seconds.</param>
    [TestMethod]
    [DataRow(0)]
    [DataRow(-1)]
    public void ANonPositiveSenderConstraintThresholdIsRefused(int seconds)
    {
        TimeSpan value = TimeSpan.FromSeconds(seconds);

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => TimingPolicy.Default with { CredentialAccessTokenSenderConstraintThreshold = value });
    }


    /// <summary>
    /// <see href="https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1">FAPI 2.0 Security
    /// Profile Section 5.3.2.1</see> item 13: "to accommodate clock offsets, shall accept JWTs with an iat or nbf
    /// timestamp between 0 and 10 seconds in the future but shall reject JWTs with an iat or nbf timestamp greater than
    /// 60 seconds in the future. See Note 3 for further details and rationale; and" The clock skew
    /// <see cref="PolicyProfiles.ApplyFapi20"/> sets on the request is the server's
    /// <see cref="TimingPolicy.ClockSkewTolerance"/> raised to 10 seconds when below and lowered to 60 seconds when
    /// above.
    /// </summary>
    /// <param name="configuredSeconds">The server's clock skew tolerance, in seconds.</param>
    /// <param name="expectedSeconds">The request's clock skew tolerance, in seconds.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow(120, 60)]
    [DataRow(5, 10)]
    [DataRow(30, 30)]
    public async Task TheFapi20ClockSkewIsHeldWithinTenToSixtySecondsAsync(int configuredSeconds, int expectedSeconds)
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        ExchangeContext context = await ContextOnServerAsync(
            app, TimingPolicy.Default with { ClockSkewTolerance = TimeSpan.FromSeconds(configuredSeconds) }).ConfigureAwait(false);

        PolicyProfiles.ApplyFapi20(context);

        Assert.AreEqual(TimeSpan.FromSeconds(expectedSeconds), context.ClockSkewTolerance);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</see>: "Implementers MAY
    /// provide for some small leeway, usually no more than a few minutes, to account for clock skew." The RFC 6749 with
    /// PKCE profile holds no FAPI 2.0 skew window: the clock skew <see cref="PolicyProfiles.ApplyRfc6749WithPkce"/> sets
    /// is the server's <see cref="TimingPolicy.ClockSkewTolerance"/> of 120 seconds.
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task TheRfc6749ClockSkewIsTheServersOwnAsync()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        ExchangeContext context = await ContextOnServerAsync(
            app, TimingPolicy.Default with { ClockSkewTolerance = TimeSpan.FromSeconds(120) }).ConfigureAwait(false);

        PolicyProfiles.ApplyRfc6749WithPkce(context);

        Assert.AreEqual(TimeSpan.FromSeconds(120), context.ClockSkewTolerance);
    }


    /// <summary>
    /// The library's rule for the policy-bag lifetime getters: a request with no policy value of a token kind reads,
    /// through the getter of that kind, the request server's own <see cref="TimingPolicy"/> value, the value
    /// <see cref="TokenLifetimes.TryResolve"/> issues the token with when neither a registration override nor a policy
    /// value is set.
    /// </summary>
    /// <param name="getter">The policy-bag getter the row reads.</param>
    /// <param name="expectedSeconds">The request server's lifetime of that kind, in seconds.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow(nameof(TimingPolicy.AccessTokenLifetime), 420)]
    [DataRow(nameof(TimingPolicy.IdTokenLifetime), 480)]
    [DataRow(nameof(TimingPolicy.RefreshTokenLifetime), 32400)]
    public async Task APolicyLifetimeGetterFallsBackToTheRequestServersTimingPolicyAsync(string getter, int expectedSeconds)
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        ExchangeContext context = await ContextOnServerAsync(app, TimingPolicy.Default with
        {
            AccessTokenLifetime = TimeSpan.FromSeconds(420),
            IdTokenLifetime = TimeSpan.FromSeconds(480),
            RefreshTokenLifetime = TimeSpan.FromSeconds(32400)
        }).ConfigureAwait(false);

        TimeSpan read = getter switch
        {
            nameof(TimingPolicy.AccessTokenLifetime) => context.AccessTokenLifetime,
            nameof(TimingPolicy.IdTokenLifetime) => context.IdTokenLifetime,
            nameof(TimingPolicy.RefreshTokenLifetime) => context.RefreshTokenLifetime,
            _ => throw new ArgumentOutOfRangeException(nameof(getter), getter, "Unknown getter.")
        };

        Assert.AreEqual(TimeSpan.FromSeconds(expectedSeconds), read);
    }


    /// <summary>
    /// The library's rule for a request no built-in profile ran on: the policy-bag getters of the authorization code
    /// lifetime, the <c>request_uri</c> lifetime, the request object lifetime ceiling and the clock skew read the
    /// request server's own <see cref="TimingPolicy"/> value (<see cref="TimingPolicy.AuthorizationCodeLifetime"/>,
    /// <see cref="TimingPolicy.AuthCodeParLifetime"/>, <see cref="TimingPolicy.AuthCodeRequestObjectLifetime"/>,
    /// <see cref="TimingPolicy.ClockSkewTolerance"/>), as the token-lifetime getters do, unclamped. The values the
    /// profiles derive come from the same record, so a request is held to the deployment's own timings whether or not a
    /// profile ran. The fallback is the library's own rule; no clause sets it.
    /// </summary>
    /// <param name="getter">The policy-bag getter the row reads.</param>
    /// <param name="expectedSeconds">The request server's value behind that getter, in seconds.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow("AuthorizationCodeLifetime", 30)]
    [DataRow("RequestUriLifetime", 45)]
    [DataRow("JarLifetimeCeiling", 50)]
    [DataRow("ClockSkewTolerance", 20)]
    public async Task APolicyGetterOfARequestNoProfileRanOnReadsTheRequestServersTimingPolicyAsync(string getter, int expectedSeconds)
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        ExchangeContext context = await ContextOnServerAsync(app, TimingPolicy.Default with
        {
            AuthorizationCodeLifetime = TimeSpan.FromSeconds(30),
            AuthCodeParLifetime = TimeSpan.FromSeconds(45),
            AuthCodeRequestObjectLifetime = TimeSpan.FromSeconds(50),
            ClockSkewTolerance = TimeSpan.FromSeconds(20)
        }).ConfigureAwait(false);

        TimeSpan read = getter switch
        {
            "AuthorizationCodeLifetime" => context.AuthorizationCodeLifetime,
            "RequestUriLifetime" => context.RequestUriLifetime,
            "JarLifetimeCeiling" => context.JarLifetimeCeiling,
            "ClockSkewTolerance" => context.ClockSkewTolerance,
            _ => throw new ArgumentOutOfRangeException(nameof(getter), getter, "Unknown getter.")
        };

        Assert.AreEqual(TimeSpan.FromSeconds(expectedSeconds), read);
    }


    /// <summary>
    /// A copy of <see cref="TimingPolicy.Default"/> with the lifetime <paramref name="member"/> names set to
    /// <paramref name="value"/> through its <c>init</c> accessor.
    /// </summary>
    /// <param name="member">The <see cref="TimingPolicy"/> lifetime member.</param>
    /// <param name="value">The value set.</param>
    /// <returns>The record with the value set.</returns>
    private static TimingPolicy WithLifetime(string member, TimeSpan value) => member switch
    {
        nameof(TimingPolicy.Oid4VpRequestUriLifetime) => TimingPolicy.Default with { Oid4VpRequestUriLifetime = value },
        nameof(TimingPolicy.Oid4VpRequestObjectLifetime) => TimingPolicy.Default with { Oid4VpRequestObjectLifetime = value },
        nameof(TimingPolicy.AuthCodeParLifetime) => TimingPolicy.Default with { AuthCodeParLifetime = value },
        nameof(TimingPolicy.AuthCodeRequestObjectLifetime) => TimingPolicy.Default with { AuthCodeRequestObjectLifetime = value },
        nameof(TimingPolicy.AuthorizationCodeLifetime) => TimingPolicy.Default with { AuthorizationCodeLifetime = value },
        nameof(TimingPolicy.AccessTokenLifetime) => TimingPolicy.Default with { AccessTokenLifetime = value },
        nameof(TimingPolicy.IdTokenLifetime) => TimingPolicy.Default with { IdTokenLifetime = value },
        nameof(TimingPolicy.RefreshTokenLifetime) => TimingPolicy.Default with { RefreshTokenLifetime = value },
        nameof(TimingPolicy.IdJagLifetime) => TimingPolicy.Default with { IdJagLifetime = value },
        nameof(TimingPolicy.FederationEntityConfigurationLifetime) => TimingPolicy.Default with { FederationEntityConfigurationLifetime = value },
        _ => throw new ArgumentOutOfRangeException(nameof(member), member, "Unknown member.")
    };


    /// <summary>
    /// Reads the lifetime <paramref name="member"/> names from <paramref name="policy"/>.
    /// </summary>
    /// <param name="policy">The record read.</param>
    /// <param name="member">The <see cref="TimingPolicy"/> lifetime member.</param>
    /// <returns>The value the record holds.</returns>
    private static TimeSpan ReadLifetime(TimingPolicy policy, string member) => member switch
    {
        nameof(TimingPolicy.Oid4VpRequestUriLifetime) => policy.Oid4VpRequestUriLifetime,
        nameof(TimingPolicy.Oid4VpRequestObjectLifetime) => policy.Oid4VpRequestObjectLifetime,
        nameof(TimingPolicy.AuthCodeParLifetime) => policy.AuthCodeParLifetime,
        nameof(TimingPolicy.AuthCodeRequestObjectLifetime) => policy.AuthCodeRequestObjectLifetime,
        nameof(TimingPolicy.AuthorizationCodeLifetime) => policy.AuthorizationCodeLifetime,
        nameof(TimingPolicy.AccessTokenLifetime) => policy.AccessTokenLifetime,
        nameof(TimingPolicy.IdTokenLifetime) => policy.IdTokenLifetime,
        nameof(TimingPolicy.RefreshTokenLifetime) => policy.RefreshTokenLifetime,
        nameof(TimingPolicy.IdJagLifetime) => policy.IdJagLifetime,
        nameof(TimingPolicy.FederationEntityConfigurationLifetime) => policy.FederationEntityConfigurationLifetime,
        _ => throw new ArgumentOutOfRangeException(nameof(member), member, "Unknown member.")
    };


    /// <summary>
    /// Sets <paramref name="timings"/> as the server's <see cref="TimingPolicy"/> and returns an exchange context whose
    /// request server is that server.
    /// </summary>
    /// <param name="app">The test host whose server serves the context.</param>
    /// <param name="timings">The server's timing record.</param>
    /// <returns>The exchange context.</returns>
    private static async Task<ExchangeContext> ContextOnServerAsync(TestHostShell app, TimingPolicy timings)
    {
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.Timings = timings;
        }).ConfigureAwait(false);
        ExchangeContext context = new();
        context.SetServer(app.Server);

        return context;
    }
}
