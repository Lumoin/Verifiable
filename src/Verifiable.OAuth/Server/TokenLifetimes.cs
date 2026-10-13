using Verifiable.Core;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The one resolution of an issued token's lifetime. Every site that issues an access token, an ID Token, a refresh
/// token or an Identity Assertion JWT Authorization Grant, and every site that states or checks such a token's
/// lifetime, reads it here.
/// </summary>
/// <remarks>
/// <para>
/// The lifetime of a kind is read in this order:
/// </para>
/// <list type="number">
/// <item><description>
/// The registration's own override, the <see cref="ClientRecord.TokenLifetimes"/> entry under the kind's
/// <see cref="WellKnownTokenTypes"/> name (<see cref="ClientRecord.GetTokenLifetime"/>).
/// </description></item>
/// <item><description>
/// Else the request's policy value of that kind on the <see cref="ExchangeContext"/>, which the built-in
/// <see cref="PolicyProfiles"/> set from the server's <see cref="TimingPolicy"/> and an application's
/// <see cref="ResolvePolicyDelegate"/> may set (<see cref="PolicyExchangeContextExtensions"/>). The ID-JAG has no
/// policy value of its own.
/// </description></item>
/// <item><description>
/// Else the server's <see cref="TimingPolicy"/>, the one the context's request server carries, or
/// <see cref="TimingPolicy.Default"/> when no server is on the context.
/// </description></item>
/// </list>
/// <para>
/// The four kinds with a lifetime are <see cref="TokenType.AccessToken"/>
/// (<see cref="TimingPolicy.AccessTokenLifetime"/>), <see cref="TokenType.IdToken"/>
/// (<see cref="TimingPolicy.IdTokenLifetime"/>), <see cref="TokenType.RefreshToken"/>
/// (<see cref="TimingPolicy.RefreshTokenLifetime"/>) and <see cref="TokenType.IdJag"/>
/// (<see cref="TimingPolicy.IdJagLifetime"/>). Any other <see cref="TokenType"/> is a kind the library issues no
/// token of and is answered <see langword="false"/>.
/// </para>
/// <para>
/// The first of the three that holds a value for the kind is the lifetime the token is issued with, within the
/// profile's ceilings: the registration's override for its client, the policy value for the request, the
/// <see cref="TimingPolicy"/> for the server. A registration's lifetime map is the application's own record, so a
/// value in it that is not issuable is refused here, as every other tier's is. The value is the token's <c>exp</c> less its
/// <c>iat</c> (<see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</see>), the
/// stored expiry of a refresh token, and the <c>expires_in</c> a response states
/// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>,
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 Section 2.2.1</see>).
/// </para>
/// </remarks>
public static class TokenLifetimes
{
    /// <summary>
    /// Resolves the lifetime of a token of <paramref name="tokenType"/> issued under <paramref name="registration"/>
    /// for the request <paramref name="context"/> carries, in the order the class remarks state.
    /// </summary>
    /// <param name="registration">The client registration the token is issued under.</param>
    /// <param name="tokenType">The kind of the token.</param>
    /// <param name="context">The request's exchange context, carrying its policy values and its request server.</param>
    /// <param name="lifetime">
    /// The resolved lifetime in whole seconds, the fraction of a second dropped, when the answer is
    /// <see langword="true"/>; <see cref="TimeSpan.Zero"/> otherwise.
    /// </param>
    /// <returns>
    /// <see langword="true"/> for an access token, an ID Token, a refresh token or an ID-JAG whose resolved lifetime is
    /// issuable: its whole seconds are at least one and at most <see cref="int.MaxValue"/>, the library's own rule. A
    /// response states the lifetime in seconds (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749
    /// Section 5.1</see>: "The lifetime in seconds of the access token."); the library writes <c>iat</c>, <c>exp</c>
    /// and a 32-bit <c>expires_in</c> in whole seconds, so a lifetime under one second would issue a token born expired
    /// and one above <see cref="int.MaxValue"/> seconds is more than it writes.
    /// <see langword="false"/> for any other kind, which has no lifetime the library issues a token with, for a
    /// resolved lifetime outside those bounds, and for a value present under the kind's policy name that is not a
    /// <see cref="TimeSpan"/>. A <see langword="false"/> answer means the resolved lifetime is not issuable, whoever
    /// supplied it: the endpoints answer it 500 <c>server_error</c> with nothing issued, and the producers throw
    /// <see cref="InvalidOperationException"/> to a direct caller.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="registration"/> or <paramref name="context"/> is null.</exception>
    public static bool TryResolve(ClientRecord registration, TokenType tokenType, ExchangeContext context, out TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        (string? overrideName, string? policyKey) = tokenType switch
        {
            _ when tokenType == TokenType.AccessToken => (WellKnownTokenTypes.AccessToken, PolicyContextKeys.AccessTokenLifetime),
            _ when tokenType == TokenType.IdToken => (WellKnownTokenTypes.IdToken, PolicyContextKeys.IdTokenLifetime),
            _ when tokenType == TokenType.RefreshToken => (WellKnownTokenTypes.RefreshToken, PolicyContextKeys.RefreshTokenLifetime),
            _ when tokenType == TokenType.IdJag => (WellKnownTokenTypes.IdJag, null),
            _ => (null, null)
        };

        if(overrideName is null)
        {
            lifetime = TimeSpan.Zero;

            return false;
        }

        if(registration.GetTokenLifetime(overrideName) is TimeSpan registered)
        {
            return IsIssuable(registered, out lifetime);
        }

        //Presence and type are two checks: a value present under the kind's policy name that is not a
        //TimeSpan states no lifetime, and is never an absent value the server's default stands in for.
        if(policyKey is not null && context.TryGetValue(policyKey, out object? policyValue))
        {
            if(policyValue is TimeSpan requested)
            {
                return IsIssuable(requested, out lifetime);
            }

            lifetime = TimeSpan.Zero;

            return false;
        }

        TimingPolicy timings = context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default;
        TimeSpan configured = tokenType switch
        {
            _ when tokenType == TokenType.AccessToken => timings.AccessTokenLifetime,
            _ when tokenType == TokenType.IdToken => timings.IdTokenLifetime,
            _ when tokenType == TokenType.RefreshToken => timings.RefreshTokenLifetime,
            _ => timings.IdJagLifetime
        };

        return IsIssuable(configured, out lifetime);
    }


    /// <summary>
    /// The smallest lifetime an artifact is issued with: one whole second. A lifetime under it states
    /// <c>expires_in</c> 0 and issues an artifact born expired.
    /// </summary>
    private static long MinimumLifetimeSeconds { get; } = 1;


    /// <summary>
    /// The largest lifetime an artifact is issued with: <see cref="int.MaxValue"/> whole seconds, the library's own
    /// bound, the most the library writes in a response's 32-bit <c>expires_in</c>.
    /// </summary>
    private static long MaximumLifetimeSeconds { get; } = int.MaxValue;


    /// <summary>
    /// The one rule of an issuable lifetime, read by <see cref="TryResolve"/>, by every <see cref="TimingPolicy"/>
    /// lifetime and by the authorization code and pushed <c>request_uri</c> sites of the authorization server: the
    /// whole seconds of <paramref name="candidate"/> are at least <see cref="MinimumLifetimeSeconds"/> and at most
    /// <see cref="MaximumLifetimeSeconds"/>, and the lifetime issued is those whole seconds, the fraction of a second
    /// dropped, the library's own rule. A response states lifetimes in seconds
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "The lifetime in
    /// seconds of the access token."; <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 Section
    /// 2.2</see>: "the lifetime of the request URI in seconds as a positive integer"), and the library writes
    /// <c>iat</c>, <c>exp</c> and <c>expires_in</c> in whole seconds, so the <c>expires_in</c> a response states equals
    /// the artifact's own lifetime.
    /// </summary>
    /// <param name="candidate">The value to read.</param>
    /// <param name="lifetime">
    /// The whole seconds of <paramref name="candidate"/> when it is issuable; <see cref="TimeSpan.Zero"/> otherwise.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="candidate"/> is issuable.</returns>
    internal static bool IsIssuable(TimeSpan candidate, out TimeSpan lifetime)
    {
        long wholeSeconds = candidate.Ticks / TimeSpan.TicksPerSecond;
        bool isIssuable = wholeSeconds >= MinimumLifetimeSeconds && wholeSeconds <= MaximumLifetimeSeconds;
        lifetime = isIssuable ? TimeSpan.FromTicks(wholeSeconds * TimeSpan.TicksPerSecond) : TimeSpan.Zero;

        return isIssuable;
    }


    /// <summary>
    /// The one rule of <see cref="IsIssuable"/> for a lifetime that is a caller's own argument, read by the lifetimes
    /// the library's client issues with: a request object's and a client assertion's. The library writes an
    /// artifact's <c>iat</c> and <c>exp</c> as whole-second NumericDates, so a lifetime under one second would make
    /// <c>exp</c> equal <c>iat</c>; the refusal throws, and an issuable value is answered as its whole seconds.
    /// </summary>
    /// <param name="value">The lifetime the caller supplied.</param>
    /// <param name="parameterName">The name of the caller's argument, carried by the refusal.</param>
    /// <returns>The whole seconds of <paramref name="value"/> when it is issuable.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The whole seconds of <paramref name="value"/> are under one or above <see cref="int.MaxValue"/>.
    /// </exception>
    internal static TimeSpan RequireIssuable(TimeSpan value, string parameterName)
    {
        if(!IsIssuable(value, out TimeSpan lifetime))
        {
            throw new ArgumentOutOfRangeException(
                parameterName, value, "A lifetime is at least one and at most int.MaxValue whole seconds.");
        }

        return lifetime;
    }
}
