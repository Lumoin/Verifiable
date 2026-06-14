using Verifiable.Core;
using Verifiable.Server.Pipeline;
namespace Verifiable.Server.Routing;

/// <summary>
/// The typed payload a <see cref="MatchRequestDelegate"/> returns when an
/// endpoint matches the inbound request, carrying any classification data
/// that downstream handlers consume.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="MatchPayload"/> is an abstract record. The library ships
/// <see cref="EmptyMatchPayload"/> for matchers that have no classification
/// data to carry into their handler — the matcher body has expressed the
/// full acceptance test by returning a non-<see langword="null"/> payload,
/// and the handler reconstructs whatever it needs from
/// <see cref="RequestFields"/> and <see cref="ExchangeContext"/>. Token-aware
/// matchers and application-specific matchers derive their own subtypes
/// carrying the data their handlers need — a classified access token, a
/// parsed JWS header, an extracted introspection hint.
/// </para>
/// <para>
/// The dispatcher places the matched payload on
/// <see cref="ExchangeContext"/> via the
/// <see cref="ExchangeContextServerExtensions.SetMatchPayload"/> extension before
/// invoking the matched endpoint's handler; the handler reads it through
/// <see cref="ExchangeContextServerExtensions.MatchPayload"/> and pattern-matches
/// to the subtype it expects:
/// </para>
/// <code>
/// if(context.MatchPayload is UserInfoMatchPayload userInfo)
/// {
///     ClassifiedToken token = userInfo.AccessToken;
///     //...handler logic...
/// }
/// </code>
/// <para>
/// <strong>Hostile-input safety.</strong>
/// A matcher that returns a <see cref="MatchPayload"/> instance has decided
/// the inbound request is shaped for its endpoint. Subtypes should carry
/// only the parsed inputs the handler needs, not raw bytes; the parsing
/// itself is the matcher's responsibility, run while it still has the option
/// to return <see langword="null"/> and let another matcher try.
/// </para>
/// </remarks>
public abstract record MatchPayload
{
    /// <summary>
    /// The shared singleton for matches that carry no classification data
    /// into the handler. Returned by matchers whose acceptance test is
    /// satisfied without producing any data the handler couldn't reconstruct
    /// itself from <see cref="RequestFields"/> and <see cref="ExchangeContext"/>.
    /// </summary>
    public static MatchPayload Empty { get; } = new EmptyMatchPayload();
}
