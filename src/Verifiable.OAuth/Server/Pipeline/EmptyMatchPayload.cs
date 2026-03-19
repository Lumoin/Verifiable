using System.Diagnostics;

using Verifiable.OAuth.Server.Routing;
namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// The <see cref="MatchPayload"/> subtype representing a successful match
/// with no additional classification data. Use the
/// <see cref="MatchPayload.Empty"/> singleton rather than constructing
/// instances directly.
/// </summary>
/// <remarks>
/// <para>
/// Returned by matchers whose decision is fully captured in the act of
/// returning non-<see langword="null"/> — for example, the PAR-vs-direct
/// authorize disambiguation matchers in
/// <see cref="AuthCodeEndpoints"/>, which return
/// <see cref="MatchPayload.Empty"/> when the request matches and
/// <see langword="null"/> otherwise.
/// </para>
/// </remarks>
[DebuggerDisplay("EmptyMatchPayload")]
internal sealed record EmptyMatchPayload: MatchPayload;
