using System.Diagnostics;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// The <see cref="MatchPayload"/> the §3.6.4 / §3.6.5 / §3.6.6 exchange matchers carry: the
/// <c>{localExchangeId}</c> path segment they extracted while they still had the option to decline the
/// match. The handler reads it through <c>context.MatchPayload</c> rather than re-parsing the path,
/// so the parsing is the matcher's responsibility (the hostile-input-safety guidance on
/// <see cref="MatchPayload"/>).
/// </summary>
[DebuggerDisplay("VcalmExchangeIdMatchPayload ExchangeId={ExchangeId}")]
public sealed record VcalmExchangeIdMatchPayload(string ExchangeId): MatchPayload;
