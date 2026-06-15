using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The <see cref="MatchPayload"/> the §C.2 <c>GET /status-lists/{id}</c> matcher carries: the
/// <c>{id}</c> path segment it extracted while it still had the option to decline the match. The
/// handler reads it through <c>context.MatchPayload</c> rather than re-parsing the path, so the
/// parsing is the matcher's responsibility (the hostile-input-safety guidance on
/// <see cref="MatchPayload"/>). Distinct from <see cref="VcalmCredentialIdMatchPayload"/> so the two
/// id-bearing routes never cross-bind.
/// </summary>
[DebuggerDisplay("VcalmStatusListIdMatchPayload StatusListId={StatusListId}")]
public sealed record VcalmStatusListIdMatchPayload(string StatusListId): MatchPayload;
