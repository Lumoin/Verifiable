using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The <see cref="MatchPayload"/> the §3.5.4 <c>GET /presentations/{id}</c> and §3.5.5
/// <c>DELETE /presentations/{id}</c> matcher carries: the <c>{id}</c> path segment it extracted while
/// it still had the option to decline the match. The handler reads it through
/// <c>context.MatchPayload</c> rather than re-parsing the path, so the parsing is the matcher's
/// responsibility (the hostile-input-safety guidance on <see cref="MatchPayload"/>). Distinct from
/// <see cref="VcalmCredentialIdMatchPayload"/> / <see cref="VcalmStatusListIdMatchPayload"/> so the
/// id-bearing routes never cross-bind.
/// </summary>
[DebuggerDisplay("VcalmPresentationIdMatchPayload PresentationId={PresentationId}")]
public sealed record VcalmPresentationIdMatchPayload(string PresentationId): MatchPayload;
