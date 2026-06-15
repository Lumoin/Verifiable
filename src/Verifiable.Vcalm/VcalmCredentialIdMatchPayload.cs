using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The <see cref="MatchPayload"/> the §3.2.2 <c>GET /credentials/{id}</c> and §3.2.3
/// <c>DELETE /credentials/{id}</c> matcher carries: the <c>{id}</c> path segment it extracted while
/// it still had the option to decline the match. The handler reads it through
/// <c>context.MatchPayload</c> rather than re-parsing the path, so the parsing is the matcher's
/// responsibility (the hostile-input-safety guidance on <see cref="MatchPayload"/>).
/// </summary>
[DebuggerDisplay("VcalmCredentialIdMatchPayload CredentialId={CredentialId}")]
public sealed record VcalmCredentialIdMatchPayload(string CredentialId): MatchPayload;
