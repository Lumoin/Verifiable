using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The <see cref="MatchPayload"/> the W3C VCALM 1.0 §3.7.4 interaction-protocols-response and §3.7.5
/// inviteRequest matchers carry: the trailing id path segment they extracted (the
/// <c>{localInteractionId}</c> for §3.7.4, the <c>{localInviteId}</c> for §3.7.5) while they still had
/// the option to decline the match. The handler reads it through <c>context.MatchPayload</c> rather
/// than re-parsing the path, so the parsing is the matcher's responsibility (the hostile-input-safety
/// guidance on <see cref="MatchPayload"/>).
/// </summary>
[DebuggerDisplay("VcalmInteractionIdMatchPayload Id={Id}")]
public sealed record VcalmInteractionIdMatchPayload(string Id): MatchPayload;
