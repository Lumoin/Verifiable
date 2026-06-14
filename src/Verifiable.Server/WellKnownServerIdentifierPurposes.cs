using System.Diagnostics;

namespace Verifiable.Server;

/// <summary>
/// The host-generic <see cref="IdentifierPurpose"/> instances the dispatch host itself
/// generates identifiers for. URN scheme:
/// <c>urn:verifiable:identifier-purpose:server:&lt;name&gt;</c>.
/// </summary>
/// <remarks>
/// A protocol family ships its own well-known purpose class for the identifier sites its
/// endpoints generate; this class carries only the purposes the host's own dispatch loop
/// generates.
/// </remarks>
[DebuggerDisplay("WellKnownServerIdentifierPurposes")]
public static class WellKnownServerIdentifierPurposes
{
    /// <summary>
    /// Flow identifier — the per-request correlation key the dispatcher stamps onto a new
    /// flow when a flow-creating endpoint matches. v7 GUIDs by default so the encoded
    /// creation timestamp gives database indexes and forensic archives time-locality for
    /// free.
    /// </summary>
    public static IdentifierPurpose FlowId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:server:flow_id");
}
