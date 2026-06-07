using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Version constants populated onto the <c>AssessorVersion</c> field of
/// <see cref="Verifiable.Core.Assessment.AssessmentResult"/> instances
/// returned by Federation library validators and gate hooks.
/// </summary>
/// <remarks>
/// Distinct from the spec version of OpenID Federation 1.0 itself: this
/// is the Federation assessor implementation version, tracked separately
/// so downstream audit consumers can correlate assessment outputs with
/// the specific library build that produced them. Bumped when a Federation
/// validator's behaviour changes (added/removed checks, claim shape
/// changes, etc.) rather than when the underlying spec rev changes.
/// </remarks>
[DebuggerDisplay("WellKnownFederationVersions")]
public static class WellKnownFederationVersions
{
    /// <summary>
    /// Version applied to every Federation-library assessor's output.
    /// </summary>
    public static readonly string AssessorVersion = "1.0.0";
}
