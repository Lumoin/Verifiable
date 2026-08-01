using System.Diagnostics;
using Verifiable.Cryptography.Text;

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
    /// <summary>The UTF-8 source literal of <see cref="AssessorVersion"/>.</summary>
    public static ReadOnlySpan<byte> AssessorVersionUtf8 => "1.1.0"u8;

    /// <summary>
    /// Version applied to every Federation-library assessor's output. Bumped to
    /// <c>1.1.0</c> when the Entity Statement and Trust Mark rule sets gained the <c>kid</c>-header MUST checks
    /// (<see cref="WellKnownFederationClaimIds.KidPresent"/>,
    /// <see cref="WellKnownFederationClaimIds.TrustMarkKidPresent"/>) and the <c>jwks</c>-presence check was
    /// reshaped to <see cref="WellKnownFederationClaimIds.JwksPresentPerStatementShape"/>.
    /// </summary>
    public static string AssessorVersion { get; } = Utf8Constants.ToInternedString(AssessorVersionUtf8);
}
