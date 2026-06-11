using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth;

/// <summary>
/// Well-known issuer / assessor identifiers for the OAuth track's
/// <see cref="Verifiable.Core.Assessment.ClaimIssuer{T}"/> and
/// <see cref="Verifiable.Core.Assessment.ClaimAssessor{T}"/> instances.
/// </summary>
/// <remarks>
/// Used as the <c>issuerId</c> parameter to the assessment-pattern
/// constructors. The string flows into telemetry tags, forensic-archive
/// records, and OpenTelemetry attributes — naming should stay stable
/// across versions because audit trails reference it.
/// </remarks>
[DebuggerDisplay("WellKnownAssessorIds")]
public static class WellKnownAssessorIds
{
    /// <summary>The UTF-8 source literal of <see cref="ClaimContributors"/>.</summary>
    public static ReadOnlySpan<byte> ClaimContributorsUtf8 => "oauth.claim-contributors"u8;

    /// <summary>
    /// Issuer identifier for the composed claim-contribution issuer on
    /// <see cref="Server.ServerConfiguration.ClaimIssuer"/>.
    /// </summary>
    public static readonly string ClaimContributors = Utf8Constants.ToInternedString(ClaimContributorsUtf8);
}
