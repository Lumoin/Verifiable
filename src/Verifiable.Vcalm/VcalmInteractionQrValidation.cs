using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The outcome of validating a W3C VCALM 1.0 §3.7.1 interaction URL against the §3.7.2 QR-code length
/// bounds. The library validates the URL the QR would carry and ENFORCES the bounds; it never renders
/// the QR image itself (§3.7.2 ISO-18004 encoding is the application's presentation concern, layered
/// over a URL this validation marks <see cref="IsValid"/>).
/// </summary>
/// <remarks>
/// §3.7.2: the interaction URL "SHOULD NOT exceed 400 alphanumeric characters, and MUST NOT exceed
/// 4,296 alphanumeric characters." The MUST-NOT is the hard bound — a URL over it cannot be a single QR
/// code, so <see cref="IsValid"/> is <see langword="false"/>. The SHOULD-NOT is the advisory bound — a
/// URL over it is still valid but carries <see cref="HasAdvisory"/> so a deployment can shorten it for
/// broader QR interoperability.
/// </remarks>
[DebuggerDisplay("VcalmInteractionQrValidation IsValid={IsValid} HasAdvisory={HasAdvisory} UrlLength={UrlLength}")]
public sealed record VcalmInteractionQrValidation
{
    /// <summary>The character length of the validated §3.7.1 interaction URL.</summary>
    public required int UrlLength { get; init; }

    /// <summary>
    /// Whether the URL satisfies the §3.7.2 MUST-NOT hard bound (<see cref="VcalmInteractionUrlComposer.QrMaximumLength"/>).
    /// <see langword="false"/> when the URL is too long to be a single QR code.
    /// </summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// Whether the URL exceeds the §3.7.2 SHOULD-NOT advisory bound
    /// (<see cref="VcalmInteractionUrlComposer.QrAdvisoryLengthLimit"/>) while still satisfying the
    /// MUST-NOT hard bound — a non-fatal advisory the deployment MAY act on by shortening the URL.
    /// </summary>
    public required bool HasAdvisory { get; init; }
}
