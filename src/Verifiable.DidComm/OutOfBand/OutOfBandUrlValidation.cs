using System.Diagnostics;

namespace Verifiable.DidComm.OutOfBand;

/// <summary>
/// The outcome of validating a DIDComm Out-of-Band invitation URL against the QR-code length bounds.
/// The library validates the URL the QR would carry and ENFORCES the bounds; it never renders the QR
/// image itself (ISO 18004 encoding is the application's presentation concern, layered over a URL this
/// validation marks <see cref="IsValid"/>).
/// </summary>
/// <remarks>
/// DIDComm v2.1 §Short URL Message Retrieval motivates a length bound: "It seems inevitable that the
/// length of some DIDComm messages will be too long to produce a useable QR code." The hard bound is
/// the maximum a single Version-40 QR code can carry in alphanumeric mode (ISO 18004); a URL over it
/// cannot be a single QR code, so <see cref="IsValid"/> is <see langword="false"/> and the sender
/// SHOULD switch to the shortened <c>_oobid</c> form. The advisory bound is a softer threshold past
/// which a deployment MAY prefer the shortened form for broader scanner interoperability.
/// </remarks>
[DebuggerDisplay("OutOfBandUrlValidation IsValid={IsValid} HasAdvisory={HasAdvisory} UrlLength={UrlLength}")]
public sealed record OutOfBandUrlValidation
{
    /// <summary>The character length of the validated Out-of-Band invitation URL.</summary>
    public required int UrlLength { get; init; }

    /// <summary>
    /// Whether the URL satisfies the hard QR-code length bound
    /// (<see cref="OutOfBandInvitationExtensions.QrMaximumLength"/>). <see langword="false"/> when the
    /// URL is too long to be a single QR code and the sender should use the shortened form.
    /// </summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// Whether the URL exceeds the advisory length bound
    /// (<see cref="OutOfBandInvitationExtensions.QrAdvisoryLength"/>) while still satisfying the hard
    /// bound — a non-fatal advisory the deployment MAY act on by switching to the shortened form.
    /// </summary>
    public required bool HasAdvisory { get; init; }
}
