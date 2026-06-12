using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// An immutable snapshot of APDU command/response exchanges with source metadata.
/// </summary>
/// <remarks>
/// <para>
/// Packages captured APDU traffic with identifying information about the source card.
/// This enables:
/// </para>
/// <list type="bullet">
///   <item><description>Deterministic replay via <see cref="VirtualCard"/>.</description></item>
///   <item><description>Remote debugging by sharing recordings between devices.</description></item>
///   <item><description>Compliance auditing with timestamped exchange logs.</description></item>
///   <item><description>Forensic analysis of card provisioning and authentication flows.</description></item>
/// </list>
/// </remarks>
/// <param name="Info">Metadata about the card that produced this recording.</param>
/// <param name="Exchanges">The captured command/response pairs in chronological order.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record ApduRecording(
    CardSessionInfo Info,
    IReadOnlyList<ApduExchange> Exchanges)
{
    private string DebuggerDisplay =>
        $"ApduRecording({Info.Platform}, {Exchanges.Count} exchanges)";
}
