using System.Collections.Generic;

namespace Verifiable.Tpm;

/// <summary>
/// An immutable snapshot of TPM command/response exchanges with source metadata.
/// </summary>
/// <remarks>
/// <para>
/// <b>Purpose:</b> TpmRecording packages captured TPM traffic with identifying
/// information about the source TPM. This enables:
/// </para>
/// <list type="bullet">
///   <item><description>Deterministic replay via <see cref="VirtualTpm.Load(TpmRecording)"/>.</description></item>
///   <item><description>Debugging by comparing recordings from different TPMs.</description></item>
///   <item><description>Compliance auditing with timestamped exchange logs.</description></item>
/// </list>
/// <para>
/// <b>Creating recordings:</b> Use <see cref="TpmRecorder.ToRecording"/> after capturing traffic:
/// </para>
/// <code>
/// using var recorder = new TpmRecorder();
/// using (tpm.Subscribe(recorder))
/// {
///     tpm.GetRandom(16);
/// }
/// TpmRecording recording = recorder.ToRecording(tpm.GetSessionInfo(TimeProvider.System));
/// </code>
/// <para>
/// <b>Replaying:</b> Load into a VirtualTpm for hardware-free testing:
/// </para>
/// <code>
/// var virtualTpm = new VirtualTpm();
/// virtualTpm.Load(recording);
/// </code>
/// </remarks>
/// <param name="Info">Metadata about the TPM that produced this recording.</param>
/// <param name="Exchanges">The captured command/response pairs in chronological order.</param>
/// <seealso cref="TpmRecorder"/>
/// <seealso cref="VirtualTpm"/>
/// <seealso cref="TpmSessionInfo"/>
public sealed record TpmRecording(
    TpmSessionInfo Info,
    IReadOnlyList<TpmExchange> Exchanges);