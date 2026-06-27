using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// The parsed envelope layout of a TPM command response.
/// </summary>
/// <remarks>
/// <para>
/// The layout captures the offsets and lengths discovered while reading the response
/// header and handle area. It holds buffer-relative positions rather than spans so the
/// parsing reader (a ref struct) is fully contained within the synchronous parse step
/// and the carrier can flow back across the executor's async boundaries.
/// </para>
/// </remarks>
/// <param name="Tag">The response tag (TPM_ST value).</param>
/// <param name="ResponseSize">The total response size as reported by the response header.</param>
/// <param name="ResponseCode">The response code from the response header.</param>
/// <param name="OutHandles">The output handles read from the response handle area.</param>
/// <param name="ParametersStart">The buffer offset where the parameter area begins.</param>
/// <param name="ParametersLength">The length of the parameter area in bytes.</param>
/// <param name="AuthStart">The buffer offset where the authorization area begins.</param>
/// <param name="AuthLength">The length of the authorization area in bytes.</param>
/// <param name="HasSessions">Whether the response carries an authorization (session) area.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
internal readonly record struct TpmResponseLayout(
    ushort Tag,
    uint ResponseSize,
    uint ResponseCode,
    uint[] OutHandles,
    int ParametersStart,
    int ParametersLength,
    int AuthStart,
    int AuthLength,
    bool HasSessions)
{
    private string DebuggerDisplay =>
        $"Layout(rc=0x{ResponseCode:X8}, params={ParametersStart}+{ParametersLength}, auth={AuthStart}+{AuthLength}, sessions={HasSessions})";
}
