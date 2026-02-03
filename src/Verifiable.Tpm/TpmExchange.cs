using System;

namespace Verifiable.Tpm;

/// <summary>
/// A single TPM command/response exchange with timing information.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see> for command/response structure details.
/// </para>
/// </remarks>
/// <param name="StartTicks">Timestamp ticks when command was submitted.</param>
/// <param name="EndTicks">Timestamp ticks when response was received.</param>
/// <param name="Command">The command bytes sent to TPM.</param>
/// <param name="Response">The response bytes received from TPM.</param>
public readonly record struct TpmExchange(
    long StartTicks,
    long EndTicks,
    ReadOnlyMemory<byte> Command,
    ReadOnlyMemory<byte> Response)
{
    /// <summary>
    /// Duration of the exchange.
    /// </summary>
    public TimeSpan Duration => TimeSpan.FromTicks(EndTicks - StartTicks);
}