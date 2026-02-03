using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Interface for TPM command inputs.
/// </summary>
/// <remarks>
/// <para>
/// Command inputs represent the handle area and parameter area of a TPM command.
/// They do NOT include the header or authorization area - those are handled by the executor.
/// </para>
/// <para>
/// <b>TPM command structure:</b>
/// </para>
/// <code>
/// | Header (10 bytes) | HandleArea | AuthArea (optional) | ParameterArea |
/// </code>
/// <para>
/// The executor builds this structure by:
/// </para>
/// <list type="number">
///   <item><description>Writing the header.</description></item>
///   <item><description>Calling <see cref="WriteHandles"/> to write the handle area.</description></item>
///   <item><description>Writing the authorization area (if sessions are present).</description></item>
///   <item><description>Calling <see cref="WriteParameters"/> to write the parameter area.</description></item>
/// </list>
/// <para>
/// <b>Handle count validation:</b>
/// </para>
/// <para>
/// The number of handles written by <see cref="WriteHandles"/> must match the C_HANDLES
/// value from <see cref="TpmaCc"/> for the command. The executor validates this by checking
/// that exactly <c>C_HANDLES * sizeof(uint)</c> bytes were written.
/// </para>
/// </remarks>
public interface ITpmCommandInput
{
    /// <summary>
    /// Gets the TPM command code (TPM_CC).
    /// </summary>
    TpmCcConstants CommandCode { get; }

    /// <summary>
    /// Gets the total serialized size of the handle area plus the parameter area, in bytes.
    /// </summary>
    /// <returns>Size in bytes of handles + parameters (excluding header and auth area).</returns>
    int GetSerializedSize();

    /// <summary>
    /// Writes the handle area (TPM_HANDLE values) in command order.
    /// </summary>
    /// <param name="writer">The writer positioned at the start of the handle area.</param>
    /// <remarks>
    /// <para>
    /// The number of handles is fixed by the command definition in Part 3 of the TPM specification.
    /// Commands with no input handles should have an empty implementation.
    /// </para>
    /// <para>
    /// Each handle is a 4-byte big-endian value written via <see cref="TpmWriter.WriteUInt32"/>.
    /// </para>
    /// </remarks>
    void WriteHandles(ref TpmWriter writer);

    /// <summary>
    /// Writes the parameter area (all non-handle fields) in command order.
    /// </summary>
    /// <param name="writer">The writer positioned at the start of the parameter area.</param>
    /// <remarks>
    /// <para>
    /// The parameter area contains all command-specific data that is not a handle.
    /// The format is defined by each command in Part 3 of the TPM specification.
    /// </para>
    /// </remarks>
    void WriteParameters(ref TpmWriter writer);
}