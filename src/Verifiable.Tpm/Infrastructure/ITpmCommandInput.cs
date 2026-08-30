using Verifiable.Tpm.Spec.Constants;

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
    /// Gets whether the first parameter of this command is a sized buffer eligible for session-based
    /// parameter encryption (the command's <c>decrypt</c> attribute).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per TPM 2.0 Library Part 1, Section 18.1 only the first parameter of the parameter area can be
    /// encrypted, and only when it has an explicit size field. A command whose first parameter is a fixed-size
    /// scalar (for example a <c>UINT16</c>) is not encryptable and leaves this <see langword="false"/>.
    /// </para>
    /// <para>
    /// The executor refuses to send a command over a session whose <c>decrypt</c> attribute is set unless this
    /// returns <see langword="true"/>, mirroring the TPM's own <c>TPM_RC_ATTRIBUTES</c>/<c>TPM_RC_SYMMETRIC</c>
    /// rejection rather than emitting a request the TPM would reject.
    /// </para>
    /// </remarks>
    bool FirstCommandParameterIsEncryptable => false;

    /// <summary>
    /// Whether the command handle at <paramref name="handleIndex"/> (in handle order) names a sequence object,
    /// whose cpHash Name term is the Empty Buffer ("If an authorization or audit for a sequence object requires
    /// computation of a cpHash and an rpHash, the Name associated with sequenceHandle will be the Empty Buffer",
    /// TPM 2.0 Library Part 1, clause 29.4.6; Part 3, clause 17.7.1). A transient handle's value cannot say
    /// whether it names a key or a sequence, so the input — which knows its own command table — declares it,
    /// and <see cref="TpmCommandExecutor"/> derives the term rather than requiring a caller-supplied Name.
    /// </summary>
    /// <param name="handleIndex">The zero-based position in the command's handle area.</param>
    /// <returns><see langword="true"/> when the handle at that position is a sequence handle.</returns>
    bool HandleIsSequence(int handleIndex) => false;

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
