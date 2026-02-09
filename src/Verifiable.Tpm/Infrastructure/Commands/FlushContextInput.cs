using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_FlushContext command.
/// </summary>
/// <remarks>
/// <para>
/// This command removes a loaded object, sequence object, or session from TPM memory.
/// It is used to clean up sessions when they are no longer needed.
/// </para>
/// <para>
/// <strong>Wire format:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>flushHandle (TPMI_DH_CONTEXT) - the handle to flush.</description></item>
/// </list>
/// <para>
/// <strong>Note:</strong> This command has no authorization and no response parameters.
/// The handle is not in the handle area but in the parameters area.
/// </para>
/// <para>
/// See TPM 2.0 Part 3, Section 28.4 - TPM2_FlushContext.
/// </para>
/// </remarks>
public readonly record struct FlushContextInput: ITpmCommandInput
{
    /// <summary>
    /// The handle to flush (session, transient object, or sequence).
    /// </summary>
    public required uint FlushHandle { get; init; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_FlushContext;

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //No handles. Parameters: flushHandle.
        return sizeof(uint);
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //FlushContext has no input handles.
        //The flushHandle is in the parameter area, not the handle area.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt32(FlushHandle);
    }

    /// <summary>
    /// Creates a FlushContext input for the specified handle.
    /// </summary>
    /// <param name="handle">The handle to flush.</param>
    /// <returns>A FlushContextInput for the handle.</returns>
    public static FlushContextInput ForHandle(uint handle) => new()
    {
        FlushHandle = handle
    };
}