using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Extension methods for <see cref="TpmCcConstants"/>.
/// </summary>
/// <remarks>
/// <para>
/// Provides command-specific metadata that cannot be derived from the command code alone.
/// The spec-defined TPMA_CC contains this information, but it must be retrieved via
/// TPM2_GetCapability(TPM_CAP_COMMANDS) at runtime. This extension provides a static
/// mapping for common commands.
/// </para>
/// <para>
/// <b>Why this exists:</b>
/// </para>
/// <para>
/// The executor uses <see cref="GetCommandAttributes"/> to determine the input handle
/// count (C_HANDLES) for a command, which is needed to correctly split the command
/// layout into: Header | Handles | AuthArea | Parameters.
/// </para>
/// <para>
/// <b>Extensibility:</b>
/// </para>
/// <para>
/// Library users can define additional command mappings using the same pattern:
/// </para>
/// <code>
/// public static partial class TpmCcConstantsExtensions
/// {
///     public static TpmaCc GetCommandAttributes(this TpmCcConstants commandCode) => commandCode switch
///     {
///         TpmCcConstants.TPM_CC_MyVendorCommand => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),
///         _ => DefaultGetCommandAttributes(commandCode)
///     };
/// }
/// </code>
/// </remarks>
public static partial class TpmCcConstantsExtensions
{
    /// <summary>
    /// Gets the TPMA_CC (command code attributes) for a command.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <returns>The command attributes.</returns>
    /// <exception cref="System.NotSupportedException">
    /// Thrown when the command code is not mapped. Add a mapping for the command.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This method returns the spec-defined TPMA_CC for common commands. The most
    /// important field is <see cref="TpmaCc.C_HANDLES"/>, which tells the executor
    /// how many handles are in the command's handle area.
    /// </para>
    /// <para>
    /// <b>Note:</b> This is a partial mapping. Commands not listed here will throw.
    /// Extend this method for additional commands.
    /// </para>
    /// </remarks>
    public static TpmaCc GetCommandAttributes(this TpmCcConstants commandCode) => commandCode switch
    {
        //Section 11.1 - TPM2_StartAuthSession.
        //Handle area: tpmKey, bind (2 handles, neither requires auth).
        //Response: sessionHandle (1 handle).
        TpmCcConstants.TPM_CC_StartAuthSession
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 16.1 - TPM2_GetRandom.
        //Handle area: none (0 handles).
        //Response: no handles.
        TpmCcConstants.TPM_CC_GetRandom
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Section 24.1 - TPM2_CreatePrimary.
        //Handle area: @primaryHandle (1 handle, requires auth).
        //Response: objectHandle (1 handle).
        TpmCcConstants.TPM_CC_CreatePrimary
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 28.4 - TPM2_FlushContext.
        //Handle area: none (0 handles).
        //Note: flushHandle is in the parameter area, not handle area.
        //Response: no handles.
        TpmCcConstants.TPM_CC_FlushContext
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Section 30.2 - TPM2_GetCapability.
        //Handle area: none (0 handles).
        //Response: no handles.
        TpmCcConstants.TPM_CC_GetCapability
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Section 22.4 - TPM2_PCR_Read.
        //Handle area: none (0 handles).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PCR_Read
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        _ => throw new System.NotSupportedException($"TPMA_CC mapping missing for '{commandCode}'.")
    };
}