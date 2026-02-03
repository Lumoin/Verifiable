namespace Verifiable.Tpm;

/// <summary>
/// Windows TPM Base Services (TBS) result codes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Purpose:</b> TBS is the Windows API layer that manages TPM access. These result
/// codes indicate errors at the TBS layer, distinct from TPM response codes (<see cref="TpmRc"/>).
/// </para>
/// <para>
/// <b>Error categories:</b>
/// </para>
/// <list type="bullet">
///   <item><description>0x00000000 - Success.</description></item>
///   <item><description>0x80280000-0x802800FF - TBS-specific errors.</description></item>
///   <item><description>0x80284000-0x802840FF - TPM command errors passed through TBS.</description></item>
/// </list>
/// <para>
/// See <see href="https://learn.microsoft.com/en-us/windows/win32/tbs/tbs-return-codes">
/// TBS Return Codes</see> for the complete list.
/// </para>
/// </remarks>
public enum TbsResult: uint
{
    /// <summary>
    /// TBS_SUCCESS: The function succeeded.
    /// </summary>
    TBS_SUCCESS = 0x00000000,

    /// <summary>
    /// TBS_E_INTERNAL_ERROR: An internal software error occurred.
    /// </summary>
    TBS_E_INTERNAL_ERROR = 0x80284001,

    /// <summary>
    /// TBS_E_BAD_PARAMETER: One or more parameter values are not valid.
    /// </summary>
    TBS_E_BAD_PARAMETER = 0x80284002,

    /// <summary>
    /// TBS_E_INVALID_OUTPUT_POINTER: A specified output pointer is not valid.
    /// </summary>
    TBS_E_INVALID_OUTPUT_POINTER = 0x80284003,

    /// <summary>
    /// TBS_E_INVALID_CONTEXT: The specified context handle does not refer to a valid context.
    /// </summary>
    TBS_E_INVALID_CONTEXT = 0x80284004,

    /// <summary>
    /// TBS_E_INSUFFICIENT_BUFFER: The output buffer is too small.
    /// </summary>
    TBS_E_INSUFFICIENT_BUFFER = 0x80284005,

    /// <summary>
    /// TBS_E_IOERROR: An error occurred while communicating with the TPM.
    /// </summary>
    TBS_E_IOERROR = 0x80284006,

    /// <summary>
    /// TBS_E_INVALID_CONTEXT_PARAM: A context parameter that is not valid was passed when attempting to create a TBS context.
    /// </summary>
    TBS_E_INVALID_CONTEXT_PARAM = 0x80284007,

    /// <summary>
    /// TBS_E_SERVICE_NOT_RUNNING: The TBS service is not running and could not be started.
    /// </summary>
    TBS_E_SERVICE_NOT_RUNNING = 0x80284008,

    /// <summary>
    /// TBS_E_TOO_MANY_TBS_CONTEXTS: A new context could not be created because there are too many open contexts.
    /// </summary>
    TBS_E_TOO_MANY_TBS_CONTEXTS = 0x80284009,

    /// <summary>
    /// TBS_E_TOO_MANY_RESOURCES: A new virtual resource could not be created because there are too many open virtual resources.
    /// </summary>
    TBS_E_TOO_MANY_RESOURCES = 0x8028400A,

    /// <summary>
    /// TBS_E_SERVICE_START_PENDING: The TBS service has been started but is not yet running.
    /// </summary>
    TBS_E_SERVICE_START_PENDING = 0x8028400B,

    /// <summary>
    /// TBS_E_PPI_NOT_SUPPORTED: The physical presence interface is not supported.
    /// </summary>
    TBS_E_PPI_NOT_SUPPORTED = 0x8028400C,

    /// <summary>
    /// TBS_E_COMMAND_CANCELED: The command was canceled.
    /// </summary>
    TBS_E_COMMAND_CANCELED = 0x8028400D,

    /// <summary>
    /// TBS_E_BUFFER_TOO_LARGE: The input or output buffer is too large.
    /// </summary>
    TBS_E_BUFFER_TOO_LARGE = 0x8028400E,

    /// <summary>
    /// TBS_E_TPM_NOT_FOUND: A compatible Trusted Platform Module (TPM) Security Device cannot be found on this computer.
    /// </summary>
    TBS_E_TPM_NOT_FOUND = 0x8028400F,

    /// <summary>
    /// TBS_E_SERVICE_DISABLED: The TBS service has been disabled.
    /// </summary>
    TBS_E_SERVICE_DISABLED = 0x80284010,

    /// <summary>
    /// TBS_E_NO_EVENT_LOG: The TBS event log is not available.
    /// </summary>
    TBS_E_NO_EVENT_LOG = 0x80284011,

    /// <summary>
    /// TBS_E_ACCESS_DENIED: The caller does not have the appropriate rights to perform the requested operation.
    /// </summary>
    TBS_E_ACCESS_DENIED = 0x80284012,

    /// <summary>
    /// TBS_E_PROVISIONING_NOT_ALLOWED: The TPM provisioning action is not allowed by the specified flags.
    /// </summary>
    TBS_E_PROVISIONING_NOT_ALLOWED = 0x80284013,

    /// <summary>
    /// TBS_E_PPI_FUNCTION_UNSUPPORTED: The Physical Presence Interface of this firmware does not support the requested method.
    /// </summary>
    TBS_E_PPI_FUNCTION_UNSUPPORTED = 0x80284014,

    /// <summary>
    /// TBS_E_OWNERAUTH_NOT_FOUND: The requested TPM OwnerAuth value was not found.
    /// </summary>
    TBS_E_OWNERAUTH_NOT_FOUND = 0x80284015,

    /// <summary>
    /// TBS_E_PROVISIONING_INCOMPLETE: The TPM provisioning did not complete.
    /// </summary>
    TBS_E_PROVISIONING_INCOMPLETE = 0x80284016
}


/// <summary>
/// Extension methods for TBS result code handling.
/// </summary>
public static class TbsResultExtensions
{
    /// <summary>
    /// Gets a human-readable description of the TBS result code.
    /// </summary>
    /// <param name="result">The TBS result code.</param>
    /// <returns>A description of the error, or the hex code if unknown.</returns>
    public static string GetDescription(this TbsResult result)
    {
        return result switch
        {
            TbsResult.TBS_SUCCESS => "The function succeeded.",
            TbsResult.TBS_E_INTERNAL_ERROR => "An internal software error occurred.",
            TbsResult.TBS_E_BAD_PARAMETER => "One or more parameter values are not valid.",
            TbsResult.TBS_E_INVALID_OUTPUT_POINTER => "A specified output pointer is not valid.",
            TbsResult.TBS_E_INVALID_CONTEXT => "The specified context handle does not refer to a valid context.",
            TbsResult.TBS_E_INSUFFICIENT_BUFFER => "The output Buffer is too small.",
            TbsResult.TBS_E_IOERROR => "An error occurred while communicating with the TPM.",
            TbsResult.TBS_E_INVALID_CONTEXT_PARAM => "A context parameter that is not valid was passed when attempting to create a TPM Base Services (TBS) context.",
            TbsResult.TBS_E_SERVICE_NOT_RUNNING => "The TPM Base Services (TBS) service is not running and could not be started.",
            TbsResult.TBS_E_TOO_MANY_TBS_CONTEXTS => "A new context could not be created because there are too many open contexts.",
            TbsResult.TBS_E_TOO_MANY_RESOURCES => "A new virtual resource could not be created because there are too many open virtual resources.",
            TbsResult.TBS_E_SERVICE_START_PENDING => "The TPM Base Services (TBS) service has been started but is not yet running.",
            TbsResult.TBS_E_PPI_NOT_SUPPORTED => "The Physical Presence Interface (PPI) is not supported.",
            TbsResult.TBS_E_COMMAND_CANCELED => "The command was canceled.",
            TbsResult.TBS_E_BUFFER_TOO_LARGE => "The input or output Buffer is too large.",
            TbsResult.TBS_E_TPM_NOT_FOUND => "A compatible Trusted Platform Module (TPM) Security Device cannot be found on this computer.",
            TbsResult.TBS_E_SERVICE_DISABLED => "The TPM Base Services (TBS) service has been disabled.",
            TbsResult.TBS_E_NO_EVENT_LOG => "The TPM Base Services (TBS) event log is not available.",
            TbsResult.TBS_E_ACCESS_DENIED => "The caller does not have the appropriate rights to perform the requested operation.",
            TbsResult.TBS_E_PROVISIONING_NOT_ALLOWED => "The TPM provisioning action is not allowed by the specified flags.",
            TbsResult.TBS_E_PPI_FUNCTION_UNSUPPORTED => "The Physical Presence Interface (PPI) of this firmware does not support the requested method.",
            TbsResult.TBS_E_OWNERAUTH_NOT_FOUND => "The requested TPM OwnerAuth value was not found.",
            TbsResult.TBS_E_PROVISIONING_INCOMPLETE => "The TPM provisioning did not complete.",
            _ => $"Unknown TPM Base Services (TBS) error: 0x{(uint)result:X8}"
        };
    }
}