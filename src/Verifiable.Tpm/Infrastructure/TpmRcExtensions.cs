using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Extension methods for TPM response code analysis and formatting.
/// </summary>
/// <remarks>
/// <para>
/// TPM response codes use a structured bit layout defined in TPM 2.0 Library Specification
/// Part 2, section 6.6. This class provides methods to extract and interpret the various
/// fields within a response code.
/// </para>
/// <para>
/// <b>Response code formats:</b>
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       Format-zero (bit 7 clear): General errors and warnings not tied to specific parameters.
///     </description>
///   </item>
///   <item>
///     <description>
///       Format-one (bit 7 set): Errors associated with a specific parameter, handle, or session.
///     </description>
///   </item>
/// </list>
/// <para>
/// <b>Format-zero bit layout (Table 16):</b>
/// </para>
/// <list type="bullet">
///   <item><description>Bits 6:0 (E): Error number.</description></item>
///   <item><description>Bit 7 (F): Format selector, clear for format-zero.</description></item>
///   <item><description>Bit 8 (V): Version, set for TPM 2.0 codes.</description></item>
///   <item><description>Bit 9: Reserved, shall be zero.</description></item>
///   <item><description>Bit 10 (T): TCG/vendor indicator.</description></item>
///   <item><description>Bit 11 (S): Severity, set for warnings.</description></item>
/// </list>
/// <para>
/// <b>Format-one bit layout (Table 18):</b>
/// </para>
/// <list type="bullet">
///   <item><description>Bits 5:0 (E): Error number.</description></item>
///   <item><description>Bit 6 (P): Set if error is parameter-related.</description></item>
///   <item><description>Bit 7 (F): Format selector, set for format-one.</description></item>
///   <item><description>Bits 11:8 (N): Parameter, handle, or session number (1-based).</description></item>
/// </list>
/// </remarks>
public static class TpmRcExtensions
{
    //Bit masks for response code fields (TPM 2.0 Library Specification Part 2, Tables 16 and 18).
    private const uint FormatBitMask = 0x080;
    private const uint VersionBitMask = 0x100;
    private const uint VendorBitMask = 0x400;
    private const uint SeverityBitMask = 0x800;
    private const uint ParameterBitMask = 0x040;
    private const uint NumberFieldMask = 0xF00;
    private const int NumberFieldShift = 8;

    //Error number masks differ by format (TPM 2.0 Library Specification Part 2, Tables 16 and 18).
    [SuppressMessage("Performance", "CA1823:Avoid unused private fields", Justification = "Spec-defined mask for format-zero error extraction (TPM 2.0 Part 2, Table 16).")]
    private const uint FormatZeroErrorMask = 0x07F;
    private const uint FormatOneErrorMask = 0x03F;

    //Session indicator in N field (bit 11 set means session, clear means handle).
    private const uint SessionIndicatorMask = 0x800;

    /// <summary>
    /// Determines whether the response code uses format-one encoding.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// <see langword="true"/> if the response code is format-one (parameter/handle/session error);
    /// <see langword="false"/> if format-zero (general error or warning).
    /// </returns>
    public static bool IsFormatOne(this TpmRcConstants rc)
    {
        return ((uint)rc & FormatBitMask) != 0;
    }

    /// <summary>
    /// Determines whether the response code is a warning rather than an error.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// <see langword="true"/> if the response code is a warning;
    /// <see langword="false"/> if it is an error.
    /// </returns>
    public static bool IsWarning(this TpmRcConstants rc)
    {
        uint value = (uint)rc;

        //Warnings are format-zero with S bit set (RC_WARN range).
        return (value & FormatBitMask) == 0 && (value & SeverityBitMask) != 0;
    }

    /// <summary>
    /// Determines whether the response code is a TPM 2.0 specification code.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// <see langword="true"/> if the response code is defined by TPM 2.0;
    /// <see langword="false"/> if it is a legacy TPM 1.2 code.
    /// </returns>
    public static bool IsVersion2(this TpmRcConstants rc)
    {
        uint value = (uint)rc;

        //Format-one codes are always TPM 2.0.
        if((value & FormatBitMask) != 0)
        {
            return true;
        }

        //Format-zero codes check the version bit.
        return (value & VersionBitMask) != 0;
    }

    /// <summary>
    /// Determines whether the response code is vendor-specific.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// <see langword="true"/> if the response code is defined by the TPM vendor;
    /// <see langword="false"/> if it is defined by the TCG specification.
    /// </returns>
    public static bool IsVendorSpecific(this TpmRcConstants rc)
    {
        uint value = (uint)rc;

        //Only meaningful for format-zero codes.
        if((value & FormatBitMask) != 0)
        {
            return false;
        }

        return (value & VendorBitMask) != 0;
    }

    /// <summary>
    /// Determines whether the error is associated with a parameter.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// <see langword="true"/> if the error is parameter-related;
    /// <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsParameterError(this TpmRcConstants rc)
    {
        uint value = (uint)rc;

        //Must be format-one with P bit set.
        return (value & FormatBitMask) != 0 && (value & ParameterBitMask) != 0;
    }

    /// <summary>
    /// Determines whether the error is associated with a handle.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// <see langword="true"/> if the error is handle-related;
    /// <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsHandleError(this TpmRcConstants rc)
    {
        uint value = (uint)rc;

        //Must be format-one with P bit clear and N field indicating handle (bit 11 clear).
        if((value & FormatBitMask) == 0 || (value & ParameterBitMask) != 0)
        {
            return false;
        }

        //N field in bits 11:8. Handles use N = 1-7 (bit 11 clear).
        uint nField = (value & NumberFieldMask) >> NumberFieldShift;
        return nField >= 1 && nField <= 7;
    }

    /// <summary>
    /// Determines whether the error is associated with a session.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// <see langword="true"/> if the error is session-related;
    /// <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsSessionError(this TpmRcConstants rc)
    {
        uint value = (uint)rc;

        //Must be format-one with P bit clear and N field indicating session (bit 11 set).
        if((value & FormatBitMask) == 0 || (value & ParameterBitMask) != 0)
        {
            return false;
        }

        //Sessions use N = 8-15 (bit 11 set in N field, which is bit 11 of the response code).
        return (value & SessionIndicatorMask) != 0;
    }

    /// <summary>
    /// Gets the parameter number associated with a format-one error.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// The 1-based parameter number (1-15), or 0 if unspecified or not a parameter error.
    /// </returns>
    public static int GetParameterNumber(this TpmRcConstants rc)
    {
        if(!rc.IsParameterError())
        {
            return 0;
        }

        return (int)((uint)rc & NumberFieldMask) >> NumberFieldShift;
    }

    /// <summary>
    /// Gets the handle number associated with a format-one error.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// The 1-based handle number (1-7), or 0 if unspecified or not a handle error.
    /// </returns>
    public static int GetHandleNumber(this TpmRcConstants rc)
    {
        if(!rc.IsHandleError())
        {
            return 0;
        }

        return (int)((uint)rc & NumberFieldMask) >> NumberFieldShift;
    }

    /// <summary>
    /// Gets the session number associated with a format-one error.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// The 1-based session number (1-7), or 0 if unspecified or not a session error.
    /// </returns>
    public static int GetSessionNumber(this TpmRcConstants rc)
    {
        if(!rc.IsSessionError())
        {
            return 0;
        }

        //Session number is the lower 3 bits of the N field (N - 8).
        uint nField = ((uint)rc & NumberFieldMask) >> NumberFieldShift;
        return (int)(nField & 0x7);
    }

    /// <summary>
    /// Gets the base error code without parameter, handle, or session modifiers.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>
    /// The base error code that can be compared against <see cref="TpmRcConstants"/> values.
    /// </returns>
    public static TpmRcConstants GetBaseError(this TpmRcConstants rc)
    {
        uint value = (uint)rc;

        if((value & FormatBitMask) != 0)
        {
            //Format-one: extract format bit and error number, clear N field and P bit.
            return (TpmRcConstants)(value & (FormatBitMask | FormatOneErrorMask));
        }

        //Format-zero: the value is already the base error.
        return rc;
    }

    /// <summary>
    /// Gets a human-readable description of the TPM response code.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>A description of the error including any parameter, handle, or session context.</returns>
    public static string GetDescription(this TpmRcConstants rc)
    {
        if(rc == TpmRcConstants.TPM_RC_SUCCESS)
        {
            return "Success.";
        }

        TpmRcConstants baseError = rc.GetBaseError();
        string baseDescription = GetBaseErrorDescription(baseError);

        //Add context for format-one errors.
        if(rc.IsParameterError())
        {
            int paramNum = rc.GetParameterNumber();
            return paramNum > 0
                ? $"{baseDescription} (parameter {paramNum})"
                : baseDescription;
        }

        if(rc.IsHandleError())
        {
            int handleNum = rc.GetHandleNumber();
            return handleNum > 0
                ? $"{baseDescription} (handle {handleNum})"
                : baseDescription;
        }

        if(rc.IsSessionError())
        {
            int sessionNum = rc.GetSessionNumber();
            return sessionNum > 0
                ? $"{baseDescription} (session {sessionNum})"
                : baseDescription;
        }

        return baseDescription;
    }

    /// <summary>
    /// Gets the description for a base error code.
    /// </summary>
    private static string GetBaseErrorDescription(TpmRcConstants rc)
    {
        return rc switch
        {
            //Format-zero errors (RC_VER1 range).
            TpmRcConstants.TPM_RC_INITIALIZE => "TPM not initialized by TPM2_Startup or already initialized.",
            TpmRcConstants.TPM_RC_FAILURE => "Commands not accepted due to TPM failure.",
            TpmRcConstants.TPM_RC_SEQUENCE => "Improper use of a sequence handle.",
            TpmRcConstants.TPM_RC_PRIVATE => "Reserved error code (not currently used).",
            TpmRcConstants.TPM_RC_HMAC => "Reserved error code (not currently used).",
            TpmRcConstants.TPM_RC_DISABLED => "The command is disabled.",
            TpmRcConstants.TPM_RC_EXCLUSIVE => "Command failed because audit sequence required exclusivity.",
            TpmRcConstants.TPM_RC_AUTH_TYPE => "Authorization handle is not correct for command.",
            TpmRcConstants.TPM_RC_AUTH_MISSING => "Command requires an authorization session for handle and it is not present.",
            TpmRcConstants.TPM_RC_POLICY => "Policy failure in math operation or an invalid authPolicy value.",
            TpmRcConstants.TPM_RC_PCR => "PCR check failed.",
            TpmRcConstants.TPM_RC_PCR_CHANGED => "PCR have changed since checked.",
            TpmRcConstants.TPM_RC_UPGRADE => "TPM is in field upgrade mode.",
            TpmRcConstants.TPM_RC_TOO_MANY_CONTEXTS => "Context ID counter is at maximum.",
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE => "authValue or authPolicy is not available for selected entity.",
            TpmRcConstants.TPM_RC_REBOOT => "A _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation.",
            TpmRcConstants.TPM_RC_UNBALANCED => "The protection algorithms (hash and symmetric) are not reasonably balanced.",
            TpmRcConstants.TPM_RC_COMMAND_SIZE => "Command size value is inconsistent with contents of the command Buffer.",
            TpmRcConstants.TPM_RC_COMMAND_CODE => "Command code not supported.",
            TpmRcConstants.TPM_RC_AUTHSIZE => "The value of authorizationSize is out of range.",
            TpmRcConstants.TPM_RC_AUTH_CONTEXT => "Use of an authorization session with a context command that cannot have one.",
            TpmRcConstants.TPM_RC_NV_RANGE => "NV offset plus size is out of range.",
            TpmRcConstants.TPM_RC_NV_SIZE => "Requested allocation size is larger than allowed.",
            TpmRcConstants.TPM_RC_NV_LOCKED => "NV access locked.",
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION => "NV access authorization fails in command actions.",
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED => "An NV Index is used before being initialized or state could not be restored.",
            TpmRcConstants.TPM_RC_NV_SPACE => "Insufficient space for NV allocation.",
            TpmRcConstants.TPM_RC_NV_DEFINED => "NV Index or persistent object already defined.",
            TpmRcConstants.TPM_RC_BAD_CONTEXT => "Context in TPM2_ContextLoad is not valid.",
            TpmRcConstants.TPM_RC_CPHASH => "cpHash value already set or not correct for use.",
            TpmRcConstants.TPM_RC_PARENT => "Handle for parent is not a valid parent.",
            TpmRcConstants.TPM_RC_NEEDS_TEST => "Some function needs testing.",
            TpmRcConstants.TPM_RC_NO_RESULT => "Internal function cannot process a request due to an unspecified problem.",
            TpmRcConstants.TPM_RC_SENSITIVE => "The sensitive area did not unmarshal correctly after decryption.",
            TpmRcConstants.TPM_RC_READ_ONLY => "Command failed because the TPM is in Read-Only mode of operation.",

            //Format-one errors (RC_FMT1 range).
            TpmRcConstants.TPM_RC_ASYMMETRIC => "Asymmetric algorithm not supported or not correct.",
            TpmRcConstants.TPM_RC_ATTRIBUTES => "Inconsistent attributes.",
            TpmRcConstants.TPM_RC_HASH => "Hash algorithm not supported or not appropriate.",
            TpmRcConstants.TPM_RC_VALUE => "Value is out of range or is not correct for the context.",
            TpmRcConstants.TPM_RC_HIERARCHY => "Hierarchy is not enabled or is not correct for the use.",
            TpmRcConstants.TPM_RC_KEY_SIZE => "Key size is not supported.",
            TpmRcConstants.TPM_RC_MGF => "Mask generation function not supported.",
            TpmRcConstants.TPM_RC_MODE => "Mode of operation not supported.",
            TpmRcConstants.TPM_RC_TYPE => "The type of the value is not appropriate for the use.",
            TpmRcConstants.TPM_RC_HANDLE => "The handle is not correct for the use.",
            TpmRcConstants.TPM_RC_KDF => "Unsupported key derivation function or function not appropriate for use.",
            TpmRcConstants.TPM_RC_RANGE => "Value was out of allowed range.",
            TpmRcConstants.TPM_RC_AUTH_FAIL => "The authorization HMAC check failed and DA counter incremented.",
            TpmRcConstants.TPM_RC_NONCE => "Invalid nonce size or nonce value mismatch.",
            TpmRcConstants.TPM_RC_PP => "Authorization requires assertion of Physical Presence.",
            TpmRcConstants.TPM_RC_SCHEME => "Unsupported or incompatible scheme.",
            TpmRcConstants.TPM_RC_SIZE => "Structure is the wrong size.",
            TpmRcConstants.TPM_RC_SYMMETRIC => "Unsupported symmetric algorithm or key size, or not appropriate for instance.",
            TpmRcConstants.TPM_RC_TAG => "Incorrect structure tag.",
            TpmRcConstants.TPM_RC_SELECTOR => "Union selector is incorrect.",
            TpmRcConstants.TPM_RC_INSUFFICIENT => "Not enough octets in the input Buffer to unmarshal a value.",
            TpmRcConstants.TPM_RC_SIGNATURE => "The signature is not valid.",
            TpmRcConstants.TPM_RC_KEY => "Key fields are not compatible with the selected use.",
            TpmRcConstants.TPM_RC_POLICY_FAIL => "A policy check failed.",
            TpmRcConstants.TPM_RC_INTEGRITY => "Integrity check failed.",
            TpmRcConstants.TPM_RC_TICKET => "Invalid ticket.",
            TpmRcConstants.TPM_RC_RESERVED_BITS => "Reserved bits not set to zero as required.",
            TpmRcConstants.TPM_RC_BAD_AUTH => "Authorization failure without DA implications.",
            TpmRcConstants.TPM_RC_EXPIRED => "The policy has expired.",
            TpmRcConstants.TPM_RC_POLICY_CC => "The commandCode in the policy is not the commandCode of the command.",
            TpmRcConstants.TPM_RC_BINDING => "Public and sensitive portions of an object are not cryptographically bound.",
            TpmRcConstants.TPM_RC_CURVE => "Curve not supported.",
            TpmRcConstants.TPM_RC_ECC_POINT => "Point is not on the required curve.",
            TpmRcConstants.TPM_RC_FW_LIMITED => "Hierarchy is firmware-limited but Firmware Secret is unavailable.",
            TpmRcConstants.TPM_RC_SVN_LIMITED => "Hierarchy is SVN-limited but Firmware SVN Secret is unavailable.",
            TpmRcConstants.TPM_RC_CHANNEL => "Command requires secure channel protection.",
            TpmRcConstants.TPM_RC_CHANNEL_KEY => "Secure channel was not established with required requester or TPM key.",

            //Warnings (RC_WARN range).
            TpmRcConstants.TPM_RC_CONTEXT_GAP => "Gap for context ID is too large.",
            TpmRcConstants.TPM_RC_OBJECT_MEMORY => "Out of memory for object contexts.",
            TpmRcConstants.TPM_RC_SESSION_MEMORY => "Out of memory for session contexts.",
            TpmRcConstants.TPM_RC_MEMORY => "Out of shared object/session memory or need space for internal operations.",
            TpmRcConstants.TPM_RC_SESSION_HANDLES => "Out of session handles; a session must be flushed before a new one can be created.",
            TpmRcConstants.TPM_RC_OBJECT_HANDLES => "Out of object handles; a reboot is required.",
            TpmRcConstants.TPM_RC_LOCALITY => "Bad locality.",
            TpmRcConstants.TPM_RC_YIELDED => "TPM has suspended operation; forward progress was made and command may be retried.",
            TpmRcConstants.TPM_RC_CANCELED => "The command was canceled.",
            TpmRcConstants.TPM_RC_TESTING => "TPM is performing self-tests.",
            TpmRcConstants.TPM_RC_REFERENCE_H0 => "The 1st handle references a transient object or session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_H1 => "The 2nd handle references a transient object or session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_H2 => "The 3rd handle references a transient object or session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_H3 => "The 4th handle references a transient object or session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_H4 => "The 5th handle references a transient object or session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_H5 => "The 6th handle references a transient object or session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_H6 => "The 7th handle references a transient object or session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_S0 => "The 1st authorization session handle references a session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_S1 => "The 2nd authorization session handle references a session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_S2 => "The 3rd authorization session handle references a session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_S3 => "The 4th authorization session handle references a session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_S4 => "The 5th session handle references a session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_S5 => "The 6th session handle references a session that is not loaded.",
            TpmRcConstants.TPM_RC_REFERENCE_S6 => "The 7th authorization session handle references a session that is not loaded.",
            TpmRcConstants.TPM_RC_NV_RATE => "TPM is rate-limiting accesses to prevent NV wearout.",
            TpmRcConstants.TPM_RC_LOCKOUT => "Authorizations for DA-protected objects not allowed; TPM is in lockout mode.",
            TpmRcConstants.TPM_RC_RETRY => "The TPM was not able to start the command.",
            TpmRcConstants.TPM_RC_NV_UNAVAILABLE => "Command may require writing NV and NV is not currently accessible.",

            //Special cases.
            TpmRcConstants.TPM_RC_BAD_TAG => "Bad tag.",

            _ => $"Unknown TPM response code: '0x{(uint)rc:X8}'."
        };
    }
}