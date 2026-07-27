using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_PolicyAuthorize.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_PolicyAuthorize has no response handles and no response parameters beyond the header (TPM 2.0 Library
/// Part 3, Section 23.16, Table 151); a successful response indicates the session's policyDigest was replaced
/// with the authority-controlled value <c>H(H(0...0 || TPM_CC_PolicyAuthorize || keySign) || policyRef)</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyAuthorizeResponse: ITpmWireType
{
    /// <summary>
    /// Gets the singleton instance. Since this response has no data, a single instance is reused.
    /// </summary>
    public static PolicyAuthorizeResponse Instance { get; } = new();

    private PolicyAuthorizeResponse()
    {
    }

    /// <summary>
    /// Parses the (empty) response parameters.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <returns>The singleton response instance.</returns>
    public static PolicyAuthorizeResponse Parse(ref TpmReader reader)
    {
        //No parameters to parse.
        return Instance;
    }

    private static string DebuggerDisplay => "PolicyAuthorizeResponse()";
}
