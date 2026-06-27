using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_PolicyPCR.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_PolicyPCR has no response handles and no response parameters beyond the header; a successful response
/// indicates the policy session's policyDigest was extended with the PCR selection and digest.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyPcrResponse: ITpmWireType
{
    /// <summary>
    /// Gets the singleton instance. Since this response has no data, a single instance is reused.
    /// </summary>
    public static PolicyPcrResponse Instance { get; } = new();

    private PolicyPcrResponse()
    {
    }

    /// <summary>
    /// Parses the (empty) response parameters.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <returns>The singleton response instance.</returns>
    public static PolicyPcrResponse Parse(ref TpmReader reader)
    {
        //No parameters to parse.
        return Instance;
    }

    private static string DebuggerDisplay => "PolicyPcrResponse()";
}
