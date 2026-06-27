using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_PolicyAuthValue.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_PolicyAuthValue has no response handles and no response parameters beyond the header; a successful
/// response indicates the policy session's policyDigest and isAuthValueNeeded flag were updated.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyAuthValueResponse: ITpmWireType
{
    /// <summary>
    /// Gets the singleton instance. Since this response has no data, a single instance is reused.
    /// </summary>
    public static PolicyAuthValueResponse Instance { get; } = new();

    private PolicyAuthValueResponse()
    {
    }

    /// <summary>
    /// Parses the (empty) response parameters.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <returns>The singleton response instance.</returns>
    public static PolicyAuthValueResponse Parse(ref TpmReader reader)
    {
        //No parameters to parse.
        return Instance;
    }

    private static string DebuggerDisplay => "PolicyAuthValueResponse()";
}
