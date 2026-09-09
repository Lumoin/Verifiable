using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_TestParms command (TPM 2.0 Library Part 3, clause 30.3). Asks whether <see cref="Parameters"/>
/// is a combination of algorithm parameters this TPM supports; the command's own action is nothing beyond the
/// unmarshal (Part 4 <c>TestParms.c</c>'s <c>TPM2_TestParms()</c>: "The parameters are tested at unmarshal process. We do nothing in
/// command action").
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> None (0 handles).
/// </para>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>parameters (TPMT_PUBLIC_PARMS) - algorithm parameters to be validated (Part 2, clause 12.2.3.10, Table 234).</description></item>
/// </list>
/// <para>
/// This command may be sent with <c>TPM_ST_NO_SESSIONS</c>, or with <c>TPM_ST_SESSIONS</c> when an audit
/// session is present (Table 240); an audit session is not admitted by this executor, so the session form
/// cannot succeed here. See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 30.3 (Table 240).
/// </para>
/// </remarks>
/// <param name="Parameters">The algorithm parameters to validate.</param>
public readonly record struct TestParmsInput(TpmtPublicParms Parameters): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_TestParms;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>TPMT_PUBLIC_PARMS</c> carries no size field of its own (Part 2, Table 234), so it is not eligible
    /// for session-based parameter encryption (TPM 2.0 Library Part 1, clause 18.1's "any first parameter can
    /// be encrypted as long as the parameter has a size field").
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => false;

    /// <inheritdoc/>
    public int GetSerializedSize() => Parameters.SerializedSize;

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //TestParms has no input handles.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        Parameters.WriteTo(ref writer);
    }
}
