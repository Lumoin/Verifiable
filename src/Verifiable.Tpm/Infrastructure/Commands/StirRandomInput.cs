using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_StirRandom command (TPM 2.0 Library Part 3, clause 16.2). Adds <see cref="InData"/> to
/// the RNG's reseed state.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> None (0 handles).
/// </para>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>inData (TPM2B_SENSITIVE_DATA) - additional input, bounded at 128 octets (Part 2, clause 11.1.13, Table 169).</description></item>
/// </list>
/// <para>
/// This command may be sent with <c>TPM_ST_NO_SESSIONS</c>, or with <c>TPM_ST_SESSIONS</c> when a decrypt
/// session protects <c>inData</c>; an audit session is not admitted by this executor. See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 16.2 (Table 77).
/// </para>
/// </remarks>
/// <param name="InData">
/// The additional input to fold into the RNG's reseed state. BORROWS the caller's carrier: this type neither
/// owns nor disposes it — the caller retains ownership across the call, as <see cref="GetRandomInput"/>'s bare
/// scalar parameter needs no ownership discipline at all and this command's sized one inherits the same
/// non-owning contract.
/// </param>
public readonly record struct StirRandomInput(Tpm2bSensitiveData InData): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_StirRandom;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>inData</c> is a sized buffer and is the command's first (and only) parameter, so it is eligible for
    /// session-based parameter encryption (TPM 2.0 Library Part 1, clause 18.1). A session without the
    /// <c>decrypt</c> attribute is unaffected; this only enables a caller that attaches a decrypt session to
    /// actually request encryption.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(ushort) + InData.Length;

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //StirRandom has no input handles.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        InData.WriteTo(ref writer);
    }
}
