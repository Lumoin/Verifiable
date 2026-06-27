using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyPCR command (CC = 0x0000017F).
/// </summary>
/// <remarks>
/// <para>
/// Binds a policy to the values of a set of PCRs. The command updates the session's policyDigest as
/// <c>policyDigestnew = H_policyAlg(policyDigestold || TPM_CC_PolicyPCR || pcrs || pcrDigest)</c> where
/// <c>pcrs</c> is the marshaled <c>TPML_PCR_SELECTION</c> and <c>pcrDigest</c> is the digest of the selected PCR
/// values. Pass an empty <c>pcrDigest</c> to bind to the current PCR state (the TPM computes the digest); a
/// non-empty value is checked against the current state on a real session and used verbatim on a trial session.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.7):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>pcrDigest (TPM2B_DIGEST): The expected digest of the selected PCR values, or empty.</description></item>
///   <item><description>pcrs (TPML_PCR_SELECTION): The PCRs the policy is bound to.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyPcrInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    private IMemoryOwner<byte>? PcrDigestOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyPCR;

    /// <summary>
    /// Gets the policy session handle the assertion is applied to.
    /// </summary>
    public uint PolicySession { get; }

    /// <summary>
    /// Gets the expected PCR digest, or empty to bind to the current PCR state.
    /// </summary>
    public ReadOnlyMemory<byte> PcrDigest { get; }

    /// <summary>
    /// Gets the PCR selection the policy is bound to.
    /// </summary>
    public TpmlPcrSelection Pcrs { get; }

    private PolicyPcrInput(uint policySession, IMemoryOwner<byte>? pcrDigestOwner, ReadOnlyMemory<byte> pcrDigest, TpmlPcrSelection pcrs)
    {
        PolicySession = policySession;
        PcrDigestOwner = pcrDigestOwner;
        PcrDigest = pcrDigest;
        Pcrs = pcrs;
    }

    /// <summary>
    /// Creates a TPM2_PolicyPCR input. Takes ownership of <paramref name="pcrs"/>.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <param name="pcrDigest">The expected PCR digest, or empty to bind to the current PCR state.</param>
    /// <param name="pcrs">The PCR selection (ownership transfers to the returned input).</param>
    /// <param name="pool">The memory pool for the digest copy.</param>
    /// <returns>A new <see cref="PolicyPcrInput"/>.</returns>
    public static PolicyPcrInput Create(uint policySession, ReadOnlySpan<byte> pcrDigest, TpmlPcrSelection pcrs, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pcrs);
        ArgumentNullException.ThrowIfNull(pool);

        if(pcrDigest.IsEmpty)
        {
            return new PolicyPcrInput(policySession, null, ReadOnlyMemory<byte>.Empty, pcrs);
        }

        IMemoryOwner<byte> owner = pool.Rent(pcrDigest.Length);
        pcrDigest.CopyTo(owner.Memory.Span);

        return new PolicyPcrInput(policySession, owner, owner.Memory[..pcrDigest.Length], pcrs);
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +                       //policySession (handle area)
               sizeof(ushort) + PcrDigest.Length +  //pcrDigest (TPM2B_DIGEST)
               Pcrs.GetSerializedSize();            //pcrs (TPML_PCR_SELECTION)
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(PcrDigest.Span);
        Pcrs.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            PcrDigestOwner?.Dispose();
            Pcrs.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"PolicyPcrInput(Session=0x{PolicySession:X8}, PcrDigest={PcrDigest.Length} bytes, {Pcrs.Count} selection(s))";
}
