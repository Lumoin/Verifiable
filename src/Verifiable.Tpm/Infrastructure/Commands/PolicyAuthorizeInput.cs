using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyAuthorize command (CC = 0x0000016A).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session when its current policyDigest equals <see cref="ApprovedPolicy"/> and
/// <see cref="CheckTicketDigest"/> proves an authority signed <c>H_keySignNameAlg(approvedPolicy || policyRef)</c>
/// (the ticket TPM2_VerifySignature() returns), then REPLACES the session's policyDigest with
/// <c>H(H(0...0 || TPM_CC_PolicyAuthorize || keySign) || policyRef)</c> — a value that depends only on the
/// authority's key and the policy qualifier, never on whatever policy actually produced
/// <see cref="ApprovedPolicy"/>. This is the mechanism that lets an object's fixed authPolicy accept a policy
/// the authority can revise at will (TPM 2.0 Library Part 3, Section 23.16).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.16, Table 150):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle being extended. Requires no authorization.</description></item>
///   <item><description>approvedPolicy (TPM2B_DIGEST): The policy digest being approved; must equal the session's current policyDigest.</description></item>
///   <item><description>policyRef (TPM2B_NONCE): An opaque qualifier; Empty Buffer if none.</description></item>
///   <item><description>keySign (TPM2B_NAME): The Name of the key that signed the approval (its first two octets are the hash algorithm aHash is built with).</description></item>
///   <item><description>checkTicket (TPMT_TK_VERIFIED): The ticket TPM2_VerifySignature() returned, proving keySign signed <c>H(approvedPolicy || policyRef)</c>; may be a NULL Ticket for a trial session.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyAuthorizeInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    private IMemoryOwner<byte> ApprovedPolicyOwner { get; }

    private IMemoryOwner<byte> PolicyRefOwner { get; }

    private IMemoryOwner<byte> KeySignOwner { get; }

    private IMemoryOwner<byte> CheckTicketDigestOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyAuthorize;

    /// <summary>
    /// Gets the policy session handle being extended.
    /// </summary>
    public uint PolicySession { get; }

    /// <summary>
    /// Gets the policy digest being approved; must equal the session's current policyDigest.
    /// </summary>
    public ReadOnlyMemory<byte> ApprovedPolicy { get; }

    /// <summary>
    /// Gets the opaque policy qualifier, or empty for none.
    /// </summary>
    public ReadOnlyMemory<byte> PolicyRef { get; }

    /// <summary>
    /// Gets the Name of the key that signed the approval (<c>nameAlg || H(TPMT_PUBLIC)</c>).
    /// </summary>
    public ReadOnlyMemory<byte> KeySign { get; }

    /// <summary>
    /// Gets the checkTicket's structure tag (TPM_ST_VERIFIED).
    /// </summary>
    public ushort CheckTicketTag { get; }

    /// <summary>
    /// Gets the checkTicket's hierarchy (the signing key's own hierarchy, or TPM_RH_NULL for a NULL ticket).
    /// </summary>
    public uint CheckTicketHierarchy { get; }

    /// <summary>
    /// Gets the checkTicket's HMAC digest (empty for a NULL ticket).
    /// </summary>
    public ReadOnlyMemory<byte> CheckTicketDigest { get; }

    /// <summary>
    /// Creates a TPM2_PolicyAuthorize input.
    /// </summary>
    /// <param name="policySession">The policy session handle being extended.</param>
    /// <param name="approvedPolicy">The policy digest being approved.</param>
    /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
    /// <param name="keySign">The Name of the key that signed the approval.</param>
    /// <param name="checkTicketTag">The checkTicket's structure tag (TPM_ST_VERIFIED).</param>
    /// <param name="checkTicketHierarchy">The checkTicket's hierarchy.</param>
    /// <param name="checkTicketDigest">The checkTicket's HMAC digest, or empty for a NULL ticket.</param>
    /// <param name="pool">The memory pool for the parameter buffers.</param>
    /// <returns>A new <see cref="PolicyAuthorizeInput"/>.</returns>
    public static PolicyAuthorizeInput Create(
        uint policySession,
        ReadOnlySpan<byte> approvedPolicy,
        ReadOnlySpan<byte> policyRef,
        ReadOnlySpan<byte> keySign,
        ushort checkTicketTag,
        uint checkTicketHierarchy,
        ReadOnlySpan<byte> checkTicketDigest,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> approvedPolicyOwner = pool.Rent(Math.Max(approvedPolicy.Length, 1));
        approvedPolicy.CopyTo(approvedPolicyOwner.Memory.Span);

        IMemoryOwner<byte> policyRefOwner = pool.Rent(Math.Max(policyRef.Length, 1));
        policyRef.CopyTo(policyRefOwner.Memory.Span);

        IMemoryOwner<byte> keySignOwner = pool.Rent(Math.Max(keySign.Length, 1));
        keySign.CopyTo(keySignOwner.Memory.Span);

        IMemoryOwner<byte> checkTicketDigestOwner = pool.Rent(Math.Max(checkTicketDigest.Length, 1));
        checkTicketDigest.CopyTo(checkTicketDigestOwner.Memory.Span);

        return new PolicyAuthorizeInput(
            policySession,
            approvedPolicyOwner,
            approvedPolicyOwner.Memory[..approvedPolicy.Length],
            policyRefOwner,
            policyRefOwner.Memory[..policyRef.Length],
            keySignOwner,
            keySignOwner.Memory[..keySign.Length],
            checkTicketTag,
            checkTicketHierarchy,
            checkTicketDigestOwner,
            checkTicketDigestOwner.Memory[..checkTicketDigest.Length]);
    }

    private PolicyAuthorizeInput(
        uint policySession,
        IMemoryOwner<byte> approvedPolicyOwner,
        ReadOnlyMemory<byte> approvedPolicy,
        IMemoryOwner<byte> policyRefOwner,
        ReadOnlyMemory<byte> policyRef,
        IMemoryOwner<byte> keySignOwner,
        ReadOnlyMemory<byte> keySign,
        ushort checkTicketTag,
        uint checkTicketHierarchy,
        IMemoryOwner<byte> checkTicketDigestOwner,
        ReadOnlyMemory<byte> checkTicketDigest)
    {
        PolicySession = policySession;
        ApprovedPolicyOwner = approvedPolicyOwner;
        ApprovedPolicy = approvedPolicy;
        PolicyRefOwner = policyRefOwner;
        PolicyRef = policyRef;
        KeySignOwner = keySignOwner;
        KeySign = keySign;
        CheckTicketTag = checkTicketTag;
        CheckTicketHierarchy = checkTicketHierarchy;
        CheckTicketDigestOwner = checkTicketDigestOwner;
        CheckTicketDigest = checkTicketDigest;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +                                                                //policySession (handle area).
               sizeof(ushort) + ApprovedPolicy.Length +                                       //approvedPolicy (TPM2B_DIGEST).
               sizeof(ushort) + PolicyRef.Length +                                             //policyRef (TPM2B_NONCE).
               sizeof(ushort) + KeySign.Length +                                               //keySign (TPM2B_NAME).
               sizeof(ushort) + sizeof(uint) + sizeof(ushort) + CheckTicketDigest.Length;      //checkTicket (TPMT_TK_VERIFIED).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteTpm2b(ApprovedPolicy.Span);
        writer.WriteTpm2b(PolicyRef.Span);
        writer.WriteTpm2b(KeySign.Span);

        //checkTicket (TPMT_TK_VERIFIED): tag + hierarchy + digest (TPM2B_DIGEST).
        writer.WriteUInt16(CheckTicketTag);
        writer.WriteUInt32(CheckTicketHierarchy);
        writer.WriteTpm2b(CheckTicketDigest.Span);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            ApprovedPolicyOwner.Dispose();
            PolicyRefOwner.Dispose();
            KeySignOwner.Dispose();
            CheckTicketDigestOwner.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"PolicyAuthorizeInput(Session=0x{PolicySession:X8}, ApprovedPolicy={ApprovedPolicy.Length} bytes, KeySign={KeySign.Length} bytes)";
}
