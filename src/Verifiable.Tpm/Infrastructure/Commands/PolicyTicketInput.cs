using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyTicket command (CC = 0x00000172).
/// </summary>
/// <remarks>
/// <para>
/// Similar to TPM2_PolicySigned(), except it takes a <see cref="TicketDigest"/> instead of a signed
/// authorization. The TPM reconstructs the ticket from <see cref="Timeout"/>, <see cref="CpHashA"/>,
/// <see cref="PolicyRef"/>, and <see cref="AuthName"/> and compares it to the supplied ticket; on a match the
/// session's policyDigest is updated by <c>PolicyUpdate(commandCode, authName, policyRef)</c>, where
/// <c>commandCode</c> is <c>TPM_CC_PolicySigned</c> or <c>TPM_CC_PolicySecret</c> depending on
/// <see cref="TicketTag"/> — never <c>TPM_CC_PolicyTicket</c> itself. As long as the ticket has not expired, its
/// effect on the session's policyDigest and timeout is identical to the TPM2_PolicySigned()/TPM2_PolicySecret()
/// call that produced it, which is what makes ticket replay a valid stand-in for holding the original
/// authorization material (TPM 2.0 Library Part 1, clause 16.7.12).
/// </para>
/// <para>
/// Unlike TPM2_PolicySigned()/TPM2_PolicySecret(), this command carries no nonceTPM of its own —
/// <see cref="Timeout"/> is the already-resolved value from the prior response that minted the ticket, not a
/// fresh deadline computed against a live nonce.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 23.5, Table 148):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle being extended. Requires no authorization.</description></item>
///   <item><description>timeout (TPM2B_TIMEOUT): The value returned when the ticket was produced.</description></item>
///   <item><description>cpHashA (TPM2B_DIGEST): Digest of the command parameters this authorization is limited to; Empty Buffer if unlimited.</description></item>
///   <item><description>policyRef (TPM2B_NONCE): An opaque qualifier for the policy; Empty Buffer if none.</description></item>
///   <item><description>authName (TPM2B_NAME): The Name of the object that provided the original authorization.</description></item>
///   <item><description>ticket (TPMT_TK_AUTH): The authorization ticket returned by an earlier TPM2_PolicySigned() or TPM2_PolicySecret().</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyTicketInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    private IMemoryOwner<byte> TimeoutOwner { get; }

    private IMemoryOwner<byte> CpHashAOwner { get; }

    private IMemoryOwner<byte> PolicyRefOwner { get; }

    private IMemoryOwner<byte> AuthNameOwner { get; }

    private IMemoryOwner<byte> TicketDigestOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyTicket;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>policySession</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 23.5.2, Table 148) — the
    /// first session in an authorization area over this command is a companion, never an authorizer, so a
    /// decrypt or encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0
    /// Library Part 1, clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <summary>
    /// Gets the policy session handle being extended.
    /// </summary>
    public uint PolicySession { get; }

    /// <summary>
    /// Gets the timeout value exactly as returned when the ticket was produced (the raw big-endian
    /// TPM2B_TIMEOUT buffer, MSb-flagged per TPM 2.0 Library Part 2, clause 10.3.10).
    /// </summary>
    public ReadOnlyMemory<byte> Timeout { get; }

    /// <summary>
    /// Gets the digest of the command parameters this authorization is limited to, or empty if unlimited.
    /// </summary>
    public ReadOnlyMemory<byte> CpHashA { get; }

    /// <summary>
    /// Gets the opaque policy qualifier, or empty for none.
    /// </summary>
    public ReadOnlyMemory<byte> PolicyRef { get; }

    /// <summary>
    /// Gets the Name of the object that provided the original authorization.
    /// </summary>
    public ReadOnlyMemory<byte> AuthName { get; }

    /// <summary>
    /// Gets the ticket's structure tag (TPM_ST_AUTH_SIGNED or TPM_ST_AUTH_SECRET), which selects the commandCode
    /// the fold uses on success.
    /// </summary>
    public ushort TicketTag { get; }

    /// <summary>
    /// Gets the ticket's hierarchy, used as-is to select the proof value the TPM recomputes the ticket HMAC with.
    /// </summary>
    public uint TicketHierarchy { get; }

    /// <summary>
    /// Gets the ticket's HMAC digest.
    /// </summary>
    public ReadOnlyMemory<byte> TicketDigest { get; }

    /// <summary>
    /// Creates a TPM2_PolicyTicket input.
    /// </summary>
    /// <param name="policySession">The policy session handle being extended.</param>
    /// <param name="timeout">The timeout value exactly as returned when the ticket was produced.</param>
    /// <param name="cpHashA">The digest of the command parameters this authorization is limited to, or empty if unlimited.</param>
    /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
    /// <param name="authName">The Name of the object that provided the original authorization.</param>
    /// <param name="ticketTag">The ticket's structure tag (TPM_ST_AUTH_SIGNED or TPM_ST_AUTH_SECRET).</param>
    /// <param name="ticketHierarchy">The ticket's hierarchy.</param>
    /// <param name="ticketDigest">The ticket's HMAC digest.</param>
    /// <param name="pool">The memory pool for the parameter buffers.</param>
    /// <returns>A new <see cref="PolicyTicketInput"/>.</returns>
    public static PolicyTicketInput Create(
        uint policySession,
        ReadOnlySpan<byte> timeout,
        ReadOnlySpan<byte> cpHashA,
        ReadOnlySpan<byte> policyRef,
        ReadOnlySpan<byte> authName,
        ushort ticketTag,
        uint ticketHierarchy,
        ReadOnlySpan<byte> ticketDigest,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> timeoutOwner = pool.Rent(Math.Max(timeout.Length, 1));
        timeout.CopyTo(timeoutOwner.Memory.Span);

        IMemoryOwner<byte> cpHashAOwner = pool.Rent(Math.Max(cpHashA.Length, 1));
        cpHashA.CopyTo(cpHashAOwner.Memory.Span);

        IMemoryOwner<byte> policyRefOwner = pool.Rent(Math.Max(policyRef.Length, 1));
        policyRef.CopyTo(policyRefOwner.Memory.Span);

        IMemoryOwner<byte> authNameOwner = pool.Rent(Math.Max(authName.Length, 1));
        authName.CopyTo(authNameOwner.Memory.Span);

        IMemoryOwner<byte> ticketDigestOwner = pool.Rent(Math.Max(ticketDigest.Length, 1));
        ticketDigest.CopyTo(ticketDigestOwner.Memory.Span);

        return new PolicyTicketInput(
            policySession,
            timeoutOwner,
            timeoutOwner.Memory[..timeout.Length],
            cpHashAOwner,
            cpHashAOwner.Memory[..cpHashA.Length],
            policyRefOwner,
            policyRefOwner.Memory[..policyRef.Length],
            authNameOwner,
            authNameOwner.Memory[..authName.Length],
            ticketTag,
            ticketHierarchy,
            ticketDigestOwner,
            ticketDigestOwner.Memory[..ticketDigest.Length]);
    }

    private PolicyTicketInput(
        uint policySession,
        IMemoryOwner<byte> timeoutOwner,
        ReadOnlyMemory<byte> timeout,
        IMemoryOwner<byte> cpHashAOwner,
        ReadOnlyMemory<byte> cpHashA,
        IMemoryOwner<byte> policyRefOwner,
        ReadOnlyMemory<byte> policyRef,
        IMemoryOwner<byte> authNameOwner,
        ReadOnlyMemory<byte> authName,
        ushort ticketTag,
        uint ticketHierarchy,
        IMemoryOwner<byte> ticketDigestOwner,
        ReadOnlyMemory<byte> ticketDigest)
    {
        PolicySession = policySession;
        TimeoutOwner = timeoutOwner;
        Timeout = timeout;
        CpHashAOwner = cpHashAOwner;
        CpHashA = cpHashA;
        PolicyRefOwner = policyRefOwner;
        PolicyRef = policyRef;
        AuthNameOwner = authNameOwner;
        AuthName = authName;
        TicketTag = ticketTag;
        TicketHierarchy = ticketHierarchy;
        TicketDigestOwner = ticketDigestOwner;
        TicketDigest = ticketDigest;
    }

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint) +                                                              //policySession (handle area).
        sizeof(ushort) + Timeout.Length +                                           //timeout (TPM2B_TIMEOUT).
        sizeof(ushort) + CpHashA.Length +                                           //cpHashA (TPM2B_DIGEST).
        sizeof(ushort) + PolicyRef.Length +                                         //policyRef (TPM2B_NONCE).
        sizeof(ushort) + AuthName.Length +                                          //authName (TPM2B_NAME).
        sizeof(ushort) + sizeof(uint) + sizeof(ushort) + TicketDigest.Length;       //ticket (TPMT_TK_AUTH).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteTpm2b(Timeout.Span);
        writer.WriteTpm2b(CpHashA.Span);
        writer.WriteTpm2b(PolicyRef.Span);
        writer.WriteTpm2b(AuthName.Span);

        //ticket (TPMT_TK_AUTH): tag + hierarchy + digest (TPM2B_DIGEST).
        writer.WriteUInt16(TicketTag);
        writer.WriteUInt32(TicketHierarchy);
        writer.WriteTpm2b(TicketDigest.Span);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            TimeoutOwner.Dispose();
            CpHashAOwner.Dispose();
            PolicyRefOwner.Dispose();
            AuthNameOwner.Dispose();
            TicketDigestOwner.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"PolicyTicketInput(Session=0x{PolicySession:X8}, TicketTag=0x{TicketTag:X4}, TicketDigest={TicketDigest.Length} bytes)";
}
