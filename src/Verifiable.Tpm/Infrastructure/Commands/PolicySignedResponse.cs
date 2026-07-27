using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_PolicySigned command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 23.3):
/// </para>
/// <list type="bullet">
///   <item><description>timeout (TPM2B_TIMEOUT): the expiration relative to the session, or empty when no ticket is produced.</description></item>
///   <item><description>policyTicket (TPMT_TK_AUTH): an authorization ticket, or a NULL ticket when no ticket is produced (the deferred-mint form this wave ships, TPM 2.0 Library Part 3, Section 23.2.5).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicySignedResponse: IDisposable, ITpmWireType
{
    private bool disposed;
    private IMemoryOwner<byte> TimeoutOwner { get; }
    private int TimeoutLength { get; }
    private IMemoryOwner<byte> TicketDigestOwner { get; }
    private int TicketDigestLength { get; }

    /// <summary>
    /// Gets the timeout value (empty in this wave's deferred-ticket form).
    /// </summary>
    public ReadOnlySpan<byte> Timeout => TimeoutOwner.Memory.Span[..TimeoutLength];

    /// <summary>
    /// Gets the authorization ticket (a NULL ticket in this wave's deferred-ticket form).
    /// </summary>
    public TpmtTkAuth PolicyTicket { get; }

    private PolicySignedResponse(
        IMemoryOwner<byte> timeoutOwner, int timeoutLength, IMemoryOwner<byte> ticketDigestOwner, int ticketDigestLength, TpmtTkAuth policyTicket)
    {
        this.TimeoutOwner = timeoutOwner;
        this.TimeoutLength = timeoutLength;
        this.TicketDigestOwner = ticketDigestOwner;
        this.TicketDigestLength = ticketDigestLength;
        PolicyTicket = policyTicket;
    }

    /// <summary>
    /// Parses a TPM2_PolicySigned response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The rented buffers are owned by the returned PolicySignedResponse and disposed by the caller.")]
    public static PolicySignedResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //timeout (TPM2B_TIMEOUT).
        ushort timeoutSize = reader.ReadUInt16();
        IMemoryOwner<byte> timeoutOwner = pool.Rent(Math.Max((int)timeoutSize, 1));
        if(timeoutSize > 0)
        {
            reader.ReadBytes(timeoutSize).CopyTo(timeoutOwner.Memory.Span[..timeoutSize]);
        }

        //policyTicket (TPMT_TK_AUTH): tag (UINT16) + hierarchy (UINT32) + digest (TPM2B_DIGEST).
        ushort tag = reader.ReadUInt16();
        uint hierarchy = reader.ReadUInt32();
        ushort digestSize = reader.ReadUInt16();
        IMemoryOwner<byte> ticketDigestOwner = pool.Rent(Math.Max((int)digestSize, 1));
        if(digestSize > 0)
        {
            reader.ReadBytes(digestSize).CopyTo(ticketDigestOwner.Memory.Span[..digestSize]);
        }

        var ticket = new TpmtTkAuth(tag, hierarchy, ticketDigestOwner.Memory[..digestSize]);

        return new PolicySignedResponse(timeoutOwner, timeoutSize, ticketDigestOwner, digestSize, ticket);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            TimeoutOwner.Dispose();
            TicketDigestOwner.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"PolicySignedResponse(timeout={TimeoutLength} bytes, ticket={PolicyTicket})";
}
