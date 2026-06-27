using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_PolicySecret command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 23.4):
/// </para>
/// <list type="bullet">
///   <item><description>timeout (TPM2B_TIMEOUT): the expiration relative to the session, or empty when no ticket is produced.</description></item>
///   <item><description>policyTicket (TPMT_TK_AUTH): an authorization ticket, or a NULL ticket when the immediate (expiration 0) form is used.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicySecretResponse: IDisposable, ITpmWireType
{
    private bool disposed;
    private readonly IMemoryOwner<byte> timeoutOwner;
    private readonly int timeoutLength;
    private readonly IMemoryOwner<byte> ticketDigestOwner;
    private readonly int ticketDigestLength;

    /// <summary>
    /// Gets the timeout value (empty in the immediate form).
    /// </summary>
    public ReadOnlySpan<byte> Timeout => timeoutOwner.Memory.Span[..timeoutLength];

    /// <summary>
    /// Gets the authorization ticket (a NULL ticket in the immediate form).
    /// </summary>
    public TpmtTkAuth PolicyTicket { get; }

    private PolicySecretResponse(
        IMemoryOwner<byte> timeoutOwner, int timeoutLength, IMemoryOwner<byte> ticketDigestOwner, int ticketDigestLength, TpmtTkAuth policyTicket)
    {
        this.timeoutOwner = timeoutOwner;
        this.timeoutLength = timeoutLength;
        this.ticketDigestOwner = ticketDigestOwner;
        this.ticketDigestLength = ticketDigestLength;
        PolicyTicket = policyTicket;
    }

    /// <summary>
    /// Parses a TPM2_PolicySecret response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The rented buffers are owned by the returned PolicySecretResponse and disposed by the caller.")]
    public static PolicySecretResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
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

        return new PolicySecretResponse(timeoutOwner, timeoutSize, ticketDigestOwner, digestSize, ticket);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            timeoutOwner.Dispose();
            ticketDigestOwner.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"PolicySecretResponse(timeout={timeoutLength} bytes, ticket={PolicyTicket})";
}
