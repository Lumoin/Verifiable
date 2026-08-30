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
///   <item><description>policyTicket (TPMT_TK_AUTH): a real authorization ticket when expiration was negative on a non-trial session, otherwise a NULL ticket (TPM 2.0 Library Part 3, Section 23.2.5).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicySignedResponse: IDisposable, ITpmWireType
{
    private bool disposed;
    private IMemoryOwner<byte> TimeoutOwner { get; }
    private int TimeoutLength { get; }

    /// <summary>
    /// Gets the timeout value (an 8-octet big-endian deadline when a ticket is produced; empty otherwise).
    /// </summary>
    public ReadOnlySpan<byte> Timeout => TimeoutOwner.Memory.Span[..TimeoutLength];

    /// <summary>
    /// Gets the authorization ticket (a NULL ticket unless expiration was negative on a non-trial session). It
    /// owns its own digest storage and is released by this response's <see cref="Dispose"/>.
    /// </summary>
    public TpmtTkAuth PolicyTicket { get; }

    /// <summary>
    /// Initializes a parsed TPM2_PolicySigned() response over the carriers its parse rented.
    /// </summary>
    /// <param name="timeoutOwner">The pooled storage holding the timeout octets; ownership transfers to this response.</param>
    /// <param name="timeoutLength">The number of valid octets at the head of <paramref name="timeoutOwner"/>.</param>
    /// <param name="policyTicket">The parsed authorization ticket; ownership transfers to this response.</param>
    private PolicySignedResponse(IMemoryOwner<byte> timeoutOwner, int timeoutLength, TpmtTkAuth policyTicket)
    {
        this.TimeoutOwner = timeoutOwner;
        this.TimeoutLength = timeoutLength;
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
    public static PolicySignedResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //timeout (TPM2B_TIMEOUT).
        ushort timeoutSize = reader.ReadUInt16();
        IMemoryOwner<byte> timeoutOwner = pool.Rent(Math.Max((int)timeoutSize, 1));
        try
        {
            if(timeoutSize > 0)
            {
                reader.ReadBytes(timeoutSize).CopyTo(timeoutOwner.Memory.Span[..timeoutSize]);
            }

            //policyTicket (TPMT_TK_AUTH, TPM 2.0 Library Part 2, clause 10.6.6, Table 114): the ticket carrier
            //reads its own tag, hierarchy, and digest and owns whatever storage the digest needs.
            TpmtTkAuth ticket = TpmtTkAuth.Parse(ref reader, pool);

            return new PolicySignedResponse(timeoutOwner, timeoutSize, ticket);
        }
        catch
        {
            //The timeout rental's only owner is this frame until the response adopts it, so a refused ticket
            //parse must release it.
            timeoutOwner.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            TimeoutOwner.Dispose();
            PolicyTicket.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"PolicySignedResponse(timeout={TimeoutLength} bytes, ticket={PolicyTicket})";
}
