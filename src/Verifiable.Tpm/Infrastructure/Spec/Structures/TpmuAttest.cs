using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Union of attestation bodies (TPMU_ATTEST), selected by the enclosing TPMS_ATTEST <c>type</c>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>quote</c> (<see cref="TpmsQuoteInfo"/>) and <c>certify</c> (<see cref="TpmsCertifyInfo"/>) members are
/// modelled. The other attestation bodies (creation, command-audit, session-audit, time, NV) share this union
/// and can be added as the corresponding commands are implemented; until then their selectors are rejected by
/// <see cref="Parse"/>.
/// </para>
/// <para>
/// <b>Union members:</b>
/// </para>
/// <list type="bullet">
///   <item><description>TPM_ST_ATTEST_QUOTE: TPMS_QUOTE_INFO (see <see cref="Quote"/>).</description></item>
///   <item><description>TPM_ST_ATTEST_CERTIFY: TPMS_CERTIFY_INFO (see <see cref="Certify"/>).</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.12.11, Table 177 (TPMU_ATTEST).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmuAttest: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the attestation type selector (for example TPM_ST_ATTEST_QUOTE or TPM_ST_ATTEST_CERTIFY).
    /// </summary>
    public TpmStConstants Type { get; }

    /// <summary>
    /// Gets the quote information when <see cref="Type"/> is TPM_ST_ATTEST_QUOTE; otherwise <see langword="null"/>.
    /// </summary>
    public TpmsQuoteInfo? Quote { get; }

    /// <summary>
    /// Gets the certify information when <see cref="Type"/> is TPM_ST_ATTEST_CERTIFY; otherwise <see langword="null"/>.
    /// </summary>
    public TpmsCertifyInfo? Certify { get; }

    /// <summary>
    /// Initializes a new attestation body for a quote.
    /// </summary>
    private TpmuAttest(TpmStConstants type, TpmsQuoteInfo quote)
    {
        Type = type;
        Quote = quote;
        Certify = null;
    }

    /// <summary>
    /// Initializes a new attestation body for a certify.
    /// </summary>
    private TpmuAttest(TpmStConstants type, TpmsCertifyInfo certify)
    {
        Type = type;
        Certify = certify;
        Quote = null;
    }

    /// <summary>
    /// Creates an attestation body for a quote.
    /// </summary>
    /// <param name="quote">The quote information. Ownership is transferred.</param>
    /// <returns>The attestation body.</returns>
    public static TpmuAttest ForQuote(TpmsQuoteInfo quote)
    {
        ArgumentNullException.ThrowIfNull(quote);

        return new TpmuAttest(TpmStConstants.TPM_ST_ATTEST_QUOTE, quote);
    }

    /// <summary>
    /// Creates an attestation body for a certify.
    /// </summary>
    /// <param name="certify">The certify information. Ownership is transferred.</param>
    /// <returns>The attestation body.</returns>
    public static TpmuAttest ForCertify(TpmsCertifyInfo certify)
    {
        ArgumentNullException.ThrowIfNull(certify);

        return new TpmuAttest(TpmStConstants.TPM_ST_ATTEST_CERTIFY, certify);
    }

    /// <summary>
    /// Gets the serialized size of this union.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return Type switch
        {
            TpmStConstants.TPM_ST_ATTEST_QUOTE => Quote!.SerializedSize,
            TpmStConstants.TPM_ST_ATTEST_CERTIFY => Certify!.SerializedSize,
            _ => throw new NotSupportedException($"Attestation type '{Type}' is not supported for serialization.")
        };
    }

    /// <summary>
    /// Writes this union to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <remarks>
    /// The type selector is not written; it is written separately as part of TPMS_ATTEST.
    /// </remarks>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        switch(Type)
        {
            case(TpmStConstants.TPM_ST_ATTEST_QUOTE):
            {
                Quote!.WriteTo(ref writer);
                break;
            }
            case(TpmStConstants.TPM_ST_ATTEST_CERTIFY):
            {
                Certify!.WriteTo(ref writer);
                break;
            }
            default:
            {
                throw new NotSupportedException($"Attestation type '{Type}' is not supported for serialization.");
            }
        }
    }

    /// <summary>
    /// Parses an attestation body from a TPM reader using the supplied type selector.
    /// </summary>
    /// <param name="type">The attestation type selector from the enclosing TPMS_ATTEST.</param>
    /// <param name="reader">The reader positioned at the start of the attestation body.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed attestation body.</returns>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="type"/> is not a supported attestation type.</exception>
    public static TpmuAttest Parse(TpmStConstants type, ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return type switch
        {
            TpmStConstants.TPM_ST_ATTEST_QUOTE => new TpmuAttest(type, TpmsQuoteInfo.Parse(ref reader, pool)),
            TpmStConstants.TPM_ST_ATTEST_CERTIFY => new TpmuAttest(type, TpmsCertifyInfo.Parse(ref reader, pool)),
            _ => throw new NotSupportedException($"Attestation type '{type}' is not supported for parsing.")
        };
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Quote?.Dispose();
            Certify?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => Type switch
    {
        TpmStConstants.TPM_ST_ATTEST_QUOTE => $"TPMU_ATTEST(QUOTE, {Quote})",
        TpmStConstants.TPM_ST_ATTEST_CERTIFY => $"TPMU_ATTEST(CERTIFY, {Certify})",
        _ => $"TPMU_ATTEST({Type})"
    };
}
