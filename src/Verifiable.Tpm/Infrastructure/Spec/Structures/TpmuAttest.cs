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
/// The <c>quote</c> (<see cref="TpmsQuoteInfo"/>), <c>certify</c> (<see cref="TpmsCertifyInfo"/>), <c>creation</c>
/// (<see cref="TpmsCreationInfo"/>), <c>time</c> (<see cref="TpmsTimeAttestInfo"/>), and <c>nv</c>
/// (<see cref="TpmsNvCertifyInfo"/>) members are modelled. The remaining attestation bodies (command-audit,
/// session-audit, NV-digest) share this union and can be added as the corresponding commands are implemented;
/// until then their selectors are rejected by <see cref="Parse"/>.
/// </para>
/// <para>
/// <b>Union members:</b>
/// </para>
/// <list type="bullet">
///   <item><description>TPM_ST_ATTEST_QUOTE: TPMS_QUOTE_INFO (see <see cref="Quote"/>).</description></item>
///   <item><description>TPM_ST_ATTEST_CERTIFY: TPMS_CERTIFY_INFO (see <see cref="Certify"/>).</description></item>
///   <item><description>TPM_ST_ATTEST_CREATION: TPMS_CREATION_INFO (see <see cref="Creation"/>).</description></item>
///   <item><description>TPM_ST_ATTEST_TIME: TPMS_TIME_ATTEST_INFO (see <see cref="Time"/>).</description></item>
///   <item><description>TPM_ST_ATTEST_NV: TPMS_NV_CERTIFY_INFO (see <see cref="Nv"/>).</description></item>
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
    /// Gets the creation information when <see cref="Type"/> is TPM_ST_ATTEST_CREATION; otherwise <see langword="null"/>.
    /// </summary>
    public TpmsCreationInfo? Creation { get; }

    /// <summary>
    /// Gets the time information when <see cref="Type"/> is TPM_ST_ATTEST_TIME; otherwise <see langword="null"/>.
    /// </summary>
    public TpmsTimeAttestInfo? Time { get; }

    /// <summary>
    /// Gets the NV-certify information when <see cref="Type"/> is TPM_ST_ATTEST_NV; otherwise <see langword="null"/>.
    /// </summary>
    public TpmsNvCertifyInfo? Nv { get; }

    /// <summary>
    /// Initializes a new attestation body, with exactly one of the union members set.
    /// </summary>
    private TpmuAttest(TpmStConstants type, TpmsQuoteInfo? quote, TpmsCertifyInfo? certify, TpmsCreationInfo? creation, TpmsTimeAttestInfo? time, TpmsNvCertifyInfo? nv)
    {
        Type = type;
        Quote = quote;
        Certify = certify;
        Creation = creation;
        Time = time;
        Nv = nv;
    }

    /// <summary>
    /// Creates an attestation body for a quote.
    /// </summary>
    /// <param name="quote">The quote information. Ownership is transferred.</param>
    /// <returns>The attestation body.</returns>
    public static TpmuAttest ForQuote(TpmsQuoteInfo quote)
    {
        ArgumentNullException.ThrowIfNull(quote);

        return new TpmuAttest(TpmStConstants.TPM_ST_ATTEST_QUOTE, quote, null, null, null, null);
    }

    /// <summary>
    /// Creates an attestation body for a certify.
    /// </summary>
    /// <param name="certify">The certify information. Ownership is transferred.</param>
    /// <returns>The attestation body.</returns>
    public static TpmuAttest ForCertify(TpmsCertifyInfo certify)
    {
        ArgumentNullException.ThrowIfNull(certify);

        return new TpmuAttest(TpmStConstants.TPM_ST_ATTEST_CERTIFY, null, certify, null, null, null);
    }

    /// <summary>
    /// Creates an attestation body for a creation certification.
    /// </summary>
    /// <param name="creation">The creation information. Ownership is transferred.</param>
    /// <returns>The attestation body.</returns>
    public static TpmuAttest ForCreation(TpmsCreationInfo creation)
    {
        ArgumentNullException.ThrowIfNull(creation);

        return new TpmuAttest(TpmStConstants.TPM_ST_ATTEST_CREATION, null, null, creation, null, null);
    }

    /// <summary>
    /// Creates an attestation body for a time attestation.
    /// </summary>
    /// <param name="time">The time information.</param>
    /// <returns>The attestation body.</returns>
    public static TpmuAttest ForTime(TpmsTimeAttestInfo time) =>
        new(TpmStConstants.TPM_ST_ATTEST_TIME, null, null, null, time, null);

    /// <summary>
    /// Creates an attestation body for an NV-certify.
    /// </summary>
    /// <param name="nv">The NV-certify information. Ownership is transferred.</param>
    /// <returns>The attestation body.</returns>
    public static TpmuAttest ForNv(TpmsNvCertifyInfo nv)
    {
        ArgumentNullException.ThrowIfNull(nv);

        return new TpmuAttest(TpmStConstants.TPM_ST_ATTEST_NV, null, null, null, null, nv);
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
            TpmStConstants.TPM_ST_ATTEST_CREATION => Creation!.SerializedSize,
            TpmStConstants.TPM_ST_ATTEST_TIME => TpmsTimeAttestInfo.SerializedSize,
            TpmStConstants.TPM_ST_ATTEST_NV => Nv!.SerializedSize,
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
            case(TpmStConstants.TPM_ST_ATTEST_CREATION):
            {
                Creation!.WriteTo(ref writer);
                break;
            }
            case(TpmStConstants.TPM_ST_ATTEST_TIME):
            {
                Time!.Value.WriteTo(ref writer);
                break;
            }
            case(TpmStConstants.TPM_ST_ATTEST_NV):
            {
                Nv!.WriteTo(ref writer);
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
            TpmStConstants.TPM_ST_ATTEST_QUOTE => new TpmuAttest(type, TpmsQuoteInfo.Parse(ref reader, pool), null, null, null, null),
            TpmStConstants.TPM_ST_ATTEST_CERTIFY => new TpmuAttest(type, null, TpmsCertifyInfo.Parse(ref reader, pool), null, null, null),
            TpmStConstants.TPM_ST_ATTEST_CREATION => new TpmuAttest(type, null, null, TpmsCreationInfo.Parse(ref reader, pool), null, null),
            TpmStConstants.TPM_ST_ATTEST_TIME => new TpmuAttest(type, null, null, null, TpmsTimeAttestInfo.Parse(ref reader), null),
            TpmStConstants.TPM_ST_ATTEST_NV => new TpmuAttest(type, null, null, null, null, TpmsNvCertifyInfo.Parse(ref reader, pool)),
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
            Creation?.Dispose();
            Nv?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => Type switch
    {
        TpmStConstants.TPM_ST_ATTEST_QUOTE => $"TPMU_ATTEST(QUOTE, {Quote})",
        TpmStConstants.TPM_ST_ATTEST_CERTIFY => $"TPMU_ATTEST(CERTIFY, {Certify})",
        TpmStConstants.TPM_ST_ATTEST_CREATION => $"TPMU_ATTEST(CREATION, {Creation})",
        TpmStConstants.TPM_ST_ATTEST_TIME => $"TPMU_ATTEST(TIME, {Time})",
        TpmStConstants.TPM_ST_ATTEST_NV => $"TPMU_ATTEST(NV, {Nv})",
        _ => $"TPMU_ATTEST({Type})"
    };
}
