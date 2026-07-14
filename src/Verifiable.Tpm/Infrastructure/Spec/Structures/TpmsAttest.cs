using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// The common attestation structure (TPMS_ATTEST) the TPM produces and signs for the attestation commands.
/// </summary>
/// <remarks>
/// <para>
/// Every attestation begins with <see cref="Magic"/> == <see cref="TpmConstants32.TPM_GENERATED_VALUE"/>, which
/// a verifier MUST check: it is the marker the TPM stamps on data it generated, so a signature over a structure
/// lacking it cannot be a genuine TPM attestation (TPM 2.0 Library Part 2, Section 10.12.12). <see cref="Type"/>
/// then selects the <see cref="Attested"/> body.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_GENERATED   magic;                   // UINT32, MUST be TPM_GENERATED_VALUE.
///     TPMI_ST_ATTEST  type;                    // UINT16, selects the attested union member.
///     TPM2B_NAME      qualifiedSigner;         // Qualified Name of the signing key.
///     TPM2B_DATA      extraData;               // External information (the caller's qualifyingData/nonce).
///     TPMS_CLOCK_INFO clockInfo;               // Clock, resetCount, restartCount, safe.
///     UINT64          firmwareVersion;         // TPM-vendor firmware version.
///     TPMU_ATTEST     attested;                // Type-specific attestation body.
/// } TPMS_ATTEST;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.12.12, Table 178.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsAttest: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the magic value; a genuine TPM attestation has this equal to <see cref="TpmConstants32.TPM_GENERATED_VALUE"/>.
    /// </summary>
    public uint Magic { get; }

    /// <summary>
    /// Gets the attestation type, which selects the <see cref="Attested"/> body.
    /// </summary>
    public TpmStConstants Type { get; }

    /// <summary>
    /// Gets the Qualified Name of the key that signed this attestation.
    /// </summary>
    public Tpm2bName QualifiedSigner { get; }

    /// <summary>
    /// Gets the external data supplied by the caller (the <c>qualifyingData</c> nonce), echoed for freshness.
    /// </summary>
    public Tpm2bData ExtraData { get; }

    /// <summary>
    /// Gets the TPM clock and reset state at the time of attestation.
    /// </summary>
    public TpmsClockInfo ClockInfo { get; }

    /// <summary>
    /// Gets the TPM firmware version.
    /// </summary>
    public ulong FirmwareVersion { get; }

    /// <summary>
    /// Gets the type-specific attestation body.
    /// </summary>
    public TpmuAttest Attested { get; }

    /// <summary>
    /// Gets whether <see cref="Magic"/> equals <see cref="TpmConstants32.TPM_GENERATED_VALUE"/>.
    /// </summary>
    public bool IsTpmGenerated => Magic == TpmConstants32.TPM_GENERATED_VALUE;

    /// <summary>
    /// Initializes a new attestation structure.
    /// </summary>
    private TpmsAttest(
        uint magic,
        TpmStConstants type,
        Tpm2bName qualifiedSigner,
        Tpm2bData extraData,
        TpmsClockInfo clockInfo,
        ulong firmwareVersion,
        TpmuAttest attested)
    {
        Magic = magic;
        Type = type;
        QualifiedSigner = qualifiedSigner;
        ExtraData = extraData;
        ClockInfo = clockInfo;
        FirmwareVersion = firmwareVersion;
        Attested = attested;
    }

    /// <summary>
    /// Creates an attestation structure from its fields (for tests and round-trips).
    /// </summary>
    /// <param name="magic">The magic value (use <see cref="TpmConstants32.TPM_GENERATED_VALUE"/> for a TPM-genuine image).</param>
    /// <param name="type">The attestation type, which must match <paramref name="attested"/>.</param>
    /// <param name="qualifiedSigner">The Qualified Name of the signer. Ownership is transferred.</param>
    /// <param name="extraData">The caller's qualifying data. Ownership is transferred.</param>
    /// <param name="clockInfo">The clock and reset state.</param>
    /// <param name="firmwareVersion">The firmware version.</param>
    /// <param name="attested">The type-specific attestation body. Ownership is transferred.</param>
    /// <returns>The created attestation structure.</returns>
    public static TpmsAttest Create(
        uint magic,
        TpmStConstants type,
        Tpm2bName qualifiedSigner,
        Tpm2bData extraData,
        TpmsClockInfo clockInfo,
        ulong firmwareVersion,
        TpmuAttest attested)
    {
        ArgumentNullException.ThrowIfNull(qualifiedSigner);
        ArgumentNullException.ThrowIfNull(extraData);
        ArgumentNullException.ThrowIfNull(attested);

        return new TpmsAttest(magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion, attested);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return sizeof(uint) +                       //magic (TPM_GENERATED)
               sizeof(ushort) +                     //type (TPMI_ST_ATTEST)
               QualifiedSigner.SerializedSize +
               ExtraData.SerializedSize +
               TpmsClockInfo.SerializedSize +
               sizeof(ulong) +                      //firmwareVersion
               Attested.GetSerializedSize();
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt32(Magic);
        writer.WriteUInt16((ushort)Type);
        QualifiedSigner.WriteTo(ref writer);
        ExtraData.WriteTo(ref writer);
        ClockInfo.WriteTo(ref writer);
        writer.WriteUInt64(FirmwareVersion);
        Attested.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses an attestation structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed attestation structure.</returns>
    public static TpmsAttest Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        uint magic = reader.ReadUInt32();
        var type = (TpmStConstants)reader.ReadUInt16();
        Tpm2bName qualifiedSigner = Tpm2bName.Parse(ref reader, pool);
        try
        {
            Tpm2bData extraData = Tpm2bData.Parse(ref reader, pool);
            try
            {
                //A malformed clockInfo/firmwareVersion/attested field throws after qualifiedSigner and extraData
                //are already rented; the two catch blocks unwind those pooled buffers rather than leaking them.
                TpmsClockInfo clockInfo = TpmsClockInfo.Parse(ref reader);
                ulong firmwareVersion = reader.ReadUInt64();
                TpmuAttest attested = TpmuAttest.Parse(type, ref reader, pool);

                return new TpmsAttest(magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion, attested);
            }
            catch
            {
                extraData.Dispose();
                throw;
            }
        }
        catch
        {
            qualifiedSigner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            QualifiedSigner.Dispose();
            ExtraData.Dispose();
            Attested.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMS_ATTEST(magic=0x{Magic:X8}, {Type}, fw={FirmwareVersion})";
}
