using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Sized buffer wrapping a marshaled attestation structure (TPM2B_ATTEST).
/// </summary>
/// <remarks>
/// <para>
/// The attestation commands return the signed statement as this sized buffer. The signature is computed over
/// the <b>raw</b> attestation bytes, so this type retains them verbatim (<see cref="GetRawBytes"/>) for
/// signature verification, alongside the parsed <see cref="AttestationData"/> for field inspection — mirroring
/// how <see cref="Tpm2bPublic"/> keeps the raw public-area bytes used to compute a key's Name.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the attestationData buffer in bytes.
///     BYTE   attestationData[size];            // A marshaled TPMS_ATTEST.
/// } TPM2B_ATTEST;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.12.13, Table 179.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bAttest: ITpmWireType, IDisposable
{
    private readonly IMemoryOwner<byte>? rawStorage;
    private readonly int rawLength;
    private bool disposed;

    /// <summary>
    /// Gets the parsed attestation structure.
    /// </summary>
    public TpmsAttest AttestationData { get; }

    /// <summary>
    /// Initializes a new sized attestation buffer.
    /// </summary>
    private Tpm2bAttest(TpmsAttest attestationData, IMemoryOwner<byte>? rawStorage, int rawLength)
    {
        AttestationData = attestationData;
        this.rawStorage = rawStorage;
        this.rawLength = rawLength;
    }

    /// <summary>
    /// Gets the raw marshaled attestation bytes (the exact bytes the signature is computed over).
    /// </summary>
    /// <returns>The raw attestation bytes.</returns>
    /// <remarks>
    /// Verification hashes these bytes with the signing scheme's hash algorithm; re-serializing the parsed
    /// <see cref="AttestationData"/> is not guaranteed to reproduce them, so verify against this span.
    /// </remarks>
    public ReadOnlySpan<byte> GetRawBytes()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(rawStorage is null)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        return rawStorage.Memory.Span.Slice(0, rawLength);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return sizeof(ushort) + rawLength;
    }

    /// <summary>
    /// Writes this structure to a TPM writer, preserving the raw attestation bytes.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)rawLength);
        writer.WriteBytes(GetRawBytes());
    }

    /// <summary>
    /// Parses a sized attestation buffer from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed attestation buffer.</returns>
    public static Tpm2bAttest Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            throw new InvalidOperationException("TPM2B_ATTEST size cannot be zero.");
        }

        //Retain the raw bytes: the signature is over them, so verification hashes these exact bytes.
        IMemoryOwner<byte> rawStorage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(rawStorage.Memory.Span.Slice(0, size));

        //Parse the TPMS_ATTEST from the raw bytes.
        var innerReader = new TpmReader(rawStorage.Memory.Span.Slice(0, size));
        TpmsAttest attestationData = TpmsAttest.Parse(ref innerReader, pool);

        return new Tpm2bAttest(attestationData, rawStorage, size);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            AttestationData.Dispose();
            rawStorage?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPM2B_ATTEST({rawLength} bytes, {AttestationData.Type})";
}
