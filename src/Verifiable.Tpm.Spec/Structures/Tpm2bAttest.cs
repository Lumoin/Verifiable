using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

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
/// Specification reference: TPM 2.0 Library Part 2, clause 10.11.13, Table 155.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bAttest: ITpmWireType, IDisposable
{
    private IMemoryOwner<byte>? RawStorage { get; }
    private int RawLength { get; }
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
        this.RawStorage = rawStorage;
        this.RawLength = rawLength;
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

        if(RawStorage is null)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        return RawStorage.Memory.Span.Slice(0, RawLength);
    }

    /// <summary>
    /// Gets the raw marshaled attestation bytes as memory, for asynchronous consumers such as the registered
    /// digest and verification seams. The memory aliases this instance's pooled storage — it is valid until
    /// <see cref="Dispose"/> and must not be copied out into untracked arrays.
    /// </summary>
    /// <returns>The raw attestation bytes.</returns>
    public ReadOnlyMemory<byte> GetRawMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(RawStorage is null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return RawStorage.Memory.Slice(0, RawLength);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return sizeof(ushort) + RawLength;
    }

    /// <summary>
    /// Writes this structure to a TPM writer, preserving the raw attestation bytes.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)RawLength);
        writer.WriteBytes(GetRawBytes());
    }

    /// <summary>
    /// Wraps an already-marshaled <c>TPMS_ATTEST</c> held in pooled memory — the form an attestation builder
    /// produces before signing it — taking ownership of the storage and exposing the structure view parsed from
    /// those same octets.
    /// </summary>
    /// <param name="attestationData">The pooled storage holding the marshaled <c>TPMS_ATTEST</c>; ownership transfers to the returned instance, or is released here when the length is refused or the octets do not parse — the caller never holds it again once it is handed in.</param>
    /// <param name="length">The number of valid octets in <paramref name="attestationData"/>.</param>
    /// <param name="pool">The memory pool for the structure view's buffers.</param>
    /// <returns>The sized attestation buffer over the supplied storage.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> is zero, negative, larger than the storage, or larger than a <c>UINT16</c> size field can carry; the storage has been released.</exception>
    public static Tpm2bAttest FromMarshaled(IMemoryOwner<byte> attestationData, int length, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(attestationData);

        try
        {
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, attestationData.Memory.Length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, ushort.MaxValue);

            var innerReader = new TpmReader(attestationData.Memory.Span.Slice(0, length));
            TpmsAttest attestationView = TpmsAttest.Parse(ref innerReader, pool);

            return new Tpm2bAttest(attestationView, attestationData, length);
        }
        catch
        {
            attestationData.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Parses a sized attestation buffer from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The declared size is checked against <see cref="TpmReader.Remaining"/> before <c>rawStorage</c> is
    /// rented, so a truncated outer buffer throws the same <see cref="ArgumentOutOfRangeException"/>
    /// <see cref="TpmReader.ReadBytes(int)"/> would have thrown without ever renting. Once <c>rawStorage</c> is
    /// rented, a refusing <see cref="TpmsAttest.Parse"/> — any field of the enclosed structure, including the
    /// nested <c>TPMU_ATTEST</c> body, declaring a size past its own bound, or truncated before it — is caught
    /// and <c>rawStorage</c> is released before the exception leaves, the same try/catch/dispose/rethrow shape as
    /// <see cref="FromMarshaled"/>.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed attestation buffer.</returns>
    /// <exception cref="InvalidOperationException">The declared size is zero, or a field of the enclosed <c>TPMS_ATTEST</c> declares a size past its own structure's bound.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>, or a field of the enclosed <c>TPMS_ATTEST</c> is truncated before its own declared size.</exception>
    /// <exception cref="NotSupportedException">The enclosed <c>TPMS_ATTEST</c> names an attestation type <see cref="TpmuAttest.Parse"/> does not model.</exception>
    public static Tpm2bAttest Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            throw new InvalidOperationException("TPM2B_ATTEST size cannot be zero.");
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), size, $"TPM2B_ATTEST size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        //Retain the raw bytes: the signature is over them, so verification hashes these exact bytes.
        IMemoryOwner<byte> rawStorage = pool.Rent(size);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(size);
            source.CopyTo(rawStorage.Memory.Span.Slice(0, size));

            //Parse the TPMS_ATTEST from the raw bytes.
            var innerReader = new TpmReader(rawStorage.Memory.Span.Slice(0, size));
            TpmsAttest attestationData = TpmsAttest.Parse(ref innerReader, pool);

            return new Tpm2bAttest(attestationData, rawStorage, size);
        }
        catch
        {
            rawStorage.Dispose();
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
            AttestationData.Dispose();
            RawStorage?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPM2B_ATTEST({RawLength} bytes, {AttestationData.Type})";

    /// <summary>
    /// Returns the same metadata-only summary the debugger shows — the raw octet count and the
    /// attestation type, never the attestation bytes — so an enclosing type's own diagnostic
    /// string interpolation renders this instance meaningfully instead of its type name.
    /// </summary>
    public override string ToString() => DebuggerDisplay;
}
