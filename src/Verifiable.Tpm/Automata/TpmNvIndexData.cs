using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// A defined NV Index's data area held in pooled storage: the octets <c>TPM2_NV_Write()</c>,
/// <c>TPM2_NV_Increment()</c>, and a PIN Index's own counter update store, and <c>TPM2_NV_Read()</c>,
/// <c>TPM2_NV_Certify()</c>, and <c>TPM2_PolicyNV()</c> read back. Its size is fixed at definition by
/// <c>TPMS_NV_PUBLIC.dataSize</c> (TPM 2.0 Library Part 2, clause 13.6, Table 235), which is what
/// <see cref="Capacity"/> holds; the area carries no structure of its own on the wire — the commands that
/// transfer it frame a <c>TPM2B_MAX_NV_BUFFER</c> window over it — so no TPM 2.0 structure names the durable
/// area itself and it is modelled as a length-carrying pooled buffer rather than as a <c>TPM2B_*</c> type.
/// </summary>
/// <remarks>
/// <para>
/// The content is the caller-visible content of an NV Index — an EK certificate, a monotonic counter, a PIN
/// Index's <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> attempt count and threshold (Part 2, clause 13.3) — none of
/// which is a secret the way an authValue or a private key is, so the storage is a plain
/// <see cref="IMemoryOwner{T}"/> rental rather than a tagged secret carrier, the same shape
/// <see cref="TpmParameterArea"/> and <see cref="Verifiable.Tpm.Spec.Structures.Tpm2bName"/> use for their own
/// public content.
/// </para>
/// <para>
/// The whole area is rented ONCE, at <c>TPM2_NV_DefineSpace()</c>, at the declared <see cref="Capacity"/>, and
/// every later store <see cref="Write"/>s into it in place — the model of NV memory the specification describes,
/// where an Index's space is reserved at definition and a write merges <c>data.size</c> octets into
/// <c>nvIndex→data</c> starting at <c>nvIndex→data[offset]</c> (Part 3, clause 31.7.1). That is also what keeps
/// the area poolable at all: every store happens inside a pure state transition that holds no memory pool, so an
/// area re-rented per write would have nowhere to rent from.
/// </para>
/// <para>
/// <see cref="Length"/> is the WRITTEN extent — the octets a store has actually reached — and grows to at most
/// <see cref="Capacity"/>. A store at a non-zero offset advances it over the reserved octets below that offset,
/// which read as the zeros <see cref="Allocate"/> leaves them at.
/// </para>
/// <para>
/// The written extent is the bound this model checks a read or certify window against, where the clauses that
/// state the rule name the Index's declared <c>dataSize</c> — <see cref="Capacity"/> here: "If offset and the
/// size field of data add to a value that is greater than the dataSize field of the NV Index referenced by
/// nvIndex, the TPM shall return an error (TPM_RC_NV_RANGE)" (TPM 2.0 Library Part 3, clause 31.13.1 for
/// <c>TPM2_NV_Read()</c>, and clause 31.16.1 for <c>TPM2_NV_Certify()</c>, which states it of "offset and
/// size"). A window that
/// lies inside the declared space but reaches past the octets a store has written is therefore
/// <c>TPM_RC_NV_RANGE</c> here, where those clauses admit it.
/// </para>
/// <para>
/// The area is rented by the defining command's parser as the parser's last act and owned by the parsed request
/// record until the defining transition transfers it onto the Index; from there the Index is its owner and
/// releases it when the Index leaves the automaton's dictionary (<c>TPM2_NV_UndefineSpace()</c>,
/// <c>TPM2_Clear()</c>, simulator teardown). Every other holder — a read response intent, a declared certify or
/// framing action — borrows it and never disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmNvIndexData: IDisposable
{
    /// <summary>
    /// The shared zero-capacity instance backing every Index defined with a <c>dataSize</c> of zero.
    /// </summary>
    private static TpmNvIndexData EmptyInstance { get; } = new();

    /// <summary>
    /// The pooled storage, or <see langword="null"/> for <see cref="Empty"/>.
    /// </summary>
    private IMemoryOwner<byte>? Storage { get; }

    /// <summary>
    /// Whether <see cref="Dispose"/> has already released <see cref="Storage"/>.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Initializes the zero-capacity instance, which rents nothing and is immune to disposal.
    /// </summary>
    private TpmNvIndexData()
    {
        Storage = null;
        Capacity = 0;
        Length = 0;
    }

    /// <summary>
    /// Initializes a data area over pooled storage reserved at an Index's declared size.
    /// </summary>
    /// <param name="storage">The pooled storage this instance takes ownership of.</param>
    /// <param name="capacity">The Index's declared <c>dataSize</c>, the number of octets reserved.</param>
    private TpmNvIndexData(IMemoryOwner<byte> storage, int capacity)
    {
        Storage = storage;
        Capacity = capacity;
        Length = 0;
    }

    /// <summary>
    /// Gets the shared zero-capacity data area, used by every Index whose declared <c>dataSize</c> is zero. It
    /// rents nothing and its <see cref="Dispose"/> is a no-op.
    /// </summary>
    public static TpmNvIndexData Empty => EmptyInstance;

    /// <summary>
    /// Gets the number of octets reserved for this Index at definition (<c>TPMS_NV_PUBLIC.dataSize</c>).
    /// </summary>
    public int Capacity { get; }

    /// <summary>
    /// Gets the written extent: the number of octets at the start of the area a store has reached. Zero for an
    /// Index that has never been written.
    /// </summary>
    public int Length { get; private set; }

    /// <summary>
    /// Gets whether the area holds no written octets.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the written octets as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(Storage is null)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return Storage.Memory.Span[..Length];
        }
    }

    /// <summary>
    /// Gets the written octets as read-only memory aliasing this instance's pooled storage — for a borrowing
    /// consumer such as a read response's framing window or an attestation over the Index's content, valid
    /// until <see cref="Dispose"/> and never copied into an untracked array.
    /// </summary>
    /// <returns>The written octets.</returns>
    public ReadOnlyMemory<byte> AsReadOnlyMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(Storage is null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return Storage.Memory[..Length];
    }

    /// <summary>
    /// Reserves an Index's data area at its declared size, with every reserved octet zero: a freshly defined
    /// Index's area reads as zeros before any store has reached it, and a store at a non-zero offset leaves the
    /// octets below that offset reading as zeros rather than as whatever the rental carried.
    /// </summary>
    /// <param name="dataSize">The Index's declared <c>dataSize</c> in octets.</param>
    /// <param name="pool">The memory pool the storage is rented from.</param>
    /// <returns>The data area; the caller owns it. A declared size of zero yields <see cref="Empty"/>, which rents nothing.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static TpmNvIndexData Allocate(ushort dataSize, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(dataSize == 0)
        {
            return Empty;
        }

        IMemoryOwner<byte> storage = pool.Rent(dataSize);
        try
        {
            //The reserved octets are this type's own content the moment they are reserved: Length advances over
            //them on a store at a non-zero offset and Span publishes them from there on, so they are zeroed here
            //rather than taken as whatever state the rental arrives in.
            storage.Memory.Span[..dataSize].Clear();

            return new TpmNvIndexData(storage, dataSize);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Merges <paramref name="data"/> into the area starting at <paramref name="offset"/> and advances
    /// <see cref="Length"/> to cover it, the store <c>TPM2_NV_Write()</c> performs (TPM 2.0 Library Part 3,
    /// clause 31.7.1: "the TPM will merge the <c>data.size</c> octets of <c>data.buffer</c> value into the
    /// <c>nvIndex→data</c> starting at <c>nvIndex→data[offset]</c>").
    /// </summary>
    /// <param name="offset">The octet offset into the area at which the store begins.</param>
    /// <param name="data">The octets to store.</param>
    /// <exception cref="ObjectDisposedException">Thrown when the owning Index has already released this area.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="offset"/> is negative or the store would run past <see cref="Capacity"/>; the calling transition has already range-checked the store against the Index's declared size, so this is the fail-closed backstop.</exception>
    public void Write(int offset, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);

        int end = offset + data.Length;
        ArgumentOutOfRangeException.ThrowIfGreaterThan(end, Capacity, nameof(data));

        if(Storage is not null && !data.IsEmpty)
        {
            data.CopyTo(Storage.Memory.Span[offset..]);
        }

        if(end > Length)
        {
            Length = end;
        }
    }

    /// <summary>
    /// Releases the pooled storage. Repeated calls and calls on <see cref="Empty"/> do nothing.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            Storage?.Dispose();
            disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: the written extent and the reserved size only, never the octets
    /// themselves.
    /// </summary>
    private string DebuggerDisplay => $"NvIndexData({Length}/{Capacity} bytes)";
}
