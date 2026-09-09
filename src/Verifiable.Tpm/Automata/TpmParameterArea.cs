using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// A command's or a response's parameter area held in pooled storage: the octets that follow the handle and
/// authorization areas of a command, or that follow the response header and precede the response authorization
/// area (TPM 2.0 Library Part 1, clause 15.7 equation 15, printed page 106, and clause 15.8 equation 16,
/// printed page 107 — cpHash's and rpHash's <c>parameters</c> term). The area is a concatenation of a command's
/// or response's own parameters and carries no structure of its own, so no TPM 2.0 structure names it and it is
/// modelled as a length-carrying pooled buffer rather than as a <c>TPM2B_*</c> type.
/// </summary>
/// <remarks>
/// <para>
/// The content is a command's parameters exactly as they arrived on the wire, and — once a parameter-decryption
/// step has transformed the area in place (Part 3, clause 5.7) — those parameters in PLAINTEXT: the recovered
/// <c>TPMS_SENSITIVE_CREATE</c> of a <c>TPM2_Create()</c>, which carries both the object's <c>userAuth</c> and
/// the sealed <c>data</c>, or the recovered replacement authorization value of a <c>TPM2_NV_DefineSpace()</c>,
/// <c>TPM2_NV_ChangeAuth()</c> or <c>TPM2_HierarchyChangeAuth()</c>. The storage is therefore a PINNED rental
/// that <see cref="Dispose"/> zeroes before returning it to the pool, the same allocation kind and the same
/// clear-before-release discipline the <c>TPM2B_*</c> secret carriers use, even though the area itself carries
/// no tag: an unpinned slab is movable, so a compaction between the decrypt and the release would leave copies
/// of the recovered plaintext elsewhere on the heap.
/// </para>
/// <para>
/// <see cref="Memory"/> is a MUTABLE view of the same octets <see cref="Span"/> and
/// <see cref="AsReadOnlyMemory"/> expose, and it exists so a parameter-decryption step can transform the
/// captured area in place. That is normative rather than an optimization: cpHash is computed over the
/// parameters exactly as received, ciphertext included (Part 3, clause 5.6, which precedes clause 5.7's
/// decryption; Part 1, clause 18.1), and the command body is then decoded from the decrypted octets — so the
/// ciphertext the digest covered and the plaintext the body consumes must be the same buffer, transformed
/// between the two readings.
/// </para>
/// <para>
/// A command's area is rented by its parser as the parser's last act and owned by the parsed request record; a
/// response's area is rented by the framing effect and owned by the response intent, whose serialization is the
/// terminal owner. Every other holder — a declared action, a verification-queue record — borrows it and never
/// disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmParameterArea: IDisposable
{
    /// <summary>
    /// The shared zero-length instance backing every parameter-free command and response.
    /// </summary>
    private static TpmParameterArea EmptyInstance { get; } = new();

    /// <summary>
    /// The pooled storage, or <see langword="null"/> for <see cref="Empty"/>.
    /// </summary>
    private IMemoryOwner<byte>? Storage { get; }

    /// <summary>
    /// Whether <see cref="Dispose"/> has already released <see cref="Storage"/>.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Initializes the zero-length instance, which rents nothing and is immune to disposal.
    /// </summary>
    private TpmParameterArea()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes a parameter area over pooled storage.
    /// </summary>
    /// <param name="storage">The pooled storage this instance takes ownership of.</param>
    /// <param name="length">The number of valid octets at the start of <paramref name="storage"/>.</param>
    private TpmParameterArea(IMemoryOwner<byte> storage, int length)
    {
        Storage = storage;
        Length = length;
    }

    /// <summary>
    /// Gets the shared zero-length parameter area, used by every command and response that carries no
    /// parameters at all. It rents nothing and its <see cref="Dispose"/> is a no-op.
    /// </summary>
    public static TpmParameterArea Empty => EmptyInstance;

    /// <summary>
    /// Gets whether the area carries no octets.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the number of octets in the area.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the area's octets as a read-only span.
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
    /// Gets a MUTABLE view of the area's octets, for a parameter-decryption step that transforms the captured
    /// area in place so that the digested ciphertext and the decoded plaintext are the same buffer (TPM 2.0
    /// Library Part 3, clause 5.6 before clause 5.7).
    /// </summary>
    public Memory<byte> Memory
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(Storage is null)
            {
                return Memory<byte>.Empty;
            }

            return Storage.Memory[..Length];
        }
    }

    /// <summary>
    /// Gets the area's octets as read-only memory aliasing this instance's pooled storage — for a borrowing
    /// consumer such as a cpHash concatenation, valid until <see cref="Dispose"/> and never copied into an
    /// untracked array.
    /// </summary>
    /// <returns>The area's octets.</returns>
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
    /// Creates a parameter area holding a copy of the supplied octets in a PINNED rental, since a
    /// parameter-decryption step can leave recovered plaintext in it.
    /// </summary>
    /// <param name="octets">The parameter octets exactly as they appeared on the wire.</param>
    /// <param name="pool">The memory pool the storage is rented from.</param>
    /// <returns>The parameter area; the caller owns it. An empty input yields <see cref="Empty"/>, which rents nothing.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static TpmParameterArea Create(ReadOnlySpan<byte> octets, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(octets.IsEmpty)
        {
            return Empty;
        }

        IMemoryOwner<byte> storage = pool.Rent(octets.Length, AllocationKind.Pinned);
        try
        {
            octets.CopyTo(storage.Memory.Span);

            return new TpmParameterArea(storage, octets.Length);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Takes ownership of storage a caller has already rented and filled — the shape a response-framing step
    /// uses, where the area is written directly into the rental by a writer rather than copied in afterwards.
    /// </summary>
    /// <param name="storage">The pooled storage to take ownership of.</param>
    /// <param name="length">The number of valid octets at the start of <paramref name="storage"/>.</param>
    /// <returns>The parameter area; the caller no longer owns <paramref name="storage"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="storage"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="length"/> is negative or exceeds the storage.</exception>
    public static TpmParameterArea Adopt(IMemoryOwner<byte> storage, int length)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, storage.Memory.Length);

        return new TpmParameterArea(storage, length);
    }

    /// <summary>
    /// Zeroes the octets and releases the pooled storage. The zeroing covers the whole rental rather than the
    /// valid prefix, so a decrypt that recovered plaintext into the area leaves nothing behind whichever length
    /// the area was framed at. Repeated calls and calls on <see cref="Empty"/> do nothing.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            if(Storage is not null)
            {
                Storage.Memory.Span.Clear();
                Storage.Dispose();
            }

            disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: the octet count only, never the octets themselves.
    /// </summary>
    private string DebuggerDisplay => $"ParameterArea({Length} bytes)";
}
