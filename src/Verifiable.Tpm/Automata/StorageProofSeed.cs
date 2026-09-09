using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The rotatable seed the storage and endorsement hierarchy proofs (<c>shProof</c>, <c>ehProof</c>)
/// derive from — the simulator's stand-in for the Storage Primary Seed a real TPM keeps in NV
/// (TPM 2.0 Library Part 1, clauses 11.4.4 and 11.5), held in a pinned, zero-on-dispose carrier
/// because every owner/endorsement-hierarchy proof, and therefore every outstanding
/// creation/context-integrity ticket, is an HMAC keyed from it.
/// </summary>
/// <remarks>
/// <para>
/// <c>TPM2_Clear()</c> replaces the seed from the RNG (Part 3, clause 24.6.1), which is the whole
/// mechanism by which outstanding owner/endorsement tickets and saved contexts stop verifying:
/// rotating the seed invalidates them structurally, with no revocation pass over any list. The
/// carrier makes the rotation's memory story explicit — the outgoing seed's buffer is disposed
/// (zeroed and returned to its pool) when the replacement is installed.
/// </para>
/// <para>
/// <see cref="Empty"/> models the not-yet-generated state every construction that supplies no seed
/// starts from — proof derivation falls back to the platform seed while it holds, which is what
/// makes a freshly manufactured TPM's per-hierarchy proofs exactly what one shared seed yields. It
/// is backed by <see cref="EmptyMemoryOwner"/> and therefore safe to alias and immune to disposal,
/// following the same sentinel convention as <see cref="SessionBoundEntity.Unbound"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("StorageProofSeed(IsGenerated={IsGenerated})")]
public sealed class StorageProofSeed: SensitiveMemory
{
    /// <summary>
    /// The shared not-yet-generated seed, held from construction until <c>TPM2_Clear()</c> generates
    /// a real one (or a caller supplies a fixed carrier). Backed by <see cref="EmptyMemoryOwner"/>,
    /// so it is safe to alias across states and immune to disposal.
    /// </summary>
    public static StorageProofSeed Empty { get; } = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Initializes the carrier over <paramref name="storage"/>, whose ownership transfers to this
    /// instance.
    /// </summary>
    /// <param name="storage">The memory owner holding the seed octets.</param>
    private StorageProofSeed(IMemoryOwner<byte> storage): base(storage, TpmTags.StorageProofSeed)
    {
    }

    /// <summary>
    /// Gets the seed length in octets; zero for <see cref="Empty"/>.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets whether this carrier holds a generated (or caller-fixed) seed rather than the
    /// <see cref="Empty"/> sentinel.
    /// </summary>
    public bool IsGenerated => MemoryOwner is not EmptyMemoryOwner;

    /// <summary>
    /// Creates a seed carrier holding a copy of <paramref name="seed"/> in pinned pooled storage.
    /// </summary>
    /// <param name="seed">The seed octets; an empty span answers <see cref="Empty"/>.</param>
    /// <param name="pool">The memory pool the pinned storage is rented from.</param>
    /// <returns>The seed carrier; the caller owns it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static StorageProofSeed Create(ReadOnlySpan<byte> seed, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(seed.IsEmpty)
        {
            return Empty;
        }

        IMemoryOwner<byte> storage = pool.Rent(seed.Length, AllocationKind.Pinned);
        seed.CopyTo(storage.Memory.Span);

        return new StorageProofSeed(storage);
    }
}
