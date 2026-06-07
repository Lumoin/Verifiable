using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Geometry;

/// <summary>
/// The pooled fallback for expansion storage: a tagged, exact-size rental
/// of <see cref="double"/> components for the cases whose capacity bound
/// exceeds the caller's stack budget. The hot path never sees this type —
/// it allocates expansion storage with <c>stackalloc</c> sized by the
/// capacity functions on <see cref="Expansions"/>; this owner exists for
/// the long tail.
/// </summary>
/// <remarks>
/// Rentals come from <see cref="SensitiveMemoryPool{T}.Shared"/>, which
/// returns exactly the requested length — slices keep their meaning — and
/// clears returned memory. Dispose returns the rental; the
/// <see cref="Components"/> span must not be touched afterwards.
/// </remarks>
[DebuggerDisplay("ExpansionBuffer: Length = {Length}")]
public readonly record struct ExpansionBuffer: IDisposable
{
    /// <summary>The exact-size pool rental backing <see cref="Components"/>.</summary>
    private IMemoryOwner<double> Owner { get; }

    /// <summary>What this buffer holds; see <see cref="GeometryTags"/>.</summary>
    public Tag Tag { get; }

    /// <summary>The rented component storage, exactly the requested length.</summary>
    public Span<double> Components => Owner.Memory.Span;

    /// <summary>The component capacity this buffer was rented for.</summary>
    public int Length => Owner.Memory.Length;

    private ExpansionBuffer(IMemoryOwner<double> owner, Tag tag)
    {
        Owner = owner;
        Tag = tag;
    }

    /// <summary>
    /// Rents storage for <paramref name="componentCount"/> expansion
    /// components, tagged as <see cref="GeometryTags.ExpansionScratch"/>.
    /// </summary>
    public static ExpansionBuffer Rent(int componentCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(componentCount);

        return new ExpansionBuffer(SensitiveMemoryPool<double>.Shared.Rent(componentCount), GeometryTags.ExpansionScratch);
    }

    /// <summary>Returns the rental to the pool.</summary>
    public void Dispose()
    {
        Owner.Dispose();
    }
}
