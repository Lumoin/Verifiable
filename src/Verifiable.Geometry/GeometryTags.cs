using Verifiable.Cryptography;

namespace Verifiable.Geometry;

/// <summary>
/// Pre-built singleton <see cref="Tag"/> instances for geometry buffers,
/// following the same shape as the cryptographic tag collections: one
/// immutable, type-keyed tag per buffer purpose, created once.
/// </summary>
public static class GeometryTags
{
    /// <summary>Tags expansion scratch that spilled from stack to pool.</summary>
    public static Tag ExpansionScratch { get; } = Tag.Create((typeof(GeometryBufferKind), GeometryBufferKind.ExpansionScratch));

    /// <summary>Tags a pooled triangulation result buffer.</summary>
    public static Tag TriangulationResult { get; } = Tag.Create((typeof(GeometryBufferKind), GeometryBufferKind.TriangulationResult));
}
