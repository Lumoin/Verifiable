namespace Verifiable.Geometry;

/// <summary>
/// Discriminates what a pooled geometry buffer holds. Used as the
/// type-keyed payload in <see cref="GeometryTags"/> so a rented buffer is
/// never opaque bytes-with-no-story.
/// </summary>
public enum GeometryBufferKind
{
    /// <summary>Expansion components that outgrew the caller's stack budget.</summary>
    ExpansionScratch,

    /// <summary>A triangulation result owned by the caller until disposed.</summary>
    TriangulationResult
}
