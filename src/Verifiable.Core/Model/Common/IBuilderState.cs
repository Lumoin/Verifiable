using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Model.Common
{
    /// <summary>
    /// Marker interface for builder state objects.
    /// </summary>
    public interface IBuilderState { }


    /// <summary>
    /// A signature to generate fragment identifiers for verification methods.
    /// </summary>
    /// <param name="state">The builder state containing context information.</param>
    /// <returns>A fragment identifier (without the <c>#</c> prefix).</returns>
    /// <remarks>
    /// This generator should typically be called only when no explicit fragment is provided
    /// in the <see cref="KeyMaterialInput"/>. Builders are responsible for checking for explicit fragments
    /// before invoking the generator.
    /// </remarks>
    public delegate string FragmentGenerator(IBuilderState state);
}
