using System.Collections.Generic;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Extension methods for <see cref="TpmsAlgProperty"/>.
/// </summary>
/// <remarks>
/// Provides interpretation and query methods for algorithm properties.
/// </remarks>
public static class TpmsAlgPropertyExtensions
{
    /// <summary>
    /// Gets a human-readable description of the algorithm and its capabilities.
    /// </summary>
    /// <param name="property">The algorithm property to describe.</param>
    /// <returns>A human-readable description.</returns>
    public static string GetDescription(this TpmsAlgProperty property)
    {
        var capabilities = property.GetCapabilities();
        string caps = capabilities.Count > 0
            ? string.Join(", ", capabilities)
            : "none";

        return $"ALG_0x{property.Algorithm:X4}: [{caps}]";
    }

    /// <summary>
    /// Gets a list of capability names for the algorithm.
    /// </summary>
    /// <param name="property">The algorithm property.</param>
    /// <returns>A list of capability names.</returns>
    public static IReadOnlyList<string> GetCapabilities(this TpmsAlgProperty property)
    {
        var capabilities = new List<string>();

        if(property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.ASYMMETRIC))
        {
            capabilities.Add("asymmetric");
        }

        if(property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.SYMMETRIC))
        {
            capabilities.Add("symmetric");
        }

        if(property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.HASH))
        {
            capabilities.Add("hash");
        }

        if(property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.SIGNING))
        {
            capabilities.Add("signing");
        }

        if(property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.ENCRYPTING))
        {
            capabilities.Add("encrypting");
        }

        if(property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.OBJECT))
        {
            capabilities.Add("object");
        }

        if(property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.METHOD))
        {
            capabilities.Add("method");
        }

        return capabilities;
    }

    /// <summary>
    /// Determines if the algorithm is a hash algorithm.
    /// </summary>
    /// <param name="property">The algorithm property.</param>
    /// <returns><c>true</c> if this is a hash algorithm; otherwise, <c>false</c>.</returns>
    public static bool IsHash(this TpmsAlgProperty property)
    {
        return property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.HASH);
    }

    /// <summary>
    /// Determines if the algorithm is an asymmetric algorithm.
    /// </summary>
    /// <param name="property">The algorithm property.</param>
    /// <returns><c>true</c> if this is an asymmetric algorithm; otherwise, <c>false</c>.</returns>
    public static bool IsAsymmetric(this TpmsAlgProperty property)
    {
        return property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.ASYMMETRIC);
    }

    /// <summary>
    /// Determines if the algorithm is a symmetric algorithm.
    /// </summary>
    /// <param name="property">The algorithm property.</param>
    /// <returns><c>true</c> if this is a symmetric algorithm; otherwise, <c>false</c>.</returns>
    public static bool IsSymmetric(this TpmsAlgProperty property)
    {
        return property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.SYMMETRIC);
    }

    /// <summary>
    /// Determines if the algorithm can be used for signing.
    /// </summary>
    /// <param name="property">The algorithm property.</param>
    /// <returns><c>true</c> if this algorithm supports signing; otherwise, <c>false</c>.</returns>
    public static bool IsSigning(this TpmsAlgProperty property)
    {
        return property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.SIGNING);
    }

    /// <summary>
    /// Determines if the algorithm can be used for encryption.
    /// </summary>
    /// <param name="property">The algorithm property.</param>
    /// <returns><c>true</c> if this algorithm supports encryption; otherwise, <c>false</c>.</returns>
    public static bool IsEncrypting(this TpmsAlgProperty property)
    {
        return property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.ENCRYPTING);
    }

    /// <summary>
    /// Determines if the algorithm can be used for object creation.
    /// </summary>
    /// <param name="property">The algorithm property.</param>
    /// <returns><c>true</c> if this algorithm can be used for objects; otherwise, <c>false</c>.</returns>
    public static bool IsObject(this TpmsAlgProperty property)
    {
        return property.AlgorithmAttributes.HasFlag(TpmaAlgorithm.OBJECT);
    }
}