using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Proofs
{
    /// <summary>
    /// Specifies the canonicalization algorithm used by a cryptosuite to transform
    /// a document into a deterministic byte representation before hashing and signing.
    /// Each algorithm is represented by an integer constant.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This struct is part of a structured tagging mechanism designed to clearly
    /// define proof processing contexts. It works in conjunction with <see cref="CryptosuiteInfo"/>
    /// to provide a comprehensive framework for Data Integrity proof operations.
    /// </para>
    /// <para>
    /// Canonicalization ensures that semantically equivalent documents produce identical
    /// byte sequences, which is essential for deterministic digital signatures. Different
    /// algorithms trade off between complexity, semantic preservation, and implementation
    /// requirements.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#canonicalization">
    /// Data Integrity §4.3 Canonicalization</see>.
    /// </para>
    /// </remarks>
    public readonly struct CanonicalizationAlgorithm: IEquatable<CanonicalizationAlgorithm>
    {
        /// <summary>
        /// No canonicalization applied. The document is processed as-is.
        /// </summary>
        public static CanonicalizationAlgorithm None { get; } = new(0);

        /// <summary>
        /// RDF Dataset Canonicalization 1.0 (formerly known as URDNA2015).
        /// This algorithm produces a canonical form of an RDF dataset that preserves
        /// the full semantics of JSON-LD documents including blank node identifiers.
        /// See <see href="https://www.w3.org/TR/rdf-canon/">RDF Dataset Canonicalization</see>.
        /// </summary>
        public static CanonicalizationAlgorithm Rdfc10 { get; } = new(1);

        /// <summary>
        /// JSON Canonicalization Scheme per RFC 8785.
        /// This algorithm produces a canonical JSON representation without requiring
        /// JSON-LD processing, making it simpler to implement but losing some semantic
        /// equivalence guarantees.
        /// See <see href="https://www.rfc-editor.org/rfc/rfc8785">RFC 8785</see>.
        /// </summary>
        public static CanonicalizationAlgorithm Jcs { get; } = new(2);


        private static readonly List<CanonicalizationAlgorithm> algorithms = new([None, Rdfc10, Jcs]);

        /// <summary>
        /// Gets the collection of all registered canonicalization algorithms.
        /// </summary>
        public static IReadOnlyList<CanonicalizationAlgorithm> Algorithms => algorithms.AsReadOnly();

        /// <summary>
        /// Gets the integer code representing this canonicalization algorithm.
        /// </summary>
        public int Algorithm { get; }


        private CanonicalizationAlgorithm(int algorithm)
        {
            Algorithm = algorithm;
        }


        /// <summary>
        /// Creates and registers a new canonicalization algorithm with the specified code.
        /// </summary>
        /// <param name="algorithm">The integer code for the new algorithm.</param>
        /// <returns>The newly created canonicalization algorithm.</returns>
        /// <exception cref="ArgumentException">Thrown if the code already exists.</exception>
        public static CanonicalizationAlgorithm Create(int algorithm)
        {
            for(int i = 0; i < algorithms.Count; ++i)
            {
                if(algorithms[i].Algorithm == algorithm)
                {
                    throw new ArgumentException("Algorithm code already exists.", nameof(algorithm));
                }
            }

            var newAlgorithm = new CanonicalizationAlgorithm(algorithm);
            algorithms.Add(newAlgorithm);

            return newAlgorithm;
        }


        /// <inheritdoc/>
        public override string ToString() => CanonicalizationAlgorithmNames.GetName(this);


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(CanonicalizationAlgorithm other)
        {
            return Algorithm == other.Algorithm;
        }

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj) =>
            obj is CanonicalizationAlgorithm algorithm && Equals(algorithm);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in CanonicalizationAlgorithm left, in CanonicalizationAlgorithm right) =>
            left.Equals(right);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in CanonicalizationAlgorithm left, in CanonicalizationAlgorithm right) =>
            !left.Equals(right);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in object left, in CanonicalizationAlgorithm right) =>
            left is CanonicalizationAlgorithm algorithm && algorithm.Equals(right);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in CanonicalizationAlgorithm left, in object right) =>
            right is CanonicalizationAlgorithm algorithm && left.Equals(algorithm);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in object left, in CanonicalizationAlgorithm right) =>
            !(left == right);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in CanonicalizationAlgorithm left, in object right) =>
            !(left == right);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => Algorithm.GetHashCode();
    }


    /// <summary>
    /// Provides human-readable names for <see cref="CanonicalizationAlgorithm"/> values.
    /// </summary>
    public static class CanonicalizationAlgorithmNames
    {
        /// <summary>
        /// Gets the name for the specified canonicalization algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to get the name for.</param>
        /// <returns>The human-readable name of the algorithm.</returns>
        public static string GetName(CanonicalizationAlgorithm algorithm) => GetName(algorithm.Algorithm);


        /// <summary>
        /// Gets the name for the specified algorithm code.
        /// </summary>
        /// <param name="algorithm">The algorithm code to get the name for.</param>
        /// <returns>The human-readable name of the algorithm.</returns>
        public static string GetName(int algorithm) => algorithm switch
        {
            var a when a == CanonicalizationAlgorithm.None.Algorithm => nameof(CanonicalizationAlgorithm.None),
            var a when a == CanonicalizationAlgorithm.Rdfc10.Algorithm => nameof(CanonicalizationAlgorithm.Rdfc10),
            var a when a == CanonicalizationAlgorithm.Jcs.Algorithm => nameof(CanonicalizationAlgorithm.Jcs),
            _ => $"Unknown ({algorithm})"
        };
    }
}