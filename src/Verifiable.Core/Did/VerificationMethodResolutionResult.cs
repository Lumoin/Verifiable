using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;


namespace Verifiable.Core.Did
{
    /// <summary>
    /// Delegate for resolving external DID references that cannot be resolved locally.
    /// The resolver implementation can use any strategy such as HTTP requests, IPFS, blockchain lookups,
    /// caching layers, or combinations thereof.
    /// </summary>
    /// <param name="didReference">The DID reference to resolve (e.g., "did:example:123#key-1").</param>
    /// <returns>A task that resolves to the verification method if found, or null if not found or resolution failed.</returns>
    /// <remarks>
    /// This delegate abstracts away the implementation details of how external DID documents are retrieved.
    /// The resolver is responsible for parsing the DID reference, fetching the appropriate DID document,
    /// and extracting the referenced verification method.
    /// </remarks>
    public delegate ValueTask<VerificationMethod?> ExternalVerificationMethodResolver(string didReference);


    /// <summary>
    /// Represents the result of attempting to resolve a verification method reference.
    /// This structure provides complete transparency about whether resolution succeeded,
    /// whether the method was found locally or externally, and what the original reference was.
    /// </summary>
    public readonly struct VerificationMethodResolutionResult: IEquatable<VerificationMethodResolutionResult>
    {
        /// <summary>
        /// The resolved verification method, or null if resolution failed.
        /// </summary>
        public VerificationMethod? Method { get; }

        /// <summary>
        /// The original reference that was being resolved. Only populated for unresolved results.
        /// </summary>
        public string? Reference { get; }

        /// <summary>
        /// Indicates whether the verification method was successfully resolved.
        /// </summary>
        public bool IsResolved { get; }

        /// <summary>
        /// Indicates whether the resolution was performed locally (within the same DID document)
        /// or required external resolution. Only meaningful when IsResolved is true.
        /// </summary>
        public bool IsLocal { get; }


        /// <summary>
        /// Private constructor for creating resolution results.
        /// </summary>
        /// <param name="method">The resolved verification method.</param>
        /// <param name="reference">The original reference being resolved.</param>
        /// <param name="isResolved">Whether resolution succeeded.</param>
        /// <param name="isLocal">Whether resolution was local or external.</param>
        private VerificationMethodResolutionResult(VerificationMethod? method, string? reference, bool isResolved, bool isLocal)
        {
            Method = method;
            Reference = reference;
            IsResolved = isResolved;
            IsLocal = isLocal;
        }


        /// <summary>
        /// Creates a result indicating successful resolution of a verification method.
        /// </summary>
        /// <param name="method">The successfully resolved verification method.</param>
        /// <param name="isLocal">Whether the resolution was performed locally or externally.</param>
        /// <returns>A resolution result indicating success.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="method"/> is null.</exception>
        public static VerificationMethodResolutionResult Resolved(VerificationMethod method, bool isLocal = true)
        {
            ArgumentNullException.ThrowIfNull(method, nameof(method));

            return new VerificationMethodResolutionResult(method, null, true, isLocal);
        }


        /// <summary>
        /// Creates a result indicating failed resolution of a verification method reference.
        /// </summary>
        /// <param name="reference">The reference that could not be resolved.</param>
        /// <returns>A resolution result indicating failure.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="reference"/> is null or whitespace.</exception>
        public static VerificationMethodResolutionResult Unresolved(string reference)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(reference, nameof(reference));

            return new VerificationMethodResolutionResult(null, reference, false, false);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(VerificationMethodResolutionResult other)
        {
            return Method == other.Method
                && Reference == other.Reference
                && IsResolved == other.IsResolved
                && IsLocal == other.IsLocal;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? o) => o is VerificationMethodResolutionResult result && Equals(result);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in VerificationMethodResolutionResult result1, in VerificationMethodResolutionResult result2) => result1.Equals(result2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in VerificationMethodResolutionResult result1, in VerificationMethodResolutionResult result2) => !result1.Equals(result2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in object result1, in VerificationMethodResolutionResult result2) => result1 is VerificationMethodResolutionResult r && r.Equals(result2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in VerificationMethodResolutionResult result1, in object result2) => result2 is VerificationMethodResolutionResult r && result1.Equals(r);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in object result1, in VerificationMethodResolutionResult result2) => !(result1 == result2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in VerificationMethodResolutionResult result1, in object result2) => !(result1 == result2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Method);
            hash.Add(Reference);
            hash.Add(IsResolved);
            hash.Add(IsLocal);

            return hash.ToHashCode();
        }
    }
}