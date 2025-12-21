using System;
using System.Collections.Generic;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents the build state for constructing <c>did:web</c> DID documents with representation metadata.
    /// This state is passed between transformation functions during the fold/aggregate process
    /// and contains all the information needed to construct a <c>did:web</c> DID document.
    /// </summary>
    public struct WebDidBuildState: IEquatable<WebDidBuildState>, IBuilderState
    {
        /// <summary>
        /// Gets the web domain that forms the basis of the <c>did:web</c> identifier.
        /// </summary>
        public required string WebDomain { get; init; }

        /// <summary>
        /// Gets the collection of key material inputs for creating verification methods.
        /// </summary>
        public required IReadOnlyList<KeyMaterialInput> KeyInputs { get; init; }

        /// <summary>
        /// Gets the target representation type for the DID document.
        /// Determines context handling and serialization rules.
        /// </summary>
        public DidRepresentationType RepresentationType { get; init; }

        /// <summary>
        /// Gets the DID Core version to use for the context URI.
        /// </summary>
        public required string DidCoreVersion { get; init; }

        /// <summary>
        /// Gets the additional contexts to include in JSON-LD representation beyond the default DID context.
        /// Only used when RepresentationType includes context.
        /// </summary>
        public required string[] AdditionalContexts { get; init; }

        /// <summary>
        /// Gets or sets the current verification method index being processed.
        /// Used by fragment generators and other transformation logic to determine context.
        /// </summary>
        public int CurrentVerificationMethodIndex { get; set; }

        /// <summary>
        /// Determines whether two specified instances of <see cref="WebDidBuildState"/> are equal.
        /// </summary>
        public static bool operator ==(WebDidBuildState left, WebDidBuildState right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// Determines whether two specified instances of <see cref="WebDidBuildState"/> are not equal.
        /// </summary>
        public static bool operator !=(WebDidBuildState left, WebDidBuildState right)
        {
            return !left.Equals(right);
        }


        /// <summary>
        /// Determines whether the specified <see cref="WebDidBuildState"/> is equal to the current instance.
        /// </summary>
        public bool Equals(WebDidBuildState other)
        {
            return WebDomain == other.WebDomain
                && KeyInputs?.Count == other.KeyInputs?.Count
                && RepresentationType == other.RepresentationType
                && DidCoreVersion == other.DidCoreVersion
                && AdditionalContexts.AsSpan().SequenceEqual(other.AdditionalContexts.AsSpan())
                && CurrentVerificationMethodIndex == other.CurrentVerificationMethodIndex;
        }


        /// <summary>
        /// Determines whether the specified object is equal to the current instance.
        /// </summary>
        public override bool Equals(object? obj)
        {
            return obj is WebDidBuildState other && Equals(other);
        }


        /// <summary>
        /// Returns the hash code for this instance.
        /// </summary>
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(WebDomain);
            hash.Add(KeyInputs?.Count ?? 0);
            hash.Add(RepresentationType);
            hash.Add(DidCoreVersion);
            hash.Add(CurrentVerificationMethodIndex);

            foreach(string context in AdditionalContexts)
            {
                hash.Add(context);
            }

            return hash.ToHashCode();
        }
    }
}