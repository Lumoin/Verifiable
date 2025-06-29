using System;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did.CryptographicSuites;

namespace Verifiable.Core.Builders
{
    /// <summary>
    /// Represents the build state for constructing <c>did:web</c> DID documents with representation metadata.
    /// This state is passed between transformation functions during the fold/aggregate process
    /// and contains all the information needed to construct a <c>did:web</c> DID document.
    /// </summary>
    public readonly struct WebDidBuildState : IEquatable<WebDidBuildState>
    {
        /// <summary>
        /// Gets the original public key material used to create this DID document.
        /// </summary>
        public PublicKeyMemory PublicKey { get; init; }

        /// <summary>
        /// Gets the cryptographic suite that determines how the public key is represented
        /// in the verification method of the DID document.
        /// </summary>
        public CryptographicSuite Suite { get; init; }

        /// <summary>
        /// Gets the web domain that forms the basis of the <c>did:web</c> identifier.
        /// </summary>
        public string WebDomain { get; init; }

        /// <summary>
        /// Gets the encoded key identifier used in verification method IDs and key references.
        /// </summary>
        public string EncodedKey { get; init; }

        /// <summary>
        /// Gets the target representation type for the DID document.
        /// Determines context handling and serialization rules.
        /// </summary>
        public DidRepresentationType RepresentationType { get; init; }

        /// <summary>
        /// Gets the DID Core version to use for the context URI.
        /// </summary>
        public string DidCoreVersion { get; init; }

        /// <summary>
        /// Gets the additional contexts to include in JSON-LD representation beyond the default DID context.
        /// Only used when RepresentationType includes context.
        /// </summary>
        public string[] AdditionalContexts { get; init; }


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
            return PublicKey.Equals(other.PublicKey)
                && Equals(Suite, other.Suite)
                && WebDomain == other.WebDomain
                && EncodedKey == other.EncodedKey
                && RepresentationType == other.RepresentationType
                && DidCoreVersion == other.DidCoreVersion
                && AdditionalContexts.AsSpan().SequenceEqual(other.AdditionalContexts.AsSpan());
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
            hash.Add(PublicKey);
            hash.Add(Suite);
            hash.Add(WebDomain);
            hash.Add(EncodedKey);
            hash.Add(RepresentationType);
            hash.Add(DidCoreVersion);

            foreach(string context in AdditionalContexts)
            {
                hash.Add(context);
            }

            return hash.ToHashCode();
        }
    }
}