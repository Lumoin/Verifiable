using System;

namespace Verifiable.Core.Model.Did.Methods
{
    /// <summary>
    /// Provides well-known DID method prefixes and utility methods for DID method identification and comparison.
    /// This class contains the standard prefixes for supported DID methods and helper functions for
    /// efficient prefix matching during DID parsing and deserialization operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// DID method prefixes are the standardized identifiers that appear at the beginning of DID strings
    /// to indicate which DID method specification should be used for resolution and processing.
    /// For example, <c>did:key</c> indicates the DID Key method, while <c>did:web</c> indicates the DID Web method.
    /// </para>
    /// <para>
    /// This class centralizes prefix definitions to ensure consistency across the library and provides
    /// utility methods for fast prefix comparison and canonicalization. The comparison methods use
    /// culture-invariant string comparison for predictable behavior across different locales.
    /// </para>
    /// <para>
    /// During DID deserialization, these prefixes are used to determine the appropriate concrete
    /// DID method type to instantiate, enabling polymorphic handling of different DID methods
    /// while maintaining type safety and performance.
    /// </para>
    /// </remarks>
    public static class WellKnownDidMethodPrefixes
    {
        /// <summary>
        /// The prefix of <see cref="KeyDidMethod"/> method.
        /// </summary>
        public static string KeyDidMethodPrefix { get; } = "did:key";

        /// <summary>
        /// The prefix of <see cref="WebDidMethod"/> method.
        /// </summary>
        public static string WebDidMethodPrefix { get; } = "did:web";

        /// <summary>
        /// The prefix of <see cref="EbsiDidMethod"/> method.
        /// </summary>
        public static string EbsiDidMethodPrefix { get; } = "did:ebsi";


        /// If <paramref name="didPrefix"/> is <see cref="EbsiDidMethodPrefix"/> or not.
        /// </summary>
        /// <param name="didPrefix">The did method prefix.</param>.
        /// <returns><see langword="true" /> if  <paramref name="didPrefix"/> is <see cref="KeyDidMethodPrefix"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEbsiDidPrefix(string didPrefix) => Equals(EbsiDidMethodPrefix, didPrefix);


        /// <summary>
        /// If <paramref name="didPrefix"/> is <see cref="KeyDidMethodPrefix"/> or not.
        /// </summary>
        /// <param name="didPrefix">The did method prefix.</param>.
        /// <returns><see langword="true" /> if  <paramref name="didPrefix"/> is <see cref="KeyDidMethodPrefix"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsKeyDidPrefix(string didPrefix) => Equals(KeyDidMethodPrefix, didPrefix);


        /// If <paramref name="didPrefix"/> is <see cref="WebDidMethodPrefix"/> or not.
        /// </summary>
        /// <param name="didPrefix">The did method prefix.</param>.
        /// <returns><see langword="true" /> if  <paramref name="didPrefix"/> is <see cref="KeyDidMethodPrefix"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsWebDidPrefix(string didPrefix) => Equals(WebDidMethodPrefix, didPrefix);



        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="didPrefix">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="didPrefix"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string didPrefix) => didPrefix switch
        {
            string _ when IsEbsiDidPrefix(didPrefix) => EbsiDidMethodPrefix,
            string _ when IsKeyDidPrefix(didPrefix) => KeyDidMethodPrefix,
            string _ when IsWebDidPrefix(didPrefix) => WebDidMethodPrefix,
            string _ => didPrefix
        };


        /// <summary>
        /// Returns a value that indicates if the DID method prefixes are the same.
        /// </summary>
        /// <param name="didPrefixA">The first DID method prefix to compare.</param>
        /// <param name="didPrefixB">The second DID method prefix to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the <paramref name="didPrefixA"/> and <paramref name="didPrefixB"/> are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string didPrefixA, string didPrefixB)
        {
            return ReferenceEquals(didPrefixA, didPrefixB) || StringComparer.InvariantCulture.Equals(didPrefixA, didPrefixB);
        }
    }
}
