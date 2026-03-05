using System;

namespace Verifiable.Core.Model.Did.Methods;

/// <summary>
/// Well-known DID method prefix constants and utility methods for prefix identification
/// and comparison.
/// </summary>
/// <remarks>
/// <para>
/// DID method prefixes are the standardized identifiers that appear at the beginning of
/// DID strings to indicate which DID method specification governs resolution and processing.
/// For example, <c>did:key</c> indicates the DID Key method, while <c>did:web</c> indicates
/// the DID Web method.
/// </para>
/// <para>
/// This class centralizes prefix definitions to ensure consistency across the library.
/// The comparison methods use culture-invariant string comparison for predictable behavior
/// across different locales.
/// </para>
/// <para>
/// During DID deserialization these prefixes are used to determine the appropriate concrete
/// DID method type to instantiate, enabling polymorphic handling of different DID methods
/// while maintaining type safety and performance.
/// </para>
/// </remarks>
public static class WellKnownDidMethodPrefixes
{
    /// <summary>The prefix for <see cref="KeyDidMethod"/>: <c>did:key</c>.</summary>
    public static string KeyDidMethodPrefix { get; } = "did:key";

    /// <summary>The prefix for <see cref="WebDidMethod"/>: <c>did:web</c>.</summary>
    public static string WebDidMethodPrefix { get; } = "did:web";

    /// <summary>The prefix for <see cref="EbsiDidMethod"/>: <c>did:ebsi</c>.</summary>
    public static string EbsiDidMethodPrefix { get; } = "did:ebsi";

    /// <summary>The prefix for <c>did:cheqd</c>.</summary>
    public static string CheqdDidMethodPrefix { get; } = "did:cheqd";

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="didPrefix"/> is <see cref="KeyDidMethodPrefix"/>.
    /// </summary>
    public static bool IsKeyDidPrefix(string didPrefix) => Equals(KeyDidMethodPrefix, didPrefix);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="didPrefix"/> is <see cref="WebDidMethodPrefix"/>.
    /// </summary>
    public static bool IsWebDidPrefix(string didPrefix) => Equals(WebDidMethodPrefix, didPrefix);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="didPrefix"/> is <see cref="EbsiDidMethodPrefix"/>.
    /// </summary>
    public static bool IsEbsiDidPrefix(string didPrefix) => Equals(EbsiDidMethodPrefix, didPrefix);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="didPrefix"/> is <see cref="CheqdDidMethodPrefix"/>.
    /// </summary>
    public static bool IsCheqdDidPrefix(string didPrefix) => Equals(CheqdDidMethodPrefix, didPrefix);

    /// <summary>
    /// Returns the equivalent interned instance for the given prefix, or the original string
    /// if no well-known prefix matches. This enables reference equality comparisons elsewhere.
    /// </summary>
    public static string GetCanonicalizedValue(string didPrefix) => didPrefix switch
    {
        string _ when IsKeyDidPrefix(didPrefix) => KeyDidMethodPrefix,
        string _ when IsWebDidPrefix(didPrefix) => WebDidMethodPrefix,
        string _ when IsEbsiDidPrefix(didPrefix) => EbsiDidMethodPrefix,
        string _ when IsCheqdDidPrefix(didPrefix) => CheqdDidMethodPrefix,
        _ => didPrefix
    };

    /// <summary>
    /// Returns <see langword="true"/> when the two prefixes are equal using
    /// culture-invariant comparison.
    /// </summary>
    public static bool Equals(string didPrefixA, string didPrefixB)
    {
        return ReferenceEquals(didPrefixA, didPrefixB)
            || StringComparer.InvariantCulture.Equals(didPrefixA, didPrefixB);
    }
}