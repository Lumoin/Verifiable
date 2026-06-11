using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Verifiable.OAuth;

/// <summary>
/// Length-independent equality for credential-bearing values. An ordinal comparison
/// exits on the first differing element, which lets a network attacker measure how
/// much of a guessed secret matched and recover it incrementally. These comparisons
/// take time dependent only on the input lengths — the length itself is not treated
/// as secret, so differing lengths return <see langword="false"/> immediately.
/// </summary>
public static class FixedTimeComparison
{
    /// <summary>
    /// Compares two strings in fixed time over their UTF-16 code units.
    /// </summary>
    /// <param name="left">The first value.</param>
    /// <param name="right">The second value.</param>
    /// <returns><see langword="true"/> when both are <see langword="null"/> or ordinally equal.</returns>
    public static bool AreEqual(string? left, string? right)
    {
        if(left is null || right is null)
        {
            return ReferenceEquals(left, right);
        }

        return CryptographicOperations.FixedTimeEquals(
            MemoryMarshal.AsBytes(left.AsSpan()),
            MemoryMarshal.AsBytes(right.AsSpan()));
    }
}
