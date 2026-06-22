using System;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// The did:webvh <c>versionId</c> value: a version number, a literal dash, and the entryHash
/// (for example <c>1-QmRRaLXwc6BjBuBPosSupJwEQ8w9f3znP7yfbpGfwcnLr6</c>).
/// </summary>
/// <remarks>
/// The version number starts at 1 for the first entry and increments by one per entry; the entryHash is
/// the <c>base58btc(multihash(...))</c> hash that links the entry to its predecessor (did:webvh v1.0,
/// The DID Log File).
/// </remarks>
public static class WebVhVersionId
{
    /// <summary>
    /// Splits a <c>versionId</c> into its version number and entryHash.
    /// </summary>
    /// <param name="versionId">The <c>versionId</c> string.</param>
    /// <param name="versionNumber">The parsed version number when this returns <see langword="true"/>.</param>
    /// <param name="entryHash">The entryHash (the part after the first dash) when this returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="versionId"/> is a well-formed versionId; otherwise <see langword="false"/>.</returns>
    public static bool TryParse(string? versionId, out int versionNumber, out string entryHash)
    {
        versionNumber = 0;
        entryHash = string.Empty;

        if(string.IsNullOrEmpty(versionId))
        {
            return false;
        }

        int dashIndex = versionId.IndexOf('-', StringComparison.Ordinal);
        if(dashIndex <= 0 || dashIndex == versionId.Length - 1)
        {
            return false;
        }

        if(!int.TryParse(versionId.AsSpan(0, dashIndex), out int parsedNumber) || parsedNumber < 1)
        {
            return false;
        }

        versionNumber = parsedNumber;
        entryHash = versionId[(dashIndex + 1)..];

        return true;
    }
}
