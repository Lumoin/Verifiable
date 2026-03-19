using System.Text.RegularExpressions;

namespace Verifiable.Core.Validation;


/// <summary>
/// Provides compiled regular expressions for validating <c>did:key</c> identifiers.
/// </summary>
public static partial class KeyDidRegex
{
    /// <summary>
    /// Validates that the DID identifier conforms to the <c>did:key</c> method specification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The pattern matches: <c>did:key:z[Base58-BTC characters]+</c>
    /// </para>
    /// <para>
    /// The caret (<c>^</c>) and dollar (<c>$</c>) anchors ensure the entire string matches.
    /// </para>
    /// </remarks>
    /// <returns>A compiled regex for validating <c>did:key</c> identifiers.</returns>
    [GeneratedRegex("^did:key:z[a-km-zA-HJ-NP-Z1-9]+$")]
    public static partial Regex DidKeyIdentifier();


    /// <summary>
    /// Validates that the identifier with fragment conforms to the <c>did:key</c> method
    /// specification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The pattern matches: <c>did:key:z[Base58-BTC characters]+#[Base58-BTC characters]+</c>
    /// </para>
    /// </remarks>
    /// <returns>A compiled regex for validating <c>did:key</c> identifiers with fragments.</returns>
    [GeneratedRegex("^did:key:z[a-km-zA-HJ-NP-Z1-9]+\\#[a-km-zA-HJ-NP-Z1-9]+$")]
    public static partial Regex DidKeyIdentifierWithFragment();
}
