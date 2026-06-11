using System;
using System.Text;

namespace Verifiable.Cryptography.Text;

/// <summary>
/// The shared home of the UTF-8-first well-known constant convention. Well-known protocol
/// names declare their single source literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property
/// (<c>XUtf8 =&gt; "..."u8</c> — the bytes live in the binary's data section, no heap
/// allocation) and derive the string view from it through this class. This library is the
/// root of the project graph, so every constants-bearing project reaches the convention from
/// here.
/// </summary>
public static class Utf8Constants
{
    /// <summary>
    /// Derives the string view of a well-known UTF-8 source literal. The result is interned:
    /// string literals are interned by the runtime, decoded strings are not, so interning here
    /// keeps a derived constant reference-equal to every other constant and literal with the
    /// same text — the fast path canonicalization helpers such as
    /// <c>WellKnownJwtClaimNames.GetCanonicalizedValue</c> rely on.
    /// </summary>
    /// <param name="utf8SourceLiteral">The constant's UTF-8 source literal.</param>
    /// <returns>The interned string view of the literal.</returns>
    public static string ToInternedString(ReadOnlySpan<byte> utf8SourceLiteral) =>
        string.Intern(Encoding.UTF8.GetString(utf8SourceLiteral));
}
