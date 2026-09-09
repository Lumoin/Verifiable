using System.IO;
using System.Text.RegularExpressions;
using Verifiable.Tests.Foundation;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Structural guard for the UTF-8-first well-known constant convention: every public static
/// <c>XUtf8</c> span property must sit beside a public static string member <c>X</c> that names the
/// identical text — either derived through <c>Utf8Constants.ToInternedString(XUtf8)</c> (the
/// correct-by-construction form most of this tree uses, which ties the string's content to the
/// span's own <c>u8</c> literal and interns it in one call) or, for a leaf whose own layering rule
/// forbids referencing the type <c>ToInternedString</c> would otherwise share a literal with,
/// independently restated as the identical string literal (compile-time string literals are
/// themselves always interned by the runtime, so this form loses no interning guarantee, only the
/// single-source-of-truth one <c>ToInternedString</c> gives) — so a second hand-written literal that
/// silently drifted from its span, or an orphaned <c>*Utf8</c> property with no string view at all,
/// cannot creep in unnoticed. Checked as a source scan over every <c>src/**</c> file, with no
/// reflection over any loaded assembly.
/// </summary>
[TestClass]
internal sealed class WellKnownUtf8ConstantTests
{
    /// <summary>Matches a public static UTF-8 source-literal span property's declaration line.</summary>
    private static Regex Utf8SpanPropertyPattern { get; } = new(
        @"public\s+static\s+ReadOnlySpan<byte>\s+(\w+)Utf8\s*=>\s*""((?:[^""\\]|\\.)*)""u8;",
        RegexOptions.Compiled);


    /// <summary>
    /// Every <c>XUtf8</c> span property declared anywhere under <c>src/**</c> has, in the same file, a
    /// public static string member <c>X</c> whose text agrees with the span's own <c>u8</c> literal —
    /// through the mandated <c>Utf8Constants.ToInternedString(XUtf8)</c> derivation, or, where that is
    /// unavailable, as the identical restated literal — proving the UTF-8 and string views cannot drift
    /// apart, without reading either member's runtime value.
    /// </summary>
    [TestMethod]
    public void EveryUtf8SpanPropertyMatchesItsStringMember()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();
        IReadOnlyList<string> files = SourceHygieneScanner.EnumerateSourceFilesUnder(repositoryRoot, "src");

        List<string> orphans = [];
        List<string> mismatches = [];
        int pairCount = 0;

        foreach(string filePath in files)
        {
            string text = File.ReadAllText(filePath);
            string relativePath = Path.GetRelativePath(repositoryRoot, filePath).Replace(Path.DirectorySeparatorChar, '/');

            foreach(Match spanMatch in Utf8SpanPropertyPattern.Matches(text))
            {
                string name = spanMatch.Groups[1].Value;
                string spanLiteral = spanMatch.Groups[2].Value;
                var siblingPattern = new Regex(
                    $@"public\s+static\s+(?:readonly\s+)?string\s+{Regex.Escape(name)}\s*(?:\{{\s*get;\s*\}}\s*=|=)\s*(?:Utf8Constants\.ToInternedString\({Regex.Escape(name)}Utf8\)|""((?:[^""\\]|\\.)*)"")\s*;");

                Match siblingMatch = siblingPattern.Match(text);
                if(!siblingMatch.Success)
                {
                    orphans.Add($"{relativePath}: {name}Utf8 has no string sibling {name} agreeing with it.");
                }
                else if(siblingMatch.Groups[1].Success && siblingMatch.Groups[1].Value != spanLiteral)
                {
                    mismatches.Add($"{relativePath}: {name} = \"{siblingMatch.Groups[1].Value}\" does not match {name}Utf8 = \"{spanLiteral}\".");
                }

                pairCount++;
            }
        }

        Assert.IsEmpty(orphans, string.Join(Environment.NewLine, orphans));
        Assert.IsEmpty(mismatches, string.Join(Environment.NewLine, mismatches));
        Assert.IsGreaterThanOrEqualTo(900, pairCount,
            "The sweep must discover the well-known constant surface; a collapse in pair count means the XUtf8 declaration shape changed.");
    }
}
