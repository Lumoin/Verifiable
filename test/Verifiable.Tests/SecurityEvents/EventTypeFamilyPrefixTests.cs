using System.IO;
using System.Text.RegularExpressions;
using Verifiable.Tests.Foundation;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// The event-type classes declare each member's full URI as its own UTF-8 source literal
/// while the family-membership predicates (<c>Is*EventType</c>) match on a shared prefix
/// constant. This sweep pins the two in coherence: every declared event-type URI must
/// carry its family's prefix, so a typo in either a member literal or the prefix is
/// caught structurally rather than by a downstream interop failure. Checked as a source
/// scan of each declaring file's own <c>XUtf8</c> literals against that file's own
/// <c>Prefix</c> constant, with no reflection over the loaded type.
/// </summary>
[TestClass]
internal sealed class EventTypeFamilyPrefixTests
{
    /// <summary>Matches a public static UTF-8 source-literal span property's declaration line.</summary>
    private static Regex Utf8SpanPropertyPattern { get; } = new(
        @"public\s+static\s+ReadOnlySpan<byte>\s+\w+Utf8\s*=>\s*""((?:[^""\\]|\\.)*)""u8;",
        RegexOptions.Compiled);

    /// <summary>Matches the family's shared prefix constant declaration.</summary>
    private static Regex PrefixConstantPattern { get; } = new(
        @"private\s+const\s+string\s+Prefix\s*=\s*""((?:[^""\\]|\\.)*)""\s*;",
        RegexOptions.Compiled);


    [TestMethod]
    public void EveryEventTypeUriCarriesItsFamilyPrefix()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertFamily(repositoryRoot, "src/Verifiable.Core/SecurityEvents/CaepEventTypes.cs", expectedMemberCount: 8);
        AssertFamily(repositoryRoot, "src/Verifiable.Core/SecurityEvents/RiscEventTypes.cs", expectedMemberCount: 14);
        AssertFamily(repositoryRoot, "src/Verifiable.Core/SecurityEvents/SsfEventTypes.cs", expectedMemberCount: 2);
    }


    /// <summary>
    /// Asserts that <paramref name="relativePath"/> declares exactly <paramref name="expectedMemberCount"/>
    /// <c>XUtf8</c> literals and that every one of them starts with that same file's own <c>Prefix</c>
    /// constant.
    /// </summary>
    /// <param name="repositoryRoot">The repository root <paramref name="relativePath"/> is relative to.</param>
    /// <param name="relativePath">The declaring file's repository-relative path.</param>
    /// <param name="expectedMemberCount">The spec catalogue's expected member count.</param>
    private static void AssertFamily(string repositoryRoot, string relativePath, int expectedMemberCount)
    {
        string text = File.ReadAllText(Path.Combine(repositoryRoot, relativePath));

        Match prefixMatch = PrefixConstantPattern.Match(text);
        Assert.IsTrue(prefixMatch.Success, $"{relativePath} must declare its family's Prefix constant.");
        string prefix = prefixMatch.Groups[1].Value;

        MatchCollection members = Utf8SpanPropertyPattern.Matches(text);
        Assert.HasCount(expectedMemberCount, members, $"{relativePath} must declare its spec catalogue of event-type URIs.");

        foreach(Match member in members)
        {
            string uri = member.Groups[1].Value;
            Assert.StartsWith(prefix, uri, StringComparison.Ordinal,
                $"{relativePath}: \"{uri}\" must carry the family prefix \"{prefix}\".");
        }
    }
}
