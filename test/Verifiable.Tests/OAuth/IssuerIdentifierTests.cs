using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The public issuer grammar and ordinal identity used at registration and in metadata and
/// authorization-response validation. Every refusal leaves the accepted value absent.
/// </summary>
[TestClass]
internal sealed class IssuerIdentifierTests
{
    /// <summary>Null and empty spellings carry no issuer.</summary>
    /// <param name="issuer">The original spelling to refuse.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    public void ParseRefusesEmpty(string? issuer)
    {
        Result<IssuerIdentifier, IssuerIdentifierFault> parsed = IssuerIdentifier.Parse(issuer);

        Assert.IsFalse(parsed.IsSuccess);
        Assert.AreEqual(IssuerIdentifierFault.Empty, parsed.Error);
        Assert.IsNull(parsed.Value);
    }


    /// <summary>An issuer must first parse as an absolute URI.</summary>
    /// <param name="issuer">The original spelling to refuse.</param>
    [TestMethod]
    [DataRow("relative/issuer")]
    [DataRow("https://")]
    [DataRow("https://issuer.example:65536/")]
    public void ParseRefusesAbsoluteUri(string issuer)
    {
        Result<IssuerIdentifier, IssuerIdentifierFault> parsed = IssuerIdentifier.Parse(issuer);

        Assert.IsFalse(parsed.IsSuccess);
        Assert.AreEqual(IssuerIdentifierFault.AbsoluteUri, parsed.Error);
        Assert.IsNull(parsed.Value);
    }


    /// <summary>The original spelling must be well-formed before URI repairs.</summary>
    /// <param name="issuer">The original spelling to refuse.</param>
    [TestMethod]
    [DataRow("https://issuer.example/a b")]
    [DataRow("https://issuer.example/%GG")]
    [DataRow("https://issuer.example/a\\b")]
    [DataRow(" https://issuer.example/")]
    public void ParseRefusesOriginalSyntax(string issuer)
    {
        Result<IssuerIdentifier, IssuerIdentifierFault> parsed = IssuerIdentifier.Parse(issuer);

        Assert.IsFalse(parsed.IsSuccess);
        Assert.AreEqual(IssuerIdentifierFault.OriginalSyntax, parsed.Error);
        Assert.IsNull(parsed.Value);
    }


    /// <summary>RFC 8414 section 2 requires HTTPS.</summary>
    /// <param name="issuer">The original spelling to refuse.</param>
    [TestMethod]
    [DataRow("http://issuer.example/")]
    [DataRow("urn:example:issuer")]
    public void ParseRefusesScheme(string issuer)
    {
        Result<IssuerIdentifier, IssuerIdentifierFault> parsed = IssuerIdentifier.Parse(issuer);

        Assert.IsFalse(parsed.IsSuccess);
        Assert.AreEqual(IssuerIdentifierFault.Scheme, parsed.Error);
        Assert.IsNull(parsed.Value);
    }


    /// <summary>RFC 8414 section 2 forbids a query, including an empty one.</summary>
    /// <param name="issuer">The original spelling to refuse.</param>
    [TestMethod]
    [DataRow("https://issuer.example/?tenant=a")]
    [DataRow("https://issuer.example/?")]
    public void ParseRefusesQuery(string issuer)
    {
        Result<IssuerIdentifier, IssuerIdentifierFault> parsed = IssuerIdentifier.Parse(issuer);

        Assert.IsFalse(parsed.IsSuccess);
        Assert.AreEqual(IssuerIdentifierFault.Query, parsed.Error);
        Assert.IsNull(parsed.Value);
    }


    /// <summary>RFC 8414 section 2 forbids a fragment, including an empty one.</summary>
    /// <param name="issuer">The original spelling to refuse.</param>
    [TestMethod]
    [DataRow("https://issuer.example/#tenant")]
    [DataRow("https://issuer.example/#")]
    public void ParseRefusesFragment(string issuer)
    {
        Result<IssuerIdentifier, IssuerIdentifierFault> parsed = IssuerIdentifier.Parse(issuer);

        Assert.IsFalse(parsed.IsSuccess);
        Assert.AreEqual(IssuerIdentifierFault.Fragment, parsed.Error);
        Assert.IsNull(parsed.Value);
    }


    /// <summary>The key and string representation preserve every character accepted at ingress.</summary>
    /// <param name="issuer">The original spelling to retain.</param>
    [TestMethod]
    [DataRow("HTTPS://ISSUER.EXAMPLE:443/Tenant%2fA")]
    [DataRow("https://issuer.example")]
    [DataRow("https://issuer.example/")]
    [DataRow("https://issuer.example/a/../b")]
    [DataRow("https://issuer.example/%3F%23")]
    public void ParsePreservesOriginalSpellingAndComparisonKey(string issuer)
    {
        IssuerIdentifier accepted = ParseAccepted(issuer);

        Assert.AreEqual(issuer, accepted.OriginalString);
        Assert.AreEqual(issuer, accepted.ComparisonKey);
        Assert.AreEqual(issuer, accepted.ToString());
    }


    /// <summary>The existing issuer reader admits Unicode without folding or encoding its identity.</summary>
    [TestMethod]
    public void ParsePreservesUnicodeIssuerSpelling()
    {
        string original = "https://b" + char.ConvertFromUtf32(0x00FC)
            + "cher.example/" + char.ConvertFromUtf32(0x79DF);
        IssuerIdentifier accepted = ParseAccepted(original);

        Assert.AreEqual(original, accepted.OriginalString);
        Assert.AreEqual(original, accepted.ComparisonKey);
        Assert.AreNotEqual(ParseAccepted("https://xn--bcher-kva.example/%E7%A7%9F"), accepted);
    }


    /// <summary>Separately parsed identical keys select the same registered issuer in a hash set.</summary>
    [TestMethod]
    public void EqualityAndHashingUseOnlyTheComparisonKey()
    {
        IssuerIdentifier first = ParseAccepted("HTTPS://ISSUER.EXAMPLE:443/Tenant%2fA");
        IssuerIdentifier second = ParseAccepted("HTTPS://ISSUER.EXAMPLE:443/Tenant%2fA");
        HashSet<IssuerIdentifier> registered = [first];

        Assert.AreNotSame(first, second);
        Assert.AreEqual(first.ComparisonKey, second.ComparisonKey);
        Assert.AreEqual(first, second);
        Assert.IsTrue(first.Equals((object)second));
        Assert.IsTrue(first == second);
        Assert.IsFalse(first != second);
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode());
        Assert.IsFalse(registered.Add(second));
        Assert.HasCount(1, registered);
    }


    /// <summary>No URI canonicalization may broaden issuer identity beyond the ordinal key.</summary>
    /// <param name="firstSpelling">The registered issuer spelling.</param>
    /// <param name="secondSpelling">A distinct candidate spelling.</param>
    [TestMethod]
    [DataRow("HTTPS://issuer.example", "https://issuer.example")]
    [DataRow("https://ISSUER.EXAMPLE", "https://issuer.example")]
    [DataRow("https://issuer.example", "https://issuer.example:443")]
    [DataRow("https://issuer.example", "https://issuer.example/")]
    [DataRow("https://issuer.example/tenant", "https://issuer.example/tenant/child")]
    [DataRow("https://issuer.example/tenant", "https://issuer.example/tenant/")]
    [DataRow("https://issuer.example/Tenant", "https://issuer.example/tenant")]
    [DataRow("https://issuer.example/a/../b", "https://issuer.example/b")]
    [DataRow("https://issuer.example/%41", "https://issuer.example/A")]
    [DataRow("https://issuer.example/%2f", "https://issuer.example/%2F")]
    public void EqualityKeepsEverySpellingDifference(string firstSpelling, string secondSpelling)
    {
        IssuerIdentifier first = ParseAccepted(firstSpelling);
        IssuerIdentifier second = ParseAccepted(secondSpelling);
        HashSet<IssuerIdentifier> registered = [first];

        Assert.AreNotEqual(first.ComparisonKey, second.ComparisonKey);
        Assert.AreNotEqual(first, second);
        Assert.IsFalse(first.Equals((object)second));
        Assert.IsFalse(first == second);
        Assert.IsTrue(first != second);
        Assert.IsTrue(registered.Add(second));
        Assert.HasCount(2, registered);
    }


    /// <summary>A repaired URI must not pass metadata validation by matching its own malformed spelling.</summary>
    [TestMethod]
    public void MetadataMatchRefusesMalformedOriginalSpelling()
    {
        Uri issuer = new("https://issuer.example/a b");
        AuthorizationServerMetadata metadata = new() { Issuer = issuer };

        Assert.IsFalse(AuthorizationServerMetadataValidation.IsIssuerMatch(metadata, issuer));
    }


    /// <summary>A known issuer's malformed spelling must not pass the authorization-response gate.</summary>
    [TestMethod]
    public void AuthorizationResponseRefusesMalformedOriginalSpelling()
    {
        Uri issuer = new("https://issuer.example/a b");

        Assert.IsFalse(AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(
            issuer.OriginalString, issuer, static _ => true));
    }


    /// <summary>Reads an accepted fixture through the same public parser a host uses.</summary>
    /// <param name="issuer">The fixture's original spelling.</param>
    /// <returns>The accepted issuer.</returns>
    private static IssuerIdentifier ParseAccepted(string issuer)
    {
        Result<IssuerIdentifier, IssuerIdentifierFault> parsed = IssuerIdentifier.Parse(issuer);
        Assert.IsTrue(parsed.IsSuccess, $"Unexpected refusal: {parsed.Error}.");

        return parsed.Value;
    }
}
