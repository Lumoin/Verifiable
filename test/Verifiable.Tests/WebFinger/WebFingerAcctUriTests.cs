using System;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// Tests for <see cref="WebFingerClient.CreateAccountResource"/> — the library's default <c>acct:</c> query
/// target construction per <see href="https://www.rfc-editor.org/rfc/rfc7565">RFC 7565</see> ("The 'acct' URI
/// Scheme"), which the library's resource defaulting builds on. These are T5 of the conformance matrix.
/// </summary>
[TestClass]
internal sealed class WebFingerAcctUriTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// REF-1: the produced resource matches the
    /// <see href="https://www.rfc-editor.org/rfc/rfc7565#section-7">RFC 7565 §7</see> ABNF
    /// (<c>acctURI = "acct:" userpart "@" host</c>).
    /// </summary>
    [TestMethod]
    public void REF1_ProducesTheAcctSchemeWithUserPartAtHost()
    {
        Assert.AreEqual("acct:alice@example.com", WebFingerClient.CreateAccountResource("alice", "example.com"));
    }


    /// <summary>
    /// REF-1: the exact <see href="https://www.rfc-editor.org/rfc/rfc7565#section-4">§4</see> worked example
    /// round-trips through <see cref="WebFingerClient.CreateAccountResource"/>.
    /// </summary>
    [TestMethod]
    public void REF1_MatchesTheSection4WorkedExample()
    {
        string resource = WebFingerClient.CreateAccountResource("juliet@capulet.example", "shoppingsite.example");

        Assert.AreEqual("acct:juliet%40capulet.example@shoppingsite.example", resource);
    }


    /// <summary>
    /// REF-2: an <c>@</c> inside the user part is percent-encoded as <c>%40</c> so that the LAST (unencoded)
    /// <c>@</c> in the produced resource is the one delimiting the host — never one embedded in the user part.
    /// </summary>
    [TestMethod]
    public void REF2_AtSignInsideTheUserPartIsPercentEncodedSoTheLastAtDelimitsTheHost()
    {
        string resource = WebFingerClient.CreateAccountResource("alice@sub.example", "example.com");

        Assert.AreEqual("acct:alice%40sub.example@example.com", resource);

        int lastAt = resource.LastIndexOf('@');
        Assert.AreEqual("example.com", resource[(lastAt + 1)..], "The host is everything after the LAST @.");
        Assert.IsFalse(resource[..lastAt].Contains('@', StringComparison.Ordinal), "No raw @ may remain before the delimiting @.");
    }


    /// <summary>
    /// REF-3: the RFC 7565 §4 "compare via case + percent-encoding normalization (RFC 3986 §6.2.2.1/2)" MUST
    /// binds an application that NEEDS to compare two <c>acct:</c> URIs for equivalence.
    /// <see cref="Verifiable.WebFinger"/> performs NO such comparison — <c>WF-29</c> establishes that a
    /// resolved <c>subject</c> is preserved even when it differs from the requested resource — so the
    /// antecedent "if an application needs to compare" never applies here. This test documents that as
    /// vacuously not-applicable, per the RFC's own conditional wording, rather than exercising an unused
    /// comparison helper: it asserts the resolver does not reject a JRD whose <c>subject</c> is a case- and
    /// percent-encoding-different <c>acct:</c> URI from the requested resource.
    /// </summary>
    [TestMethod]
    public async Task REF3_ResolverDoesNotRejectAJrdWhoseSubjectDiffersFromTheResourceComparisonNeverApplies()
    {
        const string resource = "acct:alice@example.com";
        const string host = "example.com";
        const string queryUrl = "https://example.com/.well-known/webfinger?resource=acct%3Aalice%40example.com";

        //Deliberately a differently-cased, differently percent-encoded acct: URI from the requested resource —
        //the shape REF-3's comparison rule would govern IF this library ever compared subject to resource.
        const string jrdJson = """{"subject":"acct:Alice%40Example.COM@Example.com"}""";

        OutboundTransportDelegate transport = (request, context, cancellationToken) =>
        {
            int status = string.Equals(request.Target.AbsoluteUri, queryUrl, StringComparison.Ordinal) ? 200 : 404;
            TaggedMemory<byte> body = new(Encoding.UTF8.GetBytes(jrdJson), BufferTags.Json);

            return ValueTask.FromResult(new OutboundResponse { StatusCode = status, Body = body });
        };

        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);
        WebFingerResolveDelegate resolver = WebFingerClient.BuildResolving(transport, WebFingerJrdJsonParsing.ParseJrd);

        WebFingerResolutionResult result = await resolver(resource, host, [], context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, "REF-3's comparison rule never applies: a differing subject is not a rejection reason.");
        Assert.AreNotEqual(resource, result.Jrd!.Subject, "The fixture intentionally differs from the requested resource.");
    }
}
