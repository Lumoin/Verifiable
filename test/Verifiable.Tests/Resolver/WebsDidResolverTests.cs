using System;
using Verifiable.Cesr;
using Verifiable.DidWebs;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebsDidResolver.Resolve"/> and <see cref="WebsDidResolver.ResolveKeriEventStreamUrl"/> —
/// the <c>did:webs</c> identifier to <c>did.json</c> / <c>keri.cesr</c> HTTPS URL transform, anchored on the
/// worked examples in the
/// <see href="https://trustoverip.github.io/kswg-did-method-webs-specification/#sample-didwebs-urls">
/// did:webs specification, Sample did:webs URLs</see>.
/// </summary>
[TestClass]
internal sealed class WebsDidResolverTests
{
    //The sample AID (a Blake3-256 KERI SAID) from the specification's worked Sample did:webs URLs.
    private const string Aid = "EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR";


    /// <summary>
    /// The DID-to-HTTPS transform maps the colon-delimited method-specific id (host, optional %3A-encoded port,
    /// optional path, trailing AID) to the <c>did.json</c> URL exactly as did:web does, always over <c>https</c>
    /// (did:webs Target System(s)).
    /// </summary>
    [TestMethod]
    [DataRow(
        "did:webs:w3c-ccg.github.io:" + Aid,
        "https://w3c-ccg.github.io/" + Aid + "/did.json")]
    [DataRow(
        "did:webs:w3c-ccg.github.io:user:alice:" + Aid,
        "https://w3c-ccg.github.io/user/alice/" + Aid + "/did.json")]
    [DataRow(
        "did:webs:example.com%3A3000:user:alice:" + Aid,
        "https://example.com:3000/user/alice/" + Aid + "/did.json")]
    public void ResolveDidDocumentUrlMatchesSpecificationExamples(string did, string expectedUrl)
    {
        Assert.AreEqual(expectedUrl, WebsDidResolver.Resolve(did));
    }


    /// <summary>
    /// The KERI event stream URL is the <c>did.json</c> URL with its trailing <c>/did.json</c> replaced by
    /// <c>/keri.cesr</c> (did:webs Target System(s)).
    /// </summary>
    [TestMethod]
    [DataRow(
        "did:webs:w3c-ccg.github.io:" + Aid,
        "https://w3c-ccg.github.io/" + Aid + "/keri.cesr")]
    [DataRow(
        "did:webs:w3c-ccg.github.io:user:alice:" + Aid,
        "https://w3c-ccg.github.io/user/alice/" + Aid + "/keri.cesr")]
    [DataRow(
        "did:webs:example.com%3A3000:user:alice:" + Aid,
        "https://example.com:3000/user/alice/" + Aid + "/keri.cesr")]
    public void ResolveKeriEventStreamUrlMatchesSpecificationExamples(string did, string expectedUrl)
    {
        Assert.AreEqual(expectedUrl, WebsDidResolver.ResolveKeriEventStreamUrl(did));
    }


    /// <summary>
    /// The did:webs transform is the did:web host and path transform: the host MUST be a domain name, so an
    /// IP-literal host is rejected; and a path segment MUST name a single component, so a dot-segment or an
    /// encoded path separator (<c>%2F</c>) — which would re-target the DID's location — is rejected. These guards
    /// are inherited from the shared did:web-family transform.
    /// </summary>
    [TestMethod]
    [DataRow("did:webs:127.0.0.1:" + Aid)]                    //IPv4-literal host.
    [DataRow("did:webs:127.0.0.1%3A3000:" + Aid)]            //IPv4-literal host with a %3A-encoded port.
    [DataRow("did:webs:192.168.1.1:user:" + Aid)]            //Private IPv4-literal host.
    [DataRow("did:webs:example.com:..:" + Aid)]              //Literal parent dot-segment (path traversal).
    [DataRow("did:webs:example.com:%2E%2E:" + Aid)]          //Percent-encoded parent dot-segment.
    [DataRow("did:webs:example.com:a%2Fb:" + Aid)]           //Segment carrying an encoded path separator.
    public void RejectsIpHostAndUnsafePathSegment(string did)
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebsDidResolver.Resolve(did));
    }


    /// <summary>
    /// The final path component MUST be a well-formed KERI SAID AID: a segment of the wrong length, a segment
    /// carrying a non-Base64URL character, or a segment whose CESR code is not a digest code (for example the
    /// Ed25519 verification-key code <c>D</c>) is not a did:webs AID (did:webs Method-Specific Identifier).
    /// </summary>
    [TestMethod]
    [DataRow("did:webs:example.com:not-a-said")]                                              //Not a CESR primitive shape at all.
    [DataRow("did:webs:example.com:EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jin")]              //Blake3-256 code but too short.
    [DataRow("did:webs:example.com:EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGRxx")]          //Blake3-256 code but too long.
    [DataRow("did:webs:example.com:DA_52v7lAkIJVUuruh40GvMsY3_K7J4-ZdVo7NoD2xzm")]            //A 44-char CESR primitive whose code is a verification key, not a digest.
    public void RejectsMalformedAid(string did)
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebsDidResolver.Resolve(did));
    }


    /// <summary>An AID with no host in front of it MUST be rejected: a did:webs always has a host and a path.</summary>
    [TestMethod]
    public void RejectsIdentifierWithoutHost()
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebsDidResolver.Resolve($"did:webs:{Aid}"));
    }


    /// <summary>An identifier of a different DID method MUST be rejected, including the closest cousins.</summary>
    [TestMethod]
    [DataRow("did:web:example.com:" + Aid)]
    [DataRow("did:webvh:example.com:" + Aid)]
    [DataRow("did:webplus:example.com:" + Aid)]
    public void RejectsNonWebsIdentifier(string did)
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebsDidResolver.Resolve(did));
    }


    /// <summary>A null, empty or whitespace identifier MUST be rejected.</summary>
    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    public void RejectsEmptyIdentifier(string did)
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebsDidResolver.Resolve(did));
    }


    /// <summary>
    /// A did:webs AID may use any of the nine KERI SAID digest codes the CESR master code table defines, not only
    /// the codes this build can currently compute a digest for: the identifier transform validates the AID by
    /// shape, so the method is algorithm-agile at the identifier layer (whether the KERI event stream's digest can
    /// then be verified is a separate, resolve-time concern).
    /// </summary>
    [TestMethod]
    [DataRow("E")]   //Blake3-256.
    [DataRow("F")]   //Blake2b-256.
    [DataRow("G")]   //Blake2s-256.
    [DataRow("H")]   //SHA3-256.
    [DataRow("I")]   //SHA2-256.
    [DataRow("0D")]  //Blake3-512.
    [DataRow("0E")]  //Blake2b-512.
    [DataRow("0F")]  //SHA3-512.
    [DataRow("0G")]  //SHA2-512.
    public void AcceptsEveryKeriSaidDigestCodeAid(string code)
    {
        //A shape-valid SAID for the code: the code followed by Base64URL padding to the code's full text size
        //(44 characters for a 256-bit digest, 88 for a 512-bit digest).
        int fullSize = code.Length == 1 ? 44 : 88;
        string aid = code + new string('A', fullSize - code.Length);

        Assert.AreEqual(
            $"https://example.com/{aid}/did.json",
            WebsDidResolver.Resolve($"did:webs:example.com:{aid}"),
            $"A did:webs AID using the '{code}' digest code must be accepted by the identifier transform.");
    }
}
