using Verifiable.DidComm;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Parse and rejection tests for <see cref="MessageTypeUri"/> against the MTURI grammar of
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#message-type-uri">DIDComm Messaging v2.1 §Message Type URI</see>.
/// </summary>
[TestClass]
internal sealed class MessageTypeUriTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The canonical <c>https://didcomm.org/routing/2.0/forward</c> MTURI decomposes into its four capture groups.</summary>
    [TestMethod]
    public void ParsesHttpsRoutingForward()
    {
        MessageTypeUri mturi = MessageTypeUri.Parse("https://didcomm.org/routing/2.0/forward");

        Assert.AreEqual("https://didcomm.org/", mturi.DocumentationUri);
        Assert.AreEqual("routing", mturi.ProtocolName);
        Assert.AreEqual("2.0", mturi.ProtocolVersion);
        Assert.AreEqual(2, mturi.MajorVersion);
        Assert.AreEqual(0, mturi.MinorVersion);
        Assert.AreEqual("forward", mturi.MessageTypeName);
    }


    /// <summary>The <c>did:example:1234567890;spec/lets_do_lunch/1.0/proposal</c> DID-rooted MTURI parses with the delimiter form.</summary>
    [TestMethod]
    public void ParsesDidRootedMturi()
    {
        MessageTypeUri mturi = MessageTypeUri.Parse("did:example:1234567890;spec/lets_do_lunch/1.0/proposal");

        Assert.AreEqual("did:example:1234567890;spec/", mturi.DocumentationUri);
        Assert.AreEqual("lets_do_lunch", mturi.ProtocolName);
        Assert.AreEqual("1.0", mturi.ProtocolVersion);
        Assert.AreEqual(1, mturi.MajorVersion);
        Assert.AreEqual(0, mturi.MinorVersion);
        Assert.AreEqual("proposal", mturi.MessageTypeName);
    }


    /// <summary>
    /// The <c>https://github.com/myorg/myproject/tree/master/docs/lets_do_lunch/1.0/proposal</c>
    /// form exercises the maximal trailing-identifier-run logic: the protocol name is the last
    /// identifier run before the version, and the multi-segment path is all documentation URI.
    /// </summary>
    [TestMethod]
    public void ParsesGithubTreePathMturi()
    {
        MessageTypeUri mturi = MessageTypeUri.Parse(
            "https://github.com/myorg/myproject/tree/master/docs/lets_do_lunch/1.0/proposal");

        Assert.AreEqual("https://github.com/myorg/myproject/tree/master/docs/", mturi.DocumentationUri);
        Assert.AreEqual("lets_do_lunch", mturi.ProtocolName);
        Assert.AreEqual("1.0", mturi.ProtocolVersion);
        Assert.AreEqual(1, mturi.MajorVersion);
        Assert.AreEqual(0, mturi.MinorVersion);
        Assert.AreEqual("proposal", mturi.MessageTypeName);
    }


    /// <summary>An MTURI with no version segment is malformed.</summary>
    [TestMethod]
    public void RejectsMissingVersionSegment()
    {
        Assert.IsFalse(MessageTypeUri.TryParse("https://didcomm.org/routing/forward", out _));
        Assert.ThrowsExactly<FormatException>(() => MessageTypeUri.Parse("https://didcomm.org/routing/forward"));
    }


    /// <summary>An MTURI whose version segment does not start with a digit is malformed.</summary>
    [TestMethod]
    public void RejectsVersionNotStartingWithDigit()
    {
        Assert.IsFalse(MessageTypeUri.TryParse("https://didcomm.org/routing/v2.0/forward", out _));
        Assert.ThrowsExactly<FormatException>(() => MessageTypeUri.Parse("https://didcomm.org/routing/v2.0/forward"));
    }


    /// <summary>An MTURI with a trailing slash has an empty message-type-name and is malformed.</summary>
    [TestMethod]
    public void RejectsTrailingSlash()
    {
        Assert.IsFalse(MessageTypeUri.TryParse("https://didcomm.org/routing/2.0/forward/", out _));
        Assert.ThrowsExactly<FormatException>(() => MessageTypeUri.Parse("https://didcomm.org/routing/2.0/forward/"));
    }


    /// <summary>The spec-mandated dispatch comparison treats an exact MTURI as the same message type.</summary>
    [TestMethod]
    public void IsSameMessageTypeMatchesExact()
    {
        MessageTypeUri forward = MessageTypeUri.Parse("https://didcomm.org/routing/2.0/forward");

        Assert.IsTrue(forward.IsSameMessageType("https://didcomm.org/routing/2.0/forward"));
    }


    /// <summary>
    /// The dispatch comparison ignores case and the identifier punctuation (<c>_</c>, <c>-</c>, <c>.</c>) in
    /// the protocol and message names (DIDComm v2.1 §Message Type URI: "compare the protocol name and message
    /// type name ignoring case and punctuation").
    /// </summary>
    [TestMethod]
    public void IsSameMessageTypeIgnoresCaseAndPunctuation()
    {
        MessageTypeUri problem = MessageTypeUri.Parse("https://didcomm.org/report-problem/2.0/problem-report");

        Assert.IsTrue(problem.IsSameMessageType("https://didcomm.org/ReportProblem/2.0/Problem_Report"));
    }


    /// <summary>
    /// A higher minor version under the same major is semver-compatible for dispatch (DIDComm v2.1 §Semver
    /// Rules: a minor increment only adds backward-compatible functionality), so a future <c>2.5</c> forward
    /// still dispatches to a <c>2.0</c> forward handler.
    /// </summary>
    [TestMethod]
    public void IsSameMessageTypeAllowsHigherMinorVersion()
    {
        MessageTypeUri forward = MessageTypeUri.Parse("https://didcomm.org/routing/2.0/forward");

        Assert.IsTrue(forward.IsSameMessageType("https://didcomm.org/routing/2.5/forward"));
    }


    /// <summary>A different major version is not semver-compatible — it does not dispatch (DIDComm v2.1 §Semver Rules).</summary>
    [TestMethod]
    public void IsSameMessageTypeRejectsDifferentMajorVersion()
    {
        MessageTypeUri forward = MessageTypeUri.Parse("https://didcomm.org/routing/2.0/forward");

        Assert.IsFalse(forward.IsSameMessageType("https://didcomm.org/routing/3.0/forward"));
    }


    /// <summary>A different message-type name is a different message type even within the same protocol version.</summary>
    [TestMethod]
    public void IsSameMessageTypeRejectsDifferentMessageName()
    {
        MessageTypeUri forward = MessageTypeUri.Parse("https://didcomm.org/routing/2.0/forward");

        Assert.IsFalse(forward.IsSameMessageType("https://didcomm.org/routing/2.0/forwarded"));
    }


    /// <summary>
    /// A same-named protocol message under a different documentation URI (a different protocol authority) does
    /// not collide — the dispatch match requires the documentation URI to agree.
    /// </summary>
    [TestMethod]
    public void IsSameMessageTypeRejectsDifferentDocumentationUri()
    {
        MessageTypeUri forward = MessageTypeUri.Parse("https://didcomm.org/routing/2.0/forward");

        Assert.IsFalse(forward.IsSameMessageType("https://evil.example/routing/2.0/forward"));
    }


    /// <summary>A value that is not a well-formed MTURI never matches.</summary>
    [TestMethod]
    public void IsSameMessageTypeRejectsMalformed()
    {
        MessageTypeUri forward = MessageTypeUri.Parse("https://didcomm.org/routing/2.0/forward");

        Assert.IsFalse(forward.IsSameMessageType("not-an-mturi"));
        Assert.IsFalse(forward.IsSameMessageType((string?)null));
    }


    /// <summary>
    /// The documentation URI (the protocol authority) is matched case-SENSITIVELY — the spec scopes
    /// case/punctuation insensitivity to the protocol-name and message-type-name tokens only, and a doc-uri
    /// may be a case-sensitive DID, so a case-variant authority does NOT match.
    /// </summary>
    [TestMethod]
    public void IsSameMessageTypeMatchesDocumentationUriCaseSensitively()
    {
        MessageTypeUri forward = MessageTypeUri.Parse("https://didcomm.org/routing/2.0/forward");

        Assert.IsFalse(forward.IsSameMessageType("https://DIDComm.org/routing/2.0/forward"));
    }
}
