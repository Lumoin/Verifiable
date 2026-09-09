using Verifiable.Core.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusListReference"/>.
/// </summary>
[TestClass]
internal sealed class StatusListReferenceTests
{
    /// <summary>
    /// Gets the index of the suspended credential used for testing purposes.
    /// </summary>
    private int SuspendedCredentialIndex { get; } = StatusListTestConstants.SuspendedCredentialIndex;
    
    /// <summary>
    /// Gets the example subject value used for token generation in test scenarios.
    /// </summary>
    private string ExampleTokenSubject { get; } = StatusListTestConstants.ExampleTokenSubject;
    
    /// <summary>
    /// Gets the subject identifier associated with the second token used in status list tests.
    /// </summary>
    private string SecondTokenSubject { get; } = StatusListTestConstants.SecondTokenSubject;


    [TestMethod]
    public void ConstructorSetsProperties()
    {
        var reference = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);

        Assert.AreEqual(SuspendedCredentialIndex, reference.Index);
        Assert.AreEqual(ExampleTokenSubject, reference.Uri);
    }


    [TestMethod]
    public void ConstructorThrowsForNegativeIndex()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new StatusListReference(-1, ExampleTokenSubject));
    }


    [TestMethod]
    public void ConstructorThrowsForNullUri()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new StatusListReference(0, null!));
    }


    [TestMethod]
    public void ConstructorThrowsForWhitespaceUri()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new StatusListReference(0, "   "));
    }


    /// <summary>
    /// Per Token Status List Section 6.2's uri claim, restated for Section 6.3's CBOR entry (same
    /// definition): "The value of uri MUST be a URI conforming to [RFC3986]." A relative reference has no
    /// scheme and therefore does not conform.
    /// </summary>
    [TestMethod]
    public void ConstructorThrowsForRelativeUri()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new StatusListReference(0, "/statuslists/1"));
    }


    /// <summary>
    /// Per Token Status List Section 6.2/6.3: "The value of uri MUST be a URI conforming to [RFC3986]." A
    /// scheme-less string such as a bare host and path is not an RFC 3986 URI.
    /// </summary>
    [TestMethod]
    public void ConstructorThrowsForSchemeLessUri()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new StatusListReference(0, "example.com/list"));
    }


    /// <summary>
    /// Per Token Status List Section 6.2/6.3: "The value of uri MUST be a URI conforming to [RFC3986]." An
    /// absolute https URI with an explicit scheme conforms.
    /// </summary>
    [TestMethod]
    public void ConstructorAcceptsAbsoluteHttpsUri()
    {
        var reference = new StatusListReference(0, "https://example.com/statuslists/1");

        Assert.AreEqual("https://example.com/statuslists/1", reference.Uri);
    }


    /// <summary>
    /// Per Token Status List Section 6.2/6.3: "The value of uri MUST be a URI conforming to [RFC3986]."
    /// RFC 3986 does not require an http(s) scheme; a urn: URI is an absolute URI with an explicit scheme
    /// and therefore conforms.
    /// </summary>
    [TestMethod]
    public void ConstructorAcceptsUrnUri()
    {
        var reference = new StatusListReference(0, "urn:example:statuslists:1");

        Assert.AreEqual("urn:example:statuslists:1", reference.Uri);
    }


    [TestMethod]
    public void EqualityForIdenticalReferences()
    {
        var a = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);
        var b = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);

        Assert.AreEqual(a, b);
        Assert.IsTrue(a == b);
    }


    [TestMethod]
    public void InequalityForDifferentIndex()
    {
        var a = new StatusListReference(0, ExampleTokenSubject);
        var b = new StatusListReference(1, ExampleTokenSubject);

        Assert.AreNotEqual(a, b);
        Assert.IsTrue(a != b);
    }


    [TestMethod]
    public void InequalityForDifferentUri()
    {
        var a = new StatusListReference(0, ExampleTokenSubject);
        var b = new StatusListReference(0, SecondTokenSubject);

        Assert.AreNotEqual(a, b);
    }


    [TestMethod]
    public void GetHashCodeConsistentForEqualReferences()
    {
        var a = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);
        var b = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);

        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
    }


    [TestMethod]
    public void ToStringContainsIndexAndUri()
    {
        var reference = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);
        string result = reference.ToString();

        Assert.Contains(SuspendedCredentialIndex.ToString(System.Globalization.CultureInfo.InvariantCulture), result, StringComparison.Ordinal);
        Assert.Contains(ExampleTokenSubject, result, StringComparison.Ordinal);
    }    
}
