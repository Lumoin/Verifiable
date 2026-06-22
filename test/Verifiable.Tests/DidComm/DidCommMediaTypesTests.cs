using Verifiable.DidComm;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// The DIDComm media-type predicates, with emphasis on the RFC 7515 §4.1.9 / DIDComm v2.1 §Message Types
/// (L192) recipient MUST: "the recipient MUST treat media types not containing / as having the application/
/// prefix present." A conformant peer MAY emit the prefix-omitted <c>typ</c> (e.g. <c>didcomm-encrypted+json</c>),
/// so the consume-side predicates these <c>typ</c> checks gate on MUST accept it as the full media type.
/// </summary>
[TestClass]
internal sealed class DidCommMediaTypesTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Each predicate accepts both the full media type and its RFC 7515 §4.1.9 prefix-omitted form (and the
    /// match is case-insensitive per RFC 9110 §8.3.1).
    /// </summary>
    [TestMethod]
    [DataRow("application/didcomm-encrypted+json")]
    [DataRow("didcomm-encrypted+json")]
    [DataRow("DIDCOMM-ENCRYPTED+JSON")]
    [DataRow("application/DIDCOMM-encrypted+JSON")]
    public void IsEncrypted_AcceptsFullAndPrefixOmittedForms(string typ)
    {
        Assert.IsTrue(DidCommMediaTypes.IsEncrypted(typ),
            $"'{typ}' MUST be recognized as the encrypted media type (RFC 7515 §4.1.9 prefix-omission).");
    }


    /// <summary>The signed predicate likewise accepts the prefix-omitted form.</summary>
    [TestMethod]
    [DataRow("application/didcomm-signed+json")]
    [DataRow("didcomm-signed+json")]
    public void IsSigned_AcceptsFullAndPrefixOmittedForms(string typ)
    {
        Assert.IsTrue(DidCommMediaTypes.IsSigned(typ), $"'{typ}' MUST be recognized as the signed media type.");
    }


    /// <summary>The plaintext predicate likewise accepts the prefix-omitted form.</summary>
    [TestMethod]
    [DataRow("application/didcomm-plain+json")]
    [DataRow("didcomm-plain+json")]
    public void IsPlaintext_AcceptsFullAndPrefixOmittedForms(string typ)
    {
        Assert.IsTrue(DidCommMediaTypes.IsPlaintext(typ), $"'{typ}' MUST be recognized as the plaintext media type.");
    }


    /// <summary>
    /// Prefix restoration applies only to the absent prefix — it does not blur the three types into each
    /// other, and a non-matching value (with or without a slash) is still rejected.
    /// </summary>
    [TestMethod]
    [DataRow("didcomm-signed+json")]
    [DataRow("application/didcomm-plain+json")]
    [DataRow("didcomm/encrypted+json")]
    [DataRow("application/json")]
    [DataRow("")]
    [DataRow(null)]
    public void IsEncrypted_RejectsOtherMediaTypes(string? typ)
    {
        Assert.IsFalse(DidCommMediaTypes.IsEncrypted(typ), $"'{typ ?? "<null>"}' is not the encrypted media type.");
    }
}
