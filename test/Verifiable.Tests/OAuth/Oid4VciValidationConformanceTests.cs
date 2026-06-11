using System.Text.Json;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OID4VCI 1.0 / RFC 6749 description charset conformance for the issuer-emitted
/// <c>error_description</c> (§8.3.1.2 Credential Error Response) and the consumed
/// <c>event_description</c> (§11.1 Notification), enforced by <see cref="ErrorDescriptionCharset"/>
/// and applied at the single error-body emission point in <see cref="ServerHttpResponse"/>.
/// </summary>
[TestClass]
internal sealed class Oid4VciValidationConformanceTests
{
    /// <summary>
    /// §8.3.1.2 / §11.1: "The values for the error_description parameter MUST NOT include characters
    /// outside the set %x20-21 / %x23-5B / %x5D-7E." A conformant value is returned unchanged; a
    /// value carrying the excluded <c>"</c> (0x22), <c>\</c> (0x5C), or a control character (0x0A)
    /// has those characters stripped.
    /// </summary>
    [TestMethod]
    public void SanitizeStripsCharactersOutsideTheAllowedSet()
    {
        const string conformant = "Could not store the Credential. Out of storage (code 42)!";
        Assert.IsTrue(ErrorDescriptionCharset.IsConformant(conformant));
        Assert.AreEqual(conformant, ErrorDescriptionCharset.Sanitize(conformant),
            "An already-conformant description is returned unchanged.");

        //0x22 ("), 0x5C (\), and 0x0A (control) are all outside %x20-21 / %x23-5B / %x5D-7E.
        const string withExcluded = "bad \" and \\ and \n here";
        Assert.IsFalse(ErrorDescriptionCharset.IsConformant(withExcluded));
        string sanitized = ErrorDescriptionCharset.Sanitize(withExcluded)!;
        Assert.AreEqual("bad  and  and  here", sanitized);
        Assert.IsTrue(ErrorDescriptionCharset.IsConformant(sanitized),
            "The sanitized value contains only allowed characters.");
    }


    /// <summary>
    /// §8.3.1.2: a Credential Error Response carrying an out-of-charset character in its
    /// <c>error_description</c> is sanitized on emit, so the emitted value conforms to
    /// %x20-21 / %x23-5B / %x5D-7E and the body remains well-formed JSON (the excluded
    /// <c>"</c>/<c>\</c> can no longer break the interpolated body).
    /// </summary>
    [TestMethod]
    public void EmittedErrorDescriptionIsSanitizedAndBodyStaysValidJson()
    {
        ServerHttpResponse response = ServerHttpResponse.BadRequest(
            "invalid_credential_request", "rejected \"quoted\" value\twith a tab");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        string emitted = doc.RootElement.GetProperty("error_description").GetString()!;

        Assert.AreEqual("rejected quoted valuewith a tab", emitted);
        Assert.IsTrue(ErrorDescriptionCharset.IsConformant(emitted),
            "§8.3.1.2: the emitted error_description MUST NOT include out-of-charset characters.");
    }
}
