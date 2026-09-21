using System.Text;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for <see cref="SdJwtIssuerHeader.TryReadKid"/> — the <c>kid</c> header read
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4">RFC 7515, Section 4.1.4</see>
/// defines, which SD-JWT VC draft-19 §4.2 RECOMMENDS the Issuer-signed JWT carry.
/// </summary>
[TestClass]
internal sealed class SdJwtIssuerHeaderKidTests
{
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>A header carrying a <c>kid</c> member reads it back exactly.</summary>
    [TestMethod]
    public void TryReadKidReturnsTrueAndTheValueWhenPresent()
    {
        string compactJws = BuildCompactJwsWithHeader("""{"alg":"ES256","kid":"issuer-key-1"}""");

        bool found = SdJwtIssuerHeader.TryReadKid(compactJws, TestSetup.Base64UrlDecoder, Pool, out string? kid);

        Assert.IsTrue(found);
        Assert.AreEqual("issuer-key-1", kid);
    }


    /// <summary>A header carrying no <c>kid</c> member reports <see langword="false"/> and a <see langword="null"/> value.</summary>
    [TestMethod]
    public void TryReadKidReturnsFalseWhenAbsent()
    {
        string compactJws = BuildCompactJwsWithHeader("""{"alg":"ES256"}""");

        bool found = SdJwtIssuerHeader.TryReadKid(compactJws, TestSetup.Base64UrlDecoder, Pool, out string? kid);

        Assert.IsFalse(found);
        Assert.IsNull(kid);
    }


    /// <summary>A compact JWS with no dot separator at all reports <see langword="false"/> rather than throwing.</summary>
    [TestMethod]
    public void TryReadKidReturnsFalseWhenNoDotSeparatorIsPresent()
    {
        bool found = SdJwtIssuerHeader.TryReadKid("no-dot-here", TestSetup.Base64UrlDecoder, Pool, out string? kid);

        Assert.IsFalse(found);
        Assert.IsNull(kid);
    }


    //Builds a syntactically valid three-segment compact JWS whose protected header is the
    //supplied JSON — the payload and signature segments are never read by TryReadKid, so they
    //are placeholders.
    private static string BuildCompactJwsWithHeader(string headerJson)
    {
        string headerSegment = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson));

        return $"{headerSegment}.cGF5bG9hZA.c2ln";
    }
}
