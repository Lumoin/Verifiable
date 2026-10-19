using System.Text;
using Verifiable.JCose;
using Verifiable.OAuth;

namespace Verifiable.Tests.Jose;

/// <summary>
/// The library's one reading of a signed JWT's decoded parts (<see cref="JwtHeader.Read"/>, <see cref="JwtPayload.Read"/>), which
/// <see cref="JwsAccessTokenJsonParser.Default"/> composes for the access-token and ID Token validators: each part read once through
/// the strict judgement of a document a protocol reads as one JSON object, every member at every depth held as a claims set holds
/// it, and a document the judgement refuses answered with its typed refusal, never an exception.
/// </summary>
[TestClass]
internal sealed class JwtPartReadingTests
{
    /// <summary>
    /// An access token's header and claims read back as written: strings decoded once, a whole number as a long and a fraction
    /// as the decimal holding it exactly (RFC 7519 section 2: "non-integer values can be represented"), an array as a list, the
    /// <c>cnf</c> (RFC 7800 section 3) and the nested <c>act</c> chain (RFC 8693 section 4.1) as dictionaries, the literals as
    /// booleans, and a present <c>null</c> as a claim present with no value, never left out.
    /// </summary>
    [TestMethod]
    public void AnAccessTokensPartsReadBackAsWritten()
    {
        var header = Assert.IsInstanceOfType<JwtPartRead<JwtHeader>>(JwsAccessTokenJsonParser.Default.ParseHeader(
            Encoding.UTF8.GetBytes(/*lang=json,strict*/ """{"alg":"ES256","kid":"k1","typ":"at+jwt"}"""))).Part;

        var claims = Assert.IsInstanceOfType<JwtPartRead<JwtPayload>>(JwsAccessTokenJsonParser.Default.ParseClaims(
            Encoding.UTF8.GetBytes(/*lang=json,strict*/ """
                {"iss":"https://issuer.example","sub":"person","aud":["rs-1","rs-2"],"exp":1700003600,"iat":1700000000.25,
                 "cnf":{"jkt":"thumbprint"},"act":{"sub":"agent","act":{"sub":"earlier-agent"}},"consented":true,
                 "revoked":false,"nbf_note":null}
                """))).Part;

        Assert.AreEqual("ES256", header[WellKnownJoseHeaderNames.Alg]);
        Assert.AreEqual("k1", header[WellKnownJwkMemberNames.Kid], "A string is decoded once.");
        Assert.AreEqual("at+jwt", header[WellKnownJoseHeaderNames.Typ]);
        Assert.HasCount(3, header);

        Assert.AreEqual("person", claims[WellKnownJwtClaimNames.Sub]);
        Assert.AreSequenceEqual(new object[] { "rs-1", "rs-2" }, Assert.IsInstanceOfType<List<object>>(claims[WellKnownJwtClaimNames.Aud]));
        Assert.AreEqual(1700003600L, claims[WellKnownJwtClaimNames.Exp]);
        Assert.AreEqual(1700000000.25m, claims[WellKnownJwtClaimNames.Iat]);
        Assert.AreEqual("thumbprint", Assert.IsInstanceOfType<Dictionary<string, object>>(claims[WellKnownJwtClaimNames.Cnf])[WellKnownJwtClaimNames.JwkThumbprint]);

        var actor = Assert.IsInstanceOfType<Dictionary<string, object>>(claims[WellKnownJwtClaimNames.Act]);

        Assert.AreEqual("agent", actor[WellKnownJwtClaimNames.Sub]);
        Assert.AreEqual("earlier-agent", Assert.IsInstanceOfType<Dictionary<string, object>>(actor[WellKnownJwtClaimNames.Act])[WellKnownJwtClaimNames.Sub]);
        Assert.IsTrue(Assert.IsInstanceOfType<bool>(claims["consented"]), "The true literal is the boolean true.");
        Assert.IsFalse(Assert.IsInstanceOfType<bool>(claims["revoked"]), "The false literal is the boolean false.");
        Assert.IsTrue(claims.ContainsKey("nbf_note"), "A present null is a claim present, never one left out.");
        Assert.IsNull(claims["nbf_note"]);
        Assert.HasCount(10, claims);
    }


    /// <summary>
    /// A part the strict judgement refuses is answered with the refusal as the reader answered it: a member name repeated in the
    /// part's own object or in one nested within it (RFC 8259 section 4) names the name and the depth, a member naming no Unicode
    /// text (RFC 8259 section 8.2) names the member and its part, and a document that is no one JSON object is answered as such.
    /// </summary>
    /// <param name="json">The part's JSON text.</param>
    /// <param name="expectedName">The member the refusal names, or <see langword="null"/> for a document that is no object.</param>
    /// <param name="expectedDepth">The depth of the object the refusal names, or zero for a document that is no object.</param>
    [TestMethod]
    [DataRow(/*lang=json*/ """{"sub":"a","sub":"b"}""", "sub", 1, DisplayName = "A repeated claim")]
    [DataRow(/*lang=json*/ """{"cnf":{"jkt":"a","jkt":"b"}}""", "jkt", 2, DisplayName = "A member repeated in a nested object")]
    [DataRow(/*lang=json*/ """{"sub":"\uD800"}""", "sub", 1, DisplayName = "A claim naming no Unicode text")]
    [DataRow("""["sub"]""", null, 0, DisplayName = "An array")]
    [DataRow("""{"sub":"a"} {}""", null, 0, DisplayName = "A value followed by another")]
    public void APartTheJudgementRefusesIsAnsweredWithItsRefusal(string json, string? expectedName, int expectedDepth)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var payloadRefusal = Assert.IsInstanceOfType<JwtPartRefused<JwtPayload>>(JwtPayload.Read(bytes)).Refusal;
        var headerRefusal = Assert.IsInstanceOfType<JwtPartRefused<JwtHeader>>(JwtHeader.Read(bytes)).Refusal;

        Assert.AreEqual(payloadRefusal.GetType(), headerRefusal.GetType(), "Both parts are judged by the one judgement.");

        if(payloadRefusal is JsonRepeatedMemberName repeated)
        {
            Assert.AreEqual(expectedName, repeated.Name);
            Assert.AreEqual(expectedDepth, repeated.ObjectDepth);

            return;
        }

        if(payloadRefusal is JsonUndecodableMember undecodable)
        {
            Assert.AreEqual(expectedName, undecodable.Name);
            Assert.AreEqual(expectedDepth, undecodable.ObjectDepth);
            Assert.AreEqual(JsonUndecodableMemberPart.Value, undecodable.Part);

            return;
        }

        _ = Assert.IsInstanceOfType<JsonNotOneObject>(payloadRefusal);
        Assert.IsNull(expectedName);
    }
}
