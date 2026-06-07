using System.Text;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Example-based tests for <see cref="JwkJsonReader.ExtractObjectAsString"/>.
/// </summary>
/// <remarks>
/// The helper slices the JSON text of an object-valued property — braces
/// included — out of a containing JSON blob. Designed for the OID4VP §5.10
/// wallet_metadata case where the Verifier needs the <c>jwks</c> sub-object
/// as a self-contained JWKS JSON string for <c>JwksEpkExtractor</c>.
/// </remarks>
[TestClass]
internal sealed class JwkJsonReaderObjectExtractionTests
{
    [TestMethod]
    public void ExtractObjectAsStringReturnsObjectWithOuterBraces()
    {
        string source = """{"a":1,"jwks":{"keys":[{"kty":"EC"}]},"z":"end"}""";
        string? extracted = JwkJsonReader.ExtractObjectAsString(
            Encoding.UTF8.GetBytes(source), "jwks"u8);

        Assert.AreEqual("""{"keys":[{"kty":"EC"}]}""", extracted);
    }


    [TestMethod]
    public void ExtractObjectAsStringHandlesNestedObjects()
    {
        string source =
            """{"outer":{"inner":{"deepest":"value"},"next":"more"},"after":1}""";
        string? extracted = JwkJsonReader.ExtractObjectAsString(
            Encoding.UTF8.GetBytes(source), "outer"u8);

        Assert.AreEqual(
            """{"inner":{"deepest":"value"},"next":"more"}""",
            extracted);
    }


    [TestMethod]
    public void ExtractObjectAsStringIgnoresBracesInsideStringValues()
    {
        //The } inside the string value must not close the outer object early.
        string source = """{"k":{"x":"has } brace","y":"and { another"}}""";
        string? extracted = JwkJsonReader.ExtractObjectAsString(
            Encoding.UTF8.GetBytes(source), "k"u8);

        Assert.AreEqual(
            """{"x":"has } brace","y":"and { another"}""",
            extracted);
    }


    [TestMethod]
    public void ExtractObjectAsStringHandlesWhitespaceAroundColon()
    {
        string source = """{"jwks"   :   {"keys":[]}}""";
        string? extracted = JwkJsonReader.ExtractObjectAsString(
            Encoding.UTF8.GetBytes(source), "jwks"u8);

        Assert.AreEqual("""{"keys":[]}""", extracted);
    }


    [TestMethod]
    public void ExtractObjectAsStringReturnsNullWhenKeyAbsent()
    {
        string source = """{"other":{"keys":[]}}""";
        string? extracted = JwkJsonReader.ExtractObjectAsString(
            Encoding.UTF8.GetBytes(source), "jwks"u8);

        Assert.IsNull(extracted);
    }


    [TestMethod]
    public void ExtractObjectAsStringReturnsNullWhenValueIsNotObject()
    {
        string source = """{"jwks":"not-an-object"}""";
        string? extracted = JwkJsonReader.ExtractObjectAsString(
            Encoding.UTF8.GetBytes(source), "jwks"u8);

        Assert.IsNull(extracted);
    }


    [TestMethod]
    public void ExtractObjectAsStringReturnsNullOnUnbalancedBraces()
    {
        string source = """{"jwks":{"keys":[{"kty":"EC"}]""";
        string? extracted = JwkJsonReader.ExtractObjectAsString(
            Encoding.UTF8.GetBytes(source), "jwks"u8);

        Assert.IsNull(extracted);
    }


    [TestMethod]
    public void ExtractObjectAsStringRoundtripsForJwksEpkExtractor()
    {
        //End-to-end shape used by the §5.10 path: wallet_metadata wrapping a
        //jwks object. Slicing yields a self-contained JWKS string that
        //JwksEpkExtractor.ExtractP256EncryptionKey can consume directly.
        string walletMetadata = """
            {"jwks":{"keys":[{"kty":"EC","crv":"P-256","use":"enc",
            "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]},
            "authorization_encrypted_response_enc":"A128GCM"}
            """;

        string? jwksJson = JwkJsonReader.ExtractObjectAsString(
            Encoding.UTF8.GetBytes(walletMetadata), "jwks"u8);

        Assert.IsNotNull(jwksJson);
        Assert.IsTrue(jwksJson.StartsWith('{') && jwksJson.EndsWith('}'),
            "Sliced JWKS must be a self-contained object.");
        Assert.Contains("\"keys\"", jwksJson, StringComparison.Ordinal);
    }


    [TestMethod]
    public void ExtractStringValueIgnoresStringValueEqualToKeyName()
    {
        //Regression: a string value that equals a later property's key name must
        //not shadow that key. Here an earlier property has value "x" and a later
        //property has key "x"; ExtractStringValue must skip the value-position
        //"x" and recover the real "x" property's value. This is the exact shape
        //CsCheck found for JwkJsonReaderWriterPropertyTests.MultiplePropertiesAllExtractCorrectly
        //(seed fQu3mkFiEUrk): IndexOfKey matched the value token because it did
        //not require key position (a following colon).
        string source = """{"a":"x","x":"MB7A5PFqW"}""";
        byte[] json = Encoding.UTF8.GetBytes(source);

        Assert.AreEqual("MB7A5PFqW", JwkJsonReader.ExtractStringValue(json, "x"u8),
            "The real \"x\" property must be recovered, not the earlier value \"x\".");
        Assert.AreEqual("x", JwkJsonReader.ExtractStringValue(json, "a"u8),
            "The earlier property whose value is \"x\" must still read correctly.");
        Assert.IsTrue(JwkJsonReader.ContainsKey(json, "x"u8),
            "ContainsKey must agree that key \"x\" is present.");
    }


    [TestMethod]
    public void ExtractStringValueDistinguishesKeyFromValueWhenValueOnlyMatch()
    {
        //A value equal to the searched key with no real key of that name present
        //must yield null, not the value token. {"a":"x"} has no key "x".
        byte[] json = Encoding.UTF8.GetBytes("""{"a":"x"}""");

        Assert.IsNull(JwkJsonReader.ExtractStringValue(json, "x"u8),
            "A value-position token must never be returned as if it were a key.");
        Assert.IsFalse(JwkJsonReader.ContainsKey(json, "x"u8),
            "ContainsKey must not report a value-position token as a present key.");
    }


    [TestMethod]
    public void ExtractNestedObjectPropertiesIgnoresBracesInsideStringValues()
    {
        //A string value containing a literal '}' must not bias the object-depth
        //counter in FindObjectContent — otherwise the inner object span is
        //truncated at the brace inside the string and the real properties after
        //it are lost. Reachable from SD-JWT VP verification, which parses
        //attacker-influenced payloads.
        byte[] json = Encoding.UTF8.GetBytes(
            """{"cnf":{"jwk":{"kty":"EC","note":"has } brace","crv":"P-256"}}}""");

        //Search keys stay u8 byte literals to match the span-based reader's idiom
        //(the real consumer SdJwtVpTokenVerification passes "cnf"u8/"jwk"u8; the
        //WellKnown* names are strings and would force an allocation here). The
        //dictionary-key assertions index a Dictionary<string,object>, so they use
        //the WellKnownJwkMemberNames constants.
        Dictionary<string, object>? inner =
            JwkJsonReader.ExtractNestedObjectProperties(json, "cnf"u8, "jwk"u8);

        Assert.IsNotNull(inner);
        Assert.AreEqual("EC", inner![WellKnownJwkMemberNames.Kty]);
        Assert.AreEqual("has } brace", inner["note"]);
        Assert.AreEqual("P-256", inner[WellKnownJwkMemberNames.Crv],
            "The property after the brace-bearing string value must survive — proving the " +
            "depth counter skipped the string content rather than closing the object early.");
    }


    [TestMethod]
    public void ExtractNestedObjectPropertiesHandlesEscapedQuoteThenBraceInValue()
    {
        //An escaped quote inside the value must not end string-skipping early,
        //and a following brace must still be ignored by the depth counter.
        byte[] json = Encoding.UTF8.GetBytes(
            """{"cnf":{"jwk":{"kty":"EC","note":"a \" then } brace","crv":"P-256"}}}""");

        Dictionary<string, object>? inner =
            JwkJsonReader.ExtractNestedObjectProperties(json, "cnf"u8, "jwk"u8);

        Assert.IsNotNull(inner);
        Assert.AreEqual("P-256", inner![WellKnownJwkMemberNames.Crv]);
    }
}
