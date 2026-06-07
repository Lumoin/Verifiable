using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Example-based tests for <see cref="WalletMetadataReader.ParseForJarEncryption"/>.
/// </summary>
/// <remarks>
/// Covers the wallet_metadata shapes the OID4VP 1.0 §5.10 verifier path
/// consumes: jwks present with/without enc, only enc, only jwks, neither,
/// malformed input.
/// </remarks>
[TestClass]
internal sealed class WalletMetadataReaderTests
{
    [TestMethod]
    public void ParseForJarEncryptionReturnsBothJwksAndEncWhenPresent()
    {
        string metadata = """
            {"jwks":{"keys":[{"kty":"EC","crv":"P-256","use":"enc",
            "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]},
            "authorization_encrypted_response_enc":"A256GCM"}
            """;

        (string? jwksJson, string? enc) =
            WalletMetadataReader.ParseForJarEncryption(metadata);

        Assert.IsNotNull(jwksJson);
        Assert.Contains("\"keys\"", jwksJson, StringComparison.Ordinal);
        Assert.AreEqual(WellKnownJweEncryptionAlgorithms.A256Gcm, enc);
    }


    [TestMethod]
    public void ParseForJarEncryptionReturnsJwksOnlyWhenEncAbsent()
    {
        string metadata = """{"jwks":{"keys":[]}}""";

        (string? jwksJson, string? enc) =
            WalletMetadataReader.ParseForJarEncryption(metadata);

        Assert.AreEqual("""{"keys":[]}""", jwksJson);
        Assert.IsNull(enc);
    }


    [TestMethod]
    public void ParseForJarEncryptionReturnsEncOnlyWhenJwksAbsent()
    {
        string metadata =
            """{"authorization_encrypted_response_enc":"A128GCM"}""";

        (string? jwksJson, string? enc) =
            WalletMetadataReader.ParseForJarEncryption(metadata);

        Assert.IsNull(jwksJson);
        Assert.AreEqual(WellKnownJweEncryptionAlgorithms.A128Gcm, enc);
    }


    [TestMethod]
    public void ParseForJarEncryptionReturnsNullsForUnrelatedMetadata()
    {
        //The Wallet might POST metadata that says nothing about JAR
        //encryption — only signing algorithms, formats, etc. Both slots
        //must come back null so the verifier serves a plain signed JAR.
        string metadata = """
            {"authorization_endpoint":"openid4vp://",
            "vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}}}
            """;

        (string? jwksJson, string? enc) =
            WalletMetadataReader.ParseForJarEncryption(metadata);

        Assert.IsNull(jwksJson);
        Assert.IsNull(enc);
    }


    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("   ")]
    public void ParseForJarEncryptionReturnsNullsForEmptyInput(string? input)
    {
        (string? jwksJson, string? enc) =
            WalletMetadataReader.ParseForJarEncryption(input);

        Assert.IsNull(jwksJson);
        Assert.IsNull(enc);
    }


    [TestMethod]
    public void ParseForJarEncryptionToleratesMalformedJwksWithoutThrowing()
    {
        //Unbalanced braces inside the jwks object value: the opening { for
        //jwks never closes. Parser must return null rather than throwing —
        //the verifier surfaces a structural problem only when the JWKS is
        //actually used, not at the metadata-parsing layer.
        string metadata =
            "{\"jwks\":{\"keys\":[{\"kty\":\"EC\",\"x\":\"...\",\"y\":\"...\"}]" +
            ",\"authorization_encrypted_response_enc\":\"A128GCM\"";

        (string? jwksJson, string? enc) =
            WalletMetadataReader.ParseForJarEncryption(metadata);

        Assert.IsNull(jwksJson);
    }


    [TestMethod]
    public void ParseForJarEncryptionHandlesUnicodeWhitespace()
    {
        //Standard JSON whitespace around the colon and after the key must
        //not break extraction.
        string metadata = "{\"jwks\" :\n\t{\"keys\":[]} }";

        (string? jwksJson, string? enc) =
            WalletMetadataReader.ParseForJarEncryption(metadata);

        Assert.AreEqual("""{"keys":[]}""", jwksJson);
        Assert.IsNull(enc);
    }


    [TestMethod]
    public void ParseClientIdPrefixesSupportedReturnsAdvertisedPrefixes()
    {
        string metadata = """
            {"client_id_prefixes_supported":["redirect_uri","x509_san_dns","verifier_attestation"]}
            """;

        List<string>? schemes =
            WalletMetadataReader.ParseClientIdPrefixesSupported(metadata);

        Assert.IsNotNull(schemes);
        Assert.HasCount(3, schemes);
        Assert.Contains("redirect_uri", schemes, StringComparer.Ordinal);
        Assert.Contains("x509_san_dns", schemes, StringComparer.Ordinal);
        Assert.Contains("verifier_attestation", schemes, StringComparer.Ordinal);
    }


    [TestMethod]
    public void ParseClientIdPrefixesSupportedReturnsEmptyForEmptyArray()
    {
        List<string>? schemes =
            WalletMetadataReader.ParseClientIdPrefixesSupported(
                """{"client_id_prefixes_supported":[]}""");

        Assert.IsNotNull(schemes);
        Assert.HasCount(0, schemes);
    }


    [TestMethod]
    public void ParseClientIdPrefixesSupportedReturnsNullWhenAbsent()
    {
        Assert.IsNull(WalletMetadataReader.ParseClientIdPrefixesSupported("{}"));
    }


    [TestMethod]
    public void ParseRequestObjectSigningAlgValuesSupportedReturnsAdvertisedAlgs()
    {
        string metadata = """
            {"request_object_signing_alg_values_supported":["ES256","EdDSA"]}
            """;

        List<string>? algs =
            WalletMetadataReader.ParseRequestObjectSigningAlgValuesSupported(metadata);

        Assert.IsNotNull(algs);
        Assert.HasCount(2, algs);
        Assert.Contains(WellKnownJwaValues.Es256, algs, StringComparer.Ordinal);
        Assert.Contains(WellKnownJwaValues.EdDsa, algs, StringComparer.Ordinal);
    }


    [TestMethod]
    public void ParseAuthorizationEndpointReadsCustomScheme()
    {
        string metadata = """
            {"authorization_endpoint":"openid4vp://"}
            """;

        string? endpoint = WalletMetadataReader.ParseAuthorizationEndpoint(metadata);

        Assert.AreEqual("openid4vp://", endpoint);
    }


    [TestMethod]
    public void ParseVpFormatsSupportedJsonReturnsNestedObjectAsText()
    {
        string metadata = """
            {"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}}}
            """;

        string? formatsJson = WalletMetadataReader.ParseVpFormatsSupportedJson(metadata);

        Assert.IsNotNull(formatsJson);
        Assert.Contains("dc+sd-jwt", formatsJson, StringComparison.Ordinal);
        Assert.Contains("sd-jwt_alg_values", formatsJson, StringComparison.Ordinal);
        Assert.IsTrue(formatsJson.StartsWith('{') && formatsJson.EndsWith('}'),
            "Returned vp_formats_supported text must be a self-contained JSON object.");
    }


    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("   ")]
    public void AdditionalReadersAllReturnNullForEmptyInput(string? input)
    {
        Assert.IsNull(WalletMetadataReader.ParseClientIdPrefixesSupported(input));
        Assert.IsNull(WalletMetadataReader.ParseRequestObjectSigningAlgValuesSupported(input));
        Assert.IsNull(WalletMetadataReader.ParseAuthorizationEndpoint(input));
        Assert.IsNull(WalletMetadataReader.ParseVpFormatsSupportedJson(input));
    }
}
