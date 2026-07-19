using System.Linq;
using System.Text;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server.Pipeline;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Defect-taxonomy example-based tests for <see cref="ClientIdMetadataDocumentReader.Parse"/> —
/// draft-ietf-oauth-client-id-metadata-document-02 §4/§4.1/§8.6 (CIMD-013/019/021/022/023/028/058).
/// </summary>
[TestClass]
internal sealed class ClientIdMetadataDocumentReaderTests
{
    [TestMethod]
    public void ParseReturnsNoDefectsForValidFullDocument()
    {
        string document = """
            {
              "client_id": "https://client.example.com/app",
              "client_name": "Example Client",
              "client_uri": "https://client.example.com/",
              "logo_uri": "https://client.example.com/logo.png",
              "redirect_uris": ["https://client.example.com/cb"],
              "grant_types": ["authorization_code", "refresh_token"],
              "response_types": ["code"],
              "token_endpoint_auth_method": "private_key_jwt",
              "scope": "openid profile",
              "jwks": {"keys": [{"kty":"EC","crv":"P-256",
                "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]},
              "software_statement": "eyJhbGciOiJSUzI1NiJ9.payload.sig"
            }
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.AreEqual(ClientIdMetadataDocumentDefects.None, result.Defects);
        Assert.IsFalse(result.HasDefects);
        Assert.AreEqual("https://client.example.com/app", result.ClientId);
        Assert.IsNotNull(result.Metadata);
        Assert.AreEqual("Example Client", result.Metadata.ClientName);
        Assert.AreEqual(new Uri("https://client.example.com/"), result.Metadata.ClientUri);
        Assert.AreEqual(new Uri("https://client.example.com/logo.png"), result.Metadata.LogoUri);
        Assert.HasCount(1, result.Metadata.RedirectUris);
        Assert.AreEqual(new Uri("https://client.example.com/cb"), result.Metadata.RedirectUris[0]);
        Assert.HasCount(2, result.Metadata.GrantTypes);
        Assert.Contains(GrantType.AuthorizationCode, result.Metadata.GrantTypes);
        Assert.Contains(GrantType.RefreshToken, result.Metadata.GrantTypes);
        Assert.HasCount(1, result.Metadata.ResponseTypes);
        Assert.AreEqual(ResponseType.AuthorizationCode, result.Metadata.ResponseTypes[0]);
        Assert.AreEqual(ClientAuthenticationMethod.PrivateKeyJwt, result.Metadata.TokenEndpointAuthMethod!.Value);
        Assert.AreEqual("openid profile", result.Metadata.Scope);
        Assert.IsNotNull(result.Metadata.Jwks);
        Assert.Contains("\"keys\"", result.Metadata.Jwks, StringComparison.Ordinal);
        Assert.AreEqual("eyJhbGciOiJSUzI1NiJ9.payload.sig", result.Metadata.SoftwareStatement);
    }


    [TestMethod]
    public void ParseFlagsMissingClientId()
    {
        ClientIdMetadataDocumentReadResult result = Parse("""{"client_name":"No Id Client"}""");

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.MissingClientId));
        Assert.IsNull(result.ClientId);
    }


    [TestMethod]
    public void ParseFlagsClientSecretPresent()
    {
        string document = """
            {"client_id":"https://client.example.com/app","client_secret":"s3cr3t"}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.ClientSecretFieldsPresent));
    }


    [TestMethod]
    public void ParseFlagsClientSecretExpiresAtPresent()
    {
        string document = """
            {"client_id":"https://client.example.com/app","client_secret_expires_at":1735689600}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.ClientSecretFieldsPresent));
    }


    [TestMethod]
    [DataRow("client_secret_post")]
    [DataRow("client_secret_basic")]
    [DataRow("client_secret_jwt")]
    public void ParseFlagsEachSymmetricAuthMethod(string wireValue)
    {
        string document = $$"""
            {"client_id":"https://client.example.com/app","token_endpoint_auth_method":"{{wireValue}}"}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.SymmetricAuthMethod));
        Assert.IsNull(result.Metadata!.TokenEndpointAuthMethod);
    }


    [TestMethod]
    public void ParseFlagsUnknownAuthMethod()
    {
        string document = """
            {"client_id":"https://client.example.com/app","token_endpoint_auth_method":"quantum_signed_jwt"}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.UnknownAuthMethod));
        Assert.IsFalse(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.SymmetricAuthMethod));
        Assert.IsNull(result.Metadata!.TokenEndpointAuthMethod);
    }


    [TestMethod]
    [DataRow("none", 0)]
    [DataRow("private_key_jwt", 4)]
    [DataRow("tls_client_auth", 5)]
    [DataRow("self_signed_tls_client_auth", 6)]
    [DataRow("attest_jwt_client_auth", 7)]
    [DataRow("spiffe_jwt", 8)]
    public void ParseAcceptsKnownNonSymmetricAuthMethods(string wireValue, int expectedCode)
    {
        string document = $$"""
            {"client_id":"https://client.example.com/app","token_endpoint_auth_method":"{{wireValue}}"}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.AreEqual(ClientIdMetadataDocumentDefects.None, result.Defects);
        Assert.IsNotNull(result.Metadata!.TokenEndpointAuthMethod);
        Assert.AreEqual(expectedCode, result.Metadata.TokenEndpointAuthMethod!.Value.Code);
    }


    [TestMethod]
    public void ParseFlagsPrivateKeyMaterialForOctJwkWithK()
    {
        string document = """
            {"client_id":"https://client.example.com/app",
             "jwks":{"keys":[{"kty":"oct","k":"c2VjcmV0LXZhbHVl"}]}}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.PrivateKeyMaterialInJwks));
    }


    [TestMethod]
    public void ParseFlagsPrivateKeyMaterialForEcJwkWithD()
    {
        string document = """
            {"client_id":"https://client.example.com/app",
             "jwks":{"keys":[{"kty":"EC","crv":"P-256",
               "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
               "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
               "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}]}}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.PrivateKeyMaterialInJwks));
    }


    [TestMethod]
    public void ParseAcceptsPublicOnlyJwks()
    {
        string document = """
            {"client_id":"https://client.example.com/app",
             "jwks":{"keys":[{"kty":"EC","crv":"P-256",
               "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
               "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsFalse(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.PrivateKeyMaterialInJwks));
    }


    [TestMethod]
    public void ParseFlagsJavascriptSchemeJwksUri()
    {
        string document = """
            {"client_id":"https://client.example.com/app","jwks_uri":"javascript:alert(1)"}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.InvalidJwksUri));
        Assert.IsNull(result.Metadata!.JwksUri);
    }


    [TestMethod]
    public void ParseFlagsRelativeLogoUri()
    {
        string document = """
            {"client_id":"https://client.example.com/app","logo_uri":"/relative/logo.png"}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.InvalidLogoUri));
        Assert.IsNull(result.Metadata!.LogoUri);
    }


    [TestMethod]
    public void ParseFlagsNonHttpsClientUri()
    {
        string document = """
            {"client_id":"https://client.example.com/app","client_uri":"http://client.example.com/"}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.InvalidClientUri));
        Assert.IsNull(result.Metadata!.ClientUri);
    }


    [TestMethod]
    public void ParseFlagsUnparsableRedirectUriEntry()
    {
        string document = """
            {"client_id":"https://client.example.com/app",
             "redirect_uris":["https://client.example.com/cb","not-a-uri"]}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.InvalidRedirectUri));
        Assert.HasCount(1, result.Metadata!.RedirectUris);
        Assert.AreEqual(new Uri("https://client.example.com/cb"), result.Metadata.RedirectUris[0]);
    }


    [TestMethod]
    [DataRow("javascript:alert(document.cookie)")]
    [DataRow("data:text/html,<script>alert(1)</script>")]
    [DataRow("vbscript:msgbox(1)")]
    public void ParseFlagsDangerousSchemeRedirectUri(string dangerousRedirectUri)
    {
        string document = $$"""
            {"client_id":"https://client.example.com/app",
             "redirect_uris":["https://client.example.com/cb",{{System.Text.Json.JsonSerializer.Serialize(dangerousRedirectUri)}}]}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.InvalidRedirectUri));
        Assert.HasCount(1, result.Metadata!.RedirectUris);
        Assert.AreEqual(new Uri("https://client.example.com/cb"), result.Metadata.RedirectUris[0]);
    }


    [TestMethod]
    public void ParseAcceptsNativeCustomSchemeRedirectUri()
    {
        string document = """
            {"client_id":"https://client.example.com/app",
             "redirect_uris":["com.example.app:/oauth/callback"]}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsFalse(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.InvalidRedirectUri));
        Assert.HasCount(1, result.Metadata!.RedirectUris);
        Assert.AreEqual(new Uri("com.example.app:/oauth/callback"), result.Metadata.RedirectUris[0]);
    }


    [TestMethod]
    public void ParseCarriesSoftwareStatementAndLogoUriThrough()
    {
        string document = """
            {"client_id":"https://client.example.com/app",
             "logo_uri":"https://client.example.com/logo.png",
             "software_statement":"eyJhbGciOiJFUzI1NiJ9.claims.sig"}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.AreEqual(ClientIdMetadataDocumentDefects.None, result.Defects);
        Assert.AreEqual(new Uri("https://client.example.com/logo.png"), result.Metadata!.LogoUri);
        Assert.AreEqual("eyJhbGciOiJFUzI1NiJ9.claims.sig", result.Metadata.SoftwareStatement);
    }


    [TestMethod]
    public void ParseAccumulatesMultipleDefectsOnOneDocument()
    {
        string document = """
            {"client_secret":"s3cr3t","token_endpoint_auth_method":"client_secret_basic"}
            """;

        ClientIdMetadataDocumentReadResult result = Parse(document);

        Assert.IsTrue(result.HasDefects);
        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.MissingClientId));
        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.ClientSecretFieldsPresent));
        Assert.IsTrue(result.Defects.HasFlag(ClientIdMetadataDocumentDefects.SymmetricAuthMethod));
    }


    private static ClientIdMetadataDocumentReadResult Parse(string document) =>
        ClientIdMetadataDocumentReader.Parse(Encoding.UTF8.GetBytes(document));
}
