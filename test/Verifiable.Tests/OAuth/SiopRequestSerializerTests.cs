using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Siop;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Direct tests for <see cref="SiopRequestSerializer"/> — the RP-side composition of
/// SIOPv2 §9 Authorization Requests and §7.5 RP metadata.
/// </summary>
[TestClass]
internal sealed class SiopRequestSerializerTests
{
    private const string ClientId = "https://client.example.org/cb";
    private const string Nonce = "n-0S6_WzA2Mj";

    private static readonly Uri RedirectUri = new("https://client.example.org/cb");


    [TestMethod]
    public void ComposesRequiredParametersInSpecOrder()
    {
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce
        };

        string query = SiopRequestSerializer.ToQueryString(request);

        Assert.StartsWith("response_type=id_token&", query);
        Assert.Contains($"client_id={Uri.EscapeDataString(ClientId)}", query);
        Assert.Contains($"redirect_uri={Uri.EscapeDataString(RedirectUri.OriginalString)}", query);
        Assert.Contains($"scope={WellKnownScopes.OpenId}", query);
        Assert.Contains($"nonce={Nonce}", query);
        Assert.DoesNotContain("id_token_type", query);
        Assert.DoesNotContain("client_metadata", query);
        Assert.DoesNotContain("state", query);
    }


    [TestMethod]
    public void ComposesOptionalParametersWhenSet()
    {
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce,
            IdTokenType = SiopIdTokenTypes.SubjectSignedIdToken,
            State = "af0ifjsldkj",
            ResponseMode = WellKnownResponseModes.DirectPost
        };

        string query = SiopRequestSerializer.ToQueryString(request);

        Assert.Contains($"id_token_type={SiopIdTokenTypes.SubjectSignedIdToken}", query);
        Assert.Contains("state=af0ifjsldkj", query);
        Assert.Contains($"response_mode={WellKnownResponseModes.DirectPost}", query);
    }


    [TestMethod]
    public void EmitsClientMetadataAsUrlEncodedJson()
    {
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce,
            ClientMetadata = new SiopRelyingPartyMetadata
            {
                SubjectSyntaxTypesSupported = [SiopSubjectSyntaxTypes.JwkThumbprint, "did:key"],
                IdTokenSignedResponseAlg = "ES256"
            }
        };

        string query = SiopRequestSerializer.ToQueryString(request);

        string marker = "client_metadata=";
        int start = query.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        int end = query.IndexOf('&', start);
        string encoded = end < 0 ? query[start..] : query[start..end];
        string json = Uri.UnescapeDataString(encoded);

        Assert.AreEqual(
            """{"subject_syntax_types_supported":["urn:ietf:params:oauth:jwk-thumbprint","did:key"],"id_token_signed_response_alg":"ES256"}""",
            json);
    }


    [TestMethod]
    public void RejectsClientMetadataTogetherWithClientMetadataUri()
    {
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce,
            ClientMetadata = new SiopRelyingPartyMetadata
            {
                SubjectSyntaxTypesSupported = [SiopSubjectSyntaxTypes.JwkThumbprint]
            },
            ClientMetadataUri = new Uri("https://client.example.org/metadata")
        };

        _ = Assert.ThrowsExactly<ArgumentException>(() => SiopRequestSerializer.ToQueryString(request));
    }


    [TestMethod]
    public void ComposesAuthorizationRequestLinkForCustomSchemeAndClaimedUrl()
    {
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce
        };

        string customSchemeLink = SiopRequestSerializer.ToAuthorizationRequestLink(
            SiopRequestSerializer.DefaultScheme, request);
        string claimedUrlLink = SiopRequestSerializer.ToAuthorizationRequestLink(
            "https://wallet.example.com/universal-link?session=abc", request);

        Assert.StartsWith("siopv2://?response_type=id_token&", customSchemeLink);
        Assert.StartsWith("https://wallet.example.com/universal-link?session=abc&response_type=id_token&", claimedUrlLink);
    }


    [TestMethod]
    public void SerializesRelyingPartyMetadataWithAdditionalParameters()
    {
        SiopRelyingPartyMetadata metadata = new()
        {
            SubjectSyntaxTypesSupported = ["did:example"],
            AdditionalParameters = new Dictionary<string, object>
            {
                ["logo_uri"] = "https://client.example.org/logo.png"
            }
        };

        string json = SiopRequestSerializer.ToJson(metadata);

        Assert.AreEqual(
            """{"subject_syntax_types_supported":["did:example"],"logo_uri":"https://client.example.org/logo.png"}""",
            json);
    }
}
