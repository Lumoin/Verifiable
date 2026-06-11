using Verifiable.OAuth.Siop;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Characterization + override tests for <see cref="SiopProviderMetadataWriter"/> and the
/// <see cref="SiopProviderMetadata"/> static §15.1 / §6.1 documents — the Self-Issued
/// OpenID Provider Discovery Metadata a wallet (Self-Issued OP) advertises so an RP can
/// discover its capabilities per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-6.1">SIOPv2 §6.1</see>.
/// The first tests pin the exact mandated values of the §15.1 static-configuration sets so
/// an accidental change to a default breaks a test rather than silently shipping a
/// non-interoperable document. Every test asserts the §6.1 <c>jwks_uri</c> MUST NOT
/// invariant, the defining security property of a Self-Issued OP.
/// </summary>
[TestClass]
internal sealed class SiopProviderMetadataTests
{
    [TestMethod]
    public void StaticSiopv2DocumentCarriesTheExactSection1512MandatedValues()
    {
        string json = SiopProviderMetadataWriter.ToJson(SiopProviderMetadata.StaticSiopv2);

        //§15.1.2: "authorization_endpoint": "siopv2:".
        Assert.Contains("\"authorization_endpoint\":\"siopv2:\"", json, StringComparison.Ordinal);

        //§6.1: response_types_supported "MUST include id_token." §15.1.2 lists ["id_token"].
        Assert.Contains("\"response_types_supported\":[\"id_token\"]", json, StringComparison.Ordinal);

        //§6.1: scopes_supported "MUST support the openid scope value." §15.1.2 lists ["openid"].
        Assert.Contains("\"scopes_supported\":[\"openid\"]", json, StringComparison.Ordinal);

        //§6.1: subject_types_supported "Valid values include pairwise and public."
        //§15.1.2 lists ["pairwise"].
        Assert.Contains("\"subject_types_supported\":[\"pairwise\"]", json, StringComparison.Ordinal);

        //§15.1.2: id_token_signing_alg_values_supported ["ES256"].
        Assert.Contains("\"id_token_signing_alg_values_supported\":[\"ES256\"]", json, StringComparison.Ordinal);

        //§15.1.2: request_object_signing_alg_values_supported ["ES256"].
        Assert.Contains("\"request_object_signing_alg_values_supported\":[\"ES256\"]", json, StringComparison.Ordinal);

        //§6.1 / §15.1.2: subject_syntax_types_supported. "When Subject Syntax Type is JWK
        //Thumbprint, a valid value is urn:ietf:params:oauth:jwk-thumbprint defined in
        //[RFC9278]."
        Assert.Contains(
            "\"subject_syntax_types_supported\":[\"urn:ietf:params:oauth:jwk-thumbprint\"]",
            json, StringComparison.Ordinal);

        //§15.1.2: id_token_types_supported ["subject_signed_id_token"].
        Assert.Contains("\"id_token_types_supported\":[\"subject_signed_id_token\"]", json, StringComparison.Ordinal);

        //§15.1.2 omits issuer; the static set carries no Issuer Identifier.
        Assert.DoesNotContain("\"issuer\":", json, StringComparison.Ordinal,
            "The §15.1.2 static set omits the issuer member.");

        //§6.1: "jwks_uri parameter MUST NOT be present in Self-Issued OP Metadata."
        AssertNoJwksUri(json);
    }


    [TestMethod]
    public void StaticOpenIdDocumentCarriesTheExactSection1513MandatedValues()
    {
        string json = SiopProviderMetadataWriter.ToJson(SiopProviderMetadata.StaticOpenId);

        //§15.1.3: "authorization_endpoint": "openid:".
        Assert.Contains("\"authorization_endpoint\":\"openid:\"", json, StringComparison.Ordinal);

        //§15.1.3: response_types_supported ["vp_token","id_token"] — "used with both vp_token
        //and id_token as supported response_type".
        Assert.Contains("\"response_types_supported\":[\"vp_token\",\"id_token\"]", json, StringComparison.Ordinal);

        //§15.1.3: vp_formats_supported { "jwt_vp": { "alg": ["ES256"] }, "jwt_vc": { "alg":
        //["ES256"] } }.
        Assert.Contains(
            "\"vp_formats_supported\":{\"jwt_vp\":{\"alg\":[\"ES256\"]},\"jwt_vc\":{\"alg\":[\"ES256\"]}}",
            json, StringComparison.Ordinal);

        //§15.1.3 remaining mandated values, identical to §15.1.2.
        Assert.Contains("\"scopes_supported\":[\"openid\"]", json, StringComparison.Ordinal);
        Assert.Contains("\"subject_types_supported\":[\"pairwise\"]", json, StringComparison.Ordinal);
        Assert.Contains("\"id_token_signing_alg_values_supported\":[\"ES256\"]", json, StringComparison.Ordinal);
        Assert.Contains("\"request_object_signing_alg_values_supported\":[\"ES256\"]", json, StringComparison.Ordinal);
        Assert.Contains(
            "\"subject_syntax_types_supported\":[\"urn:ietf:params:oauth:jwk-thumbprint\"]",
            json, StringComparison.Ordinal);
        Assert.Contains("\"id_token_types_supported\":[\"subject_signed_id_token\"]", json, StringComparison.Ordinal);

        //§6.1: "jwks_uri parameter MUST NOT be present in Self-Issued OP Metadata."
        AssertNoJwksUri(json);
    }


    [TestMethod]
    public void DynamicDiscoveryDocumentCarriesTheIssuerAndOpChosenAlgsWithoutJwksUri()
    {
        //§6.1 non-normative example shape: an OP that supports ES256K + EdDSA and the
        //urn:ietf:params:oauth:jwk-thumbprint + did:key subject syntax types, advertised via
        //Dynamic Discovery with an https issuer and a claimed-URL authorization_endpoint.
        SiopProviderMetadata metadata = SiopProviderMetadata.Create(
            authorizationEndpoint: "https://wallet.example.com",
            issuer: "https://example.org",
            idTokenSigningAlgValuesSupported: ["ES256K", "EdDSA"],
            requestObjectSigningAlgValuesSupported: ["ES256K", "EdDSA"],
            subjectSyntaxTypesSupported:
            [
                SiopSubjectSyntaxTypes.JwkThumbprint,
                "did:key"
            ],
            idTokenTypesSupported: [SiopIdTokenTypes.SubjectSignedIdToken]);

        string json = SiopProviderMetadataWriter.ToJson(metadata);

        //§6.1: issuer "MUST be identical to the iss Claim value in ID Tokens issued from this
        //Self-Issued OP."
        Assert.Contains("\"issuer\":\"https://example.org\"", json, StringComparison.Ordinal);
        Assert.Contains("\"authorization_endpoint\":\"https://wallet.example.com\"", json, StringComparison.Ordinal);

        //§6.1: response_types_supported "MUST include id_token"; Create fills the mandated
        //default.
        Assert.Contains("\"response_types_supported\":[\"id_token\"]", json, StringComparison.Ordinal);

        //§6.1: scopes_supported "MUST support the openid scope value."
        Assert.Contains("\"scopes_supported\":[\"openid\"]", json, StringComparison.Ordinal);

        //§6.1: the OP-chosen signing algs flow through verbatim. "Valid values include RS256,
        //ES256, ES256K, and EdDSA."
        Assert.Contains("\"id_token_signing_alg_values_supported\":[\"ES256K\",\"EdDSA\"]", json, StringComparison.Ordinal);
        Assert.Contains("\"request_object_signing_alg_values_supported\":[\"ES256K\",\"EdDSA\"]", json, StringComparison.Ordinal);

        //§6.1: subject_syntax_types_supported with a JWK Thumbprint value and a did: method.
        Assert.Contains(
            "\"subject_syntax_types_supported\":[\"urn:ietf:params:oauth:jwk-thumbprint\",\"did:key\"]",
            json, StringComparison.Ordinal);

        //§6.1 default subject_types_supported when the caller omits it.
        Assert.Contains("\"subject_types_supported\":[\"public\"]", json, StringComparison.Ordinal);

        //§6.1: "jwks_uri parameter MUST NOT be present in Self-Issued OP Metadata. If it is,
        //the RP MUST ignore it and use the sub Claim in the ID Token to obtain signing keys."
        AssertNoJwksUri(json);
    }


    [TestMethod]
    public void OptionalIdTokenTypesSupportedMemberIsOmittedWhenUnset()
    {
        //§6.1: id_token_types_supported is OPTIONAL "the default value is
        //attester_signed_id_token" — omitting the member is the spec default, not an error.
        SiopProviderMetadata metadata = SiopProviderMetadata.Create(
            authorizationEndpoint: "openid-vc://",
            issuer: "https://wallet.lumoin.com",
            idTokenSigningAlgValuesSupported: ["ES256"],
            requestObjectSigningAlgValuesSupported: ["ES256"],
            subjectSyntaxTypesSupported: [SiopSubjectSyntaxTypes.JwkThumbprint]);

        string json = SiopProviderMetadataWriter.ToJson(metadata);

        Assert.DoesNotContain("\"id_token_types_supported\":", json, StringComparison.Ordinal,
            "id_token_types_supported is OPTIONAL and must be omitted when unset.");

        //The REQUIRED members are still present.
        Assert.Contains("\"issuer\":\"https://wallet.lumoin.com\"", json, StringComparison.Ordinal);
        Assert.Contains("\"authorization_endpoint\":\"openid-vc://\"", json, StringComparison.Ordinal);

        AssertNoJwksUri(json);
    }


    //§6.1 security invariant: "Note that contrary to [OpenID.Discovery], jwks_uri parameter
    //MUST NOT be present in Self-Issued OP Metadata." A Self-Issued OP has no fixed key set;
    //the signing key travels in the id_token's sub_jwk claim. The model has no jwks_uri
    //member at all, so the writer cannot emit one — this asserts the structural invariant
    //holds at the wire level.
    private static void AssertNoJwksUri(string json)
    {
        Assert.DoesNotContain("jwks_uri", json, StringComparison.Ordinal,
            "SIOPv2 §6.1: jwks_uri MUST NOT be present in Self-Issued OP Metadata.");
    }
}
