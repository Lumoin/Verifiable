using Verifiable.OAuth.Siop;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Direct tests for <see cref="SiopRequestValidation"/> — the Self-Issued OP (wallet)
/// validating the Relying Party's inbound Authorization Request per SIOPv2 §7.4
/// (Relying Party Metadata Error Response) and §10.3 (Self-Issued OP Error Response).
/// This is the mirror of <see cref="SelfIssuedIdTokenValidation"/>: where that primitive
/// has the RP validate the OP's id_token response, this one has the OP validate the RP's
/// request. Every negative case is a request a misconfigured or hostile RP could send,
/// and each test quotes the normative sentence it proves.
/// </summary>
[TestClass]
internal sealed class SiopRequestValidationTests
{
    private const string ClientId = "https://client.example.org/cb";
    private const string Nonce = "n-0S6_WzA2Mj";

    private static readonly Uri RedirectUri = new("https://client.example.org/cb");

    //The OP's own capabilities: the Subject Syntax Types it supports (its §6.1
    //subject_syntax_types_supported) and the ID Token signing algorithms it will honor
    //(its §6.1 id_token_signing_alg_values_supported).
    private static readonly string[] OpSupportedSubjectSyntaxTypes =
        [SiopSubjectSyntaxTypes.JwkThumbprint, "did:key"];

    private static readonly string[] OpSupportedSigningAlgValues = ["ES256", "EdDSA"];


    [TestMethod]
    public void AcceptsWellFormedRequestWithSupportedConsistentMetadata()
    {
        //§10.3: "A Self-Issued OpenID Provider Response is returned when Self-Issued OP
        //supports all Relying Party parameter values received from the Relying Party in
        //the client_metadata parameter." A non-pre-registered RP passing supported values
        //by value is accepted.
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce,
            ClientMetadata = new SiopRelyingPartyMetadata
            {
                SubjectSyntaxTypesSupported = [SiopSubjectSyntaxTypes.JwkThumbprint],
                IdTokenSignedResponseAlg = "ES256"
            }
        };

        SiopRequestValidationResult result = SiopRequestValidation.Validate(
            request,
            OpSupportedSubjectSyntaxTypes,
            OpSupportedSigningAlgValues,
            isClientPreRegistered: false,
            dereferencedClientMetadata: null);

        Assert.IsTrue(result.IsMetadataSourceConsistent);
        Assert.IsTrue(result.IsClientMetadataUriResolved);
        Assert.IsTrue(result.IsSubjectSyntaxSupported);
        Assert.IsTrue(result.AreClientMetadataValuesSupported);
        Assert.IsTrue(result.IsValid);
        Assert.IsNull(result.ErrorCode);
    }


    [TestMethod]
    public void AcceptsPreRegisteredClientWithNoJustInTimeMetadata()
    {
        //§7.4: "When the Self-Issued OP receives a Client ID of Section 7.2 that it has
        //cached following one of the methods defined in Section 7.2, it does not return
        //an error." A pre-registered Client ID with no client_metadata / client_metadata_uri
        //is consistent and the OP evaluates against its cached/registered metadata.
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce
        };

        SiopRequestValidationResult result = SiopRequestValidation.Validate(
            request,
            OpSupportedSubjectSyntaxTypes,
            OpSupportedSigningAlgValues,
            isClientPreRegistered: true,
            dereferencedClientMetadata: null);

        Assert.IsTrue(result.IsValid);
        Assert.IsNull(result.ErrorCode);
    }


    [TestMethod]
    public void RejectsRequestWhoseSubjectSyntaxTypesTheOpDoesNotSupport()
    {
        //§10.3 subject_syntax_types_not_supported: "the Self-Issued OP does not support
        //any of the Subject Syntax Types supported by the RP, which were communicated in
        //the request in the subject_syntax_types_supported parameter."
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce,
            ClientMetadata = new SiopRelyingPartyMetadata
            {
                SubjectSyntaxTypesSupported = ["did:example", "did:web"]
            }
        };

        SiopRequestValidationResult result = SiopRequestValidation.Validate(
            request,
            OpSupportedSubjectSyntaxTypes,
            OpSupportedSigningAlgValues,
            isClientPreRegistered: false,
            dereferencedClientMetadata: null);

        Assert.IsFalse(result.IsSubjectSyntaxSupported);
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SiopErrors.SubjectSyntaxTypesNotSupported, result.ErrorCode);
    }


    [TestMethod]
    public void RejectsRequestAskingForAnUnsupportedSigningAlgorithm()
    {
        //§10.3 client_metadata_value_not_supported: "the Self-Issued OP does not support
        //some Relying Party parameter values received in the request." The RP asks for an
        //id_token_signed_response_alg outside the OP's id_token_signing_alg_values_supported.
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce,
            ClientMetadata = new SiopRelyingPartyMetadata
            {
                SubjectSyntaxTypesSupported = [SiopSubjectSyntaxTypes.JwkThumbprint],
                IdTokenSignedResponseAlg = "RS256"
            }
        };

        SiopRequestValidationResult result = SiopRequestValidation.Validate(
            request,
            OpSupportedSubjectSyntaxTypes,
            OpSupportedSigningAlgValues,
            isClientPreRegistered: false,
            dereferencedClientMetadata: null);

        Assert.IsTrue(result.IsSubjectSyntaxSupported);
        Assert.IsFalse(result.AreClientMetadataValuesSupported);
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SiopErrors.ClientMetadataValueNotSupported, result.ErrorCode);
    }


    [TestMethod]
    public void RejectsPreRegisteredClientThatAlsoCarriesClientMetadata()
    {
        //§7.4: "Self-Issued OPs compliant with this specification MUST NOT proceed with
        //the transaction when pre-registered client metadata has been found based on the
        //Client ID, but client_metadata parameter has also been present."
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce,
            ClientMetadata = new SiopRelyingPartyMetadata
            {
                SubjectSyntaxTypesSupported = [SiopSubjectSyntaxTypes.JwkThumbprint]
            }
        };

        SiopRequestValidationResult result = SiopRequestValidation.Validate(
            request,
            OpSupportedSubjectSyntaxTypes,
            OpSupportedSigningAlgValues,
            isClientPreRegistered: true,
            dereferencedClientMetadata: null);

        Assert.IsFalse(result.IsMetadataSourceConsistent);
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SiopErrors.InvalidClientMetadataObject, result.ErrorCode);
    }


    [TestMethod]
    public void RejectsRequestCarryingBothClientMetadataAndClientMetadataUri()
    {
        //§9: "When request or request_uri parameters are NOT present, and RP is NOT using
        //OpenID Federation 1.0 Automatic Registration to pass entire RP metadata,
        //client_metadata or client_metadata_uri parameters MUST be present in the request.
        //client_metadata and client_metadata_uri are mutually exclusive."
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

        SiopRequestValidationResult result = SiopRequestValidation.Validate(
            request,
            OpSupportedSubjectSyntaxTypes,
            OpSupportedSigningAlgValues,
            isClientPreRegistered: false,
            dereferencedClientMetadata: SiopDereferencedClientMetadata.Resolved(
                new SiopRelyingPartyMetadata
                {
                    SubjectSyntaxTypesSupported = [SiopSubjectSyntaxTypes.JwkThumbprint]
                }));

        Assert.IsFalse(result.IsMetadataSourceConsistent);
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SiopErrors.InvalidClientMetadataObject, result.ErrorCode);
    }


    [TestMethod]
    public void RejectsRequestWhoseClientMetadataUriFailedToDereference()
    {
        //§10.3 invalid_client_metadata_uri: "the client_metadata_uri in the Authorization
        //Request returns an error or contains invalid data." The OP performed the
        //dereference outside this primitive and passes the failure in as data.
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce,
            ClientMetadataUri = new Uri("https://client.example.org/metadata")
        };

        SiopRequestValidationResult result = SiopRequestValidation.Validate(
            request,
            OpSupportedSubjectSyntaxTypes,
            OpSupportedSigningAlgValues,
            isClientPreRegistered: false,
            dereferencedClientMetadata: SiopDereferencedClientMetadata.Failed());

        Assert.IsTrue(result.IsMetadataSourceConsistent);
        Assert.IsFalse(result.IsClientMetadataUriResolved);
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SiopErrors.InvalidClientMetadataUri, result.ErrorCode);
    }


    [TestMethod]
    public void AcceptsRequestWhoseClientMetadataUriResolvedToSupportedMetadata()
    {
        //§7.3 / §10.3: when client_metadata_uri dereferences to a valid RP parameter
        //Object whose values the OP supports, the request is accepted exactly as the
        //by-value path. "A successful Authorization Response implicitly indicates that the
        //client metadata parameters were accepted." (§7.2)
        SiopRequest request = new()
        {
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            Nonce = Nonce,
            ClientMetadataUri = new Uri("https://client.example.org/metadata")
        };

        SiopRequestValidationResult result = SiopRequestValidation.Validate(
            request,
            OpSupportedSubjectSyntaxTypes,
            OpSupportedSigningAlgValues,
            isClientPreRegistered: false,
            dereferencedClientMetadata: SiopDereferencedClientMetadata.Resolved(
                new SiopRelyingPartyMetadata
                {
                    SubjectSyntaxTypesSupported = ["did:key"],
                    IdTokenSignedResponseAlg = "EdDSA"
                }));

        Assert.IsTrue(result.IsValid);
        Assert.IsNull(result.ErrorCode);
    }
}
