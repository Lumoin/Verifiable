using System.Text.Json;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Dcql;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// Conformance tests for the W3C VCALM 1.0 §3.4 verifiable presentation request (VPR) model, its
/// strict STJ parser, and the §3.4.5-grouped holder-side evaluation
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>). A VPR is the payload a verifier sends a holder inside a §3.6 exchange; these
/// tests exercise the parse + holder "what can I present" computation in process, the surface the
/// §3.6 exchange engine consumes. The same refusals and holder evaluations are driven over the real
/// HTTPS wire by <see cref="VcalmExchangeEndpointTests"/>.
/// </summary>
[TestClass]
internal sealed class VerifiablePresentationRequestTests
{
    /// <summary>The MSTest context of the running test.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The serializer options carrying the DCQL converters the parser deserializes a DCQL entry with.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>The examples context the test credentials carry beside the base context.</summary>
    private const string AlumniContext = "https://www.w3.org/ns/credentials/examples/v2";

    /// <summary>The credential type the Query By Example tests request.</summary>
    private const string AlumniCredentialType = "ExampleAlumniCredential";

    /// <summary>The issuer of the test credentials.</summary>
    private const string AuthorityIssuer = "did:web:authority.example";

    /// <summary>An issuer that is not the test credentials' issuer.</summary>
    private const string OtherIssuer = "did:web:other.example";

    /// <summary>The URL of the Recognized Entities list the specification's own <c>recognizedIn</c> example points to.</summary>
    private const string RecognizedListUrl = "https://url.example/list.vc";

    /// <summary>The DID methods the DID Authentication parse test expects.</summary>
    private static string[] KeyAndWebMethods { get; } = ["key", "web"];

    /// <summary>The allowed actions the authorization capability parse test expects.</summary>
    private static string[] ReadAndWriteActions { get; } = ["read", "write"];

    /// <summary>The cryptosuites the bare-string Query By Example test expects, a bare string first and an object second.</summary>
    private static string[] MixedCryptosuites { get; } = ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"];

    /// <summary>The envelope media types the bare-string Query By Example test expects, a bare string first and an object second.</summary>
    private static string[] MixedEnvelopes { get; } = ["application/jwt", "application/vc+sd-jwt"];

    /// <summary>The single DID method the method-specific-properties test expects.</summary>
    private static string[] WebMethod { get; } = ["web"];

    /// <summary>The single cryptosuite the cryptosuite-specific-properties test expects.</summary>
    private static string[] EcdsaRdfcCryptosuite { get; } = ["ecdsa-rdfc-2019"];


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: "The
    /// credentialQuery property in a QueryByExample query is a single object", supporting "reason",
    /// "example" ("An OPTIONAL object that provides an example of the credential being requested,
    /// including its @context, type, and optionally credentialSubject fields to indicate which claims are
    /// needed"), "acceptedIssuers" and "acceptedCryptosuites". A request carrying each of them, as the
    /// clause's own example does, parses with every member in the model.
    /// </summary>
    [TestMethod]
    public void ParsesQueryByExampleWithExampleIssuersAndCryptosuites()
    {
        const string json = """
        {
            "query": [{
                "type": "QueryByExample",
                "credentialQuery": {
                    "reason": "We need to know if you are an alumni of this school.",
                    "example": {
                        "@context": [
                            "https://www.w3.org/ns/credentials/v2",
                            "https://www.w3.org/ns/credentials/examples/v2"
                        ],
                        "type": "ExampleAlumniCredential",
                        "credentialSubject": { "type": "Alumni" }
                    },
                    "acceptedIssuers": [{ "id": "did:web:authority.example" }],
                    "acceptedCryptosuites": [
                        { "cryptosuite": "ecdsa-sd-2023" },
                        { "cryptosuite": "bbs-2023" }
                    ]
                }
            }],
            "challenge": "3182bdea-63d9-11ea-b6de-3b7c1404d57f",
            "domain": "reunion.example"
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        Assert.AreEqual("reunion.example", request.Domain);
        Assert.AreEqual("3182bdea-63d9-11ea-b6de-3b7c1404d57f", request.Challenge);
        Assert.HasCount(1, request.Query);

        QueryByExampleQuery qbe = Assert.IsInstanceOfType<QueryByExampleQuery>(request.Query[0]);
        Assert.AreEqual(VcalmQueryTypes.QueryByExample, qbe.Type);
        Assert.AreEqual("We need to know if you are an alumni of this school.", qbe.CredentialQuery.Reason);

        Assert.IsNotNull(qbe.CredentialQuery.Example);
        QueryByExampleCredential example = qbe.CredentialQuery.Example;
        Assert.Contains(AlumniCredentialType, example.Types);
        Assert.Contains(Context.Credentials20, example.Context);
        Assert.AreEqual("Alumni", example.SubjectFields["type"]);

        Assert.HasCount(1, qbe.CredentialQuery.AcceptedIssuers);
        Assert.AreEqual(AuthorityIssuer, qbe.CredentialQuery.AcceptedIssuers[0].Id);
        Assert.Contains("ecdsa-sd-2023", qbe.CredentialQuery.AcceptedCryptosuites);
        Assert.Contains("bbs-2023", qbe.CredentialQuery.AcceptedCryptosuites);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedIssuers</c> is "An OPTIONAL array of items, or lists that contain items", and its
    /// "Valid example values include: did:web:red-issuer.example https://blue-issuer.example/ {"id":
    /// "did:web:green-issuer.example"} {"recognizedIn": {"id": "https://url.example/list.vc", "type":
    /// "RecognizedEntityCredential"}}". Every example value parses, word for word, together with a list
    /// that contains items; each item of the list joins the accepted issuers, and the parser leaves the
    /// recognizedIn item's recognized issuers empty, since the request carries only the list's URL.
    /// </summary>
    [TestMethod]
    public void ParsesAcceptedIssuerShapes()
    {
        const string json = """
        {
            "query": [{
                "type": "QueryByExample",
                "credentialQuery": {
                    "acceptedIssuers": [
                        "did:web:red-issuer.example",
                        "https://blue-issuer.example/",
                        {"id": "did:web:green-issuer.example"},
                        {"recognizedIn": {"id": "https://url.example/list.vc", "type": "RecognizedEntityCredential"}},
                        ["did:web:listed-issuer.example", {"id": "https://listed-issuer.example/"}]
                    ]
                }
            }]
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        QueryByExampleQuery qbe = Assert.IsInstanceOfType<QueryByExampleQuery>(request.Query[0]);
        Assert.HasCount(6, qbe.CredentialQuery.AcceptedIssuers);
        Assert.AreEqual("did:web:red-issuer.example", qbe.CredentialQuery.AcceptedIssuers[0].Id);
        Assert.AreEqual("https://blue-issuer.example/", qbe.CredentialQuery.AcceptedIssuers[1].Id);
        Assert.AreEqual("did:web:green-issuer.example", qbe.CredentialQuery.AcceptedIssuers[2].Id);
        Assert.IsNull(qbe.CredentialQuery.AcceptedIssuers[3].Id);
        Assert.AreEqual(RecognizedListUrl, qbe.CredentialQuery.AcceptedIssuers[3].RecognizedInId);
        Assert.IsEmpty(qbe.CredentialQuery.AcceptedIssuers[3].RecognizedIssuerIds);
        Assert.AreEqual("did:web:listed-issuer.example", qbe.CredentialQuery.AcceptedIssuers[4].Id);
        Assert.AreEqual("https://listed-issuer.example/", qbe.CredentialQuery.AcceptedIssuers[5].Id);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedIssuers</c> is "An OPTIONAL array of items, or lists that contain items", and "Each
    /// item MUST be either 1) a [URL] that identifies an issuer in the issuer property of the received
    /// verifiable credential, or 2) an object that contains an id property whose value is a [URL] that
    /// identifies an issuer in the issuer property of the received verifiable credential, or 3) an
    /// object that contains a recognizedIn property that is associated with an object with a type
    /// property that is set to RecognizedEntityCredential and an id property with a [URL] value";
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST
    /// throw an error if an endpoint receives data, options, or option values that it does not
    /// understand or know how to process." [URL] is the
    /// <see href="https://url.spec.whatwg.org/#url-writing">URL Standard</see>, under which "A valid URL
    /// string defines what input would not trigger a validation error or failure when parsed by the URL
    /// parser", and whose URL code points outside ASCII are "code points in the range U+00A0 to
    /// U+10FFFD, inclusive, excluding surrogates and noncharacters". A value that is not an array, an
    /// item of none of the three shapes, a URL that is not a valid URL string in any of the three forms
    /// (a host that ends in a number without being an IPv4 address, surrounding white space, a newline,
    /// user information, a port above 65535, a backslash, a C1 control code point below U+00A0 in the
    /// path or the fragment), an empty list, or a list nested inside a list refuses the whole request.
    /// </summary>
    /// <param name="acceptedIssuersJson">The <c>acceptedIssuers</c> member value.</param>
    [TestMethod]
    [DataRow("[\"https://test.42/\"]")]
    [DataRow("[{\"id\": \"https://test.42/\"}]")]
    [DataRow("[{\"recognizedIn\": {\"id\": \"https://test.42/\", \"type\": \"RecognizedEntityCredential\"}}]")]
    [DataRow("[\" https://a.example/\"]")]
    [DataRow("[\"https://a.example/\\n\"]")]
    [DataRow("[\"https://user@a.example/\"]")]
    [DataRow("[\"https://a.example:65536/\"]")]
    [DataRow("[\"C:\\\\x\"]")]
    [DataRow("[\"https://a.example/a\\u0085b\"]")]
    [DataRow("[\"https://a.example/#a\\u009Fb\"]")]
    [DataRow("[{\"id\": \"https://a.example/\", \"recognizedIn\": 42}]")]
    [DataRow("[{}]")]
    [DataRow("[42]")]
    [DataRow("[null]")]
    [DataRow("\"did:web:authority.example\"")]
    [DataRow("[\"not a url\"]")]
    [DataRow("[{\"id\": \"not a url\"}]")]
    [DataRow("[{\"id\": 42}]")]
    [DataRow("[{\"recognizedIn\": {\"id\": \"https://url.example/list.vc\"}}]")]
    [DataRow("[{\"recognizedIn\": {\"id\": \"https://url.example/list.vc\", \"type\": \"VerifiableRecognitionCredential\"}}]")]
    [DataRow("[{\"recognizedIn\": {\"id\": \"not a url\", \"type\": \"RecognizedEntityCredential\"}}]")]
    [DataRow("[{\"recognizedIn\": \"https://url.example/list.vc\"}]")]
    [DataRow("[[]]")]
    [DataRow("[[[\"did:web:authority.example\"]]]")]
    public void QueryByExampleRefusesMalformedAcceptedIssuer(string acceptedIssuersJson)
    {
        string json = "{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedIssuers\":"
            + acceptedIssuersJson + "}}]}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, acceptedIssuersJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedCryptosuites</c> is "An OPTIONAL array specifying which cryptographic proof suites
    /// the verifier will accept. Each element SHOULD be an object with a cryptosuite property
    /// referencing a Data Integrity cryptosuite name or Ed25519Signature2020 for legacy (for backwards
    /// compatibility, string values MAY also be used and are to be interpreted as the cryptosuite
    /// name)"; <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations
    /// MUST throw an error if an endpoint receives data, options, or option values that it does not
    /// understand or know how to process." A value that is not an array, or an element that names no
    /// cryptosuite, refuses the whole request.
    /// </summary>
    /// <param name="acceptedCryptosuitesJson">The <c>acceptedCryptosuites</c> member value.</param>
    [TestMethod]
    [DataRow("[{}]")]
    [DataRow("[42]")]
    [DataRow("[null]")]
    [DataRow("[\"\"]")]
    [DataRow("[{\"cryptosuite\": \"\"}]")]
    [DataRow("[{\"cryptosuite\": 7}]")]
    [DataRow("\"eddsa-rdfc-2022\"")]
    public void QueryByExampleRefusesMalformedAcceptedCryptosuite(string acceptedCryptosuitesJson)
    {
        string json = "{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedCryptosuites\":"
            + acceptedCryptosuitesJson + "}}]}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, acceptedCryptosuitesJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedEnvelopes</c> is "An OPTIONAL array specifying which envelope formats the verifier
    /// will accept. Each element SHOULD be an object with a mediaType property referencing the media
    /// type for the envelope (for backwards compatibility, string values MAY also be used and are to be
    /// interpreted as the media type)"; <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM
    /// §2.4</see>: "Implementations MUST throw an error if an endpoint receives data, options, or option
    /// values that it does not understand or know how to process." A value that is not an array, or an
    /// element that names no media type, refuses the whole request.
    /// </summary>
    /// <param name="acceptedEnvelopesJson">The <c>acceptedEnvelopes</c> member value.</param>
    [TestMethod]
    [DataRow("[{}]")]
    [DataRow("[[]]")]
    [DataRow("[{\"mediaType\": 7}]")]
    [DataRow("[{\"mediaType\": \"\"}]")]
    [DataRow("\"application/jwt\"")]
    public void QueryByExampleRefusesMalformedAcceptedEnvelope(string acceptedEnvelopesJson)
    {
        string json = "{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedEnvelopes\":"
            + acceptedEnvelopesJson + "}}]}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, acceptedEnvelopesJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: for
    /// <c>acceptedCryptosuites</c>, "Each element SHOULD be an object with a cryptosuite property
    /// referencing a Data Integrity cryptosuite name or Ed25519Signature2020 for legacy (for backwards
    /// compatibility, string values MAY also be used and are to be interpreted as the cryptosuite
    /// name)". A Query By Example carrying a bare string element beside an object parses, the string
    /// read as the cryptosuite name.
    /// </summary>
    [TestMethod]
    public void QueryByExampleAcceptsBareCryptosuiteStrings()
    {
        const string json = """
        {
            "query": [{
                "type": "QueryByExample",
                "credentialQuery": {
                    "acceptedCryptosuites": ["eddsa-rdfc-2022", {"cryptosuite": "ecdsa-rdfc-2019"}]
                }
            }]
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        QueryByExampleQuery qbe = Assert.IsInstanceOfType<QueryByExampleQuery>(request.Query[0]);
        Assert.AreSequenceEqual(MixedCryptosuites, qbe.CredentialQuery.AcceptedCryptosuites.ToArray());
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: for
    /// <c>acceptedEnvelopes</c>, "Each element SHOULD be an object with a mediaType property referencing
    /// the media type for the envelope (for backwards compatibility, string values MAY also be used and
    /// are to be interpreted as the media type)". A Query By Example carrying a bare string element
    /// beside an object parses, the string read as the media type.
    /// </summary>
    [TestMethod]
    public void QueryByExampleAcceptsBareEnvelopeStrings()
    {
        const string json = """
        {
            "query": [{
                "type": "QueryByExample",
                "credentialQuery": {
                    "acceptedEnvelopes": ["application/jwt", {"mediaType": "application/vc+sd-jwt"}]
                }
            }]
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        QueryByExampleQuery qbe = Assert.IsInstanceOfType<QueryByExampleQuery>(request.Query[0]);
        Assert.AreSequenceEqual(MixedEnvelopes, qbe.CredentialQuery.AcceptedEnvelopes.ToArray());
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: each
    /// <c>acceptedIssuers</c> item may be "a [URL] that identifies an issuer in the issuer property of the
    /// received verifiable credential", [URL] being the
    /// <see href="https://url.spec.whatwg.org/#url-writing">URL Standard</see>, whose "absolute-URL
    /// string" is a "URL-scheme string" ("one ASCII alpha, followed by zero or more of ASCII
    /// alphanumeric, U+002B (+), U+002D (-), and U+002E (.)") followed by ":" and, for a scheme that is
    /// not special, "a scheme-relative-URL string, a path-absolute-non-authority-URL string, or an
    /// opaque-path-URL string"; a special URL's host is "a valid domain string, a valid IPv4-address
    /// string, or: U+005B ([), followed by a valid IPv6-address string, followed by U+005D (])"; the URL
    /// code points outside ASCII are "code points in the range U+00A0 to U+10FFFD, inclusive, excluding
    /// surrogates and noncharacters". Each such valid URL string parses as an accepted issuer and keeps
    /// its original text.
    /// </summary>
    /// <param name="issuer">The accepted-issuer URL.</param>
    [TestMethod]
    [DataRow("a:b")]
    [DataRow("urn:uuid:5a5f4b5e-2b9c-4e6f-8a7d-1c3b5e7f9a0b")]
    [DataRow("did:web:red-issuer.example")]
    [DataRow("https://127.0.0.1:8443/issuers/1?active=true#key-1")]
    [DataRow("https://[2001:db8::1]/")]
    [DataRow("https://münchen.example/")]
    [DataRow("https://a.example/a\u00A0b")]
    public void QueryByExampleAcceptsUrlStandardIssuer(string issuer)
    {
        string json = "{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedIssuers\":[\""
            + issuer + "\"]}}]}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure, issuer);
        QueryByExampleQuery qbe = Assert.IsInstanceOfType<QueryByExampleQuery>(request.Query[0]);
        Assert.AreEqual(issuer, qbe.CredentialQuery.AcceptedIssuers[0].Id);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: <c>example</c>
    /// is "An OPTIONAL object that provides an example of the credential being requested, including its
    /// @context, type, and optionally credentialSubject fields to indicate which claims are needed";
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw
    /// an error if an endpoint receives data, options, or option values that it does not understand or
    /// know how to process." An example that is not an object, an <c>@context</c> or <c>type</c> that is
    /// neither a string nor an array of strings, and a <c>credentialSubject</c> that is not an object each
    /// refuse the whole request rather than leave the example unconstrained.
    /// </summary>
    /// <param name="exampleJson">The <c>example</c> member value.</param>
    [TestMethod]
    [DataRow("42")]
    [DataRow("\"ExampleAlumniCredential\"")]
    [DataRow("[]")]
    [DataRow("null")]
    [DataRow("{\"type\": 7}")]
    [DataRow("{\"type\": [\"ExampleAlumniCredential\", 7]}")]
    [DataRow("{\"@context\": {}}")]
    [DataRow("{\"credentialSubject\": \"Alumni\"}")]
    public void QueryByExampleRefusesMalformedExample(string exampleJson)
    {
        string json = "{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"example\":" + exampleJson + "}}]}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, exampleJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: <c>reason</c> is
    /// "An OPTIONAL string that provides a human-readable explanation for why the credential is being
    /// requested"; <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations
    /// MUST throw an error if an endpoint receives data, options, or option values that it does not
    /// understand or know how to process." A <c>reason</c> that is not a string refuses the whole
    /// request.
    /// </summary>
    /// <param name="reasonJson">The <c>reason</c> member value.</param>
    [TestMethod]
    [DataRow("7")]
    [DataRow("{\"text\": \"alumni\"}")]
    public void QueryByExampleRefusesNonStringReason(string reasonJson)
    {
        string json = "{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"reason\":" + reasonJson + "}}]}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, reasonJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: "Multiple
    /// queries with the same group value are processed as "AND" operations, while queries with different
    /// or missing group values are processed as "OR" operations";
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw
    /// an error if an endpoint receives data, options, or option values that it does not understand or
    /// know how to process." A <c>group</c> that is not a string refuses the whole request, never read
    /// as a missing group that would turn the verifier's AND into an OR.
    /// </summary>
    /// <param name="groupJson">The <c>group</c> member value.</param>
    [TestMethod]
    [DataRow("1")]
    [DataRow("null")]
    [DataRow("true")]
    [DataRow("{\"name\": \"certification\"}")]
    public void RefusesNonStringGroup(string groupJson)
    {
        string json = "{\"query\":[{\"type\":\"QueryByExample\",\"group\":" + groupJson
            + ",\"credentialQuery\":{\"example\":{\"type\":\"ExampleAlumniCredential\"}}},"
            + "{\"type\":\"QueryByExample\",\"group\":" + groupJson
            + ",\"credentialQuery\":{\"example\":{\"type\":\"MembershipCredential\"}}}]}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, groupJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>:
    /// <c>domain</c> is "An OPTIONAL string that a verifier provides to a holder during a presentation
    /// request"; <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations
    /// MUST throw an error if an endpoint receives data, options, or option values that it does not
    /// understand or know how to process." A <c>domain</c> that is not a string refuses the whole request.
    /// </summary>
    /// <param name="domainJson">The <c>domain</c> member value.</param>
    [TestMethod]
    [DataRow("42")]
    [DataRow("[\"reunion.example\"]")]
    [DataRow("null")]
    public void RefusesNonStringDomain(string domainJson)
    {
        string json = "{\"query\":[{\"type\":\"DIDAuthentication\"}],\"domain\":" + domainJson + "}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, domainJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>:
    /// <c>challenge</c> is "An OPTIONAL, unique string that is provided by a verifier to a holder during a
    /// specific presentation request"; <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM
    /// §2.4</see>: "Implementations MUST throw an error if an endpoint receives data, options, or option
    /// values that it does not understand or know how to process." A <c>challenge</c> that is not a
    /// string refuses the whole request.
    /// </summary>
    /// <param name="challengeJson">The <c>challenge</c> member value.</param>
    [TestMethod]
    [DataRow("42")]
    [DataRow("{\"value\": \"3182bdea\"}")]
    [DataRow("null")]
    public void RefusesNonStringChallenge(string challengeJson)
    {
        string json = "{\"query\":[{\"type\":\"DIDAuthentication\"}],\"challenge\":" + challengeJson + "}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, challengeJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw
    /// an error if an endpoint receives data, options, or option values that it does not understand or
    /// know how to process." A member name repeated inside one object of the request, at any depth and
    /// whichever occurrence is malformed or narrower, refuses the whole request: resolved to one of its
    /// occurrences it could leave an acceptance constraint empty, the value that places no constraint,
    /// or drop a malformed one unseen.
    /// </summary>
    /// <param name="json">The request JSON text.</param>
    [TestMethod]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedIssuers\":42,\"acceptedIssuers\":[]}}]}")]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedIssuers\":[\"https://a.example\"],\"acceptedIssuers\":[]}}]}")]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedCryptosuites\":[{}],\"acceptedCryptosuites\":[]}}]}")]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedEnvelopes\":[{}],\"acceptedEnvelopes\":[]}}]}")]
    [DataRow("{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{}],\"acceptedMethods\":[]}]}")]
    [DataRow("{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":7,\"acceptedMethods\":[{\"method\":\"key\"}]}]}")]
    [DataRow("{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{\"method\":7,\"method\":\"key\"}]}]}")]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedIssuers\":[{\"id\":7,\"id\":\"https://a.example\"}]}}]}")]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedIssuers\":[\"https://a.example\"]},\"credentialQuery\":{}}]}")]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"type\":\"QueryByExample\",\"credentialQuery\":{}}]}")]
    [DataRow("{\"query\":[{\"type\":\"DIDAuthentication\"}],\"domain\":\"a.example\",\"domain\":\"b.example\"}")]
    public void RefusesRepeatedMemberName(string json)
    {
        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, json);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>: "A JSON text is a
    /// serialized value." with the grammar <c>JSON-text = ws value ws</c>. The text <c>{</c> opens an object it never
    /// closes, so the JSON reader refuses it and the request reports <see cref="VcalmParseFailure.Unparseable"/>.
    /// </summary>
    [TestMethod]
    public void TextThatDoesNotReadIsUnparseable()
    {
        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse("{", JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Unparseable, request.Failure);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>:
    /// "The value associated with a particular property is malformed." The text <c>[]</c> reads as a JSON text, an array
    /// where <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM Section 3.4.1</see>
    /// names an object, so the request reports <see cref="VcalmParseFailure.Malformed"/>.
    /// </summary>
    [TestMethod]
    public void TopLevelArrayIsMalformed()
    {
        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse("[]", JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>:
    /// "The value associated with a particular property is malformed." The text <c>{"query":7}</c> reads as a JSON
    /// object whose <c>query</c> is a number where
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM Section 3.4.1</see> names an
    /// array of query maps, so the request reports <see cref="VcalmParseFailure.Malformed"/>.
    /// </summary>
    [TestMethod]
    public void QueryOfTheWrongKindIsMalformed()
    {
        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse("{\"query\":7}", JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>: "A DID Authentication query MUST be of the following form": a "type" that is "A
    /// REQUIRED string value that MUST be set to DIDAuthentication", "acceptedMethods" ("An optional
    /// array of objects expressing that the verifier would accept any DID Method listed") and
    /// "acceptedCryptosuites". A query of that form parses with both lists, and the accepted methods
    /// decide which holder DIDs are acceptable.
    /// </summary>
    [TestMethod]
    public void ParsesDidAuthenticationQuery()
    {
        const string json = """
        {
            "query": [{
                "type": "DIDAuthentication",
                "acceptedMethods": [{ "method": "key" }, { "method": "web" }],
                "acceptedCryptosuites": [{ "cryptosuite": "ecdsa-rdfc-2019" }]
            }],
            "challenge": "99612b24-63d9-11ea-b99f-4f66f3e4f81a",
            "domain": "example.com"
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        DidAuthenticationQuery didAuth = Assert.IsInstanceOfType<DidAuthenticationQuery>(request.Query[0]);
        Assert.AreEqual(VcalmQueryTypes.DidAuthentication, didAuth.Type);
        Assert.AreSequenceEqual(KeyAndWebMethods, didAuth.AcceptedMethods.ToArray(), SequenceOrder.InAnyOrder);
        Assert.Contains("ecdsa-rdfc-2019", didAuth.AcceptedCryptosuites);

        //§3.4.3 holder predicate: a did:key holder is accepted, a did:cheqd holder is not.
        Assert.IsTrue(didAuth.IsHolderAccepted("did:key:z6MkExampleKey"));
        Assert.IsFalse(didAuth.IsHolderAccepted("did:cheqd:mainnet:123"));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>: <c>acceptedMethods</c> is "An optional array of objects expressing that the
    /// verifier would accept any DID Method listed. Each object in the array MUST contain a property
    /// called method with a value that is a DID Method name"; the DID syntax rules are "method-name =
    /// 1*method-char" and "method-char = %x61-7A / DIGIT"
    /// (<see href="https://www.w3.org/TR/did-core/#did-syntax">DID Core 1.0 §3.1</see>);
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw
    /// an error if an endpoint receives data, options, or option values that it does not understand or
    /// know how to process." A value that is not an array, an element that is not an object, or an
    /// object whose <c>method</c> is missing, not a string, or not a DID method name (empty, a whole DID,
    /// uppercase, or carrying a character outside lowercase letters and digits) refuses the whole
    /// request, even beside a well-formed element.
    /// </summary>
    /// <param name="acceptedMethodsJson">The <c>acceptedMethods</c> member value.</param>
    [TestMethod]
    [DataRow("[{\"method\":\"did:key\"}]")]
    [DataRow("[{\"method\":\"KEY\"}]")]
    [DataRow("[{\"method\":\"k-y\"}]")]
    [DataRow("[{\"method\":\"k e y\"}]")]
    [DataRow("[{}]")]
    [DataRow("[{\"method\":\"\"}]")]
    [DataRow("[{\"method\":7}]")]
    [DataRow("[{\"method\":null}]")]
    [DataRow("[\"key\"]")]
    [DataRow("\"key\"")]
    [DataRow("[{\"method\":\"key\"},{}]")]
    public void DidAuthenticationRefusesMalformedMethod(string acceptedMethodsJson)
    {
        string json = "{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":" + acceptedMethodsJson + "}]}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, acceptedMethodsJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>: <c>acceptedCryptosuites</c> is "An optional array of objects that conveys the
    /// cryptography suites among which the holder MUST choose when generating a cryptographic proof to
    /// be submitted to this verifier. Each object in the array MUST contain a property called
    /// cryptosuite with a value that is a Data Integrity cryptosuite name (or Ed25519Signature2020 for
    /// legacy)"; <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>:
    /// "Implementations MUST throw an error if an endpoint receives data, options, or option values that
    /// it does not understand or know how to process." An element that is not an object, or an object
    /// whose <c>cryptosuite</c> is missing, empty or not a string, refuses the whole request.
    /// </summary>
    /// <param name="acceptedCryptosuitesJson">The <c>acceptedCryptosuites</c> member value.</param>
    [TestMethod]
    [DataRow("[{}]")]
    [DataRow("[{\"cryptosuite\":null}]")]
    [DataRow("[{\"suite\":\"x\"}]")]
    [DataRow("[{\"cryptosuite\":\"\"}]")]
    [DataRow("[\"ecdsa-rdfc-2019\"]")]
    [DataRow("{\"cryptosuite\":\"ecdsa-rdfc-2019\"}")]
    public void DidAuthenticationRefusesMalformedCryptosuite(string acceptedCryptosuitesJson)
    {
        string json = "{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{\"method\":\"key\"}],"
            + "\"acceptedCryptosuites\":" + acceptedCryptosuitesJson + "}]}";

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure, acceptedCryptosuitesJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>: "Each object in the array MUST contain a property called method with a value that
    /// is a DID Method name, and MAY contain other properties that are specific to the DID Method." Such
    /// properties beside a well-formed <c>method</c> leave the request well formed.
    /// </summary>
    [TestMethod]
    public void DidAuthenticationAcceptsMethodSpecificProperties()
    {
        const string json = """
        {
            "query": [{
                "type": "DIDAuthentication",
                "acceptedMethods": [{"method": "web", "networkHint": {"region": "eu"}}]
            }]
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        DidAuthenticationQuery didAuth = Assert.IsInstanceOfType<DidAuthenticationQuery>(request.Query[0]);
        Assert.AreSequenceEqual(WebMethod, didAuth.AcceptedMethods.ToArray());
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>: "Each object in the array MUST contain a property called cryptosuite with a value
    /// that is a Data Integrity cryptosuite name (or Ed25519Signature2020 for legacy), and MAY contain
    /// other properties that are specific to the cryptosuite." Such properties beside a well-formed
    /// <c>cryptosuite</c> leave the request well formed.
    /// </summary>
    [TestMethod]
    public void DidAuthenticationAcceptsCryptosuiteSpecificProperties()
    {
        const string json = """
        {
            "query": [{
                "type": "DIDAuthentication",
                "acceptedCryptosuites": [{"cryptosuite": "ecdsa-rdfc-2019", "curve": "P-256"}]
            }]
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        DidAuthenticationQuery didAuth = Assert.IsInstanceOfType<DidAuthenticationQuery>(request.Query[0]);
        Assert.AreSequenceEqual(EcdsaRdfcCryptosuite, didAuth.AcceptedCryptosuites.ToArray());
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>:
    /// query is "A REQUIRED property that specifies the information requested by the verifier. The value
    /// MUST be one or more maps where each map MUST define a type property with an associated string
    /// value." A query entry without a type is refused.
    /// </summary>
    [TestMethod]
    public void RejectsQueryEntryMissingType()
    {
        const string json = """
        { "query": [{ "credentialQuery": { "reason": "no type here" } }] }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>:
    /// query is "A REQUIRED property that specifies the information requested by the verifier. The value
    /// MUST be one or more maps". An empty query array holds no map and is refused.
    /// </summary>
    [TestMethod]
    public void RejectsEmptyQueryArray()
    {
        VerifiablePresentationRequest request =
            VcalmPresentationRequestJsonParsing.Parse("""{ "query": [] }""", JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>:
    /// "The query property serves as the main extension point mechanism for requests for data in the
    /// presentation", and "all query objects are of the following form": maps that "MUST define a type
    /// property with an associated string value". A map of that form whose type this library does not
    /// define parses as an extension query, not a failure.
    /// </summary>
    [TestMethod]
    public void ParsesUnknownQueryTypeAsExtension()
    {
        const string json = """
        { "query": [{ "type": "SomeFutureQueryType", "futureMember": 42 }] }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        UnknownQuery unknown = Assert.IsInstanceOfType<UnknownQuery>(request.Query[0]);
        Assert.AreEqual("SomeFutureQueryType", unknown.Type);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization-capability-request">VCALM §3.4.4</see>:
    /// "This query type would be included in a request to ask for Authorization Capabilities or "ZCAPs"
    /// in the Verifiable Presentation", and "Authorization Capability queries and responses might not be
    /// standardized at this time." The clause's own example parses into the capability query model.
    /// </summary>
    [TestMethod]
    public void ParsesAuthorizationCapabilityQuery()
    {
        const string json = """
        {
            "query": [{
                "type": "AuthorizationCapabilityQuery",
                "capabilityQuery": [{
                    "referenceId": "a-memorable-name",
                    "allowedAction": ["read", "write"],
                    "controller": "did:example:1234",
                    "invocationTarget": { "type": "urn:edv:documents" }
                }]
            }]
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        AuthorizationCapabilityRequestQuery capability =
            Assert.IsInstanceOfType<AuthorizationCapabilityRequestQuery>(request.Query[0]);
        Assert.HasCount(1, capability.CapabilityQuery);
        Assert.AreEqual("a-memorable-name", capability.CapabilityQuery[0].ReferenceId);
        Assert.AreSequenceEqual(ReadAndWriteActions, capability.CapabilityQuery[0].AllowedAction.ToArray(), SequenceOrder.InAnyOrder);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>:
    /// "The query property serves as the main extension point mechanism for requests for data in the
    /// presentation", and the draft's own requests carry queries of <c>"type":
    /// "DigitalCredentialQueryLanguage"</c>. Such a query parses into the Digital Credentials Query
    /// Language model with its credential query intact.
    /// </summary>
    [TestMethod]
    public void ParsesDcqlTypedQueryIntoDcqlModel()
    {
        const string json = """
        {
            "query": [{
                "type": "DigitalCredentialQueryLanguage",
                "credentials": [{
                    "id": "vc",
                    "format": "ExampleAlumniCredential",
                    "meta": {},
                    "claims": [{ "path": ["credentialSubject", "alumniOf"] }]
                }]
            }]
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.None, request.Failure);
        DigitalCredentialQueryLanguageQuery dcql =
            Assert.IsInstanceOfType<DigitalCredentialQueryLanguageQuery>(request.Query[0]);
        DcqlQuery query = dcql.Query;
        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(1, query.Credentials);
        Assert.AreEqual("ExampleAlumniCredential", query.Credentials[0].Format);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#top-level-queries-and-operation">VCALM §3.4.5.1</see>:
    /// "At the top-most level of the request structure, different types of queries are expected to be
    /// processed as "AND" operations if each one's group property is set to the same value." With only
    /// one of the two credentials of the same group held the group is not satisfied, and with both held
    /// it is.
    /// </summary>
    [TestMethod]
    public void GroupedQueriesAreAndedInEvaluation()
    {
        VerifiablePresentationRequest request = new()
        {
            Query =
            [
                QueryByExampleFor(AlumniCredentialType, "type", "Alumni", group: "certification"),
                QueryByExampleFor("MembershipCredential", "membershipLevel", "Gold", group: "certification")
            ]
        };

        VerifiableCredential alumni = BuildCredential(
            AlumniCredentialType, AuthorityIssuer, ("type", "Alumni"));

        //Only the alumni credential is held — the certification AND-group needs both.
        VprEvaluationResult partial = VprEvaluator.Evaluate(request, [alumni]);
        Assert.IsFalse(partial.IsSatisfiable);
        Assert.HasCount(1, partial.Groups);
        Assert.IsFalse(partial.Groups[0].IsSatisfied);

        VerifiableCredential membership = BuildCredential(
            "MembershipCredential", AuthorityIssuer, ("membershipLevel", "Gold"));

        //With both held, the AND-group is satisfied.
        VprEvaluationResult full = VprEvaluator.Evaluate(request, [alumni, membership]);
        Assert.IsTrue(full.IsSatisfiable);
        Assert.IsTrue(full.Groups[0].IsSatisfied);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#nested-queries-or-operation">VCALM §3.4.5.2</see>:
    /// "Within a specific query type, an "OR" operation can be applied, by either not specifying the
    /// group or providing group values that are different from one another." Of two queries with
    /// different group values, the one the held credential matches satisfies the request.
    /// </summary>
    [TestMethod]
    public void UngroupedOrDifferentGroupQueriesAreOredInEvaluation()
    {
        VerifiablePresentationRequest request = new()
        {
            Query =
            [
                QueryByExampleFor(AlumniCredentialType, "type", "Alumni", group: "college-degree"),
                QueryByExampleFor("MembershipCredential", "membershipLevel", "Gold", group: "job-experience")
            ]
        };

        //Only the membership credential is held — the OR over the two distinct groups still succeeds.
        VerifiableCredential membership = BuildCredential(
            "MembershipCredential", AuthorityIssuer, ("membershipLevel", "Gold"));

        VprEvaluationResult result = VprEvaluator.Evaluate(request, [membership]);

        Assert.IsTrue(result.IsSatisfiable);
        Assert.HasCount(2, result.Groups);
        //One group (the membership one) is satisfied, the alumni group is not.
        _ = Assert.ContainsSingle(result.Groups.Where(g => g.IsSatisfied));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: "Any field
    /// included in a Query By Example is a required field", and "it is up to the wallet that is
    /// responding to the query to ensure that its response does not reveal any information beyond what
    /// is being requested." The holder selects only the credential matching the example, and the
    /// requested field is the whole disclosure.
    /// </summary>
    [TestMethod]
    public void QueryByExampleEvaluationSelectsMatchAndComputesMinimalDisclosure()
    {
        VerifiablePresentationRequest request = new()
        {
            Query = [QueryByExampleFor(AlumniCredentialType, "alumniOf", "Example University", group: null)]
        };

        VerifiableCredential match = BuildCredential(
            AlumniCredentialType, AuthorityIssuer, ("alumniOf", "Example University"));
        VerifiableCredential nonMatch = BuildCredential(
            "MembershipCredential", AuthorityIssuer, ("membershipLevel", "Gold"));

        VprEvaluationResult result = VprEvaluator.Evaluate(request, [match, nonMatch]);

        Assert.IsTrue(result.IsSatisfiable);
        VprQueryMatch queryMatch = result.Groups[0].QueryMatches[0];
        Assert.IsTrue(queryMatch.IsSatisfied);
        Assert.HasCount(1, queryMatch.Matches);
        Assert.AreSame(match, queryMatch.Matches[0].Credential);

        //§3.4.2 selective disclosure: the requested credentialSubject field is the minimal disclosure.
        Assert.HasCount(1, queryMatch.Matches[0].Disclosures);
        Assert.AreEqual("/credentialSubject/alumniOf", queryMatch.Matches[0].Disclosures[0].ToString());
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: "To request a
    /// field without any statement about an expected value, a requester can include the field in the
    /// request and leave the value as an empty string." A credential carrying the field with any value
    /// satisfies such a query.
    /// </summary>
    [TestMethod]
    public void EmptyStringExampleFieldMatchesAnyValue()
    {
        VerifiablePresentationRequest request = new()
        {
            Query = [QueryByExampleFor(AlumniCredentialType, "alumniOf", value: "", group: null)]
        };

        VerifiableCredential anyValue = BuildCredential(
            AlumniCredentialType, AuthorityIssuer, ("alumniOf", "Some Other University"));

        VprEvaluationResult result = VprEvaluator.Evaluate(request, [anyValue]);

        Assert.IsTrue(result.IsSatisfiable);
        Assert.IsTrue(result.Groups[0].QueryMatches[0].IsSatisfied);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: "To request a
    /// field without any statement about an expected value, a requester can include the field in the
    /// request and leave the value as an empty string", so a non-empty value is a statement about the
    /// expected value. A credential carrying the field with another value does not satisfy the query.
    /// </summary>
    [TestMethod]
    public void NonEmptyExampleFieldConstrainsValue()
    {
        VerifiablePresentationRequest request = new()
        {
            Query = [QueryByExampleFor(AlumniCredentialType, "alumniOf", "Example University", group: null)]
        };

        VerifiableCredential wrongValue = BuildCredential(
            AlumniCredentialType, AuthorityIssuer, ("alumniOf", "Different University"));

        VprEvaluationResult result = VprEvaluator.Evaluate(request, [wrongValue]);

        Assert.IsFalse(result.IsSatisfiable);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedIssuers</c> identifies "entities that the verifier recognizes and accepts as issuers of
    /// the verifiable credential", an item being "an object that contains an id property whose value is a
    /// [URL] that identifies an issuer in the issuer property of the received verifiable credential". A
    /// credential from the named issuer satisfies the query; one from another issuer does not.
    /// </summary>
    [TestMethod]
    public void AcceptedIssuersFiltersByIssuer()
    {
        QueryByExampleQuery query = new()
        {
            Type = VcalmQueryTypes.QueryByExample,
            CredentialQuery = new QueryByExampleCredentialQuery
            {
                Example = new QueryByExampleCredential
                {
                    Types = [AlumniCredentialType],
                    SubjectFields = System.Collections.Immutable.ImmutableDictionary<string, string>.Empty
                },
                AcceptedIssuers = [new QueryByExampleAcceptedIssuer { Id = AuthorityIssuer }]
            }
        };
        VerifiablePresentationRequest request = new() { Query = [query] };

        VerifiableCredential accepted = BuildCredential(AlumniCredentialType, AuthorityIssuer, ("alumniOf", "X"));
        VerifiableCredential rejected = BuildCredential(AlumniCredentialType, OtherIssuer, ("alumniOf", "X"));

        Assert.IsTrue(VprEvaluator.Evaluate(request, [accepted]).IsSatisfiable);
        Assert.IsFalse(VprEvaluator.Evaluate(request, [rejected]).IsSatisfiable);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: a
    /// <c>recognizedIn</c> item points to a <c>RecognizedEntityCredential</c> and "the list contains
    /// recognized issuers that are acceptable to the verifier". A request whose only accepted-issuer
    /// item is the specification's own <c>recognizedIn</c> example, parsed from the request JSON, names
    /// no issuer until the caller has retrieved and verified that list; a credential from any issuer
    /// then does not satisfy it.
    /// </summary>
    [TestMethod]
    public void RecognizedInOnlyRefusesWithoutRecognizedIssuerIds()
    {
        const string json = """
        {
            "query": [{
                "type": "QueryByExample",
                "credentialQuery": {
                    "example": { "type": "ExampleAlumniCredential" },
                    "acceptedIssuers": [
                        {"recognizedIn": {"id": "https://url.example/list.vc", "type": "RecognizedEntityCredential"}}
                    ]
                }
            }]
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);
        Assert.AreEqual(VcalmParseFailure.None, request.Failure);

        VerifiableCredential credential = BuildCredential(AlumniCredentialType, AuthorityIssuer, ("alumniOf", "X"));

        Assert.IsFalse(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "A recognizedIn-only constraint with no recognized issuers supplied accepts no issuer.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: "the list
    /// contains recognized issuers that are acceptable to the verifier". When the caller's retrieved
    /// and verified list names another issuer, a credential from an issuer not on the list does not
    /// satisfy a <c>recognizedIn</c>-only constraint.
    /// </summary>
    [TestMethod]
    public void RecognizedInOnlyRefusesUnrecognizedIssuer()
    {
        VerifiablePresentationRequest request = RequestAcceptingIssuers(
            new QueryByExampleAcceptedIssuer { RecognizedInId = RecognizedListUrl, RecognizedIssuerIds = [OtherIssuer] });

        VerifiableCredential credential = BuildCredential(AlumniCredentialType, AuthorityIssuer, ("alumniOf", "X"));

        Assert.IsFalse(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "An issuer absent from the recognized list is not accepted.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: "the list
    /// contains recognized issuers that are acceptable to the verifier". When the caller's retrieved
    /// and verified list names the credential's issuer, the credential satisfies a
    /// <c>recognizedIn</c>-only constraint.
    /// </summary>
    [TestMethod]
    public void RecognizedInOnlyAcceptsRecognizedIssuer()
    {
        VerifiablePresentationRequest request = RequestAcceptingIssuers(
            new QueryByExampleAcceptedIssuer
            {
                RecognizedInId = RecognizedListUrl,
                RecognizedIssuerIds = [OtherIssuer, AuthorityIssuer]
            });

        VerifiableCredential credential = BuildCredential(AlumniCredentialType, AuthorityIssuer, ("alumniOf", "X"));

        Assert.IsTrue(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "An issuer on the recognized list is accepted.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedIssuers</c> identifies "entities that the verifier recognizes and accepts as issuers",
    /// each item one way of naming them. A credential whose issuer is on the recognized list of a
    /// <c>recognizedIn</c> item satisfies the constraint even though a direct item beside it names
    /// another issuer.
    /// </summary>
    [TestMethod]
    public void RecognizedInItemAcceptsRecognizedIssuerBesideUnmatchedDirectItem()
    {
        VerifiablePresentationRequest request = RequestAcceptingIssuers(
            new QueryByExampleAcceptedIssuer { Id = OtherIssuer },
            new QueryByExampleAcceptedIssuer { RecognizedInId = RecognizedListUrl, RecognizedIssuerIds = [AuthorityIssuer] });

        VerifiableCredential credential = BuildCredential(AlumniCredentialType, AuthorityIssuer, ("alumniOf", "X"));

        Assert.IsTrue(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "Any accepted-issuer item that names the issuer accepts it.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>:
    /// "The query property serves as the main extension point mechanism for requests for data in the
    /// presentation", and a query of <c>"type": "DigitalCredentialQueryLanguage"</c> is one of them. The
    /// holder evaluates it with the Digital Credentials Query Language and selects the matching
    /// credential, the matched claim path being the disclosure.
    /// </summary>
    [TestMethod]
    public void DcqlQueryEvaluatesViaDcqlEvaluator()
    {
        DigitalCredentialQueryLanguageQuery dcql = new()
        {
            Type = VcalmQueryTypes.DigitalCredentialQueryLanguage,
            Query = DcqlFixtures.VcDataModelSubjectField(AlumniCredentialType, "alumniOf")
        };
        VerifiablePresentationRequest request = new() { Query = [dcql] };

        VerifiableCredential match = BuildCredential(
            AlumniCredentialType, AuthorityIssuer, ("alumniOf", "Example University"));
        VerifiableCredential nonMatch = BuildCredential(
            "MembershipCredential", AuthorityIssuer, ("membershipLevel", "Gold"));

        VprEvaluationResult result = VprEvaluator.Evaluate(request, [match, nonMatch]);

        Assert.IsTrue(result.IsSatisfiable);
        VprQueryMatch queryMatch = result.Groups[0].QueryMatches[0];
        Assert.IsTrue(queryMatch.IsSatisfied);
        Assert.HasCount(1, queryMatch.Matches);
        Assert.AreSame(match, queryMatch.Matches[0].Credential);
        Assert.Contains(
            "/credentialSubject/alumniOf",
            queryMatch.Matches[0].Disclosures.Select(d => d.ToString()).ToArray());
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>: <c>acceptedMethods</c> is "An optional array of objects expressing that the
    /// verifier would accept any DID Method listed". A holder controlling a DID of a listed method
    /// satisfies the query without holding any credential; a holder whose DID is of another method, or
    /// who offers no DID, does not.
    /// </summary>
    [TestMethod]
    public void DidAuthenticationSatisfiedByAcceptedHolderDid()
    {
        DidAuthenticationQuery didAuth = new()
        {
            Type = VcalmQueryTypes.DidAuthentication,
            AcceptedMethods = ["key"]
        };
        VerifiablePresentationRequest request = new() { Query = [didAuth] };

        VprEvaluationResult accepted = VprEvaluator.Evaluate(request, [], holderDids: ["did:key:z6MkExampleKey"]);
        Assert.IsTrue(accepted.IsSatisfiable);

        VprEvaluationResult rejected = VprEvaluator.Evaluate(request, [], holderDids: ["did:web:example.com"]);
        Assert.IsFalse(rejected.IsSatisfiable);

        VprEvaluationResult noDids = VprEvaluator.Evaluate(request, []);
        Assert.IsFalse(noDids.IsSatisfiable);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>: <c>acceptedCryptosuites</c> is "An optional array of objects that conveys the
    /// cryptography suites among which the holder MUST choose when generating a cryptographic proof to be
    /// submitted to this verifier." A holder controlling an accepted-method DID satisfies a constrained
    /// query only when it can sign with one of the accepted cryptosuites; with none to offer it cannot,
    /// and a query that omits the array places no cryptosuite constraint.
    /// </summary>
    [TestMethod]
    public void DidAuthenticationGatesOnAcceptedCryptosuites()
    {
        DidAuthenticationQuery didAuth = new()
        {
            Type = VcalmQueryTypes.DidAuthentication,
            AcceptedMethods = ["key"],
            AcceptedCryptosuites = ["ecdsa-rdfc-2019"]
        };
        VerifiablePresentationRequest request = new() { Query = [didAuth] };
        string[] holderDids = ["did:key:z6MkExampleKey"];

        //The holder can sign with an accepted cryptosuite — satisfiable.
        VprEvaluationResult matching = VprEvaluator.Evaluate(
            request, [], holderDids: holderDids, holderCryptosuites: ["ecdsa-rdfc-2019"]);
        Assert.IsTrue(matching.IsSatisfiable,
            "An accepted-method DID plus an accepted cryptosuite satisfies the §3.4.3 query.");

        //The holder controls the DID but signs only with a non-accepted cryptosuite — unsatisfiable.
        VprEvaluationResult wrongSuite = VprEvaluator.Evaluate(
            request, [], holderDids: holderDids, holderCryptosuites: ["bbs-2023"]);
        Assert.IsFalse(wrongSuite.IsSatisfiable,
            "A holder that cannot sign with an accepted cryptosuite cannot satisfy the query.");

        //The holder advertises no cryptosuite while the query constrains them — fail closed.
        VprEvaluationResult noSuite = VprEvaluator.Evaluate(request, [], holderDids: holderDids);
        Assert.IsFalse(noSuite.IsSatisfiable,
            "A constrained acceptedCryptosuites with no demonstrable holder cryptosuite fails closed.");

        //An UNCONSTRAINED query (no acceptedCryptosuites) is satisfied on the DID predicate alone.
        DidAuthenticationQuery unconstrained = new()
        {
            Type = VcalmQueryTypes.DidAuthentication,
            AcceptedMethods = ["key"]
        };
        VprEvaluationResult anySuite = VprEvaluator.Evaluate(
            new VerifiablePresentationRequest { Query = [unconstrained] }, [], holderDids: holderDids);
        Assert.IsTrue(anySuite.IsSatisfiable,
            "A DID Authentication query that omits acceptedCryptosuites places no cryptosuite constraint.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: a
    /// <c>recognizedIn</c> item's "list contains recognized issuers that are acceptable to the verifier".
    /// An item whose recognized issuers were never supplied, even as a <see langword="default"/> array,
    /// names no issuer, and evaluation answers unsatisfied rather than failing.
    /// </summary>
    [TestMethod]
    public void RecognizedInWithDefaultRecognizedIssuerIdsAcceptsNoIssuer()
    {
        VerifiablePresentationRequest request = RequestAcceptingIssuers(
            new QueryByExampleAcceptedIssuer { RecognizedInId = RecognizedListUrl, RecognizedIssuerIds = default });

        VerifiableCredential credential = BuildCredential(AlumniCredentialType, AuthorityIssuer, ("alumniOf", "X"));

        Assert.IsFalse(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "A recognizedIn item with no recognized issuers supplied accepts no issuer.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedCryptosuites</c> names "which cryptographic proof suites the verifier will accept", each
    /// element "referencing a Data Integrity cryptosuite name or Ed25519Signature2020 for legacy". A
    /// credential whose proof is of the legacy <c>Ed25519Signature2020</c> type, which carries no
    /// cryptosuite, satisfies a query accepting that name.
    /// </summary>
    [TestMethod]
    public void AcceptedCryptosuitesMatchLegacyProofType()
    {
        VerifiablePresentationRequest request = RequestAcceptingCryptosuites(["Ed25519Signature2020"], []);
        DataIntegritySecuredCredential credential = BuildSecuredCredential(new DataIntegrityProof { Type = "Ed25519Signature2020" });

        Assert.IsTrue(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "A legacy proof type named among the accepted cryptosuites is accepted.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedEnvelopes</c> "enables the holder to provide credentials in formats other than the
    /// default Data Integrity format", and in the clause's example "The acceptedEnvelopes property
    /// indicates that JWT-based envelope formats are also acceptable." A query naming only accepted
    /// envelopes is satisfied by a credential secured with a Data Integrity proof.
    /// </summary>
    [TestMethod]
    public void AcceptedEnvelopesKeepDataIntegrityAcceptable()
    {
        VerifiablePresentationRequest request = RequestAcceptingCryptosuites([], ["application/jwt"]);
        DataIntegritySecuredCredential credential = BuildSecuredCredential(
            new DataIntegrityProof { Cryptosuite = EddsaRdfc2022CryptosuiteInfo.Instance });

        Assert.IsTrue(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "Accepted envelopes add formats; the default Data Integrity format stays acceptable.");
    }


    /// <summary>
    /// Builds a request whose single Query By Example entry, with no example, accepts the given
    /// cryptosuites and envelope media types.
    /// </summary>
    /// <param name="acceptedCryptosuites">The accepted cryptosuite names.</param>
    /// <param name="acceptedEnvelopes">The accepted envelope media types.</param>
    /// <returns>The request.</returns>
    private static VerifiablePresentationRequest RequestAcceptingCryptosuites(string[] acceptedCryptosuites, string[] acceptedEnvelopes)
    {
        QueryByExampleQuery query = new()
        {
            Type = VcalmQueryTypes.QueryByExample,
            CredentialQuery = new QueryByExampleCredentialQuery
            {
                AcceptedCryptosuites = [.. acceptedCryptosuites],
                AcceptedEnvelopes = [.. acceptedEnvelopes]
            }
        };

        return new VerifiablePresentationRequest { Query = [query] };
    }


    /// <summary>
    /// Builds a VC Data Model 2.0 credential of <see cref="AlumniCredentialType"/> from
    /// <see cref="AuthorityIssuer"/> carrying <paramref name="proof"/>, for evaluation only: the proof is
    /// never verified here, the evaluator reads only its cryptosuite or type.
    /// </summary>
    /// <param name="proof">The proof the credential carries.</param>
    /// <returns>The credential.</returns>
    private static DataIntegritySecuredCredential BuildSecuredCredential(DataIntegrityProof proof) =>
        new()
        {
            Context = Context.FromIris(Context.Credentials20, AlumniContext),
            Type = [CredentialConstants.VerifiableCredentialType, AlumniCredentialType],
            Issuer = new Issuer { Id = AuthorityIssuer },
            CredentialSubject = [new CredentialSubject { AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal) }],
            Proof = [proof]
        };


    /// <summary>
    /// Builds a request whose single Query By Example entry asks for an <see cref="AlumniCredentialType"/>
    /// credential from one of <paramref name="acceptedIssuers"/>.
    /// </summary>
    /// <param name="acceptedIssuers">The accepted-issuer items of the query.</param>
    /// <returns>The request.</returns>
    private static VerifiablePresentationRequest RequestAcceptingIssuers(params QueryByExampleAcceptedIssuer[] acceptedIssuers)
    {
        QueryByExampleQuery query = new()
        {
            Type = VcalmQueryTypes.QueryByExample,
            CredentialQuery = new QueryByExampleCredentialQuery
            {
                Example = new QueryByExampleCredential { Types = [AlumniCredentialType] },
                AcceptedIssuers = [.. acceptedIssuers]
            }
        };

        return new VerifiablePresentationRequest { Query = [query] };
    }


    /// <summary>
    /// Builds an ungrouped or grouped Query By Example entry requesting <paramref name="credentialType"/>
    /// with one subject field <paramref name="field"/> of the requested <paramref name="value"/>.
    /// </summary>
    /// <param name="credentialType">The requested credential type.</param>
    /// <param name="field">The requested subject field.</param>
    /// <param name="value">The requested value; empty for any value.</param>
    /// <param name="group">The §3.4.5 group, or <see langword="null"/> for none.</param>
    /// <returns>The query entry.</returns>
    private static QueryByExampleQuery QueryByExampleFor(
        string credentialType, string field, string value, string? group)
    {
        System.Collections.Immutable.ImmutableDictionary<string, string> subjectFields =
            System.Collections.Immutable.ImmutableDictionary.CreateRange(
                StringComparer.Ordinal,
                new[] { new KeyValuePair<string, string>(field, value) });

        return new QueryByExampleQuery
        {
            Type = VcalmQueryTypes.QueryByExample,
            Group = group,
            CredentialQuery = new QueryByExampleCredentialQuery
            {
                Example = new QueryByExampleCredential
                {
                    Types = [credentialType],
                    SubjectFields = subjectFields
                }
            }
        };
    }


    /// <summary>
    /// Builds an unsecured VC Data Model 2.0 credential of <paramref name="credentialType"/> issued by
    /// <paramref name="issuer"/> with the given subject fields.
    /// </summary>
    /// <param name="credentialType">The credential type beside <c>VerifiableCredential</c>.</param>
    /// <param name="issuer">The issuer id.</param>
    /// <param name="subjectFields">The subject's fields.</param>
    /// <returns>The credential.</returns>
    private static VerifiableCredential BuildCredential(
        string credentialType, string issuer, params (string Field, object Value)[] subjectFields)
    {
        Dictionary<string, object> additionalData = new(StringComparer.Ordinal);
        foreach((string field, object fieldValue) in subjectFields)
        {
            additionalData[field] = fieldValue;
        }

        return new VerifiableCredential
        {
            Context = Context.FromIris(Context.Credentials20, AlumniContext),
            Type = [CredentialConstants.VerifiableCredentialType, credentialType],
            Issuer = new Issuer { Id = issuer },
            CredentialSubject = [new CredentialSubject { AdditionalData = additionalData }]
        };
    }
}
