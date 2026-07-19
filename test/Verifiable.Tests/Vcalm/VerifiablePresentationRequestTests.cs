using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
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
/// tests exercise the parse + holder "what can I present" computation in isolation, the surface the
/// §3.6 exchange engine consumes.
/// </summary>
[TestClass]
internal sealed class VerifiablePresentationRequestTests
{
    public TestContext TestContext { get; set; } = null!;

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    private const string AlumniContext = "https://www.w3.org/ns/credentials/examples/v2";
    private const string AlumniCredentialType = "ExampleAlumniCredential";
    private const string AuthorityIssuer = "did:web:authority.example";
    private const string OtherIssuer = "did:web:other.example";

    private static readonly string[] KeyAndWebMethods = ["key", "web"];
    private static readonly string[] ReadAndWriteActions = ["read", "write"];


    //§3.4.2: parse a VPR with a QueryByExample query carrying example + acceptedIssuers +
    //acceptedCryptosuites — the model round-trips every member.
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


    //§3.4.2: the three acceptedIssuers shapes — bare URL string, {id}, {recognizedIn{id,type}} — all
    //round-trip into the neutral model.
    [TestMethod]
    public void ParsesAcceptedIssuerShapes()
    {
        const string json = """
        {
            "query": [{
                "type": "QueryByExample",
                "credentialQuery": {
                    "acceptedIssuers": [
                        "https://blue-issuer.example/",
                        { "id": "did:web:green-issuer.example" },
                        { "recognizedIn": { "id": "https://url.example/list.vc", "type": "VerifiableRecognitionCredential" } }
                    ]
                }
            }]
        }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);
        QueryByExampleQuery qbe = Assert.IsInstanceOfType<QueryByExampleQuery>(request.Query[0]);

        Assert.HasCount(3, qbe.CredentialQuery.AcceptedIssuers);
        Assert.AreEqual("https://blue-issuer.example/", qbe.CredentialQuery.AcceptedIssuers[0].Id);
        Assert.AreEqual("did:web:green-issuer.example", qbe.CredentialQuery.AcceptedIssuers[1].Id);
        Assert.IsNull(qbe.CredentialQuery.AcceptedIssuers[2].Id);
        Assert.AreEqual("https://url.example/list.vc", qbe.CredentialQuery.AcceptedIssuers[2].RecognizedInId);
    }


    //§3.4.3: parse a DIDAuthentication query — acceptedMethods + acceptedCryptosuites.
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


    //§3.4.1: each query map MUST define a string type — a query entry without one is rejected.
    [TestMethod]
    public void RejectsQueryEntryMissingType()
    {
        const string json = """
        { "query": [{ "credentialQuery": { "reason": "no type here" } }] }
        """;

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(json, JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure);
    }


    //§3.4.1: query is REQUIRED and is "one or more" maps — an empty query array is rejected.
    [TestMethod]
    public void RejectsEmptyQueryArray()
    {
        VerifiablePresentationRequest request =
            VcalmPresentationRequestJsonParsing.Parse("""{ "query": [] }""", JsonOptions);

        Assert.AreEqual(VcalmParseFailure.Malformed, request.Failure);
    }


    //§3.4.1: a recognized-shape query map with an unknown type is an open-extension UnknownQuery, not
    //a parse failure (the query array is an extension point).
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


    //§3.4.4 (editor-unstable): the AuthorizationCapabilityQuery parses defensively — it is modeled,
    //never a conformance gate.
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


    //§3.4: a DCQL-typed query maps to the existing DcqlQuery model (mapped, not reimplemented).
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


    //§3.4.5.1: queries sharing a group value are ANDed — both must be satisfiable for the group to
    //succeed. With only one of the two credentials held, the AND-group is not satisfied.
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


    //§3.4.5.2: queries with different or missing group values are ORed — any matching alternative
    //satisfies the request.
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
        Assert.ContainsSingle(result.Groups.Where(g => g.IsSatisfied));
    }


    //Holder-side evaluation: a QueryByExample match selects the matching credential and the §3.4.2
    //requested field becomes the minimal disclosure path.
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


    //§3.4.2: an example field with an empty-string value requests the field with no value
    //expectation — any value satisfies it.
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


    //§3.4.2: a non-empty example field value constrains the disclosed value — a mismatching value
    //does not satisfy the query.
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


    //§3.4.2: acceptedIssuers filters by issuer — a credential from a non-accepted issuer does not
    //satisfy the query.
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


    //§3.4 DCQL co-equal type: a DCQL-typed query evaluates via DcqlEvaluator and selects the matching
    //VC-DM 2.0 credential, with the matched claim path as the minimal disclosure.
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


    //§3.4.3: a DIDAuthentication query is satisfied when the holder controls a DID of an accepted
    //method, independent of held credentials.
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


    //§3.4.3 acceptedCryptosuites: when the query constrains the authentication-proof cryptosuites, the
    //holder satisfies it only if it controls an accepted-method DID AND can sign with one of the
    //accepted cryptosuites ("the holder MUST choose [from acceptedCryptosuites] when generating the
    //authentication proof"). A constrained query with no demonstrable holder cryptosuite fails closed.
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
            Context = new Context { Contexts = [Context.Credentials20, AlumniContext] },
            Type = [CredentialConstants.VerifiableCredentialType, credentialType],
            Issuer = new Issuer { Id = issuer },
            CredentialSubject = [new CredentialSubject { AdditionalData = additionalData }]
        };
    }
}
