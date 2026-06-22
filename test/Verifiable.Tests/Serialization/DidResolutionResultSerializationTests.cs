using System;
using System.Text.Json;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Shape and round-trip tests for the W3C DID Resolution Result and DID URL Dereferencing Result envelope
/// converters (<see cref="Verifiable.Json.Converters.DidResolutionResultConverter"/>,
/// <see cref="Verifiable.Json.Converters.DidDereferencingResultConverter"/>,
/// <see cref="Verifiable.Json.Converters.DidProblemDetailsConverter"/>) driven directly through the
/// serializer (no HTTP). The envelope member names, the failure-case <c>null</c> document and empty document
/// metadata, the RFC 9457 null-omission of the problem-details optional members, and the structural
/// round-trip of both result kinds are asserted against the spec's envelope shape.
/// </summary>
[TestClass]
internal sealed class DidResolutionResultSerializationTests
{
    private const string SubjectDid = "did:example:123";

    private static JsonSerializerOptions Options { get; } = TestSetup.DefaultSerializationOptions;


    [TestMethod]
    public void SuccessEnvelopeCarriesDocumentAndMetadata()
    {
        DidResolutionResult result = DidResolutionResult.Success(
            NewDocument(SubjectDid),
            new DidDocumentMetadata { VersionId = "1-abc" },
            contentType: "application/did+json");

        string json = JsonSerializerExtensions.Serialize(result, Options);

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;

        Assert.AreEqual(SubjectDid, root.GetProperty("didDocument").GetProperty("id").GetString(),
            "The success envelope's didDocument MUST carry the resolved DID id.");
        Assert.AreEqual("application/did+json", root.GetProperty("didResolutionMetadata").GetProperty("contentType").GetString(),
            "The success envelope's didResolutionMetadata MUST carry the contentType.");
        Assert.AreEqual("1-abc", root.GetProperty("didDocumentMetadata").GetProperty("versionId").GetString(),
            "The success envelope's didDocumentMetadata MUST carry the versionId.");
    }


    [TestMethod]
    public void FailureEnvelopeOmitsDocumentAndUnsetProblemMembers()
    {
        DidResolutionResult result = DidResolutionResult.Failure(DidResolutionErrors.NotFound);

        string json = JsonSerializerExtensions.Serialize(result, Options);

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;

        Assert.AreEqual(JsonValueKind.Null, root.GetProperty("didDocument").ValueKind,
            "A failed resolution MUST write didDocument as JSON null.");
        Assert.AreEqual(JsonValueKind.Object, root.GetProperty("didDocumentMetadata").ValueKind,
            "A failed resolution MUST write didDocumentMetadata as an object.");
        Assert.AreEqual(0, CountMembers(root.GetProperty("didDocumentMetadata")),
            "A failed resolution's didDocumentMetadata MUST serialize to an empty object.");

        JsonElement metadata = root.GetProperty("didResolutionMetadata");

        //The error field MUST be the lowerCamelCase string code; the RFC 9457 object is carried separately in
        //problemDetails (did:webvh v1.0, error envelope).
        Assert.AreEqual(JsonValueKind.String, metadata.GetProperty("error").ValueKind,
            "The error field MUST be the string error code, not the RFC 9457 object.");
        Assert.AreEqual("notFound", metadata.GetProperty("error").GetString(),
            "A NOT_FOUND failure MUST carry the 'notFound' error code.");

        JsonElement problemDetails = metadata.GetProperty("problemDetails");
        Assert.AreEqual(DidErrorTypes.NotFound.AbsoluteUri, problemDetails.GetProperty("type").GetString(),
            "The problemDetails MUST carry the W3C NOT_FOUND type URI.");
        Assert.IsTrue(problemDetails.TryGetProperty("title", out _),
            "NOT_FOUND sets a Title, so problemDetails MUST carry the title member.");
        Assert.IsFalse(problemDetails.TryGetProperty("status", out _),
            "An unset Status MUST be omitted from problemDetails.");
        Assert.IsFalse(problemDetails.TryGetProperty("detail", out _),
            "An unset Detail MUST be omitted from problemDetails.");
        Assert.IsFalse(problemDetails.TryGetProperty("instance", out _),
            "An unset Instance MUST be omitted from problemDetails.");
    }


    [TestMethod]
    public void ProblemDetailsWritesAllSetMembersAndTypesStatusAsNumber()
    {
        DidProblemDetails populated = new(
            DidErrorTypes.NotFound,
            Title: "t",
            Status: 404,
            Detail: "d",
            Instance: new Uri("urn:x"));

        DidResolutionResult result = DidResolutionResult.Failure(populated);

        string json = JsonSerializerExtensions.Serialize(result, Options);

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement metadata = document.RootElement.GetProperty("didResolutionMetadata");

        Assert.AreEqual("notFound", metadata.GetProperty("error").GetString(),
            "The error field MUST be the string code.");

        JsonElement problemDetails = metadata.GetProperty("problemDetails");
        Assert.AreEqual(DidErrorTypes.NotFound.AbsoluteUri, problemDetails.GetProperty("type").GetString());
        Assert.AreEqual("t", problemDetails.GetProperty("title").GetString());
        Assert.AreEqual(JsonValueKind.Number, problemDetails.GetProperty("status").ValueKind,
            "The RFC 9457 status MUST be a JSON number, not a string.");
        Assert.AreEqual(404, problemDetails.GetProperty("status").GetInt32());
        Assert.AreEqual("d", problemDetails.GetProperty("detail").GetString());
        Assert.AreEqual("urn:x", problemDetails.GetProperty("instance").GetString());
    }


    [TestMethod]
    public void ProblemDetailsWithOnlyTypeWritesOnlyType()
    {
        DidProblemDetails typeOnly = new(DidErrorTypes.InvalidDid);

        DidResolutionResult result = DidResolutionResult.Failure(typeOnly);

        string json = JsonSerializerExtensions.Serialize(result, Options);

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement metadata = document.RootElement.GetProperty("didResolutionMetadata");

        Assert.AreEqual("invalidDid", metadata.GetProperty("error").GetString(),
            "The error field MUST be the string code.");

        JsonElement problemDetails = metadata.GetProperty("problemDetails");
        Assert.AreEqual(DidErrorTypes.InvalidDid.AbsoluteUri, problemDetails.GetProperty("type").GetString());
        Assert.AreEqual(1, CountMembers(problemDetails),
            "A bare problem-details (type only) MUST write ONLY the type member in problemDetails.");
    }


    /// <summary>The metadata error envelope round-trips: the string code and the separate problemDetails object
    /// reconstruct the same <see cref="DidProblemDetails"/> (by type) on read.</summary>
    [TestMethod]
    public void ErrorEnvelopeRoundTripsCodeAndProblemDetails()
    {
        DidProblemDetails populated = new(
            DidErrorTypes.InvalidDid,
            Title: "Invalid DID",
            Detail: "Parse error.");

        DidResolutionResult result = DidResolutionResult.Failure(populated);

        string json = JsonSerializerExtensions.Serialize(result, Options);
        DidResolutionResult roundTripped = JsonSerializerExtensions.Deserialize<DidResolutionResult>(json, Options)!;

        Assert.AreEqual(DidErrorTypes.InvalidDid, roundTripped.ResolutionMetadata.Error?.Type,
            "The error type MUST survive the string-code + problemDetails round-trip.");
        Assert.AreEqual("Parse error.", roundTripped.ResolutionMetadata.Error?.Detail,
            "The problemDetails Detail MUST survive the round-trip.");
    }


    [TestMethod]
    public void ResolutionResultRoundTrips()
    {
        DidResolutionResult result = DidResolutionResult.Success(
            NewDocument(SubjectDid),
            new DidDocumentMetadata { VersionId = "1-abc" },
            contentType: "application/did+json");

        string json = JsonSerializerExtensions.Serialize(result, Options);
        DidResolutionResult roundTripped = JsonSerializerExtensions.Deserialize<DidResolutionResult>(json, Options)!;

        Assert.AreEqual(SubjectDid, roundTripped.Document?.Id?.Id,
            "The resolved DID id MUST survive a serialization round-trip.");
        Assert.AreEqual("application/did+json", roundTripped.ResolutionMetadata.ContentType,
            "The resolution-metadata contentType MUST survive a serialization round-trip.");
    }


    [TestMethod]
    public void DereferencingResultMemberNamesAndDocumentRoundTrip()
    {
        DidDereferencingResult result = DidDereferencingResult.Success(
            NewDocument(SubjectDid),
            contentType: "application/did+json");

        string json = JsonSerializerExtensions.Serialize(result, Options);

        using(JsonDocument document = JsonDocument.Parse(json))
        {
            JsonElement root = document.RootElement;
            Assert.IsTrue(root.TryGetProperty("contentStream", out _),
                "The dereferencing envelope MUST use the 'contentStream' member name.");
            Assert.IsTrue(root.TryGetProperty("dereferencingMetadata", out _),
                "The dereferencing envelope MUST use the 'dereferencingMetadata' member name.");
            Assert.AreEqual(SubjectDid, root.GetProperty("contentStream").GetProperty("id").GetString(),
                "The contentStream MUST carry the dereferenced DID document id.");
        }

        DidDereferencingResult roundTripped = JsonSerializerExtensions.Deserialize<DidDereferencingResult>(json, Options)!;

        Assert.IsInstanceOfType<DidDocument>(roundTripped.ContentStream,
            "A DID-document content stream MUST round-trip back as a DidDocument.");
        Assert.AreEqual(SubjectDid, ((DidDocument)roundTripped.ContentStream!).Id?.Id,
            "The round-tripped contentStream document MUST carry the original DID id.");
    }


    //A minimal DID document carrying an @context and an id, the two members the dereferencing reader keys on
    //to materialize the content stream back as a DidDocument.
    private static DidDocument NewDocument(string id)
    {
        return new DidDocument
        {
            Context = new Context { Contexts = [Context.DidCore10] },
            Id = new GenericDidMethod(id)
        };
    }


    private static int CountMembers(JsonElement objectElement)
    {
        int count = 0;
        foreach(JsonProperty _ in objectElement.EnumerateObject())
        {
            count++;
        }

        return count;
    }
}
