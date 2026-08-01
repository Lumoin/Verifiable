using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the sixteen serialisation-agnostic messages of clause 5.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> — that each message's required members are the ones its own clause makes
/// mandatory, that the closed hierarchy is exactly the eight operations' requests and responses, and that a
/// message returns every carrier it owns.
/// </summary>
/// <remarks>
/// <para>
/// The cardinality assertions are made through the compiler's own record of which members are required rather
/// than by reading the source: a member declared <c>required</c> carries an attribute the runtime can see, so the
/// test asserts what the type actually obliges a caller to state.
/// </para>
/// <para>
/// Two of the assertions are about places the document contradicts itself, and both are asserted as the reading
/// the library states: the evidence of a validation request is required although the reproduced schema marks it
/// optional, and the filter of a search request is optional although the reproduced schema marks it mandatory.
/// </para>
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "A payload built here is put into the message that owns it, whose own Dispose releases it; every message the tests build is disposed exactly once, either by a using or by the loop that walks the sixteen of them. Disposing a payload beside the message that owns it would return the same rented memory twice.")]
internal sealed class PreservationMessageTests
{
    /// <summary>The two member sets the evidence-versus-object tightening is asserted against.</summary>
    private static string[] EvidenceRequiredMembers { get; } = ["Content", "ContentForm", "FormatId"];

    /// <summary>The member set a preservation object obliges, which is the evidence's minus the format identifier.</summary>
    private static string[] ObjectRequiredMembers { get; } = ["Content", "ContentForm"];


    /// <summary>Every one of the sixteen message kinds is realised by exactly one message type, and no type shares a kind.</summary>
    [TestMethod]
    public void EveryMessageKindIsRealisedByExactlyOneMessageType()
    {
        IReadOnlyList<PreservationMessage> messages = EveryMessage();
        Assert.HasCount(16, messages, "Eight operations, one request and one response each.");

        List<PreservationMessageKind> kinds = messages.Select(message => message.Kind).ToList();
        Assert.HasCount(16, kinds.Distinct().ToList(), "No two messages share a kind.");
        Assert.DoesNotContain(PreservationMessageKind.NotEvaluated, kinds, "No message reads as the unset kind.");

        foreach(PreservationMessageKind kind in Enum.GetValues<PreservationMessageKind>())
        {
            if(kind == PreservationMessageKind.NotEvaluated)
            {
                continue;
            }

            Assert.Contains(kind, kinds, $"{kind} is declared but no message answers with it.");
        }

        foreach(PreservationMessage message in messages)
        {
            Assert.IsTrue(
                PreservationWellKnown.IsOperationName(message.OperationName),
                $"{message.Kind} states an operation name the document does not define.");
            message.Dispose();
        }
    }


    /// <summary>
    /// Requests and responses are exactly the two halves of the hierarchy, and every response carries the result
    /// component its own clause makes mandatory.
    /// </summary>
    [TestMethod]
    public void TheHierarchyIsEightRequestsAndEightResponsesAndEveryResponseCarriesAResult()
    {
        IReadOnlyList<PreservationMessage> messages = EveryMessage();

        List<PreservationMessage> requests = messages.Where(message => message is PreservationRequest).ToList();
        List<PreservationMessage> responses = messages.Where(message => message is PreservationResponse).ToList();

        Assert.HasCount(8, requests);
        Assert.HasCount(8, responses);

        foreach(PreservationMessage message in responses)
        {
            PreservationResponse response = (PreservationResponse)message;
            Assert.IsNotNull(response.Result);
            Assert.IsNotEmpty(response.Result.ResultMajor);
        }

        foreach(PreservationMessage message in messages)
        {
            message.Dispose();
        }
    }


    /// <summary>
    /// Each message obliges a caller to state exactly the members its own clause makes mandatory — the load-bearing
    /// half of "the model matches the specification's cardinalities".
    /// </summary>
    /// <param name="typeName">The message type whose required members are checked.</param>
    /// <param name="expectedRequiredMembers">The members the clause makes mandatory, as a comma-separated list.</param>
    [TestMethod]
    [DataRow(nameof(RetrieveInfoRequest), "", DisplayName = "clause 5.3.2.1: both elements optional")]
    [DataRow(nameof(RetrieveInfoResponse), "Result", DisplayName = "clause 5.3.2.2: the profiles are zero or more")]
    [DataRow(nameof(PreservePreservationObjectRequest), "ProfileIdentifier", DisplayName = "clause 5.3.3.1: the profile is mandatory and the objects are not")]
    [DataRow(nameof(PreservePreservationObjectResponse), "Result", DisplayName = "clause 5.3.3.2: the identifier is conditionally mandatory, which no type can state")]
    [DataRow(nameof(RetrievePreservationObjectRequest), "PreservationObjectId", DisplayName = "clause 5.3.4.1")]
    [DataRow(nameof(RetrievePreservationObjectResponse), "Result", DisplayName = "clause 5.3.4.2")]
    [DataRow(nameof(DeletePreservationObjectRequest), "PreservationObjectId", DisplayName = "clause 5.3.5.1")]
    [DataRow(nameof(DeletePreservationObjectResponse), "Result", DisplayName = "clause 5.3.5.2: the one response with no payload of its own")]
    [DataRow(nameof(UpdatePreservationObjectContainerRequest), "DeltaContainers,PreservationObjectId", DisplayName = "clause 5.3.6.1: one or more deltas")]
    [DataRow(nameof(UpdatePreservationObjectContainerResponse), "Result", DisplayName = "clause 5.3.6.2")]
    [DataRow(nameof(RetrieveTraceRequest), "PreservationObjectId", DisplayName = "clause 5.3.7.1")]
    [DataRow(nameof(RetrieveTraceResponse), "Result,Trace", DisplayName = "clause 5.3.7.2: the trace is mandatory")]
    [DataRow(nameof(ValidateEvidenceRequest), "Evidence", DisplayName = "clause 5.3.8.1: the prose makes the evidence mandatory")]
    [DataRow(nameof(ValidateEvidenceResponse), "Result", DisplayName = "clause 5.3.8.2: both payload members optional")]
    [DataRow(nameof(SearchRequest), "", DisplayName = "clause 5.3.9.1: the prose makes the filter optional")]
    [DataRow(nameof(SearchResponse), "Result", DisplayName = "clause 5.3.9.2")]
    public void EachMessageObligesTheMembersItsOwnClauseMakesMandatory(string typeName, string expectedRequiredMembers)
    {
        Type messageType = typeof(PreservationMessage).Assembly.GetTypes().Single(type => type.Name == typeName);
        string[] expected = expectedRequiredMembers.Length == 0
            ? []
            : [.. expectedRequiredMembers.Split(',').OrderBy(member => member, StringComparer.Ordinal)];

        Assert.AreSequenceEqual(expected, RequiredMembersOf(messageType), typeName);
    }


    /// <summary>
    /// The evidence component tightens what the object component leaves optional: a format identifier is
    /// mandatory on an evidence and not on an object, which is the one member the wire's inheritance overrides.
    /// </summary>
    [TestMethod]
    public void TheEvidenceComponentMakesTheFormatIdentifierMandatoryAndTheObjectComponentDoesNot()
    {
        Assert.Contains("FormatId", RequiredMembersOf(typeof(PreservationEvidence)));
        Assert.DoesNotContain("FormatId", RequiredMembersOf(typeof(PreservationObject)));

        Assert.AreSequenceEqual(EvidenceRequiredMembers, RequiredMembersOf(typeof(PreservationEvidence)));
        Assert.AreSequenceEqual(ObjectRequiredMembers, RequiredMembersOf(typeof(PreservationObject)));
    }


    /// <summary>
    /// A delta of an update request is a preservation object under another element name, because both syntaxes
    /// resolve the element to the payload component rather than to a type of its own.
    /// </summary>
    [TestMethod]
    public void ADeltaIsAPreservationObjectUnderAnotherElementName()
    {
        PropertyInfo deltas = typeof(UpdatePreservationObjectContainerRequest).GetProperty(nameof(UpdatePreservationObjectContainerRequest.DeltaContainers))!;
        Assert.AreEqual(typeof(IReadOnlyList<PreservationObject>), deltas.PropertyType);

        PropertyInfo submitted = typeof(PreservePreservationObjectRequest).GetProperty(nameof(PreservePreservationObjectRequest.PreservationObjects))!;
        Assert.AreEqual(deltas.PropertyType, submitted.PropertyType, "The same component carries both.");

        PropertyInfo report = typeof(ValidateEvidenceResponse).GetProperty(nameof(ValidateEvidenceResponse.ValidationReport))!;
        Assert.AreEqual(typeof(PreservationObject), report.PropertyType, "A validation report is carried as a preservation object too.");
    }


    /// <summary>The deletion response is the only message that adds no member of its own to the base component.</summary>
    [TestMethod]
    public void TheDeletionResponseIsTheOnlyMessageWithNoPayloadOfItsOwn()
    {
        static IReadOnlyList<string> OwnMembers(Type type) =>
        [
            .. type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Select(property => property.Name)
                .Where(name => name is not (nameof(PreservationMessage.Kind) or nameof(PreservationMessage.OperationName)))
                .OrderBy(name => name, StringComparer.Ordinal)
        ];

        Assert.IsEmpty(OwnMembers(typeof(DeletePreservationObjectResponse)));

        foreach(PreservationMessage message in EveryMessage())
        {
            if(message.Kind != PreservationMessageKind.DeletePreservationObjectResponse)
            {
                Assert.IsNotEmpty(OwnMembers(message.GetType()), $"{message.Kind} states members of its own.");
            }

            message.Dispose();
        }
    }


    /// <summary>
    /// Disposing a message returns every carrier the message owns — the payloads, the optional inputs and
    /// outputs, and the extensions a profile inside a response carries.
    /// </summary>
    [TestMethod]
    public void DisposingAMessageReturnsEveryCarrierItOwns()
    {
        using MeteredHousePool pool = new();

        PreservePreservationObjectRequest request = new()
        {
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects =
            [
                PreservationMessageSource.Object("first", pool.Pool),
                PreservationMessageSource.Object("second", pool.Pool)
            ],
            OptionalInputs = [PreservationMessageSource.OpaqueElement("<optional/>", pool.Pool)]
        };

        Assert.AreEqual(3, pool.RentedCount);
        Assert.AreEqual(3, pool.OutstandingCount);

        request.Dispose();
        Assert.AreEqual(0, pool.OutstandingCount, "A request returns its payloads and its optional inputs.");

        RetrieveInfoResponse response = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            Profiles = [PreservationMessageSource.Profile(extensions: [PreservationMessageSource.OpaqueElement("<extension/>", pool.Pool)])],
            OptionalOutputs = [PreservationMessageSource.OpaqueElement("<optional/>", pool.Pool)]
        };

        Assert.AreEqual(5, pool.RentedCount);
        Assert.AreEqual(2, pool.OutstandingCount);

        response.Dispose();
        Assert.AreEqual(0, pool.OutstandingCount, "A response reaches the extensions of every profile it carries.");

        using MeteredHousePool validationPool = new();
        ValidateEvidenceRequest validation = new()
        {
            Evidence = PreservationMessageSource.Evidence("evidence", validationPool.Pool),
            PreservationObjects = [PreservationMessageSource.Object("covered", validationPool.Pool)]
        };

        Assert.AreEqual(2, validationPool.OutstandingCount);
        validation.Dispose();
        Assert.AreEqual(0, validationPool.OutstandingCount, "A validation request owns both the evidence and the objects it came with.");
    }


    /// <summary>
    /// A payload carries the tag its kind states, so a carrier can be routed without being parsed again, and the
    /// message keeps the octets the caller stated rather than a view onto them.
    /// </summary>
    [TestMethod]
    public void EveryPayloadCarriesTheTagItsKindStates()
    {
        using PreservationObject preservationObject = PreservationMessageSource.Object("payload", BaseMemoryPool.Shared);
        using PreservationEvidence evidence = PreservationMessageSource.Evidence("evidence", BaseMemoryPool.Shared);
        using PreservationOpaqueElement opaque = PreservationMessageSource.OpaqueElement("<optional/>", BaseMemoryPool.Shared);

        Assert.AreEqual(PreservationTags.PreservationObject, preservationObject.Content.Tag);
        Assert.AreEqual(PreservationTags.PreservationEvidence, evidence.Content.Tag);
        Assert.AreEqual(PreservationTags.OpaqueElement, opaque.Content.Tag);

        Assert.AreEqual("payload".Length, preservationObject.Content.Length);
        Assert.AreEqual(PreservationContentForm.BinaryData, preservationObject.ContentForm);
    }


    /// <summary>
    /// The messages that carry a repeatable element default to an empty list rather than to nothing, so a caller
    /// that states none is not distinguishable from one that states an empty sequence — which is what the wire
    /// does too.
    /// </summary>
    [TestMethod]
    public void ARepeatableElementDefaultsToNoneRatherThanToNothing()
    {
        using PreservePreservationObjectRequest request = new() { ProfileIdentifier = "https://example.invalid/preservation/profile/1" };
        Assert.IsEmpty(request.PreservationObjects, "Clause 5.3.3.1.1 admits a submission with no object at all.");
        Assert.IsEmpty(request.OptionalInputs);
        Assert.IsNull(request.RequestId);

        using SearchResponse response = new() { Result = PreservationMessageSource.SuccessfulResult() };
        Assert.IsEmpty(response.PreservationObjectIds);
        Assert.IsEmpty(response.OptionalOutputs);

        using RetrieveTraceResponse trace = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            Trace = new PreservationTrace()
        };
        Assert.IsEmpty(trace.Trace.Events, "A trace with no events is how a service says it recorded none.");
    }


    /// <summary>The members a type obliges a caller to state, in ordinal order.</summary>
    /// <param name="type">The type to read.</param>
    /// <returns>The names of the required members, including those the base types declare.</returns>
    private static IReadOnlyList<string> RequiredMembersOf(Type type)
    {
        List<string> required = [];
        for(Type? current = type; current is not null; current = current.BaseType)
        {
            foreach(PropertyInfo property in current.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                if(property.GetCustomAttribute<RequiredMemberAttribute>() is not null)
                {
                    required.Add(property.Name);
                }
            }
        }

        return [.. required.Distinct(StringComparer.Ordinal).OrderBy(name => name, StringComparer.Ordinal)];
    }


    /// <summary>
    /// One instance of each of the sixteen messages, each stating exactly the members its own clause makes
    /// mandatory. The caller disposes them.
    /// </summary>
    /// <returns>The sixteen messages.</returns>
    private static IReadOnlyList<PreservationMessage> EveryMessage() =>
    [
        new RetrieveInfoRequest(),
        new RetrieveInfoResponse { Result = PreservationMessageSource.SuccessfulResult() },
        new PreservePreservationObjectRequest { ProfileIdentifier = "https://example.invalid/preservation/profile/1" },
        new PreservePreservationObjectResponse { Result = PreservationMessageSource.SuccessfulResult() },
        new RetrievePreservationObjectRequest { PreservationObjectId = "po-1" },
        new RetrievePreservationObjectResponse { Result = PreservationMessageSource.SuccessfulResult() },
        new DeletePreservationObjectRequest { PreservationObjectId = "po-1" },
        new DeletePreservationObjectResponse { Result = PreservationMessageSource.SuccessfulResult() },
        new UpdatePreservationObjectContainerRequest
        {
            PreservationObjectId = "po-1",
            DeltaContainers = [PreservationMessageSource.Object("delta", BaseMemoryPool.Shared)]
        },
        new UpdatePreservationObjectContainerResponse { Result = PreservationMessageSource.SuccessfulResult() },
        new RetrieveTraceRequest { PreservationObjectId = "po-1" },
        new RetrieveTraceResponse { Result = PreservationMessageSource.SuccessfulResult(), Trace = new PreservationTrace() },
        new ValidateEvidenceRequest { Evidence = PreservationMessageSource.Evidence("evidence", BaseMemoryPool.Shared) },
        new ValidateEvidenceResponse { Result = PreservationMessageSource.SuccessfulResult() },
        new SearchRequest(),
        new SearchResponse { Result = PreservationMessageSource.SuccessfulResult() }
    ];
}
