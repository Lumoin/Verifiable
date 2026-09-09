using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.Foundation;
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
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
    /// ETSI TS 119 511 V1.2.1</see> PRP-8.1-02, PRP-8.1-13, and
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> 512-5.3.2.1.1-1, 512-5.3.3.1.1-1, 512-5.3.6.1.1-1, 512-5.3.7.1.1-1,
    /// 512-5.3.8.1.1-1, 512-5.3.8.2-naming, 512-5.3.9.1.1-1.
    /// </remarks>
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
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> 512-5.3.1.1.2-1, 512-5.3.1.2.1-2.
    /// </remarks>
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
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
    /// ETSI TS 119 511 V1.2.1</see> PRP-8.1-05, PRP-8.1-06, PRP-8.1-07, PRP-8.1-08, and
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> 512-5.3.3.1.1-2, 512-5.3.3.1-note, 512-5.3.3.2.1-1, 512-5.3.4.1.1-1,
    /// 512-5.3.5.1.1-1, 512-5.3.6.1.1-2, 512-5.3.7.1.1-2, 512-5.3.7.2.1-1, 512-5.3.8.1.1-2, 512-5.3.9.1.1-2.
    /// </remarks>
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
        string[] expected = expectedRequiredMembers.Length == 0
            ? []
            : [.. expectedRequiredMembers.Split(',').OrderBy(member => member, StringComparer.Ordinal)];

        Assert.AreSequenceEqual(expected, RequiredMembersOf(typeName), typeName);
    }


    /// <summary>
    /// The evidence component tightens what the object component leaves optional: a format identifier is
    /// mandatory on an evidence and not on an object, which is the one member the wire's inheritance overrides.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> 512-5.4.4.1-1.
    /// </remarks>
    [TestMethod]
    public void TheEvidenceComponentMakesTheFormatIdentifierMandatoryAndTheObjectComponentDoesNot()
    {
        Assert.Contains("FormatId", RequiredMembersOf(nameof(PreservationEvidence)));
        Assert.DoesNotContain("FormatId", RequiredMembersOf(nameof(PreservationObject)));

        Assert.AreSequenceEqual(EvidenceRequiredMembers, RequiredMembersOf(nameof(PreservationEvidence)));
        Assert.AreSequenceEqual(ObjectRequiredMembers, RequiredMembersOf(nameof(PreservationObject)));
    }


    /// <summary>
    /// A delta of an update request is a preservation object under another element name, because both syntaxes
    /// resolve the element to the payload component rather than to a type of its own.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
    /// ETSI TS 119 511 V1.2.1</see> PRP-8.1-14, and
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> 512-5.3.6.1-strategies, 512-5.3.6.1.1-3, 512-5.3.6.1-disambiguation, 512-E.
    /// </remarks>
    [TestMethod]
    public void ADeltaIsAPreservationObjectUnderAnotherElementName()
    {
        string deltasType = PropertyTypeOf(nameof(UpdatePreservationObjectContainerRequest), nameof(UpdatePreservationObjectContainerRequest.DeltaContainers));
        Assert.AreEqual("IReadOnlyList<PreservationObject>", deltasType);

        string submittedType = PropertyTypeOf(nameof(PreservePreservationObjectRequest), nameof(PreservePreservationObjectRequest.PreservationObjects));
        Assert.AreEqual(deltasType, submittedType, "The same component carries both.");

        string reportType = PropertyTypeOf(nameof(ValidateEvidenceResponse), nameof(ValidateEvidenceResponse.ValidationReport));
        Assert.AreEqual("PreservationObject", reportType, "A validation report is carried as a preservation object too.");
    }


    /// <summary>The deletion response is the only message that adds no member of its own to the base component.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> 512-5.3.5.2-1.
    /// </remarks>
    [TestMethod]
    public void TheDeletionResponseIsTheOnlyMessageWithNoPayloadOfItsOwn()
    {
        Assert.IsEmpty(OwnPropertiesOf(nameof(DeletePreservationObjectResponse)));

        foreach(PreservationMessage message in EveryMessage())
        {
            if(message.Kind != PreservationMessageKind.DeletePreservationObjectResponse)
            {
                Assert.IsNotEmpty(OwnPropertiesOf(message.GetType().Name), $"{message.Kind} states members of its own.");
            }

            message.Dispose();
        }
    }


    /// <summary>
    /// Disposing a message returns every carrier the message owns — the payloads, the optional inputs and
    /// outputs, and the extensions a profile inside a response carries.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> 512-5.4.7.1-13. Each fixture (<c>request</c>, <c>response</c>,
    /// <c>validation</c>) is disposed explicitly, not via a <c>using</c> declaration, because the
    /// <see cref="MeteredHousePool.OutstandingCount"/> assertion immediately after each dispose call must see
    /// the carriers already returned; a <c>using</c> declaration would defer that release to the method's end.
    /// </remarks>
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
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> 512-binding-instants.
    /// </remarks>
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
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> 512-5.3.2.2.1-1, 512-5.3.3.1.1-3, 512-5.3.3.2.1-2, 512-5.3.4.2.1-2,
    /// 512-5.3.8.1.1-3, 512-5.3.9.2.1-1, 512-5.4.5.1-6.
    /// </remarks>
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


    /// <summary>The repository-relative path declaring the sixteen message types and their two base components.</summary>
    private const string PreservationMessagesPath = "src/Verifiable.Cryptography/Pki/PreservationMessages.cs";

    /// <summary>The repository-relative path declaring <see cref="PreservationObject"/> and <see cref="PreservationEvidence"/>.</summary>
    private const string PreservationComponentsPath = "src/Verifiable.Cryptography/Pki/PreservationComponents.cs";

    /// <summary>Matches a top-level <c>public sealed class</c> or <c>public sealed record</c> declaration and the base-type list following its colon, if any.</summary>
    private static Regex ClassOrRecordDeclarationPattern { get; } = new(
        @"(?m)^public sealed (?:class|record) (\w+)(?:\s*:\s*([^\r\n{]+))?",
        RegexOptions.Compiled);

    /// <summary>Matches a public instance property declaration (block- or expression-bodied), capturing its type and name.</summary>
    private static Regex PropertyDeclarationPattern { get; } = new(
        @"public\s+(?:required\s+)?(?:override\s+)?([\w<>\[\],\.\?]+)\s+(\w+)\s*(?:\{|=>)",
        RegexOptions.Compiled);

    /// <summary>Matches a public <see langword="required"/> instance property declaration, capturing its name.</summary>
    private static Regex RequiredPropertyDeclarationPattern { get; } = new(
        @"public\s+required\s+[\w<>\[\],\.\?]+\s+(\w+)\s*(?:\{|=>)",
        RegexOptions.Compiled);

    /// <summary>
    /// Every message and component type's own declaration span (its base-type list and its body text, up to
    /// the next top-level class/record declaration or end of file), keyed by type name, read from the two
    /// declaring files — a source scan standing in for reflection over the loaded types.
    /// </summary>
    private static Dictionary<string, (string BaseTypes, string Body)> MessageAndComponentClassSpans { get; } = BuildClassSpans();


    /// <summary>Builds <see cref="MessageAndComponentClassSpans"/> from the two declaring files.</summary>
    /// <returns>Every declared type's base-type list and body text, keyed by type name.</returns>
    private static Dictionary<string, (string BaseTypes, string Body)> BuildClassSpans()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();
        Dictionary<string, (string BaseTypes, string Body)> spans = SpansOf(File.ReadAllText(Path.Combine(repositoryRoot, PreservationMessagesPath)));
        foreach((string name, (string baseTypes, string body)) in SpansOf(File.ReadAllText(Path.Combine(repositoryRoot, PreservationComponentsPath))))
        {
            spans[name] = (baseTypes, body);
        }

        return spans;


        static Dictionary<string, (string BaseTypes, string Body)> SpansOf(string text)
        {
            List<(int Index, string Name, string BaseTypes)> declarations =
            [
                .. ClassOrRecordDeclarationPattern.Matches(text)
                    .Select(static m => (m.Index, Name: m.Groups[1].Value, BaseTypes: m.Groups[2].Success ? m.Groups[2].Value : string.Empty))
            ];

            Dictionary<string, (string BaseTypes, string Body)> result = [];
            for(int i = 0; i < declarations.Count; ++i)
            {
                int start = declarations[i].Index;
                int end = i + 1 < declarations.Count ? declarations[i + 1].Index : text.Length;
                result[declarations[i].Name] = (declarations[i].BaseTypes, text[start..end]);
            }

            return result;
        }
    }


    /// <summary>The members a type obliges a caller to state, in ordinal order — read from its own declaring
    /// file rather than by reflection over the loaded type: every <see langword="required"/> property this
    /// type's own span declares, plus <c>Result</c> when the type extends <see cref="PreservationResponse"/>,
    /// the one required member that base component declares.</summary>
    /// <param name="typeName">The type to read.</param>
    /// <returns>The names of the required members, including the one the response base type declares.</returns>
    private static IReadOnlyList<string> RequiredMembersOf(string typeName)
    {
        (string baseTypes, string body) = MessageAndComponentClassSpans[typeName];
        List<string> required = [.. RequiredPropertyDeclarationPattern.Matches(body).Select(static m => m.Groups[1].Value)];

        if(baseTypes.Contains(nameof(PreservationResponse), StringComparison.Ordinal))
        {
            required.Add(nameof(PreservationResponse.Result));
        }

        return [.. required.Distinct(StringComparer.Ordinal).OrderBy(static name => name, StringComparer.Ordinal)];
    }


    /// <summary>The type text a property declares, from its own declaring type's span, with a trailing nullable-reference <c>?</c> stripped.</summary>
    /// <param name="typeName">The declaring type.</param>
    /// <param name="propertyName">The property to read.</param>
    /// <returns>The declared type text.</returns>
    private static string PropertyTypeOf(string typeName, string propertyName)
    {
        (_, string body) = MessageAndComponentClassSpans[typeName];
        Match match = PropertyDeclarationPattern.Matches(body).Single(m => m.Groups[2].Value == propertyName);

        return match.Groups[1].Value.TrimEnd('?');
    }


    /// <summary>The properties a type's own span declares, excluding the base <see cref="PreservationMessage.Kind"/>/<see cref="PreservationMessage.OperationName"/> overrides every message restates.</summary>
    /// <param name="typeName">The type to read.</param>
    /// <returns>The type's own declared property names, in ordinal order.</returns>
    private static IReadOnlyList<string> OwnPropertiesOf(string typeName)
    {
        (_, string body) = MessageAndComponentClassSpans[typeName];

        return [.. PropertyDeclarationPattern.Matches(body)
            .Select(static m => m.Groups[2].Value)
            .Where(static name => name is not (nameof(PreservationMessage.Kind) or nameof(PreservationMessage.OperationName)))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static name => name, StringComparer.Ordinal)];
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
