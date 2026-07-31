using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the seams and the bounds of the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> — the per-operation delegates with their context and result, and the bounds a
/// peer applies to a message it did not build.
/// </summary>
/// <remarks>
/// <para>
/// The bounds are where the obligations no type can carry are checked: the "at least one" cardinalities, the
/// media type a payload has to state when it states no format, the one-or-two policies of a profile, and the
/// retention period a temporary-storage profile owes. Each of them is exercised in both directions, because a
/// check that only ever sees conformant input has not been shown to refuse anything.
/// </para>
/// <para>
/// The seam test wires a stand-in service to the delegates and calls it, which is what shows the vocabulary is
/// composable at all: the seam carries plain records, the transport is nowhere in sight, and the result owns the
/// response it carries.
/// </para>
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "A payload built here is put into the message that owns it and a profile stating one departure is a record copy sharing the carriers of the instance it was copied from; exactly one instance of each carrier set is disposed — the message or the copy actually put under test, held in a using — and disposing the other as well would return the same rented memory twice.")]
internal sealed class PreservationSeamTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = default!;


    /// <summary>A message stating everything its clause requires and nothing beyond a bound is admitted.</summary>
    [TestMethod]
    public void AConformantMessageIsInsideEveryBound()
    {
        using PreservePreservationObjectRequest request = new()
        {
            RequestId = "request-1",
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects = [PreservationMessageSource.Object("payload", BaseMemoryPool.Shared)],
            OptionalInputs = [PreservationMessageSource.OpaqueElement("<optional/>", BaseMemoryPool.Shared, "an-input")]
        };

        Assert.AreEqual(
            PreservationMessageStatus.WithinBounds,
            PreservationMessageBounds.State(request, PreservationMessageLimits.Conformant));

        using RetrieveInfoResponse response = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            Profiles = [PreservationMessageSource.Profile()]
        };

        Assert.AreEqual(
            PreservationMessageStatus.WithinBounds,
            PreservationMessageBounds.State(response, PreservationMessageLimits.Conformant));
    }


    /// <summary>
    /// A payload states either a format identifier or a media type, and one that states neither is refused —
    /// clause 5.4.5.1's own obligation, which is about the value rather than about the shape.
    /// </summary>
    [TestMethod]
    public void APayloadStatingNeitherAFormatNorAMediaTypeIsRefused()
    {
        using PreservePreservationObjectRequest neither = new()
        {
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects = [PreservationMessageSource.Object("payload", BaseMemoryPool.Shared, formatId: null)]
        };

        Assert.AreEqual(
            PreservationMessageStatus.MediaTypeAbsent,
            PreservationMessageBounds.State(neither, PreservationMessageLimits.Conformant));

        using PreservePreservationObjectRequest mediaTypeOnly = new()
        {
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects = [PreservationMessageSource.Object("payload", BaseMemoryPool.Shared, formatId: null, mimeType: "application/octet-stream")]
        };

        Assert.AreEqual(
            PreservationMessageStatus.WithinBounds,
            PreservationMessageBounds.State(mediaTypeOnly, PreservationMessageLimits.Conformant),
            "A media type on its own satisfies the obligation.");
    }


    /// <summary>A payload whose content form has not been stated is refused rather than read as either alternative.</summary>
    [TestMethod]
    public void APayloadWithNoStatedContentFormIsRefused()
    {
        using PreservePreservationObjectRequest request = new()
        {
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects =
            [
                PreservationMessageSource.Object("payload", BaseMemoryPool.Shared, contentForm: PreservationContentForm.NotEvaluated)
            ]
        };

        Assert.AreEqual(
            PreservationMessageStatus.ContentFormNotStated,
            PreservationMessageBounds.State(request, PreservationMessageLimits.Conformant));
    }


    /// <summary>An update request stating no delta at all is refused: its clause requires one or more.</summary>
    [TestMethod]
    public void AnUpdateStatingNoDeltaIsRefused()
    {
        using UpdatePreservationObjectContainerRequest empty = new()
        {
            PreservationObjectId = "po-1",
            DeltaContainers = []
        };

        Assert.AreEqual(
            PreservationMessageStatus.RequiredValueAbsent,
            PreservationMessageBounds.State(empty, PreservationMessageLimits.Conformant));

        using UpdatePreservationObjectContainerRequest stated = new()
        {
            PreservationObjectId = "po-1",
            DeltaContainers = [PreservationMessageSource.Object("delta", BaseMemoryPool.Shared)]
        };

        Assert.AreEqual(
            PreservationMessageStatus.WithinBounds,
            PreservationMessageBounds.State(stated, PreservationMessageLimits.Conformant));
    }


    /// <summary>
    /// A profile owes at least one operation, one goal and one evidence format, one or two policies, and — when
    /// it announces temporary storage — an evidence retention period.
    /// </summary>
    [TestMethod]
    public void AProfileOwesTheCardinalitiesItsOwnClauseStates()
    {
        using PreservationProfile noGoal = PreservationMessageSource.Profile() with { PreservationGoals = [] };
        Assert.AreEqual(PreservationMessageStatus.RequiredValueAbsent, StateOfProfile(noGoal));

        using PreservationProfile noPolicy = PreservationMessageSource.Profile() with { Policies = [] };
        Assert.AreEqual(PreservationMessageStatus.PolicyCountNotStated, StateOfProfile(noPolicy));

        using PreservationProfile threePolicies = PreservationMessageSource.Profile() with
        {
            Policies =
            [
                new PreservationPolicyReference { PolicyType = PreservationWellKnown.PreservationEvidencePolicyType },
                new PreservationPolicyReference { PolicyType = PreservationWellKnown.SignatureValidationPolicyType },
                new PreservationPolicyReference { PolicyType = PreservationWellKnown.PreservationEvidencePolicyType }
            ]
        };
        Assert.AreEqual(PreservationMessageStatus.PolicyCountNotStated, StateOfProfile(threePolicies), "Clause 5.4.7.1 admits one policy or two.");

        using PreservationProfile temporaryWithoutRetention = PreservationMessageSource.Profile(storageModel: PreservationWellKnown.WithTemporaryStorageModel);
        Assert.AreEqual(PreservationMessageStatus.RetentionPeriodAbsent, StateOfProfile(temporaryWithoutRetention));

        using PreservationProfile temporaryWithRetention = PreservationMessageSource.Profile(
            storageModel: PreservationWellKnown.WithTemporaryStorageModel,
            retentionPeriod: "P10Y");
        Assert.AreEqual(PreservationMessageStatus.WithinBounds, StateOfProfile(temporaryWithRetention));

        using PreservationProfile permanentWithoutRetention = PreservationMessageSource.Profile(storageModel: PreservationWellKnown.WithStorageModel);
        Assert.AreEqual(PreservationMessageStatus.WithinBounds, StateOfProfile(permanentWithoutRetention), "Only a temporary-storage profile owes the period.");
    }


    /// <summary>Each numeric bound refuses what lies beyond it, and names what it refused.</summary>
    [TestMethod]
    public void EachNumericBoundRefusesWhatLiesBeyondIt()
    {
        PreservationMessageLimits tight = new()
        {
            MaximumPreservationObjects = 1,
            MaximumPayloadByteLength = 4,
            MaximumIdentifierLength = 64,
            MaximumVersionIdentifiers = 1,
            MaximumRelatedObjectReferences = 1,
            MaximumProfiles = 0,
            MaximumTraceEvents = 1,
            MaximumFilterLength = 4,
            MaximumOpaqueElements = 0,
            MaximumOpaqueElementByteLength = 1,
            MaximumIdentifiers = 1
        };

        using PreservePreservationObjectRequest tooMany = new()
        {
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects =
            [
                PreservationMessageSource.Object("a", BaseMemoryPool.Shared),
                PreservationMessageSource.Object("b", BaseMemoryPool.Shared)
            ]
        };
        Assert.AreEqual(PreservationMessageStatus.TooManyPreservationObjects, PreservationMessageBounds.State(tooMany, tight));

        using PreservePreservationObjectRequest tooLarge = new()
        {
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects = [PreservationMessageSource.Object("far too long", BaseMemoryPool.Shared)]
        };
        Assert.AreEqual(PreservationMessageStatus.PayloadTooLarge, PreservationMessageBounds.State(tooLarge, tight));

        using RetrieveTraceRequest longIdentifier = new()
        {
            PreservationObjectId = new string('p', tight.MaximumIdentifierLength + 1)
        };
        Assert.AreEqual(PreservationMessageStatus.IdentifierTooLong, PreservationMessageBounds.State(longIdentifier, tight));

        using RetrievePreservationObjectRequest tooManyVersions = new()
        {
            PreservationObjectId = "po-1",
            VersionIds = ["v1", "v2"]
        };
        Assert.AreEqual(PreservationMessageStatus.TooManyVersionIdentifiers, PreservationMessageBounds.State(tooManyVersions, tight));

        using RetrieveInfoResponse tooManyProfiles = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            Profiles = [PreservationMessageSource.Profile()]
        };
        Assert.AreEqual(PreservationMessageStatus.TooManyProfiles, PreservationMessageBounds.State(tooManyProfiles, tight));

        using RetrieveTraceResponse tooManyEvents = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            Trace = new PreservationTrace
            {
                Events =
                [
                    Event("PreservePO"),
                    Event("RetrievePO")
                ]
            }
        };
        Assert.AreEqual(PreservationMessageStatus.TooManyTraceEvents, PreservationMessageBounds.State(tooManyEvents, tight));

        using SearchRequest longFilter = new() { Filter = "poid=1" };
        Assert.AreEqual(PreservationMessageStatus.FilterTooLong, PreservationMessageBounds.State(longFilter, tight));

        using SearchRequest tooManyInputs = new()
        {
            OptionalInputs = [PreservationMessageSource.OpaqueElement("<optional/>", BaseMemoryPool.Shared)]
        };
        Assert.AreEqual(PreservationMessageStatus.TooManyOpaqueElements, PreservationMessageBounds.State(tooManyInputs, tight));

        PreservationMessageLimits oneElement = tight with { MaximumOpaqueElements = 1 };
        using SearchRequest largeInput = new()
        {
            OptionalInputs = [PreservationMessageSource.OpaqueElement("<optional/>", BaseMemoryPool.Shared)]
        };
        Assert.AreEqual(PreservationMessageStatus.OpaqueElementTooLarge, PreservationMessageBounds.State(largeInput, oneElement));

        using PreservePreservationObjectRequest tooManyReferences = new()
        {
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects =
            [
                PreservationMessageSource.Object("a", BaseMemoryPool.Shared) with { RelatedObjects = ["a", "b"] }
            ]
        };
        Assert.AreEqual(PreservationMessageStatus.TooManyRelatedObjectReferences, PreservationMessageBounds.State(tooManyReferences, tight));

        //A search response's identifier list is repeated without limit in the specification's own cardinality
        //(clause 5.10, POID 0..unbounded), so the count bound is this library's, and without one the whole
        //identifier-list path was bound only per element — a list of any length answered WithinBounds however
        //tight every other bound was set.
        using SearchResponse tooManyResults = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            PreservationObjectIds = ["po-1", "po-2"]
        };
        Assert.AreEqual(PreservationMessageStatus.TooManyIdentifiers, PreservationMessageBounds.State(tooManyResults, tight));

        using SearchResponse withinResults = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            PreservationObjectIds = ["po-1"]
        };
        Assert.AreEqual(PreservationMessageStatus.WithinBounds, PreservationMessageBounds.State(withinResults, tight));

        //The same bound reaches the other repeated identifier-valued elements, which is what makes it a
        //completeness bound rather than one patched arm: a profile's preservation goals are one such list.
        using RetrieveInfoResponse tooManyGoals = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            Profiles = [PreservationMessageSource.Profile() with { PreservationGoals = ["goal-1", "goal-2"] }]
        };
        Assert.AreEqual(
            PreservationMessageStatus.TooManyIdentifiers,
            PreservationMessageBounds.State(tooManyGoals, tight with { MaximumProfiles = 1 }));

        //Builds one event of a trace, whose three mandatory members are what the bound is checked against.
        static PreservationEvent Event(string operation) => new()
        {
            Time = new DateTimeOffset(2026, 7, 31, 12, 0, 0, TimeSpan.Zero),
            Subject = "a",
            Operation = operation
        };
    }


    /// <summary>The bounds are a pure function of the message and the limits: the same inputs answer the same, twice.</summary>
    [TestMethod]
    public void TheBoundsAreAPureFunctionOfTheirInputs()
    {
        using RetrievePreservationObjectRequest request = new()
        {
            PreservationObjectId = "po-1",
            VersionIds = [PreservationWellKnown.AllVersionsIdentifier]
        };

        PreservationMessageStatus first = PreservationMessageBounds.State(request, PreservationMessageLimits.Conformant);
        PreservationMessageStatus second = PreservationMessageBounds.State(request, PreservationMessageLimits.Conformant);

        Assert.AreEqual(PreservationMessageStatus.WithinBounds, first);
        Assert.AreEqual(first, second);

        _ = Assert.Throws<ArgumentNullException>(() => PreservationMessageBounds.State(null!, PreservationMessageLimits.Conformant));
        _ = Assert.Throws<ArgumentNullException>(() => PreservationMessageBounds.State(request, null!));
    }


    /// <summary>A result carries the response only on success, and refuses to be built as a failure that succeeded.</summary>
    [TestMethod]
    public void AResultCarriesTheResponseOnlyOnSuccess()
    {
        SearchResponse response = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            PreservationObjectIds = ["po-1"]
        };

        using PreservationOperationResult<SearchResponse> succeeded = PreservationOperationResult<SearchResponse>.Succeeded(response);
        Assert.IsTrue(succeeded.IsSucceeded);
        Assert.AreEqual(PreservationOperationOutcome.Succeeded, succeeded.Outcome);
        Assert.AreSame(response, succeeded.Response);
        Assert.IsNull(succeeded.FailureReason);

        using PreservationOperationResult<SearchResponse> failed = PreservationOperationResult<SearchResponse>.Failed(
            PreservationOperationOutcome.NoPermission,
            "the client may not search");
        Assert.IsFalse(failed.IsSucceeded);
        Assert.IsNull(failed.Response);
        Assert.IsNotEmpty(failed.FailureReason!);
        Assert.AreEqual(
            PreservationResultWellKnown.NoPermission,
            PreservationResultWellKnown.ResultMinorFromOutcome(failed.Outcome),
            "The outcome states which code the response reports.");

        _ = Assert.Throws<ArgumentNullException>(() => PreservationOperationResult<SearchResponse>.Succeeded(null!));
        _ = Assert.Throws<ArgumentException>(() => PreservationOperationResult<SearchResponse>.Failed(PreservationOperationOutcome.Succeeded, "not a failure"));

        PreservationOperationResult<SearchResponse> unset = new() { Outcome = default };
        Assert.IsFalse(unset.IsSucceeded, "A result whose outcome has not been computed does not read as a success.");
    }


    /// <summary>Disposing a result returns every carrier the response it owns carries.</summary>
    [TestMethod]
    public void DisposingAResultReturnsTheResponsesCarriers()
    {
        using PreservationMessageSource.CountingMemoryPool pool = new();

        RetrievePreservationObjectResponse response = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(PreservationResultWellKnown.RequestOnlyPartlySuccessful),
            PreservationObjects = [PreservationMessageSource.Object("payload", pool)]
        };

        PreservationOperationResult<RetrievePreservationObjectResponse> result =
            PreservationOperationResult<RetrievePreservationObjectResponse>.Succeeded(response);

        Assert.AreEqual(1, pool.OutstandingCount);
        result.Dispose();
        Assert.AreEqual(0, pool.OutstandingCount);

        using PreservationOperationResult<RetrievePreservationObjectResponse> failure =
            PreservationOperationResult<RetrievePreservationObjectResponse>.Failed(PreservationOperationOutcome.UnknownPreservationObjectIdentifier, "no such object");
        failure.Dispose();
        Assert.AreEqual(0, pool.OutstandingCount, "A failed result owns nothing to return.");
    }


    /// <summary>A context defaults to the conformant bounds and carries the request the caller still owns.</summary>
    [TestMethod]
    public void AContextDefaultsToTheConformantBounds()
    {
        using SearchRequest request = new() { Filter = "poid=1" };
        PreservationOperationContext<SearchRequest> context = new() { Request = request };

        Assert.AreSame(PreservationMessageLimits.Conformant, context.Limits);
        Assert.AreSame(request, context.Request);

        PreservationOperationContext<SearchRequest> narrower = context with { Limits = new PreservationMessageLimits { MaximumFilterLength = 2 } };
        Assert.AreEqual(2, narrower.Limits.MaximumFilterLength);
        Assert.AreSame(request, narrower.Request, "The bounds vary per call; the request does not move.");
    }


    /// <summary>
    /// The seams compose: a stand-in service answers two of the eight operations through the delegate types, one
    /// with a response and one with a refusal, and neither the seam nor the messages mention a transport.
    /// </summary>
    [TestMethod]
    public async Task AStandInServiceAnswersThroughTheOperationSeams()
    {
        PreservePreservationObjectDelegate preserve = static (context, pool, cancellationToken) =>
        {
            PreservationMessageStatus status = PreservationMessageBounds.State(context.Request, context.Limits);
            if(status != PreservationMessageStatus.WithinBounds)
            {
                return ValueTask.FromResult(PreservationOperationResult<PreservePreservationObjectResponse>.Failed(
                    PreservationOperationOutcome.ParameterError,
                    status.ToString()));
            }

            PreservePreservationObjectResponse response = new()
            {
                Result = PreservationMessageSource.SuccessfulResult(),
                RequestId = context.Request.RequestId,
                PreservationObjectId = "po-1"
            };

            return ValueTask.FromResult(PreservationOperationResult<PreservePreservationObjectResponse>.Succeeded(response));
        };

        SearchDelegate search = static (context, pool, cancellationToken) =>
            ValueTask.FromResult(PreservationOperationResult<SearchResponse>.Failed(
                PreservationOperationOutcome.NotSupported,
                "this service publishes no query language"));

        using PreservePreservationObjectRequest submission = new()
        {
            RequestId = "request-1",
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects = [PreservationMessageSource.Object("payload", BaseMemoryPool.Shared)]
        };

        using PreservationOperationResult<PreservePreservationObjectResponse> preserved = await preserve(
            new PreservationOperationContext<PreservePreservationObjectRequest> { Request = submission },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsTrue(preserved.IsSucceeded);
        Assert.AreEqual("po-1", preserved.Response!.PreservationObjectId);
        Assert.AreEqual("request-1", preserved.Response.RequestId, "Clause 5.3.1.1 requires the identifier to come back.");

        using SearchRequest query = new() { Filter = "poid=1" };
        using PreservationOperationResult<SearchResponse> searched = await search(
            new PreservationOperationContext<SearchRequest> { Request = query },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsFalse(searched.IsSucceeded);
        Assert.AreEqual(
            PreservationResultWellKnown.NotSupported,
            PreservationResultWellKnown.ResultMinorFromOutcome(searched.Outcome));
        Assert.IsTrue(
            PreservationResultWellKnown.IsResultMinorStatedForOperation(
                PreservationWellKnown.SearchOperation,
                PreservationResultWellKnown.ResultMinorFromOutcome(searched.Outcome)),
            "A refusal states a code the operation's own clause enumerates.");
    }


    /// <summary>
    /// The serialisation seams carry their contexts and results the way the other delegate seams of this
    /// namespace do: a parse states what it expects the octets to be, and an encoding states which syntax it
    /// wants.
    /// </summary>
    [TestMethod]
    public async Task TheSerialisationSeamsCarryTheirContextsAndRefusalsAsStatuses()
    {
        EncodePreservationMessageDelegate encode = static (context, pool, cancellationToken) =>
        {
            bool carriesMarkup = context.Message is PreservePreservationObjectRequest request
                && request.PreservationObjects.Any(preservationObject => preservationObject.ContentForm == PreservationContentForm.XmlData);

            return carriesMarkup && context.Syntax == PreservationSyntax.Json
                ? ValueTask.FromResult(PreservationMessageEncodeResult.Failed(
                    PreservationMessageEncodeStatus.ContentFormNotRepresentable,
                    "the JSON binding carries no markup alternative"))
                : ValueTask.FromResult(PreservationMessageEncodeResult.Encoded(
                    PooledMemory.FromBytes("<PreservePO/>"u8, pool, PreservationTags.OpaqueElement)));
        };

        using PreservePreservationObjectRequest markup = new()
        {
            ProfileIdentifier = "https://example.invalid/preservation/profile/1",
            PreservationObjects =
            [
                PreservationMessageSource.Object("<data/>", BaseMemoryPool.Shared, contentForm: PreservationContentForm.XmlData)
            ]
        };

        using PreservationMessageEncodeResult refused = await encode(
            new PreservationMessageEncodeContext { Message = markup, Syntax = PreservationSyntax.Json },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsFalse(refused.IsEncoded);
        Assert.AreEqual(PreservationMessageEncodeStatus.ContentFormNotRepresentable, refused.Status);
        Assert.IsNull(refused.Document, "A refusal owns nothing.");

        using PreservationMessageEncodeResult written = await encode(
            new PreservationMessageEncodeContext { Message = markup, Syntax = PreservationSyntax.Xml },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsTrue(written.IsEncoded);
        Assert.IsNotNull(written.Document);

        ParsePreservationMessageDelegate parse = static (context, pool, cancellationToken) =>
            ValueTask.FromResult(context.ExpectedKind == PreservationMessageKind.SearchRequest
                ? PreservationMessageParseResult.Valid(new SearchRequest { Filter = "poid=1" })
                : PreservationMessageParseResult.Failed(PreservationMessageParseStatus.UnexpectedMessage, "the octets are a search request"));

        using PooledMemory document = PooledMemory.FromBytes("<Search/>"u8, BaseMemoryPool.Shared, PreservationTags.OpaqueElement);

        using PreservationMessageParseResult parsed = await parse(
            new PreservationMessageParseContext
            {
                Document = document,
                ExpectedKind = PreservationMessageKind.SearchRequest,
                Syntax = PreservationSyntax.Xml
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsTrue(parsed.IsValid);
        Assert.AreEqual(PreservationMessageKind.SearchRequest, parsed.Message!.Kind);

        using PreservationMessageParseResult mismatched = await parse(
            new PreservationMessageParseContext
            {
                Document = document,
                ExpectedKind = PreservationMessageKind.DeletePreservationObjectRequest,
                Syntax = PreservationSyntax.Xml
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsFalse(mismatched.IsValid);
        Assert.AreEqual(PreservationMessageParseStatus.UnexpectedMessage, mismatched.Status);
        Assert.IsNull(mismatched.Message, "A refused parse owns nothing.");
    }


    /// <summary>States the bounds of one profile by putting it into the response that carries profiles.</summary>
    /// <param name="profile">The profile to judge. The caller disposes it.</param>
    /// <returns>The bounds status of a discovery response carrying exactly that profile.</returns>
    private static PreservationMessageStatus StateOfProfile(PreservationProfile profile)
    {
        RetrieveInfoResponse response = new()
        {
            Result = PreservationMessageSource.SuccessfulResult(),
            Profiles = [profile]
        };

        return PreservationMessageBounds.State(response, PreservationMessageLimits.Conformant);
    }
}
