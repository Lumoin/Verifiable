using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cryptography.Pki.Xml;

/// <summary>
/// The worked implementation of <see cref="EncodePreservationMessageDelegate"/> and
/// <see cref="ParsePreservationMessageDelegate"/> for BOTH normative syntaxes of clause 5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>, staged beside the seam it implements.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why it is here and not in the library.</strong> One syntax is XML and the other is JSON, and
/// <c>Verifiable.Cryptography</c> references neither — the same split
/// <see cref="AsicManifestXmlBinding"/>, <see cref="MetsXmlBinding"/> and <see cref="PremisXmlBinding"/> already
/// make. The namespace already names where a future binding package would live.
/// </para>
/// <para>
/// <strong>Every wire name comes from the registry.</strong> Element names and JSON member names are read from
/// the <see cref="PreservationName"/>-valued getters, never derived from one another — which is the whole point
/// of the registry, since the document's own tables map <c>VersionID</c> to two different member names in two
/// components.
/// </para>
/// <para>
/// <strong>Three documented limitations of this staged example, each stated rather than papered over.</strong>
/// (1) The <c>Result</c> component is defined by reference to an external base specification and this repository
/// transcribes no mapping table for it, so the names below are this binding's own and are marked as such.
/// (2) The sub-components of a profile's operation and policy descriptors likewise have no transcribed table, so
/// an operation rides as its own name and a policy as its own type — a round trip through this binding therefore
/// preserves what those elements identify and not what they further describe.
/// (3) The JSON syntax carries no discriminator at all, so a parse asked for the wrong message reports the
/// missing particle it looked for rather than <see cref="PreservationMessageParseStatus.UnexpectedMessage"/>,
/// which the XML syntax does report from the root element's name.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> The XML reader prohibits document type definitions and resolves
/// nothing, and both readers bound what they accept through
/// <see cref="PreservationMessageParseContext.Limits"/> before any payload is materialised.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal",
    Justification = "The staged bindings of this wave are declared in the namespace a future binding package would use, and are public there so that promoting the file is a move rather than a rewrite.")]
public static class PreservationMessageXmlJsonBinding
{
    /// <summary>The element and member name this binding gives the <c>Result</c> component; see the class remarks.</summary>
    private static PreservationName Result { get; } = new("Result", "result");

    /// <summary>The element and member name this binding gives the result's major code.</summary>
    private static PreservationName ResultMajor { get; } = new("ResultMajor", "resultMajor");

    /// <summary>The element and member name this binding gives the result's minor code.</summary>
    private static PreservationName ResultMinor { get; } = new("ResultMinor", "resultMinor");

    /// <summary>The element and member name this binding gives the result's message.</summary>
    private static PreservationName ResultMessage { get; } = new("ResultMessage", "resultMessage");

    /// <summary>The suffix clause 5.3's own headings give a response message's element name.</summary>
    private static string ResponseSuffix { get; } = "Response";

    /// <summary>The reader settings every parse uses: no document type definition, no resolver, bounded input.</summary>
    private static XmlReaderSettings ReaderSettings { get; } = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        IgnoreWhitespace = true,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true
    };


    /// <summary>
    /// Writes one message of clause 5.3 in the stated syntax.
    /// </summary>
    /// <param name="context">The message to write and the syntax to write it in.</param>
    /// <param name="pool">The memory pool the produced document's carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encoding result.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static ValueTask<PreservationMessageEncodeResult> EncodeAsync(
        PreservationMessageEncodeContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(context.Syntax is not PreservationSyntax.Xml and not PreservationSyntax.Json)
        {
            return ValueTask.FromResult(PreservationMessageEncodeResult.Failed(
                PreservationMessageEncodeStatus.SyntaxNotSupported, "this binding writes the two normative syntaxes and nothing else"));
        }

        PreservationMessageStatus bounds = StateBounds(context.Message, context.Limits);
        if(bounds != PreservationMessageStatus.WithinBounds)
        {
            return ValueTask.FromResult(PreservationMessageEncodeResult.Failed(
                PreservationMessageEncodeStatus.LimitExceeded, bounds.ToString()));
        }

        if(context.Syntax == PreservationSyntax.Json && CarriesMarkupPayload(context.Message))
        {
            return ValueTask.FromResult(PreservationMessageEncodeResult.Failed(
                PreservationMessageEncodeStatus.ContentFormNotRepresentable,
                "the JSON schema of the PO component omits the markup alternative of the value choice"));
        }

        var writer = new MessageWriter(context.Syntax, ElementNameOf(context.Message));
        WriteMessage(writer, context.Message);

        return ValueTask.FromResult(PreservationMessageEncodeResult.Encoded(
            PooledMemory.FromBytes(writer.ToOctets(), pool, PreservationTags.OpaqueElement)));
    }


    /// <summary>
    /// Reads one message of clause 5.3 from the stated syntax, as the message the caller says it is.
    /// </summary>
    /// <param name="context">The document, the message it is expected to be, and the bounds to read it under.</param>
    /// <param name="pool">The memory pool the message's payload carriers are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The parse result.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every payload carrier transfers to the returned message, which the result owns and the caller disposes; a refusal returns before any carrier is rented.")]
    public static ValueTask<PreservationMessageParseResult> ParseAsync(
        PreservationMessageParseContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(context.Syntax is not PreservationSyntax.Xml and not PreservationSyntax.Json)
        {
            return ValueTask.FromResult(PreservationMessageParseResult.Failed(
                PreservationMessageParseStatus.SyntaxNotSupported, "this binding reads the two normative syntaxes and nothing else"));
        }

        //A whole message document carries its payloads in base 64, so a document longer than the payload bound
        //allows for could not have been produced by a conformant peer; the per-payload bounds are applied by
        //PreservationMessageBounds once the message exists.
        if(context.Document.Length > context.Limits.MaximumPayloadByteLength)
        {
            return ValueTask.FromResult(PreservationMessageParseResult.Failed(
                PreservationMessageParseStatus.LimitExceeded, "the document is longer than the caller admitted"));
        }

        MessageReader reader;
        try
        {
            reader = MessageReader.Create(context.Syntax, context.Document.AsReadOnlySpan());
        }
        catch(XmlException exception)
        {
            return ValueTask.FromResult(PreservationMessageParseResult.Failed(PreservationMessageParseStatus.Malformed, exception.Message));
        }
        catch(JsonException exception)
        {
            return ValueTask.FromResult(PreservationMessageParseResult.Failed(PreservationMessageParseStatus.Malformed, exception.Message));
        }

        if(context.Syntax == PreservationSyntax.Xml && !reader.RootIs(ElementNameOf(context.ExpectedKind)))
        {
            return ValueTask.FromResult(PreservationMessageParseResult.Failed(
                PreservationMessageParseStatus.UnexpectedMessage, "the root element names another message"));
        }

        PreservationMessage? message = ReadMessage(reader, context.ExpectedKind, pool, out string? missing);

        return ValueTask.FromResult(message is null
            ? PreservationMessageParseResult.Failed(PreservationMessageParseStatus.MissingRequiredElement, missing ?? "a required particle is absent")
            : PreservationMessageParseResult.Valid(message));
    }


    /// <summary>States the bounds of one message, whichever of the two hierarchies it belongs to.</summary>
    /// <param name="message">The message to judge.</param>
    /// <param name="limits">The bounds to judge it under.</param>
    /// <returns>What the bounds checker concluded.</returns>
    private static PreservationMessageStatus StateBounds(PreservationMessage message, PreservationMessageLimits limits) => message switch
    {
        PreservationRequest request => PreservationMessageBounds.State(request, limits),
        PreservationResponse response => PreservationMessageBounds.State(response, limits),
        _ => PreservationMessageStatus.WithinBounds
    };


    /// <summary>Determines whether a message carries a payload whose content form the JSON binding cannot hold.</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when some payload states the markup alternative of the value choice.</returns>
    private static bool CarriesMarkupPayload(PreservationMessage message) => message switch
    {
        PreservePreservationObjectRequest request => request.PreservationObjects.Any(static o => o.ContentForm == PreservationContentForm.XmlData),
        PreservePreservationObjectResponse response => response.PreservationObjects.Any(static o => o.ContentForm == PreservationContentForm.XmlData),
        RetrievePreservationObjectResponse response => response.PreservationObjects.Any(static o => o.ContentForm == PreservationContentForm.XmlData),
        UpdatePreservationObjectContainerRequest request => request.DeltaContainers.Any(static o => o.ContentForm == PreservationContentForm.XmlData),
        ValidateEvidenceRequest request => request.Evidence.ContentForm == PreservationContentForm.XmlData
            || request.PreservationObjects.Any(static o => o.ContentForm == PreservationContentForm.XmlData),
        _ => false
    };


    /// <summary>States the element name clause 5.3's own headings give a message.</summary>
    /// <param name="message">The message.</param>
    /// <returns>The element name.</returns>
    private static string ElementNameOf(PreservationMessage message) =>
        message is PreservationResponse ? message.OperationName + ResponseSuffix : message.OperationName;


    /// <summary>States the element name clause 5.3's own headings give one of the sixteen message kinds.</summary>
    /// <param name="kind">The message kind.</param>
    /// <returns>The element name.</returns>
    private static string ElementNameOf(PreservationMessageKind kind) => kind switch
    {
        PreservationMessageKind.RetrieveInfoRequest => PreservationWellKnown.RetrieveInfoOperation,
        PreservationMessageKind.RetrieveInfoResponse => PreservationWellKnown.RetrieveInfoOperation + ResponseSuffix,
        PreservationMessageKind.PreservePreservationObjectRequest => PreservationWellKnown.PreservePreservationObjectOperation,
        PreservationMessageKind.PreservePreservationObjectResponse => PreservationWellKnown.PreservePreservationObjectOperation + ResponseSuffix,
        PreservationMessageKind.RetrievePreservationObjectRequest => PreservationWellKnown.RetrievePreservationObjectOperation,
        PreservationMessageKind.RetrievePreservationObjectResponse => PreservationWellKnown.RetrievePreservationObjectOperation + ResponseSuffix,
        PreservationMessageKind.DeletePreservationObjectRequest => PreservationWellKnown.DeletePreservationObjectOperation,
        PreservationMessageKind.DeletePreservationObjectResponse => PreservationWellKnown.DeletePreservationObjectOperation + ResponseSuffix,
        PreservationMessageKind.UpdatePreservationObjectContainerRequest => PreservationWellKnown.UpdatePreservationObjectContainerOperation,
        PreservationMessageKind.UpdatePreservationObjectContainerResponse => PreservationWellKnown.UpdatePreservationObjectContainerOperation + ResponseSuffix,
        PreservationMessageKind.RetrieveTraceRequest => PreservationWellKnown.RetrieveTraceOperation,
        PreservationMessageKind.RetrieveTraceResponse => PreservationWellKnown.RetrieveTraceOperation + ResponseSuffix,
        PreservationMessageKind.ValidateEvidenceRequest => PreservationWellKnown.ValidateEvidenceOperation,
        PreservationMessageKind.ValidateEvidenceResponse => PreservationWellKnown.ValidateEvidenceOperation + ResponseSuffix,
        PreservationMessageKind.SearchRequest => PreservationWellKnown.SearchOperation,
        PreservationMessageKind.SearchResponse => PreservationWellKnown.SearchOperation + ResponseSuffix,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "A message of no kind has no element name.")
    };


    /// <summary>Writes one message's own particles, on top of whichever base component it extends.</summary>
    /// <param name="writer">The writer the message is written into.</param>
    /// <param name="message">The message to write.</param>
    private static void WriteMessage(MessageWriter writer, PreservationMessage message)
    {
        writer.Text(PreservationRequestParameterNames.RequestId, message.RequestId);
        if(message is PreservationRequest request)
        {
            foreach(PreservationOpaqueElement element in request.OptionalInputs)
            {
                writer.Base64(PreservationRequestParameterNames.OptionalInputs, element.Content.AsReadOnlySpan());
            }
        }

        if(message is PreservationResponse response)
        {
            writer.Child(Result, WriteResult(writer.Syntax, response.Result));
            foreach(PreservationOpaqueElement element in response.OptionalOutputs)
            {
                writer.Base64(PreservationResponseParameterNames.OptionalOutputs, element.Content.AsReadOnlySpan());
            }
        }

        switch(message)
        {
            case RetrieveInfoRequest retrieveInfo:
                writer.Text(RetrieveInfoRequestParameterNames.Profile, retrieveInfo.ProfileIdentifier);
                writer.Text(RetrieveInfoRequestParameterNames.Status, retrieveInfo.Status);
                break;

            case RetrieveInfoResponse retrieveInfoResponse:
                foreach(PreservationProfile profile in retrieveInfoResponse.Profiles)
                {
                    writer.Child(RetrieveInfoResponseParameterNames.Profile, WriteProfile(writer.Syntax, profile));
                }

                break;

            case PreservePreservationObjectRequest preserve:
                writer.Text(PreservePreservationObjectRequestParameterNames.Profile, preserve.ProfileIdentifier);
                foreach(PreservationObject preservationObject in preserve.PreservationObjects)
                {
                    writer.Child(PreservePreservationObjectRequestParameterNames.PreservationObject, WriteObject(writer.Syntax, preservationObject));
                }

                break;

            case PreservePreservationObjectResponse preserveResponse:
                writer.Text(PreservePreservationObjectResponseParameterNames.PreservationObjectId, preserveResponse.PreservationObjectId);
                foreach(PreservationObject preservationObject in preserveResponse.PreservationObjects)
                {
                    writer.Child(PreservePreservationObjectResponseParameterNames.PreservationObject, WriteObject(writer.Syntax, preservationObject));
                }

                break;

            case RetrievePreservationObjectRequest retrieve:
                writer.Text(RetrievePreservationObjectRequestParameterNames.PreservationObjectId, retrieve.PreservationObjectId);
                foreach(string versionId in retrieve.VersionIds)
                {
                    writer.Text(RetrievePreservationObjectRequestParameterNames.VersionId, versionId);
                }

                writer.Text(RetrievePreservationObjectRequestParameterNames.SubjectOfRetrieval, retrieve.SubjectOfRetrieval);
                writer.Text(RetrievePreservationObjectRequestParameterNames.PreservationObjectFormat, retrieve.PreservationObjectFormat);
                writer.Text(RetrievePreservationObjectRequestParameterNames.EvidenceFormat, retrieve.EvidenceFormat);
                break;

            case RetrievePreservationObjectResponse retrieveResponse:
                foreach(PreservationObject preservationObject in retrieveResponse.PreservationObjects)
                {
                    writer.Child(RetrievePreservationObjectResponseParameterNames.PreservationObject, WriteObject(writer.Syntax, preservationObject));
                }

                break;

            case UpdatePreservationObjectContainerRequest update:
                writer.Text(UpdatePreservationObjectContainerRequestParameterNames.PreservationObjectId, update.PreservationObjectId);
                foreach(PreservationObject delta in update.DeltaContainers)
                {
                    writer.Child(UpdatePreservationObjectContainerRequestParameterNames.DeltaContainer, WriteObject(writer.Syntax, delta));
                }

                break;

            case UpdatePreservationObjectContainerResponse updateResponse:
                writer.Text(UpdatePreservationObjectContainerResponseParameterNames.VersionId, updateResponse.VersionId);
                break;

            case RetrieveTraceRequest trace:
                writer.Text(RetrieveTraceRequestParameterNames.PreservationObjectId, trace.PreservationObjectId);
                break;

            case RetrieveTraceResponse traceResponse:
                writer.Child(RetrieveTraceResponseParameterNames.Trace, WriteTrace(writer.Syntax, traceResponse.Trace));
                break;

            case ValidateEvidenceRequest validate:
                writer.Child(ValidateEvidenceRequestParameterNames.Evidence, WriteEvidence(writer.Syntax, validate.Evidence));
                foreach(PreservationObject preservationObject in validate.PreservationObjects)
                {
                    writer.Child(ValidateEvidenceRequestParameterNames.PreservationObject, WriteObject(writer.Syntax, preservationObject));
                }

                break;

            case ValidateEvidenceResponse validateResponse:
                if(validateResponse.ValidationReport is PreservationObject report)
                {
                    writer.Child(ValidateEvidenceResponseParameterNames.ValidationReport, WriteObject(writer.Syntax, report));
                }

                writer.Instant(ValidateEvidenceResponseParameterNames.ProofOfExistence, validateResponse.ProofOfExistence);
                break;

            case SearchRequest search:
                writer.Text(SearchRequestParameterNames.Filter, search.Filter);
                break;

            case SearchResponse searchResponse:
                foreach(string identifier in searchResponse.PreservationObjectIds)
                {
                    writer.Text(SearchResponseParameterNames.PreservationObjectId, identifier);
                }

                break;

            default:
                break;
        }
    }


    /// <summary>Writes the <c>Result</c> component of a response.</summary>
    /// <param name="syntax">The syntax being written.</param>
    /// <param name="result">The result to write.</param>
    /// <returns>The written component.</returns>
    private static MessageWriter WriteResult(PreservationSyntax syntax, PreservationResult result)
    {
        var writer = new MessageWriter(syntax, Result.XmlElementName);
        writer.Text(ResultMajor, result.ResultMajor);
        writer.Text(ResultMinor, result.ResultMinor);
        writer.Text(ResultMessage, result.ResultMessage);

        return writer;
    }


    /// <summary>Writes one <c>PO</c> component.</summary>
    /// <param name="syntax">The syntax being written.</param>
    /// <param name="preservationObject">The object to write.</param>
    /// <returns>The written component.</returns>
    private static MessageWriter WriteObject(PreservationSyntax syntax, PreservationObject preservationObject)
    {
        var writer = new MessageWriter(syntax, PreservationObjectParameterNames.BinaryData.XmlElementName);
        writer.Base64(PreservationObjectParameterNames.BinaryData, preservationObject.Content.AsReadOnlySpan());
        writer.Text(PreservationObjectParameterNames.FormatId, preservationObject.FormatId);
        writer.Text(PreservationObjectParameterNames.MimeType, preservationObject.MimeType);
        writer.Text(PreservationObjectParameterNames.PronomId, preservationObject.PronomId);
        writer.Text(PreservationObjectParameterNames.Id, preservationObject.Id);
        foreach(string related in preservationObject.RelatedObjects)
        {
            writer.Text(PreservationObjectParameterNames.RelatedObjects, related);
        }

        return writer;
    }


    /// <summary>Writes one <c>Evidence</c> component.</summary>
    /// <param name="syntax">The syntax being written.</param>
    /// <param name="evidence">The evidence to write.</param>
    /// <returns>The written component.</returns>
    private static MessageWriter WriteEvidence(PreservationSyntax syntax, PreservationEvidence evidence)
    {
        var writer = new MessageWriter(syntax, PreservationEvidenceParameterNames.BinaryData.XmlElementName);
        writer.Base64(PreservationEvidenceParameterNames.BinaryData, evidence.Content.AsReadOnlySpan());
        writer.Text(PreservationEvidenceParameterNames.FormatId, evidence.FormatId);
        writer.Text(PreservationEvidenceParameterNames.MimeType, evidence.MimeType);
        writer.Text(PreservationEvidenceParameterNames.Id, evidence.Id);
        writer.Text(PreservationEvidenceParameterNames.PreservationObjectId, evidence.PreservationObjectId);
        writer.Text(PreservationEvidenceParameterNames.VersionId, evidence.VersionId);

        return writer;
    }


    /// <summary>Writes one <c>Trace</c> component and its events.</summary>
    /// <param name="syntax">The syntax being written.</param>
    /// <param name="trace">The trace to write.</param>
    /// <returns>The written component.</returns>
    private static MessageWriter WriteTrace(PreservationSyntax syntax, PreservationTrace trace)
    {
        var writer = new MessageWriter(syntax, PreservationTraceParameterNames.Event.XmlElementName);
        foreach(PreservationEvent recorded in trace.Events)
        {
            var eventWriter = new MessageWriter(syntax, PreservationTraceParameterNames.Event.XmlElementName);
            eventWriter.Instant(PreservationEventParameterNames.Time, recorded.Time);
            eventWriter.Text(PreservationEventParameterNames.Subject, recorded.Subject);
            eventWriter.Text(PreservationEventParameterNames.Operation, recorded.Operation);
            eventWriter.Text(PreservationEventParameterNames.Object, recorded.Object);
            eventWriter.Text(PreservationEventParameterNames.Detail, recorded.Detail);
            writer.Child(PreservationTraceParameterNames.Event, eventWriter);
        }

        return writer;
    }


    /// <summary>Writes one profile, to the depth the transcribed mapping tables reach.</summary>
    /// <param name="syntax">The syntax being written.</param>
    /// <param name="profile">The profile to write.</param>
    /// <returns>The written component.</returns>
    private static MessageWriter WriteProfile(PreservationSyntax syntax, PreservationProfile profile)
    {
        var writer = new MessageWriter(syntax, PreservationProfileParameterNames.ProfileIdentifier.XmlElementName);
        writer.Text(PreservationProfileParameterNames.ProfileIdentifier, profile.ProfileIdentifier);
        foreach(PreservationOperationDescriptor operation in profile.Operations)
        {
            writer.Text(PreservationProfileParameterNames.Operation, operation.Name);
        }

        foreach(PreservationPolicyReference policy in profile.Policies)
        {
            writer.Text(PreservationProfileParameterNames.Policy, policy.PolicyType);
        }

        writer.Instant(PreservationProfileParameterNames.ProfileValidityPeriod, profile.ValidityPeriod.ValidFrom);
        writer.Text(PreservationProfileParameterNames.PreservationStorageModel, profile.StorageModel);
        foreach(string goal in profile.PreservationGoals)
        {
            writer.Text(PreservationProfileParameterNames.PreservationGoal, goal);
        }

        foreach(PreservationFormatDescriptor format in profile.EvidenceFormats)
        {
            writer.Text(PreservationProfileParameterNames.EvidenceFormat, format.FormatId);
        }

        writer.Text(PreservationProfileParameterNames.SchemeIdentifier, profile.SchemeIdentifier);
        writer.Text(PreservationProfileParameterNames.PreservationEvidenceRetentionPeriod, profile.PreservationEvidenceRetentionPeriod);

        return writer;
    }


    /// <summary>Reads one message of the expected kind, or states which particle it could not find.</summary>
    /// <param name="reader">The document.</param>
    /// <param name="kind">Which message the octets are expected to be.</param>
    /// <param name="pool">The memory pool payload carriers are rented from.</param>
    /// <param name="missing">The particle that was absent, when the read failed.</param>
    /// <returns>The message, or <see langword="null"/> when a required particle was absent.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every component read here transfers to the message that carries it, and the message's own Dispose releases the whole tree; a refusal returns before any component that owns a carrier has been built.")]
    private static PreservationMessage? ReadMessage(
        MessageReader reader,
        PreservationMessageKind kind,
        BaseMemoryPool pool,
        out string? missing)
    {
        missing = null;
        string? requestId = reader.Text(PreservationRequestParameterNames.RequestId);
        switch(kind)
        {
            case PreservationMessageKind.RetrieveInfoRequest:
                return new RetrieveInfoRequest
                {
                    RequestId = requestId,
                    ProfileIdentifier = reader.Text(RetrieveInfoRequestParameterNames.Profile),
                    Status = reader.Text(RetrieveInfoRequestParameterNames.Status)
                };

            case PreservationMessageKind.RetrieveInfoResponse:
            {
                PreservationResult? result = ReadResult(reader);
                if(result is null)
                {
                    missing = Result.XmlElementName;

                    return null;
                }

                var profiles = new List<PreservationProfile>();
                foreach(MessageReader child in reader.Children(RetrieveInfoResponseParameterNames.Profile))
                {
                    PreservationProfile? profile = ReadProfile(child);
                    if(profile is null)
                    {
                        missing = PreservationProfileParameterNames.ProfileIdentifier.XmlElementName;

                        return null;
                    }

                    profiles.Add(profile);
                }

                return new RetrieveInfoResponse { RequestId = requestId, Result = result, Profiles = profiles };
            }

            case PreservationMessageKind.PreservePreservationObjectRequest:
            {
                string? profileIdentifier = reader.Text(PreservePreservationObjectRequestParameterNames.Profile);
                if(profileIdentifier is null)
                {
                    missing = PreservePreservationObjectRequestParameterNames.Profile.XmlElementName;

                    return null;
                }

                return new PreservePreservationObjectRequest
                {
                    RequestId = requestId,
                    ProfileIdentifier = profileIdentifier,
                    PreservationObjects = ReadObjects(reader, PreservePreservationObjectRequestParameterNames.PreservationObject, pool)
                };
            }

            case PreservationMessageKind.PreservePreservationObjectResponse:
            {
                PreservationResult? result = ReadResult(reader);
                if(result is null)
                {
                    missing = Result.XmlElementName;

                    return null;
                }

                return new PreservePreservationObjectResponse
                {
                    RequestId = requestId,
                    Result = result,
                    PreservationObjectId = reader.Text(PreservePreservationObjectResponseParameterNames.PreservationObjectId),
                    PreservationObjects = ReadObjects(reader, PreservePreservationObjectResponseParameterNames.PreservationObject, pool)
                };
            }

            case PreservationMessageKind.RetrievePreservationObjectRequest:
            {
                string? identifier = reader.Text(RetrievePreservationObjectRequestParameterNames.PreservationObjectId);
                if(identifier is null)
                {
                    missing = RetrievePreservationObjectRequestParameterNames.PreservationObjectId.XmlElementName;

                    return null;
                }

                return new RetrievePreservationObjectRequest
                {
                    RequestId = requestId,
                    PreservationObjectId = identifier,
                    VersionIds = reader.Texts(RetrievePreservationObjectRequestParameterNames.VersionId),
                    SubjectOfRetrieval = reader.Text(RetrievePreservationObjectRequestParameterNames.SubjectOfRetrieval),
                    PreservationObjectFormat = reader.Text(RetrievePreservationObjectRequestParameterNames.PreservationObjectFormat),
                    EvidenceFormat = reader.Text(RetrievePreservationObjectRequestParameterNames.EvidenceFormat)
                };
            }

            case PreservationMessageKind.RetrievePreservationObjectResponse:
            {
                PreservationResult? result = ReadResult(reader);
                if(result is null)
                {
                    missing = Result.XmlElementName;

                    return null;
                }

                return new RetrievePreservationObjectResponse
                {
                    RequestId = requestId,
                    Result = result,
                    PreservationObjects = ReadObjects(reader, RetrievePreservationObjectResponseParameterNames.PreservationObject, pool)
                };
            }

            case PreservationMessageKind.UpdatePreservationObjectContainerRequest:
            {
                string? identifier = reader.Text(UpdatePreservationObjectContainerRequestParameterNames.PreservationObjectId);
                if(identifier is null)
                {
                    missing = UpdatePreservationObjectContainerRequestParameterNames.PreservationObjectId.XmlElementName;

                    return null;
                }

                return new UpdatePreservationObjectContainerRequest
                {
                    RequestId = requestId,
                    PreservationObjectId = identifier,
                    DeltaContainers = ReadObjects(reader, UpdatePreservationObjectContainerRequestParameterNames.DeltaContainer, pool)
                };
            }

            case PreservationMessageKind.UpdatePreservationObjectContainerResponse:
            {
                PreservationResult? result = ReadResult(reader);
                if(result is null)
                {
                    missing = Result.XmlElementName;

                    return null;
                }

                return new UpdatePreservationObjectContainerResponse
                {
                    RequestId = requestId,
                    Result = result,
                    VersionId = reader.Text(UpdatePreservationObjectContainerResponseParameterNames.VersionId)
                };
            }

            case PreservationMessageKind.RetrieveTraceRequest:
            {
                string? identifier = reader.Text(RetrieveTraceRequestParameterNames.PreservationObjectId);
                if(identifier is null)
                {
                    missing = RetrieveTraceRequestParameterNames.PreservationObjectId.XmlElementName;

                    return null;
                }

                return new RetrieveTraceRequest { RequestId = requestId, PreservationObjectId = identifier };
            }

            case PreservationMessageKind.RetrieveTraceResponse:
            {
                PreservationResult? result = ReadResult(reader);
                MessageReader? traceReader = reader.Child(RetrieveTraceResponseParameterNames.Trace);
                if(result is null || traceReader is null)
                {
                    missing = result is null ? Result.XmlElementName : RetrieveTraceResponseParameterNames.Trace.XmlElementName;

                    return null;
                }

                var events = new List<PreservationEvent>();
                foreach(MessageReader child in traceReader.Children(PreservationTraceParameterNames.Event))
                {
                    DateTimeOffset? time = child.Instant(PreservationEventParameterNames.Time);
                    string? subject = child.Text(PreservationEventParameterNames.Subject);
                    string? operation = child.Text(PreservationEventParameterNames.Operation);
                    if(time is null || subject is null || operation is null)
                    {
                        missing = PreservationTraceParameterNames.Event.XmlElementName;

                        return null;
                    }

                    events.Add(new PreservationEvent
                    {
                        Time = time.Value,
                        Subject = subject,
                        Operation = operation,
                        Object = child.Text(PreservationEventParameterNames.Object),
                        Detail = child.Text(PreservationEventParameterNames.Detail)
                    });
                }

                return new RetrieveTraceResponse
                {
                    RequestId = requestId,
                    Result = result,
                    Trace = new PreservationTrace { Events = events }
                };
            }

            case PreservationMessageKind.ValidateEvidenceRequest:
            {
                MessageReader? evidenceReader = reader.Child(ValidateEvidenceRequestParameterNames.Evidence);
                PreservationEvidence? evidence = evidenceReader is null ? null : ReadEvidence(evidenceReader, pool);
                if(evidence is null)
                {
                    missing = ValidateEvidenceRequestParameterNames.Evidence.XmlElementName;

                    return null;
                }

                return new ValidateEvidenceRequest
                {
                    RequestId = requestId,
                    Evidence = evidence,
                    PreservationObjects = ReadObjects(reader, ValidateEvidenceRequestParameterNames.PreservationObject, pool)
                };
            }

            case PreservationMessageKind.ValidateEvidenceResponse:
            {
                PreservationResult? result = ReadResult(reader);
                if(result is null)
                {
                    missing = Result.XmlElementName;

                    return null;
                }

                MessageReader? reportReader = reader.Child(ValidateEvidenceResponseParameterNames.ValidationReport);

                return new ValidateEvidenceResponse
                {
                    RequestId = requestId,
                    Result = result,
                    ValidationReport = reportReader is null ? null : ReadObject(reportReader, pool),
                    ProofOfExistence = reader.Instant(ValidateEvidenceResponseParameterNames.ProofOfExistence)
                };
            }

            case PreservationMessageKind.SearchRequest:
                return new SearchRequest { RequestId = requestId, Filter = reader.Text(SearchRequestParameterNames.Filter) };

            case PreservationMessageKind.SearchResponse:
            {
                PreservationResult? result = ReadResult(reader);
                if(result is null)
                {
                    missing = Result.XmlElementName;

                    return null;
                }

                return new SearchResponse
                {
                    RequestId = requestId,
                    Result = result,
                    PreservationObjectIds = reader.Texts(SearchResponseParameterNames.PreservationObjectId)
                };
            }

            default:
                missing = "a message of no kind has no particles";

                return null;
        }
    }


    /// <summary>Reads the <c>Result</c> component of a response.</summary>
    /// <param name="reader">The response's reader.</param>
    /// <returns>The result, or <see langword="null"/> when the response states none.</returns>
    private static PreservationResult? ReadResult(MessageReader reader)
    {
        MessageReader? child = reader.Child(Result);
        string? major = child?.Text(ResultMajor);

        return child is null || major is null
            ? null
            : new PreservationResult
            {
                ResultMajor = major,
                ResultMinor = child.Text(ResultMinor),
                ResultMessage = child.Text(ResultMessage)
            };
    }


    /// <summary>Reads every <c>PO</c> component a message carries under one name.</summary>
    /// <param name="reader">The message's reader.</param>
    /// <param name="name">The name the objects are carried under.</param>
    /// <param name="pool">The memory pool payload carriers are rented from.</param>
    /// <returns>The objects, whose carriers the message that receives them owns.</returns>
    private static List<PreservationObject> ReadObjects(MessageReader reader, PreservationName name, BaseMemoryPool pool)
    {
        var objects = new List<PreservationObject>();
        foreach(MessageReader child in reader.Children(name))
        {
            objects.Add(ReadObject(child, pool));
        }

        return objects;
    }


    /// <summary>Reads one <c>PO</c> component.</summary>
    /// <param name="reader">The component's reader.</param>
    /// <param name="pool">The memory pool the payload carrier is rented from.</param>
    /// <returns>The object, whose carrier the message that receives it owns.</returns>
    private static PreservationObject ReadObject(MessageReader reader, BaseMemoryPool pool) =>
        new()
        {
            Content = PooledMemory.FromBytes(
                reader.Base64(PreservationObjectParameterNames.BinaryData), pool, PreservationTags.PreservationObject),
            ContentForm = PreservationContentForm.BinaryData,
            FormatId = reader.Text(PreservationObjectParameterNames.FormatId),
            MimeType = reader.Text(PreservationObjectParameterNames.MimeType),
            PronomId = reader.Text(PreservationObjectParameterNames.PronomId),
            Id = reader.Text(PreservationObjectParameterNames.Id),
            RelatedObjects = reader.Texts(PreservationObjectParameterNames.RelatedObjects)
        };


    /// <summary>Reads one <c>Evidence</c> component.</summary>
    /// <param name="reader">The component's reader.</param>
    /// <param name="pool">The memory pool the payload carrier is rented from.</param>
    /// <returns>The evidence, or <see langword="null"/> when it states no format identifier.</returns>
    private static PreservationEvidence? ReadEvidence(MessageReader reader, BaseMemoryPool pool)
    {
        string? formatId = reader.Text(PreservationEvidenceParameterNames.FormatId);

        return formatId is null
            ? null
            : new PreservationEvidence
            {
                Content = PooledMemory.FromBytes(
                    reader.Base64(PreservationEvidenceParameterNames.BinaryData), pool, PreservationTags.PreservationEvidence),
                ContentForm = PreservationContentForm.BinaryData,
                FormatId = formatId,
                MimeType = reader.Text(PreservationEvidenceParameterNames.MimeType),
                Id = reader.Text(PreservationEvidenceParameterNames.Id),
                PreservationObjectId = reader.Text(PreservationEvidenceParameterNames.PreservationObjectId),
                VersionId = reader.Text(PreservationEvidenceParameterNames.VersionId)
            };
    }


    /// <summary>Reads one profile, to the depth this binding writes one.</summary>
    /// <param name="reader">The profile's reader.</param>
    /// <returns>The profile, or <see langword="null"/> when a member clause 5.4.7 makes mandatory is absent.</returns>
    private static PreservationProfile? ReadProfile(MessageReader reader)
    {
        string? identifier = reader.Text(PreservationProfileParameterNames.ProfileIdentifier);
        string? storageModel = reader.Text(PreservationProfileParameterNames.PreservationStorageModel);
        DateTimeOffset? validFrom = reader.Instant(PreservationProfileParameterNames.ProfileValidityPeriod);
        if(identifier is null || storageModel is null || validFrom is null)
        {
            return null;
        }

        var operations = new List<PreservationOperationDescriptor>();
        foreach(string operation in reader.Texts(PreservationProfileParameterNames.Operation))
        {
            operations.Add(new PreservationOperationDescriptor { Name = operation });
        }

        var policies = new List<PreservationPolicyReference>();
        foreach(string policy in reader.Texts(PreservationProfileParameterNames.Policy))
        {
            policies.Add(new PreservationPolicyReference { PolicyType = policy });
        }

        var evidenceFormats = new List<PreservationFormatDescriptor>();
        foreach(string format in reader.Texts(PreservationProfileParameterNames.EvidenceFormat))
        {
            evidenceFormats.Add(new PreservationFormatDescriptor { FormatId = format });
        }

        return new PreservationProfile
        {
            ProfileIdentifier = identifier,
            Operations = operations,
            Policies = policies,
            ValidityPeriod = new PreservationValidityPeriod { ValidFrom = validFrom.Value },
            StorageModel = storageModel,
            PreservationGoals = reader.Texts(PreservationProfileParameterNames.PreservationGoal),
            EvidenceFormats = evidenceFormats,
            SchemeIdentifier = reader.Text(PreservationProfileParameterNames.SchemeIdentifier),
            PreservationEvidenceRetentionPeriod = reader.Text(PreservationProfileParameterNames.PreservationEvidenceRetentionPeriod)
        };
    }


    /// <summary>
    /// One document being written, in whichever of the two syntaxes the caller asked for.
    /// </summary>
    /// <remarks>
    /// The two halves are kept behind one shape so that a message is written once rather than twice, which is what
    /// makes a divergence between the syntaxes impossible to introduce by accident. Which spelling of a name is
    /// used is the only difference, and it comes from the registry.
    /// </remarks>
    private sealed class MessageWriter
    {
        /// <summary>The element being built, when the XML syntax is being written.</summary>
        private readonly XElement? element;

        /// <summary>The object being built, when the JSON syntax is being written.</summary>
        private readonly JsonObject? json;


        /// <summary>Initializes a writer for one element or object.</summary>
        /// <param name="syntax">The syntax being written.</param>
        /// <param name="elementName">The element name the XML syntax gives this node.</param>
        internal MessageWriter(PreservationSyntax syntax, string elementName)
        {
            Syntax = syntax;
            if(syntax == PreservationSyntax.Xml)
            {
                element = new XElement(XName.Get(elementName, PreservationWellKnown.PreservationNamespace));
            }
            else
            {
                json = [];
            }
        }


        /// <summary>The syntax this writer is writing.</summary>
        internal PreservationSyntax Syntax { get; }


        /// <summary>Writes one textual member, or nothing at all when the value is absent.</summary>
        /// <param name="name">The member's name pair.</param>
        /// <param name="value">The value, or <see langword="null"/> to write nothing.</param>
        internal void Text(PreservationName name, string? value)
        {
            if(value is null)
            {
                return;
            }

            if(element is not null)
            {
                element.Add(new XElement(XName.Get(name.XmlElementName, PreservationWellKnown.PreservationNamespace), value));
            }
            else
            {
                Append(name.JsonMemberName, JsonValue.Create(value));
            }
        }


        /// <summary>Writes one binary member as base 64, which is how both syntaxes carry octets.</summary>
        /// <param name="name">The member's name pair.</param>
        /// <param name="octets">The octets to write.</param>
        internal void Base64(PreservationName name, ReadOnlySpan<byte> octets) => Text(name, Convert.ToBase64String(octets));


        /// <summary>
        /// Writes one instant: an XML date and time in the XML syntax, and an integer of milliseconds since the
        /// epoch in the JSON one, which is the difference clause 5's own syntax sub-clauses state.
        /// </summary>
        /// <param name="name">The member's name pair.</param>
        /// <param name="value">The instant, or <see langword="null"/> to write nothing.</param>
        internal void Instant(PreservationName name, DateTimeOffset? value)
        {
            if(value is not DateTimeOffset instant)
            {
                return;
            }

            if(element is not null)
            {
                Text(name, instant.ToString("O", CultureInfo.InvariantCulture));
            }
            else
            {
                Append(name.JsonMemberName, JsonValue.Create(instant.ToUnixTimeMilliseconds()));
            }
        }


        /// <summary>Writes one child component.</summary>
        /// <param name="name">The child's name pair.</param>
        /// <param name="child">The child, written by a writer of its own.</param>
        internal void Child(PreservationName name, MessageWriter child)
        {
            if(element is not null)
            {
                var renamed = new XElement(XName.Get(name.XmlElementName, PreservationWellKnown.PreservationNamespace), child.element!.Elements());
                element.Add(renamed);
            }
            else
            {
                Append(name.JsonMemberName, child.json!.DeepClone());
            }
        }


        /// <summary>States the written document's octets, in UTF-8.</summary>
        /// <returns>The octets.</returns>
        internal byte[] ToOctets() => element is not null
            ? Encoding.UTF8.GetBytes(element.ToString(SaveOptions.DisableFormatting))
            : Encoding.UTF8.GetBytes(json!.ToJsonString());


        /// <summary>
        /// Appends one JSON member, turning a member stated twice into the array a repeatable element becomes.
        /// </summary>
        /// <param name="memberName">The member's name.</param>
        /// <param name="value">The value to append.</param>
        private void Append(string memberName, JsonNode? value)
        {
            if(!json!.TryGetPropertyValue(memberName, out JsonNode? existing))
            {
                json[memberName] = value;

                return;
            }

            if(existing is JsonArray array)
            {
                array.Add(value);

                return;
            }

            json[memberName] = new JsonArray(existing!.DeepClone(), value);
        }
    }


    /// <summary>
    /// One document being read, in whichever of the two syntaxes it was written in.
    /// </summary>
    /// <remarks>
    /// A repeatable element is an element occurring more than once in the XML syntax and an array member in the
    /// JSON one, and both are read as the same list here — which is the one structural difference between the two
    /// syntaxes that a caller of this binding never has to know about.
    /// </remarks>
    private sealed class MessageReader
    {
        /// <summary>The element being read, when the XML syntax is being read.</summary>
        private readonly XElement? element;

        /// <summary>The object being read, when the JSON syntax is being read.</summary>
        private readonly JsonObject? json;


        /// <summary>Initializes a reader over one element or object.</summary>
        /// <param name="element">The element, or <see langword="null"/> when JSON is being read.</param>
        /// <param name="json">The object, or <see langword="null"/> when XML is being read.</param>
        private MessageReader(XElement? element, JsonObject? json)
        {
            this.element = element;
            this.json = json;
        }


        /// <summary>Creates a reader over a whole document.</summary>
        /// <param name="syntax">The syntax the document is written in.</param>
        /// <param name="document">The document's octets.</param>
        /// <returns>The reader.</returns>
        /// <exception cref="XmlException">When the XML syntax is asked for and the octets are not well-formed markup.</exception>
        /// <exception cref="JsonException">When the JSON syntax is asked for and the octets are not a JSON object.</exception>
        internal static MessageReader Create(PreservationSyntax syntax, ReadOnlySpan<byte> document)
        {
            if(syntax == PreservationSyntax.Xml)
            {
                using var reader = XmlReader.Create(new System.IO.MemoryStream(document.ToArray()), ReaderSettings);

                return new MessageReader(XElement.Load(reader), json: null);
            }

            JsonNode? node = JsonNode.Parse(document.ToArray());

            return node is JsonObject asObject
                ? new MessageReader(element: null, asObject)
                : throw new JsonException("A preservation message is a JSON object.");
        }


        /// <summary>Determines whether the document's root element carries the expected name.</summary>
        /// <param name="elementName">The name the expected message's own clause gives it.</param>
        /// <returns><see langword="true"/> when the root is that element.</returns>
        internal bool RootIs(string elementName) =>
            element is not null && string.Equals(element.Name.LocalName, elementName, StringComparison.Ordinal);


        /// <summary>Reads one textual member.</summary>
        /// <param name="name">The member's name pair.</param>
        /// <returns>The value, or <see langword="null"/> when the document states none.</returns>
        internal string? Text(PreservationName name)
        {
            if(element is not null)
            {
                return element.Element(XName.Get(name.XmlElementName, PreservationWellKnown.PreservationNamespace))?.Value;
            }

            return json!.TryGetPropertyValue(name.JsonMemberName, out JsonNode? node) && node is JsonValue value
                ? value.GetValue<object>().ToString()
                : null;
        }


        /// <summary>Reads every value a repeatable textual member states.</summary>
        /// <param name="name">The member's name pair.</param>
        /// <returns>The values, in the order the document states them.</returns>
        internal List<string> Texts(PreservationName name)
        {
            var values = new List<string>();
            if(element is not null)
            {
                foreach(XElement child in element.Elements(XName.Get(name.XmlElementName, PreservationWellKnown.PreservationNamespace)))
                {
                    values.Add(child.Value);
                }

                return values;
            }

            if(!json!.TryGetPropertyValue(name.JsonMemberName, out JsonNode? node) || node is null)
            {
                return values;
            }

            if(node is JsonArray array)
            {
                foreach(JsonNode? item in array)
                {
                    if(item is JsonValue value)
                    {
                        values.Add(value.GetValue<object>().ToString()!);
                    }
                }

                return values;
            }

            values.Add(node.GetValue<object>().ToString()!);

            return values;
        }


        /// <summary>Reads one binary member from its base-64 text.</summary>
        /// <param name="name">The member's name pair.</param>
        /// <returns>The octets, empty when the document states none.</returns>
        internal byte[] Base64(PreservationName name)
        {
            string? text = Text(name);

            return text is null ? [] : Convert.FromBase64String(text);
        }


        /// <summary>Reads one instant, from whichever form the syntax states it in.</summary>
        /// <param name="name">The member's name pair.</param>
        /// <returns>The instant, or <see langword="null"/> when the document states none.</returns>
        internal DateTimeOffset? Instant(PreservationName name)
        {
            string? text = Text(name);
            if(text is null)
            {
                return null;
            }

            return element is not null
                ? DateTimeOffset.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)
                : DateTimeOffset.FromUnixTimeMilliseconds(long.Parse(text, CultureInfo.InvariantCulture));
        }


        /// <summary>Reads one child component.</summary>
        /// <param name="name">The child's name pair.</param>
        /// <returns>A reader over the child, or <see langword="null"/> when the document states none.</returns>
        internal MessageReader? Child(PreservationName name)
        {
            if(element is not null)
            {
                XElement? child = element.Element(XName.Get(name.XmlElementName, PreservationWellKnown.PreservationNamespace));

                return child is null ? null : new MessageReader(child, json: null);
            }

            return json!.TryGetPropertyValue(name.JsonMemberName, out JsonNode? node) && node is JsonObject asObject
                ? new MessageReader(element: null, asObject)
                : null;
        }


        /// <summary>Reads every occurrence of one repeatable child component.</summary>
        /// <param name="name">The child's name pair.</param>
        /// <returns>Readers over the children, in the order the document states them.</returns>
        internal List<MessageReader> Children(PreservationName name)
        {
            var children = new List<MessageReader>();
            if(element is not null)
            {
                foreach(XElement child in element.Elements(XName.Get(name.XmlElementName, PreservationWellKnown.PreservationNamespace)))
                {
                    children.Add(new MessageReader(child, json: null));
                }

                return children;
            }

            if(!json!.TryGetPropertyValue(name.JsonMemberName, out JsonNode? node) || node is null)
            {
                return children;
            }

            if(node is JsonArray array)
            {
                foreach(JsonNode? item in array)
                {
                    if(item is JsonObject asObject)
                    {
                        children.Add(new MessageReader(element: null, asObject));
                    }
                }

                return children;
            }

            if(node is JsonObject single)
            {
                children.Add(new MessageReader(element: null, single));
            }

            return children;
        }
    }
}
