using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The bounds a peer applies to a preservation-protocol message it did not build.
/// </summary>
/// <remarks>
/// A request arrives from a client and a response arrives from a service, so every bound here exists to make a
/// message that is hostile rather than merely large a refusal instead of a resource exhaustion — the same
/// discipline <see cref="AsicManifestParseLimits"/> and <see cref="EArkPackageLimits"/> apply to their own
/// attacker-reachable inputs. The defaults are the ones <see cref="Conformant"/> states; the specification itself
/// states no numeric bound anywhere in clause 5, so these are this library's, chosen to admit any message a
/// conformant service is likely to build and no more.
/// </remarks>
public sealed record PreservationMessageLimits
{
    /// <summary>The bounds a conformant message fits inside.</summary>
    public static PreservationMessageLimits Conformant { get; } = new();

    /// <summary>
    /// The largest number of preservation objects one message may carry, 4096 — the same bound the container
    /// reader puts on entries, since a submission of a whole container is the largest submission there is.
    /// </summary>
    public int MaximumPreservationObjects { get; init; } = 4096;

    /// <summary>The largest number of octets one preservation object or evidence may carry, 64 MiB.</summary>
    public int MaximumPayloadByteLength { get; init; } = 64 * 1024 * 1024;

    /// <summary>The largest number of characters an identifier-valued element may occupy, 1024 — the object identifier, a version identifier, a format identifier, a profile identifier.</summary>
    public int MaximumIdentifierLength { get; init; } = 1024;

    /// <summary>
    /// The largest number of values one repeatable identifier-valued element may state, 4096 — a search
    /// response's preservation-object identifiers, a profile's preservation goals, a retrieval request's format
    /// identifiers.
    /// </summary>
    /// <remarks>
    /// Bounding each value's length without bounding how many there are leaves the list itself unbounded, which
    /// is a resource question rather than a value question: the specification states these elements at
    /// <c>0..unbounded</c>, so the cardinality bound can only be this library's. The elements a narrower bound
    /// already covers keep it — a retrieval request's version identifiers are held to
    /// <see cref="MaximumVersionIdentifiers"/> first — and this is the floor under every identifier list that
    /// has no bound of its own.
    /// </remarks>
    public int MaximumIdentifiers { get; init; } = 4096;

    /// <summary>The largest number of <c>VersionID</c> elements one retrieval request may state, 256.</summary>
    public int MaximumVersionIdentifiers { get; init; } = 256;

    /// <summary>The largest number of identifier references one preservation object's <c>RelatedObjects</c> may state, 256.</summary>
    public int MaximumRelatedObjectReferences { get; init; } = 256;

    /// <summary>The largest number of profiles one discovery response may carry, 64.</summary>
    public int MaximumProfiles { get; init; } = 64;

    /// <summary>The largest number of events one trace may carry, 4096.</summary>
    public int MaximumTraceEvents { get; init; } = 4096;

    /// <summary>The largest number of characters a <c>Filter</c> element may occupy, 4096.</summary>
    public int MaximumFilterLength { get; init; } = 4096;

    /// <summary>The largest number of sub-components carried verbatim in one list, 64 — optional inputs, optional outputs, profile extensions.</summary>
    public int MaximumOpaqueElements { get; init; } = 64;

    /// <summary>The largest number of octets one verbatim-carried sub-component may occupy, 1 MiB.</summary>
    public int MaximumOpaqueElementByteLength { get; init; } = 1024 * 1024;
}


/// <summary>
/// Why <see cref="PreservationMessageBounds.State"/> did, or did not, admit a message.
/// </summary>
/// <remarks>
/// <see cref="WithinBounds"/> is deliberately not zero: a status that has not been computed must not read as an
/// admitted message.
/// </remarks>
public enum PreservationMessageStatus
{
    /// <summary>No bounds check has been performed. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The message is inside every bound and states every value its own clause requires.</summary>
    WithinBounds = 1,

    /// <summary>More preservation objects than <see cref="PreservationMessageLimits.MaximumPreservationObjects"/>.</summary>
    TooManyPreservationObjects = 2,

    /// <summary>A payload longer than <see cref="PreservationMessageLimits.MaximumPayloadByteLength"/>.</summary>
    PayloadTooLarge = 3,

    /// <summary>An identifier-valued element longer than <see cref="PreservationMessageLimits.MaximumIdentifierLength"/>.</summary>
    IdentifierTooLong = 4,

    /// <summary>More version identifiers than <see cref="PreservationMessageLimits.MaximumVersionIdentifiers"/>.</summary>
    TooManyVersionIdentifiers = 5,

    /// <summary>More identifier references than <see cref="PreservationMessageLimits.MaximumRelatedObjectReferences"/>.</summary>
    TooManyRelatedObjectReferences = 6,

    /// <summary>More profiles than <see cref="PreservationMessageLimits.MaximumProfiles"/>.</summary>
    TooManyProfiles = 7,

    /// <summary>More trace events than <see cref="PreservationMessageLimits.MaximumTraceEvents"/>.</summary>
    TooManyTraceEvents = 8,

    /// <summary>A filter longer than <see cref="PreservationMessageLimits.MaximumFilterLength"/>.</summary>
    FilterTooLong = 9,

    /// <summary>More verbatim-carried sub-components than <see cref="PreservationMessageLimits.MaximumOpaqueElements"/>.</summary>
    TooManyOpaqueElements = 10,

    /// <summary>A verbatim-carried sub-component longer than <see cref="PreservationMessageLimits.MaximumOpaqueElementByteLength"/>.</summary>
    OpaqueElementTooLarge = 11,

    /// <summary>
    /// A repeatable element the message's own clause requires at least one of was stated empty — the deltas of an
    /// update request, or a profile's operations, policies, goals or evidence formats.
    /// </summary>
    RequiredValueAbsent = 12,

    /// <summary>
    /// A preservation object states neither a format identifier nor a media type, which clause 5.4.5.1 forbids:
    /// the media type "shall be present, if the <c>FormatId</c> element is omitted".
    /// </summary>
    MediaTypeAbsent = 13,

    /// <summary>A profile states neither one nor two policies, the cardinality clause 5.4.7.1 gives.</summary>
    PolicyCountNotStated = 14,

    /// <summary>
    /// A profile whose storage model is temporary storage states no evidence retention period, which clause
    /// 5.4.7.1 requires "in case of preservation with temporary storage".
    /// </summary>
    RetentionPeriodAbsent = 15,

    /// <summary>A payload carries no content form, so nothing states which alternative of the value choice it came from.</summary>
    ContentFormNotStated = 16,

    /// <summary>More values in one repeatable identifier-valued element than <see cref="PreservationMessageLimits.MaximumIdentifiers"/>.</summary>
    TooManyIdentifiers = 17
}


/// <summary>
/// States whether one message of the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> is inside the bounds a peer applies to it and states the values its own clause
/// requires but no type can carry.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What this checks and what it does not.</strong> It checks bounds, the "at least one" cardinalities a
/// list type cannot state, the media-type obligation of clause 5.4.5.1, the policy cardinality of clause 5.4.7.1
/// and the retention-period condition of the same clause. It judges no vocabulary value — whether a storage
/// model, a goal or a result code is one the specification states is what the recognition helpers of
/// <see cref="PreservationWellKnown"/>, <see cref="PreservationFormatWellKnown"/> and
/// <see cref="PreservationResultWellKnown"/> answer, and a peer decides for itself how strict to be about a value
/// it does not recognise.
/// </para>
/// <para>
/// <strong>It is pure over its inputs.</strong> No clock is read, no ambient state is consulted and nothing is
/// disposed: the same message and the same bounds always answer the same.
/// </para>
/// </remarks>
public static class PreservationMessageBounds
{
    /// <summary>States whether a message is admissible under the given bounds.</summary>
    /// <param name="message">The message, as it was built or as a parse produced it.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>
    /// <see cref="PreservationMessageStatus.WithinBounds"/> when the message is admissible, and the first
    /// violation found otherwise.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when either argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// The switch is exhaustive over the sixteen cases the closed hierarchy admits; the discard arm exists
    /// because the compiler cannot see that and answers <see cref="PreservationMessageStatus.NotEvaluated"/>,
    /// which is not an admission.
    /// </remarks>
    public static PreservationMessageStatus State(PreservationMessage message, PreservationMessageLimits limits)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(limits);

        PreservationMessageStatus baseStatus = message switch
        {
            PreservationRequest request => StateOpaqueElements(request.OptionalInputs, limits),
            PreservationResponse response => StateResponseBase(response, limits),
            _ => PreservationMessageStatus.NotEvaluated
        };

        if(baseStatus != PreservationMessageStatus.WithinBounds)
        {
            return baseStatus;
        }

        PreservationMessageStatus identifierStatus = StateIdentifier(message.RequestId, limits);
        if(identifierStatus != PreservationMessageStatus.WithinBounds)
        {
            return identifierStatus;
        }

        return message switch
        {
            RetrieveInfoRequest request =>
                Combine(StateIdentifier(request.ProfileIdentifier, limits), StateIdentifier(request.Status, limits)),
            RetrieveInfoResponse response => StateProfiles(response.Profiles, limits),
            PreservePreservationObjectRequest request =>
                Combine(StateIdentifier(request.ProfileIdentifier, limits), StateObjects(request.PreservationObjects, limits)),
            PreservePreservationObjectResponse response =>
                Combine(StateIdentifier(response.PreservationObjectId, limits), StateObjects(response.PreservationObjects, limits)),
            RetrievePreservationObjectRequest request => StateRetrieveRequest(request, limits),
            RetrievePreservationObjectResponse response => StateObjects(response.PreservationObjects, limits),
            DeletePreservationObjectRequest request =>
                Combine(StateIdentifier(request.PreservationObjectId, limits), StateIdentifier(request.Mode, limits)),
            DeletePreservationObjectResponse => PreservationMessageStatus.WithinBounds,
            UpdatePreservationObjectContainerRequest request => StateUpdateRequest(request, limits),
            UpdatePreservationObjectContainerResponse response => StateIdentifier(response.VersionId, limits),
            RetrieveTraceRequest request => StateIdentifier(request.PreservationObjectId, limits),
            RetrieveTraceResponse response => StateTrace(response.Trace, limits),
            ValidateEvidenceRequest request =>
                Combine(StateEvidence(request.Evidence, limits), StateObjects(request.PreservationObjects, limits)),
            ValidateEvidenceResponse response =>
                response.ValidationReport is null ? PreservationMessageStatus.WithinBounds : StateObject(response.ValidationReport, limits),
            SearchRequest request => StateFilter(request.Filter, limits),
            SearchResponse response => StateIdentifiers(response.PreservationObjectIds, limits),
            _ => PreservationMessageStatus.NotEvaluated
        };
    }


    /// <summary>States the bounds every response shares — its optional outputs and its result codes.</summary>
    /// <param name="response">The response.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateResponseBase(PreservationResponse response, PreservationMessageLimits limits) =>
        Combine(
            StateOpaqueElements(response.OptionalOutputs, limits),
            Combine(StateIdentifier(response.Result.ResultMajor, limits), StateIdentifier(response.Result.ResultMinor, limits)));


    /// <summary>States the bounds of a retrieval request, whose version identifiers and format identifiers are its own.</summary>
    /// <param name="request">The retrieval request.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateRetrieveRequest(RetrievePreservationObjectRequest request, PreservationMessageLimits limits)
    {
        if(request.VersionIds.Count > limits.MaximumVersionIdentifiers)
        {
            return PreservationMessageStatus.TooManyVersionIdentifiers;
        }

        return Combine(
            StateIdentifier(request.PreservationObjectId, limits),
            Combine(
                StateIdentifiers(request.VersionIds, limits),
                Combine(
                    StateIdentifier(request.SubjectOfRetrieval, limits),
                    Combine(
                        StateIdentifier(request.PreservationObjectFormat, limits),
                        StateIdentifier(request.EvidenceFormat, limits)))));
    }


    /// <summary>States the bounds of an update request, which requires at least one delta.</summary>
    /// <param name="request">The update request.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateUpdateRequest(UpdatePreservationObjectContainerRequest request, PreservationMessageLimits limits)
    {
        if(request.DeltaContainers.Count == 0)
        {
            return PreservationMessageStatus.RequiredValueAbsent;
        }

        return Combine(StateIdentifier(request.PreservationObjectId, limits), StateObjects(request.DeltaContainers, limits));
    }


    /// <summary>States the bounds of a trace and of every event in it.</summary>
    /// <param name="trace">The trace.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateTrace(PreservationTrace trace, PreservationMessageLimits limits)
    {
        if(trace.Events.Count > limits.MaximumTraceEvents)
        {
            return PreservationMessageStatus.TooManyTraceEvents;
        }

        foreach(PreservationEvent stated in trace.Events)
        {
            PreservationMessageStatus status = Combine(
                StateIdentifier(stated.Subject, limits),
                Combine(StateIdentifier(stated.Operation, limits), StateIdentifier(stated.Object, limits)));
            if(status != PreservationMessageStatus.WithinBounds)
            {
                return status;
            }
        }

        return PreservationMessageStatus.WithinBounds;
    }


    /// <summary>States the bounds of a list of preservation objects.</summary>
    /// <param name="objects">The objects.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateObjects(IReadOnlyList<PreservationObject> objects, PreservationMessageLimits limits)
    {
        if(objects.Count > limits.MaximumPreservationObjects)
        {
            return PreservationMessageStatus.TooManyPreservationObjects;
        }

        foreach(PreservationObject stated in objects)
        {
            PreservationMessageStatus status = StateObject(stated, limits);
            if(status != PreservationMessageStatus.WithinBounds)
            {
                return status;
            }
        }

        return PreservationMessageStatus.WithinBounds;
    }


    /// <summary>States the bounds of one preservation object, including the media-type obligation of clause 5.4.5.1.</summary>
    /// <param name="preservationObject">The object.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateObject(PreservationObject preservationObject, PreservationMessageLimits limits)
    {
        if(preservationObject.ContentForm == PreservationContentForm.NotEvaluated)
        {
            return PreservationMessageStatus.ContentFormNotStated;
        }

        if(preservationObject.Content.Length > limits.MaximumPayloadByteLength)
        {
            return PreservationMessageStatus.PayloadTooLarge;
        }

        if(preservationObject.FormatId is null && preservationObject.MimeType is null)
        {
            return PreservationMessageStatus.MediaTypeAbsent;
        }

        if(preservationObject.RelatedObjects.Count > limits.MaximumRelatedObjectReferences)
        {
            return PreservationMessageStatus.TooManyRelatedObjectReferences;
        }

        return Combine(
            StateIdentifier(preservationObject.FormatId, limits),
            Combine(
                StateIdentifier(preservationObject.MimeType, limits),
                Combine(StateIdentifier(preservationObject.Id, limits), StateIdentifiers(preservationObject.RelatedObjects, limits))));
    }


    /// <summary>States the bounds of one evidence, whose format identifier its own clause makes mandatory.</summary>
    /// <param name="evidence">The evidence.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateEvidence(PreservationEvidence evidence, PreservationMessageLimits limits)
    {
        if(evidence.ContentForm == PreservationContentForm.NotEvaluated)
        {
            return PreservationMessageStatus.ContentFormNotStated;
        }

        if(evidence.Content.Length > limits.MaximumPayloadByteLength)
        {
            return PreservationMessageStatus.PayloadTooLarge;
        }

        if(evidence.RelatedObjects.Count > limits.MaximumRelatedObjectReferences)
        {
            return PreservationMessageStatus.TooManyRelatedObjectReferences;
        }

        return Combine(
            StateIdentifier(evidence.FormatId, limits),
            Combine(
                StateIdentifier(evidence.PreservationObjectId, limits),
                Combine(StateIdentifier(evidence.VersionId, limits), StateIdentifiers(evidence.RelatedObjects, limits))));
    }


    /// <summary>States the bounds of a list of profiles.</summary>
    /// <param name="profiles">The profiles.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateProfiles(IReadOnlyList<PreservationProfile> profiles, PreservationMessageLimits limits)
    {
        if(profiles.Count > limits.MaximumProfiles)
        {
            return PreservationMessageStatus.TooManyProfiles;
        }

        foreach(PreservationProfile profile in profiles)
        {
            PreservationMessageStatus status = StateProfile(profile, limits);
            if(status != PreservationMessageStatus.WithinBounds)
            {
                return status;
            }
        }

        return PreservationMessageStatus.WithinBounds;
    }


    /// <summary>
    /// States the bounds of one profile, including the three obligations of clause 5.4.7.1 that no type can carry:
    /// the mandatory-repeatable elements, the policy cardinality and the conditional retention period.
    /// </summary>
    /// <param name="profile">The profile.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateProfile(PreservationProfile profile, PreservationMessageLimits limits)
    {
        if(profile.Operations.Count == 0
            || profile.PreservationGoals.Count == 0
            || profile.EvidenceFormats.Count == 0)
        {
            return PreservationMessageStatus.RequiredValueAbsent;
        }

        if(profile.Policies.Count is not (1 or 2))
        {
            return PreservationMessageStatus.PolicyCountNotStated;
        }

        //A profile is the one component whose own repeated elements are all stated 0..unbounded or 1..unbounded,
        //so one profile is enough to carry an unbounded message. They are held to the same cardinality floor as
        //every other repeated identifier-valued element rather than to a bound of their own.
        if(profile.Operations.Count > limits.MaximumIdentifiers
            || profile.EvidenceFormats.Count > limits.MaximumIdentifiers
            || profile.Specifications.Count > limits.MaximumIdentifiers
            || profile.Descriptions.Count > limits.MaximumIdentifiers)
        {
            return PreservationMessageStatus.TooManyIdentifiers;
        }

        bool isTemporaryStorage = string.Equals(
            profile.StorageModel,
            PreservationWellKnown.WithTemporaryStorageModel,
            StringComparison.Ordinal);
        if(isTemporaryStorage && profile.PreservationEvidenceRetentionPeriod is null)
        {
            return PreservationMessageStatus.RetentionPeriodAbsent;
        }

        PreservationMessageStatus extensionStatus = StateOpaqueElements(profile.Extensions, limits);
        if(extensionStatus != PreservationMessageStatus.WithinBounds)
        {
            return extensionStatus;
        }

        foreach(PreservationOperationDescriptor operation in profile.Operations)
        {
            if(operation.InputFormats.Count > limits.MaximumIdentifiers
                || operation.OutputFormats.Count > limits.MaximumIdentifiers)
            {
                return PreservationMessageStatus.TooManyIdentifiers;
            }

            PreservationMessageStatus status = Combine(
                StateIdentifier(operation.Name, limits),
                StateIdentifiers(operation.Options, limits));
            if(status != PreservationMessageStatus.WithinBounds)
            {
                return status;
            }
        }

        return Combine(
            StateIdentifier(profile.ProfileIdentifier, limits),
            Combine(
                StateIdentifier(profile.SchemeIdentifier, limits),
                Combine(StateIdentifier(profile.StorageModel, limits), StateIdentifiers(profile.PreservationGoals, limits))));
    }


    /// <summary>States the bounds of a list of sub-components carried verbatim.</summary>
    /// <param name="elements">The elements.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateOpaqueElements(IReadOnlyList<PreservationOpaqueElement> elements, PreservationMessageLimits limits)
    {
        if(elements.Count > limits.MaximumOpaqueElements)
        {
            return PreservationMessageStatus.TooManyOpaqueElements;
        }

        foreach(PreservationOpaqueElement element in elements)
        {
            if(element.Content.Length > limits.MaximumOpaqueElementByteLength)
            {
                return PreservationMessageStatus.OpaqueElementTooLarge;
            }

            PreservationMessageStatus status = StateIdentifier(element.Identifier, limits);
            if(status != PreservationMessageStatus.WithinBounds)
            {
                return status;
            }
        }

        return PreservationMessageStatus.WithinBounds;
    }


    /// <summary>States whether one identifier-valued value is inside the length bound.</summary>
    /// <param name="value">The value, or <see langword="null"/> when the message stated none.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns><see cref="PreservationMessageStatus.IdentifierTooLong"/> or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateIdentifier(string? value, PreservationMessageLimits limits) =>
        value is not null && value.Length > limits.MaximumIdentifierLength
            ? PreservationMessageStatus.IdentifierTooLong
            : PreservationMessageStatus.WithinBounds;


    /// <summary>States whether a list of identifier-valued elements is inside both the count bound and the length bound.</summary>
    /// <param name="values">The values.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns>The first violation, or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    /// <remarks>
    /// The count is checked before the values, so a list too long to admit is refused without walking it. Every
    /// repeatable identifier-valued element of the eight operations passes through here, which is what makes
    /// <see cref="PreservationMessageLimits.MaximumIdentifiers"/> a bound on the whole shape rather than on one
    /// message's arm.
    /// </remarks>
    private static PreservationMessageStatus StateIdentifiers(IReadOnlyList<string> values, PreservationMessageLimits limits)
    {
        if(values.Count > limits.MaximumIdentifiers)
        {
            return PreservationMessageStatus.TooManyIdentifiers;
        }

        foreach(string value in values)
        {
            if(value.Length > limits.MaximumIdentifierLength)
            {
                return PreservationMessageStatus.IdentifierTooLong;
            }
        }

        return PreservationMessageStatus.WithinBounds;
    }


    /// <summary>States whether a filter is inside its own length bound.</summary>
    /// <param name="filter">The filter, or <see langword="null"/>.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <returns><see cref="PreservationMessageStatus.FilterTooLong"/> or <see cref="PreservationMessageStatus.WithinBounds"/>.</returns>
    private static PreservationMessageStatus StateFilter(string? filter, PreservationMessageLimits limits) =>
        filter is not null && filter.Length > limits.MaximumFilterLength
            ? PreservationMessageStatus.FilterTooLong
            : PreservationMessageStatus.WithinBounds;


    /// <summary>Returns the first of two statuses that is not an admission.</summary>
    /// <param name="first">The status checked first.</param>
    /// <param name="second">The status checked second.</param>
    /// <returns><paramref name="first"/> when it is not <see cref="PreservationMessageStatus.WithinBounds"/>, and <paramref name="second"/> otherwise.</returns>
    private static PreservationMessageStatus Combine(PreservationMessageStatus first, PreservationMessageStatus second) =>
        first != PreservationMessageStatus.WithinBounds ? first : second;
}
