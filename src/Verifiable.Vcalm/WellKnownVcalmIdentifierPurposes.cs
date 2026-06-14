using System.Diagnostics;
using Verifiable.Server;

namespace Verifiable.Vcalm;

/// <summary>
/// Library-shipped <see cref="IdentifierPurpose"/> instances for the W3C VCALM 1.0
/// identifier-generation sites. The <see cref="IdentifierPurpose"/> TYPE lives in the neutral
/// <c>Verifiable.Server</c> host; the VALUES here are VCALM's, colocated with the VCALM endpoints
/// that consume them.
/// </summary>
/// <remarks>
/// Each purpose is a URN of the form
/// <c>urn:verifiable:identifier-purpose:vcalm:&lt;name&gt;</c>, threaded through the
/// identifier-generation seam so a deployment owns the value's format and entropy.
/// </remarks>
[DebuggerDisplay("WellKnownVcalmIdentifierPurposes")]
public static class WellKnownVcalmIdentifierPurposes
{
    /// <summary>
    /// VCALM 1.0 §3.3.3 verifier challenge — the random string the
    /// <c>POST /challenges</c> endpoint mints for a holder to embed as the presentation proof's
    /// <c>challenge</c>, then checks on a later §3.3.2 <c>/presentations/verify</c> call via the
    /// issued-challenge persistence seam ("track the number of times the challenge has been passed
    /// to verification endpoints as options.challenge").
    /// </summary>
    public static IdentifierPurpose VcalmChallenge { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:vcalm:challenge");

    /// <summary>
    /// VCALM 1.0 §C.1 status-list id — the identifier the <c>POST /status-lists</c> endpoint mints
    /// for a new status-list credential when the request omits <c>id</c> ("If not provided, the
    /// service will generate one."). Threaded through the identifier-generation seam so a deployment
    /// owns the value's format (e.g. the resolvable status-list-credential URL).
    /// </summary>
    public static IdentifierPurpose VcalmStatusListId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:vcalm:status-list-id");

    /// <summary>
    /// VCALM 1.0 §3.5.2 presentation id — the identifier the <c>POST /presentations</c> endpoint
    /// mints to key a created presentation in the §3.5.3 / §3.5.4 store when the presentation carries
    /// no <c>id</c> of its own. Threaded through the identifier-generation seam so a deployment owns
    /// the value's format. A presentation that already carries an <c>id</c> is stored under that id;
    /// this purpose is used only to fabricate a store key, never written into the presentation.
    /// </summary>
    public static IdentifierPurpose VcalmPresentationId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:vcalm:presentation-id");

    /// <summary>
    /// VCALM 1.0 §3.6.3 exchange id — the local exchange identifier the
    /// <c>POST /workflows/{localWorkflowId}/exchanges</c> endpoint mints for a new exchange instance.
    /// It is the <c>{localExchangeId}</c> path segment the §3.6.4 / §3.6.5 / §3.6.6 endpoints address
    /// the exchange by and the §3.6 capability-URL secret possession alone authorizes participation
    /// with ("Initiating the exchange does not require any authorization beyond the exchange URL […]
    /// exchange URLs can also be capability URLs"). Threaded through the host-generic
    /// identifier-generation seam so a deployment owns the value's format and entropy.
    /// </summary>
    public static IdentifierPurpose VcalmExchangeId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:vcalm:exchange-id");

    /// <summary>
    /// VCALM 1.0 §3.6.3 exchange challenge — the anti-replay nonce the exchange engine mints when it
    /// issues a §3.4 verifiable presentation request to the holder during a §3.6.5 vcapi step
    /// ("createChallenge"); the holder echoes it in the presentation proof and the engine binds the
    /// returned <c>verifiablePresentation</c> against it. Threaded through the identifier-generation
    /// seam so a deployment owns the value's format and entropy. The exchange's <c>expires</c> bounds
    /// the challenge's lifetime (§3.6.2: "if a challenge is bound to an exchange, that challenge
    /// ceases to be valid at the date referenced by the expires property of the exchange").
    /// </summary>
    public static IdentifierPurpose VcalmExchangeChallenge { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:vcalm:exchange-challenge");

    /// <summary>
    /// VCALM 1.0 §3.6.5 exchange reference id — the <c>urn:uuid:</c> correlation value the exchange
    /// engine MAY include in a vcapi message ("A server MAY include a referenceId property in an
    /// exchange message […] The value of referenceId SHOULD be a urn:uuid: value."). When the engine
    /// sends one, the holder SHOULD echo it on its next message; it aids debugging and links
    /// potentially delayed or misordered messages to the correct request. Threaded through the
    /// identifier-generation seam so a deployment owns the value's format.
    /// </summary>
    public static IdentifierPurpose VcalmExchangeReferenceId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:vcalm:exchange-reference-id");

    /// <summary>
    /// VCALM 1.0 §3.6.1 workflow id — the local workflow identifier the <c>POST /workflows</c> endpoint
    /// mints for a new workflow when the create request omits <c>id</c> (§3.6.1: "Passing an ID is
    /// OPTIONAL"). It is the <c>{localWorkflowId}</c> path segment the §3.6.2 read and the §3.6.3
    /// create-exchange endpoint address the workflow by. Threaded through the host-generic
    /// identifier-generation seam so a deployment owns the value's format.
    /// </summary>
    public static IdentifierPurpose VcalmWorkflowId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:vcalm:workflow-id");

    /// <summary>
    /// VCALM 1.0 §3.6.7 callback id — the local callback identifier the engine mints to form a
    /// <c>POST /callbacks/{localCallbackId}</c> capability URL when a step carries a callback. §3.6.7:
    /// "the 'localCallbackId' value must express at least 128-bits of random information in order to
    /// ensure the full callback URL can be treated as a capability URL." Threaded through the
    /// host-generic identifier-generation seam so a deployment owns the value's format and supplies the
    /// REQUIRED ≥128-bit entropy.
    /// </summary>
    public static IdentifierPurpose VcalmCallbackId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:vcalm:callback-id");

    /// <summary>
    /// VCALM 1.0 §3.7.1 interaction id — the interaction-specific identifier the coordinator mints to
    /// form a §3.7.1 interaction URL (<c>https://app.example/interactions/{localInteractionId}?iuv=1</c>).
    /// §3.7.1: the URL "SHOULD be opaque and require no URL syntax processing before it is fetched"; the
    /// coordinator owns the value's format and entropy through this seam, so the id can carry the
    /// capability-URL guess-resistance a §3.7 interaction needs.
    /// </summary>
    public static IdentifierPurpose VcalmInteractionId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:vcalm:interaction-id");
}
