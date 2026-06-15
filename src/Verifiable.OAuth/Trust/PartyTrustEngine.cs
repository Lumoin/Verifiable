namespace Verifiable.OAuth.Trust;

/// <summary>
/// A mechanism by which trust in an OAuth/OID4VP counterparty is established. The
/// engine is neutral over the mechanism; each is supplied by an adapter that lifts
/// mechanism-specific proof into <see cref="TrustEvidence{TMechanismEvidence}"/> and
/// contributes <see cref="TrustAssessorDelegate{TMechanismEvidence}"/> instances —
/// exactly as SD-JWT / mdoc / SD-CWT are format primitives behind the DCQL disclosure
/// engine.
/// </summary>
/// <remarks>
/// The well-known values mirror the trust paths OAuth/OID4VP already exposes as
/// client-id prefixes (<c>openid_federation</c>, <c>x509_san_dns</c>/<c>x509_hash</c>,
/// <c>did</c>, <c>verifier_attestation</c>). They are identifiers, not transport.
/// </remarks>
public readonly record struct TrustMechanism(string Value)
{
    /// <summary>OpenID Federation 1.0 — a trust chain of Entity Statements to a Trust Anchor.</summary>
    public static TrustMechanism OpenIdFederation { get; } = new("openid_federation");

    /// <summary>An X.509 certificate chain to a trusted root (OID4VP x509_*, mdoc IACA, AdES, TPM).</summary>
    public static TrustMechanism X509Chain { get; } = new("x509_chain");

    /// <summary>A Decentralized Identifier document resolved for the party.</summary>
    public static TrustMechanism DecentralizedIdentifier { get; } = new("did");

    /// <summary>A verifier-attestation JWT vouched for by a trusted attester.</summary>
    public static TrustMechanism VerifierAttestation { get; } = new("verifier_attestation");
}


/// <summary>
/// The kind of a <see cref="TrustSignal"/>. Signals are the dynamic dimension: a
/// pull-based status (Token Status List, trust-mark status, certificate revocation,
/// statement <c>exp</c>) or a pushed Continuous Access Evaluation Profile (CAEP)
/// event delivered over the Shared Signals Framework. The engine consumes signals
/// as DATA in a <see cref="TrustSignalSnapshot"/>; the transport (polling, SSF
/// streams) is a provider concern outside the engine.
/// </summary>
public readonly record struct TrustSignalKind(string Value)
{
    /// <summary>The subject was revoked (credential, key, registration, trust mark).</summary>
    public static TrustSignalKind Revocation { get; } = new("revocation");

    /// <summary>A Token Status List entry (valid / revoked / suspended) for the subject.</summary>
    public static TrustSignalKind StatusListEntry { get; } = new("status_list");

    /// <summary>A freshness / expiry bound on the subject (e.g. statement or mark <c>exp</c>).</summary>
    public static TrustSignalKind Expiry { get; } = new("expiry");

    /// <summary>A CAEP event (session-revoked, credential-change, assurance-level-change, …).</summary>
    public static TrustSignalKind CaepEvent { get; } = new("caep_event");
}


/// <summary>
/// One trust signal about a subject (a party, key, credential, or mark identifier).
/// </summary>
public sealed record TrustSignal
{
    /// <summary>What the signal asserts.</summary>
    public required TrustSignalKind Kind { get; init; }

    /// <summary>The identifier the signal is about (party id, key id, credential id, mark id).</summary>
    public required string Subject { get; init; }

    /// <summary>When the signal was observed, when known.</summary>
    public DateTimeOffset? ObservedAt { get; init; }

    /// <summary>Mechanism-specific detail (status value, event payload, revocation reason).</summary>
    public IReadOnlyDictionary<string, object>? Detail { get; init; }
}


/// <summary>
/// The set of signals known to the assessment at a point in time. Fed to the engine
/// as immutable data; re-assessment is "run the engine again against a newer snapshot."
/// </summary>
public sealed record TrustSignalSnapshot
{
    /// <summary>The instant this snapshot reflects.</summary>
    public required DateTimeOffset AsOf { get; init; }

    /// <summary>The signals observed as of <see cref="AsOf"/>.</summary>
    public IReadOnlyList<TrustSignal> Signals { get; init; } = [];

    /// <summary>An empty snapshot (no signals known) as of <paramref name="asOf"/>.</summary>
    public static TrustSignalSnapshot Empty(DateTimeOffset asOf) => new() { AsOf = asOf };
}


/// <summary>
/// The neutral subject of a trust assessment plus its mechanism-specific proof.
/// The mechanism-neutral analogue of <c>DisclosureMatch&lt;TCredential&gt;</c>: the
/// engine reasons over the neutral fields, while <typeparamref name="TMechanismEvidence"/>
/// carries the typed proof (a Federation trust chain, an X.509 chain, a DID document)
/// that mechanism assessors understand.
/// </summary>
/// <typeparam name="TMechanismEvidence">The mechanism-specific proof type.</typeparam>
public sealed record TrustEvidence<TMechanismEvidence>
{
    /// <summary>The party being assessed (Entity Identifier, client_id, DID, …).</summary>
    public required string PartyIdentifier { get; init; }

    /// <summary>The mechanism the proof belongs to.</summary>
    public required TrustMechanism Mechanism { get; init; }

    /// <summary>The typed mechanism proof the assessors validate.</summary>
    public required TMechanismEvidence MechanismEvidence { get; init; }

    /// <summary>
    /// The metadata the party asserts about itself, before policy/constraints are
    /// applied. Assessors narrow this into the effective metadata.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AssertedMetadata { get; init; }

    /// <summary>The trust roots the assessment must reach (anchors / trusted CAs / trusted attesters).</summary>
    public IReadOnlyList<string> TrustAnchors { get; init; } = [];
}


/// <summary>
/// The per-call context handed to each <see cref="TrustAssessorDelegate{TMechanismEvidence}"/>.
/// All inputs an assessor needs are explicit on this record — caller/app data never
/// reaches an assessor through a captured closure.
/// </summary>
/// <typeparam name="TMechanismEvidence">The mechanism-specific proof type.</typeparam>
public sealed record TrustAssessmentContext<TMechanismEvidence>
{
    /// <summary>The party and its proof.</summary>
    public required TrustEvidence<TMechanismEvidence> Evidence { get; init; }

    /// <summary>The signals known for this assessment.</summary>
    public required TrustSignalSnapshot Signals { get; init; }

    /// <summary>The assessment instant (clock injected by the caller).</summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>
    /// The effective metadata accumulated by assessors that ran earlier in the
    /// pipeline; an assessor narrows from here (the running meet).
    /// </summary>
    public IReadOnlyDictionary<string, object>? CurrentEffectiveMetadata { get; init; }
}


/// <summary>The disposition an assessor returns. Monotone: an assessor may only confirm, narrow, or reject — never broaden trust.</summary>
public enum TrustVerdictOutcome
{
    /// <summary>This assessor's concern is satisfied; trust is unaffected.</summary>
    Affirm,

    /// <summary>Trust holds but is constrained (narrowed metadata, shortened validity, added triggers).</summary>
    Constrain,

    /// <summary>This assessor refuses trust; the pipeline stops and the party is untrusted.</summary>
    Reject
}


/// <summary>
/// A signal whose future arrival invalidates the assessment. Recorded on the
/// <see cref="PartyTrustAssessment"/> so a caller can subscribe (CAEP/SSF), poll
/// (status list / trust-mark status), or schedule re-evaluation (expiry).
/// </summary>
public sealed record ReevaluationTrigger
{
    /// <summary>The signal kind that would invalidate the assessment.</summary>
    public required TrustSignalKind Kind { get; init; }

    /// <summary>The subject to watch (party id, key id, credential id, mark id).</summary>
    public required string Subject { get; init; }

    /// <summary>Optional pointer (status-list URI, stream id, the <c>exp</c> instant).</summary>
    public string? Detail { get; init; }
}


/// <summary>
/// One assessor's verdict. The Layer-4 unit of the pipeline (see
/// <see cref="PartyTrustEngine"/>): rule-based (e.g. Federation entity-statement and
/// trust-chain checks), constraint-based, signal-based (revocation/CAEP), or
/// risk/trust scoring.
/// </summary>
public sealed record TrustAssessorVerdict
{
    /// <summary>The disposition.</summary>
    public required TrustVerdictOutcome Outcome { get; init; }

    /// <summary>An identifier for the assessor, for the decision record.</summary>
    public string? AssessorId { get; init; }

    /// <summary>Why, when <see cref="Outcome"/> is <see cref="TrustVerdictOutcome.Reject"/> or a narrowing.</summary>
    public string? Reason { get; init; }

    /// <summary>
    /// The assessor's narrowed view of the effective metadata (e.g. the result of
    /// applying Federation metadata policy). The assessor owns the lattice/meet; the
    /// engine simply adopts the latest constrained view.
    /// </summary>
    public IReadOnlyDictionary<string, object>? ConstrainedMetadata { get; init; }

    /// <summary>An upper bound on validity this assessor imposes (e.g. min statement <c>exp</c>).</summary>
    public DateTimeOffset? ValidUntil { get; init; }

    /// <summary>Signals whose arrival should re-fire the assessment.</summary>
    public IReadOnlyList<ReevaluationTrigger> ReevaluationTriggers { get; init; } = [];

    /// <summary>An <see cref="TrustVerdictOutcome.Affirm"/> verdict from <paramref name="assessorId"/>.</summary>
    public static TrustAssessorVerdict Affirm(string assessorId) =>
        new() { Outcome = TrustVerdictOutcome.Affirm, AssessorId = assessorId };

    /// <summary>A <see cref="TrustVerdictOutcome.Reject"/> verdict from <paramref name="assessorId"/> with <paramref name="reason"/>.</summary>
    public static TrustAssessorVerdict Reject(string assessorId, string reason) =>
        new() { Outcome = TrustVerdictOutcome.Reject, AssessorId = assessorId, Reason = reason };
}


/// <summary>
/// The Layer-4 assessor seam — the single extension point the party-trust engine drops
/// out to, mirroring <c>PolicyAssessorDelegate</c> in the DCQL disclosure engine. The
/// application composes a list of these (the engine behind the seam); a thin caller
/// (EndpointServer, verifier, wallet) invokes the engine.
/// </summary>
/// <typeparam name="TMechanismEvidence">The mechanism-specific proof type.</typeparam>
public delegate ValueTask<TrustAssessorVerdict> TrustAssessorDelegate<TMechanismEvidence>(
    TrustAssessmentContext<TMechanismEvidence> context,
    CancellationToken cancellationToken);


/// <summary>
/// The outcome of a party-trust assessment — whether the counterparty is trusted, its
/// effective (constraint-applied) metadata, and the temporal/signal envelope that makes
/// the result dynamic. The analogue of <c>CredentialDisclosureDecision</c>: a decision,
/// not a bare boolean.
/// </summary>
public sealed record PartyTrustAssessment
{
    /// <summary>The party assessed.</summary>
    public required string PartyIdentifier { get; init; }

    /// <summary>The mechanism the proof belonged to.</summary>
    public required TrustMechanism Mechanism { get; init; }

    /// <summary>Whether trust holds. False when any assessor rejected or no assessor affirmed (fail-closed).</summary>
    public required bool IsTrusted { get; init; }

    /// <summary>The instant the assessment was computed.</summary>
    public required DateTimeOffset AssessedAt { get; init; }

    /// <summary>The effective metadata after all narrowing assessors; empty when untrusted.</summary>
    public IReadOnlyDictionary<string, object> EffectiveMetadata { get; init; } =
        PartyTrustEngine.EmptyMetadata;

    /// <summary>
    /// The instant beyond which the assessment must not be relied upon without
    /// re-evaluation (the minimum bound across assessors). <see langword="null"/>
    /// when no assessor imposed a bound.
    /// </summary>
    public DateTimeOffset? ValidUntil { get; init; }

    /// <summary>Signals whose arrival invalidates this assessment and should trigger re-evaluation.</summary>
    public IReadOnlyList<ReevaluationTrigger> ReevaluationTriggers { get; init; } = [];

    /// <summary>The first rejection reason, when <see cref="IsTrusted"/> is false.</summary>
    public string? RejectionReason { get; init; }
}


/// <summary>
/// The auditable record of a single assessment — the inputs, every assessor verdict
/// in order, and the resulting <see cref="PartyTrustAssessment"/>. The Layer-6 analogue
/// of <c>DisclosureDecisionRecord</c> (audit / trace / explainability), and the
/// provenance narrative of the trust decision.
/// </summary>
/// <typeparam name="TMechanismEvidence">The mechanism-specific proof type.</typeparam>
public sealed record TrustDecisionRecord<TMechanismEvidence>
{
    /// <summary>The evidence assessed.</summary>
    public required TrustEvidence<TMechanismEvidence> Evidence { get; init; }

    /// <summary>The signal snapshot the assessment ran against.</summary>
    public required TrustSignalSnapshot Signals { get; init; }

    /// <summary>Every assessor verdict, in pipeline order (terminates at the first reject).</summary>
    public required IReadOnlyList<TrustAssessorVerdict> Verdicts { get; init; }

    /// <summary>The decision derived from the verdicts.</summary>
    public required PartyTrustAssessment Assessment { get; init; }

    /// <summary>Optional W3C trace correlation supplied by the caller.</summary>
    public string? TraceId { get; init; }
}


/// <summary>
/// The OAuth/OID4VP <strong>party-trust engine</strong> — a pure, mechanism-neutral
/// assessment of whether to trust a counterparty (a verifier, a relying party, or a
/// peer) in an OAuth/OID4VP exchange, given its mechanism proof, a signal snapshot, and
/// a clock. Modelled on the DCQL disclosure engine (<c>DisclosureComputation</c>): a
/// single entry, a neutral generic input, a pluggable assessor pipeline, and an
/// auditable decision record, wired behind one delegate seam with the application
/// supplying the engine.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope.</strong> This is the OAuth party-trust instance, not a universal trust
/// subsystem. It is mechanism-neutral <em>within OAuth</em> (the client-id-prefix
/// mechanisms — federation / x509 / did / verifier-attestation), and its consumers are
/// OAuth/OID4VP (verifier trust, client-id resolution, federation RP registration). The
/// cross-layer trust <em>primitives</em> (X.509 chain validation) live in
/// <c>Verifiable.Cryptography.Pki</c> and are shared with mdoc-IACA; only this assessment
/// orchestration is OAuth-shaped.
/// </para>
/// <para>
/// <strong>Shared epistemic frame.</strong> This engine and the DCQL disclosure engine
/// (<c>DisclosureComputation</c>) are two instances of one structure: <em>monotone
/// authority over a provenance lattice, emitting an auditable provenance narrative</em>.
/// The disclosure engine's "Authority monotonicity and provenance" remarks describe
/// <c>⊤ ⊇ S_issuer ⊇ S_holder ⊇ S_verifier ⊇ ⊥</c> — authority over disclosed information
/// that can only narrow along a chain. Party trust is the same shape: authority/vouching
/// flows monotone-decreasing from a Trust Anchor down the chain (metadata policy can only
/// constrain, never broaden — a genuine lattice meet, reusing <c>MetadataPolicyMerger</c>);
/// the <see cref="TrustDecisionRecord{TMechanismEvidence}"/> is the provenance trail; and
/// signals are entropy updates that revise the assessment over time. The shared structure
/// is why the two engines look alike — they are both epistemic engines, not copies.
/// </para>
/// <para>
/// <strong>Layering</strong> (the trust counterpart of the disclosure engine's layers):
/// </para>
/// <code>
/// ┌──────────────────────────────────────────────────────────────────────┐
/// │  Party + mechanism proof ──►        ◄── Trust anchors / policy         │
/// │  (Federation chain, X.509,          ◄── Signal snapshot (status,       │
/// │   DID doc, attestation)                  revocation, CAEP, expiry)     │
/// │            │                                     │                     │
/// │            ▼                                     ▼                     │
/// │  ┌─────────────────────────────────────────────────────┐              │
/// │  │  Layer 3   Trust structure                          │              │
/// │  │  path-to-anchor validity  +  metadata-policy MEET    │              │
/// │  │  (the policy meet is a genuine lattice — reuses      │              │
/// │  │   MetadataPolicyMerger/Applicator)                   │              │
/// │  └──────────────────────┬──────────────────────────────┘              │
/// │                         ▼                                             │
/// │  ┌─────────────────────────────────────────────────────┐              │
/// │  │  Layer 4   TrustAssessorDelegate pipeline           │              │
/// │  │  ┌───────────┐ ┌───────────┐ ┌───────────┐          │              │
/// │  │  │ rule-based│ │ signal /  │ │ risk /    │          │              │
/// │  │  │ (entity-  │ │ revocation│ │ trust     │          │              │
/// │  │  │  stmt,    │ │ (status,  │ │ scoring   │          │              │
/// │  │  │  chain)   │ │  CAEP)    │ │           │          │              │
/// │  │  └───────────┘ └───────────┘ └───────────┘          │              │
/// │  │  each may Affirm | Constrain | Reject (monotone)    │              │
/// │  └──────────────────────┬──────────────────────────────┘              │
/// │                         ▼                                             │
/// │  ┌─────────────────────────────────────────────────────┐              │
/// │  │  Layer 6   PartyTrustAssessment + TrustDecisionRecord│              │
/// │  │  decision · effective metadata · validity · triggers │              │
/// │  └─────────────────────────────────────────────────────┘              │
/// └──────────────────────────────────────────────────────────────────────┘
/// </code>
/// <para>
/// <strong>Execution.</strong> Assessors run in order against a per-call
/// <see cref="TrustAssessmentContext{TMechanismEvidence}"/>. Each verdict either affirms,
/// narrows (constrained metadata, a shorter validity bound, more re-evaluation triggers),
/// or rejects. A reject stops the pipeline (fail-closed). The running effective metadata
/// is the latest constrained view; <c>ValidUntil</c> is the minimum bound across
/// assessors; triggers are the union.
/// </para>
/// <para>
/// <strong>Invariants.</strong>
/// </para>
/// <list type="bullet">
///   <item><description><em>Fail-closed</em>: an empty assessor list yields <c>IsTrusted == false</c>; trust is never granted by default.</description></item>
///   <item><description><em>Monotonicity</em>: an assessor can only narrow or reject — no assessor broadens trust or widens effective metadata beyond its input.</description></item>
///   <item><description><em>Reject is terminal</em>: the first <see cref="TrustVerdictOutcome.Reject"/> ends the pipeline; later assessors do not run.</description></item>
///   <item><description><em>Validity is the meet</em>: <c>ValidUntil</c> is the earliest bound any assessor imposed.</description></item>
///   <item><description><em>Untrusted carries nothing</em>: a rejected assessment exposes empty effective metadata and no validity bound.</description></item>
/// </list>
/// </remarks>
public static class PartyTrustEngine
{
    internal static readonly IReadOnlyDictionary<string, object> EmptyMetadata =
        new Dictionary<string, object>(StringComparer.Ordinal);


    /// <summary>
    /// Runs the assessor pipeline over <paramref name="evidence"/> against
    /// <paramref name="signals"/> and returns the decision record.
    /// </summary>
    /// <typeparam name="TMechanismEvidence">The mechanism-specific proof type.</typeparam>
    /// <param name="evidence">The party and its mechanism proof.</param>
    /// <param name="signals">The signals known as of the assessment.</param>
    /// <param name="assessors">The ordered assessor pipeline (Layer 4).</param>
    /// <param name="now">The assessment instant (caller-injected clock).</param>
    /// <param name="traceId">Optional trace correlation for the record.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The assessment and its auditable record.</returns>
    public static async ValueTask<TrustDecisionRecord<TMechanismEvidence>> AssessAsync<TMechanismEvidence>(
        TrustEvidence<TMechanismEvidence> evidence,
        TrustSignalSnapshot signals,
        IReadOnlyList<TrustAssessorDelegate<TMechanismEvidence>> assessors,
        DateTimeOffset now,
        string? traceId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(signals);
        ArgumentNullException.ThrowIfNull(assessors);

        List<TrustAssessorVerdict> verdicts = new(assessors.Count);
        IReadOnlyDictionary<string, object> effectiveMetadata = evidence.AssertedMetadata ?? EmptyMetadata;
        DateTimeOffset? validUntil = null;
        List<ReevaluationTrigger> triggers = [];

        //Fail-closed: with no assessor to affirm trust, the party is untrusted.
        bool trusted = assessors.Count > 0;
        string? rejection = trusted ? null : "No trust assessors were configured; fail-closed.";

        foreach(TrustAssessorDelegate<TMechanismEvidence> assessor in assessors)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TrustAssessmentContext<TMechanismEvidence> context = new()
            {
                Evidence = evidence,
                Signals = signals,
                Now = now,
                CurrentEffectiveMetadata = effectiveMetadata
            };

            TrustAssessorVerdict verdict = await assessor(context, cancellationToken).ConfigureAwait(false);
            verdicts.Add(verdict);

            if(verdict.Outcome == TrustVerdictOutcome.Reject)
            {
                trusted = false;
                rejection = verdict.Reason ?? "Rejected by a trust assessor.";
                break;
            }

            //Monotone narrowing: adopt the assessor's constrained metadata, take the
            //earlier validity bound, and accumulate re-evaluation triggers.
            if(verdict.ConstrainedMetadata is not null)
            {
                effectiveMetadata = verdict.ConstrainedMetadata;
            }

            if(verdict.ValidUntil is { } verdictValidUntil)
            {
                validUntil = validUntil is { } current && current <= verdictValidUntil
                    ? current
                    : verdictValidUntil;
            }

            foreach(ReevaluationTrigger trigger in verdict.ReevaluationTriggers)
            {
                triggers.Add(trigger);
            }
        }

        PartyTrustAssessment assessment = new()
        {
            PartyIdentifier = evidence.PartyIdentifier,
            Mechanism = evidence.Mechanism,
            IsTrusted = trusted,
            AssessedAt = now,
            EffectiveMetadata = trusted ? effectiveMetadata : EmptyMetadata,
            ValidUntil = trusted ? validUntil : null,
            ReevaluationTriggers = triggers,
            RejectionReason = rejection
        };

        return new TrustDecisionRecord<TMechanismEvidence>
        {
            Evidence = evidence,
            Signals = signals,
            Verdicts = verdicts,
            Assessment = assessment,
            TraceId = traceId
        };
    }
}
