using System.Globalization;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Trust;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Adapts OpenID Federation trust-chain validation into the neutral
/// <see cref="PartyTrustEngine"/> — the first mechanism provider behind the
/// party-trust assessor seam. It lifts an already-computed
/// <see cref="TrustChainValidationOutcome"/> into a
/// <see cref="TrustEvidence{TMechanismEvidence}"/> and contributes the Federation
/// assessors, exactly as a credential format is a primitive behind the DCQL
/// disclosure engine.
/// </summary>
/// <remarks>
/// <para>
/// The mechanism evidence is the <see cref="TrustChainValidationOutcome"/> itself, so
/// the assessors are stateless static delegates that read the outcome from the
/// per-call context — no caller data is captured in a closure. The heavy chain
/// validation (signature verification, anchor termination, metadata policy) is the
/// existing Federation pipeline's job (<c>TrustChainValidator</c> /
/// <c>EntityStatementValidator</c>); this adapter surfaces its result into a trust
/// decision.
/// </para>
/// <para>
/// Authority in a Federation chain flows monotone-decreasing from the Trust Anchor
/// down to the leaf — the same provenance-lattice shape the disclosure engine
/// documents (<c>⊤ ⊇ … ⊇ ⊥</c>). The freshness assessor bounds the assessment's
/// validity to the chain's earliest <c>exp</c> and emits an expiry re-evaluation
/// trigger; richer dynamic signals (trust-mark status, revocation, CAEP) are
/// additional assessors layered behind the same seam.
/// </para>
/// </remarks>
public static class FederationTrustAdapter
{
    private const string ChainAssessorId = "federation.trust-chain";
    private const string FreshnessAssessorId = "federation.freshness";


    /// <summary>The mechanism this adapter provides.</summary>
    public static TrustMechanism Mechanism => TrustMechanism.OpenIdFederation;


    /// <summary>
    /// The Federation assessor pipeline in order: chain validity, then freshness.
    /// Pass to <see cref="PartyTrustEngine.AssessAsync{TMechanismEvidence}"/>.
    /// </summary>
    public static IReadOnlyList<TrustAssessorDelegate<TrustChainValidationOutcome>> Assessors { get; } =
        [AssessChainValidityAsync, AssessFreshnessAsync];


    /// <summary>
    /// Lifts a Federation trust-chain validation outcome into neutral party-trust
    /// evidence: the leaf entity id as the party, the chain's anchor as the trust
    /// anchor, and the outcome as the mechanism evidence the assessors read.
    /// </summary>
    /// <param name="outcome">The result of validating the trust chain.</param>
    /// <param name="assertedMetadata">The party's asserted metadata, narrowed by assessors.</param>
    public static TrustEvidence<TrustChainValidationOutcome> ToEvidence(
        TrustChainValidationOutcome outcome,
        IReadOnlyDictionary<string, object>? assertedMetadata = null)
    {
        ArgumentNullException.ThrowIfNull(outcome);

        TrustChain? chain = outcome.Chain;
        string party = chain is not null ? chain.Subject.Issuer.Value : "(unresolved)";
        IReadOnlyList<string> anchors = chain is not null ? [chain.TrustAnchor.Issuer.Value] : [];

        return new TrustEvidence<TrustChainValidationOutcome>
        {
            PartyIdentifier = party,
            Mechanism = TrustMechanism.OpenIdFederation,
            MechanismEvidence = outcome,
            AssertedMetadata = assertedMetadata,
            TrustAnchors = anchors
        };
    }


    /// <summary>
    /// Assessor: affirms when the chain resolved to a trusted anchor and every
    /// Federation validation claim passed; rejects on an unresolved chain or any
    /// failing validation claim.
    /// </summary>
    public static ValueTask<TrustAssessorVerdict> AssessChainValidityAsync(
        TrustAssessmentContext<TrustChainValidationOutcome> context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        TrustChainValidationOutcome outcome = context.Evidence.MechanismEvidence;

        if(!outcome.IsValid)
        {
            return Verdict(TrustAssessorVerdict.Reject(
                ChainAssessorId, outcome.FailureReason ?? "Trust chain did not resolve to a trusted anchor."));
        }

        ClaimIssueResult? result = outcome.ValidationResult;
        if(result is null)
        {
            return Verdict(TrustAssessorVerdict.Reject(
                ChainAssessorId, "Trust chain carried no validation result."));
        }

        foreach(Claim claim in result.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Failure)
            {
                return Verdict(TrustAssessorVerdict.Reject(
                    ChainAssessorId, $"Federation validation check failed: {claim.Id}."));
            }
        }

        return Verdict(TrustAssessorVerdict.Affirm(ChainAssessorId));
    }


    /// <summary>
    /// Assessor: bounds validity to the chain's earliest <c>exp</c> (the effective
    /// chain expiry per Federation §10.4) and emits an expiry re-evaluation trigger.
    /// </summary>
    public static ValueTask<TrustAssessorVerdict> AssessFreshnessAsync(
        TrustAssessmentContext<TrustChainValidationOutcome> context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        TrustChain? chain = context.Evidence.MechanismEvidence.Chain;
        if(chain is null || chain.Statements.Count == 0)
        {
            return Verdict(TrustAssessorVerdict.Affirm(FreshnessAssessorId));
        }

        DateTimeOffset minExp = chain.Statements[0].ExpiresAt;
        foreach(EntityStatement statement in chain.Statements)
        {
            if(statement.ExpiresAt < minExp)
            {
                minExp = statement.ExpiresAt;
            }
        }

        ReevaluationTrigger expiry = new()
        {
            Kind = TrustSignalKind.Expiry,
            Subject = context.Evidence.PartyIdentifier,
            Detail = minExp.ToString("O", CultureInfo.InvariantCulture)
        };

        return Verdict(new TrustAssessorVerdict
        {
            Outcome = TrustVerdictOutcome.Constrain,
            AssessorId = FreshnessAssessorId,
            ValidUntil = minExp,
            ReevaluationTriggers = [expiry]
        });
    }


    private static ValueTask<TrustAssessorVerdict> Verdict(TrustAssessorVerdict verdict) =>
        new(verdict);
}
