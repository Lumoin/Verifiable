using System.Buffers;
using System.Diagnostics;
using Verifiable.OAuth.Trust;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// OpenID Federation 1.0 §12.1 automatic client registration: assesses a
/// Relying Party whose <c>client_id</c> is its Entity Identifier and whose
/// signed Authorization Request carries an inline <c>trust_chain</c>, and
/// derives the RP's effective metadata so the Authorization Server can admit
/// it for the request without a prior out-of-band registration.
/// </summary>
/// <remarks>
/// <para>
/// Server-side analogue of <see cref="Oid4Vp.FederationBoundJarKeyResolver"/>:
/// the same composition — validate the inline chain
/// (<see cref="ValidateTrustChainAsyncDelegate"/>), route the outcome through
/// the <see cref="PartyTrustEngine"/> with the
/// <see cref="FederationTrustAdapter.Assessors"/>, and confirm
/// <c>chain[0].sub</c> equals the asserted <c>client_id</c> — but the final
/// step derives the RP's effective metadata via
/// <see cref="FederationEffectiveMetadataResolver"/> instead of extracting a
/// JAR signing key. Where the OID4VP resolver answers "what key signs the
/// verifier's request object", this engine answers "what is this RP's
/// effective metadata, and may it be admitted".
/// </para>
/// <para>
/// Fail-closed and exception-free: every rejection path returns a
/// <see cref="FederationAutomaticRegistrationResult"/> carrying the reason,
/// so the authorize endpoint maps a refusal onto an OAuth error rather than
/// catching an exception. The HTTP fetch of the chain (walking the RP's
/// <c>authority_hints</c>) is out of scope here — the inline
/// <c>trust_chain</c> JOSE-header path is the §12.1 mechanism this engine
/// serves; a fetch-driven <see cref="ValidateTrustChainAsyncDelegate"/> can
/// be supplied without changing this composition.
/// </para>
/// </remarks>
[DebuggerDisplay("FederationAutomaticRegistration")]
public static class FederationAutomaticRegistration
{
    /// <summary>
    /// Validates the inline trust chain, assesses party trust, confirms the
    /// subject matches the asserted <c>client_id</c>, and resolves the RP's
    /// effective metadata for <paramref name="entityType"/>.
    /// </summary>
    /// <param name="trustChainValues">
    /// The compact JWS strings from the Authorization Request's
    /// <c>trust_chain</c> JOSE header, positionally aligned leaf → trust
    /// anchor (Federation §4.3).
    /// </param>
    /// <param name="expectedSubject">
    /// The RP's Entity Identifier — its <c>client_id</c> (with any
    /// <c>openid_federation:</c> prefix already stripped). Registration
    /// proceeds only if <c>chain[0].sub</c> equals this value.
    /// </param>
    /// <param name="entityType">
    /// The entity type whose metadata is resolved — typically
    /// <see cref="WellKnownEntityTypeIdentifiers.OpenIdRelyingParty"/> (or
    /// <see cref="WellKnownEntityTypeIdentifiers.OAuthClient"/> for a bare
    /// OAuth deployment). The subject MUST declare metadata for this type or
    /// registration is refused.
    /// </param>
    /// <param name="trustAnchors">
    /// The Authorization Server's trust anchor allow-list. The chain's
    /// terminal statement's issuer must appear here.
    /// </param>
    /// <param name="validationTime">The instant temporal checks evaluate against.</param>
    /// <param name="clockSkew">Maximum acceptable clock skew for temporal checks.</param>
    /// <param name="validateChain">
    /// Delegate that parses, signature-verifies, and rule-validates the inline
    /// chain. See <see cref="ValidateTrustChainAsyncDelegate"/>.
    /// </param>
    /// <param name="metadataPolicyEvaluator">
    /// Delegate evaluating §6.1.3.1.8 operator-combination legality. Wire to
    /// <see cref="FederationDefaultHooks.EvaluateMetadataPolicy"/> for the
    /// library default.
    /// </param>
    /// <param name="metadataPolicyApplicator">
    /// Delegate applying the merged policy to the subject's declared metadata
    /// (§6.1.4.2). Wire to
    /// <see cref="FederationDefaultHooks.ApplyMetadataPolicy"/> for the
    /// library default.
    /// </param>
    /// <param name="pool">Memory pool the chain validation rents transient buffers from.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// A registered result carrying the effective metadata + validated chain,
    /// or a rejected result carrying the reason.
    /// </returns>
    public static async ValueTask<FederationAutomaticRegistrationResult> ResolveAsync(
        IReadOnlyList<string> trustChainValues,
        EntityIdentifier expectedSubject,
        EntityTypeIdentifier entityType,
        IReadOnlyCollection<EntityIdentifier> trustAnchors,
        DateTimeOffset validationTime,
        TimeSpan clockSkew,
        ValidateTrustChainAsyncDelegate validateChain,
        EvaluateMetadataPolicyDelegate metadataPolicyEvaluator,
        ApplyMetadataPolicyDelegate metadataPolicyApplicator,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(trustChainValues);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(metadataPolicyEvaluator);
        ArgumentNullException.ThrowIfNull(metadataPolicyApplicator);
        ArgumentNullException.ThrowIfNull(pool);

        TrustChainValidationOutcome outcome = await validateChain(
            trustChainValues, trustAnchors, validationTime, clockSkew, pool, cancellationToken)
            .ConfigureAwait(false);

        //Route the trust decision through the party-trust engine. The Federation
        //assessors (chain validity + freshness) decide whether the RP is trusted;
        //this centralises the decision and adds defence-in-depth — a failing
        //validation claim is rejected even if the outcome flag reported the chain
        //valid. Mirrors FederationBoundJarKeyResolver on the OID4VP side.
        TrustEvidence<TrustChainValidationOutcome> evidence = FederationTrustAdapter.ToEvidence(outcome);
        TrustDecisionRecord<TrustChainValidationOutcome> trust = await PartyTrustEngine.AssessAsync(
            evidence,
            TrustSignalSnapshot.Empty(validationTime),
            FederationTrustAdapter.Assessors,
            validationTime,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!trust.Assessment.IsTrusted || outcome.Chain is null)
        {
            return FederationAutomaticRegistrationResult.Rejected(
                expectedSubject,
                trust.Assessment.RejectionReason ?? outcome.FailureReason ?? "Trust chain rejected.",
                trust.Assessment);
        }

        if(outcome.Chain.Statements.Count == 0
            || !outcome.Chain.Statements[0].Subject.Equals(expectedSubject))
        {
            return FederationAutomaticRegistrationResult.Rejected(
                expectedSubject,
                $"chain[0].sub does not match the client_id '{expectedSubject.Value}'.",
                trust.Assessment);
        }

        MetadataPolicyApplyResult? metadata = await FederationEffectiveMetadataResolver.ResolveAsync(
            outcome.Chain, entityType, metadataPolicyEvaluator, metadataPolicyApplicator, cancellationToken)
            .ConfigureAwait(false);

        if(metadata is null)
        {
            return FederationAutomaticRegistrationResult.Rejected(
                expectedSubject,
                $"The subject did not declare '{entityType.Value}' metadata; automatic registration requires it.",
                trust.Assessment);
        }

        if(!metadata.IsSuccess || metadata.EffectiveMetadata is null)
        {
            return FederationAutomaticRegistrationResult.Rejected(
                expectedSubject,
                metadata.FailureReason ?? "Metadata policy application failed.",
                trust.Assessment);
        }

        return FederationAutomaticRegistrationResult.Registered(
            expectedSubject,
            metadata.EffectiveMetadata,
            outcome.Chain,
            trust.Assessment.ValidUntil,
            trust.Assessment);
    }
}
