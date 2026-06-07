using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.Core.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Walks a <see cref="TrustChain"/> running OpenID Federation 1.0's
/// metadata-policy pipeline (§6.1.4) end-to-end: for each entity type the
/// subject declares metadata for, accumulates the chain's
/// <c>metadata_policy</c> claims via <see cref="MetadataPolicyMerger"/>,
/// then applies the merged result against the subject's declared
/// metadata via <see cref="MetadataPolicyApplicator"/>. The outcome
/// surfaces as a <see cref="ClaimIssueResult"/> alongside the
/// <see cref="TrustChainValidator"/> output, with claim ids
/// <see cref="WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal"/>
/// (1140) and <see cref="WellKnownFederationClaimIds.MetadataPolicyAppliedCleanly"/>
/// (1141) emitted once per entity type.
/// </summary>
/// <remarks>
/// <para>
/// Operates on the inline trust chain only — the same scope as
/// <see cref="TrustChainValidator"/>. HTTP-fetch chain construction
/// lives in the B.5 track.
/// </para>
/// <para>
/// The orchestrator reads the subject's declared metadata from
/// position 0 of the chain (the subject's Entity Configuration's
/// <c>metadata</c> claim) and iterates the entity types declared there.
/// Entity types named in upstream <c>metadata_policy</c> claims but
/// absent from the subject's metadata produce no claim output — there is
/// nothing for the policy to apply against, which matches §6.1.4's
/// scoping.
/// </para>
/// <para>
/// <c>metadata_policy_crit</c> enforcement (§6.1.3.2) is wired: the orchestrator
/// emits the <see cref="WellKnownFederationClaimIds.MetadataPolicyCritOperatorsUnderstood"/>
/// check exactly once per run, walking every statement's <c>metadata_policy_crit</c>
/// and failing — with a <see cref="MetadataPolicyCritFailureContext"/> listing the
/// offenders — when any listed critical operator falls outside the library-known set
/// (<see cref="WellKnownMetadataPolicyOperators"/> plus deployment-defined extensions).
/// A critical operator the receiver does not understand rejects the chain; a
/// non-critical unknown operator is not fatal, per §6.1.3.2.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataPolicyOrchestrator")]
public static class MetadataPolicyOrchestrator
{
    /// <summary>
    /// Runs the metadata-policy pipeline against <paramref name="chain"/>.
    /// </summary>
    public static async ValueTask<ClaimIssueResult> RunAsync(
        TrustChain chain,
        EvaluateMetadataPolicyDelegate evaluator,
        ApplyMetadataPolicyDelegate applicator,
        TimeProvider timeProvider,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(evaluator);
        ArgumentNullException.ThrowIfNull(applicator);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentException.ThrowIfNullOrEmpty(correlationId);

        List<Claim> claims = [];
        ClaimIssueCompletionStatus completionStatus = ClaimIssueCompletionStatus.Complete;
        int rulesExecuted = 0;

        //§6.1.3.2 critical-operator awareness check — always emitted exactly once
        //per orchestrator run regardless of whether any statement carries
        //metadata_policy_crit. Vacuously Success when no crit claims appear.
        claims.Add(EvaluateMetadataPolicyCrit(chain));
        rulesExecuted++;

        Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>> declaredByType =
            ReadSubjectDeclaredMetadata(chain);

        //One §6.1.3.2 crit-check pseudo-rule + one pseudo-rule per declared
        //entity type. Per-entity-type rule emits 1140 then 1141; the crit-check
        //rule emits 1143.
        int totalRules = declaredByType.Count + 1;

        foreach(KeyValuePair<EntityTypeIdentifier, IReadOnlyDictionary<string, object>> entry in declaredByType)
        {
            if(cancellationToken.IsCancellationRequested)
            {
                completionStatus = ClaimIssueCompletionStatus.Cancelled;
                break;
            }

            EntityTypeIdentifier entityType = entry.Key;
            IReadOnlyDictionary<string, object> declaredMetadata = entry.Value;

            //Accumulate metadata_policy entries from positions 1..N-1, walking from
            //the Trust Anchor down toward the subject. The chunk-2 merger's
            //asymmetry is upstream/downstream; we pass the prior accumulator as
            //upstream and each newly-walked statement's policy as downstream.
            (EntityTypeMetadataPolicy? mergedBlock, string? mergeFailure) =
                AccumulatePolicyForEntityType(chain, entityType);

            if(mergeFailure is not null)
            {
                //Merge conflict — emit 1140 Failure with no MetadataPolicyEvaluationContext
                //(merge failures aren't operator-pair conflicts; they are deeper structural
                //conflicts surfaced via the merge result's FailureReason). The 1141 emission
                //is NotApplicable since apply can't run.
                claims.Add(new Claim(
                    WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal,
                    ClaimOutcome.Failure));
                claims.Add(new Claim(
                    WellKnownFederationClaimIds.MetadataPolicyAppliedCleanly,
                    ClaimOutcome.NotApplicable));
                rulesExecuted++;
                continue;
            }

            //Run the evaluator against the merged block as a raw dict (the delegate
            //signature takes the raw per-entity-type form).
            Dictionary<string, object> rawMergedBlock = ToRawBlock(mergedBlock!);
            Claim evaluationClaim = await evaluator(rawMergedBlock, entityType, cancellationToken)
                .ConfigureAwait(false);
            claims.Add(evaluationClaim);

            if(evaluationClaim.Outcome != ClaimOutcome.Success)
            {
                //Combination illegal — skip apply; emit 1141 NotApplicable.
                claims.Add(new Claim(
                    WellKnownFederationClaimIds.MetadataPolicyAppliedCleanly,
                    ClaimOutcome.NotApplicable));
                rulesExecuted++;
                continue;
            }

            //Run the applicator.
            MetadataPolicyApplyResult applyResult = await applicator(
                declaredMetadata, rawMergedBlock, entityType, cancellationToken).ConfigureAwait(false);
            claims.Add(new Claim(
                WellKnownFederationClaimIds.MetadataPolicyAppliedCleanly,
                applyResult.IsSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure));
            rulesExecuted++;
        }

        DateTime creationTimestamp = timeProvider.GetUtcNow().UtcDateTime;

        return new ClaimIssueResult(
            ClaimIssueResultId: Guid.CreateVersion7(timeProvider.GetUtcNow()).ToString("N"),
            ClaimIssuerId: WellKnownFederationAssessorIds.ApplyMetadataPolicy,
            CorrelationId: correlationId,
            Claims: claims,
            CreationTimestampInUtc: creationTimestamp,
            CompletionStatus: completionStatus,
            RulesExecuted: rulesExecuted,
            TotalRules: totalRules,
            IssuingContext: new ClaimIssueResultContext { Inputs = chain },
            ClaimIssuerTraceId: TracingUtilities.GetOrCreateTraceId(),
            ClaimIssuerSpanId: TracingUtilities.GetOrCreateSpanId(),
            Baggage: TracingUtilities.GetOrCreateBaggage());
    }


    private static Claim EvaluateMetadataPolicyCrit(TrustChain chain)
    {
        //Walk every statement; collect every operator named in any
        //metadata_policy_crit claim; check each against
        //WellKnownMetadataPolicyOperators. Order-preserving, duplicate-collapsing
        //walk so the failure context reports a stable, deduplicated list.
        HashSet<string> seen = new(StringComparer.Ordinal);
        List<MetadataPolicyOperator> unknown = [];

        foreach(EntityStatement statement in chain.Statements)
        {
            if(!statement.Payload.TryGetValue(WellKnownFederationClaimNames.MetadataPolicyCrit, out object? critObj)
                || critObj is not IEnumerable<object> critList)
            {
                continue;
            }

            foreach(object item in critList)
            {
                if(item is not string operatorName || string.IsNullOrWhiteSpace(operatorName))
                {
                    continue;
                }
                if(!seen.Add(operatorName))
                {
                    continue;
                }
                MetadataPolicyOperator op = new(operatorName);
                if(!IsLibraryKnownOperator(op))
                {
                    unknown.Add(op);
                }
            }
        }

        if(unknown.Count == 0)
        {
            return new Claim(
                WellKnownFederationClaimIds.MetadataPolicyCritOperatorsUnderstood,
                ClaimOutcome.Success);
        }

        return new Claim(
            WellKnownFederationClaimIds.MetadataPolicyCritOperatorsUnderstood,
            ClaimOutcome.Failure,
            new MetadataPolicyCritFailureContext { UnknownOperators = unknown },
            Claim.NoSubClaims);
    }


    private static bool IsLibraryKnownOperator(MetadataPolicyOperator op) =>
        op.Equals(WellKnownMetadataPolicyOperators.Value)
        || op.Equals(WellKnownMetadataPolicyOperators.Add)
        || op.Equals(WellKnownMetadataPolicyOperators.Default)
        || op.Equals(WellKnownMetadataPolicyOperators.OneOf)
        || op.Equals(WellKnownMetadataPolicyOperators.SubsetOf)
        || op.Equals(WellKnownMetadataPolicyOperators.SupersetOf)
        || op.Equals(WellKnownMetadataPolicyOperators.Essential);


    private static Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>> ReadSubjectDeclaredMetadata(TrustChain chain)
    {
        Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>> result = [];
        if(chain.Statements.Count == 0)
        {
            return result;
        }

        if(!chain.Statements[0].Payload.TryGetValue(WellKnownFederationClaimNames.Metadata, out object? metaObj)
            || metaObj is not IReadOnlyDictionary<string, object> metaDict)
        {
            return result;
        }

        foreach(KeyValuePair<string, object> kvp in metaDict)
        {
            if(string.IsNullOrWhiteSpace(kvp.Key)
                || kvp.Value is not IReadOnlyDictionary<string, object> typeMetadata)
            {
                continue;
            }
            result[new EntityTypeIdentifier(kvp.Key)] = typeMetadata;
        }

        return result;
    }


    //Shared with FederationEffectiveMetadataResolver — both walk the same
    //chain-accumulation path. Internal rather than private so the resolver
    //can call it directly without duplicating the §6.1.4.1 merge logic.
    internal static (EntityTypeMetadataPolicy? Merged, string? FailureReason) AccumulatePolicyForEntityType(
        TrustChain chain, EntityTypeIdentifier entityType)
    {
        //Start with an empty per-entity-type block so the iteration can call Merge
        //unconditionally.
        EntityTypeMetadataPolicy accumulator = new()
        {
            EntityType = entityType,
            ParameterPolicies = new Dictionary<string, ParameterPolicy>(),
        };

        //Walk from anchor (position N-1) down to position 1 (just above the leaf).
        //§6.1.4.1 layers policies from the top down; merge inputs are
        //(upstream=accumulator, downstream=new statement's block).
        for(int i = chain.Statements.Count - 1; i >= 1; i--)
        {
            EntityStatement statement = chain.Statements[i];

            if(!statement.Payload.TryGetValue(WellKnownFederationClaimNames.MetadataPolicy, out object? policyObj)
                || policyObj is not IReadOnlyDictionary<string, object> policyDict)
            {
                continue;
            }

            if(!policyDict.TryGetValue(entityType.Value, out object? blockObj)
                || blockObj is not IReadOnlyDictionary<string, object> rawBlock)
            {
                continue;
            }

            MetadataPolicyParseResult parseResult = MetadataPolicyParser.ParseEntityTypeBlock(entityType, rawBlock);
            if(!parseResult.IsSuccess)
            {
                return (null, parseResult.FailureReason);
            }

            EntityTypeMetadataPolicy downstream = parseResult.Snapshot!.EntityTypes[entityType];
            MetadataPolicyMergeResult mergeResult = MetadataPolicyMerger.Merge(accumulator, downstream);
            if(!mergeResult.IsSuccess)
            {
                return (null, mergeResult.FailureReason);
            }

            accumulator = mergeResult.MergedBlock!;
        }

        return (accumulator, null);
    }


    //Shared with FederationEffectiveMetadataResolver — converts typed
    //EntityTypeMetadataPolicy back to the raw dict shape the
    //EvaluateMetadataPolicyDelegate / ApplyMetadataPolicyDelegate signatures
    //consume.
    internal static Dictionary<string, object> ToRawBlock(EntityTypeMetadataPolicy block)
    {
        Dictionary<string, object> rawParameters = new(StringComparer.Ordinal);
        foreach(KeyValuePair<string, ParameterPolicy> entry in block.ParameterPolicies)
        {
            Dictionary<string, object> rawOperators = new(StringComparer.Ordinal);
            foreach(KeyValuePair<MetadataPolicyOperator, object> opEntry in entry.Value.Operators)
            {
                rawOperators[opEntry.Key.Value] = opEntry.Value;
            }
            rawParameters[entry.Key] = rawOperators;
        }
        return rawParameters;
    }
}
