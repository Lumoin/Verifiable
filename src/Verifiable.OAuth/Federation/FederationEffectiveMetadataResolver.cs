using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Computes the OpenID Federation 1.0 §6.1.4 effective metadata for a single
/// entity type by walking the chain's <c>metadata_policy</c> claims (anchor →
/// leaf), merging via <see cref="MetadataPolicyMerger"/>, and applying the
/// merged policy against the subject's declared metadata via
/// <see cref="ApplyMetadataPolicyDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// Single-entity-type complement to <see cref="MetadataPolicyOrchestrator"/>.
/// The orchestrator iterates every entity type declared on the subject and
/// emits one <see cref="Claim"/> per type; this resolver returns the
/// effective metadata for one type as a typed
/// <see cref="MetadataPolicyApplyResult"/> the caller can consume directly.
/// Wallets that need the Verifier's metadata block from the chain
/// (encryption key, signing alg constraints, etc.) call this instead of
/// the orchestrator and inspect <see cref="MetadataPolicyApplyResult.EffectiveMetadata"/>.
/// </para>
/// <para>
/// Returns <see langword="null"/> when the subject did not declare metadata
/// for <paramref name="entityType"/> — that is not a policy failure; it is
/// a structural fact about the chain (the subject doesn't play that role).
/// Callers distinguish "subject didn't declare" (null) from "policy failed"
/// (non-null result with <see cref="MetadataPolicyApplyResult.IsSuccess"/>
/// false).
/// </para>
/// </remarks>
[DebuggerDisplay("FederationEffectiveMetadataResolver")]
public static class FederationEffectiveMetadataResolver
{
    /// <summary>
    /// Resolves the effective metadata for <paramref name="entityType"/> on
    /// the subject of <paramref name="chain"/>.
    /// </summary>
    /// <returns>
    /// A <see cref="MetadataPolicyApplyResult"/> when the subject declared
    /// metadata for the requested type; <see langword="null"/> when no such
    /// declaration is present in <c>chain[0]</c>'s metadata. Caller checks
    /// <see cref="MetadataPolicyApplyResult.IsSuccess"/> to distinguish
    /// effective-metadata-available from policy-application-failed.
    /// </returns>
    public static async ValueTask<MetadataPolicyApplyResult?> ResolveAsync(
        TrustChain chain,
        EntityTypeIdentifier entityType,
        EvaluateMetadataPolicyDelegate evaluator,
        ApplyMetadataPolicyDelegate applicator,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(evaluator);
        ArgumentNullException.ThrowIfNull(applicator);

        if(chain.Statements.Count == 0)
        {
            return null;
        }

        //Read the subject's declared metadata for this entity type.
        EntityStatement subject = chain.Statements[0];
        if(!subject.Payload.TryGetValue(WellKnownFederationClaimNames.Metadata, out object? metaObj)
            || metaObj is not IReadOnlyDictionary<string, object> metaDict
            || !metaDict.TryGetValue(entityType.Value, out object? entityMetaObj)
            || entityMetaObj is not IReadOnlyDictionary<string, object> declaredMetadata)
        {
            return null;
        }

        //§6.2.3: an Entity Type not permitted by the chain's accumulated
        //allowed_entity_types constraint MUST be removed from the subject's metadata
        //(federation_entity is always allowed), done before any metadata policy is
        //accumulated or applied. A removed type resolves to null — the same shape the
        //caller already treats as "the subject does not play that role."
        if(IsEntityTypeRemovedByConstraint(chain, entityType))
        {
            return null;
        }

        //Accumulate the chain's metadata_policy claims for this entity type
        //(anchor → leaf) via the shared walker.
        (EntityTypeMetadataPolicy? mergedBlock, string? mergeFailure) =
            MetadataPolicyOrchestrator.AccumulatePolicyForEntityType(chain, entityType);

        if(mergeFailure is not null)
        {
            return MetadataPolicyApplyResult.Failed(
                $"Metadata policy accumulation failed for entity type '{entityType.Value}': {mergeFailure}");
        }

        //Convert merged policy to raw-dict shape the delegates consume.
        Dictionary<string, object> rawMergedBlock = MetadataPolicyOrchestrator.ToRawBlock(mergedBlock!);

        //§6.1.3.1.8 operator combination legality.
        Claim evaluationClaim = await evaluator(rawMergedBlock, entityType, cancellationToken)
            .ConfigureAwait(false);
        if(evaluationClaim.Outcome != ClaimOutcome.Success)
        {
            return MetadataPolicyApplyResult.Failed(
                $"Operator combination is illegal for entity type '{entityType.Value}' (§6.1.3.1.8).");
        }

        //§6.1.4.2 apply.
        return await applicator(declaredMetadata, rawMergedBlock, entityType, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Whether <paramref name="entityType"/> is removed from the subject's effective
    /// metadata by the chain's accumulated §6.2.3 <c>allowed_entity_types</c> constraint.
    /// <c>federation_entity</c> is always allowed and never removed. When no statement
    /// declares the constraint nothing is removed; otherwise the type is removed unless
    /// every constraining statement permits it (intersection semantics — each statement
    /// constrains all entities subordinate to it, and the subject is subordinate to all).
    /// </summary>
    private static bool IsEntityTypeRemovedByConstraint(TrustChain chain, EntityTypeIdentifier entityType)
    {
        if(string.Equals(entityType.Value, WellKnownEntityTypeIdentifiers.FederationEntity.Value, StringComparison.Ordinal))
        {
            return false;
        }

        foreach(EntityStatement statement in chain.Statements)
        {
            if(TryReadAllowedEntityTypes(statement.Payload, out HashSet<string> allowed)
                && !allowed.Contains(entityType.Value))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Reads <c>constraints.allowed_entity_types</c> into a set. Returns
    /// <see langword="false"/> when the statement carries no <c>allowed_entity_types</c>
    /// member; an empty array yields an empty set (only <c>federation_entity</c> allowed,
    /// per §6.2.3).
    /// </summary>
    private static bool TryReadAllowedEntityTypes(UnverifiedJwtPayload payload, out HashSet<string> allowed)
    {
        allowed = new HashSet<string>(StringComparer.Ordinal);
        if(!payload.TryGetValue(WellKnownFederationClaimNames.Constraints, out object? constraintsObj)
            || constraintsObj is not IReadOnlyDictionary<string, object> constraints
            || !constraints.TryGetValue(WellKnownFederationClaimNames.AllowedEntityTypes, out object? typesObj)
            || typesObj is not IEnumerable<object> types)
        {
            return false;
        }

        foreach(object item in types)
        {
            if(item is string value && !string.IsNullOrWhiteSpace(value))
            {
                allowed.Add(value);
            }
        }

        return true;
    }
}
