using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Combines two metadata-policy entries per OpenID Federation 1.0 §6.1.4.1.
/// The orchestrator walks the trust chain from Trust Anchor down to
/// subject, accumulating policies via repeated calls to
/// <see cref="Merge(MetadataPolicySnapshot, MetadataPolicySnapshot)"/>; the
/// resulting snapshot is then handed to
/// <see cref="ApplyMetadataPolicyDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// Per-operator merge rules:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="WellKnownMetadataPolicyOperators.Value"/>: must be equal across sides; otherwise conflict.</description></item>
///   <item><description><see cref="WellKnownMetadataPolicyOperators.Add"/>: union of the two arrays.</description></item>
///   <item><description><see cref="WellKnownMetadataPolicyOperators.Default"/>: must be equal across sides; otherwise conflict.</description></item>
///   <item><description><see cref="WellKnownMetadataPolicyOperators.OneOf"/>: intersection of the two value sets (empty result → conflict).</description></item>
///   <item><description><see cref="WellKnownMetadataPolicyOperators.SubsetOf"/>: intersection (an empty result is allowed, §6.1.3.1.5).</description></item>
///   <item><description><see cref="WellKnownMetadataPolicyOperators.SupersetOf"/>: union.</description></item>
///   <item><description><see cref="WellKnownMetadataPolicyOperators.Essential"/>: logical OR.</description></item>
/// </list>
/// <para>
/// Extension operators (not on
/// <see cref="WellKnownMetadataPolicyOperators"/>) are merged with a
/// permissive equality rule: if both sides declare the same operator with
/// equal values, the merged entry carries that value; if values differ,
/// the merge is rejected. Deployments wanting bespoke merge semantics for
/// extension operators register a custom merger / evaluator pipeline.
/// </para>
/// <para>
/// After the per-operator merge, the resulting operator combination is
/// re-checked against the §6.1.3.1.8 table via
/// <see cref="MetadataPolicyEvaluator.IsOperatorPairLegal"/>; a merge that
/// would produce an illegal combination is rejected even when each input
/// was internally legal.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataPolicyMerger")]
public static class MetadataPolicyMerger
{
    /// <summary>
    /// Merges two per-entity-type policy blocks. Both inputs must share the
    /// same <see cref="EntityTypeMetadataPolicy.EntityType"/>; mismatched
    /// entity types fail the merge.
    /// </summary>
    public static MetadataPolicyMergeResult Merge(
        EntityTypeMetadataPolicy upstream,
        EntityTypeMetadataPolicy downstream)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(downstream);

        if(!upstream.EntityType.Equals(downstream.EntityType))
        {
            return MetadataPolicyMergeResult.Failed(
                $"Cannot merge metadata policies for different entity types: '{upstream.EntityType.Value}' vs '{downstream.EntityType.Value}'.");
        }

        Dictionary<string, ParameterPolicy> mergedParameters = [];

        //Collect the union of parameter names.
        HashSet<string> allParameterNames = new(StringComparer.Ordinal);
        foreach(string name in upstream.ParameterPolicies.Keys)
        {
            allParameterNames.Add(name);
        }
        foreach(string name in downstream.ParameterPolicies.Keys)
        {
            allParameterNames.Add(name);
        }

        foreach(string parameterName in allParameterNames)
        {
            bool upHas = upstream.ParameterPolicies.TryGetValue(parameterName, out ParameterPolicy? upParam);
            bool downHas = downstream.ParameterPolicies.TryGetValue(parameterName, out ParameterPolicy? downParam);

            if(upHas && !downHas)
            {
                mergedParameters[parameterName] = upParam!;
                continue;
            }
            if(!upHas && downHas)
            {
                mergedParameters[parameterName] = downParam!;
                continue;
            }

            //Both sides have the parameter — merge operator-by-operator.
            (ParameterPolicy? mergedParam, string? reason) = MergeParameter(
                upstream.EntityType, parameterName, upParam!, downParam!);
            if(mergedParam is null)
            {
                return MetadataPolicyMergeResult.Failed(reason!);
            }
            mergedParameters[parameterName] = mergedParam;
        }

        EntityTypeMetadataPolicy merged = new()
        {
            EntityType = upstream.EntityType,
            ParameterPolicies = mergedParameters,
        };

        return MetadataPolicyMergeResult.MergedFromBlock(merged);
    }


    /// <summary>
    /// Merges two whole snapshots. Per-entity-type blocks present on only
    /// one side carry through unchanged; entity-types present on both are
    /// merged via <see cref="Merge(EntityTypeMetadataPolicy, EntityTypeMetadataPolicy)"/>.
    /// </summary>
    public static MetadataPolicyMergeResult Merge(
        MetadataPolicySnapshot upstream,
        MetadataPolicySnapshot downstream)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(downstream);

        Dictionary<EntityTypeIdentifier, EntityTypeMetadataPolicy> mergedEntityTypes = [];

        HashSet<EntityTypeIdentifier> allEntityTypes = [];
        foreach(EntityTypeIdentifier id in upstream.EntityTypes.Keys)
        {
            allEntityTypes.Add(id);
        }
        foreach(EntityTypeIdentifier id in downstream.EntityTypes.Keys)
        {
            allEntityTypes.Add(id);
        }

        foreach(EntityTypeIdentifier entityType in allEntityTypes)
        {
            bool upHas = upstream.EntityTypes.TryGetValue(entityType, out EntityTypeMetadataPolicy? upBlock);
            bool downHas = downstream.EntityTypes.TryGetValue(entityType, out EntityTypeMetadataPolicy? downBlock);

            if(upHas && !downHas)
            {
                mergedEntityTypes[entityType] = upBlock!;
                continue;
            }
            if(!upHas && downHas)
            {
                mergedEntityTypes[entityType] = downBlock!;
                continue;
            }

            MetadataPolicyMergeResult blockResult = Merge(upBlock!, downBlock!);
            if(!blockResult.IsSuccess)
            {
                return blockResult;
            }
            mergedEntityTypes[entityType] = blockResult.MergedBlock!;
        }

        return MetadataPolicyMergeResult.MergedFromSnapshot(new MetadataPolicySnapshot
        {
            EntityTypes = mergedEntityTypes,
        });
    }


    private static (ParameterPolicy? Merged, string? Reason) MergeParameter(
        EntityTypeIdentifier entityType,
        string parameterName,
        ParameterPolicy upstream,
        ParameterPolicy downstream)
    {
        Dictionary<MetadataPolicyOperator, object> mergedOperators = [];

        HashSet<MetadataPolicyOperator> allOperators = [];
        foreach(MetadataPolicyOperator op in upstream.Operators.Keys)
        {
            allOperators.Add(op);
        }
        foreach(MetadataPolicyOperator op in downstream.Operators.Keys)
        {
            allOperators.Add(op);
        }

        foreach(MetadataPolicyOperator op in allOperators)
        {
            bool upHas = upstream.Operators.TryGetValue(op, out object? upValue);
            bool downHas = downstream.Operators.TryGetValue(op, out object? downValue);

            if(upHas && !downHas)
            {
                mergedOperators[op] = upValue!;
                continue;
            }
            if(!upHas && downHas)
            {
                mergedOperators[op] = downValue!;
                continue;
            }

            //Both sides have the operator. Apply per-operator merge rule.
            (object? merged, string? reason) = MergeOperatorValues(
                entityType, parameterName, op, upValue!, downValue!);
            if(merged is null)
            {
                return (null, reason);
            }
            mergedOperators[op] = merged;
        }

        //After merging, validate the resulting operator combination is legal.
        MetadataPolicyOperator[] operatorArray = [.. mergedOperators.Keys];
        for(int i = 0; i < operatorArray.Length; i++)
        {
            for(int j = i + 1; j < operatorArray.Length; j++)
            {
                if(!MetadataPolicyEvaluator.IsOperatorPairLegal(operatorArray[i], operatorArray[j]))
                {
                    return (null,
                        $"Merged policy for '{entityType.Value}/{parameterName}' would combine incompatible operators '{operatorArray[i].Value}' and '{operatorArray[j].Value}' (§6.1.3.1.8).");
                }
            }
        }

        return (new ParameterPolicy
        {
            ParameterName = parameterName,
            Operators = mergedOperators,
        }, null);
    }


    private static (object? Merged, string? Reason) MergeOperatorValues(
        EntityTypeIdentifier entityType,
        string parameterName,
        MetadataPolicyOperator op,
        object upstream,
        object downstream)
    {
        string locator = $"{entityType.Value}/{parameterName}/{op.Value}";

        if(op.Equals(WellKnownMetadataPolicyOperators.Value)
            || op.Equals(WellKnownMetadataPolicyOperators.Default))
        {
            return ValuesEqual(upstream, downstream)
                ? (upstream, null)
                : (null, $"Conflicting '{op.Value}' values for '{locator}' across statements.");
        }

        if(op.Equals(WellKnownMetadataPolicyOperators.Add)
            || op.Equals(WellKnownMetadataPolicyOperators.SupersetOf))
        {
            //Union of arrays.
            if(upstream is not IEnumerable<object> upList || downstream is not IEnumerable<object> downList)
            {
                return (null, $"Operator '{op.Value}' for '{locator}' expects array values on both sides.");
            }
            return (UnionPreservingOrder(upList, downList), null);
        }

        if(op.Equals(WellKnownMetadataPolicyOperators.OneOf))
        {
            //Intersection of arrays. An empty result is a policy error (§6.1.3.1.4).
            if(upstream is not IEnumerable<object> upList || downstream is not IEnumerable<object> downList)
            {
                return (null, $"Operator '{op.Value}' for '{locator}' expects array values on both sides.");
            }
            List<object> intersection = IntersectPreservingOrder(upList, downList);
            if(intersection.Count == 0)
            {
                return (null, $"Intersection of '{op.Value}' value sets for '{locator}' is empty.");
            }
            return (intersection, null);
        }

        if(op.Equals(WellKnownMetadataPolicyOperators.SubsetOf))
        {
            //Intersection of arrays. An empty result is allowed (§6.1.3.1.5 notes the
            //intersection "may thus be an empty array []").
            if(upstream is not IEnumerable<object> upList || downstream is not IEnumerable<object> downList)
            {
                return (null, $"Operator '{op.Value}' for '{locator}' expects array values on both sides.");
            }
            return (IntersectPreservingOrder(upList, downList), null);
        }

        if(op.Equals(WellKnownMetadataPolicyOperators.Essential))
        {
            //Logical OR. Once essential becomes true, it stays true downstream.
            bool upBool = upstream is bool ub && ub;
            bool downBool = downstream is bool db && db;
            return (upBool || downBool, null);
        }

        //Extension operator. Permissive: equal values merge to that value;
        //unequal values reject.
        return ValuesEqual(upstream, downstream)
            ? (upstream, null)
            : (null, $"Extension operator '{op.Value}' for '{locator}' has conflicting values across statements; deployment-defined merge required.");
    }


    private static bool ValuesEqual(object left, object right)
    {
        //Reference equality short-circuit.
        if(ReferenceEquals(left, right))
        {
            return true;
        }

        //Both lists: element-wise equality (order-insensitive set comparison).
        if(left is IEnumerable<object> leftList && right is IEnumerable<object> rightList)
        {
            HashSet<object> leftSet = new(leftList);
            HashSet<object> rightSet = new(rightList);
            return leftSet.SetEquals(rightSet);
        }

        return Equals(left, right);
    }


    private static List<object> UnionPreservingOrder(IEnumerable<object> upstream, IEnumerable<object> downstream)
    {
        List<object> result = [];
        HashSet<object> seen = [];
        foreach(object item in upstream)
        {
            if(seen.Add(item))
            {
                result.Add(item);
            }
        }
        foreach(object item in downstream)
        {
            if(seen.Add(item))
            {
                result.Add(item);
            }
        }
        return result;
    }


    private static List<object> IntersectPreservingOrder(IEnumerable<object> upstream, IEnumerable<object> downstream)
    {
        HashSet<object> downSet = new(downstream);
        List<object> result = [];
        foreach(object item in upstream)
        {
            if(downSet.Contains(item))
            {
                result.Add(item);
            }
        }
        return result;
    }
}
