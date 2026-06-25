using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Evaluates operator-combination legality per OpenID Federation 1.0
/// §6.1.3.1.8. Given an <see cref="EntityTypeMetadataPolicy"/>, walks
/// every <see cref="ParameterPolicy"/> and confirms that any pair of
/// declared operators is compatible per the spec's combination table.
/// </summary>
/// <remarks>
/// <para>
/// The compatibility table is encoded as the
/// <see cref="IsOperatorPairLegal"/> private function. Extension operators
/// (any <see cref="MetadataPolicyOperator"/> not on
/// <see cref="WellKnownMetadataPolicyOperators"/>) bypass the table —
/// they are considered combinable with anything since the library has no
/// semantic knowledge of them. Deployments enforcing constraints on
/// extension operators register their own evaluator delegate.
/// </para>
/// <para>
/// Evaluation is fail-fast: the first illegal pair encountered (in
/// dictionary-iteration order) is reported via
/// <see cref="MetadataPolicyEvaluationContext"/> on the returned
/// <see cref="Claim"/>. The caller's
/// <see cref="EvaluateMetadataPolicyDelegate"/> implementation determines
/// whether failures of distinct parameters in the same policy block need
/// to be enumerated separately — the library default reports only the
/// first.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataPolicyEvaluator")]
public static class MetadataPolicyEvaluator
{
    /// <summary>
    /// Evaluates a per-entity-type policy block in its raw payload-side
    /// shape (parameter-name to operator-dict mapping). Parses the block
    /// via <see cref="MetadataPolicyParser.ParseEntityTypeBlock"/> first;
    /// returns a structural-rejection failure claim if parsing fails.
    /// </summary>
    public static Claim EvaluateOperatorCombinations(
        IReadOnlyDictionary<string, object> rawBlock,
        EntityTypeIdentifier entityType)
    {
        ArgumentNullException.ThrowIfNull(rawBlock);

        MetadataPolicyParseResult parseResult = MetadataPolicyParser.ParseEntityTypeBlock(entityType, rawBlock);
        if(!parseResult.IsSuccess)
        {
            //Structural rejection — emit Failure with no context subclass; the
            //failure surfaces as the same claim id as an illegal combination so
            //downstream observers learn from the claim outcome alone.
            return new Claim(
                WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal,
                ClaimOutcome.Failure);
        }

        EntityTypeMetadataPolicy block = parseResult.Snapshot!.EntityTypes[entityType];
        return EvaluateOperatorCombinations(block);
    }


    /// <summary>
    /// Evaluates a per-entity-type policy block and returns a single
    /// <see cref="Claim"/> with
    /// <see cref="WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal"/>.
    /// </summary>
    public static Claim EvaluateOperatorCombinations(EntityTypeMetadataPolicy block)
    {
        ArgumentNullException.ThrowIfNull(block);

        foreach(KeyValuePair<string, ParameterPolicy> parameterEntry in block.ParameterPolicies)
        {
            ParameterPolicy policy = parameterEntry.Value;
            MetadataPolicyOperator[] operators = [.. policy.Operators.Keys];

            //Structural legality — the §6.1.3.1.8 combination table.
            for(int i = 0; i < operators.Length; i++)
            {
                for(int j = i + 1; j < operators.Length; j++)
                {
                    if(!IsOperatorPairLegal(operators[i], operators[j]))
                    {
                        return CombinationFailure(
                            block.EntityType, parameterEntry.Key, operators[i], operators[j]);
                    }
                }
            }

            //Conditional value relationships — the "in which case ... MUST be a subset
            //of ..." clauses in each operator's §6.1.3.1.x combination list. A pair that
            //is structurally legal still fails when its configured values violate the
            //declared relationship.
            (MetadataPolicyOperator First, MetadataPolicyOperator Second)? violation =
                FindConditionalRelationshipViolation(policy);
            if(violation is not null)
            {
                return CombinationFailure(
                    block.EntityType, parameterEntry.Key, violation.Value.First, violation.Value.Second);
            }
        }

        return new Claim(
            WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal,
            ClaimOutcome.Success);
    }


    /// <summary>
    /// Builds the §6.1.3.1.8 combination-failure claim for a single offending
    /// operator pair on one parameter.
    /// </summary>
    private static Claim CombinationFailure(
        EntityTypeIdentifier entityType,
        string parameterName,
        MetadataPolicyOperator first,
        MetadataPolicyOperator second) =>
        new(
            WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal,
            ClaimOutcome.Failure,
            new MetadataPolicyEvaluationContext
            {
                EntityType = entityType,
                ParameterName = parameterName,
                FirstOperator = first,
                SecondOperator = second,
            },
            Claim.NoSubClaims);


    /// <summary>
    /// Whether two operators may both appear in a single
    /// <see cref="ParameterPolicy"/> per §6.1.3.1.8. Symmetric in its
    /// arguments. Non-well-known operators are always combinable —
    /// extension semantics are deployment-defined.
    /// </summary>
    public static bool IsOperatorPairLegal(MetadataPolicyOperator left, MetadataPolicyOperator right)
    {
        //Same operator listed twice is structurally impossible (dict keys are unique);
        //if it ever reached here we'd consider it legal.
        if(left.Equals(right))
        {
            return true;
        }

        //Extension operators carry no library-known combination constraints (§6.1.3.2);
        //the library treats them as combinable with anything. Bespoke restrictions are
        //a deployment-supplied evaluator's concern.
        if(IsExtensionOperator(left) || IsExtensionOperator(right))
        {
            return true;
        }

        //Among the seven standard operators the only disallowed pairings are one_of with
        //add, subset_of, or superset_of. one_of's §6.1.3.1.4 combination list names only
        //value, default and essential; every other standard operator (value, add, default,
        //subset_of, superset_of) lists each of its non-one_of peers as combinable (some
        //conditionally — see FindConditionalRelationshipViolation). So a standard pair is
        //legal unless exactly one side is one_of and the other is not value/default/essential.
        bool leftIsOneOf = left.Equals(WellKnownMetadataPolicyOperators.OneOf);
        bool rightIsOneOf = right.Equals(WellKnownMetadataPolicyOperators.OneOf);
        if(leftIsOneOf || rightIsOneOf)
        {
            MetadataPolicyOperator other = leftIsOneOf ? right : left;
            return other.Equals(WellKnownMetadataPolicyOperators.Value)
                || other.Equals(WellKnownMetadataPolicyOperators.Default)
                || other.Equals(WellKnownMetadataPolicyOperators.Essential);
        }

        return true;
    }


    /// <summary>
    /// Checks the conditional value relationships the §6.1.3.1.x combination
    /// lists attach to otherwise-legal operator pairs (e.g. "MAY be combined
    /// with add, in which case the values of add MUST be a subset of the
    /// values of value"). Returns the first violated pair, or <see langword="null"/>
    /// when every co-declared pair satisfies its relationship. Pairs whose
    /// combination carries no value condition (e.g. add+superset_of) are not
    /// checked here.
    /// </summary>
    private static (MetadataPolicyOperator First, MetadataPolicyOperator Second)? FindConditionalRelationshipViolation(
        ParameterPolicy policy)
    {
        IReadOnlyDictionary<MetadataPolicyOperator, object> ops = policy.Operators;

        bool hasValue = ops.TryGetValue(WellKnownMetadataPolicyOperators.Value, out object? valueVal);
        bool hasAdd = ops.TryGetValue(WellKnownMetadataPolicyOperators.Add, out object? addVal);
        bool hasDefault = ops.ContainsKey(WellKnownMetadataPolicyOperators.Default);
        bool hasOneOf = ops.TryGetValue(WellKnownMetadataPolicyOperators.OneOf, out object? oneOfVal);
        bool hasSubsetOf = ops.TryGetValue(WellKnownMetadataPolicyOperators.SubsetOf, out object? subsetOfVal);
        bool hasSupersetOf = ops.TryGetValue(WellKnownMetadataPolicyOperators.SupersetOf, out object? supersetOfVal);
        bool hasEssential = ops.TryGetValue(WellKnownMetadataPolicyOperators.Essential, out object? essentialVal);

        //§6.1.3.1.1 / §6.1.3.1.3: value combines with default only when value is not null.
        if(hasValue && hasDefault && valueVal is null)
        {
            return (WellKnownMetadataPolicyOperators.Value, WellKnownMetadataPolicyOperators.Default);
        }

        //§6.1.3.1.1: value combines with essential except when value is null and essential is true.
        if(hasValue && hasEssential && valueVal is null && essentialVal is bool essentialTrue && essentialTrue)
        {
            return (WellKnownMetadataPolicyOperators.Value, WellKnownMetadataPolicyOperators.Essential);
        }

        //§6.1.3.1.1 / §6.1.3.1.2: the values of add MUST be a subset of the values of value.
        if(hasValue && hasAdd && !IsSubset(ValueSet(addVal), ValueSet(valueVal)))
        {
            return (WellKnownMetadataPolicyOperators.Value, WellKnownMetadataPolicyOperators.Add);
        }

        //§6.1.3.1.1 / §6.1.3.1.4: the value of value MUST be among the one_of values.
        if(hasValue && hasOneOf && !IsSubset(ValueSet(valueVal), ValueSet(oneOfVal)))
        {
            return (WellKnownMetadataPolicyOperators.Value, WellKnownMetadataPolicyOperators.OneOf);
        }

        //§6.1.3.1.1 / §6.1.3.1.5: the values of value MUST be a subset of the values of subset_of.
        if(hasValue && hasSubsetOf && !IsSubset(ValueSet(valueVal), ValueSet(subsetOfVal)))
        {
            return (WellKnownMetadataPolicyOperators.Value, WellKnownMetadataPolicyOperators.SubsetOf);
        }

        //§6.1.3.1.1 / §6.1.3.1.6: the values of value MUST be a superset of the values of superset_of.
        if(hasValue && hasSupersetOf && !IsSubset(ValueSet(supersetOfVal), ValueSet(valueVal)))
        {
            return (WellKnownMetadataPolicyOperators.Value, WellKnownMetadataPolicyOperators.SupersetOf);
        }

        //§6.1.3.1.2 / §6.1.3.1.5: the values of add MUST be a subset of the values of subset_of.
        if(hasAdd && hasSubsetOf && !IsSubset(ValueSet(addVal), ValueSet(subsetOfVal)))
        {
            return (WellKnownMetadataPolicyOperators.Add, WellKnownMetadataPolicyOperators.SubsetOf);
        }

        //§6.1.3.1.5 / §6.1.3.1.6: the values of subset_of MUST be a superset of the values of superset_of.
        if(hasSubsetOf && hasSupersetOf && !IsSubset(ValueSet(supersetOfVal), ValueSet(subsetOfVal)))
        {
            return (WellKnownMetadataPolicyOperators.SubsetOf, WellKnownMetadataPolicyOperators.SupersetOf);
        }

        return null;
    }


    /// <summary>
    /// Normalises an operator value to a set for the §6.1.3.1.x subset/superset
    /// relationship checks. An array value becomes the set of its elements; a
    /// scalar becomes a one-element set; a null value becomes the empty set.
    /// </summary>
    private static HashSet<object> ValueSet(object? value)
    {
        if(value is null)
        {
            return [];
        }
        if(value is IEnumerable<object> list)
        {
            return [.. list];
        }
        return [value];
    }


    private static bool IsSubset(HashSet<object> candidate, HashSet<object> universe) =>
        candidate.IsSubsetOf(universe);


    private static bool IsExtensionOperator(MetadataPolicyOperator op) =>
        !op.Equals(WellKnownMetadataPolicyOperators.Value)
        && !op.Equals(WellKnownMetadataPolicyOperators.Add)
        && !op.Equals(WellKnownMetadataPolicyOperators.Default)
        && !op.Equals(WellKnownMetadataPolicyOperators.OneOf)
        && !op.Equals(WellKnownMetadataPolicyOperators.SubsetOf)
        && !op.Equals(WellKnownMetadataPolicyOperators.SupersetOf)
        && !op.Equals(WellKnownMetadataPolicyOperators.Essential);
}
