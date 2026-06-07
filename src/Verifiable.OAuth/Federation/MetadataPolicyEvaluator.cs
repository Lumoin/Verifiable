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

            for(int i = 0; i < operators.Length; i++)
            {
                for(int j = i + 1; j < operators.Length; j++)
                {
                    if(!IsOperatorPairLegal(operators[i], operators[j]))
                    {
                        return new Claim(
                            WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal,
                            ClaimOutcome.Failure,
                            new MetadataPolicyEvaluationContext
                            {
                                EntityType = block.EntityType,
                                ParameterName = parameterEntry.Key,
                                FirstOperator = operators[i],
                                SecondOperator = operators[j],
                            },
                            Claim.NoSubClaims);
                    }
                }
            }
        }

        return new Claim(
            WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal,
            ClaimOutcome.Success);
    }


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

        //Essential composes with every well-known operator.
        if(left.Equals(WellKnownMetadataPolicyOperators.Essential)
            || right.Equals(WellKnownMetadataPolicyOperators.Essential))
        {
            return true;
        }

        //Value and Add are exclusive with every other operator except essential.
        if(left.Equals(WellKnownMetadataPolicyOperators.Value)
            || right.Equals(WellKnownMetadataPolicyOperators.Value)
            || left.Equals(WellKnownMetadataPolicyOperators.Add)
            || right.Equals(WellKnownMetadataPolicyOperators.Add))
        {
            return false;
        }

        //Default combines with one_of, subset_of, superset_of, essential.
        if(left.Equals(WellKnownMetadataPolicyOperators.Default)
            || right.Equals(WellKnownMetadataPolicyOperators.Default))
        {
            MetadataPolicyOperator other = left.Equals(WellKnownMetadataPolicyOperators.Default) ? right : left;
            return other.Equals(WellKnownMetadataPolicyOperators.OneOf)
                || other.Equals(WellKnownMetadataPolicyOperators.SubsetOf)
                || other.Equals(WellKnownMetadataPolicyOperators.SupersetOf)
                || IsExtensionOperator(other);
        }

        //subset_of and superset_of combine with each other (and with default+essential
        //handled above).
        if(left.Equals(WellKnownMetadataPolicyOperators.SubsetOf)
            && right.Equals(WellKnownMetadataPolicyOperators.SupersetOf))
        {
            return true;
        }
        if(left.Equals(WellKnownMetadataPolicyOperators.SupersetOf)
            && right.Equals(WellKnownMetadataPolicyOperators.SubsetOf))
        {
            return true;
        }

        //one_of with subset_of / superset_of / itself is illegal.
        if((left.Equals(WellKnownMetadataPolicyOperators.OneOf) && IsRestrictionOperator(right))
            || (right.Equals(WellKnownMetadataPolicyOperators.OneOf) && IsRestrictionOperator(left)))
        {
            return false;
        }

        //Two extension operators: combinable (the library has no semantic knowledge).
        if(IsExtensionOperator(left) && IsExtensionOperator(right))
        {
            return true;
        }

        //One well-known + one extension: combinable (extension semantics deployment-defined).
        if(IsExtensionOperator(left) || IsExtensionOperator(right))
        {
            return true;
        }

        //Fallthrough: any standard-operator pair not explicitly cleared above is rejected.
        //Should not reach here for the seven standard operators — exhaustive analysis
        //of the table is encoded by the branches above.
        return false;
    }


    private static bool IsExtensionOperator(MetadataPolicyOperator op) =>
        !op.Equals(WellKnownMetadataPolicyOperators.Value)
        && !op.Equals(WellKnownMetadataPolicyOperators.Add)
        && !op.Equals(WellKnownMetadataPolicyOperators.Default)
        && !op.Equals(WellKnownMetadataPolicyOperators.OneOf)
        && !op.Equals(WellKnownMetadataPolicyOperators.SubsetOf)
        && !op.Equals(WellKnownMetadataPolicyOperators.SupersetOf)
        && !op.Equals(WellKnownMetadataPolicyOperators.Essential);


    private static bool IsRestrictionOperator(MetadataPolicyOperator op) =>
        op.Equals(WellKnownMetadataPolicyOperators.SubsetOf)
        || op.Equals(WellKnownMetadataPolicyOperators.SupersetOf);
}
