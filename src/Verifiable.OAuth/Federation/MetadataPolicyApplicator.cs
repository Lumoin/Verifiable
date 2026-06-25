using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Applies a merged metadata policy to a subject's declared metadata,
/// producing the effective metadata the subject operates under per
/// OpenID Federation 1.0 §6.1.4.2.
/// </summary>
/// <remarks>
/// <para>
/// Application order per parameter:
/// </para>
/// <list type="number">
///   <item><description><c>value</c> — replaces the parameter outright.</description></item>
///   <item><description><c>add</c> — appends to the parameter (or initializes it).</description></item>
///   <item><description><c>default</c> — supplies the parameter when not present after the previous steps.</description></item>
///   <item><description><c>one_of</c> — checks the resulting value is one of the operator's values.</description></item>
///   <item><description><c>subset_of</c> — trims the resulting array to its intersection with the operator's value set (a modifier, never a rejection; §6.1.3.1.5, Table 1).</description></item>
///   <item><description><c>superset_of</c> — checks the resulting array contains every operator value.</description></item>
///   <item><description><c>essential</c> — final presence check (the parameter MUST be present when <see langword="true"/>).</description></item>
/// </list>
/// <para>
/// Constraint violations (declared value not in one_of's set, declared
/// array missing a superset_of value, essential=true with the parameter
/// missing, etc.) surface as
/// <see cref="MetadataPolicyApplyResult.Failed"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataPolicyApplicator")]
public static class MetadataPolicyApplicator
{
    /// <summary>
    /// Applies <paramref name="mergedPolicy"/> to
    /// <paramref name="declaredMetadata"/>. Returns the effective metadata
    /// when every parameter's operators apply cleanly, or a failure when
    /// any constraint check fails.
    /// </summary>
    public static MetadataPolicyApplyResult Apply(
        IReadOnlyDictionary<string, object> declaredMetadata,
        EntityTypeMetadataPolicy mergedPolicy)
    {
        ArgumentNullException.ThrowIfNull(declaredMetadata);
        ArgumentNullException.ThrowIfNull(mergedPolicy);

        Dictionary<string, object> effective = new(StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> kvp in declaredMetadata)
        {
            effective[kvp.Key] = kvp.Value;
        }

        foreach(KeyValuePair<string, ParameterPolicy> entry in mergedPolicy.ParameterPolicies)
        {
            string parameterName = entry.Key;
            ParameterPolicy policy = entry.Value;
            string locator = $"{mergedPolicy.EntityType.Value}/{parameterName}";

            //Step 1: value (replaces outright).
            if(policy.Operators.TryGetValue(WellKnownMetadataPolicyOperators.Value, out object? valueValue))
            {
                effective[parameterName] = valueValue;
            }

            //Step 2: add (appends, initializing if absent).
            if(policy.Operators.TryGetValue(WellKnownMetadataPolicyOperators.Add, out object? addValue))
            {
                if(addValue is not IEnumerable<object> addList)
                {
                    return MetadataPolicyApplyResult.Failed(
                        $"Operator 'add' for '{locator}' expects an array value.");
                }

                List<object> combined = [];
                if(effective.TryGetValue(parameterName, out object? existing))
                {
                    if(existing is IEnumerable<object> existingList)
                    {
                        combined.AddRange(existingList);
                    }
                    else
                    {
                        return MetadataPolicyApplyResult.Failed(
                            $"Operator 'add' for '{locator}' targets a parameter whose declared value is not an array.");
                    }
                }
                HashSet<object> seen = new(combined);
                foreach(object item in addList)
                {
                    if(seen.Add(item))
                    {
                        combined.Add(item);
                    }
                }
                effective[parameterName] = combined;
            }

            //Step 3: default (only when parameter absent after value/add).
            if(policy.Operators.TryGetValue(WellKnownMetadataPolicyOperators.Default, out object? defaultValue)
                && !effective.ContainsKey(parameterName))
            {
                effective[parameterName] = defaultValue;
            }

            //Step 4: one_of constraint.
            if(policy.Operators.TryGetValue(WellKnownMetadataPolicyOperators.OneOf, out object? oneOfValue))
            {
                if(oneOfValue is not IEnumerable<object> oneOfList)
                {
                    return MetadataPolicyApplyResult.Failed(
                        $"Operator 'one_of' for '{locator}' expects an array value.");
                }

                if(effective.TryGetValue(parameterName, out object? currentForOneOf))
                {
                    HashSet<object> oneOfSet = new(oneOfList);
                    if(!oneOfSet.Contains(currentForOneOf))
                    {
                        return MetadataPolicyApplyResult.Failed(
                            $"Effective value of '{locator}' violates 'one_of' constraint.");
                    }
                }
            }

            //Step 4: subset_of — a value modifier, not a rejection (§6.1.3.1.5, Table 1).
            //The effective array is replaced by its intersection with the operator's value
            //set; values outside the set are dropped and the result MAY be the empty array.
            if(policy.Operators.TryGetValue(WellKnownMetadataPolicyOperators.SubsetOf, out object? subsetOfValue))
            {
                if(subsetOfValue is not IEnumerable<object> subsetOfList)
                {
                    return MetadataPolicyApplyResult.Failed(
                        $"Operator 'subset_of' for '{locator}' expects an array value.");
                }

                if(effective.TryGetValue(parameterName, out object? currentForSubset))
                {
                    if(currentForSubset is not IEnumerable<object> currentList)
                    {
                        return MetadataPolicyApplyResult.Failed(
                            $"Operator 'subset_of' for '{locator}' targets a parameter whose effective value is not an array.");
                    }

                    HashSet<object> subsetOfSet = new(subsetOfList);
                    List<object> intersection = [];
                    foreach(object item in currentList)
                    {
                        if(subsetOfSet.Contains(item))
                        {
                            intersection.Add(item);
                        }
                    }
                    effective[parameterName] = intersection;
                }
            }

            //Step 4: superset_of constraint.
            if(policy.Operators.TryGetValue(WellKnownMetadataPolicyOperators.SupersetOf, out object? supersetOfValue))
            {
                if(supersetOfValue is not IEnumerable<object> supersetOfList)
                {
                    return MetadataPolicyApplyResult.Failed(
                        $"Operator 'superset_of' for '{locator}' expects an array value.");
                }

                if(effective.TryGetValue(parameterName, out object? currentForSuperset))
                {
                    if(currentForSuperset is not IEnumerable<object> currentList)
                    {
                        return MetadataPolicyApplyResult.Failed(
                            $"Operator 'superset_of' for '{locator}' targets a parameter whose effective value is not an array.");
                    }

                    HashSet<object> currentSet = new(currentList);
                    foreach(object item in supersetOfList)
                    {
                        if(!currentSet.Contains(item))
                        {
                            return MetadataPolicyApplyResult.Failed(
                                $"Effective array of '{locator}' is missing a value required by 'superset_of'.");
                        }
                    }
                }
            }

            //Step 5: essential presence check. The operator value's only mandatory-to-support
            //JSON type is boolean (§6.1.3.1.7); a non-boolean value is a policy error rather
            //than a silently-ignored requirement (§6.1.3 operator value-type rule).
            if(policy.Operators.TryGetValue(WellKnownMetadataPolicyOperators.Essential, out object? essentialValue))
            {
                if(essentialValue is not bool essentialBool)
                {
                    return MetadataPolicyApplyResult.Failed(
                        $"Operator 'essential' for '{locator}' expects a boolean value.");
                }

                if(essentialBool && !effective.ContainsKey(parameterName))
                {
                    return MetadataPolicyApplyResult.Failed(
                        $"Essential parameter '{locator}' is not present in effective metadata.");
                }
            }
        }

        return MetadataPolicyApplyResult.Applied(effective);
    }


    /// <summary>
    /// Applies a raw-dictionary policy block to declared metadata. Parses
    /// the block via
    /// <see cref="MetadataPolicyParser.ParseEntityTypeBlock"/> first; a
    /// structural rejection surfaces as
    /// <see cref="MetadataPolicyApplyResult.Failed"/>.
    /// </summary>
    public static MetadataPolicyApplyResult Apply(
        IReadOnlyDictionary<string, object> declaredMetadata,
        IReadOnlyDictionary<string, object> rawBlock,
        EntityTypeIdentifier entityType)
    {
        ArgumentNullException.ThrowIfNull(declaredMetadata);
        ArgumentNullException.ThrowIfNull(rawBlock);

        MetadataPolicyParseResult parseResult = MetadataPolicyParser.ParseEntityTypeBlock(entityType, rawBlock);
        if(!parseResult.IsSuccess)
        {
            return MetadataPolicyApplyResult.Failed(parseResult.FailureReason!);
        }

        EntityTypeMetadataPolicy block = parseResult.Snapshot!.EntityTypes[entityType];
        return Apply(declaredMetadata, block);
    }
}
