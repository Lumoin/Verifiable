using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Parses the loose <c>metadata_policy</c> claim shape into a typed
/// <see cref="MetadataPolicySnapshot"/>. Structural-only — accepts the
/// shape OpenID Federation 1.0 §6.1.2 mandates and rejects anything else
/// with <see cref="MetadataPolicyParseResult.Invalid"/>; operator-
/// combination legality (§6.1.3.1.8) is a separate concern handled by the
/// chunk-2 evaluator.
/// </summary>
[DebuggerDisplay("MetadataPolicyParser")]
public static class MetadataPolicyParser
{
    /// <summary>
    /// Parses a <c>metadata_policy</c> claim into a typed snapshot.
    /// </summary>
    /// <param name="metadataPolicy">
    /// The raw claim value, expected to be an object keyed by entity-type
    /// identifier with nested per-parameter operator dictionaries.
    /// </param>
    /// <returns>
    /// A <see cref="MetadataPolicyParseResult"/> carrying the
    /// <see cref="MetadataPolicySnapshot"/> on success or a failure
    /// reason on structural rejection.
    /// </returns>
    public static MetadataPolicyParseResult Parse(IReadOnlyDictionary<string, object> metadataPolicy)
    {
        ArgumentNullException.ThrowIfNull(metadataPolicy);

        Dictionary<EntityTypeIdentifier, EntityTypeMetadataPolicy> entityTypes = [];

        foreach(KeyValuePair<string, object> entityTypeEntry in metadataPolicy)
        {
            if(string.IsNullOrWhiteSpace(entityTypeEntry.Key))
            {
                return MetadataPolicyParseResult.Invalid("metadata_policy contains an empty entity-type key.");
            }

            if(entityTypeEntry.Value is not IReadOnlyDictionary<string, object> entityTypeBlock)
            {
                return MetadataPolicyParseResult.Invalid(
                    $"metadata_policy entry for entity type '{entityTypeEntry.Key}' is not an object.");
            }

            Dictionary<string, ParameterPolicy> parameters = [];
            foreach(KeyValuePair<string, object> parameterEntry in entityTypeBlock)
            {
                if(string.IsNullOrWhiteSpace(parameterEntry.Key))
                {
                    return MetadataPolicyParseResult.Invalid(
                        $"metadata_policy for entity type '{entityTypeEntry.Key}' contains an empty parameter key.");
                }

                if(parameterEntry.Value is not IReadOnlyDictionary<string, object> operatorBlock)
                {
                    return MetadataPolicyParseResult.Invalid(
                        $"metadata_policy parameter '{entityTypeEntry.Key}/{parameterEntry.Key}' is not an object.");
                }

                Dictionary<MetadataPolicyOperator, object> operators = [];
                foreach(KeyValuePair<string, object> operatorEntry in operatorBlock)
                {
                    if(string.IsNullOrWhiteSpace(operatorEntry.Key))
                    {
                        return MetadataPolicyParseResult.Invalid(
                            $"metadata_policy parameter '{entityTypeEntry.Key}/{parameterEntry.Key}' contains an empty operator key.");
                    }

                    operators[new MetadataPolicyOperator(operatorEntry.Key)] = operatorEntry.Value;
                }

                parameters[parameterEntry.Key] = new ParameterPolicy
                {
                    ParameterName = parameterEntry.Key,
                    Operators = operators,
                };
            }

            EntityTypeIdentifier entityType = new(entityTypeEntry.Key);
            entityTypes[entityType] = new EntityTypeMetadataPolicy
            {
                EntityType = entityType,
                ParameterPolicies = parameters,
            };
        }

        return MetadataPolicyParseResult.Parsed(new MetadataPolicySnapshot
        {
            EntityTypes = entityTypes,
        });
    }


    /// <summary>
    /// Parses a single entity-type block (parameter-name to operator-dict
    /// mapping) into a typed <see cref="EntityTypeMetadataPolicy"/>. Used
    /// by callers that already know the target entity type — typically
    /// the chunk-6 federation hook delegates whose signatures pass the
    /// block and entity type separately.
    /// </summary>
    public static MetadataPolicyParseResult ParseEntityTypeBlock(
        EntityTypeIdentifier entityType,
        IReadOnlyDictionary<string, object> block)
    {
        ArgumentNullException.ThrowIfNull(block);

        Dictionary<string, ParameterPolicy> parameters = [];
        foreach(KeyValuePair<string, object> parameterEntry in block)
        {
            if(string.IsNullOrWhiteSpace(parameterEntry.Key))
            {
                return MetadataPolicyParseResult.Invalid(
                    $"metadata_policy for entity type '{entityType.Value}' contains an empty parameter key.");
            }

            if(parameterEntry.Value is not IReadOnlyDictionary<string, object> operatorBlock)
            {
                return MetadataPolicyParseResult.Invalid(
                    $"metadata_policy parameter '{entityType.Value}/{parameterEntry.Key}' is not an object.");
            }

            Dictionary<MetadataPolicyOperator, object> operators = [];
            foreach(KeyValuePair<string, object> operatorEntry in operatorBlock)
            {
                if(string.IsNullOrWhiteSpace(operatorEntry.Key))
                {
                    return MetadataPolicyParseResult.Invalid(
                        $"metadata_policy parameter '{entityType.Value}/{parameterEntry.Key}' contains an empty operator key.");
                }

                operators[new MetadataPolicyOperator(operatorEntry.Key)] = operatorEntry.Value;
            }

            parameters[parameterEntry.Key] = new ParameterPolicy
            {
                ParameterName = parameterEntry.Key,
                Operators = operators,
            };
        }

        EntityTypeMetadataPolicy typedBlock = new()
        {
            EntityType = entityType,
            ParameterPolicies = parameters,
        };

        return MetadataPolicyParseResult.Parsed(new MetadataPolicySnapshot
        {
            EntityTypes = new Dictionary<EntityTypeIdentifier, EntityTypeMetadataPolicy>
            {
                [entityType] = typedBlock,
            },
        });
    }
}
