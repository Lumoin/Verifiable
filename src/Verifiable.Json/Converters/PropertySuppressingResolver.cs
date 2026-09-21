using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Verifiable.Json.Converters;

/// <summary>
/// A decorating <see cref="IJsonTypeInfoResolver"/> that suppresses a named property
/// from the serialization contract of a specified type and its subtypes.
/// </summary>
/// <remarks>
/// <para>
/// This resolver wraps an existing resolver and post-processes the
/// <see cref="JsonTypeInfo"/> it returns. For types assignable to the target type, it
/// transforms <c>propertyName</c> through the call's own
/// <see cref="JsonSerializerOptions.PropertyNamingPolicy"/> and sets
/// <see cref="JsonPropertyInfo.ShouldSerialize"/> to <see langword="false"/> for the
/// property whose resolved <see cref="JsonPropertyInfo.Name"/> equals that transformed
/// name, so STJ skips it during serialization. Matching the resolved name this way needs
/// no inspection of the underlying CLR member, so it works identically for
/// reflection-based and source-generated resolvers; it does not match a property whose
/// JSON name was set by an explicit <c>JsonPropertyNameAttribute</c> that diverges from
/// the naming policy's transform of its CLR name.
/// </para>
/// <para>
/// The resolver never creates contracts for unknown types — it returns
/// <see langword="null"/> if the inner resolver does. This makes it safe
/// to use with source-generated resolvers in AOT scenarios.
/// </para>
/// </remarks>
internal sealed class PropertySuppressingResolver: IJsonTypeInfoResolver
{
    private IJsonTypeInfoResolver InnerResolver { get; }
    private Type TargetType { get; }
    private string PropertyName { get; }


    /// <summary>
    /// Creates a resolver that suppresses the named property from serialization.
    /// </summary>
    /// <param name="innerResolver">The resolver to decorate.</param>
    /// <param name="targetType">
    /// The type (and its subtypes) from which the property should be suppressed.
    /// </param>
    /// <param name="propertyName">
    /// The CLR property name to suppress, matched against the resolved
    /// <see cref="JsonPropertyInfo.Name"/> after the active naming policy transforms it
    /// (see the type remarks).
    /// </param>
    public PropertySuppressingResolver(
        IJsonTypeInfoResolver innerResolver,
        Type targetType,
        string propertyName)
    {
        ArgumentNullException.ThrowIfNull(innerResolver);
        ArgumentNullException.ThrowIfNull(targetType);
        ArgumentException.ThrowIfNullOrEmpty(propertyName);
        InnerResolver = innerResolver;
        TargetType = targetType;
        PropertyName = propertyName;
    }


    /// <inheritdoc />
    public JsonTypeInfo? GetTypeInfo(Type type, JsonSerializerOptions options)
    {
        var typeInfo = InnerResolver.GetTypeInfo(type, options);
        if(typeInfo is null)
        {
            return null;
        }

        if(TargetType.IsAssignableFrom(type))
        {
            //Transform the configured CLR name through the same naming policy STJ applied
            //to each property's resolved Name, then match on that resolved name directly.
            string expectedName = options.PropertyNamingPolicy?.ConvertName(PropertyName) ?? PropertyName;

            foreach(var property in typeInfo.Properties)
            {
                if(property.Name == expectedName)
                {
                    property.ShouldSerialize = static (_, _) => false;
                    break;
                }
            }
        }

        return typeInfo;
    }
}
