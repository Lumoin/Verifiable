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
/// <see cref="JsonTypeInfo"/> it returns. For types assignable to the target type,
/// it sets <see cref="JsonPropertyInfo.ShouldSerialize"/> to <see langword="false"/>
/// for the named property so that STJ skips it during serialization.
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
    /// The CLR property name to suppress. Matched by
    /// <see cref="JsonPropertyInfo.Name"/> before naming policy transformation,
    /// using the <see cref="MemberInfo.Name"/> from the property's
    /// <see cref="JsonPropertyInfo.AttributeProvider"/>.
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
            foreach(var property in typeInfo.Properties)
            {
                //Match by the CLR property name. The AttributeProvider is the
                //PropertyInfo when using DefaultJsonTypeInfoResolver. For
                //source-generated resolvers, fall back to matching by the
                //property's Get method name convention.
                bool isMatch = property.AttributeProvider is System.Reflection.PropertyInfo pi
                    && pi.Name == PropertyName;

                if(isMatch)
                {
                    property.ShouldSerialize = static (_, _) => false;
                    break;
                }
            }
        }

        return typeInfo;
    }
}