using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Json.Converters;

namespace Verifiable.Json;

/// <summary>
/// Extension methods for configuring <see cref="JsonSerializerOptions"/> with
/// OAuth server-side response type serialization.
/// </summary>
public static class JsonSerializerOptionsOAuthExtensions
{
    /// <summary>
    /// Rewrites every declared object property of <paramref name="typeInfo"/> to its RFC-mandated
    /// snake_case wire name. The OAuth and JCose models this registration resolves declare no
    /// <see cref="JsonPropertyNameAttribute"/> of their own: the JSON leaf owns their wire shape, not
    /// the model types, so every property this modifier sees is a candidate for the rewrite. The
    /// rewrite reads each property's already-resolved <see cref="JsonPropertyInfo.Name"/> rather than
    /// any CLR member name, and that name converts to the exact RFC wire name only when the resolving
    /// <see cref="JsonSerializerOptions.PropertyNamingPolicy"/> is one of the three policies that change
    /// only case and word separators, never the underlying word boundaries: no policy at all (the raw
    /// PascalCase CLR member name), <see cref="JsonNamingPolicy.CamelCase"/>, or
    /// <see cref="JsonNamingPolicy.SnakeCaseLower"/> itself, whose own conversion is idempotent. Any
    /// other policy is refused with <see cref="InvalidOperationException"/> rather than silently
    /// shipping a wrong wire name.
    /// </summary>
    /// <param name="typeInfo">The type metadata to rewrite in place.</param>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="typeInfo"/>'s resolving <see cref="JsonSerializerOptions.PropertyNamingPolicy"/>
    /// is neither <see langword="null"/>, <see cref="JsonNamingPolicy.CamelCase"/>, nor
    /// <see cref="JsonNamingPolicy.SnakeCaseLower"/>.
    /// </exception>
    private static void EnforceSnakeCaseWireNames(JsonTypeInfo typeInfo)
    {
        if(typeInfo.Kind != JsonTypeInfoKind.Object)
        {
            return;
        }

        JsonNamingPolicy? namingPolicy = typeInfo.Options.PropertyNamingPolicy;
        if(namingPolicy is not null && !ReferenceEquals(namingPolicy, JsonNamingPolicy.CamelCase) && !ReferenceEquals(namingPolicy, JsonNamingPolicy.SnakeCaseLower))
        {
            throw new InvalidOperationException(
                $"The OAuth registration for '{typeInfo.Type}' requires the options it is applied to carry no naming policy, camelCase, or snake_case lower, so its RFC-mandated wire names can be recovered exactly.");
        }

        foreach(JsonPropertyInfo property in typeInfo.Properties)
        {
            property.Name = JsonNamingPolicy.SnakeCaseLower.ConvertName(property.Name);
        }
    }


    /// <summary>
    /// Chains <see cref="VerifiableOAuthJsonContext"/>, with <see cref="EnforceSnakeCaseWireNames(JsonTypeInfo)"/>
    /// applied, into the <see cref="JsonSerializerOptions.TypeInfoResolverChain"/> of <paramref name="options"/>
    /// so that <see cref="Verifiable.OAuth.Server.ParServerResponse"/>,
    /// <see cref="Verifiable.OAuth.Server.TokenServerResponse"/>,
    /// <see cref="Verifiable.OAuth.OidcDiscoveryDocument"/>, and
    /// <see cref="Verifiable.JCose.JwksDocument"/> serialize their declared members under the snake_case
    /// wire names their respective RFCs assign, independent of the composition order with any other
    /// registration on <paramref name="options"/>. <see cref="JCose.JsonWebKey"/> needs no such rewrite: it
    /// is dictionary-shaped, so System.Text.Json serializes its entries by their literal, already-lowercase
    /// dictionary keys and never consults a naming policy for them. This method also registers
    /// <see cref="JsonWebKeyJsonConverter"/>, guarded against a duplicate add when
    /// <see cref="JsonSerializerOptionsVerifiableExtensions.ApplyVerifiableDefaults(JsonSerializerOptions, BaseMemoryPool, bool)"/>
    /// already added it, so a caller who applies this method alone still gets a <see cref="JCose.JsonWebKey"/>
    /// whose typed accessors survive deserialization.
    /// </summary>
    /// <param name="options">
    /// The options instance to extend. Typically already configured by
    /// <see cref="JsonSerializerOptionsVerifiableExtensions.ApplyVerifiableDefaults(JsonSerializerOptions, BaseMemoryPool, bool)"/>.
    /// </param>
    /// <returns>The same <paramref name="options"/> instance for chaining.</returns>
    public static JsonSerializerOptions ApplyOAuthDefaults(this JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.TypeInfoResolverChain.Add(VerifiableOAuthJsonContext.Default.WithAddedModifier(EnforceSnakeCaseWireNames));

        if(!options.Converters.Any(converter => converter is JsonWebKeyJsonConverter))
        {
            options.Converters.Add(new JsonWebKeyJsonConverter());
        }

        return options;
    }
}
