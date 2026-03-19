using System.Text.Json;

namespace Verifiable.Json;

/// <summary>
/// Extension methods for configuring <see cref="JsonSerializerOptions"/> with
/// OAuth server-side response type serialization.
/// </summary>
public static class JsonSerializerOptionsOAuthExtensions
{
    /// <summary>
    /// Chains <see cref="VerifiableOAuthJsonContext"/> into the
    /// <see cref="JsonSerializerOptions.TypeInfoResolver"/> of <paramref name="options"/>
    /// so that <see cref="Verifiable.OAuth.ParServerResponse"/>,
    /// <see cref="Verifiable.OAuth.TokenServerResponse"/>,
    /// <see cref="Verifiable.OAuth.OidcDiscoveryDocument"/>,
    /// <see cref="Verifiable.OAuth.JwksDocument"/>, and
    /// <see cref="JCose.JsonWebKey"/> are resolved with
    /// <see cref="JsonKnownNamingPolicy.SnakeCaseLower"/> as required by their
    /// respective RFCs.
    /// </summary>
    /// <param name="options">
    /// The options instance to extend. Typically already configured by
    /// <c>ApplyVerifiableDefaults</c>.
    /// </param>
    /// <returns>The same <paramref name="options"/> instance for chaining.</returns>
    public static JsonSerializerOptions ApplyOAuthDefaults(this JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.TypeInfoResolverChain.Add(VerifiableOAuthJsonContext.Default);

        return options;
    }
}
