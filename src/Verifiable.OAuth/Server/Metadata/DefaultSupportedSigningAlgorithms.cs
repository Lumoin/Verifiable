using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;

namespace Verifiable.OAuth.Server.Metadata;

/// <summary>
/// Supplies the default signing-algorithm declarations for discovery composition.
/// </summary>
/// <remarks>
/// Server signing usages resolve the registration's current public keys and
/// convert their tags to JWA names. DPoP and client assertions describe accepted
/// client signatures, so their defaults retain the existing validation declarations.
/// This helper does not decide which metadata members or endpoints are published.
/// </remarks>
public static class DefaultSupportedSigningAlgorithms
{
    /// <summary>
    /// Resolves the default algorithms for a usage without invoking the host's
    /// <see cref="AuthorizationServerCryptography.ResolveSupportedSigningAlgorithmsAsync"/> delegate.
    /// </summary>
    /// <param name="integration">The OAuth integration admitted for the request.</param>
    /// <param name="registration">The registration whose current keys are read.</param>
    /// <param name="usage">The usage named on every public-key resolution.</param>
    /// <param name="context">The request context passed unchanged to the key resolver.</param>
    /// <param name="cancellationToken">Cancellation token passed to the key resolver.</param>
    /// <returns>
    /// The existing DPoP or client-assertion declaration, or the ordinally distinct
    /// JWA names of the resolved current keys in key order. Missing key sets,
    /// an absent resolver and unresolved keys contribute no algorithms.
    /// </returns>
    public static async ValueTask<IReadOnlyList<string>> ResolveAsync(
        AuthorizationServerIntegration integration,
        ClientRecord registration,
        KeyUsageContext usage,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integration);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        if(usage == KeyUsageContext.DpopProof)
        {
            return WellKnownDpopValues.SupportedSigningAlgorithms;
        }

        if(usage == KeyUsageContext.ClientAssertion)
        {
            return [.. integration.ClientAssertionSigningAlgorithmsSupported];
        }

        if(!registration.SigningKeys.TryGetValue(usage, out SigningKeySet? signingKeySet))
        {
            return [];
        }

        ServerVerificationKeyResolverDelegate? resolver = integration.Cryptography.VerificationKeyResolver;
        if(resolver is null)
        {
            return [];
        }

        HashSet<string> algorithms = new(StringComparer.Ordinal);
        foreach(KeyId keyId in signingKeySet.Current)
        {
            PublicKeyMemory? key = await resolver(
                keyId, usage, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
            if(key is null) { continue; }

            string jwa = CryptoFormatConversions.DefaultTagToJwaConverter(key.Tag);
            _ = algorithms.Add(jwa);
        }

        return algorithms.Count == 0 ? [] : algorithms.ToArray();
    }
}
