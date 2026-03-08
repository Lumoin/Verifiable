using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Did.Methods;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Resolves <c>did:cheqd</c> identifiers to their DID document REST API URLs per the
/// <see href="https://docs.cheqd.io/identity/architecture/adr-list/adr-001-cheqd-did-method">cheqd DID method specification</see>.
/// </summary>
/// <remarks>
/// <para>
/// The cheqd DID method encodes the network name and a UUID in the method-specific identifier:
/// </para>
/// <list type="bullet">
///   <item><description><c>did:cheqd:mainnet:&lt;uuid&gt;</c> → <c>https://resolver.cheqd.net/1.0/identifiers/did:cheqd:mainnet:&lt;uuid&gt;</c></description></item>
///   <item><description><c>did:cheqd:testnet:&lt;uuid&gt;</c> → <c>https://resolver.cheqd.net/1.0/identifiers/did:cheqd:testnet:&lt;uuid&gt;</c></description></item>
/// </list>
/// <para>
/// This class computes the URL only. HTTP fetching, signature verification, and document
/// parsing are the caller's responsibility via delegates.
/// </para>
/// <para>
/// Register with <see cref="DidMethodSelectors.FromResolvers"/> using the method group directly:
/// </para>
/// <code>
/// DidMethodSelectors.FromResolvers(
///     (WellKnownDidMethodPrefixes.CheqdDidMethodPrefix, CheqdDidResolver.ResolveAsync)
/// );
/// </code>
/// </remarks>
public static class CheqdDidResolver
{
    private const string ResolverBaseUrl = "https://resolver.cheqd.net/1.0/identifiers/";

    /// <summary>
    /// Computes the REST API URL for a <c>did:cheqd</c> identifier.
    /// </summary>
    /// <param name="didCheqdIdentifier">A valid <c>did:cheqd</c> identifier string.</param>
    /// <returns>The HTTPS URL where the DID document can be fetched.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="didCheqdIdentifier"/> is <see langword="null"/>, empty,
    /// whitespace, or does not start with the <c>did:cheqd:</c> prefix.
    /// </exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "DID identifiers are strings that may contain embedded fragments per W3C DID Core. The existing DidDocument and DID method types use string URIs consistently.")]
    public static string Resolve(string didCheqdIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didCheqdIdentifier);

        string prefixWithColon = $"{WellKnownDidMethodPrefixes.CheqdDidMethodPrefix}:";
        if(!didCheqdIdentifier.StartsWith(prefixWithColon, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The given DID identifier '{didCheqdIdentifier}' is not a valid did:cheqd identifier.",
                nameof(didCheqdIdentifier));
        }

        return $"{ResolverBaseUrl}{didCheqdIdentifier}";
    }

    /// <summary>
    /// Resolves a <c>did:cheqd</c> identifier and returns a <see cref="DidResolutionResult"/>
    /// with <see cref="DidResolutionKind.DocumentUrl"/> carrying the computed REST API URL.
    /// Matches <see cref="DidMethodResolverDelegate"/> for direct registration as a method group.
    /// </summary>
    /// <param name="did">A valid <c>did:cheqd</c> identifier string.</param>
    /// <param name="options">Resolution options (not used by this method).</param>
    /// <param name="cancellationToken">Cancellation token (not used by this method).</param>
    /// <returns>
    /// A <see cref="DidResolutionResult"/> with <see cref="DidResolutionKind.DocumentUrl"/>
    /// containing the computed REST API URL. The caller is responsible for fetching the document.
    /// </returns>
    public static ValueTask<DidResolutionResult> ResolveAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(DidResolutionResult.SuccessUrl(Resolve(did)));
    }
}
