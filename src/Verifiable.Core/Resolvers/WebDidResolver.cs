using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Did.Methods;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Resolves <c>did:web</c> identifiers per the
/// <see href="https://w3c-ccg.github.io/did-method-web/">DID Web method specification</see>.
/// </summary>
/// <remarks>
/// <para>
/// The resolution algorithm transforms a <c>did:web</c> identifier into an HTTPS URL by
/// splitting on colons (DID path separators) before percent-decoding, which preserves
/// <c>%3A</c> as a literal colon for port numbers. Examples:
/// </para>
/// <list type="bullet">
///   <item><description><c>did:web:example.com</c> → <c>https://example.com/.well-known/did.json</c></description></item>
///   <item><description><c>did:web:example.com:users:alice</c> → <c>https://example.com/users/alice/did.json</c></description></item>
///   <item><description><c>did:web:example.com%3A3000:user:alice</c> → <c>https://example.com:3000/user/alice/did.json</c></description></item>
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
///     (WellKnownDidMethodPrefixes.WebDidMethodPrefix, WebDidResolver.ResolveAsync)
/// );
/// </code>
/// </remarks>
public static class WebDidResolver
{
    private static readonly char[] PathSeparator = [':'];

    /// <summary>
    /// Computes the HTTPS document URL for a <c>did:web</c> identifier.
    /// </summary>
    /// <param name="didWebIdentifier">A valid <c>did:web</c> identifier string.</param>
    /// <returns>The HTTPS URL where the DID document can be fetched.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="didWebIdentifier"/> is <see langword="null"/>, empty,
    /// whitespace, or does not start with the <c>did:web:</c> prefix.
    /// </exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "DID identifiers are strings that may contain embedded fragments per W3C DID Core. The existing DidDocument and DID method types use string URIs consistently.")]
    public static string Resolve(string didWebIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didWebIdentifier);

        string prefixWithColon = $"{WellKnownDidMethodPrefixes.WebDidMethodPrefix}:";
        if(!didWebIdentifier.StartsWith(prefixWithColon, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The given DID identifier '{didWebIdentifier}' is not a valid did:web identifier.",
                nameof(didWebIdentifier));
        }

        //Split on colons before percent-decoding. Colons in the DID method-specific ID
        //are path separators, while %3A represents a literal colon (for port numbers).
        string[] parts = didWebIdentifier[prefixWithColon.Length..].Split(PathSeparator);
        string domainAndPath = Uri.UnescapeDataString(string.Join('/', parts));
        string httpsUrl = $"https://{domainAndPath}";

        if(!domainAndPath.Contains('/', StringComparison.Ordinal))
        {
            httpsUrl += "/.well-known";
        }

        httpsUrl += "/did.json";

        return httpsUrl;
    }

    /// <summary>
    /// Resolves a <c>did:web</c> identifier and returns a <see cref="DidResolutionResult"/>
    /// with <see cref="DidResolutionKind.DocumentUrl"/> carrying the computed HTTPS URL.
    /// Matches <see cref="DidMethodResolverDelegate"/> for direct registration as a method group.
    /// </summary>
    /// <param name="did">A valid <c>did:web</c> identifier string.</param>
    /// <param name="options">Resolution options (not used by this method).</param>
    /// <param name="cancellationToken">Cancellation token (not used by this method).</param>
    /// <returns>
    /// A <see cref="DidResolutionResult"/> with <see cref="DidResolutionKind.DocumentUrl"/>
    /// containing the computed HTTPS URL. The caller is responsible for fetching the document.
    /// </returns>
    public static ValueTask<DidResolutionResult> ResolveAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(DidResolutionResult.SuccessUrl(Resolve(did)));
    }
}