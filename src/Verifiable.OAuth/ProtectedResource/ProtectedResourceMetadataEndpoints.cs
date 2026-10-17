using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// Serves the OAuth 2.0 Protected Resource Metadata documents (RFC 9728 Section 3) of the protected resources
/// co-located with the server: a capability-gated <c>GET</c> returning the Section 2 parameter set as
/// <c>application/json</c> with <c>200 OK</c> (Section 3.2), one document for the resource the registration's issuer
/// identifies and one for each of the library's own resources the request's endpoint chain holds.
/// </summary>
/// <remarks>
/// <para>
/// The issuer's document is served at the URL the host's endpoint resolver answers for
/// <see cref="WellKnownEndpointNames.ProtectedResourceMetadata"/>, its <c>resource</c> the resolved issuer in its URI
/// form (<see cref="CredentialEndpointDpopValidation.UriTextOf"/>): the same
/// identifier the Section 3 well-known URL is formed from, keeping the Section 3.3 validation invariant true by
/// construction. Its
/// members are the application's through the
/// <see cref="AuthorizationServerIntegration.ContributeProtectedResourceMetadataAsync"/> seam, asked with
/// <see cref="WellKnownEndpointNames.ProtectedResourceMetadata"/>; <c>jwks_uri</c> is read off the per-request endpoint
/// chain and written only when it is https (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728
/// Section 2</see>: "This URL MUST use the https scheme."); where the server validates DPoP proofs,
/// <c>dpop_signing_alg_values_supported</c> is the list it holds every proof to, the identifiers a proof can be accepted
/// under (<see cref="Dpop.DpopProofValidator.AcceptableProofAlgorithms"/>), by the one rule the resources' challenges
/// name their <c>algs</c> by (<see cref="CredentialEndpointDpopValidation.ResolveChallengeAlgorithmsAsync"/>: a list
/// holding a name that is no token is no list, and the member is then absent); and a contribution naming <c>none</c> among
/// <c>resource_signing_alg_values_supported</c> ("The value none MUST NOT be used.") is the server's wiring at fault,
/// answered <c>server_error</c> with no document.
/// </para>
/// <para>
/// Each of the library's own resources, UserInfo and the OID4VCI Credential, Deferred Credential and Notification
/// endpoints (<see cref="LibraryResourceEndpointNames"/>), has a document of its own whose <c>resource</c> is the
/// resource's identifier, the URL the host's endpoint resolver answers for the endpoint written in its URI form
/// (<see cref="CredentialEndpointDpopValidation.UriTextOf"/>: an internationalized host in its IDNA ASCII form, as
/// <see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section 3.1</see> maps an IRI), the one
/// text the documents, the well-known location and the challenges write for a URL: a client that sends its
/// request to that URL compares the document's <c>resource</c> with it (Section 3.3: "the resource value returned MUST
/// be identical to the URL that the client used to make the request to the resource server"). The document is served
/// at that identifier with <c>/.well-known/oauth-protected-resource</c> inserted between the host and the path
/// (<see cref="WellKnownPaths.OAuthProtectedResource"/>; Section 3: "between the host component and the path and/or
/// query components, if any"), so a tenant prefix of the path follows the suffix (Section 3.1: "Using path components
/// enables supporting multiple resources per host."). An endpoint whose URL is no resource identifier, not https or
/// carrying a fragment (Section 1.2: "a URL that uses the https scheme and has no fragment component"), has no
/// document. The document is served only at its location exactly: the request-target as the client sent it
/// (<see cref="IncomingRequest.RequestTarget"/>) equal, code point for code point, to the location's path and query
/// (Section 6: "a Unicode code-point-to-code-point equality comparison"), so another query, a missing query or another
/// spelling is not that document, and two identifiers differing in their query alone have two documents. A location
/// two documents share, two library resources' locations identical in path and query or a library resource's location
/// that is the issuer's document's, names no one resource its document could state: the server's own wiring at fault,
/// each such location is answered 500 <c>server_error</c> with
/// <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/> and no challenge of the resources involved names it
/// (<see cref="IsDocumentLocationShared"/>). A challenge names a resource's document only when the URL the client used
/// is the resource's identifier, the request-target included. The library
/// composes the document from what it knows: <c>authorization_servers</c> the issuer, <c>scopes_supported</c> the scope
/// the resource requires (<see cref="RequiredScopeOf"/>), <c>bearer_methods_supported</c> <c>["header"]</c> (the
/// resources read the <c>Authorization</c> field only, RFC 6750 Section 2.1), <c>[]</c> where the server's resources
/// require DPoP-bound access tokens
/// (<see cref="AuthorizationServerIntegration.IsDpopBoundAccessTokenRequiredAtResources"/>), which the document then
/// states as <c>dpop_bound_access_tokens_required: true</c>, <c>dpop_signing_alg_values_supported</c> the algorithms the
/// resource's challenges name as <c>algs</c>, and <c>jwks_uri</c> as the issuer's document reads it. The contribution
/// asked with the endpoint's name supplies the human-readable and documentation members alone; one naming another
/// member is answered <c>server_error</c> with no document. An issuer that does not resolve leaves either document
/// without its <c>resource</c> or <c>authorization_servers</c>, the server's own wiring at fault, answered 500
/// <c>server_error</c> with <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/>.
/// </para>
/// <para>
/// <c>signed_metadata</c> (Section 2.2) is produced by handing each document's assembled claim set to the application's
/// <see cref="AuthorizationServerIntegration.SignProtectedResourceMetadataAsync"/> signer, which owns the key, the
/// algorithm, and the spec-required <c>iss</c> claim. The same values go into both the plain document and the signed
/// JWT, so they cannot diverge.
/// </para>
/// <para>
/// Activation requires the
/// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>
/// capability. The §5 <c>WWW-Authenticate</c> <c>resource_metadata</c>
/// challenge parameter is each resource server's own 401 surface:
/// <see cref="ProtectedResourceChallenge"/> builds and parses it, the
/// co-located SSF transmitter endpoints attach it to their 401s when this
/// capability is active, and the library's own resources name their documents through
/// <see cref="TryLocateLibraryResourceDocument"/>.
/// </para>
/// </remarks>
public static class ProtectedResourceMetadataEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata))
        {
            candidates.Add(BuildProtectedResourceMetadata());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// The endpoint names of the library's own protected resources, each with a protected resource metadata document of
    /// its own: UserInfo and the OID4VCI Credential, Deferred Credential and Notification endpoints.
    /// </summary>
    internal static IReadOnlyList<string> LibraryResourceEndpointNames { get; } =
    [
        WellKnownEndpointNames.UserInfo,
        WellKnownEndpointNames.Oid4VciCredential,
        WellKnownEndpointNames.Oid4VciDeferredCredential,
        WellKnownEndpointNames.Oid4VciNotification
    ];


    /// <summary>
    /// The scope the library's resource <paramref name="endpointName"/> requires, the one place it is named for the
    /// resource's document (<c>scopes_supported</c>) and its challenges (<c>scope</c>): <see cref="WellKnownScopes.OpenId"/>
    /// for UserInfo (OpenID Connect Core 1.0 Section 5.3.1), <see langword="null"/> for a resource that requires no single
    /// scope.
    /// </summary>
    /// <param name="endpointName">The resource's endpoint name.</param>
    /// <returns>The scope, or <see langword="null"/>.</returns>
    internal static string? RequiredScopeOf(string endpointName) => endpointName switch
    {
        string name when string.Equals(name, WellKnownEndpointNames.UserInfo, StringComparison.Ordinal) => WellKnownScopes.OpenId,
        _ => null
    };


    /// <summary>
    /// Resolves the resource identifier of the library's resource <paramref name="endpointName"/>: the URL the host's
    /// endpoint resolver answered for the endpoint the request's <paramref name="chain"/> holds, written in its URI form
    /// (<see cref="CredentialEndpointDpopValidation.UriTextOf"/>), when it is a resource identifier
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-1.2">RFC 9728 Section 1.2</see>: "a URL that uses the
    /// https scheme and has no fragment component") with such a form. The text is a URL a client dials and an
    /// authorization server writes into an <c>aud</c> as given
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section 3.1</see>: "when an IRI is used
    /// for resource retrieval, the resource that the IRI locates is the same as the one located by the URI obtained after
    /// converting the IRI"), so an internationalized host is written in its IDNA ASCII form.
    /// </summary>
    /// <param name="chain">The request's endpoint chain, or <see langword="null"/> when the context carries none.</param>
    /// <param name="endpointName">The resource's endpoint name.</param>
    /// <param name="resourceIdentifier">The identifier's text, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the chain holds the endpoint at a resource identifier.</returns>
    internal static bool TryResolveLibraryResourceIdentifier(
        EndpointChain? chain, string endpointName, [NotNullWhen(true)] out string? resourceIdentifier)
    {
        resourceIdentifier = null;
        if(chain is null)
        {
            return false;
        }

        foreach(ServerEndpoint endpoint in chain)
        {
            if(string.Equals(endpoint.Name, endpointName, StringComparison.Ordinal))
            {
                resourceIdentifier = IsResourceIdentifier(endpoint.ResolvedUri)
                    ? CredentialEndpointDpopValidation.UriTextOrNullOf(endpoint.ResolvedUri)
                    : null;

                return resourceIdentifier is not null;
            }
        }

        return false;
    }


    /// <summary>
    /// Locates the protected resource metadata document of the library's resource <paramref name="endpointName"/> the
    /// request's challenges name: the document derived for the resource (<see cref="TryDeriveLibraryResourceDocument"/>)
    /// whose location serves no other document (<see cref="IsDocumentLocationShared"/>), so the pointer names only a
    /// document the library serves. The one derivation the matcher, the document and the challenges'
    /// <c>resource_metadata</c> read, so the URL advertised is the URL served.
    /// </summary>
    /// <param name="chain">The request's endpoint chain, or <see langword="null"/> when the context carries none.</param>
    /// <param name="endpointName">The resource's endpoint name.</param>
    /// <param name="resourceIdentifier">The identifier's text, or <see langword="null"/>.</param>
    /// <param name="documentUri">The document's URL, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the document is served for the request.</returns>
    internal static bool TryLocateLibraryResourceDocument(
        EndpointChain? chain,
        string endpointName,
        [NotNullWhen(true)] out string? resourceIdentifier,
        [NotNullWhen(true)] out Uri? documentUri)
    {
        if(!TryDeriveLibraryResourceDocument(chain, endpointName, out resourceIdentifier, out documentUri)
            || IsDocumentLocationShared(chain!, endpointName, documentUri))
        {
            resourceIdentifier = null;
            documentUri = null;

            return false;
        }

        return true;
    }


    /// <summary>
    /// Derives the location of the protected resource metadata document of the library's resource
    /// <paramref name="endpointName"/>: the request's <paramref name="chain"/> serves documents (it holds
    /// <see cref="WellKnownEndpointNames.ProtectedResourceMetadata"/>) and holds the endpoint at a resource identifier
    /// (<see cref="TryResolveLibraryResourceIdentifier"/>), and the location is that identifier with the well-known
    /// suffix inserted (<see cref="WellKnownPaths.OAuthProtectedResource"/>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">RFC 9728 Section 3</see>).
    /// </summary>
    /// <param name="chain">The request's endpoint chain, or <see langword="null"/> when the context carries none.</param>
    /// <param name="endpointName">The resource's endpoint name.</param>
    /// <param name="resourceIdentifier">The identifier's text, or <see langword="null"/>.</param>
    /// <param name="documentUri">The document's location, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when a location is derived.</returns>
    private static bool TryDeriveLibraryResourceDocument(
        EndpointChain? chain,
        string endpointName,
        [NotNullWhen(true)] out string? resourceIdentifier,
        [NotNullWhen(true)] out Uri? documentUri)
    {
        documentUri = null;
        if(!IsDocumentServed(chain) || !TryResolveLibraryResourceIdentifier(chain, endpointName, out resourceIdentifier))
        {
            resourceIdentifier = null;

            return false;
        }

        documentUri = WellKnownPaths.OAuthProtectedResource.ComputeUri(resourceIdentifier);

        return true;
    }


    /// <summary>
    /// Whether the location <paramref name="documentUri"/> of the document of the library's resource
    /// <paramref name="endpointName"/> serves another document too: the document of another of the library's resources
    /// the chain holds whose location is the same path and query (<see cref="IsAtLocation"/>), or the issuer's own
    /// document, matched by its path alone, where the location carries no query and its path is that document's. Such a
    /// location names no one resource its document could state
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "The resource value
    /// returned MUST be identical to the protected resource's resource identifier value into which the well-known URI
    /// path suffix was inserted to create the URL used to retrieve the metadata."), the server's own wiring at fault.
    /// Two identifiers differing in their query alone have two locations, each serving its own document.
    /// </summary>
    /// <param name="chain">The request's endpoint chain.</param>
    /// <param name="endpointName">The resource's endpoint name.</param>
    /// <param name="documentUri">The resource's document location.</param>
    /// <returns><see langword="true"/> when the location serves another document.</returns>
    private static bool IsDocumentLocationShared(EndpointChain chain, string endpointName, Uri documentUri)
    {
        foreach(ServerEndpoint endpoint in chain)
        {
            if(string.Equals(endpoint.Name, WellKnownEndpointNames.ProtectedResourceMetadata, StringComparison.Ordinal)
                && documentUri.Query.Length == 0
                && PathEquals.Equals(documentUri.AbsolutePath, endpoint.ResolvedUri.AbsolutePath))
            {
                return true;
            }
        }

        foreach(string otherEndpointName in LibraryResourceEndpointNames)
        {
            if(!string.Equals(otherEndpointName, endpointName, StringComparison.Ordinal)
                && TryDeriveLibraryResourceDocument(chain, otherEndpointName, out _, out Uri? otherDocument)
                && IsAtLocation(documentUri.PathAndQuery, otherDocument))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Whether the request-target <paramref name="requestTarget"/> is the document location
    /// <paramref name="documentUri"/>: its path and query (<see cref="Uri.PathAndQuery"/>) compared ordinally, code point
    /// for code point (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">RFC 9728 Section 6</see>:
    /// "Comparisons between the two strings MUST be performed as a Unicode code-point-to-code-point equality
    /// comparison."), so a document is served only at the location formed from its resource's identifier
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "The resource value
    /// returned MUST be identical to the protected resource's resource identifier value into which the well-known URI
    /// path suffix was inserted to create the URL used to retrieve the metadata."): another query, a missing query, or
    /// another spelling is not that location.
    /// </summary>
    /// <param name="requestTarget">The request-target, origin-form, or another location's path and query.</param>
    /// <param name="documentUri">The document location.</param>
    /// <returns><see langword="true"/> when the texts are equal.</returns>
    private static bool IsAtLocation(string requestTarget, Uri documentUri) =>
        string.Equals(requestTarget, documentUri.PathAndQuery, StringComparison.Ordinal);


    /// <summary>
    /// Whether the request's <paramref name="chain"/> serves protected resource metadata documents: it holds the
    /// endpoint named <see cref="WellKnownEndpointNames.ProtectedResourceMetadata"/>, which the registration's
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/> capability puts there.
    /// </summary>
    /// <param name="chain">The request's endpoint chain, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the chain holds the document endpoint.</returns>
    private static bool IsDocumentServed(EndpointChain? chain)
    {
        if(chain is null)
        {
            return false;
        }

        foreach(ServerEndpoint endpoint in chain)
        {
            if(string.Equals(endpoint.Name, WellKnownEndpointNames.ProtectedResourceMetadata, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Whether <paramref name="uri"/> is a resource identifier:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-1.2">RFC 9728 Section 1.2</see>, "a URL that uses the
    /// https scheme and has no fragment component."
    /// </summary>
    /// <param name="uri">The URL the host's endpoint resolver answered.</param>
    /// <returns><see langword="true"/> when the URL is absolute, https and without a fragment.</returns>
    private static bool IsResourceIdentifier(Uri uri) =>
        uri.IsAbsoluteUri
        && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
        && uri.Fragment.Length == 0;


    /// <summary>
    /// The first of the library's resources whose document location derived for the request's <paramref name="chain"/>
    /// (<see cref="TryDeriveLibraryResourceDocument"/>) is the request-target <paramref name="requestTarget"/>, its path
    /// and query exactly (<see cref="IsAtLocation"/>), or <see langword="null"/> when the request-target is no such
    /// location; a location another document's location shares is answered by
    /// <see cref="BuildProtectedResourceMetadata"/> as the server's wiring fault (<see cref="IsDocumentLocationShared"/>).
    /// </summary>
    /// <param name="chain">The request's endpoint chain, or <see langword="null"/>.</param>
    /// <param name="requestTarget">The request-target as the client sent it, <see cref="IncomingRequest.RequestTarget"/>.</param>
    /// <returns>The resource's endpoint name, or <see langword="null"/>.</returns>
    private static string? FindLibraryResourceAtDocumentLocation(EndpointChain? chain, string requestTarget)
    {
        foreach(string endpointName in LibraryResourceEndpointNames)
        {
            if(TryDeriveLibraryResourceDocument(chain, endpointName, out _, out Uri? documentUri)
                && IsAtLocation(requestTarget, documentUri))
            {
                return endpointName;
            }
        }

        return null;
    }


    /// <summary>
    /// Builds the <c>GET</c> metadata endpoint per RFC 9728 Sections 3.1 and 3.2: it matches the issuer's document at its
    /// own resolved path, the path matched alone, and the document of each of the library's resources the chain holds
    /// only at that resource's location, the request-target as the client sent it
    /// (<see cref="IncomingRequest.RequestTarget"/>) equal to the location's path and query
    /// (<see cref="IsAtLocation"/>): another query, a missing query or another spelling is not that document, and the
    /// chain walks on. A location two documents share is answered 500 <c>server_error</c> with
    /// <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/> and no document
    /// (<see cref="IsDocumentLocationShared"/>). Stateless: it resolves, assembles and serialises, short-circuiting the
    /// dispatcher with the document.
    /// </summary>
    private static EndpointCandidate BuildProtectedResourceMetadata() =>
        new()
        {
            Name = WellKnownEndpointNames.ProtectedResourceMetadata,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath)
                    && FindLibraryResourceAtDocumentLocation(context.EndpointChain, req.RequestTarget) is null)
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.RequestServer!;

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                EndpointChain? chain = context.EndpointChain;
                if(chain is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "EndpointChain not on context for protected resource metadata "
                        + "emission. DispatchAsync sets this; this code path is only "
                        + "reachable through dispatch."));
                }

                //RFC 9728 Section 3.3: a document's resource is the one identifier its location was formed from, the
                //location matched by the request-target as the client sent it; a location two documents share names no
                //one resource, the server's own wiring at fault.
                string? libraryResource = FindLibraryResourceAtDocumentLocation(chain, context.IncomingRequest!.RequestTarget);
                if(libraryResource is not null
                    && TryDeriveLibraryResourceDocument(chain, libraryResource, out _, out Uri? libraryDocument)
                    && IsDocumentLocationShared(chain, libraryResource, libraryDocument))
                {
                    return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady));
                }

                //RFC 9728 Section 3.2: "An error response uses the applicable HTTP status code value." Each document
                //names the issuer, the issuer's as its resource and each library resource's as its authorization server,
                //in its URI form; an issuer that does not resolve, or has no URI form, is the server's own wiring at
                //fault, answered as a token validation answers it.
                Uri? issuer = await CredentialEndpointDpopValidation.TryResolveIssuerAsync(server, registration, context, ct).ConfigureAwait(false);
                string? issuerText = issuer is null ? null : CredentialEndpointDpopValidation.UriTextOrNullOf(issuer);
                if(issuerText is null)
                {
                    return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady));
                }

                ServerHttpResponse document = libraryResource is null
                    ? await BuildIssuerDocumentAsync(server, registration, context, chain, issuerText, ct).ConfigureAwait(false)
                    : await BuildLibraryResourceDocumentAsync(server, registration, context, chain, issuerText, libraryResource, ct).ConfigureAwait(false);

                return (null, document);
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Composes the document whose <c>resource</c> is the issuer from the application's contribution, asked with
    /// <see cref="WellKnownEndpointNames.ProtectedResourceMetadata"/>: a contribution naming <c>none</c> among
    /// <c>resource_signing_alg_values_supported</c> is answered 500 <c>server_error</c> with no document
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>: "The value none MUST NOT
    /// be used."); where the server validates DPoP proofs, <c>dpop_signing_alg_values_supported</c> is the host's list
    /// read by the rule the resources' challenges name their <c>algs</c> by
    /// (<see cref="CredentialEndpointDpopValidation.ResolveChallengeAlgorithmsAsync"/>, a list holding a name that is no
    /// token read as no list) and filtered to the identifiers a proof can be accepted under
    /// (<see cref="CredentialEndpointDpopValidation.AcceptableChallengeAlgorithms"/>), the contribution's member read only
    /// where it validates none.
    /// </summary>
    /// <param name="server">The authorization server.</param>
    /// <param name="registration">The registration the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="chain">The request's endpoint chain.</param>
    /// <param name="issuer">The resolved issuer in its URI form, the document's <c>resource</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The document, or the 500 answer to a contribution naming <c>none</c>.</returns>
    private static async ValueTask<ServerHttpResponse> BuildIssuerDocumentAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        EndpointChain chain,
        string issuer,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        ProtectedResourceMetadataContribution contributed = oauth.ContributeProtectedResourceMetadataAsync is null
            ? ProtectedResourceMetadataContribution.Empty
            : await oauth.ContributeProtectedResourceMetadataAsync(
                registration, WellKnownEndpointNames.ProtectedResourceMetadata, context, cancellationToken).ConfigureAwait(false);

        if(contributed.ResourceSigningAlgValuesSupported is { } signingAlgorithms
            && signingAlgorithms.Contains(WellKnownJwaValues.None, StringComparer.Ordinal))
        {
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady);
        }

        //RFC 9728 Section 2: dpop_signing_alg_values_supported lists the algorithms "supported by the resource server for
        //validating Demonstrating Proof of Possession (DPoP) proof JWTs"; where the server validates proofs, those are the
        //identifiers of the host's list a proof can be accepted under (RFC 9449 Section 11.6: "In particular, the
        //algorithm none MUST NOT be allowed."), read by the one rule the challenges' algs are read by.
        IReadOnlyList<string>? dpopSigningAlgorithms = Dpop.DpopRequestReading.IsProofValidationWired(oauth)
            ? CredentialEndpointDpopValidation.AcceptableChallengeAlgorithms(
                (await CredentialEndpointDpopValidation.ResolveChallengeAlgorithmsAsync(
                    server, registration, context, cancellationToken).ConfigureAwait(false)).Algorithms)
            : contributed.DpopSigningAlgValuesSupported;

        return await WriteDocumentAsync(
            server, registration, context, issuer, HttpsJwksUriOf(chain),
            contributed with { DpopSigningAlgValuesSupported = dpopSigningAlgorithms }, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Composes the document of the library's resource <paramref name="endpointName"/> from what the library knows:
    /// <c>resource</c> the resource's identifier, <c>authorization_servers</c> the issuer
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>: "JSON array containing a
    /// list of OAuth authorization server issuer identifiers"), <c>scopes_supported</c> the scope the resource requires,
    /// <c>bearer_methods_supported</c> <c>["header"]</c> or <c>[]</c> where the server's resources require DPoP-bound
    /// access tokens, which <c>dpop_bound_access_tokens_required: true</c> then states ("whether the protected resource
    /// always requires the use of DPoP-bound access tokens"), <c>dpop_signing_alg_values_supported</c> exactly the
    /// algorithms the resource's challenges name as <c>algs</c>
    /// (<see cref="CredentialEndpointDpopValidation.ResolveChallengeAlgorithmsAsync"/>,
    /// <see cref="CredentialEndpointDpopValidation.AcceptableChallengeAlgorithms"/>), and the https <c>jwks_uri</c>. The
    /// application's contribution, asked with <paramref name="endpointName"/>, supplies the human-readable and
    /// documentation members alone; one stating any other member is answered 500 <c>server_error</c> with no document
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">Section 3.2</see>: "An error response uses the
    /// applicable HTTP status code value.").
    /// </summary>
    /// <param name="server">The authorization server.</param>
    /// <param name="registration">The registration the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="chain">The request's endpoint chain.</param>
    /// <param name="issuer">The resolved issuer in its URI form.</param>
    /// <param name="endpointName">The resource's endpoint name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The document, or the 500 answer to a contribution stating a member the library composes.</returns>
    private static async ValueTask<ServerHttpResponse> BuildLibraryResourceDocumentAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        EndpointChain chain,
        string issuer,
        string endpointName,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        _ = TryResolveLibraryResourceIdentifier(chain, endpointName, out string? resourceIdentifier);
        ProtectedResourceMetadataContribution contributed = oauth.ContributeProtectedResourceMetadataAsync is null
            ? ProtectedResourceMetadataContribution.Empty
            : await oauth.ContributeProtectedResourceMetadataAsync(registration, endpointName, context, cancellationToken).ConfigureAwait(false);
        if(IsComposedMemberContributed(contributed))
        {
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady);
        }

        bool isDpopBoundAccessTokenRequired = oauth.IsDpopBoundAccessTokenRequiredAtResources;
        string? requiredScope = RequiredScopeOf(endpointName);
        (IReadOnlyList<string>? challengeAlgorithms, _) = await CredentialEndpointDpopValidation.ResolveChallengeAlgorithmsAsync(
            server, registration, context, cancellationToken).ConfigureAwait(false);
        ProtectedResourceMetadataContribution composed = new()
        {
            AuthorizationServers = [issuer],
            ScopesSupported = requiredScope is null ? null : [requiredScope],
            BearerMethodsSupported = isDpopBoundAccessTokenRequired ? [] : [BearerMethodValues.Header],
            DpopSigningAlgValuesSupported = CredentialEndpointDpopValidation.AcceptableChallengeAlgorithms(challengeAlgorithms),
            DpopBoundAccessTokensRequired = isDpopBoundAccessTokenRequired ? true : null,
            ResourceName = contributed.ResourceName,
            ResourceDocumentation = contributed.ResourceDocumentation,
            ResourcePolicyUri = contributed.ResourcePolicyUri,
            ResourceTosUri = contributed.ResourceTosUri,
            LocalizedParameters = contributed.LocalizedParameters
        };

        return await WriteDocumentAsync(
            server, registration, context, resourceIdentifier!, HttpsJwksUriOf(chain), composed, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Whether a contribution for one of the library's own resources states a member other than the human-readable and
    /// documentation members (<c>resource_name</c>, <c>resource_documentation</c>, <c>resource_policy_uri</c>,
    /// <c>resource_tos_uri</c> and their language-tagged forms,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.1">RFC 9728 Section 2.1</see>): a member the library
    /// composes, or one that would describe the resource otherwise than it behaves, any stated value, an empty list
    /// included, or a language-tagged entry naming another member.
    /// </summary>
    /// <param name="contribution">The contribution asked for the resource.</param>
    /// <returns><see langword="true"/> when the contribution states such a member.</returns>
    private static bool IsComposedMemberContributed(ProtectedResourceMetadataContribution contribution) =>
        contribution.AuthorizationServers is not null
        || contribution.ScopesSupported is not null
        || contribution.BearerMethodsSupported is not null
        || contribution.ResourceSigningAlgValuesSupported is not null
        || contribution.TlsClientCertificateBoundAccessTokens is not null
        || contribution.AuthorizationDetailsTypesSupported is not null
        || contribution.DpopSigningAlgValuesSupported is not null
        || contribution.DpopBoundAccessTokensRequired is not null
        || (contribution.LocalizedParameters is { } localized && !localized.Keys.All(IsLanguageTaggedHumanReadableName));


    /// <summary>
    /// Whether <paramref name="name"/> is a language-tagged form of a human-readable or documentation member:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.1">RFC 9728 Section 2.1</see>, "language tags [BCP47]
    /// are added to resource metadata parameter names, delimited by a # character", over <c>resource_name</c>,
    /// <c>resource_documentation</c>, <c>resource_policy_uri</c> and <c>resource_tos_uri</c>, the tag after the
    /// <c>#</c> in the lexical form of a language tag (<see cref="IsLanguageTagForm"/>).
    /// </summary>
    /// <param name="name">The contributed member name.</param>
    /// <returns><see langword="true"/> when the name is such a form.</returns>
    private static bool IsLanguageTaggedHumanReadableName(string name)
    {
        int separator = name.IndexOf('#', StringComparison.Ordinal);
        if(separator <= 0 || separator == name.Length - 1)
        {
            return false;
        }

        string parameter = name[..separator];
        bool isHumanReadableParameter =
            string.Equals(parameter, ProtectedResourceMetadataParameterNames.ResourceName, StringComparison.Ordinal)
            || string.Equals(parameter, ProtectedResourceMetadataParameterNames.ResourceDocumentation, StringComparison.Ordinal)
            || string.Equals(parameter, ProtectedResourceMetadataParameterNames.ResourcePolicyUri, StringComparison.Ordinal)
            || string.Equals(parameter, ProtectedResourceMetadataParameterNames.ResourceTosUri, StringComparison.Ordinal);

        return isHumanReadableParameter && IsLanguageTagForm(name[(separator + 1)..]);
    }


    /// <summary>
    /// Whether <paramref name="tag"/> has the lexical form of a language tag:
    /// <see href="https://www.rfc-editor.org/rfc/rfc5646#section-2.1">RFC 5646 Section 2.1</see>, "Subtags, in turn,
    /// are a sequence of alphanumeric characters (letters and digits), distinguished and separated from other subtags in
    /// a tag by a hyphen", "All subtags have a maximum length of eight characters.  Whitespace is not permitted in a
    /// language tag." and "alphanum = (ALPHA / DIGIT)": one or more subtags of one to eight ASCII letters or digits
    /// joined by <c>-</c>. Whether the subtags are registered is not read (Section 2.1: "a language tag processor need
    /// not have a list of valid tags or subtags").
    /// </summary>
    /// <param name="tag">The text after the <c>#</c> of a member name.</param>
    /// <returns><see langword="true"/> when the text has the form.</returns>
    private static bool IsLanguageTagForm(string tag)
    {
        foreach(string subtag in tag.Split('-'))
        {
            if(subtag.Length is < 1 or > 8 || !subtag.All(char.IsAsciiLetterOrDigit))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// The <c>jwks_uri</c> of both documents: the URL of the chain's JWK Set endpoint, read off the chain the dispatcher
    /// built so the advertised URL is the one the matcher binds to, written only when it is https
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>: "This URL MUST use the
    /// https scheme."), and <see langword="null"/> otherwise.
    /// </summary>
    /// <param name="chain">The request's endpoint chain.</param>
    /// <returns>The JWK Set URL, or <see langword="null"/>.</returns>
    private static string? HttpsJwksUriOf(EndpointChain chain)
    {
        foreach(ServerEndpoint chainEndpoint in chain)
        {
            if(string.Equals(chainEndpoint.Name, WellKnownEndpointNames.MetadataJwks, StringComparison.Ordinal))
            {
                Uri jwks = chainEndpoint.ResolvedUri;

                return jwks.IsAbsoluteUri && string.Equals(jwks.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
                    ? jwks.ToString()
                    : null;
            }
        }

        return null;
    }


    /// <summary>
    /// Signs and writes one document: the Section 2.2 claim set handed to the application's signer when one is wired, then the
    /// plain document carrying the signer's JWT as <c>signed_metadata</c>, answered <c>200</c> with
    /// <c>application/json</c> (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section
    /// 3.2</see>).
    /// </summary>
    /// <param name="server">The authorization server.</param>
    /// <param name="registration">The registration the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="resource">The document's <c>resource</c>.</param>
    /// <param name="jwksUri">The document's <c>jwks_uri</c>, or <see langword="null"/>.</param>
    /// <param name="contribution">The members the document carries.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The 200 answer.</returns>
    private static async ValueTask<ServerHttpResponse> WriteDocumentAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        string resource,
        string? jwksUri,
        ProtectedResourceMetadataContribution contribution,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();

        //Section 2.2 signed_metadata: the library assembles the claim set and drops out to the application's signer (which owns
        //the key, the algorithm, and the spec-required iss claim).
        string? signedMetadata = null;
        if(oauth.SignProtectedResourceMetadataAsync is not null)
        {
            JwtPayload claims = BuildMetadataClaims(resource, jwksUri, contribution);
            signedMetadata = await oauth.SignProtectedResourceMetadataAsync(
                claims, registration, context, cancellationToken).ConfigureAwait(false);
        }

        return ServerHttpResponse.Ok(
            BuildMetadataJson(resource, jwksUri, contribution, signedMetadata), WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// Serialises the RFC 9728 §2 metadata document. Parameters with zero
    /// values are omitted per Section 3.2, but for a stated empty
    /// <c>bearer_methods_supported</c>, written as <c>[]</c> (RFC 9728 Section 2:
    /// "The empty array [] can be used to indicate that no bearer methods are
    /// supported."). Built by hand through
    /// <see cref="JsonAppender"/> to honour the <c>Verifiable.OAuth</c>
    /// serialization firewall.
    /// </summary>
    private static string BuildMetadataJson(
        string resource,
        string? jwksUri,
        ProtectedResourceMetadataContribution contribution,
        string? signedMetadata)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            _ = sb.Append('{');

            bool first = true;
            JsonAppender.AppendStringField(
                sb, ProtectedResourceMetadataParameterNames.Resource, resource, ref first);

            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.AuthorizationServers,
                contribution.AuthorizationServers, ref first);

            if(!string.IsNullOrEmpty(jwksUri))
            {
                JsonAppender.AppendStringField(
                    sb, ProtectedResourceMetadataParameterNames.JwksUri, jwksUri, ref first);
            }

            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.ScopesSupported,
                contribution.ScopesSupported, ref first);
            AppendStatedListField(sb, ProtectedResourceMetadataParameterNames.BearerMethodsSupported,
                contribution.BearerMethodsSupported, ref first);
            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.ResourceSigningAlgValuesSupported,
                contribution.ResourceSigningAlgValuesSupported, ref first);

            AppendOptionalString(sb, ProtectedResourceMetadataParameterNames.ResourceName,
                contribution.ResourceName, ref first);
            AppendOptionalString(sb, ProtectedResourceMetadataParameterNames.ResourceDocumentation,
                contribution.ResourceDocumentation, ref first);
            AppendOptionalString(sb, ProtectedResourceMetadataParameterNames.ResourcePolicyUri,
                contribution.ResourcePolicyUri, ref first);
            AppendOptionalString(sb, ProtectedResourceMetadataParameterNames.ResourceTosUri,
                contribution.ResourceTosUri, ref first);

            if(contribution.TlsClientCertificateBoundAccessTokens is bool mtlsBound)
            {
                JsonAppender.AppendBoolField(
                    sb, ProtectedResourceMetadataParameterNames.TlsClientCertificateBoundAccessTokens,
                    mtlsBound, ref first);
            }

            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.AuthorizationDetailsTypesSupported,
                contribution.AuthorizationDetailsTypesSupported, ref first);
            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.DpopSigningAlgValuesSupported,
                contribution.DpopSigningAlgValuesSupported, ref first);

            if(contribution.DpopBoundAccessTokensRequired is bool dpopRequired)
            {
                JsonAppender.AppendBoolField(
                    sb, ProtectedResourceMetadataParameterNames.DpopBoundAccessTokensRequired,
                    dpopRequired, ref first);
            }

            //§2.1 language-tagged variants, emitted verbatim.
            if(contribution.LocalizedParameters is { Count: > 0 } localized)
            {
                foreach(KeyValuePair<string, string> entry in localized)
                {
                    JsonAppender.AppendStringField(sb, entry.Key, entry.Value, ref first);
                }
            }

            if(!string.IsNullOrEmpty(signedMetadata))
            {
                JsonAppender.AppendStringField(
                    sb, ProtectedResourceMetadataParameterNames.SignedMetadata, signedMetadata, ref first);
            }

            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Assembles the §2.2 metadata claim set handed to the application's
    /// signer — the same values the plain document carries, so the signed JWT
    /// cannot diverge from the advertised document. The signer adds the
    /// spec-required <c>iss</c> claim. A <c>signed_metadata</c> claim is never
    /// part of the set (§2.2: it SHOULD NOT appear as a claim in the JWT).
    /// </summary>
    private static JwtPayload BuildMetadataClaims(
        string resource, string? jwksUri, ProtectedResourceMetadataContribution contribution)
    {
        //The text the plain document writes as resource, so the signed claim and the advertised value are identical.
        JwtPayload claims = new()
        {
            [ProtectedResourceMetadataParameterNames.Resource] = resource
        };

        if(contribution.AuthorizationServers is { Count: > 0 } servers)
        {
            claims[ProtectedResourceMetadataParameterNames.AuthorizationServers] = servers;
        }

        if(!string.IsNullOrEmpty(jwksUri))
        {
            claims[ProtectedResourceMetadataParameterNames.JwksUri] = jwksUri;
        }

        if(contribution.ScopesSupported is { Count: > 0 } scopes)
        {
            claims[ProtectedResourceMetadataParameterNames.ScopesSupported] = scopes;
        }

        //RFC 9728 Section 2: "The empty array [] can be used to indicate that no bearer methods are supported.", the
        //named exception to Section 3.2's omission of zero values, so a stated empty list is carried as stated.
        if(contribution.BearerMethodsSupported is { } bearerMethods)
        {
            claims[ProtectedResourceMetadataParameterNames.BearerMethodsSupported] = bearerMethods;
        }

        if(contribution.ResourceSigningAlgValuesSupported is { Count: > 0 } signingAlgs)
        {
            claims[ProtectedResourceMetadataParameterNames.ResourceSigningAlgValuesSupported] = signingAlgs;
        }

        if(!string.IsNullOrEmpty(contribution.ResourceName))
        {
            claims[ProtectedResourceMetadataParameterNames.ResourceName] = contribution.ResourceName;
        }

        if(!string.IsNullOrEmpty(contribution.ResourceDocumentation))
        {
            claims[ProtectedResourceMetadataParameterNames.ResourceDocumentation] = contribution.ResourceDocumentation;
        }

        if(!string.IsNullOrEmpty(contribution.ResourcePolicyUri))
        {
            claims[ProtectedResourceMetadataParameterNames.ResourcePolicyUri] = contribution.ResourcePolicyUri;
        }

        if(!string.IsNullOrEmpty(contribution.ResourceTosUri))
        {
            claims[ProtectedResourceMetadataParameterNames.ResourceTosUri] = contribution.ResourceTosUri;
        }

        if(contribution.TlsClientCertificateBoundAccessTokens is bool mtlsBound)
        {
            claims[ProtectedResourceMetadataParameterNames.TlsClientCertificateBoundAccessTokens] = mtlsBound;
        }

        if(contribution.AuthorizationDetailsTypesSupported is { Count: > 0 } detailTypes)
        {
            claims[ProtectedResourceMetadataParameterNames.AuthorizationDetailsTypesSupported] = detailTypes;
        }

        if(contribution.DpopSigningAlgValuesSupported is { Count: > 0 } dpopAlgs)
        {
            claims[ProtectedResourceMetadataParameterNames.DpopSigningAlgValuesSupported] = dpopAlgs;
        }

        if(contribution.DpopBoundAccessTokensRequired is bool dpopRequired)
        {
            claims[ProtectedResourceMetadataParameterNames.DpopBoundAccessTokensRequired] = dpopRequired;
        }

        if(contribution.LocalizedParameters is { Count: > 0 } localized)
        {
            foreach(KeyValuePair<string, string> entry in localized)
            {
                claims[entry.Key] = entry.Value;
            }
        }

        return claims;
    }


    /// <summary>
    /// Appends the string member <paramref name="name"/> when <paramref name="value"/> holds text, and nothing for a
    /// <see langword="null"/> or empty value: <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728
    /// Section 3.2</see>, "Parameters with zero values MUST be omitted from the response."
    /// </summary>
    /// <param name="sb">The document being written.</param>
    /// <param name="name">The member name.</param>
    /// <param name="value">The member value, or <see langword="null"/>.</param>
    /// <param name="first">Whether no member has been written yet; cleared when this one is.</param>
    private static void AppendOptionalString(StringBuilder sb, string name, string? value, ref bool first)
    {
        if(!string.IsNullOrEmpty(value))
        {
            JsonAppender.AppendStringField(sb, name, value, ref first);
        }
    }


    /// <summary>
    /// Appends the JSON array member <paramref name="name"/> when <paramref name="values"/> holds at least one value, and
    /// nothing for a <see langword="null"/> or empty list: <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC
    /// 9728 Section 3.2</see>, "Parameters with multiple values are represented as JSON arrays. Parameters with zero values
    /// MUST be omitted from the response."
    /// </summary>
    /// <param name="sb">The document being written.</param>
    /// <param name="name">The member name.</param>
    /// <param name="values">The member values, or <see langword="null"/>.</param>
    /// <param name="first">Whether no member has been written yet; cleared when this one is.</param>
    private static void AppendArrayField(
        StringBuilder sb, string name, IReadOnlyList<string>? values, ref bool first)
    {
        if(values is { Count: > 0 })
        {
            JsonAppender.AppendStringArrayField(sb, name, values, ref first);
        }
    }


    /// <summary>
    /// Appends the JSON array member <paramref name="name"/> whenever <paramref name="values"/> is stated, an empty list
    /// as <c>[]</c>, and nothing for <see langword="null"/>: the member whose empty array has a meaning of its own,
    /// <c>bearer_methods_supported</c> (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section
    /// 2</see>: "The empty array [] can be used to indicate that no bearer methods are supported."), the named exception
    /// to Section 3.2's omission of zero values.
    /// </summary>
    /// <param name="sb">The document being written.</param>
    /// <param name="name">The member name.</param>
    /// <param name="values">The member values, or <see langword="null"/> when the member is not stated.</param>
    /// <param name="first">Whether no member has been written yet; cleared when this one is.</param>
    private static void AppendStatedListField(
        StringBuilder sb, string name, IReadOnlyList<string>? values, ref bool first)
    {
        if(values is not null)
        {
            JsonAppender.AppendStringArrayField(sb, name, values, ref first);
        }
    }
}
