using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Resolves DIDs and dereferences DID URLs following the W3C DID Resolution v0.3 algorithms.
/// Dispatches to method-specific handlers via selector delegates.
/// </summary>
/// <remarks>
/// <para>
/// Method-specific resolvers are registered at construction time via
/// <see cref="DidMethodSelectors.FromResolvers"/>:
/// </para>
/// <code>
/// new DidResolver(DidMethodSelectors.FromResolvers(
///     (WellKnownDidMethodPrefixes.WebDidMethodPrefix, WebDidResolver.ResolveAsync),
///     (WellKnownDidMethodPrefixes.CheqdDidMethodPrefix, CheqdDidResolver.ResolveAsync)
/// ));
/// </code>
/// <para>
/// See <see href="https://w3c.github.io/did-resolution/#resolving">DID Resolution §4.4</see>
/// and <see href="https://w3c.github.io/did-resolution/#dereferencing-algorithm">§5.4</see>.
/// </para>
/// </remarks>
public sealed class DidResolver
{
    private SelectMethodResolverDelegate ResolverSelector { get; }
    private SelectMethodDereferencerDelegate DereferencerSelector { get; }

    /// <summary>
    /// Creates a new <see cref="DidResolver"/> with the specified method selectors.
    /// </summary>
    /// <param name="resolverSelector">
    /// A delegate that selects method-specific resolution handlers. Build one with
    /// <see cref="DidMethodSelectors.FromResolvers"/>.
    /// </param>
    /// <param name="dereferencerSelector">
    /// An optional delegate that selects method-specific dereferencers for path/query
    /// handling. Defaults to <see cref="DidMethodSelectors.None"/> so all dereferencing
    /// falls back to resolution then fragment matching.
    /// </param>
    public DidResolver(
        SelectMethodResolverDelegate resolverSelector,
        SelectMethodDereferencerDelegate? dereferencerSelector = null)
    {
        ArgumentNullException.ThrowIfNull(resolverSelector);
        ResolverSelector = resolverSelector;
        DereferencerSelector = dereferencerSelector ?? DidMethodSelectors.None;
    }

    /// <summary>
    /// Resolves a DID into a DID document following the W3C DID Resolution algorithm.
    /// </summary>
    /// <param name="did">The DID to resolve.</param>
    /// <param name="options">Resolution options. A <see langword="null"/> value is treated as empty options.</param>
    /// <param name="cancellationToken">Token for cancelling the operation.</param>
    /// <returns>
    /// A resolution result containing the document, resolution metadata, and document metadata.
    /// When resolution fails, <see cref="DidResolutionResult.IsSuccessful"/> is <see langword="false"/>
    /// and <see cref="DidResolutionMetadata.Error"/> carries an RFC 9457 problem details object.
    /// </returns>
    public async ValueTask<DidResolutionResult> ResolveAsync(
        string did,
        DidResolutionOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= DidResolutionOptions.Empty;

        //Step 1: Validate that the input conforms to DID syntax.
        if(!DidUrl.TryParseAbsolute(did, out var parsedDid))
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        //Step 2: Determine whether the DID method is supported.
        string methodName = parsedDid.Method!;
        var methodResolver = ResolverSelector(methodName);
        if(methodResolver is null)
        {
            return DidResolutionResult.Failure(DidResolutionErrors.MethodNotSupported);
        }

        //Steps 3–4: Option support and validity checking are delegated to the method-specific
        //resolver, as the set of supported and valid options varies by method.

        //Step 5: Execute the method-specific Read operation.
        DidResolutionResult result;
        try
        {
            result = await methodResolver(did, options, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InternalError);
        }

        //Step 5b: A deactivated DID returns an empty document with deactivated metadata.
        //The method resolver signals deactivation via DocumentMetadata.Deactivated = true
        //and a null Document. This path is reached only when the resolver sets the flag
        //without populating a document — the spec requires null document + deactivated metadata.
        if(result.IsSuccessful
            && result.Document is null
            && result.Kind == DidResolutionKind.Document
            && result.DocumentMetadata.Deactivated)
        {
            return result;
        }

        //Apply expandRelativeUrls post-processing when the option is enabled and a document
        //was returned directly. Methods that return a URL (DocumentUrl/VerifiedLog) cannot
        //have their documents expanded at this layer.
        if(options.ExpandRelativeUrls == true
            && result.IsSuccessful
            && result.Kind == DidResolutionKind.Document
            && result.Document is not null)
        {
            //PR #299 against the editor's draft proposes extending expansion to cover
            //extension properties. The current implementation expands only the three sections
            //named in the December 2025 Working Draft: services, verification methods, and
            //verification relationships.
            var expanded = ExpandRelativeUrls(result.Document, did);
            return DidResolutionResult.Success(expanded, result.DocumentMetadata, result.ResolutionMetadata.ContentType);
        }

        return result;
    }

    /// <summary>
    /// Dereferences a DID URL into a resource following the W3C DID URL Dereferencing algorithm.
    /// </summary>
    /// <param name="didUrl">The DID URL to dereference.</param>
    /// <param name="options">Dereferencing options. A <see langword="null"/> value is treated as empty options.</param>
    /// <param name="cancellationToken">Token for cancelling the operation.</param>
    /// <returns>
    /// A dereferencing result containing the resource or error information.
    /// When dereferencing fails, <see cref="DidDereferencingResult.IsSuccessful"/> is
    /// <see langword="false"/> and <see cref="DidDereferencingMetadata.Error"/> carries an
    /// RFC 9457 problem details object.
    /// </returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "DID URLs contain method-specific syntax that System.Uri does not handle correctly.")]
    public async ValueTask<DidDereferencingResult> DereferenceAsync(
        string didUrl,
        DidDereferencingOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= DidDereferencingOptions.Empty;

        //Step 1: Validate that the input conforms to DID URL syntax.
        if(!DidUrl.TryParse(didUrl, out var parsed))
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.InvalidDidUrl);
        }

        //Fragment-only references have no base DID and cannot be dereferenced.
        if(parsed.IsRelative)
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.InvalidDidUrl);
        }

        string baseDid = parsed.BaseDid!;
        string methodName = parsed.Method!;

        //If path or query is present and a method-specific dereferencer is registered, use it.
        if((parsed.Path is not null || parsed.Query is not null)
            && DereferencerSelector(methodName) is { } methodDereferencer)
        {
            try
            {
                var methodResult = await methodDereferencer(
                    baseDid, parsed.Path, parsed.Query, options, cancellationToken).ConfigureAwait(false);

                //Apply fragment processing when the method returned a document and a fragment is present.
                if(methodResult.IsSuccessful && parsed.Fragment is not null && methodResult.ContentStream is DidDocument doc)
                {
                    return DereferenceFragment(doc, parsed.Fragment, methodResult.ContentMetadata, options.VerificationRelationship);
                }

                return methodResult;
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return DidDereferencingResult.Failure(DidResolutionErrors.InternalError);
            }
        }

        //Step 2: Resolve the base DID. All DID parameters and dereferencing options are
        //passed as resolution options per the spec.
        var resolution = await ResolveAsync(baseDid, new DidResolutionOptions
        {
            Accept = options.Accept
        }, cancellationToken).ConfigureAwait(false);

        //Step 3: If the DID does not exist, return NOT_FOUND.
        if(!resolution.IsSuccessful)
        {
            return DidDereferencingResult.Failure(resolution.ResolutionMetadata.Error ?? DidResolutionErrors.NotFound);
        }

        //DocumentUrl and VerifiedLog results require the caller to fetch the document;
        //they cannot be dereferenced further at this layer.
        if(resolution.Kind != DidResolutionKind.Document)
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.NotFound);
        }

        //Step 6: No path and no query — return the resolved DID document.
        if(parsed.Path is null && parsed.Query is null && parsed.Fragment is null)
        {
            return DidDereferencingResult.Success(
                resolution.Document!,
                resolution.DocumentMetadata,
                resolution.ResolutionMetadata.ContentType);
        }

        //Step 8: Process ?service= and optionally ?relativeRef= per the dereferencing algorithm.
        //Note: PR #301 proposes adding guidance on query parameter normalization (ordering,
        //percent-encoding, duplicates) to the Parameters and Security sections. The current
        //implementation treats parameter order as significant and performs no normalization.
        if(parsed.Query is not null)
        {
            string? serviceParam = GetQueryParameter(parsed.Query, "service");
            if(serviceParam is not null)
            {
                var service = FindService(resolution.Document!, serviceParam);
                if(service is null)
                {
                    return DidDereferencingResult.Failure(DidResolutionErrors.NotFound);
                }

                string endpoint = service.ServiceEndpoint?.ToString() ?? string.Empty;

                string? relativeRef = GetQueryParameter(parsed.Query, "relativeRef");
                if(relativeRef is not null)
                {
                    //Append the relative reference per RFC 3986 §5 Reference Resolution.
                    endpoint = endpoint.TrimEnd('/') + '/' + relativeRef.TrimStart('/');
                }

                //When a fragment is present on the DID URL and the result is a service endpoint
                //URL, the fragment is appended to the endpoint URL per §5.4.2.
                if(parsed.Fragment is not null)
                {
                    endpoint = $"{endpoint}#{parsed.Fragment}";
                }

                return DidDereferencingResult.Success(endpoint, resolution.DocumentMetadata);
            }
        }

        //No fragment present — return the DID document as the content stream.
        if(parsed.Fragment is null)
        {
            return DidDereferencingResult.Success(
                resolution.Document!,
                resolution.DocumentMetadata,
                resolution.ResolutionMetadata.ContentType);
        }

        //Apply fragment dereferencing on the resolved document.
        return DereferenceFragment(resolution.Document!, parsed.Fragment, resolution.DocumentMetadata, options.VerificationRelationship);
    }

    /// <summary>
    /// Expands all relative DID URLs in the services, verification methods, and verification
    /// relationships of <paramref name="document"/> to absolute DID URLs using <paramref name="baseDid"/>
    /// as the base, per the <c>expandRelativeUrls</c> algorithm in W3C DID Resolution §4.4.
    /// </summary>
    private static DidDocument ExpandRelativeUrls(DidDocument document, string baseDid)
    {
        //Only relative IDs (those starting with '#') require expansion to absolute form.
        static string ExpandId(string id, string baseDid) => $"{baseDid}{id}";

        VerificationMethod[]? expandedVms = null;
        if(document.VerificationMethod is not null)
        {
            expandedVms = new VerificationMethod[document.VerificationMethod.Length];
            for(int i = 0; i < document.VerificationMethod.Length; ++i)
            {
                var vm = document.VerificationMethod[i];
                if(vm.Id is not null && vm.Id.StartsWith('#'))
                {
                    expandedVms[i] = new VerificationMethod
                    {
                        Id = ExpandId(vm.Id, baseDid),
                        Type = vm.Type,
                        Controller = vm.Controller,
                        Expires = vm.Expires,
                        Revoked = vm.Revoked,
                        KeyFormat = vm.KeyFormat
                    };
                }
                else
                {
                    expandedVms[i] = vm;
                }
            }
        }

        Service[]? expandedServices = null;
        if(document.Service is not null)
        {
            expandedServices = new Service[document.Service.Length];
            for(int i = 0; i < document.Service.Length; ++i)
            {
                var svc = document.Service[i];
                string? idStr = svc.Id?.ToString();
                if(idStr is not null && idStr.StartsWith('#'))
                {
                    //DidUrl.ParseAbsolute throws for invalid input; the expanded string is always
                    //valid because baseDid is a well-formed absolute DID from a prior parse step.
                    expandedServices[i] = new Service
                    {
                        Id = DidUrl.ParseAbsolute(ExpandId(idStr, baseDid)),
                        Type = svc.Type,
                        Types = svc.Types,
                        ServiceEndpoint = svc.ServiceEndpoint,
                        ServiceEndpointMap = svc.ServiceEndpointMap,
                        ServiceEndpoints = svc.ServiceEndpoints,
                        AdditionalData = svc.AdditionalData
                    };
                }
                else
                {
                    expandedServices[i] = svc;
                }
            }
        }

        return new DidDocument
        {
            Context = document.Context,
            Id = document.Id,
            AlsoKnownAs = document.AlsoKnownAs,
            Controller = document.Controller,
            VerificationMethod = expandedVms ?? document.VerificationMethod,
            Authentication = document.Authentication,
            AssertionMethod = document.AssertionMethod,
            KeyAgreement = document.KeyAgreement,
            CapabilityInvocation = document.CapabilityInvocation,
            CapabilityDelegation = document.CapabilityDelegation,
            Service = expandedServices ?? document.Service
        };
    }

    /// <summary>
    /// Extracts the value of a named parameter from a raw query string (without the leading
    /// <c>?</c>). Returns <see langword="null"/> when the parameter is not present.
    /// </summary>
    private static string? GetQueryParameter(string query, string name)
    {
        string prefix = $"{name}=";
        foreach(var segment in query.Split('&'))
        {
            if(segment.StartsWith(prefix, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(segment[prefix.Length..]);
            }
        }

        return null;
    }

    /// <summary>
    /// Finds a service in <paramref name="document"/> whose ID fragment matches
    /// <paramref name="serviceParam"/>, falling back to a match on service type.
    /// Returns <see langword="null"/> when no match is found.
    /// </summary>
    private static Service? FindService(DidDocument document, string serviceParam)
    {
        if(document.Service is null)
        {
            return null;
        }

        foreach(var service in document.Service)
        {
            if(service.Id is null)
            {
                continue;
            }

            string idString = service.Id.ToString()!;
            int hashIndex = idString.IndexOf('#', StringComparison.Ordinal);
            string idFragment = hashIndex >= 0 ? idString[(hashIndex + 1)..] : idString;
            if(string.Equals(idFragment, serviceParam, StringComparison.Ordinal))
            {
                return service;
            }

            if(string.Equals(service.Type, serviceParam, StringComparison.Ordinal))
            {
                return service;
            }
        }

        return null;
    }

    /// <summary>
    /// Locates a resource within <paramref name="document"/> by matching its fragment
    /// identifier against verification method and service IDs. When
    /// <paramref name="verificationRelationship"/> is specified, the matched verification
    /// method must be authorized for that relationship or an error is returned.
    /// </summary>
    private static DidDereferencingResult DereferenceFragment(
        DidDocument document,
        string fragment,
        DidDocumentMetadata? contentMetadata,
        string? verificationRelationship)
    {
        string fragmentWithHash = fragment.StartsWith('#') ? fragment : $"#{fragment}";

        if(document.VerificationMethod is not null)
        {
            var match = document.VerificationMethod
                .FirstOrDefault(vm => vm.Id is not null
                    && (string.Equals(vm.Id, fragmentWithHash, StringComparison.Ordinal)
                        || vm.Id.EndsWith(fragmentWithHash, StringComparison.Ordinal)));

            if(match is not null)
            {
                //When a verificationRelationship option is present, validate that the
                //matched verification method is authorized for that relationship.
                if(verificationRelationship is not null
                    && !IsAuthorizedForRelationship(document, match.Id!, verificationRelationship))
                {
                    return DidDereferencingResult.Failure(new DidProblemDetails(
                        DidErrorTypes.InvalidDidUrl,
                        Title: "Invalid verification relationship",
                        Detail: $"The verification method '{match.Id}' is not authorized for the '{verificationRelationship}' relationship."));
                }

                return DidDereferencingResult.Success(match, contentMetadata);
            }
        }

        if(document.Service is not null)
        {
            var match = document.Service
                .FirstOrDefault(svc => svc.Id is not null
                    && (string.Equals(svc.Id.ToString(), fragmentWithHash, StringComparison.Ordinal)
                        || svc.Id.ToString()!.EndsWith(fragmentWithHash, StringComparison.Ordinal)));

            if(match is not null)
            {
                return DidDereferencingResult.Success(match, contentMetadata);
            }
        }

        return DidDereferencingResult.Failure(DidResolutionErrors.NotFound);
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="vmId"/> is listed (by value or
    /// by reference) in the verification relationship array identified by
    /// <paramref name="relationship"/> on <paramref name="document"/>.
    /// </summary>
    private static bool IsAuthorizedForRelationship(
        DidDocument document,
        string vmId,
        string relationship)
    {
        IEnumerable<string?>? refs = relationship switch
        {
            "authentication" => document.Authentication?.Select(r => r.Id),
            "assertionMethod" => document.AssertionMethod?.Select(r => r.Id),
            "keyAgreement" => document.KeyAgreement?.Select(r => r.Id),
            "capabilityInvocation" => document.CapabilityInvocation?.Select(r => r.Id),
            "capabilityDelegation" => document.CapabilityDelegation?.Select(r => r.Id),
            _ => null
        };

        if(refs is null)
        {
            return false;
        }

        foreach(var refId in refs)
        {
            if(string.Equals(refId, vmId, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
