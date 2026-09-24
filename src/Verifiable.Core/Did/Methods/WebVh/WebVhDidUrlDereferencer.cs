using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Outbound;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Transport;
using Verifiable.Cryptography;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// Dereferences <c>did:webvh</c> DID URLs that carry a path: <c>&lt;did&gt;/path/to/file</c> through the
/// implicit <c>#files</c> (<c>relativeRef</c>) service, and the special <c>&lt;did&gt;/whois</c> through the
/// implicit <c>#whois</c> (<c>LinkedVerifiablePresentation</c>) service, per the did:webvh v1.0 DID URL
/// Resolution rules.
/// </summary>
/// <remarks>
/// <para>
/// Both forms first resolve and verify the base DID through the supplied
/// <see cref="DidMethodResolverDelegate"/> — the same fetch/replay/verify pipeline a plain resolution runs —
/// and read the service endpoint off the resolved <see cref="DidDocument"/>. An explicit service of the same
/// id in the DIDDoc therefore overrides the implicit one automatically, because the resolver attaches the
/// implicit services only when no explicit one is present.
/// </para>
/// <para>
/// Error mapping follows the specification's two-error model for DID URL resolution: a service endpoint whose
/// scheme is not HTTP(S) is an <c>invalidDid</c>; a resource that cannot be retrieved (for example an HTTP
/// 404, a policy denial, or a transport failure) is a <c>notFound</c>. For <c>/whois</c> the retrieved
/// <c>whois.vp</c> MUST be a W3C VCDM Verifiable Presentation signed by the DID and containing at least one
/// credential whose <c>credentialSubject.id</c> is the DID; a presentation that fails either check is an
/// <c>invalidDid</c> (the resource was found but is not a conforming whois presentation).
/// </para>
/// </remarks>
public static class WebVhDidUrlDereferencer
{
    /// <summary>
    /// Builds a <see cref="DidMethodDereferencerDelegate"/> for <c>did:webvh</c> DID URLs with a path.
    /// </summary>
    /// <param name="resolve">
    /// The <c>did:webvh</c> resolver the dereferencer drives to resolve and verify the base DID — typically the
    /// same delegate produced by <see cref="WebVhDidResolver.Build(OutboundTransportDelegate, WebVhLineParser, WebVhWitnessFileParser, WebVhDocumentIdentityReader, WebVhStateDeserializer, WebVhCanonicalizer, EncodeDelegate, DecodeDelegate, BaseMemoryPool, TimeProvider)"/> and registered for resolution.
    /// </param>
    /// <param name="transport">The application-supplied single-hop transport the guarded fetch drives.</param>
    /// <param name="presentationDeserializer">Parses a fetched <c>whois.vp</c> into a presentation.</param>
    /// <param name="presentationCanonicalizer">The canonicalizer the whois presentation's proof is verified over.</param>
    /// <param name="proofValueDecoder">Decodes the whois proof value to signature bytes.</param>
    /// <param name="presentationSerializer">Serializes the proofless presentation for canonicalization.</param>
    /// <param name="proofOptionsSerializer">Serializes the whois proof options for canonicalization.</param>
    /// <param name="base58Decoder">The base58btc decoder for the whois proof value.</param>
    /// <param name="computeDigest">The digest function the whois cryptosuite hashes with.</param>
    /// <param name="pool">The pool the whois verification buffers are rented from.</param>
    /// <param name="knownContext">
    /// The deployment's known <c>@context</c> for a <c>whois.vp</c>'s own <c>@context</c>, checked
    /// after the proof verifies per
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data Integrity
    /// 1.0 §2.4.1 Validating Contexts</see> and threaded to
    /// <see cref="PresentationDataIntegrityExtensions.VerifyLinkedPresentationAsync"/> unchanged.
    /// </param>
    /// <returns>A <see cref="DidMethodDereferencerDelegate"/> for registration with the resolver composition.</returns>
    public static DidMethodDereferencerDelegate Build(
        DidMethodResolverDelegate resolve,
        OutboundTransportDelegate transport,
        PresentationDeserializeDelegate presentationDeserializer,
        CanonicalizationDelegate presentationCanonicalizer,
        ProofValueDecoderDelegate proofValueDecoder,
        PresentationSerializeDelegate presentationSerializer,
        ProofOptionsSerializeDelegate proofOptionsSerializer,
        DecodeDelegate base58Decoder,
        ComputeDigestDelegate computeDigest,
        BaseMemoryPool pool,
        Context knownContext)
    {
        ArgumentNullException.ThrowIfNull(resolve);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(presentationDeserializer);
        ArgumentNullException.ThrowIfNull(presentationCanonicalizer);
        ArgumentNullException.ThrowIfNull(proofValueDecoder);
        ArgumentNullException.ThrowIfNull(presentationSerializer);
        ArgumentNullException.ThrowIfNull(proofOptionsSerializer);
        ArgumentNullException.ThrowIfNull(base58Decoder);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(knownContext);

        return async (baseDid, path, query, options, context, cancellationToken) =>
        {
            //The resolver dispatches a method dereferencer only for a DID URL with a path; a null path here is a
            //defensive guard, not a reachable state.
            if(path is null)
            {
                return DidDereferencingResult.Failure(DidResolutionErrors.NotFound);
            }

            //Resolve and verify the base DID. The resolved DIDDoc already carries the implicit (or explicit
            //override) #files and #whois services this dereference reads. A versionId/versionTime DID-URL query
            //is threaded into resolution so a versioned path/whois DID URL dereferences against the requested
            //version, not the latest (did:webvh v1.0, Reading did:webvh DID URLs).
            DidResolutionOptions resolutionOptions = BuildResolutionOptions(query, options.Accept);

            DidResolutionResult resolution = await resolve(baseDid, resolutionOptions, context, cancellationToken).ConfigureAwait(false);
            if(!resolution.IsSuccessful || resolution.Document is null || resolution.Kind != DidResolutionKind.Document)
            {
                return DidDereferencingResult.Failure(resolution.ResolutionMetadata.Error ?? DidResolutionErrors.NotFound);
            }

            DidDocument document = resolution.Document;
            string relativePath = path.TrimStart('/');

            if(string.Equals(relativePath, WellKnownWebVhValues.WhoisPathSegment, StringComparison.Ordinal))
            {
                return await DereferenceWhoisAsync(
                    document,
                    baseDid,
                    transport,
                    presentationDeserializer,
                    presentationCanonicalizer,
                    proofValueDecoder,
                    presentationSerializer,
                    proofOptionsSerializer,
                    base58Decoder,
                    computeDigest,
                    pool,
                    knownContext,
                    context,
                    cancellationToken).ConfigureAwait(false);
            }

            return await DereferenceFilesAsync(document, path, transport, context, cancellationToken).ConfigureAwait(false);
        };
    }


    /// <summary>
    /// Resolves <c>&lt;did&gt;/path/to/file</c>: locates the <c>#files</c> service, appends the DID URL path to its
    /// <c>serviceEndpoint</c> and retrieves the resource. A non-HTTP(S) scheme is an <c>invalidDid</c> and a resource that
    /// cannot be retrieved a <c>notFound</c>, per
    /// <see href="https://identity.foundation/didwebvh/v1.0/#did-url-path-resolution">did:webvh v1.0 DID URL Path
    /// Resolution</see>; a cancellation of the retrieval propagates (<see cref="TryFetchAsync"/>).
    /// </summary>
    /// <param name="document">The resolved and verified DID document carrying the <c>#files</c> service.</param>
    /// <param name="path">The DID URL path, with its leading <c>/</c>.</param>
    /// <param name="transport">The single-hop transport the guarded fetch drives.</param>
    /// <param name="context">The per-operation context carrying the SSRF outbound-fetch policy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The retrieved resource with its content type, or the dereferencing error.</returns>
    private static async ValueTask<DidDereferencingResult> DereferenceFilesAsync(
        DidDocument document,
        string path,
        OutboundTransportDelegate transport,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(FindServiceByFragment(document, WellKnownWebVhValues.FilesServiceFragment) is not { } files
            || ResolveHttpServiceEndpoint(files) is not { } endpoint)
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.NotFound);
        }

        string fileUrl = AppendPath(endpoint, path);
        if(!TryCreateSupportedUrl(fileUrl, out Uri? target))
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.InvalidDid);
        }

        OutboundFetchResult? fetch = await TryFetchAsync(target, transport, context, cancellationToken).ConfigureAwait(false);
        if(fetch is not { IsFetched: true, Response: { StatusCode: 200 } response })
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.NotFound);
        }

        //The resource is opaque (it may be any media type, including binary), so it is returned as the
        //transport-owned tagged buffer with the server's content type. It is not a DID document, so no
        //DID document metadata accompanies it.
        string? contentType = response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? value) ? value : null;

        return DidDereferencingResult.Success(
            response.Body, contentMetadata: null, contentType: contentType, freshness: HttpCacheFreshness.Compute(response));
    }


    /// <summary>
    /// Resolves <c>&lt;did&gt;/whois</c>: locates the <c>#whois</c> service, retrieves the <c>whois.vp</c>, verifies it
    /// is a VCDM Verifiable Presentation signed by the DID (a static linked presentation, so it has no challenge or
    /// domain) and confirms it contains at least one credential whose <c>credentialSubject.id</c> is the DID, per
    /// <see href="https://identity.foundation/didwebvh/v1.0/#whois-resolution">did:webvh v1.0 WHOIS Resolution</see>. A
    /// non-HTTP(S) scheme is an <c>invalidDid</c>, a file that cannot be retrieved a <c>notFound</c>, and a found but
    /// non-conforming presentation an <c>invalidDid</c>. A cancellation of the retrieval or of the parse propagates,
    /// bare or carried inside the parser's own exception (<see cref="WrappedCancellation"/>): a cancelled parse has
    /// shown nothing about the presentation.
    /// </summary>
    /// <param name="document">The resolved and verified DID document carrying the <c>#whois</c> service.</param>
    /// <param name="baseDid">The DID the presentation must be signed by and name as a credential subject.</param>
    /// <param name="transport">The single-hop transport the guarded fetch drives.</param>
    /// <param name="presentationDeserializer">Parses the fetched <c>whois.vp</c> into a presentation.</param>
    /// <param name="presentationCanonicalizer">The canonicalizer the presentation's proof is verified over.</param>
    /// <param name="proofValueDecoder">Decodes the proof value to signature bytes.</param>
    /// <param name="presentationSerializer">Serializes the proofless presentation for canonicalization.</param>
    /// <param name="proofOptionsSerializer">Serializes the proof options for canonicalization.</param>
    /// <param name="base58Decoder">The base58btc decoder for the proof value.</param>
    /// <param name="computeDigest">The digest function the cryptosuite hashes with.</param>
    /// <param name="pool">The pool the verification buffers are rented from.</param>
    /// <param name="knownContext">The deployment's known <c>@context</c> for the presentation.</param>
    /// <param name="context">The per-operation context carrying the SSRF outbound-fetch policy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The verified presentation, or the dereferencing error.</returns>
    private static async ValueTask<DidDereferencingResult> DereferenceWhoisAsync(
        DidDocument document,
        string baseDid,
        OutboundTransportDelegate transport,
        PresentationDeserializeDelegate presentationDeserializer,
        CanonicalizationDelegate presentationCanonicalizer,
        ProofValueDecoderDelegate proofValueDecoder,
        PresentationSerializeDelegate presentationSerializer,
        ProofOptionsSerializeDelegate proofOptionsSerializer,
        DecodeDelegate base58Decoder,
        ComputeDigestDelegate computeDigest,
        BaseMemoryPool pool,
        Context knownContext,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(FindServiceByFragment(document, WellKnownWebVhValues.WhoisServiceFragment) is not { } whois
            || ResolveHttpServiceEndpoint(whois) is not { } endpoint)
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.NotFound);
        }

        if(!TryCreateSupportedUrl(endpoint, out Uri? target))
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.InvalidDid);
        }

        OutboundFetchResult? fetch = await TryFetchAsync(target, transport, context, cancellationToken).ConfigureAwait(false);
        if(fetch is not { IsFetched: true, Response: { StatusCode: 200 } response })
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.NotFound);
        }

        DataIntegritySecuredPresentation? presentation;
        try
        {
            //The whois.vp is a full presentation graph parsed by the JSON layer; the converter yields a
            //DataIntegritySecuredPresentation when a proof is present. A presentation with no proof is not signed.
            presentation = presentationDeserializer(Encoding.UTF8.GetString(response.Body.Span)) as DataIntegritySecuredPresentation;
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch(Exception exception)
        {
            //presentationDeserializer is a caller-supplied delegate over untrusted fetched bytes; any failure
            //to parse them is an invalid DID from the dereferencer's perspective, cancellation excepted above. A
            //cancellation the parser carries inside its own exception propagates as that cancellation, as a bare
            //one does.
            WrappedCancellation.ThrowIfCarried(exception);

            return DidDereferencingResult.Failure(DidResolutionErrors.InvalidDid);
        }

        if(presentation is null)
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.InvalidDid);
        }

        //The whois.vp MUST be signed by the DID. It is a static linked presentation with no interactive
        //verifier, so it is verified without a challenge/domain binding — the verify is fail-closed against a
        //presentation that nonetheless carries one.
        CredentialVerificationResult<DataIntegritySecuredPresentation> verification = await presentation.VerifyLinkedPresentationAsync(
            document,
            presentationCanonicalizer,
            contextResolver: null,
            knownContext,
            proofValueDecoder,
            presentationSerializer,
            proofOptionsSerializer,
            base58Decoder,
            computeDigest,
            pool,
            context,
            cancellationToken).ConfigureAwait(false);

        if(!verification.IsValid)
        {
            //A whois.vp MAY reference a parallel did:web DID (in the resolved document's alsoKnownAs) rather than
            //the did:webvh DID. Since both DIDs share the same verification methods, the resolver MAY verify the
            //proof against the already-resolved did:webvh document by aliasing the proof's verification method id
            //onto the resolved document's matching-fragment authentication method (did:webvh v1.0, WHOIS
            //Resolution: "verify the proof with the already resolved DID"). This retry runs only when the proof
            //references an alsoKnownAs did:web DID, so a genuinely invalid proof still fails.
            if(BuildAlsoKnownAsAliasDocument(document, presentation) is not { } aliasDocument)
            {
                return DidDereferencingResult.Failure(DidResolutionErrors.InvalidDid);
            }

            CredentialVerificationResult<DataIntegritySecuredPresentation> retryVerification = await presentation.VerifyLinkedPresentationAsync(
                aliasDocument,
                presentationCanonicalizer,
                contextResolver: null,
                knownContext,
                proofValueDecoder,
                presentationSerializer,
                proofOptionsSerializer,
                base58Decoder,
                computeDigest,
                pool,
                context,
                cancellationToken).ConfigureAwait(false);

            if(!retryVerification.IsValid)
            {
                return DidDereferencingResult.Failure(DidResolutionErrors.InvalidDid);
            }
        }

        //The presentation MUST include at least one credential whose credentialSubject.id is the DID.
        if(!HasCredentialAboutDid(presentation, baseDid))
        {
            return DidDereferencingResult.Failure(DidResolutionErrors.InvalidDid);
        }

        return DidDereferencingResult.Success(
            presentation, contentMetadata: null, contentType: WellKnownWebVhValues.WhoisMediaType, freshness: HttpCacheFreshness.Compute(response));
    }


    /// <summary>
    /// Builds a synthetic holder document that aliases the whois proof's <c>verificationMethod</c> id onto the resolved
    /// document's matching-fragment authentication method, so a proof referencing a parallel did:web DID listed in the
    /// resolved document's <c>alsoKnownAs</c> verifies against the already-resolved did:webvh document.
    /// </summary>
    /// <param name="document">The resolved did:webvh document.</param>
    /// <param name="presentation">The whois presentation whose first proof names the verification method.</param>
    /// <returns>
    /// The alias document, or <see langword="null"/>, so the cross-verify is not attempted, unless the proof's
    /// verification method DID is a did:web DID in the resolved document's <c>alsoKnownAs</c> and the resolved document
    /// has an authentication method with the same fragment.
    /// </returns>
    private static DidDocument? BuildAlsoKnownAsAliasDocument(DidDocument document, DataIntegritySecuredPresentation presentation)
    {
        if(presentation.Proof is not { Count: > 0 } proofs || proofs[0].VerificationMethod?.Id is not { Length: > 0 } proofVerificationMethodId)
        {
            return null;
        }

        int fragmentIndex = proofVerificationMethodId.IndexOf('#', StringComparison.Ordinal);
        if(fragmentIndex <= 0)
        {
            return null;
        }

        string proofDid = proofVerificationMethodId[..fragmentIndex];
        string proofFragment = proofVerificationMethodId[(fragmentIndex + 1)..];

        //The proof must reference a did:web DID listed in the resolved document's alsoKnownAs; only then are the
        //two DIDs the established parallel pair the spec permits cross-verifying.
        if(!proofDid.StartsWith("did:web:", StringComparison.Ordinal)
            || document.AlsoKnownAs is not { } alsoKnownAs
            || Array.IndexOf(alsoKnownAs, proofDid) < 0)
        {
            return null;
        }

        VerificationMethod? matchingMethod = null;
        foreach(VerificationMethod method in document.GetLocalAuthenticationMethods())
        {
            if(method.Id is { Length: > 0 } methodId && FragmentOf(methodId) is { } fragment && string.Equals(fragment, proofFragment, StringComparison.Ordinal))
            {
                matchingMethod = method;

                break;
            }
        }

        if(matchingMethod is null || document.Id is not { } canonicalDid)
        {
            return null;
        }

        //The alias is an embedded authentication method carrying the resolved document's key material under the
        //proof's verificationMethod id, so the proof — signed over its own (did:web) verificationMethod id —
        //resolves to the same key. The signed bytes are unchanged; only the holder document used to look the key
        //up is the alias. The alias method's controller is the CANONICAL did:webvh identity (canonicalDid), not
        //the did:web alias DID (proofDid): alsoKnownAs establishes that the two DIDs name the SAME controlled
        //identity, and the whois presentation's own holder claims the canonical DID, so the resolved method's
        //controller must agree with that claim (controller-RESOLUTION semantics) for the cross-verify to bind.
        VerificationMethod aliasMethod = new()
        {
            Id = proofVerificationMethodId,
            Controller = canonicalDid.ToString(),
            Type = matchingMethod.Type,
            KeyFormat = matchingMethod.KeyFormat
        };

        return new DidDocument
        {
            Id = canonicalDid,
            Authentication = [new AuthenticationMethod(aliasMethod)]
        };
    }


    /// <summary>The fragment of a DID URL, the part after <c>#</c>.</summary>
    /// <param name="didUrl">The DID URL.</param>
    /// <returns>The fragment, or <see langword="null"/> when the DID URL has none.</returns>
    private static string? FragmentOf(string didUrl)
    {
        int fragmentIndex = didUrl.IndexOf('#', StringComparison.Ordinal);

        return fragmentIndex >= 0 ? didUrl[(fragmentIndex + 1)..] : null;
    }


    /// <summary>
    /// Whether the presentation contains at least one Verifiable Credential whose <c>credentialSubject.id</c> equals the
    /// DID. Additional credentials may describe other identifiers the controller binds the DID to.
    /// </summary>
    /// <param name="presentation">The whois presentation.</param>
    /// <param name="did">The DID a credential must name as its subject.</param>
    /// <returns><see langword="true"/> when a contained credential's subject is the DID.</returns>
    private static bool HasCredentialAboutDid(DataIntegritySecuredPresentation presentation, string did)
    {
        if(presentation.VerifiableCredential is not { } credentials)
        {
            return false;
        }

        foreach(VerifiableCredential credential in credentials)
        {
            if(credential.CredentialSubject is not { } subjects)
            {
                continue;
            }

            foreach(CredentialSubject subject in subjects)
            {
                if(string.Equals(subject.Id, did, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }


    /// <summary>
    /// The first service whose id ends with <paramref name="fragment"/>, an absolute <c>&lt;did&gt;#files</c> or a
    /// relative <c>#files</c> alike.
    /// </summary>
    /// <param name="document">The document whose services are searched.</param>
    /// <param name="fragment">The service fragment, with its <c>#</c>.</param>
    /// <returns>The service, or <see langword="null"/> when none is present.</returns>
    private static Service? FindServiceByFragment(DidDocument document, string fragment)
    {
        if(document.Service is not { } services)
        {
            return null;
        }

        foreach(Service service in services)
        {
            if(service.Id?.ToString().EndsWith(fragment, StringComparison.Ordinal) == true)
            {
                return service;
            }
        }

        return null;
    }


    /// <summary>
    /// The service's HTTP(S) endpoint URL. The implicit services use the single-string <c>serviceEndpoint</c> form, but
    /// an explicit override, which MUST take precedence, MAY express its endpoint as an array or as a map (the CID
    /// <c>serviceEndpointMap</c> form, for example a linked-vp endpoint with a <c>relativeRef</c>), so the first HTTP(S)
    /// string the chosen form yields is used and every endpoint shape an explicit override may use is honored.
    /// </summary>
    /// <param name="service">The service whose endpoint is read.</param>
    /// <returns>The endpoint URL, or <see langword="null"/> when no form yields an HTTP(S) URL.</returns>
    private static string? ResolveHttpServiceEndpoint(Service service)
    {
        if(service.ServiceEndpoint is { } endpoint)
        {
            return endpoint;
        }

        if(service.ServiceEndpointMap is { } map && ResolveHttpUrlFromMap(map) is { } mapUrl)
        {
            return mapUrl;
        }

        if(service.ServiceEndpoints is { } endpoints)
        {
            foreach(object candidate in endpoints)
            {
                if(candidate is string url && IsHttpUrl(url))
                {
                    return url;
                }

                if(candidate is IDictionary<string, object> mapCandidate && ResolveHttpUrlFromMap(mapCandidate) is { } memberUrl)
                {
                    return memberUrl;
                }
            }
        }

        return null;
    }


    /// <summary>
    /// The first HTTP(S) URL string value in a <c>serviceEndpoint</c> map. The map's value shapes are service-type
    /// specific (for example a <c>uri</c> member, or a linked-vp endpoint), so any string value that is an HTTP(S) URL is
    /// accepted as the endpoint location.
    /// </summary>
    /// <param name="map">The endpoint map.</param>
    /// <returns>The endpoint URL, or <see langword="null"/> when no value is an HTTP(S) URL.</returns>
    private static string? ResolveHttpUrlFromMap(IDictionary<string, object> map)
    {
        foreach(KeyValuePair<string, object> member in map)
        {
            if(member.Value is string url && IsHttpUrl(url))
            {
                return url;
            }
        }

        return null;
    }


    /// <summary>Whether <paramref name="value"/> starts with the <c>https://</c> or <c>http://</c> scheme, compared case-insensitively.</summary>
    /// <param name="value">The candidate endpoint string.</param>
    /// <returns><see langword="true"/> when the string names an HTTP(S) URL.</returns>
    private static bool IsHttpUrl(string value)
    {
        return value.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// Builds the resolution options for the base-DID resolve from the DID URL query and accept header. A
    /// <c>versionId</c>, <c>versionTime</c> or the did:webvh-specific <c>versionNumber</c> query parameter pins the
    /// version the path or whois is dereferenced against; an unparseable <c>versionTime</c> or <c>versionNumber</c> is
    /// ignored, so the latest version is used, rather than failing the dereference (did:webvh v1.0, Reading did:webvh
    /// DID URLs).
    /// </summary>
    /// <param name="query">The DID URL query without its leading <c>?</c>, or <see langword="null"/>.</param>
    /// <param name="accept">The dereferencing accept option, or <see langword="null"/>.</param>
    /// <returns>The resolution options.</returns>
    private static DidResolutionOptions BuildResolutionOptions(string? query, string? accept)
    {
        string? versionId = null;
        DateTimeOffset? versionTime = null;
        int? versionNumber = null;

        if(query is not null)
        {
            versionId = GetQueryParameter(query, WellKnownWebVhValues.VersionIdQueryParameter);

            if(GetQueryParameter(query, WellKnownWebVhValues.VersionTimeQueryParameter) is { } versionTimeRaw
                && DateTimeOffset.TryParse(versionTimeRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset parsed))
            {
                versionTime = parsed;
            }

            if(GetQueryParameter(query, WellKnownWebVhValues.VersionNumberQueryParameter) is { } versionNumberRaw
                && int.TryParse(versionNumberRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedNumber))
            {
                versionNumber = parsedNumber;
            }
        }

        if(versionId is null && versionTime is null && versionNumber is null && accept is null)
        {
            return DidResolutionOptions.Empty;
        }

        return new DidResolutionOptions
        {
            Accept = accept,
            VersionId = versionId,
            VersionTime = versionTime,
            VersionNumber = versionNumber
        };
    }


    /// <summary>Extracts the unescaped value of a named parameter from a raw query string without its leading <c>?</c>.</summary>
    /// <param name="query">The raw query string.</param>
    /// <param name="name">The parameter name.</param>
    /// <returns>The parameter's value, or <see langword="null"/> when the parameter is absent.</returns>
    private static string? GetQueryParameter(string query, string name)
    {
        string prefix = $"{name}=";
        foreach(string segment in query.Split('&'))
        {
            if(segment.StartsWith(prefix, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(segment[prefix.Length..]);
            }
        }

        return null;
    }


    /// <summary>
    /// Appends a DID URL path, which carries its own leading <c>/</c>, to a service endpoint, collapsing the boundary
    /// slash so the two never double up. The resolver has already removed the <c>did.jsonl</c> file and any
    /// <c>.well-known</c> segment from the <c>#files</c> endpoint, so nothing further is stripped here.
    /// </summary>
    /// <param name="endpoint">The service endpoint URL.</param>
    /// <param name="path">The DID URL path.</param>
    /// <returns>The resource URL.</returns>
    private static string AppendPath(string endpoint, string path)
    {
        return string.Concat(endpoint.TrimEnd('/'), "/", path.TrimStart('/'));
    }


    /// <summary>
    /// Parses an absolute URL and accepts only the HTTP(S) schemes did:webvh resolution supports; any other scheme, or
    /// a URL that does not parse, is rejected so the caller maps it to <c>invalidDid</c>.
    /// </summary>
    /// <param name="url">The URL text.</param>
    /// <param name="target">The parsed URL, when accepted.</param>
    /// <returns><see langword="true"/> when the URL is an absolute HTTP(S) URL.</returns>
    private static bool TryCreateSupportedUrl(string url, [NotNullWhen(true)] out Uri? target)
    {
        if(!Uri.TryCreate(url, UriKind.Absolute, out target))
        {
            return false;
        }

        return string.Equals(target.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || string.Equals(target.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// Drives the guarded outbound fetch of a DID URL's resource. A transport failure is no resource, which the caller
    /// maps to <c>notFound</c>; a cancellation is not a "not found" condition and always propagates, bare or carried
    /// inside the transport's own exception, as the inner exception of its own fault or among an aggregate's inner
    /// exceptions (<see cref="WrappedCancellation"/>), so the caller tells its own cancellation from a fetch that ended
    /// on its own budget.
    /// </summary>
    /// <param name="target">The resource URL.</param>
    /// <param name="transport">The single-hop transport the guarded fetch drives.</param>
    /// <param name="context">The per-operation context carrying the SSRF outbound-fetch policy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The fetch result, or <see langword="null"/> when the transport failed.</returns>
    private static async ValueTask<OutboundFetchResult?> TryFetchAsync(
        Uri target,
        OutboundTransportDelegate transport,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        OutboundRequest request = new() { Target = target, Method = "GET" };

        try
        {
            return await Verifiable.Core.Outbound.OutboundFetch.FetchAsync(request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch(Exception exception)
        {
            //A transport/network failure is a not-found from this helper's perspective, cancellation
            //excepted above. A cancellation the transport carries inside its own exception propagates as that
            //cancellation, as a bare one does.
            WrappedCancellation.ThrowIfCarried(exception);

            return null;
        }
    }
}
