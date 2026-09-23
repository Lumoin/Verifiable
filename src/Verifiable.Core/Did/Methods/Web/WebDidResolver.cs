using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Outbound;
using Verifiable.Core.Resolvers;

namespace Verifiable.Core.Did.Methods.Web;

/// <summary>
/// Deserializes a fetched <c>did:web</c> <c>did.json</c> (UTF-8 JSON bytes) into a
/// <see cref="DidDocument"/>. Supplied by the JSON layer so <see cref="Verifiable.Core"/> takes no
/// serializer dependency; returns <see langword="null"/> on malformed input rather than throwing.
/// </summary>
/// <param name="didDocumentJsonUtf8">The fetched document as UTF-8 JSON bytes.</param>
/// <returns>The parsed document, or <see langword="null"/> when the bytes are not a valid DID document.</returns>
public delegate DidDocument? WebDidDocumentDeserializer(ReadOnlySpan<byte> didDocumentJsonUtf8);

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

        return WebHttpsTransform.MapToUrl(didWebIdentifier[prefixWithColon.Length..], didWebIdentifier, TransformPolicy);
    }


    /// <summary>
    /// The did:web DID-to-HTTPS policy: no leading segment precedes the host, the host is not IDNA-encoded, a
    /// <c>/.well-known</c> segment is inserted when the identifier declares no path, each path segment is used
    /// as-is (the method-specific id is already in URL path form; did:web "Read"), and the document file is
    /// <c>did.json</c>.
    /// </summary>
    private static WebHttpsTransformPolicy TransformPolicy { get; } = new()
    {
        LeadingSegmentsToDrop = 0,
        IdnaEncodeHost = false,
        LocalhostUsesHttp = false,
        WellKnownWhenNoPath = true,
        MinimumPathSegments = 0,
        SegmentMapping = WebHttpsSegmentMapping.Preserve,
        DocumentFileName = "did.json"
    };


    /// <summary>
    /// Resolves a <c>did:web</c> identifier and returns a <see cref="DidResolutionResult"/>
    /// with <see cref="DidResolutionKind.DocumentUrl"/> carrying the computed HTTPS URL.
    /// Matches <see cref="DidMethodResolverDelegate"/> for direct registration as a method group.
    /// </summary>
    /// <param name="did">A valid <c>did:web</c> identifier string.</param>
    /// <param name="options">Resolution options (not used by this method).</param>
    /// <param name="context">
    /// The per-operation context (not used by this method — it returns the URL for the
    /// caller to fetch through the guarded outbound path rather than fetching itself).
    /// </param>
    /// <param name="cancellationToken">Cancellation token (not used by this method).</param>
    /// <returns>
    /// A <see cref="DidResolutionResult"/> with <see cref="DidResolutionKind.DocumentUrl"/>
    /// containing the computed HTTPS URL. The caller is responsible for fetching the document.
    /// </returns>
    public static ValueTask<DidResolutionResult> ResolveAsync(
        string did,
        DidResolutionOptions options,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(DidResolutionResult.SuccessUrl(Resolve(did)));
    }

    /// <summary>
    /// Builds a <see cref="DidMethodResolverDelegate"/> that fully resolves a <c>did:web</c> to a
    /// <see cref="DidResolutionKind.Document"/> result: it computes the HTTPS URL, fetches the
    /// <c>did.json</c> through the guarded <see cref="Outbound"/> chokepoint (SSRF policy off the
    /// <see cref="ExchangeContext"/>), and parses it with the supplied <paramref name="documentDeserializer"/>.
    /// Use this when the resolver should return the document directly; use <see cref="ResolveAsync"/> when
    /// the caller fetches the URL itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The fetch and the parse are boundaries over dependencies that throw. A transport failure is a
    /// <see cref="DidResolutionErrors.NotFound"/>; <paramref name="documentDeserializer"/> is a caller-supplied
    /// delegate over untrusted fetched bytes, so any exception it raises is a document that could not be read,
    /// refused with <see cref="InvalidDidDocumentReason.Malformed"/>. A cancellation propagates from both, and so does
    /// one the transport carries inside an exception of its own
    /// (<see cref="Verifiable.Core.Model.DataIntegrity.WrappedCancellation"/>), so the caller can
    /// tell its own cancellation from a fetch that ended on its own budget.
    /// </para>
    /// <para>
    /// The fetch is bounded by <see cref="OutboundFetchPolicy.DefaultMaxResponseBytes"/>: the request carries it as
    /// <see cref="OutboundRequest.MaxResponseBytes"/> for a transport that stops reading once a response exceeds it,
    /// and a response body over it is not parsed at all but reported as not retrieved, like a transport that
    /// abandoned the read, so a hostile or misconfigured host cannot make resolution buffer or parse an unbounded
    /// document.
    /// </para>
    /// <para>
    /// A readable document is checked for conformance before its <c>id</c> is compared with the requested DID,
    /// the order of <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3</see>
    /// steps 5 and 6. Conformance is judged against the document's own <c>id</c>: a document without one is refused
    /// with <see cref="InvalidDidDocumentReason.MissingRequiredProperty"/>, and a document embedding an identifier
    /// that does not resolve under its own <c>id</c> with <see cref="InvalidDidDocumentReason.EmbeddedIdentifierOutsideDid"/>.
    /// Only then is that <c>id</c> compared with the requested DID, so a conforming document for another subject is
    /// refused with <see cref="InvalidDidDocumentReason.IdMismatch"/>, step 6's "If controllerDocument.id does not
    /// match the controllerDocumentUrl".
    /// </para>
    /// </remarks>
    /// <param name="transport">
    /// The application-supplied single-hop transport the guarded fetch drives. <see cref="Verifiable.Core"/>
    /// takes no <c>System.Net.Http</c> dependency, so the network primitive is injected.
    /// </param>
    /// <param name="documentDeserializer">Parses the fetched <c>did.json</c> bytes into a <see cref="DidDocument"/>.</param>
    /// <returns>A <see cref="DidMethodResolverDelegate"/> for registration with <see cref="DidMethodSelectors.FromResolvers"/>.</returns>
    public static DidMethodResolverDelegate BuildResolving(
        OutboundTransportDelegate transport,
        WebDidDocumentDeserializer documentDeserializer)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(documentDeserializer);

        return async (did, options, context, cancellationToken) =>
        {
            string documentUrl;
            try
            {
                documentUrl = Resolve(did);
            }
            catch(ArgumentException)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            if(!Uri.TryCreate(documentUrl, UriKind.Absolute, out Uri? target))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            OutboundRequest request = new() { Target = target, Method = "GET", MaxResponseBytes = OutboundFetchPolicy.DefaultMaxResponseBytes };

            OutboundFetchResult fetch;
            try
            {
                //Fully qualified: within Verifiable.Core.* the bare name binds to the OutboundFetch
                //namespace, not the static class of the same leaf name.
                fetch = await Verifiable.Core.Outbound.OutboundFetch.FetchAsync(request, context, transport, cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch(Exception exception)
            {
                //A transport/network failure is a not-found from the resolver's perspective. A cancellation the
                //transport carries inside its own exception propagates as that cancellation, as a bare one does.
                Verifiable.Core.Model.DataIntegrity.WrappedCancellation.ThrowIfCarried(exception);

                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            if(!fetch.IsFetched || fetch.Response is null || fetch.Response.StatusCode != 200)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            //The authoritative size check: MaxResponseBytes on the request is a hint a transport may not honour, so a
            //body over the bound is refused here, before the deserializer ever reads it.
            if(fetch.Response.Body.Memory.Length > OutboundFetchPolicy.DefaultMaxResponseBytes)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            DidDocument? document;
            try
            {
                document = documentDeserializer(fetch.Response.Body.Span);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //documentDeserializer is a caller-supplied delegate over untrusted fetched bytes; any failure
                //to parse them (malformed JSON, an unexpected shape) is an invalid document from the
                //resolver's perspective, cancellation excepted above.
                return InvalidDocument(InvalidDidDocumentReason.Malformed);
            }

            if(document is null)
            {
                return InvalidDocument(InvalidDidDocumentReason.Malformed);
            }

            //Conformance checks run BEFORE the id comparison, per CID 1.0 §3.3 step 5 versus step 6, and they judge
            //the document against its OWN id: a non-conforming document is refused at step 5 whatever id it names,
            //and only a document that IS conforming reaches the step 6 comparison with the requested DID below. A
            //document with no id at all lacks the property every conforming document carries.
            if(document.Id is null)
            {
                return InvalidDocument(InvalidDidDocumentReason.MissingRequiredProperty);
            }

            //Key-confusion mitigation: every embedded id (verification methods, relationships, services) and
            //controller in the resolved document MUST resolve under the document's own id. A verification method
            //whose id points at a DIFFERENT DID would let the served document bind another subject's keys.
            string documentId = document.Id.ToString();
            if(!EmbeddedIdentifiersResolveUnderDid(document, documentId))
            {
                return InvalidDocument(InvalidDidDocumentReason.EmbeddedIdentifierOutsideDid);
            }

            //Step 6: the fetched document MUST declare the requested DID as its subject; a conforming document
            //served at the did:web location but claiming a different id is rejected as an id mismatch.
            if(!string.Equals(documentId, did, StringComparison.Ordinal))
            {
                return InvalidDocument(InvalidDidDocumentReason.IdMismatch);
            }

            //did:web §Key Material and Document Handling: @context is OPTIONAL. When present the document is a
            //JSON-LD representation (did:did+ld+json) processed per DID Core §6.3.2; when absent it is processed
            //via the plain-JSON rules of DID Core §6.2.2 and carries the did+json media type. A missing @context
            //is therefore not a malformed document — the representation, and thus the reported contentType, is
            //conditional on its presence.
            string contentType = HasContext(document) ? ContentTypeDidLdJson : ContentTypeDidJson;

            return DidResolutionResult.Success(
                document,
                DidDocumentMetadata.Empty,
                contentType: contentType,
                freshness: HttpCacheFreshness.Compute(fetch.Response));
        };
    }


    /// <summary>
    /// Builds the <see cref="DidErrorTypes.InvalidDidDocument"/> failure for a retrieved <c>did.json</c> that
    /// <see cref="BuildResolving"/> refuses, stating <paramref name="reason"/> as
    /// <see cref="DidResolutionResult.InvalidDocumentReason"/> so a caller running
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3</see> can tell a
    /// document whose id names another subject from a document that does not conform.
    /// </summary>
    /// <param name="reason">Why the retrieved document was refused.</param>
    /// <returns>A failed result with no document and empty document metadata.</returns>
    private static DidResolutionResult InvalidDocument(InvalidDidDocumentReason reason) => new()
    {
        ResolutionMetadata = new DidResolutionMetadata { Error = DidResolutionErrors.InvalidDidDocument },
        DocumentMetadata = DidDocumentMetadata.Empty,
        InvalidDocumentReason = reason
    };


    /// <summary>The DID Core §6.3 media type of the JSON-LD representation of a DID document, reported when an <c>@context</c> is present.</summary>
    private const string ContentTypeDidLdJson = "application/did+ld+json";

    /// <summary>The DID Core §6.2 media type of the plain-JSON representation of a DID document, reported when no <c>@context</c> is present.</summary>
    private const string ContentTypeDidJson = "application/did+json";


    /// <summary>
    /// Reports whether the document carries any <c>@context</c> at its root. Presence alone selects the JSON-LD
    /// representation; the did:web specification does not require the DID v1 context to be first (only, when
    /// present, that it be contained), so this is a presence check rather than a first-element constraint.
    /// </summary>
    private static bool HasContext(DidDocument document)
    {
        return document.Context?.Entries is { Count: > 0 };
    }


    /// <summary>
    /// Returns <see langword="true"/> when every embedded id and controller in the resolved document resolves under
    /// <paramref name="did"/>, the document's own <c>id</c>: an id is acceptable when it is that DID itself, a
    /// DID-relative reference (beginning with <c>#</c> or <c>?</c>), or an absolute id under the DID (beginning with
    /// <c>{did}#</c> or <c>{did}?</c>). Any id that names a different DID fails the check, which
    /// <see cref="BuildResolving"/> reports as <see cref="InvalidDidDocumentReason.EmbeddedIdentifierOutsideDid"/>;
    /// whether that own id is the requested DID is the separate, later step 6 comparison.
    /// </summary>
    /// <param name="document">The resolved document whose embedded identifiers are checked.</param>
    /// <param name="did">The document's own <c>id</c>, the DID every embedded identifier must resolve under.</param>
    private static bool EmbeddedIdentifiersResolveUnderDid(DidDocument document, string did)
    {
        if(document.VerificationMethod is not null)
        {
            foreach(VerificationMethod method in document.VerificationMethod)
            {
                if(!IdentifierResolvesUnderDid(method.Id, did) || !ControllerResolvesUnderDid(method.Controller, did))
                {
                    return false;
                }
            }
        }

        if(document.Service is not null)
        {
            foreach(Service service in document.Service)
            {
                if(!IdentifierResolvesUnderDid(service.Id?.ToString(), did))
                {
                    return false;
                }
            }
        }

        return EmbeddedRelationshipsResolveUnderDid(document, did);
    }


    /// <summary>
    /// Checks each verification relationship through <see cref="RelationshipOk"/>. A referenced (non-embedded) id
    /// may point at another controller's DID for cross-controller delegation, so only embedded verification methods
    /// are constrained; the key-confusion concern is about embedded key material, which is what binds keys to this
    /// subject.
    /// </summary>
    private static bool EmbeddedRelationshipsResolveUnderDid(DidDocument document, string did)
    {
        return RelationshipOk(document.Authentication, did)
            && RelationshipOk(document.AssertionMethod, did)
            && RelationshipOk(document.KeyAgreement, did)
            && RelationshipOk(document.CapabilityInvocation, did)
            && RelationshipOk(document.CapabilityDelegation, did);
    }


    /// <summary>
    /// Returns <see langword="true"/> when every embedded verification method in <paramref name="relationships"/>
    /// has an id and controller under <paramref name="did"/>; references are left to the caller's own resolution.
    /// </summary>
    private static bool RelationshipOk(VerificationMethodReference[]? relationships, string did)
    {
        if(relationships is null)
        {
            return true;
        }

        foreach(VerificationMethodReference reference in relationships)
        {
            if(reference.IsEmbeddedVerification)
            {
                VerificationMethod? embedded = reference.EmbeddedVerification;
                if(embedded is null
                    || !IdentifierResolvesUnderDid(embedded.Id, did)
                    || !ControllerResolvesUnderDid(embedded.Controller, did))
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>
    /// Returns <see langword="true"/> when an embedded method's controller is absent (the subject is the
    /// controller) or equals <paramref name="did"/>, the document's own <c>id</c>, as an embedded method of that
    /// document requires.
    /// </summary>
    private static bool ControllerResolvesUnderDid(string? controller, string did)
    {
        return string.IsNullOrEmpty(controller) || string.Equals(controller, did, StringComparison.Ordinal);
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="id"/> is absent, a DID-relative reference,
    /// <paramref name="did"/> itself, or an absolute DID URL under it.
    /// </summary>
    private static bool IdentifierResolvesUnderDid(string? id, string did)
    {
        if(string.IsNullOrEmpty(id))
        {
            //An id is required on a verification method, but an absent id is a separate malformed-document
            //concern; the absoluteness check treats it as not-confusing here.
            return true;
        }

        //A DID-relative reference resolves against the requested DID by definition.
        if(id[0] is '#' or '?')
        {
            return true;
        }

        return string.Equals(id, did, StringComparison.Ordinal)
            || id.StartsWith($"{did}#", StringComparison.Ordinal)
            || id.StartsWith($"{did}?", StringComparison.Ordinal);
    }
}
