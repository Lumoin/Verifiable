using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;
using Verifiable.Core.OutboundFetch;

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

        //Split on colons: colons in the DID method-specific ID are path separators, while %3A is the
        //percent-encoded literal colon of a port. Each segment is decoded INDEPENDENTLY and ONLY for the
        //port colon — a %2F inside a segment is NOT turned into a path separator (the URL-confusion
        //mitigation the did:web spec requires). The first segment is the host[:port]; the rest is the path.
        string[] parts = didWebIdentifier[prefixWithColon.Length..].Split(PathSeparator);

        string host = DecodePortColon(parts[0]);

        //did:web forbids an IP-address host (it MUST be a domain name): reject an IPv4/IPv6 literal at the
        //method layer rather than relying on a downstream SSRF policy that only blocks private/loopback ranges.
        if(IsIpAddressHost(host))
        {
            throw new ArgumentException(
                $"The did:web host '{host}' is an IP address; did:web requires a domain name.",
                nameof(didWebIdentifier));
        }

        var builder = new System.Text.StringBuilder("https://");
        builder.Append(host);

        bool hasPath = parts.Length > 1;
        for(int i = 1; i < parts.Length; i++)
        {
            //A segment that encodes its own '/' would forge an extra path segment after decode, so it is
            //rejected rather than silently split.
            string segment = parts[i];
            if(ContainsEncodedSlash(segment))
            {
                throw new ArgumentException(
                    $"The did:web path segment '{segment}' contains an encoded path separator.",
                    nameof(didWebIdentifier));
            }

            builder.Append('/');
            builder.Append(Uri.UnescapeDataString(segment));
        }

        if(!hasPath)
        {
            builder.Append("/.well-known");
        }

        builder.Append("/did.json");

        return builder.ToString();
    }


    //Decodes only the percent-encoded port colon (%3A) in the host segment, leaving every other character
    //as-is so no other percent-encoded delimiter can be smuggled in.
    private static string DecodePortColon(string hostSegment)
    {
        return hostSegment
            .Replace("%3A", ":", StringComparison.OrdinalIgnoreCase);
    }


    //A segment contains an encoded path separator when it carries %2F (the percent-encoded '/').
    private static bool ContainsEncodedSlash(string segment)
    {
        return segment.Contains("%2F", StringComparison.OrdinalIgnoreCase);
    }


    //Determines whether a host[:port] string is an IP-address literal (IPv4 dotted-quad or a bracketed/raw
    //IPv6 literal) rather than a domain name. The whole host is percent-decoded for this check so a literal
    //smuggled in encoded form (for example a bracketed IPv6 with percent-encoded brackets) is still caught.
    private static bool IsIpAddressHost(string host)
    {
        string candidate = Uri.UnescapeDataString(host);

        if(candidate.StartsWith('['))
        {
            //A bracketed IPv6 literal: the address is between the brackets, anything after ']' is a port.
            int close = candidate.IndexOf(']', StringComparison.Ordinal);
            candidate = close > 0 ? candidate[1..close] : candidate.Trim('[', ']');
        }
        else
        {
            //An unbracketed host with a single ':' is host:port (IPv4 or domain); two or more colons is a raw
            //IPv6 literal. Strip a single trailing port; leave a multi-colon IPv6 candidate intact.
            int firstColon = candidate.IndexOf(':', StringComparison.Ordinal);
            if(firstColon >= 0)
            {
                int lastColon = candidate.LastIndexOf(':');
                if(firstColon == lastColon)
                {
                    candidate = candidate[..firstColon];
                }
            }
        }

        return IPAddress.TryParse(candidate, out _);
    }

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
    /// <c>did.json</c> through the guarded <see cref="OutboundFetch"/> chokepoint (SSRF policy off the
    /// <see cref="ExchangeContext"/>), and parses it with the supplied <paramref name="documentDeserializer"/>.
    /// Use this when the resolver should return the document directly; use <see cref="ResolveAsync"/> when
    /// the caller fetches the URL itself.
    /// </summary>
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

            OutboundRequest request = new() { Target = target, Method = "GET" };

            OutboundFetchResult fetch;
            try
            {
                //Fully qualified: within Verifiable.Core.* the bare name binds to the OutboundFetch
                //namespace, not the static class of the same leaf name.
                fetch = await Verifiable.Core.OutboundFetch.OutboundFetch.FetchAsync(request, context, transport, cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //A transport/network failure is a not-found from the resolver's perspective.
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            if(!fetch.IsFetched || fetch.Response is null || fetch.Response.StatusCode != 200)
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
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDidDocument);
            }

            if(document is null)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDidDocument);
            }

            //The fetched document MUST declare the requested DID as its subject; a document served at the
            //did:web location but claiming a different id is rejected.
            if(!string.Equals(document.Id?.ToString(), did, StringComparison.Ordinal))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDidDocument);
            }

            //Key-confusion mitigation: every embedded id (verification methods, relationships, services) and
            //controller in the resolved document MUST resolve under the requested DID. A verification method
            //whose id points at a DIFFERENT DID would let the served document bind another subject's keys.
            if(!EmbeddedIdentifiersResolveUnderDid(document, did))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDidDocument);
            }

            //did:web §Key Material and Document Handling: @context is OPTIONAL. When present the document is a
            //JSON-LD representation (did:did+ld+json) processed per DID Core §6.3.2; when absent it is processed
            //via the plain-JSON rules of DID Core §6.2.2 and carries the did+json media type. A missing @context
            //is therefore not a malformed document — the representation, and thus the reported contentType, is
            //conditional on its presence.
            string contentType = HasContext(document) ? ContentTypeDidLdJson : ContentTypeDidJson;

            return DidResolutionResult.Success(document, DidDocumentMetadata.Empty, contentType: contentType);
        };
    }


    //The DID Core §6.3 media type for the JSON-LD representation of a DID document (an @context is present).
    private const string ContentTypeDidLdJson = "application/did+ld+json";

    //The DID Core §6.2 media type for the plain-JSON representation of a DID document (no @context).
    private const string ContentTypeDidJson = "application/did+json";


    //Reports whether the document carries any @context at its root. Presence alone selects the JSON-LD
    //representation; the did:web spec does not require the DID v1 context to be first (only, when present, that
    //it be contained), so this is a presence check rather than a first-element constraint.
    private static bool HasContext(DidDocument document)
    {
        System.Collections.Generic.List<object>? contexts = document.Context?.Contexts;

        return contexts is not null && contexts.Count > 0;
    }


    //Returns true when every embedded id and controller in the resolved document resolves under the requested
    //DID: an id is acceptable when it is the DID itself, a DID-relative reference (begins with '#' or '?'), or
    //an absolute id under the DID (begins with "<did>#" or "<did>?" or equals the DID). Any id that names a
    //different DID is rejected.
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


    //Checks each verification relationship: an embedded verification method MUST resolve under the DID, and a
    //reference MUST resolve under the DID. A referenced (non-embedded) id may point at another controller's
    //DID for cross-controller delegation, so only embedded methods are constrained here; the spec's key-
    //confusion concern is about embedded key material, which is what binds keys to this subject.
    private static bool EmbeddedRelationshipsResolveUnderDid(DidDocument document, string did)
    {
        return RelationshipOk(document.Authentication, did)
            && RelationshipOk(document.AssertionMethod, did)
            && RelationshipOk(document.KeyAgreement, did)
            && RelationshipOk(document.CapabilityInvocation, did)
            && RelationshipOk(document.CapabilityDelegation, did);
    }


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


    private static bool ControllerResolvesUnderDid(string? controller, string did)
    {
        //A controller MAY be absent (the subject is the controller) or MUST equal the DID for an embedded
        //method served at the DID's own location.
        return string.IsNullOrEmpty(controller) || string.Equals(controller, did, StringComparison.Ordinal);
    }


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
