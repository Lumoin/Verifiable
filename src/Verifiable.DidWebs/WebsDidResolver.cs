using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cesr;
using Verifiable.Core.Did.Methods.Web;

namespace Verifiable.DidWebs;

/// <summary>
/// Resolves <c>did:webs</c> identifiers per the
/// <see href="https://trustoverip.github.io/kswg-did-method-webs-specification/">did:webs Method Specification</see>.
/// </summary>
/// <remarks>
/// <para>
/// A <c>did:webs</c> identifier is a <c>did:web</c>-style host and optional path whose FINAL path component is a
/// KERI <see href="https://datatracker.ietf.org/doc/draft-ssmith-said/">SAID</see> AID (the
/// <see href="https://trustoverip.github.io/kswg-did-method-webs-specification/#method-specific-identifier">
/// method-specific identifier</see>: <c>host [%3Aport] *(":" path) ":" aid</c>). Because the AID is always
/// present a <c>did:webs</c> always has a path, so the <c>.well-known</c> no-path form of <c>did:web</c> is not used.
/// </para>
/// <list type="bullet">
///   <item><description><c>did:webs:example.com:EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR</c> → <c>https://example.com/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/did.json</c></description></item>
///   <item><description><c>did:webs:example.com:user:alice:EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR</c> → <c>https://example.com/user/alice/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/did.json</c></description></item>
///   <item><description><c>did:webs:example.com%3A3000:user:alice:EKTh…GR</c> → <c>https://example.com:3000/user/alice/EKTh…GR/did.json</c></description></item>
/// </list>
/// <para>
/// <see cref="Resolve"/> and <see cref="ResolveKeriEventStreamUrl"/> compute the two artifact URLs only (the
/// DID-to-HTTPS transform). Full resolution — fetching both the <c>did.json</c> and the <c>keri.cesr</c> KERI
/// event stream, replaying and verifying the stream by the KERI rules, deriving the DID document from the
/// resulting key state, and checking it against the served document — is layered on top in later steps. As with
/// <c>did:webplus</c> no URL-only resolver delegate is exposed: a <c>did:webs</c> is only resolved once its KERI
/// event stream has been verified, so a resolver that returned a document URL without that verification would be
/// unsound.
/// </para>
/// </remarks>
public static class WebsDidResolver
{
    /// <summary>
    /// Computes the <c>did.json</c> DID document URL for a <c>did:webs</c> identifier by applying the shared
    /// did:web-family DID-to-HTTPS transform (<see cref="WebHttpsTransform.MapToUrl"/>) with the did:webs policy:
    /// replace <c>did:webs:</c> with <c>https://</c>, map the colon-delimited segments to path separators,
    /// convert a <c>%3A</c>-encoded port to a colon, and append <c>/did.json</c>. The trailing method-specific
    /// identifier segment MUST be a well-formed KERI SAID AID.
    /// </summary>
    /// <param name="didWebsIdentifier">A valid <c>did:webs</c> identifier string.</param>
    /// <returns>The HTTPS URL where the <c>did.json</c> DID document is published.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="didWebsIdentifier"/> is <see langword="null"/>, empty, whitespace, does not
    /// start with the <c>did:webs:</c> prefix, does not end with a well-formed KERI SAID AID, has an IP-literal
    /// host, has no path segment, or has an unsafe path segment.
    /// </exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "DID identifiers contain method-specific syntax that System.Uri does not handle correctly.")]
    public static string Resolve(string didWebsIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didWebsIdentifier);

        string prefixWithColon = $"{WellKnownWebsValues.WebsDidMethodPrefix}:";
        if(!didWebsIdentifier.StartsWith(prefixWithColon, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The given DID identifier '{didWebsIdentifier}' is not a valid did:webs identifier.",
                nameof(didWebsIdentifier));
        }

        string methodSpecificId = didWebsIdentifier[prefixWithColon.Length..];

        //The AID is always the final colon-segment and MUST be a KERI SAID (a %3A-encoded port stays within the
        //host segment, so a plain colon split isolates the AID). A trailing segment that is not a well-formed
        //SAID is not a did:webs identifier — this is enforced before the transform so the failure names the AID
        //rather than a downstream path condition. The transform's own MinimumPathSegments guard then rejects an
        //AID that has no host in front of it.
        string aid = methodSpecificId[(methodSpecificId.LastIndexOf(':') + 1)..];
        if(!CesrSaid.IsWellFormedSaid(aid))
        {
            throw new ArgumentException(
                $"The did:webs identifier '{didWebsIdentifier}' does not end with a KERI SAID AID.",
                nameof(didWebsIdentifier));
        }

        return WebHttpsTransform.MapToUrl(methodSpecificId, didWebsIdentifier, TransformPolicy);
    }


    /// <summary>
    /// Computes the <c>keri.cesr</c> KERI event stream URL for a <c>did:webs</c> identifier, per the
    /// <see href="https://trustoverip.github.io/kswg-did-method-webs-specification/#target-systems">
    /// did:webs Target System(s)</see> rule: it is the <see cref="Resolve"/> DID document URL with its trailing
    /// <c>/did.json</c> replaced by <c>/keri.cesr</c>. The stream served there MUST be CESR-formatted, carry the
    /// <c>application/cesr</c> media type (<see cref="WellKnownWebsValues.KeyEventStreamMediaType"/>), and be
    /// verifiable by the KERI rules.
    /// </summary>
    /// <param name="didWebsIdentifier">A valid <c>did:webs</c> identifier string.</param>
    /// <returns>The HTTPS URL where the DID's <c>keri.cesr</c> KERI event stream is published.</returns>
    /// <exception cref="ArgumentException">Thrown for the same conditions as <see cref="Resolve"/>.</exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "DID identifiers contain method-specific syntax that System.Uri does not handle correctly.")]
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings", Justification = "DID document URLs contain method-specific syntax that System.Uri does not handle correctly; the DID method surface uses string URLs consistently.")]
    public static string ResolveKeriEventStreamUrl(string didWebsIdentifier)
    {
        string didDocumentUrl = Resolve(didWebsIdentifier);

        //Resolve guarantees the URL ends with the did.json file name, so replacing that trailing file name (the
        //separating slash is retained) yields the keri.cesr URL the spec's transform prescribes.
        return string.Concat(
            didDocumentUrl.AsSpan(0, didDocumentUrl.Length - WellKnownWebsValues.DidDocumentFile.Length),
            WellKnownWebsValues.KeyEventStreamFile);
    }


    /// <summary>
    /// The did:webs DID-to-HTTPS policy: no leading segment precedes the host, the host is not IDNA-encoded, the
    /// scheme is always <c>https</c> (did:webs is a security upgrade over did:web), no <c>/.well-known</c> segment
    /// is inserted (the required AID means a did:webs always has a path), the identifier MUST carry at least the
    /// trailing AID path segment, each path segment is used as-is (identical to did:web), and the document file is
    /// <c>did.json</c>.
    /// </summary>
    private static WebHttpsTransformPolicy TransformPolicy { get; } = new()
    {
        LeadingSegmentsToDrop = 0,
        IdnaEncodeHost = false,
        LocalhostUsesHttp = false,
        WellKnownWhenNoPath = false,
        MinimumPathSegments = 1,
        SegmentMapping = WebHttpsSegmentMapping.Preserve,
        DocumentFileName = WellKnownWebsValues.DidDocumentFile
    };
}
