namespace Verifiable.DidWebs;

/// <summary>
/// Well-known did:webs string values: the two file names a target system MUST serve at a did:webs
/// AID's web location, and the media type the KERI event stream file is served with, per the
/// <see href="https://trustoverip.github.io/kswg-did-method-webs-specification/#target-systems">
/// did:webs Method Specification, Target System(s)</see>.
/// </summary>
/// <remarks>
/// A did:webs identifier resolves to a DID document at a URL ending in <c>did.json</c> and to a KERI
/// event stream at the same URL with the trailing <c>did.json</c> replaced by <c>keri.cesr</c>; the KERI
/// event stream MUST be CESR-formatted and served with the <c>application/cesr</c> media type.
/// Centralizing these keeps the DID-to-HTTPS transform and the KERI event stream fetch consistent
/// across the resolver, the KERI event stream verifier and the tests.
/// </remarks>
public static class WellKnownWebsValues
{
    /// <summary>
    /// The prefix a did:webs DID MUST begin with, per the
    /// <see href="https://trustoverip.github.io/kswg-did-method-webs-specification/#method-name">
    /// did:webs Method Specification, Method Name</see>: <c>did:webs</c> (lower case). The method name is
    /// <c>webs</c> — "web" plus the letter "s" for the security upgrade KERI verifiability adds over did:web.
    /// </summary>
    /// <remarks>
    /// A standalone-assembly DID method keeps its prefix in its own assembly rather than in
    /// <c>Verifiable.Core</c>'s <c>WellKnownDidMethodPrefixes</c> (the same placement the Sidetree method uses),
    /// so Core carries no dependency on a method it does not itself implement.
    /// </remarks>
    public static string WebsDidMethodPrefix { get; } = "did:webs";

    /// <summary>
    /// The DID document file name served at the DID's web location, per the
    /// <see href="https://trustoverip.github.io/kswg-did-method-webs-specification/#target-systems">
    /// did:webs Method Specification, Target System(s)</see>: <c>did.json</c>.
    /// </summary>
    public static string DidDocumentFile { get; } = "did.json";

    /// <summary>
    /// The KERI event stream file name served alongside the DID document, per the
    /// <see href="https://trustoverip.github.io/kswg-did-method-webs-specification/#target-systems">
    /// did:webs Method Specification, Target System(s)</see>: <c>keri.cesr</c>.
    /// </summary>
    public static string KeyEventStreamFile { get; } = "keri.cesr";

    /// <summary>
    /// The media type the KERI event stream file MUST be served with, per the
    /// <see href="https://trustoverip.github.io/kswg-did-method-webs-specification/#target-systems">
    /// did:webs Method Specification, Target System(s)</see>: <c>application/cesr</c>.
    /// </summary>
    public static string KeyEventStreamMediaType { get; } = "application/cesr";
}
