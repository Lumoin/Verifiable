namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// Well-known did:webvh string values: the published web file names, the well-known URI segment, and the
/// implicit DID-URL service id fragments fixed by the did:webvh v1.0 specification.
/// </summary>
/// <remarks>
/// Centralizing these keeps the DID-to-HTTPS transform, the witness and whois locations, and the implicit
/// service ids consistent across the resolver, dereferencer and tests.
/// </remarks>
public static class WellKnownWebVhValues
{
    /// <summary>The DID Log file name served at the DID's web location: <c>did.jsonl</c>.</summary>
    public static string DidLogFile { get; } = "did.jsonl";

    /// <summary>The witness proofs file name, alongside the DID Log: <c>did-witness.json</c>.</summary>
    public static string DidWitnessFile { get; } = "did-witness.json";

    /// <summary>The whois Verifiable Presentation file name: <c>whois.vp</c>.</summary>
    public static string WhoisFile { get; } = "whois.vp";

    /// <summary>The special DID-URL path segment that dereferences the whois presentation: <c>whois</c>.</summary>
    public static string WhoisPathSegment { get; } = "whois";

    /// <summary>The IANA media type the whois presentation is served and returned with: <c>application/vp</c>.</summary>
    public static string WhoisMediaType { get; } = "application/vp";

    /// <summary>The media type the <c>did-witness.json</c> file SHOULD be served with: <c>application/json</c>.</summary>
    public static string WitnessFileMediaType { get; } = "application/json";

    /// <summary>The RFC 8615 well-known URI segment used for a bare-domain DID's location: <c>.well-known</c>.</summary>
    public static string WellKnownSegment { get; } = ".well-known";

    /// <summary>The implicit DID-URL path (relativeRef) service id fragment: <c>#files</c>.</summary>
    public static string FilesServiceFragment { get; } = "#files";

    /// <summary>The implicit whois LinkedVerifiablePresentation service id fragment: <c>#whois</c>.</summary>
    public static string WhoisServiceFragment { get; } = "#whois";

    /// <summary>The DID-URL query parameter selecting a specific version by id: <c>versionId</c>.</summary>
    public static string VersionIdQueryParameter { get; } = "versionId";

    /// <summary>The DID-URL query parameter selecting the version active at a time: <c>versionTime</c>.</summary>
    public static string VersionTimeQueryParameter { get; } = "versionTime";

    /// <summary>The did:webvh-specific DID-URL query parameter selecting a version by integer number: <c>versionNumber</c>.</summary>
    public static string VersionNumberQueryParameter { get; } = "versionNumber";
}
