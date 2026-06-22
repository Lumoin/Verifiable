namespace Verifiable.Core.Model.Did;

/// <summary>
/// Well-known DID document <see cref="Service.Type"/> values from the DID specification registries and
/// related specifications.
/// </summary>
/// <remarks>
/// Service type strings identify how a <see cref="Service"/> entry's <c>serviceEndpoint</c> is to be used.
/// Centralizing them here keeps the values consistent wherever a service is produced or matched (for example
/// the did:webvh implicit <c>#files</c> and <c>#whois</c> services, or OID4VP linked presentations).
/// </remarks>
public static class WellKnownServiceTypes
{
    /// <summary>
    /// The <c>relativeRef</c> service type: the service endpoint is a base URL against which a DID URL path
    /// (the <c>relativeRef</c> parameter) is resolved (DID Core, DID URL dereferencing).
    /// </summary>
    public static string RelativeRef { get; } = "relativeRef";

    /// <summary>
    /// The <c>LinkedVerifiablePresentation</c> service type: the service endpoint locates a Verifiable
    /// Presentation linked to the DID (the Linked Verifiable Presentation specification).
    /// </summary>
    public static string LinkedVerifiablePresentation { get; } = "LinkedVerifiablePresentation";

    /// <summary>
    /// The JSON-LD <c>@context</c> a <see cref="LinkedVerifiablePresentation"/> service entry carries, binding
    /// the type's semantics (the Linked Verifiable Presentation specification context).
    /// </summary>
    public static string LinkedVerifiablePresentationContext { get; } = "https://identity.foundation/linked-vp/contexts/v1";
}
