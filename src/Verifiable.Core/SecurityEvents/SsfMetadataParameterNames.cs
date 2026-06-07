namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The member NAMES of the Transmitter Configuration Metadata document a Shared
/// Signals Transmitter publishes at <c>/.well-known/ssf-configuration</c>, per
/// OpenID Shared Signals Framework 1.0 §7.1.
/// </summary>
/// <remarks>
/// These are NAMES (JSON keys), not values. A Transmitter that also serves the
/// legacy RISC discovery path publishes the same document at
/// <c>/.well-known/risc-configuration</c> (SSF §7.2.2 backward compatibility).
/// </remarks>
public static class SsfMetadataParameterNames
{
    /// <summary>
    /// <c>spec_version</c> — OPTIONAL version of the implemented spec. Absent implies
    /// <c>1_0-ID1</c>; the final 1.0 spec is <c>1_0</c>.
    /// </summary>
    public static readonly string SpecVersion = "spec_version";

    /// <summary><c>issuer</c> — REQUIRED https Issuer Identifier; equals the SET <c>iss</c>.</summary>
    public static readonly string Issuer = "issuer";

    /// <summary><c>jwks_uri</c> — URL of the Transmitter's JWK Set (REQUIRED to issue signed SETs).</summary>
    public static readonly string JwksUri = "jwks_uri";

    /// <summary><c>delivery_methods_supported</c> — RECOMMENDED list of supported delivery-method URIs.</summary>
    public static readonly string DeliveryMethodsSupported = "delivery_methods_supported";

    /// <summary><c>configuration_endpoint</c> — OPTIONAL Stream Configuration endpoint URL.</summary>
    public static readonly string ConfigurationEndpoint = "configuration_endpoint";

    /// <summary><c>status_endpoint</c> — OPTIONAL Stream Status endpoint URL.</summary>
    public static readonly string StatusEndpoint = "status_endpoint";

    /// <summary><c>add_subject_endpoint</c> — OPTIONAL Add Subject endpoint URL.</summary>
    public static readonly string AddSubjectEndpoint = "add_subject_endpoint";

    /// <summary><c>remove_subject_endpoint</c> — OPTIONAL Remove Subject endpoint URL.</summary>
    public static readonly string RemoveSubjectEndpoint = "remove_subject_endpoint";

    /// <summary><c>verification_endpoint</c> — OPTIONAL Verification endpoint URL.</summary>
    public static readonly string VerificationEndpoint = "verification_endpoint";

    /// <summary>
    /// <c>critical_subject_members</c> — OPTIONAL array of Complex Subject member names a
    /// Receiver MUST interpret if present.
    /// </summary>
    public static readonly string CriticalSubjectMembers = "critical_subject_members";

    /// <summary>
    /// <c>authorization_schemes</c> — OPTIONAL array of objects describing the supported
    /// authorization schemes for the stream-management APIs (each carries <see cref="SpecUrn"/>).
    /// </summary>
    public static readonly string AuthorizationSchemes = "authorization_schemes";

    /// <summary>
    /// <c>spec_urn</c> — REQUIRED member of an <see cref="AuthorizationSchemes"/> entry; a URN
    /// naming the authorization protocol (for example <c>urn:ietf:rfc:6749</c>).
    /// </summary>
    public static readonly string SpecUrn = "spec_urn";

    /// <summary>
    /// <c>default_subjects</c> — OPTIONAL default new-stream behavior; one of
    /// <see cref="DefaultSubjectsAll"/> or <see cref="DefaultSubjectsNone"/>.
    /// </summary>
    public static readonly string DefaultSubjects = "default_subjects";


    /// <summary>The <c>default_subjects</c> value <c>ALL</c> — new streams include all appropriate subjects.</summary>
    public static readonly string DefaultSubjectsAll = "ALL";

    /// <summary>The <c>default_subjects</c> value <c>NONE</c> — new streams include no subjects by default.</summary>
    public static readonly string DefaultSubjectsNone = "NONE";
}
