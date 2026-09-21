using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Well-known member NAMES the VC Data Model 2.0 defines for a verifiable credential, a verifiable
/// presentation, and the <see cref="Issuer"/> object embedded in a credential's <c>issuer</c> member.
/// </summary>
/// <remarks>
/// <para>
/// These are the NAMES of JSON object members (e.g., <c>"credentialSubject"</c>, <c>"validFrom"</c>),
/// not their values. Every member the <c>Verifiable.Json</c> credential, presentation, and issuer
/// converters read or write by an inline literal is named here instead, so the three converters share
/// one spelling per member.
/// </para>
/// <para>
/// <see cref="Image"/> is the one exception: the VC Data Model 2.0 text names it only inside a
/// non-normative example of the <c>issuer</c> object (using an external, non-base context), never in a
/// <c>property</c> definition of its own — the <c>Verifiable.Json</c> issuer converter still round-trips it as part of
/// the issuer object's open-world shape, so its spelling is pinned here rather than left as a fourth
/// inline literal, but its doc comment cites the example rather than a defining sentence that does not
/// exist in this specification.
/// </para>
/// <para>
/// All names are defined in
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/">Verifiable Credentials Data Model v2.0</see>
/// unless stated otherwise on the member itself.
/// </para>
/// </remarks>
public static class WellKnownCredentialMemberNames
{
    /// <summary>The UTF-8 source literal of <see cref="Context"/>.</summary>
    public static ReadOnlySpan<byte> ContextUtf8 => "@context"u8;

    /// <summary>
    /// The <c>@context</c> member. "Verifiable credentials and verifiable presentations MUST include a
    /// <c>@context</c> property... The value of the <c>@context</c> property MUST be an ordered set
    /// where the first item is a URL with the value <c>https://www.w3.org/ns/credentials/v2</c>." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC-DM 2.0 §4.3 Contexts</see>.
    /// </summary>
    public static string Context { get; } = Utf8Constants.ToInternedString(ContextUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Id"/>.</summary>
    public static ReadOnlySpan<byte> IdUtf8 => "id"u8;

    /// <summary>
    /// The <c>id</c> member. "The <c>id</c> property is OPTIONAL. If present, <c>id</c> property's
    /// value MUST be a single URL, which MAY be dereferenceable." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#identifiers">VC-DM 2.0 §4.4 Identifiers</see>.
    /// </summary>
    public static string Id { get; } = Utf8Constants.ToInternedString(IdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Type"/>.</summary>
    public static ReadOnlySpan<byte> TypeUtf8 => "type"u8;

    /// <summary>
    /// The <c>type</c> member. "Verifiable credentials and verifiable presentations MUST contain a
    /// <c>type</c> property with an associated value... The value of the <c>type</c> property MUST be
    /// one or more terms and absolute URL strings." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#types">VC-DM 2.0 §4.5 Types</see>.
    /// </summary>
    public static string Type { get; } = Utf8Constants.ToInternedString(TypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Name"/>.</summary>
    public static ReadOnlySpan<byte> NameUtf8 => "name"u8;

    /// <summary>
    /// The <c>name</c> member. "An OPTIONAL property that expresses the name of the credential." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions">VC-DM 2.0 §4.6 Names
    /// and Descriptions</see>.
    /// </summary>
    public static string Name { get; } = Utf8Constants.ToInternedString(NameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Description"/>.</summary>
    public static ReadOnlySpan<byte> DescriptionUtf8 => "description"u8;

    /// <summary>
    /// The <c>description</c> member. "An OPTIONAL property that conveys specific details about a
    /// credential." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions">VC-DM 2.0 §4.6 Names
    /// and Descriptions</see>.
    /// </summary>
    public static string Description { get; } = Utf8Constants.ToInternedString(DescriptionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Issuer"/>.</summary>
    public static ReadOnlySpan<byte> IssuerUtf8 => "issuer"u8;

    /// <summary>
    /// The <c>issuer</c> member. "A verifiable credential MUST have an <c>issuer</c> property... The
    /// value of the <c>issuer</c> property MUST be either a URL or an object containing an <c>id</c>
    /// property whose value is a URL." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#issuer">VC-DM 2.0 §4.7 Issuer</see>.
    /// </summary>
    public static string Issuer { get; } = Utf8Constants.ToInternedString(IssuerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialSubject"/>.</summary>
    public static ReadOnlySpan<byte> CredentialSubjectUtf8 => "credentialSubject"u8;

    /// <summary>
    /// The <c>credentialSubject</c> member. "A verifiable credential MUST contain a
    /// <c>credentialSubject</c> property... The value of the <c>credentialSubject</c> property is a set
    /// of objects where each object MUST be the subject of one or more claims, which MUST be serialized
    /// inside the <c>credentialSubject</c> property." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#credential-subject">VC-DM 2.0 §4.8 Credential
    /// Subject</see>.
    /// </summary>
    public static string CredentialSubject { get; } = Utf8Constants.ToInternedString(CredentialSubjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidFrom"/>.</summary>
    public static ReadOnlySpan<byte> ValidFromUtf8 => "validFrom"u8;

    /// <summary>
    /// The <c>validFrom</c> member. "If present, the value of the <c>validFrom</c> property MUST be a
    /// [XMLSCHEMA11-2] <c>dateTimeStamp</c> string value representing the date and time the credential
    /// becomes valid, which could be a date and time in the future or the past." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#validity-period">VC-DM 2.0 §4.9 Validity
    /// Period</see>.
    /// </summary>
    public static string ValidFrom { get; } = Utf8Constants.ToInternedString(ValidFromUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidUntil"/>.</summary>
    public static ReadOnlySpan<byte> ValidUntilUtf8 => "validUntil"u8;

    /// <summary>
    /// The <c>validUntil</c> member. "If present, the value of the <c>validUntil</c> property MUST be a
    /// [XMLSCHEMA11-2] <c>dateTimeStamp</c> string value representing the date and time the credential
    /// ceases to be valid, which could be a date and time in the past or the future." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#validity-period">VC-DM 2.0 §4.9 Validity
    /// Period</see>.
    /// </summary>
    public static string ValidUntil { get; } = Utf8Constants.ToInternedString(ValidUntilUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialStatus"/>.</summary>
    public static ReadOnlySpan<byte> CredentialStatusUtf8 => "credentialStatus"u8;

    /// <summary>
    /// The <c>credentialStatus</c> member. "This specification defines the <c>credentialStatus</c>
    /// property for discovering information related to the status of a verifiable credential, such as
    /// whether it is suspended or revoked." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#status">VC-DM 2.0 §4.10 Status</see>.
    /// </summary>
    public static string CredentialStatus { get; } = Utf8Constants.ToInternedString(CredentialStatusUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialSchema"/>.</summary>
    public static ReadOnlySpan<byte> CredentialSchemaUtf8 => "credentialSchema"u8;

    /// <summary>
    /// The <c>credentialSchema</c> member. "The value of the <c>credentialSchema</c> property MUST be
    /// one or more data schemas that provide verifiers with enough information to determine whether the
    /// provided data conforms to the provided schema(s). Each <c>credentialSchema</c> MUST specify its
    /// <c>type</c>." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#data-schemas">VC-DM 2.0 §4.11 Data
    /// Schemas</see>.
    /// </summary>
    public static string CredentialSchema { get; } = Utf8Constants.ToInternedString(CredentialSchemaUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Proof"/>.</summary>
    public static ReadOnlySpan<byte> ProofUtf8 => "proof"u8;

    /// <summary>
    /// The <c>proof</c> member. An embedded proof "secures the original credential by decorating the
    /// original data with a digital signature via the <c>proof</c> property" per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#securing-mechanisms">VC-DM 2.0 §4.12 Securing
    /// Mechanisms</see>.
    /// </summary>
    public static string Proof { get; } = Utf8Constants.ToInternedString(ProofUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RelatedResource"/>.</summary>
    public static ReadOnlySpan<byte> RelatedResourceUtf8 => "relatedResource"u8;

    /// <summary>
    /// The <c>relatedResource</c> member. "To extend integrity protection to a related resource, an
    /// issuer of a verifiable credential MAY include the <c>relatedResource</c> property... The value of
    /// the <c>relatedResource</c> property MUST be one or more objects." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#integrity-of-related-resources">VC-DM 2.0
    /// §5.3 Integrity of Related Resources</see>.
    /// </summary>
    public static string RelatedResource { get; } = Utf8Constants.ToInternedString(RelatedResourceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RefreshService"/>.</summary>
    public static ReadOnlySpan<byte> RefreshServiceUtf8 => "refreshService"u8;

    /// <summary>
    /// The <c>refreshService</c> member. "The value of the <c>refreshService</c> property MUST be one
    /// or more refresh services that provides enough information to the recipient's software such that
    /// the recipient can refresh the verifiable credential." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#refreshing">VC-DM 2.0 §5.4 Refreshing</see>.
    /// </summary>
    public static string RefreshService { get; } = Utf8Constants.ToInternedString(RefreshServiceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TermsOfUse"/>.</summary>
    public static ReadOnlySpan<byte> TermsOfUseUtf8 => "termsOfUse"u8;

    /// <summary>
    /// The <c>termsOfUse</c> member. "The value of the <c>termsOfUse</c> property MUST specify one or
    /// more terms of use policies under which the creator issued the credential or presentation." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#terms-of-use">VC-DM 2.0 §5.5 Terms of
    /// Use</see>.
    /// </summary>
    public static string TermsOfUse { get; } = Utf8Constants.ToInternedString(TermsOfUseUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Evidence"/>.</summary>
    public static ReadOnlySpan<byte> EvidenceUtf8 => "evidence"u8;

    /// <summary>
    /// The <c>evidence</c> member. "If present, the value of the <c>evidence</c> property MUST be
    /// either a single object or a set of one or more objects." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#evidence">VC-DM 2.0 §5.6 Evidence</see>.
    /// </summary>
    public static string Evidence { get; } = Utf8Constants.ToInternedString(EvidenceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Holder"/>.</summary>
    public static ReadOnlySpan<byte> HolderUtf8 => "holder"u8;

    /// <summary>
    /// The <c>holder</c> member. "The verifiable presentation MAY include a <c>holder</c> property. If
    /// present, the value MUST be either a URL or an object containing an <c>id</c> property." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations">VC-DM 2.0 §4.13
    /// Verifiable Presentations</see>.
    /// </summary>
    public static string Holder { get; } = Utf8Constants.ToInternedString(HolderUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VerifiableCredential"/>.</summary>
    public static ReadOnlySpan<byte> VerifiableCredentialUtf8 => "verifiableCredential"u8;

    /// <summary>
    /// The <c>verifiableCredential</c> member. "The <c>verifiableCredential</c> property MAY be present.
    /// The value MUST be one or more verifiable credential and/or enveloped verifiable credential
    /// objects (the values MUST NOT be non-object values such as numbers, strings, or URLs)." per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations">VC-DM 2.0 §4.13
    /// Verifiable Presentations</see>.
    /// </summary>
    public static string VerifiableCredential { get; } = Utf8Constants.ToInternedString(VerifiableCredentialUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Image"/>.</summary>
    public static ReadOnlySpan<byte> ImageUtf8 => "image"u8;

    /// <summary>
    /// The <c>image</c> member of an <see cref="Issuer"/> object. Named only inside a non-normative
    /// example — <c>"issuer": { "id": "did:web:credentials.utopia.example", "image": "data:image/png;..." }</c>
    /// — using an external context, never in a <c>property</c> definition of its own, per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#zero-knowledge-proofs">VC-DM 2.0 §5.7
    /// Zero-Knowledge Proofs</see> (the example the issuer object's <c>image</c> spelling comes from).
    /// </summary>
    public static string Image { get; } = Utf8Constants.ToInternedString(ImageUtf8);
}
