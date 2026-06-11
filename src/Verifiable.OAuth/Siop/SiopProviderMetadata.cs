using System.Diagnostics;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// The Self-Issued OpenID Provider Discovery Metadata a Self-Issued OP (wallet)
/// advertises so an RP can discover its capabilities, per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-6.1">SIOPv2 §6.1</see>
/// (Dynamic Discovery of Self-Issued OpenID Provider Metadata). The static-configuration
/// counterparts the RP uses when it cannot perform Dynamic Discovery are
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-15.1">SIOPv2 §15.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// When OpenID.Discovery is used the RP obtains this document from the path formed by
/// concatenating <c>/.well-known/openid-configuration</c> to the Self-Issued OP's Issuer
/// Identifier (§6.1). The defining invariant of a Self-Issued OP is that it has NO fixed
/// key set: §6.1 states "contrary to [OpenID.Discovery], <c>jwks_uri</c> parameter MUST NOT
/// be present in Self-Issued OP Metadata. If it is, the RP MUST ignore it and use the
/// <c>sub</c> Claim in the ID Token to obtain signing keys". The signing key travels in the
/// ID Token's <c>sub_jwk</c> claim (§11) or is resolved from the <c>sub</c> DID, so this type
/// deliberately cannot express a <c>jwks_uri</c> member.
/// </para>
/// <para>
/// Serialize through <see cref="SiopProviderMetadataWriter"/>; the model is transport- and
/// serialization-agnostic. The static §15.1 documents are exposed via
/// <see cref="StaticSiopv2"/> and <see cref="StaticOpenId"/>; a Dynamic Discovery document is
/// composed via <see cref="Create"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("SiopProviderMetadata AuthorizationEndpoint={AuthorizationEndpoint,nq}")]
public sealed record SiopProviderMetadata
{
    /// <summary>
    /// §6.1 <c>authorization_endpoint</c> (REQUIRED): "URL of the Self-Issued OP used by the
    /// RP to perform Authentication of the End-User. Can be custom URL scheme, or Universal
    /// Links/App links. See Section 6.2." (§6.1).
    /// </summary>
    public required string AuthorizationEndpoint { get; init; }

    /// <summary>
    /// §6.1 <c>issuer</c>: "URL using the https scheme with no query or fragment component
    /// that the Self-Issued OP asserts as its Issuer Identifier. MUST be identical to the
    /// <c>iss</c> Claim value in ID Tokens issued from this Self-Issued OP." REQUIRED for
    /// Dynamic Discovery (§6.1); the §15.1 static-configuration sets omit it, so it is
    /// <see langword="null"/> there.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// §6.1 <c>response_types_supported</c> (REQUIRED): "A JSON array of strings representing
    /// supported response types. MUST include <c>id_token</c>." (§6.1).
    /// </summary>
    public required IReadOnlyList<string> ResponseTypesSupported { get; init; }

    /// <summary>
    /// §6.1 <c>scopes_supported</c> (REQUIRED): "A JSON array of strings representing
    /// supported scopes. MUST support the <c>openid</c> scope value." (§6.1).
    /// </summary>
    public required IReadOnlyList<string> ScopesSupported { get; init; }

    /// <summary>
    /// §6.1 <c>subject_types_supported</c> (REQUIRED): "A JSON array of strings representing
    /// supported subject types. Valid values include <c>pairwise</c> and <c>public</c>."
    /// (§6.1).
    /// </summary>
    public required IReadOnlyList<string> SubjectTypesSupported { get; init; }

    /// <summary>
    /// §6.1 <c>id_token_signing_alg_values_supported</c> (REQUIRED): "A JSON array containing
    /// a list of the JWS signing algorithms (<c>alg</c> values) supported by the OP for the
    /// ID Token to encode the Claims in a JWT [RFC7519]. Valid values include <c>RS256</c>,
    /// <c>ES256</c>, <c>ES256K</c>, and <c>EdDSA</c>." (§6.1).
    /// </summary>
    public required IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; }

    /// <summary>
    /// §6.1 <c>request_object_signing_alg_values_supported</c> (REQUIRED): "A JSON array
    /// containing a list of the JWS signing algorithms (<c>alg</c> values) supported by the
    /// OP for Request Objects, which are described in Section 6.1 of [OpenID.Core]. Valid
    /// values include <c>none</c>, <c>RS256</c>, <c>ES256</c>, <c>ES256K</c>, and
    /// <c>EdDSA</c>." (§6.1).
    /// </summary>
    public required IReadOnlyList<string> RequestObjectSigningAlgValuesSupported { get; init; }

    /// <summary>
    /// §6.1 <c>subject_syntax_types_supported</c> (REQUIRED): "A JSON array of strings
    /// representing URI scheme identifiers and optionally method names of supported Subject
    /// Syntax Types defined in Section 8. When Subject Syntax Type is JWK Thumbprint, a valid
    /// value is <c>urn:ietf:params:oauth:jwk-thumbprint</c> defined in [RFC9278]. When Subject
    /// Syntax Type is Decentralized Identifier, valid values MUST be a <c>did:</c> prefix
    /// followed by a supported DID method without a <c>:</c> suffix." (§6.1). Values per
    /// <see cref="SiopSubjectSyntaxTypes"/>.
    /// </summary>
    public required IReadOnlyList<string> SubjectSyntaxTypesSupported { get; init; }

    /// <summary>
    /// §6.1 <c>id_token_types_supported</c> (OPTIONAL): "A JSON array of strings containing
    /// the list of ID Token types supported by the OP, the default value is
    /// <c>attester_signed_id_token</c>." (§6.1). Values per <see cref="SiopIdTokenTypes"/>.
    /// <see langword="null"/> omits the member, in which case the §6.1 default applies.
    /// </summary>
    public IReadOnlyList<string>? IdTokenTypesSupported { get; init; }

    /// <summary>
    /// §6.1 <c>vp_formats_supported</c> object, already serialized as a raw JSON value, or
    /// <see langword="null"/> to omit it. SIOPv2 §6.1 lists this member only in the
    /// §15.1.3 <c>openid://</c> static-configuration set; the §6.1 Dynamic Discovery member
    /// list does not require it. When supporting Verifiable Presentations (§12), the OP
    /// advertises the credential formats and algorithms it supports here.
    /// </summary>
    public string? VpFormatsSupportedJson { get; init; }


    /// <summary>
    /// Composes a Dynamic Discovery (§6.1) Self-Issued OP metadata document. The members
    /// SIOPv2 §6.1 mandates as MUST-include defaults are filled in unless the caller passes a
    /// non-empty override: <c>response_types_supported</c> includes <c>id_token</c>,
    /// <c>scopes_supported</c> includes <c>openid</c>. The signing-algorithm and
    /// subject-syntax-type lists carry the OP's own supported values.
    /// </summary>
    /// <param name="authorizationEndpoint">
    /// The §6.1 <c>authorization_endpoint</c> — a claimed URL (Universal Link / App Link,
    /// RECOMMENDED per §6.2) or a custom URL scheme.
    /// </param>
    /// <param name="issuer">
    /// The §6.1 <c>issuer</c> Identifier; an https URL with no query or fragment that equals
    /// the <c>iss</c> claim of issued ID Tokens.
    /// </param>
    /// <param name="idTokenSigningAlgValuesSupported">
    /// The §6.1 <c>id_token_signing_alg_values_supported</c> the OP supports for the
    /// Self-Issued ID Token.
    /// </param>
    /// <param name="requestObjectSigningAlgValuesSupported">
    /// The §6.1 <c>request_object_signing_alg_values_supported</c> the OP supports for Request
    /// Objects.
    /// </param>
    /// <param name="subjectSyntaxTypesSupported">
    /// The §6.1 <c>subject_syntax_types_supported</c> the OP supports; values per
    /// <see cref="SiopSubjectSyntaxTypes"/>.
    /// </param>
    /// <param name="subjectTypesSupported">
    /// The §6.1 <c>subject_types_supported</c>; defaults to <c>["public"]</c> when omitted.
    /// </param>
    /// <param name="idTokenTypesSupported">
    /// The §6.1 <c>id_token_types_supported</c>, or <see langword="null"/> to omit it.
    /// </param>
    /// <returns>The composed Dynamic Discovery metadata document.</returns>
    public static SiopProviderMetadata Create(
        string authorizationEndpoint,
        string issuer,
        IReadOnlyList<string> idTokenSigningAlgValuesSupported,
        IReadOnlyList<string> requestObjectSigningAlgValuesSupported,
        IReadOnlyList<string> subjectSyntaxTypesSupported,
        IReadOnlyList<string>? subjectTypesSupported = null,
        IReadOnlyList<string>? idTokenTypesSupported = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(authorizationEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentNullException.ThrowIfNull(idTokenSigningAlgValuesSupported);
        ArgumentNullException.ThrowIfNull(requestObjectSigningAlgValuesSupported);
        ArgumentNullException.ThrowIfNull(subjectSyntaxTypesSupported);

        return new SiopProviderMetadata
        {
            AuthorizationEndpoint = authorizationEndpoint,
            Issuer = issuer,

            //§6.1: response_types_supported MUST include id_token; scopes_supported MUST
            //support the openid scope value.
            ResponseTypesSupported = [SiopAuthorizationRequestParameterValues.ResponseTypeIdToken],
            ScopesSupported = [WellKnownScopes.OpenId],
            SubjectTypesSupported = subjectTypesSupported ?? [SubjectTypePublic],
            IdTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported,
            RequestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported,
            SubjectSyntaxTypesSupported = subjectSyntaxTypesSupported,
            IdTokenTypesSupported = idTokenTypesSupported
        };
    }


    /// <summary>
    /// The §15.1.2 set of static configuration values bound to the <c>siopv2://</c> custom
    /// URL scheme: "a set of static configuration values that can be used with
    /// <c>id_token</c> as a supported <c>response_type</c>, bound to a custom URL scheme
    /// <c>siopv2://</c> as an <c>authorization_endpoint</c>" (§15.1.2). The RP uses this when
    /// it cannot perform Dynamic Discovery and is not using a profile (§15.1).
    /// </summary>
    /// <remarks>
    /// Per §15.1.2 the <c>authorization_endpoint</c> is the bare <c>siopv2:</c> scheme, there
    /// is no <c>issuer</c> member, and every algorithm/subject-syntax list carries exactly the
    /// single value the table specifies.
    /// </remarks>
    public static SiopProviderMetadata StaticSiopv2 { get; } = new()
    {
        AuthorizationEndpoint = StaticSiopv2Scheme,
        Issuer = null,
        ResponseTypesSupported = [SiopAuthorizationRequestParameterValues.ResponseTypeIdToken],
        ScopesSupported = [WellKnownScopes.OpenId],
        SubjectTypesSupported = [SubjectTypePairwise],
        IdTokenSigningAlgValuesSupported = [SigningAlgEs256],
        RequestObjectSigningAlgValuesSupported = [SigningAlgEs256],
        SubjectSyntaxTypesSupported = [SiopSubjectSyntaxTypes.JwkThumbprint],
        IdTokenTypesSupported = [SiopIdTokenTypes.SubjectSignedIdToken]
    };


    /// <summary>
    /// The §15.1.3 set of static configuration values bound to the <c>openid://</c> custom
    /// URL scheme: "used with both <c>vp_token</c> and <c>id_token</c> as supported
    /// <c>response_type</c>, bound to a custom URL scheme <c>openid://</c> as an
    /// <c>authorization_endpoint</c>" (§15.1.3). It additionally carries a
    /// <c>vp_formats_supported</c> object advertising <c>jwt_vp</c> / <c>jwt_vc</c> with
    /// <c>ES256</c>.
    /// </summary>
    public static SiopProviderMetadata StaticOpenId { get; } = new()
    {
        AuthorizationEndpoint = StaticOpenIdScheme,
        Issuer = null,
        ResponseTypesSupported =
        [
            Oid4Vp.Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken,
            SiopAuthorizationRequestParameterValues.ResponseTypeIdToken
        ],
        VpFormatsSupportedJson = StaticOpenIdVpFormatsJson,
        ScopesSupported = [WellKnownScopes.OpenId],
        SubjectTypesSupported = [SubjectTypePairwise],
        IdTokenSigningAlgValuesSupported = [SigningAlgEs256],
        RequestObjectSigningAlgValuesSupported = [SigningAlgEs256],
        SubjectSyntaxTypesSupported = [SiopSubjectSyntaxTypes.JwkThumbprint],
        IdTokenTypesSupported = [SiopIdTokenTypes.SubjectSignedIdToken]
    };


    //§15.1.2: "authorization_endpoint": "siopv2:". The static set binds to the siopv2://
    //custom URL scheme; the metadata value the table lists is the bare scheme.
    private const string StaticSiopv2Scheme = "siopv2:";

    //§15.1.3: "authorization_endpoint": "openid:".
    private const string StaticOpenIdScheme = "openid:";

    //§6.1 subject_types_supported valid value used by the §15.1 static sets.
    private const string SubjectTypePairwise = "pairwise";

    //§6.1 subject_types_supported valid value; the Create default when the caller omits it.
    private const string SubjectTypePublic = "public";

    //The single id_token/request_object signing alg the §15.1 static sets list.
    private const string SigningAlgEs256 = "ES256";

    //§15.1.3 vp_formats_supported object, verbatim from the table:
    //{ "jwt_vp": { "alg": ["ES256"] }, "jwt_vc": { "alg": ["ES256"] } }.
    private const string StaticOpenIdVpFormatsJson =
        "{\"jwt_vp\":{\"alg\":[\"ES256\"]},\"jwt_vc\":{\"alg\":[\"ES256\"]}}";
}
