using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Text;

namespace Verifiable.JCose
{
    /// <summary>
    /// Well-known media types for Verifiable Credentials and related specifications.
    /// Follows the structure of <see cref="System.Net.Mime.MediaTypeNames"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class provides both full MIME types (for HTTP Content-Type headers) and
    /// JWT <c>typ</c> header short forms as defined in the specifications.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-jose-cose/">Securing Verifiable Credentials using JOSE and COSE</see>.
    /// </para>
    /// </remarks>
    public static class WellKnownMediaTypes
    {
        /// <summary>
        /// Media types in the <c>application</c> top-level type.
        /// </summary>
        [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
        public static class Application
        {
            /// <summary>The UTF-8 source literal of <see cref="Vc"/>.</summary>
            public static ReadOnlySpan<byte> VcUtf8 => "vc"u8;

            /// <summary>
            /// Verifiable Credential content type for use in JOSE <c>cty</c> and COSE content type (3) headers.
            /// </summary>
            /// <remarks>
            /// <para>
            /// Per the W3C VC-JOSE-COSE specification, the <c>cty</c> header parameter SHOULD be <c>vc</c>.
            /// Per RFC 7515 §4.1.10, values without a <c>/</c> are interpreted as <c>application/[value]</c>.
            /// </para>
            /// <para>
            /// See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-jose">VC-JOSE-COSE §3.1</see>.
            /// </para>
            /// </remarks>
            public static readonly string Vc = Utf8Constants.ToInternedString(VcUtf8);

            /// <summary>The UTF-8 source literal of <see cref="Vp"/>.</summary>
            public static ReadOnlySpan<byte> VpUtf8 => "vp"u8;

            /// <summary>
            /// Verifiable Presentation content type for use in JOSE <c>cty</c> and COSE content type (3) headers.
            /// </summary>
            /// <remarks>
            /// <para>
            /// Per the W3C VC-JOSE-COSE specification, the <c>cty</c> header parameter SHOULD be <c>vp</c>.
            /// Per RFC 7515 §4.1.10, values without a <c>/</c> are interpreted as <c>application/[value]</c>.
            /// </para>
            /// <para>
            /// See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-jose">VC-JOSE-COSE §3.2</see>.
            /// </para>
            /// </remarks>
            public static readonly string Vp = Utf8Constants.ToInternedString(VpUtf8);

            /// <summary>The UTF-8 source literal of <see cref="ApplicationVc"/>.</summary>
            public static ReadOnlySpan<byte> ApplicationVcUtf8 => "application/vc"u8;

            /// <summary>
            /// Full media type for an unsecured Verifiable Credential (<c>application/vc</c>).
            /// </summary>
            /// <remarks>
            /// <para>
            /// Used as the COSE content type (3) header parameter value, which unlike JOSE <c>cty</c>
            /// requires the full media type string rather than a short form.
            /// </para>
            /// <para>
            /// See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-cose">VC-JOSE-COSE §4.1</see>.
            /// </para>
            /// </remarks>
            public static readonly string ApplicationVc = Utf8Constants.ToInternedString(ApplicationVcUtf8);

            /// <summary>The UTF-8 source literal of <see cref="ApplicationVp"/>.</summary>
            public static ReadOnlySpan<byte> ApplicationVpUtf8 => "application/vp"u8;

            /// <summary>
            /// Full media type for an unsecured Verifiable Presentation (<c>application/vp</c>).
            /// </summary>
            /// <remarks>
            /// <para>
            /// Used as the COSE content type (3) header parameter value, which unlike JOSE <c>cty</c>
            /// requires the full media type string rather than a short form.
            /// </para>
            /// <para>
            /// See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-cose">VC-JOSE-COSE §4.2</see>.
            /// </para>
            /// </remarks>
            public static readonly string ApplicationVp = Utf8Constants.ToInternedString(ApplicationVpUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VcLdJwt"/>.</summary>
            public static ReadOnlySpan<byte> VcLdJwtUtf8 => "application/vc+ld+jwt"u8;

            /// <summary>
            /// Verifiable Credential secured as a JWT with JSON-LD.
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-jose">VC-JOSE-COSE §3.1</see>.</remarks>
            public static readonly string VcLdJwt = Utf8Constants.ToInternedString(VcLdJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VpLdJwt"/>.</summary>
            public static ReadOnlySpan<byte> VpLdJwtUtf8 => "application/vp+ld+jwt"u8;

            /// <summary>
            /// Verifiable Presentation secured as a JWT with JSON-LD.
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-jose">VC-JOSE-COSE §3.2</see>.</remarks>
            public static readonly string VpLdJwt = Utf8Constants.ToInternedString(VpLdJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VcJwt"/>.</summary>
            public static ReadOnlySpan<byte> VcJwtUtf8 => "application/vc+jwt"u8;

            /// <summary>
            /// Verifiable Credential secured as a JWT (non-JSON-LD).
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-jose">VC-JOSE-COSE §3.1</see>.</remarks>
            public static readonly string VcJwt = Utf8Constants.ToInternedString(VcJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VpJwt"/>.</summary>
            public static ReadOnlySpan<byte> VpJwtUtf8 => "application/vp+jwt"u8;

            /// <summary>
            /// Verifiable Presentation secured as a JWT (non-JSON-LD).
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-jose">VC-JOSE-COSE §3.2</see>.</remarks>
            public static readonly string VpJwt = Utf8Constants.ToInternedString(VpJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VcLdCose"/>.</summary>
            public static ReadOnlySpan<byte> VcLdCoseUtf8 => "application/vc+ld+cose"u8;

            /// <summary>
            /// Verifiable Credential secured using COSE with JSON-LD.
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-cose">VC-JOSE-COSE §4.1</see>.</remarks>
            public static readonly string VcLdCose = Utf8Constants.ToInternedString(VcLdCoseUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VpLdCose"/>.</summary>
            public static ReadOnlySpan<byte> VpLdCoseUtf8 => "application/vp+ld+cose"u8;

            /// <summary>
            /// Verifiable Presentation secured using COSE with JSON-LD.
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-cose">VC-JOSE-COSE §4.2</see>.</remarks>
            public static readonly string VpLdCose = Utf8Constants.ToInternedString(VpLdCoseUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VcCose"/>.</summary>
            public static ReadOnlySpan<byte> VcCoseUtf8 => "application/vc+cose"u8;

            /// <summary>
            /// Verifiable Credential secured using COSE (non-JSON-LD).
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-cose">VC-JOSE-COSE §4.1</see>.</remarks>
            public static readonly string VcCose = Utf8Constants.ToInternedString(VcCoseUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VpCose"/>.</summary>
            public static ReadOnlySpan<byte> VpCoseUtf8 => "application/vp+cose"u8;

            /// <summary>
            /// Verifiable Presentation secured using COSE (non-JSON-LD).
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-cose">VC-JOSE-COSE §4.2</see>.</remarks>
            public static readonly string VpCose = Utf8Constants.ToInternedString(VpCoseUtf8);

            /// <summary>The UTF-8 source literal of <see cref="SdJwt"/>.</summary>
            public static ReadOnlySpan<byte> SdJwtUtf8 => "application/sd-jwt"u8;

            /// <summary>
            /// Generic SD-JWT per <see href="https://datatracker.ietf.org/doc/rfc9901/">RFC 9901</see>.
            /// </summary>
            /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-9.3.1">RFC 9901 §9.3.1</see>.</remarks>
            public static readonly string SdJwt = Utf8Constants.ToInternedString(SdJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VcSdJwt"/>.</summary>
            public static ReadOnlySpan<byte> VcSdJwtUtf8 => "application/vc+sd-jwt"u8;

            /// <summary>
            /// SD-JWT Verifiable Credential.
            /// </summary>
            /// <remarks>See <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-4.2.1.1">SD-JWT VC §4.2.1.1</see>.</remarks>
            public static readonly string VcSdJwt = Utf8Constants.ToInternedString(VcSdJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="KbJwt"/>.</summary>
            public static ReadOnlySpan<byte> KbJwtUtf8 => "application/kb+jwt"u8;

            /// <summary>
            /// SD-JWT Key Binding JWT.
            /// </summary>
            /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-5.3">RFC 9901 §5.3</see>.</remarks>
            public static readonly string KbJwt = Utf8Constants.ToInternedString(KbJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="SdCwt"/>.</summary>
            public static ReadOnlySpan<byte> SdCwtUtf8 => "application/sd-cwt"u8;

            /// <summary>
            /// Generic SD-CWT per <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">draft-ietf-spice-sd-cwt</see>.
            /// </summary>
            public static readonly string SdCwt = Utf8Constants.ToInternedString(SdCwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VcSdCwt"/>.</summary>
            public static ReadOnlySpan<byte> VcSdCwtUtf8 => "application/vc+sd-cwt"u8;

            /// <summary>
            /// SD-CWT Verifiable Credential secured using COSE.
            /// </summary>
            public static readonly string VcSdCwt = Utf8Constants.ToInternedString(VcSdCwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="OauthAuthzReqJwt"/>.</summary>
            public static ReadOnlySpan<byte> OauthAuthzReqJwtUtf8 => "application/oauth-authz-req+jwt"u8;

            /// <summary>
            /// OAuth 2.0 JWT Authorization Request (<c>application/oauth-authz-req+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 §4</see>.
            /// </summary>
            public static readonly string OauthAuthzReqJwt = Utf8Constants.ToInternedString(OauthAuthzReqJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="EntityStatementJwt"/>.</summary>
            public static ReadOnlySpan<byte> EntityStatementJwtUtf8 => "application/entity-statement+jwt"u8;

            /// <summary>
            /// OpenID Federation 1.0 Entity Statement
            /// (<c>application/entity-statement+jwt</c>). Used as the HTTP
            /// Content-Type for the <c>/.well-known/openid-federation</c>
            /// Entity Configuration response and for Subordinate Statements
            /// returned from the <c>federation_fetch_endpoint</c>.
            /// See <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1">OpenID Federation 1.0 §3.1</see>.
            /// </summary>
            public static readonly string EntityStatementJwt = Utf8Constants.ToInternedString(EntityStatementJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="TrustChainJson"/>.</summary>
            public static ReadOnlySpan<byte> TrustChainJsonUtf8 => "application/trust-chain+json"u8;

            /// <summary>
            /// OpenID Federation 1.0 Trust Chain (<c>application/trust-chain+json</c>).
            /// Used as the HTTP Content-Type of an Explicit Registration request
            /// whose body is the RP's Trust Chain — a JSON array of Entity
            /// Statements — rather than a single Entity Configuration
            /// (<see cref="EntityStatementJwt"/>).
            /// See <see href="https://openid.net/specs/openid-federation-1_0.html#section-12.2.1">OpenID Federation 1.0 §12.2.1</see>.
            /// </summary>
            public static readonly string TrustChainJson = Utf8Constants.ToInternedString(TrustChainJsonUtf8);

            /// <summary>The UTF-8 source literal of <see cref="ResolveResponseJwt"/>.</summary>
            public static ReadOnlySpan<byte> ResolveResponseJwtUtf8 => "application/resolve-response+jwt"u8;

            /// <summary>
            /// OpenID Federation 1.0 Resolve Response
            /// (<c>application/resolve-response+jwt</c>). Used as the HTTP
            /// Content-Type for the signed JWT a
            /// <c>federation_resolve_endpoint</c> returns, carrying a
            /// subject's resolved metadata, trust chain, and trust marks.
            /// See <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">OpenID Federation 1.0 §8.3</see>.
            /// </summary>
            public static readonly string ResolveResponseJwt = Utf8Constants.ToInternedString(ResolveResponseJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="ExplicitRegistrationResponseJwt"/>.</summary>
            public static ReadOnlySpan<byte> ExplicitRegistrationResponseJwtUtf8 => "application/explicit-registration-response+jwt"u8;

            /// <summary>
            /// OpenID Federation 1.0 Explicit Registration Response
            /// (<c>application/explicit-registration-response+jwt</c>). Used
            /// as the HTTP Content-Type for the signed Entity Statement a
            /// <c>federation_registration_endpoint</c> returns to a Relying
            /// Party that registered explicitly.
            /// See <see href="https://openid.net/specs/openid-federation-1_0.html#section-12.2">OpenID Federation 1.0 §12.2</see> / §15.8.
            /// </summary>
            public static readonly string ExplicitRegistrationResponseJwt = Utf8Constants.ToInternedString(ExplicitRegistrationResponseJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="HistoricalKeysJwt"/>.</summary>
            public static ReadOnlySpan<byte> HistoricalKeysJwtUtf8 => "application/jwk-set+jwt"u8;

            /// <summary>
            /// OpenID Federation 1.0 Historical Keys
            /// (<c>application/jwk-set+jwt</c>). Used as the HTTP Content-Type
            /// for the signed JWK Set JWT a
            /// <c>federation_historical_keys_endpoint</c> returns, carrying the
            /// entity's historical (rotated and revoked) Federation Entity
            /// Keys.
            /// See <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.7.2">OpenID Federation 1.0 §8.7.2</see>.
            /// </summary>
            public static readonly string HistoricalKeysJwt = Utf8Constants.ToInternedString(HistoricalKeysJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="TrustMarkJwt"/>.</summary>
            public static ReadOnlySpan<byte> TrustMarkJwtUtf8 => "application/trust-mark+jwt"u8;

            /// <summary>
            /// OpenID Federation 1.0 Trust Mark (<c>application/trust-mark+jwt</c>).
            /// Used as the HTTP Content-Type for the signed Trust Mark JWT a
            /// <c>federation_trust_mark_endpoint</c> returns per
            /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.6">OpenID Federation 1.0 §8.6</see>.
            /// </summary>
            public static readonly string TrustMarkJwt = Utf8Constants.ToInternedString(TrustMarkJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="TrustMarkStatusResponseJwt"/>.</summary>
            public static ReadOnlySpan<byte> TrustMarkStatusResponseJwtUtf8 => "application/trust-mark-status-response+jwt"u8;

            /// <summary>
            /// OpenID Federation 1.0 Trust Mark Status Response
            /// (<c>application/trust-mark-status-response+jwt</c>). Used as the HTTP
            /// Content-Type for the signed status JWT a
            /// <c>federation_trust_mark_status_endpoint</c> returns per
            /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.4">OpenID Federation 1.0 §8.4</see>,
            /// carrying the queried <c>trust_mark</c> and its <c>status</c>.
            /// </summary>
            public static readonly string TrustMarkStatusResponseJwt = Utf8Constants.ToInternedString(TrustMarkStatusResponseJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="AtJwt"/>.</summary>
            public static ReadOnlySpan<byte> AtJwtUtf8 => "application/at+jwt"u8;

            /// <summary>
            /// OAuth 2.0 JWT Access Token (<c>application/at+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.1">RFC 9068 §2.1</see>.
            /// </summary>
            public static readonly string AtJwt = Utf8Constants.ToInternedString(AtJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="OauthIdJagJwt"/>.</summary>
            public static ReadOnlySpan<byte> OauthIdJagJwtUtf8 => "application/oauth-id-jag+jwt"u8;

            /// <summary>
            /// Identity Assertion JWT Authorization Grant (<c>application/oauth-id-jag+jwt</c>),
            /// the media type registered by draft-ietf-oauth-identity-assertion-authz-grant §10.1.
            /// The <see cref="Jwt.OauthIdJagJwt"/> sibling carries the short <c>typ</c> form.
            /// </summary>
            public static readonly string OauthIdJagJwt = Utf8Constants.ToInternedString(OauthIdJagJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="TokenIntrospectionJwt"/>.</summary>
            public static ReadOnlySpan<byte> TokenIntrospectionJwtUtf8 => "application/token-introspection+jwt"u8;

            /// <summary>
            /// JWT token introspection response (<c>application/token-introspection+jwt</c>).
            /// The <c>Accept</c> value a resource server requests a signed introspection
            /// response with, and the <c>Content-Type</c> of that response.
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9701#section-5">RFC 9701 §5</see>.
            /// </summary>
            public static readonly string TokenIntrospectionJwt = Utf8Constants.ToInternedString(TokenIntrospectionJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="Jwt"/>.</summary>
            public static ReadOnlySpan<byte> JwtUtf8 => "application/jwt"u8;

            /// <summary>
            /// A generic JWT (<c>application/jwt</c>) per
            /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-10.3">RFC 7519 §10.3</see>.
            /// OID4VCI 1.0 §10 uses it as the media type of encrypted Credential Requests
            /// and Responses.
            /// </summary>
            public static readonly string Jwt = Utf8Constants.ToInternedString(JwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="DpopJwt"/>.</summary>
            public static ReadOnlySpan<byte> DpopJwtUtf8 => "application/dpop+jwt"u8;

            /// <summary>
            /// DPoP proof JWT (<c>application/dpop+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see>.
            /// </summary>
            public static readonly string DpopJwt = Utf8Constants.ToInternedString(DpopJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VerifierAttestationJwt"/>.</summary>
            public static ReadOnlySpan<byte> VerifierAttestationJwtUtf8 => "application/verifier-attestation+jwt"u8;

            /// <summary>
            /// Verifier Attestation JWT (<c>application/verifier-attestation+jwt</c>).
            /// Carried in the <c>jwt</c> JOSE header parameter of a signed JAR when the
            /// <c>verifier_attestation:</c> Client Identifier Prefix is used.
            /// See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>.
            /// </summary>
            /// <remarks>
            /// The <see cref="Jwt.VerifierAttestationJwt"/> sibling carries the
            /// short form (<c>verifier-attestation+jwt</c>) used for the JWT
            /// <c>typ</c> header parameter; this Application-class entry carries
            /// the full HTTP media type with the <c>application/</c> prefix,
            /// matching the convention <see cref="OauthAuthzReqJwt"/> /
            /// <see cref="AtJwt"/> / <see cref="DpopJwt"/> follow.
            /// </remarks>
            public static readonly string VerifierAttestationJwt = Utf8Constants.ToInternedString(VerifierAttestationJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="SecEventJwt"/>.</summary>
            public static ReadOnlySpan<byte> SecEventJwtUtf8 => "application/secevent+jwt"u8;

            /// <summary>
            /// Security Event Token (<c>application/secevent+jwt</c>). The HTTP
            /// <c>Content-Type</c> for a SET delivered over push
            /// (<see href="https://www.rfc-editor.org/rfc/rfc8935#section-2.3">RFC 8935 §2.3</see>)
            /// or carried in the <c>sets</c> object of a poll response
            /// (<see href="https://www.rfc-editor.org/rfc/rfc8936">RFC 8936</see>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc8417#section-2.3">RFC 8417 §2.3</see>.
            /// </summary>
            public static readonly string SecEventJwt = Utf8Constants.ToInternedString(SecEventJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="Json"/>.</summary>
            public static ReadOnlySpan<byte> JsonUtf8 => "application/json"u8;

            /// <summary>
            /// The JSON content-type, <c>application/json</c>, per
            /// <see href="https://www.rfc-editor.org/rfc/rfc8259">RFC 8259</see>.
            /// </summary>
            public static readonly string Json = Utf8Constants.ToInternedString(JsonUtf8);

            /// <summary>The UTF-8 source literal of <see cref="FormUrlEncoded"/>.</summary>
            public static ReadOnlySpan<byte> FormUrlEncodedUtf8 => "application/x-www-form-urlencoded"u8;

            /// <summary>
            /// The form-urlencoded content-type, <c>application/x-www-form-urlencoded</c>,
            /// per <see href="https://url.spec.whatwg.org/#application/x-www-form-urlencoded">URL Standard</see>.
            /// </summary>
            public static readonly string FormUrlEncoded = Utf8Constants.ToInternedString(FormUrlEncodedUtf8);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="SdJwt"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="SdJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsSdJwt(string mediaType) => Equals(mediaType, SdJwt);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VcSdJwt"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VcSdJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVcSdJwt(string mediaType) => Equals(mediaType, VcSdJwt);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="KbJwt"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="KbJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsKbJwt(string mediaType) => Equals(mediaType, KbJwt);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="SdCwt"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="SdCwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsSdCwt(string mediaType) => Equals(mediaType, SdCwt);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VcSdCwt"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VcSdCwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVcSdCwt(string mediaType) => Equals(mediaType, VcSdCwt);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VcLdJwt"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VcLdJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVcLdJwt(string mediaType) => Equals(mediaType, VcLdJwt);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VpLdJwt"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VpLdJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVpLdJwt(string mediaType) => Equals(mediaType, VpLdJwt);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VcJwt"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VcJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVcJwt(string mediaType) => Equals(mediaType, VcJwt);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VpJwt"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VpJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVpJwt(string mediaType) => Equals(mediaType, VpJwt);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VcLdCose"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VcLdCose"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVcLdCose(string mediaType) => Equals(mediaType, VcLdCose);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VpLdCose"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VpLdCose"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVpLdCose(string mediaType) => Equals(mediaType, VpLdCose);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VcCose"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VcCose"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVcCose(string mediaType) => Equals(mediaType, VcCose);


            /// <summary>
            /// If <paramref name="mediaType"/> is <see cref="VpCose"/> or not.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="VpCose"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVpCose(string mediaType) => Equals(mediaType, VpCose);


            /// <summary>
            /// Whether <paramref name="mediaType"/> is <see cref="OauthAuthzReqJwt"/>.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="OauthAuthzReqJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsOauthAuthzReqJwt(string mediaType) => Equals(mediaType, OauthAuthzReqJwt);


            /// <summary>
            /// Whether <paramref name="mediaType"/> is <see cref="EntityStatementJwt"/>.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="EntityStatementJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsEntityStatementJwt(string mediaType) => Equals(mediaType, EntityStatementJwt);


            /// <summary>
            /// Whether <paramref name="mediaType"/> is <see cref="TrustChainJson"/>.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="TrustChainJson"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsTrustChainJson(string mediaType) => Equals(mediaType, TrustChainJson);


            /// <summary>
            /// Whether <paramref name="mediaType"/> is <see cref="AtJwt"/>.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="AtJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsAtJwt(string mediaType) => Equals(mediaType, AtJwt);


            /// <summary>
            /// Whether <paramref name="mediaType"/> is <see cref="DpopJwt"/>.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="DpopJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsDpopJwt(string mediaType) => Equals(mediaType, DpopJwt);


            /// <summary>
            /// Whether <paramref name="mediaType"/> is <see cref="SecEventJwt"/>.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="SecEventJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsSecEventJwt(string mediaType) => Equals(mediaType, SecEventJwt);


            /// <summary>
            /// Returns <see langword="true"/> if <paramref name="mediaType"/> is the
            /// <c>application/json</c> media type, comparing case-insensitively per
            /// RFC 9110 §8.3.1.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="Json"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsJson(string mediaType) => Equals(mediaType, Json);


            /// <summary>
            /// Returns <see langword="true"/> if <paramref name="mediaType"/> is the
            /// <c>application/x-www-form-urlencoded</c> media type, comparing
            /// case-insensitively per RFC 9110 §8.3.1.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="FormUrlEncoded"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsFormUrlEncoded(string mediaType) => Equals(mediaType, FormUrlEncoded);


            /// <summary>
            /// Returns the equivalent static instance, or the original instance if none match.
            /// This conversion is optional but allows for performance optimizations when comparing values elsewhere.
            /// </summary>
            /// <param name="mediaType">The media type to canonicalize.</param>
            /// <returns>The equivalent static instance of <paramref name="mediaType"/>, or the original instance if none match.</returns>
            public static string GetCanonicalizedValue(string mediaType) => mediaType switch
            {
                _ when IsVcLdJwt(mediaType) => VcLdJwt,
                _ when IsVpLdJwt(mediaType) => VpLdJwt,
                _ when IsVcJwt(mediaType) => VcJwt,
                _ when IsVpJwt(mediaType) => VpJwt,
                _ when IsVcLdCose(mediaType) => VcLdCose,
                _ when IsVpLdCose(mediaType) => VpLdCose,
                _ when IsVcCose(mediaType) => VcCose,
                _ when IsVpCose(mediaType) => VpCose,
                _ when IsVcSdJwt(mediaType) => VcSdJwt,
                _ when IsSdJwt(mediaType) => SdJwt,
                _ when IsKbJwt(mediaType) => KbJwt,
                _ when IsSdCwt(mediaType) => SdCwt,
                _ when IsVcSdCwt(mediaType) => VcSdCwt,
                _ when IsOauthAuthzReqJwt(mediaType) => OauthAuthzReqJwt,
                _ when IsAtJwt(mediaType) => AtJwt,
                _ when IsDpopJwt(mediaType) => DpopJwt,
                _ when IsSecEventJwt(mediaType) => SecEventJwt,
                _ when IsJson(mediaType) => Json,
                _ when IsFormUrlEncoded(mediaType) => FormUrlEncoded,
                _ => mediaType
            };


            /// <summary>
            /// Returns a value that indicates if the media types are the same.
            /// </summary>
            /// <param name="mediaTypeA">The first media type to compare.</param>
            /// <param name="mediaTypeB">The second media type to compare.</param>
            /// <returns><see langword="true"/> if the media types are the same; otherwise, <see langword="false"/>.</returns>
            /// <remarks>
            /// Comparison is on the <c>type/subtype</c> only, case-insensitively
            /// per <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 §8.3.1</see>.
            /// Any media-type parameters (for example a <c>; charset=utf-8</c>
            /// that a sender such as <c>System.Net.Http.StringContent</c> appends)
            /// are ignored: a wire <c>Content-Type</c> still matches its
            /// parameterless constant form, which the federation media types
            /// require since their IANA registrations define no parameters.
            /// </remarks>
            public static bool Equals(string mediaTypeA, string mediaTypeB)
            {
                return ReferenceEquals(mediaTypeA, mediaTypeB)
                    || StringComparer.OrdinalIgnoreCase.Equals(TypeAndSubtype(mediaTypeA), TypeAndSubtype(mediaTypeB));
            }


            /// <summary>
            /// Returns the <c>type/subtype</c> portion of an HTTP media type,
            /// dropping any parameters (RFC 9110 §5.6.6) such as
            /// <c>; charset=utf-8</c> so a parameterised wire <c>Content-Type</c>
            /// matches its parameterless constant form.
            /// </summary>
            /// <param name="mediaType">The media type, possibly carrying parameters.</param>
            /// <returns>The trimmed <c>type/subtype</c>, or the empty string when <paramref name="mediaType"/> is <see langword="null"/>.</returns>
            private static string TypeAndSubtype(string mediaType)
            {
                if(mediaType is null)
                {
                    return string.Empty;
                }

                int separator = mediaType.IndexOf(';', StringComparison.Ordinal);
                return (separator < 0 ? mediaType : mediaType[..separator]).Trim();
            }
        }


        /// <summary>
        /// Media types in the <c>text</c> top-level type.
        /// </summary>
        [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The media-type constants are organized like this on purpose.")]
        public static class Text
        {
            /// <summary>The UTF-8 source literal of <see cref="Html"/>.</summary>
            public static ReadOnlySpan<byte> HtmlUtf8 => "text/html"u8;

            /// <summary>
            /// The HTML content-type, <c>text/html</c>, per
            /// <see href="https://www.rfc-editor.org/rfc/rfc2854">RFC 2854</see>. The W3C VCALM 1.0
            /// §3.7.4 interaction protocols response returns a <c>text/html</c> body when the
            /// interaction URL is fetched with an unrecognized <c>Accept</c> header, directing a human
            /// being to software that understands how to process interaction URLs.
            /// </summary>
            public static readonly string Html = Utf8Constants.ToInternedString(HtmlUtf8);


            /// <summary>
            /// Returns <see langword="true"/> if <paramref name="mediaType"/> is the
            /// <c>text/html</c> media type, comparing case-insensitively per RFC 9110 §8.3.1.
            /// </summary>
            /// <param name="mediaType">The media type.</param>
            /// <returns><see langword="true"/> if <paramref name="mediaType"/> is <see cref="Html"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsHtml(string mediaType) =>
                ReferenceEquals(mediaType, Html) || StringComparer.OrdinalIgnoreCase.Equals(mediaType, Html);
        }


        /// <summary>
        /// JWT <c>typ</c> header values (short forms without the <c>application/</c> prefix).
        /// </summary>
        /// <remarks>
        /// <para>
        /// Per RFC 7515, the <c>typ</c> header parameter is used to declare the media type of the complete
        /// JWT. When the value does not contain a <c>/</c>, it is interpreted as <c>application/[value]</c>.
        /// </para>
        /// <para>
        /// See <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>.
        /// </para>
        /// </remarks>
        [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
        public static class Jwt
        {
            /// <summary>The UTF-8 source literal of <see cref="VcLdJwt"/>.</summary>
            public static ReadOnlySpan<byte> VcLdJwtUtf8 => "vc+ld+jwt"u8;

            /// <summary>
            /// Verifiable Credential as JWT with JSON-LD.
            /// </summary>
            public static readonly string VcLdJwt = Utf8Constants.ToInternedString(VcLdJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VpLdJwt"/>.</summary>
            public static ReadOnlySpan<byte> VpLdJwtUtf8 => "vp+ld+jwt"u8;

            /// <summary>
            /// Verifiable Presentation as JWT with JSON-LD.
            /// </summary>
            public static readonly string VpLdJwt = Utf8Constants.ToInternedString(VpLdJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VcJwt"/>.</summary>
            public static ReadOnlySpan<byte> VcJwtUtf8 => "vc+jwt"u8;

            /// <summary>
            /// Verifiable Credential as JWT (non-JSON-LD).
            /// </summary>
            public static readonly string VcJwt = Utf8Constants.ToInternedString(VcJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VpJwt"/>.</summary>
            public static ReadOnlySpan<byte> VpJwtUtf8 => "vp+jwt"u8;

            /// <summary>
            /// Verifiable Presentation as JWT (non-JSON-LD).
            /// </summary>
            public static readonly string VpJwt = Utf8Constants.ToInternedString(VpJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="SdJwt"/>.</summary>
            public static ReadOnlySpan<byte> SdJwtUtf8 => "sd-jwt"u8;

            /// <summary>
            /// Generic SD-JWT (short form for <c>typ</c> header) per
            /// <see href="https://datatracker.ietf.org/doc/rfc9901/">RFC 9901</see>.
            /// </summary>
            /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-9.3.1">RFC 9901 §9.3.1</see>.</remarks>
            public static readonly string SdJwt = Utf8Constants.ToInternedString(SdJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VcSdJwt"/>.</summary>
            public static ReadOnlySpan<byte> VcSdJwtUtf8 => "vc+sd-jwt"u8;

            /// <summary>
            /// SD-JWT Verifiable Credential (short form for <c>typ</c> header).
            /// </summary>
            /// <remarks>See <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-4.2.1.1">SD-JWT VC §4.2.1.1</see>.</remarks>
            public static readonly string VcSdJwt = Utf8Constants.ToInternedString(VcSdJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="KbJwt"/>.</summary>
            public static ReadOnlySpan<byte> KbJwtUtf8 => "kb+jwt"u8;

            /// <summary>
            /// Key Binding JWT (short form for <c>typ</c> header).
            /// </summary>
            /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-5.3">RFC 9901 §5.3</see>.</remarks>
            public static readonly string KbJwt = Utf8Constants.ToInternedString(KbJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="DcSdJwt"/>.</summary>
            public static ReadOnlySpan<byte> DcSdJwtUtf8 => "dc+sd-jwt"u8;

            /// <summary>
            /// SD-JWT Verifiable Credential per HAIP 1.0 and RFC 9901 (<c>dc+sd-jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9901#section-3.2.2.1.1">RFC 9901 §3.2.2.1.1</see>.
            /// </summary>
            public static readonly string DcSdJwt = Utf8Constants.ToInternedString(DcSdJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="OauthAuthzReqJwt"/>.</summary>
            public static ReadOnlySpan<byte> OauthAuthzReqJwtUtf8 => "oauth-authz-req+jwt"u8;

            /// <summary>
            /// JWT Authorization Request for JAR (<c>oauth-authz-req+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 §4</see>.
            /// </summary>
            public static readonly string OauthAuthzReqJwt = Utf8Constants.ToInternedString(OauthAuthzReqJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="AtJwt"/>.</summary>
            public static ReadOnlySpan<byte> AtJwtUtf8 => "at+jwt"u8;

            /// <summary>
            /// OAuth 2.0 JWT Access Token (<c>at+jwt</c>). Used as the <c>typ</c> header
            /// value for JWT access tokens per
            /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.1">RFC 9068 §2.1</see>.
            /// </summary>
            public static readonly string AtJwt = Utf8Constants.ToInternedString(AtJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="OauthIdJagJwt"/>.</summary>
            public static ReadOnlySpan<byte> OauthIdJagJwtUtf8 => "oauth-id-jag+jwt"u8;

            /// <summary>
            /// Identity Assertion JWT Authorization Grant (<c>oauth-id-jag+jwt</c>). The
            /// explicit <c>typ</c> header value an ID-JAG MUST carry per
            /// draft-ietf-oauth-identity-assertion-authz-grant §3.1, distinguishing the
            /// authorization-grant JWT from an access token or ID Token.
            /// </summary>
            public static readonly string OauthIdJagJwt = Utf8Constants.ToInternedString(OauthIdJagJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="TokenIntrospectionJwt"/>.</summary>
            public static ReadOnlySpan<byte> TokenIntrospectionJwtUtf8 => "token-introspection+jwt"u8;

            /// <summary>
            /// JWT token introspection response (<c>token-introspection+jwt</c>). Used as
            /// the <c>typ</c> header value of a signed introspection response so the JWT
            /// cannot be confused with an access token (RFC 9701 §8.1).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9701#section-5">RFC 9701 §5</see>.
            /// </summary>
            public static readonly string TokenIntrospectionJwt = Utf8Constants.ToInternedString(TokenIntrospectionJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="DpopJwt"/>.</summary>
            public static ReadOnlySpan<byte> DpopJwtUtf8 => "dpop+jwt"u8;

            /// <summary>
            /// DPoP proof JWT (<c>dpop+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see>.
            /// </summary>
            public static readonly string DpopJwt = Utf8Constants.ToInternedString(DpopJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="VerifierAttestationJwt"/>.</summary>
            public static ReadOnlySpan<byte> VerifierAttestationJwtUtf8 => "verifier-attestation+jwt"u8;

            /// <summary>
            /// Verifier Attestation JWT (<c>verifier-attestation+jwt</c>).
            /// Carried in the <c>jwt</c> JOSE header parameter of a signed JAR when the
            /// <c>verifier_attestation:</c> Client Identifier Prefix is used.
            /// See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>.
            /// </summary>
            public static readonly string VerifierAttestationJwt = Utf8Constants.ToInternedString(VerifierAttestationJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="SecEventJwt"/>.</summary>
            public static ReadOnlySpan<byte> SecEventJwtUtf8 => "secevent+jwt"u8;

            /// <summary>
            /// Security Event Token (<c>secevent+jwt</c>). The explicit <c>typ</c>
            /// header value a SET MUST carry per
            /// <see href="https://www.rfc-editor.org/rfc/rfc8417#section-2.3">RFC 8417 §2.3</see>
            /// and OpenID SSF 1.0 §4.1.1 (explicit typing).
            /// </summary>
            public static readonly string SecEventJwt = Utf8Constants.ToInternedString(SecEventJwtUtf8);

            /// <summary>The UTF-8 source literal of <see cref="LogoutJwt"/>.</summary>
            public static ReadOnlySpan<byte> LogoutJwtUtf8 => "logout+jwt"u8;

            /// <summary>
            /// OIDC Back-Channel Logout token (<c>logout+jwt</c>). The explicit <c>typ</c>
            /// header value a Logout Token is RECOMMENDED to carry per
            /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">OIDC Back-Channel Logout 1.0 §2.4</see>,
            /// declaring the JWS as a Logout Token rather than an ID Token or a generic SET.
            /// </summary>
            public static readonly string LogoutJwt = Utf8Constants.ToInternedString(LogoutJwtUtf8);

            /// <summary>
            /// Whether <paramref name="typ"/> is <see cref="LogoutJwt"/>.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="LogoutJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsLogoutJwt(string typ) => Equals(typ, LogoutJwt);

            /// <summary>
            /// If <paramref name="typ"/> is <see cref="SdJwt"/> or not.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="SdJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsSdJwt(string typ) => Equals(typ, SdJwt);


            /// <summary>
            /// If <paramref name="typ"/> is <see cref="VcSdJwt"/> or not.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="VcSdJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVcSdJwt(string typ) => Equals(typ, VcSdJwt);


            /// <summary>
            /// If <paramref name="typ"/> is <see cref="KbJwt"/> or not.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="KbJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsKbJwt(string typ) => Equals(typ, KbJwt);


            /// <summary>
            /// Whether <paramref name="typ"/> is <see cref="DcSdJwt"/>.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="DcSdJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsDcSdJwt(string typ) => Equals(typ, DcSdJwt);


            /// <summary>
            /// Whether <paramref name="typ"/> is <see cref="OauthAuthzReqJwt"/>.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="OauthAuthzReqJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsOauthAuthzReqJwt(string typ) => Equals(typ, OauthAuthzReqJwt);


            /// <summary>
            /// Whether <paramref name="typ"/> is <see cref="AtJwt"/>.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="AtJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsAtJwt(string typ) => Equals(typ, AtJwt);


            /// <summary>
            /// Whether <paramref name="typ"/> is <see cref="OauthIdJagJwt"/>.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="OauthIdJagJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsOauthIdJagJwt(string typ) => Equals(typ, OauthIdJagJwt);


            /// <summary>
            /// Whether <paramref name="typ"/> is <see cref="DpopJwt"/>.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="DpopJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsDpopJwt(string typ) => Equals(typ, DpopJwt);


            /// <summary>
            /// Whether <paramref name="typ"/> is <see cref="VerifierAttestationJwt"/>.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="VerifierAttestationJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVerifierAttestationJwt(string typ) => Equals(typ, VerifierAttestationJwt);


            /// <summary>
            /// Whether <paramref name="typ"/> is <see cref="SecEventJwt"/>.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="SecEventJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsSecEventJwt(string typ) => Equals(typ, SecEventJwt);


            /// <summary>
            /// If <paramref name="typ"/> is <see cref="VcLdJwt"/> or not.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="VcLdJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVcLdJwt(string typ) => Equals(typ, VcLdJwt);


            /// <summary>
            /// If <paramref name="typ"/> is <see cref="VpLdJwt"/> or not.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="VpLdJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVpLdJwt(string typ) => Equals(typ, VpLdJwt);


            /// <summary>
            /// If <paramref name="typ"/> is <see cref="VcJwt"/> or not.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="VcJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVcJwt(string typ) => Equals(typ, VcJwt);


            /// <summary>
            /// If <paramref name="typ"/> is <see cref="VpJwt"/> or not.
            /// </summary>
            /// <param name="typ">The JWT typ header value.</param>
            /// <returns><see langword="true"/> if <paramref name="typ"/> is <see cref="VpJwt"/>; otherwise, <see langword="false"/>.</returns>
            public static bool IsVpJwt(string typ) => Equals(typ, VpJwt);


            /// <summary>
            /// Returns the equivalent static instance, or the original instance if none match.
            /// This conversion is optional but allows for performance optimizations when comparing values elsewhere.
            /// </summary>
            /// <param name="typ">The typ value to canonicalize.</param>
            /// <returns>The equivalent static instance of <paramref name="typ"/>, or the original instance if none match.</returns>
            public static string GetCanonicalizedValue(string typ) => typ switch
            {
                _ when IsVcLdJwt(typ) => VcLdJwt,
                _ when IsVpLdJwt(typ) => VpLdJwt,
                _ when IsVcJwt(typ) => VcJwt,
                _ when IsVpJwt(typ) => VpJwt,
                _ when IsVcSdJwt(typ) => VcSdJwt,
                _ when IsSdJwt(typ) => SdJwt,
                _ when IsKbJwt(typ) => KbJwt,
                _ when IsDcSdJwt(typ) => DcSdJwt,
                _ when IsOauthAuthzReqJwt(typ) => OauthAuthzReqJwt,
                _ when IsAtJwt(typ) => AtJwt,
                _ when IsOauthIdJagJwt(typ) => OauthIdJagJwt,
                _ when IsDpopJwt(typ) => DpopJwt,
                _ when IsVerifierAttestationJwt(typ) => VerifierAttestationJwt,
                _ when IsSecEventJwt(typ) => SecEventJwt,
                _ => typ
            };


            /// <summary>
            /// Returns a value that indicates if the typ values are the same.
            /// </summary>
            /// <param name="typA">The first typ value to compare.</param>
            /// <param name="typB">The second typ value to compare.</param>
            /// <returns><see langword="true"/> if the typ values are the same; otherwise, <see langword="false"/>.</returns>
            /// <remarks>The comparison is case-insensitive per RFC 7515.</remarks>
            public static bool Equals(string typA, string typB)
            {
                return ReferenceEquals(typA, typB) || StringComparer.OrdinalIgnoreCase.Equals(typA, typB);
            }
        }
    }
}
