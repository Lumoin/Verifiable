using System.Diagnostics.CodeAnalysis;

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
            public static readonly string Vc = "vc";

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
            public static readonly string Vp = "vp";

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
            public static readonly string ApplicationVc = "application/vc";

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
            public static readonly string ApplicationVp = "application/vp";

            /// <summary>
            /// Verifiable Credential secured as a JWT with JSON-LD.
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-jose">VC-JOSE-COSE §3.1</see>.</remarks>
            public static readonly string VcLdJwt = "application/vc+ld+jwt";

            /// <summary>
            /// Verifiable Presentation secured as a JWT with JSON-LD.
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-jose">VC-JOSE-COSE §3.2</see>.</remarks>
            public static readonly string VpLdJwt = "application/vp+ld+jwt";

            /// <summary>
            /// Verifiable Credential secured as a JWT (non-JSON-LD).
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-jose">VC-JOSE-COSE §3.1</see>.</remarks>
            public static readonly string VcJwt = "application/vc+jwt";

            /// <summary>
            /// Verifiable Presentation secured as a JWT (non-JSON-LD).
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-jose">VC-JOSE-COSE §3.2</see>.</remarks>
            public static readonly string VpJwt = "application/vp+jwt";

            /// <summary>
            /// Verifiable Credential secured using COSE with JSON-LD.
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-cose">VC-JOSE-COSE §4.1</see>.</remarks>
            public static readonly string VcLdCose = "application/vc+ld+cose";

            /// <summary>
            /// Verifiable Presentation secured using COSE with JSON-LD.
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-cose">VC-JOSE-COSE §4.2</see>.</remarks>
            public static readonly string VpLdCose = "application/vp+ld+cose";

            /// <summary>
            /// Verifiable Credential secured using COSE (non-JSON-LD).
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-cose">VC-JOSE-COSE §4.1</see>.</remarks>
            public static readonly string VcCose = "application/vc+cose";

            /// <summary>
            /// Verifiable Presentation secured using COSE (non-JSON-LD).
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-cose">VC-JOSE-COSE §4.2</see>.</remarks>
            public static readonly string VpCose = "application/vp+cose";

            /// <summary>
            /// Generic SD-JWT per <see href="https://datatracker.ietf.org/doc/rfc9901/">RFC 9901</see>.
            /// </summary>
            /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-9.3.1">RFC 9901 §9.3.1</see>.</remarks>
            public static readonly string SdJwt = "application/sd-jwt";

            /// <summary>
            /// SD-JWT Verifiable Credential.
            /// </summary>
            /// <remarks>See <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-4.2.1.1">SD-JWT VC §4.2.1.1</see>.</remarks>
            public static readonly string VcSdJwt = "application/vc+sd-jwt";

            /// <summary>
            /// SD-JWT Key Binding JWT.
            /// </summary>
            /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-5.3">RFC 9901 §5.3</see>.</remarks>
            public static readonly string KbJwt = "application/kb+jwt";

            /// <summary>
            /// Generic SD-CWT per <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">draft-ietf-spice-sd-cwt</see>.
            /// </summary>
            public static readonly string SdCwt = "application/sd-cwt";

            /// <summary>
            /// SD-CWT Verifiable Credential secured using COSE.
            /// </summary>
            public static readonly string VcSdCwt = "application/vc+sd-cwt";

            /// <summary>
            /// OAuth 2.0 JWT Authorization Request (<c>application/oauth-authz-req+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 §4</see>.
            /// </summary>
            public static readonly string OauthAuthzReqJwt = "application/oauth-authz-req+jwt";

            /// <summary>
            /// OAuth 2.0 JWT Access Token (<c>application/at+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.1">RFC 9068 §2.1</see>.
            /// </summary>
            public static readonly string AtJwt = "application/at+jwt";

            /// <summary>
            /// DPoP proof JWT (<c>application/dpop+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see>.
            /// </summary>
            public static readonly string DpopJwt = "application/dpop+jwt";

            /// <summary>
            /// Verifier Attestation JWT (<c>verifier-attestation+jwt</c>).
            /// Carried in the <c>jwt</c> JOSE header parameter of a signed JAR when the
            /// <c>verifier_attestation:</c> Client Identifier Prefix is used.
            /// See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>.
            /// </summary>
            public static readonly string VerifierAttestationJwt = "verifier-attestation+jwt";


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
                _ => mediaType
            };


            /// <summary>
            /// Returns a value that indicates if the media types are the same.
            /// </summary>
            /// <param name="mediaTypeA">The first media type to compare.</param>
            /// <param name="mediaTypeB">The second media type to compare.</param>
            /// <returns><see langword="true"/> if the media types are the same; otherwise, <see langword="false"/>.</returns>
            /// <remarks>Media type comparison is case-insensitive per RFC 2045.</remarks>
            public static bool Equals(string mediaTypeA, string mediaTypeB)
            {
                return ReferenceEquals(mediaTypeA, mediaTypeB) || StringComparer.OrdinalIgnoreCase.Equals(mediaTypeA, mediaTypeB);
            }
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
            /// <summary>
            /// Verifiable Credential as JWT with JSON-LD.
            /// </summary>
            public static readonly string VcLdJwt = "vc+ld+jwt";

            /// <summary>
            /// Verifiable Presentation as JWT with JSON-LD.
            /// </summary>
            public static readonly string VpLdJwt = "vp+ld+jwt";

            /// <summary>
            /// Verifiable Credential as JWT (non-JSON-LD).
            /// </summary>
            public static readonly string VcJwt = "vc+jwt";

            /// <summary>
            /// Verifiable Presentation as JWT (non-JSON-LD).
            /// </summary>
            public static readonly string VpJwt = "vp+jwt";

            /// <summary>
            /// Generic SD-JWT (short form for <c>typ</c> header) per
            /// <see href="https://datatracker.ietf.org/doc/rfc9901/">RFC 9901</see>.
            /// </summary>
            /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-9.3.1">RFC 9901 §9.3.1</see>.</remarks>
            public static readonly string SdJwt = "sd-jwt";

            /// <summary>
            /// SD-JWT Verifiable Credential (short form for <c>typ</c> header).
            /// </summary>
            /// <remarks>See <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-4.2.1.1">SD-JWT VC §4.2.1.1</see>.</remarks>
            public static readonly string VcSdJwt = "vc+sd-jwt";

            /// <summary>
            /// Key Binding JWT (short form for <c>typ</c> header).
            /// </summary>
            /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-5.3">RFC 9901 §5.3</see>.</remarks>
            public static readonly string KbJwt = "kb+jwt";

            /// <summary>
            /// SD-JWT Verifiable Credential per HAIP 1.0 and RFC 9901 (<c>dc+sd-jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9901#section-3.2.2.1.1">RFC 9901 §3.2.2.1.1</see>.
            /// </summary>
            public static readonly string DcSdJwt = "dc+sd-jwt";

            /// <summary>
            /// JWT Authorization Request for JAR (<c>oauth-authz-req+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 §4</see>.
            /// </summary>
            public static readonly string OauthAuthzReqJwt = "oauth-authz-req+jwt";

            /// <summary>
            /// OAuth 2.0 JWT Access Token (<c>at+jwt</c>). Used as the <c>typ</c> header
            /// value for JWT access tokens per
            /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.1">RFC 9068 §2.1</see>.
            /// </summary>
            public static readonly string AtJwt = "at+jwt";

            /// <summary>
            /// DPoP proof JWT (<c>dpop+jwt</c>).
            /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see>.
            /// </summary>
            public static readonly string DpopJwt = "dpop+jwt";

            /// <summary>
            /// Verifier Attestation JWT (<c>verifier-attestation+jwt</c>).
            /// Carried in the <c>jwt</c> JOSE header parameter of a signed JAR when the
            /// <c>verifier_attestation:</c> Client Identifier Prefix is used.
            /// See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>.
            /// </summary>
            public static readonly string VerifierAttestationJwt = "verifier-attestation+jwt";

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
                _ when IsDpopJwt(typ) => DpopJwt,
                _ when IsVerifierAttestationJwt(typ) => VerifierAttestationJwt,
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
