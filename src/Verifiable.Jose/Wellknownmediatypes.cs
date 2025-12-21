namespace Verifiable.Jose
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
        public static class Application
        {
            /// <summary>
            /// Verifiable Credential secured as a JWT using JSON-LD.
            /// </summary>
            /// <remarks>See <see href="https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-jose">VC-JOSE-COSE §3.1</see>.</remarks>
            public static readonly string VcLdJwt = "application/vc+ld+jwt";

            /// <summary>
            /// Verifiable Presentation secured as a JWT using JSON-LD.
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