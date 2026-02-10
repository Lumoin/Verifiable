namespace Verifiable.JCose
{
    /// <summary>    
    /// JWT parameters as defined in <see href="https://www.iana.org/assignments/jwt/jwt.xhtml#claims">JSON Web Token (JWT)</see>.    
    /// </summary>
    /// <remarks>As per definition parameters are case-sensitive.</remarks>
    public static class WellKnownJwtClaims
    {
        /// <summary>
        /// The "iss" (issuer) claim identifies the principal that issued the
        /// JWT.The processing of this claim is generally application specific.
        /// The "iss" value is a case-sensitive string containing a StringOrURI
        /// value. Use of this claim is OPTIONAL.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1">"iss" (Issuer) Claim</see>.</remarks>
        public static readonly string Iss = "iss";

        /// <summary>
        /// The "sub" (subject) claim identifies the principal that is the
        /// subject of the JWT.The claims in a JWT are normally statements
        /// about the subject.  The subject value MUST either be scoped to be
        /// locally unique in the context of the issuer or be globally unique.
        /// The processing of this claim is generally application specific. The
        /// "sub" value is a case-sensitive string containing a StringOrURI
        /// value. Use of this claim is OPTIONAL.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2">"sub" (Subject) Claim</see>.</remarks>
        public static readonly string Sub = "sub";

        /// <summary>
        /// The "aud" (audience) claim identifies the recipients that the JWT is
        /// intended for.  Each principal intended to process the JWT MUST
        /// dentify itself with a value in the audience claim.If the principal
        /// processing the claim does not identify itself with a value in the
        /// "aud" claim when this claim is present, then the JWT MUST be
        /// rejected.In the general case, the "aud" value is an array of
        /// case-sensitive strings, each containing a StringOrURI value. In the
        /// special case when the JWT has one audience, the "aud" value MAY be a
        /// single case-sensitive string containing a StringOrURI value.The
        /// interpretation of audience values is generally application specific.
        /// Use of this claim is OPTIONAL.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3">"aud" (Audience) Claim</see>.</remarks>
        public static readonly string Aud = "aud";

        /// <summary>
        /// The "exp" (expiration time) claim identifies the expiration time on
        /// or after which the JWT MUST NOT be accepted for processing. The
        /// processing of the "exp" claim requires that the current date/time
        /// MUST be before the expiration date/time listed in the "exp" claim.
        /// Implementers MAY provide for some small leeway, usually no more than
        /// a few minutes, to account for clock skew.Its value MUST be a number
        /// containing a NumericDate value. Use of this claim is OPTIONAL.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4">"exp" (Expiration Time) Claim</see>.</remarks>
        public static readonly string Exp = "exp";

        /// <summary>
        /// The "nbf" (not before) claim identifies the time before which the JWT
        /// MUST NOT be accepted for processing.The processing of the "nbf"
        /// claim requires that the current date/time MUST be after or equal to
        /// the not-before date/time listed in the "nbf" claim.Implementers MAY
        /// provide for some small leeway, usually no more than a few minutes, to
        /// account for clock skew.Its value MUST be a number containing a
        /// NumericDate value. Use of this claim is OPTIONAL.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.5">"nbf" (Not Before) Claim</see>.</remarks>
        public static readonly string Nbf = "nbf";

        /// <summary>
        /// The "iat" (issued at) claim identifies the time at which the JWT was
        /// issued.This claim can be used to determine the age of the JWT. Its
        /// value MUST be a number containing a NumericDate value. Use of this
        /// claim is OPTIONAL.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6">"iat" (Issued At) Claim</see>.</remarks>
        public static readonly string Iat = "iat";

        /// <summary>
        /// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
        /// The identifier value MUST be assigned in a manner that ensures that
        /// there is a negligible probability that the same value will be
        /// accidentally assigned to a different data object; if the application
        /// uses multiple issuers, collisions MUST be prevented among values
        /// produced by different issuers as well.The "jti" claim can be used
        /// to prevent the JWT from being replayed.The "jti" value is a
        /// case-sensitive string. Use of this claim is OPTIONAL.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7">"nbf" (Not Before) Claim</see>.</remarks>
        public static readonly string Jti = "jti";

        /// <summary>
        /// End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
        /// </summary>
        /// <remarks>See more at <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0, Section 5.1 Standard Claims</see>.</remarks>
        public static readonly string Name = "name";

        /// <summary>
        /// The "vct" (verifiable credential type) claim identifies the type of the SD-JWT VC.
        /// </summary>
        /// <remarks>See more at <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.2.1.1">"vct" Claim</see>.</remarks>
        public static readonly string Vct = "vct";

        /// <summary>
        /// The "cnf" (confirmation) claim contains the confirmation method, typically
        /// the holder's public key for key binding.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1">"cnf" (Confirmation) Claim</see>.</remarks>
        public static readonly string Cnf = "cnf";


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Iss"/> or not.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns><see langword="true" /> if is <see cref="Iss"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsIssuer(string claim)
        {
            return Equals(Iss, claim);
        }


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Sub"/> or not.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns><see langword="true" /> if is <see cref="Sub"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsSub(string claim)
        {
            return Equals(Sub, claim);
        }


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Aud"/> or not.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns><see langword="true" /> if is <see cref="Aud"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsAud(string claim)
        {
            return Equals(Aud, claim);
        }


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Exp"/> or not.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns><see langword="true" /> if is <see cref="Exp"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsExp(string claim)
        {
            return Equals(Exp, claim);
        }


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Nbf"/> or not.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns><see langword="true" /> if is <see cref="Nbf"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsNbf(string claim)
        {
            return Equals(Nbf, claim);
        }


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Iat"/> or not.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns><see langword="true" /> if is <see cref="Iat"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsIat(string claim)
        {
            return Equals(Iat, claim);
        }


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Jti"/> or not.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns><see langword="true" /> if is <see cref="Jti"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsJti(string claim)
        {
            return Equals(Jti, claim);
        }


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Name"/> or not.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns><see langword="true" /> if is <see cref="Name"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsName(string claim)
        {
            return Equals(Name, claim);
        }


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Vct"/> or not.
        /// </summary>
        /// <param name="claim">The claim to check.</param>
        /// <returns><see langword="true" /> if is <see cref="Vct"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsVct(string claim)
        {
            return Equals(Vct, claim);
        }


        /// <summary>
        /// If <paramref name="claim"/> is <see cref="Cnf"/> or not.
        /// </summary>
        /// <param name="claim">The claim to check.</param>
        /// <returns><see langword="true" /> if is <see cref="Cnf"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsCnf(string claim)
        {
            return Equals(Cnf, claim);
        }


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="claim">The claim to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="claim"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string claim) => claim switch
        {
            string _ when IsIssuer(claim) => Iss,
            string _ when IsSub(claim) => Sub,
            string _ when IsAud(claim) => Aud,
            string _ when IsExp(claim) => Exp,
            string _ when IsNbf(claim) => Nbf,
            string _ when IsIat(claim) => Iat,
            string _ when IsJti(claim) => Jti,
            string _ when IsJti(claim) => Name,
            string _ when IsVct(claim) => Vct,
            string _ when IsCnf(claim) => Cnf,
            string _ => claim
        };

        /// <summary>
        /// Returns a value that indicates if the claims are the same.
        /// </summary>
        /// <param name="claimA">The first claim to compare.</param>
        /// <param name="claimB">The second claim to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the claims are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string claimA, string claimB)
        {
            return object.ReferenceEquals(claimA, claimB) || StringComparer.InvariantCulture.Equals(claimA, claimB);
        }
    }
}
