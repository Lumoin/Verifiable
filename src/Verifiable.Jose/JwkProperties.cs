namespace Verifiable.Jose
{
    /// <summary>
    /// Class containing the well-known names of JSON Web Key (JWK) parameters.
    /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7517">JSON Web Key (JWK)</see>
    /// and <see href="https://www.iana.org/assignments/jwt/jwt.xhtml">JSON Web Token (JWT)</see>.
    /// </summary>
    /// <remarks>As per definition parameters are case-sensitive.</remarks>
    public static class JwkProperties
    {
        /// <summary>
        /// The "alg" (algorithm) parameter identifies the algorithm intended for
        /// use with the key. The values used should either be registered in the
        /// IANA "JSON Web Signature and Encryption Algorithms" registry
        /// established by <see href="https://www.rfc-editor.org/rfc/rfc7518">JSON Web Algorithms (JWA)</see>
        /// or be a value that contains a Collision-Resistant Name.
        /// The "alg" value is a case-sensitive ASCII string.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.4">"alg" (Algorithm) Parameter</see>.</remarks>
        public static readonly string Alg = "alg";

        /// <summary>
        /// The "acr" (Authentication Context Class Reference) claim is used to specify the class reference of authentication context.
        /// </summary>
        /// <remarks>
        /// This is a proprietary property.
        /// The description of these claims can vary based on the usage scenario and the application that uses them.
        /// </remarks>
        public static readonly string Acr = "acr";

        /// <summary>
        /// The "amr" (Authentication Methods References) claim is used to specify the methods used in the authentication process.
        /// </summary>
        /// <remarks>
        /// This is a proprietary property.
        /// The description of these claims can vary based on the usage scenario and the application that uses them.
        /// </remarks>
        public static readonly string Amr = "amr";

        /// <summary>
        /// The "aud" (Audience) claim identifies the recipients that the JWT is intended for.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">"aud" (Audience) Claim</see>.
        /// </remarks>
        public static readonly string Aud = "aud";

        /// <summary>
        /// The "azp" (Authorized party) claim is used to specify the party to which the ID Token was issued.
        /// </summary>
        /// <remarks>
        /// This is a proprietary property.
        /// The description of these claims can vary based on the usage scenario and the application that uses them.
        /// </remarks>
        public static readonly string Azp = "azp";

        /// <summary>
        /// The "crv" (curve) parameter identifies the cryptographic curve used with the key.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1">"crv" (Curve) Parameter</see>.
        /// </remarks>
        public static readonly string Crv = "crv";

        /// <summary>
        ///  The "cty" (content type) Header Parameter defined by <see href="https://www.rfc-editor.org/rfc/rfc7515">JWS</see>
        ///  and <see href="https://www.rfc-editor.org/rfc/rfc7516">JWS</see>
        ///  is used by this specification to convey structural information about the JWT.
        ///
        ///  In the normal case in which nested signing or encryption operations
        ///  are not employed, the use of this Header Parameter is NOT
        ///  RECOMMENDED.  In the case that nested signing or encryption is
        ///  employed, this Header Parameter MUST be present; in this case, the
        ///  value MUST be "JWT", to indicate that a Nested JWT is carried in this
        ///  JWT. While media type names are not case sensitive, it is
        ///  RECOMMENDED that "JWT" always be spelled using uppercase characters
        ///  for compatibility with legacy implementations.
        ///  See <see href="https://www.rfc-editor.org/rfc/rfc7519.html#appendix-A.2">Appendix A.2 for an example of a Nested JWT</see>.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7519.html#section-5.1">"cty" (Content Type) Header Parameter</see>.</remarks>
        public static readonly string Cty = "cty";

        /// <summary>
        /// The "d" (ECC Private Key) parameter contains the Elliptic Curve private key.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.2">"d" (ECC Private Key) Parameter</see>.
        /// </remarks>
        public static readonly string D = "d";

        /// <summary>
        /// The "dp" (RSA Private Key Parameter) contains the first factor CRT exponent.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.6">"dp" (RSA Private Key Parameter)</see>.
        /// </remarks>
        public static readonly string Dp = "dp";

        /// <summary>
        /// The "dq" (RSA Private Key Parameter) contains the second factor CRT exponent.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7">"dq" (RSA Private Key Parameter)</see>.
        /// </remarks>
        public static readonly string Dq = "dq";

        /// <summary>
        /// The "e" (RSA Public Key Parameter) contains the public exponent of an RSA key.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2">"e" (RSA Public Key Parameter)</see>.
        /// </remarks>
        public static readonly string E = "e";

        /// <summary>
        /// The "exp" (Expiration Time) claim identifies the expiration time on or after which the JWT must not be accepted for processing.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">"exp" (Expiration Time) Claim</see>.
        /// </remarks>
        public static readonly string Exp = "exp";

        /// <summary>
        /// The "iat" (Issued At) claim identifies the time at which the JWT was issued.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6">"iat" (Issued At) Claim</see>.
        /// </remarks>
        public static readonly string Iat = "iat";

        /// <summary>
        /// The "iss" (Issuer) claim identifies the principal that issued the JWT.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">"iss" (Issuer) Claim</see>.
        /// </remarks>
        public static readonly string Iss = "iss";

        /// <summary>
        /// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
        /// </summary>
        /// <remarks>
        /// The identifier value MUST be assigned in a manner that ensures that
        /// there is a negligible probability that the same value will be
        /// accidentally assigned to a different data object.
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">"jti" (JWT ID) Claim</see>.
        /// </remarks>
        public static readonly string Jti = "jti";

        /// <summary>
        /// The "k" (Symmetric Key Value) parameter contains the value of the symmetric (or other single-value) key.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1">"k" (Symmetric Key Value) Parameter</see>.
        /// </remarks>
        public static readonly string K = "k";

        /// <summary>
        /// The "key_ops" (key operations) parameter identifies the operation(s)
        /// for which the key is intended to be used. The "key_ops" parameter is
        /// intended for use cases in which public, private, or symmetric keys
        /// may be present. The "use" value is a case-sensitive string.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">"key_ops" (Key Operations) Parameter</see>.</remarks>
        public static readonly string KeyOps = "key_ops";

        /// <summary>
        /// The "kid" (key ID) parameter is used to match a specific key. This
        /// is used, for instance, to choose among a set of keys within a JWK Set
        /// during key rollover. The structure of the "kid" value is
        /// unspecified.When "kid" values are used within a JWK Set, different
        /// keys within the JWK Set SHOULD use distinct "kid" values.  (One
        /// example in which different keys might use the same "kid" value is if
        /// they have different "kty" (key type) values but are considered to be
        /// equivalent alternatives by the application using them.)  The "kid"
        /// value is a case-sensitive string.  Use of this member is OPTIONAL.
        /// When used with JWS or JWE, the "kid" value is used to match a JWS or
        /// JWE "kid" Header Parameter value.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</see>.</remarks>
        public static readonly string Kid = "kid";

        /// <summary>
        /// The "kty" (key type) parameter identifies the cryptographic algorithm family
        /// used with the key, such as <c>RSA</c> or "EC". "kty" values should either be
        /// registered in the IANA "JSON Web Key Types" registry established by
        /// <see href="https://www.rfc-editor.org/rfc/rfc7518">JSON Web Algorithms (JWA)</see>
        /// or be a value that contains a Collision-Resistant Name.
        /// The "kty" value is a case-sensitive string.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.1">"kty" (Key Type) Parameter</see>.</remarks>
        public static readonly string Kty = "kty";

        /// <summary>
        /// The "n" (RSA Public Key Parameter) contains the modulus for the RSA public key.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1">"n" (RSA Public Key Parameter)</see>.
        /// </remarks>
        public static readonly string N = "n";

        /// <summary>
        /// The "nbf" (Not Before) claim identifies the time before which the JWT must not be accepted for processing.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5">"nbf" (Not Before) Claim</see>.
        /// </remarks>
        public static string Nbf => "nbf";

        /// <summary>
        /// The "p" (RSA Private Key Parameter) contains the first prime factor.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.4">"p" (RSA Private Key Parameter)</see>.
        /// </remarks>
        public static readonly string P = "p";

        /// <summary>
        /// The "q" (RSA Private Key Parameter) contains the second prime factor.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.5">"q" (RSA Private Key Parameter)</see>.
        /// </remarks>
        public static readonly string Q = "q";

        /// <summary>
        /// The "qi" (RSA Private Key Parameter) contains the first CRT coefficient.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.8">"qi" (RSA Private Key Parameter)</see>.
        /// </remarks>
        public static readonly string Qi = "qi";

        /// <summary>
        /// The "roles" claim is commonly used to communicate roles that a principal has been granted.
        /// </summary>
        /// <remarks>
        /// This is a proprietary property.
        /// The description of these claims can vary based on the usage scenario and the application that uses them.
        /// </remarks>
        public static string Roles => "roles";

        /// <summary>
        /// The "sub" (Subject) claim identifies the principal that is the subject of the JWT.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">"sub" (Subject) Claim</see>.
        /// </remarks>
        public static string Sub => "sub";

        /// <summary>
        /// The "tenant" claim is commonly used in multitenant applications to specify the tenant for which the JWT is intended.
        /// </summary>
        /// <remarks>
        /// This is a proprietary property.
        /// The description of these claims can vary based on the usage scenario and the application that uses them.
        /// </remarks>
        public static string Tenant => "tenant";

        /// <summary>
        ///  The "typ" (type) Header Parameter defined by <see href="https://www.rfc-editor.org/rfc/rfc7515">JWS</see>
        ///  and <see href="https://www.rfc-editor.org/rfc/rfc7516">JWS</see>
        ///  is used by JWT applications to declare the media type
        ///  <see href="https://www.iana.org/assignments/media-types/media-types.xhtml">IANA.MediaTypes</see> of
        ///  his complete JWT.  This is intended for use by the JWT application
        ///  when values that are not JWTs could also be present in an application
        ///  data structure that can contain a JWT object; the application can use
        ///  this value to disambiguate among the different kinds of objects that
        ///  might be present.  It will typically not be used by applications when
        ///  it is already known that the object is a JWT.This parameter is
        ///  ignored by JWT implementations; any processing of this parameter is
        ///  performed by the JWT application.If present, it is RECOMMENDED that
        ///  its value be "JWT" to indicate that this object is a JWT.  While
        ///  media type names are not case sensitive, it is RECOMMENDED that "JWT"
        ///  always be spelled using uppercase characters for compatibility with
        ///  legacy implementations.Use of this Header Parameter is OPTIONAL.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7519.html#section-5.1">"typ" (Type) Header Parameter</see>.</remarks>
        public static readonly string Typ = "typ";

        /// <summary>
        /// The "use" (public key use) parameter identifies the intended use of
        /// the public key.The "use" parameter is employed to indicate whether
        /// a public key is used for encrypting data or verifying the signature
        /// on data. The "use" value is a case-sensitive string.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">"use" (Public Key Use) Parameter</see>.</remarks>
        public static readonly string Use = "use";

        /// <summary>
        /// The "x" (ECC Public Key Parameter) contains the x-coordinate for the Elliptic Curve point.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2">"x" (ECC Public Key Parameter)</see>.
        /// </remarks>
        public static readonly string X = "x";

        /// <summary>
        /// The "x5c" (X.509 certificate chain) parameter contains a chain of one
        /// or more PKIX certificates <see href="https://www.rfc-editor.org/rfc/rfc5280">RFC5280</see>.
        /// The certificate chain is represented as a JSON array of certificate value strings. Each string
        /// in the array is a base64-encoded (<see href="https://www.rfc-editor.org/rfc/rfc4648#section-4">Section 4 of[RFC4648]</see> --
        /// not base64url-encoded) DER[ITU.X690.1994] PKIX certificate value.
        /// The PKIX certificate containing the key value MUST be the first
        /// certificate.This MAY be followed by additional certificates, with
        /// each subsequent certificate being the one used to certify the
        /// previous one.The key in the first certificate MUST match the public
        /// key represented by other members of the JWK.Use of this member is OPTIONAL.
        ///
        /// As with the "x5u" member, optional JWK members providing key usage,
        /// algorithm, or other information MAY also be present when the "x5c"
        /// member is used.If other members are present, the contents of those
        /// members MUST be semantically consistent with the related fields in
        /// the first certificate.See the last paragraph of
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.6">Section 4.6</see>
        /// for additional guidance on this.
        /// </summary>
        /// <remarks>See more at <see href=""x5c" (X.509 Certificate Chain) Parameter">"x5c" (X.509 Certificate Chain) Parameter</see>.</remarks>
        public static readonly string X5c = "x5c";

        /// <summary>
        /// The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a
        /// base64url-encoded SHA-1 thumbprint(a.k.a.digest) of the DER
        /// encoding of an X.509 certificate <see href="https://www.rfc-editor.org/rfc/rfc5280">RFC5280</see>.
        /// Note that certificate thumbprints are also sometimes known as certificate fingerprints.
        /// The key in the certificate MUST match the public key represented by
        /// other members of the JWK.Use of this member is OPTIONAL.
        /// As with the "x5u" member, optional JWK members providing key usage,
        /// algorithm, or other information MAY also be present when the "x5t"
        /// member is used.If other members are present, the contents of those
        /// members MUST be semantically consistent with the related fields in
        /// the referenced certificate.See the last paragraph of Section 4.6
        /// for additional guidance on this.
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.8">"x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter</see>.</remarks>
        public static readonly string X5t = "x5t";

        /// <summary>
        /// The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a
        /// base64url-encoded SHA-256 thumbprint(a.k.a.digest) of the DER
        /// encoding of an X.509 certificate <see href="https://www.rfc-editor.org/rfc/rfc5280">RFC5280</see>.
        /// Note that certificate thumbprints are also sometimes known as certificate fingerprints.
        /// The key in the certificate MUST match the public key represented by
        /// other members of the JWK.Use of this member is OPTIONAL.
        /// As with the "x5u" member, optional JWK members providing key usage,
        /// algorithm, or other information MAY also be present when the
        /// "x5t#S256" member is used. If other members are present, the
        /// contents of those members MUST be semantically consistent with the
        /// related fields in the referenced certificate. See the last paragraph
        /// of <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.6">Section 4.6</see>
        /// for additional guidance on this.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.9">"x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter</see>.</remarks>
        public static readonly string X5tHashS256 = "x5t#S256";

        /// <summary>
        /// The "x5u" (X.509 URL) parameter is a URI <see href="https://www.rfc-editor.org/rfc/rfc3986">RFC3986</see> that refers to a
        /// resource for an X.509 public key certificate or certificate chain
        /// <see href="https://www.rfc-editor.org/rfc/rfc5280">RFC5280</see>.
        /// The identified resource MUST provide a representation of
        /// the certificate or certificate chain that conforms to <see href="https://www.rfc-editor.org/rfc/rfc5280">RFC5280</see>
        /// in PEM-encoded form, with each certificate delimited as
        /// specified in <see href="https://www.rfc-editor.org/rfc/rfc4945#section-6.1">Section 6.1 of RFC 4945</see>
        /// <see href="https://www.rfc-editor.org/rfc/rfc4945">RFC4945</see>. The key in the first
        /// certificate MUST match the public key represented by other members of
        /// the JWK.The protocol used to acquire the resource MUST provide
        /// integrity protection; an HTTP GET request to retrieve the certificate
        /// MUST use TLS <see href="https://www.rfc-editor.org/rfc/rfc2818">RFC2818</see> <see href="https://www.rfc-editor.org/rfc/rfc5246">RFC5246</see>;
        /// the identity of the server MUST be validated, as per <see href="https://www.rfc-editor.org/rfc/rfc6125#section-6">Section 6 of RFC 6125</see>
        /// <see href="https://www.rfc-editor.org/rfc/rfc6125#section-6">RFC6125</see>. Use of this member is OPTIONAL.
        ///
        /// While there is no requirement that optional JWK members providing key
        /// usage, algorithm, or other information be present when the "x5u"
        /// member is used, doing so may improve interoperability for
        /// applications that do not handle PKIX certificates <see href="https://www.rfc-editor.org/rfc/rfc5280">RFC5280</see>. If
        /// other members are present, the contents of those members MUST be
        /// semantically consistent with the related fields in the first
        /// certificate.For instance, if the "use" member is present, then it
        /// MUST correspond to the usage that is specified in the certificate,
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.6">"x5u" (X.509 URL) Parameter</see>.</remarks>
        public static readonly string X5u = "x5u";

        /// <summary>
        /// The "y" (ECC Public Key Parameter) contains the y-coordinate for the Elliptic Curve point.
        /// </summary>
        /// <remarks>
        /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3">"y" (ECC Public Key Parameter)</see>.
        /// </remarks>
        public static readonly string Y = "y";


        /// <summary>
        /// If <paramref name="property"/> is <see cref="Acr"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Acr"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsAcr(string property)
        {
            return Equals(Acr, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="Kty"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Kty"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsKty(string property)
        {
            return Equals(Kty, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="Use"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Use"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsUse(string property)
        {
            return Equals(Use, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="KeyOps"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="KeyOps"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsKeyOps(string property)
        {
            return Equals(KeyOps, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="Alg"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Alg"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsAlg(string property)
        {
            return Equals(Alg, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="Kid"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Kid"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsKid(string property)
        {
            return Equals(Kid, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="X5u"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="X5u"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsX5u(string property)
        {
            return Equals(X5u, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="X5c"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="X5c"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsX5c(string property)
        {
            return Equals(X5c, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="X5t"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="X5t"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsX5t(string property)
        {
            return Equals(X5t, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="X5tHashS256"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="X5tHashS256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsX5tHashS256(string property)
        {
            return Equals(X5tHashS256, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="Typ"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Typ"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsTyp(string property)
        {
            return Equals(Typ, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="Cty"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Cty"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsCty(string property)
        {
            return Equals(Cty, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Amr"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Amr"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsAmr(string property)
        {
            return Equals(Amr, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Aud"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Aud"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsAud(string property)
        {
            return Equals(Aud, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Azp"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Azp"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsAzp(string property)
        {
            return Equals(Azp, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Crv"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Crv"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsCrv(string property)
        {
            return Equals(Crv, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="D"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="D"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsD(string property)
        {
            return Equals(D, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Dp"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Dp"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsDp(string property)
        {
            return Equals(Dp, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Dq"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Dq"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsDq(string property)
        {
            return Equals(Dq, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="E"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="E"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsE(string property)
        {
            return Equals(E, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Exp"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Exp"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsExp(string property)
        {
            return Equals(Exp, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Iat"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Iat"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsIat(string property)
        {
            return Equals(Iat, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Iss"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Iss"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsIss(string property)
        {
            return Equals(Iss, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Jti"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Jti"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsJti(string property)
        {
            return Equals(Jti, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="K"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="K"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsK(string property)
        {
            return Equals(K, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="N"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="N"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsN(string property)
        {
            return Equals(N, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Nbf"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Nbf"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsNbf(string property)
        {
            return Equals(Nbf, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="P"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="P"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsP(string property)
        {
            return Equals(P, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Q"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Q"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsQ(string property)
        {
            return Equals(Q, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Qi"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Qi"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsQi(string property)
        {
            return Equals(Qi, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Roles"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Roles"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRoles(string property)
        {
            return Equals(Roles, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Sub"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Sub"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsSub(string property)
        {
            return Equals(Sub, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="Tenant"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Tenant"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsTenant(string property)
        {
            return Equals(Tenant, property);
        }

        /// <summary>
        /// If <paramref name="property"/> is <see cref="X"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="X"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsX(string property)
        {
            return Equals(X, property);
        }


        /// <summary>
        /// If <paramref name="property"/> is <see cref="Y"/> or not.
        /// </summary>
        /// <param name="property">The property</param>.
        /// <returns><see langword="true" /> if is <see cref="Y"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsY(string property)
        {
            return Equals(Y, property);
        }


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="property">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="property"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string property) => property switch
        {
            string _ when IsAcr(property) => Acr,
            string _ when IsAmr(property) => Amr,
            string _ when IsAud(property) => Aud,
            string _ when IsAzp(property) => Azp,
            string _ when IsCrv(property) => Crv,
            string _ when IsD(property) => D,
            string _ when IsDp(property) => Dp,
            string _ when IsDq(property) => Dq,
            string _ when IsE(property) => E,
            string _ when IsExp(property) => Exp,
            string _ when IsIat(property) => Iat,
            string _ when IsIss(property) => Iss,
            string _ when IsJti(property) => Jti,
            string _ when IsK(property) => K,
            string _ when IsKty(property) => Kty,
            string _ when IsUse(property) => Use,
            string _ when IsKeyOps(property) => KeyOps,
            string _ when IsAlg(property) => Alg,
            string _ when IsKid(property) => Kid,
            string _ when IsX5u(property) => X5u,
            string _ when IsX5c(property) => X5c,
            string _ when IsX5t(property) => X5t,
            string _ when IsX5tHashS256(property) => X5tHashS256,
            string _ when IsTyp(property) => Typ,
            string _ when IsCty(property) => Cty,
            string _ when IsN(property) => N,
            string _ when IsNbf(property) => Nbf,
            string _ when IsP(property) => P,
            string _ when IsQ(property) => Q,
            string _ when IsQi(property) => Qi,
            string _ when IsRoles(property) => Roles,
            string _ when IsSub(property) => Sub,
            string _ when IsTenant(property) => Tenant,
            string _ when IsX(property) => X,
            string _ when IsY(property) => Y,
            string _ => property
        };



        /// <summary>
        /// Returns a value that indicates if the properties are the same.
        /// </summary>
        /// <param name="propertyA">The first claim to compare.</param>
        /// <param name="propertyB">The second claim to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the claims are the same; otherwise, <see langword="false" />.
        /// </returns>
        /// <remarks>This comparison is case-sensitive. See at <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>.</remarks>
        public static bool Equals(string propertyA, string propertyB)
        {
            return object.ReferenceEquals(propertyA, propertyB) || StringComparer.InvariantCulture.Equals(propertyA, propertyB);
        }
    }
}
