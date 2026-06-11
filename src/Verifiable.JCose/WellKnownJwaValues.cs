using Verifiable.Cryptography.Text;


namespace Verifiable.JCose
{
    /// <summary>
    /// JSON Web Algorithms (JWA) as defined in <see href="https://www.rfc-editor.org/rfc/rfc7518">RFC 7518</see>.
    /// </summary>
    /// <remarks>As per definition parameters are case-sensitive.</remarks>
    public static class WellKnownJwaValues
    {
        /// <summary>The UTF-8 source literal of <see cref="None"/>.</summary>
        public static ReadOnlySpan<byte> NoneUtf8 => "none"u8;

        /// <summary>
        /// No digital signature or encryption applied.
        /// </summary>
        /// <remarks>
        /// Use of 'none' algorithm should be restricted to specific circumstances, as it implies that the JWTs are not signed or encrypted.
        /// This can expose security vulnerabilities by allowing unauthorized modifications.
        /// More details can be found in <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.6">RFC 7518 Section 3.6</see>.
        /// </remarks>
        public static readonly string None = Utf8Constants.ToInternedString(NoneUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Hs256"/>.</summary>
        public static ReadOnlySpan<byte> Hs256Utf8 => "HS256"u8;

        /// <summary>
        /// HMAC using SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.2">HMAC with SHA-2 Functions</see>.</remarks>
        public static readonly string Hs256 = Utf8Constants.ToInternedString(Hs256Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Hs384"/>.</summary>
        public static ReadOnlySpan<byte> Hs384Utf8 => "HS384"u8;

        /// <summary>
        /// HMAC using SHA-384.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.2">HMAC with SHA-2 Functions</see>.</remarks>
        public static readonly string Hs384 = Utf8Constants.ToInternedString(Hs384Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Hs512"/>.</summary>
        public static ReadOnlySpan<byte> Hs512Utf8 => "HS512"u8;

        /// <summary>
        /// HMAC using SHA-512.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.2">HMAC with SHA-2 Functions</see>.</remarks>
        public static readonly string Hs512 = Utf8Constants.ToInternedString(Hs512Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Es256"/>.</summary>
        public static ReadOnlySpan<byte> Es256Utf8 => "ES256"u8;

        /// <summary>
        /// ECDSA using P-256 and SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Es256 = Utf8Constants.ToInternedString(Es256Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Es384"/>.</summary>
        public static ReadOnlySpan<byte> Es384Utf8 => "ES384"u8;

        /// <summary>
        /// ECDSA using P-384 and SHA-384.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Es384 = Utf8Constants.ToInternedString(Es384Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Es512"/>.</summary>
        public static ReadOnlySpan<byte> Es512Utf8 => "ES512"u8;

        /// <summary>
        /// ECDSA using P-521 and SHA-512.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Es512 = Utf8Constants.ToInternedString(Es512Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Es256K"/>.</summary>
        public static ReadOnlySpan<byte> Es256KUtf8 => "ES256K"u8;

        /// <summary>
        /// ECDSA using secp256k1 and SHA-256.
        /// </summary>
        /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc8812#section-3.1">RFC 8812 §3.1</see>: the JWA <c>alg</c> name is <c>"ES256K"</c> (no trailing "1").</remarks>
        public static readonly string Es256K = Utf8Constants.ToInternedString(Es256KUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Ps256"/>.</summary>
        public static ReadOnlySpan<byte> Ps256Utf8 => "PS256"u8;

        /// <summary>
        /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Ps256 = Utf8Constants.ToInternedString(Ps256Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Ps384"/>.</summary>
        public static ReadOnlySpan<byte> Ps384Utf8 => "PS384"u8;

        /// <summary>
        /// RSASSA-PSS using SHA-256 and MGF1 with SHA-384.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Ps384 = Utf8Constants.ToInternedString(Ps384Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Ps512"/>.</summary>
        public static ReadOnlySpan<byte> Ps512Utf8 => "PS512"u8;

        /// <summary>
        /// RSASSA-PSS using SHA-256 and MGF1 with SHA-512.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Ps512 = Utf8Constants.ToInternedString(Ps512Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Rs256"/>.</summary>
        public static ReadOnlySpan<byte> Rs256Utf8 => "RS256"u8;

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">Digital Signature with RSASSA-PKCS1-v1_5</see>.</remarks>
        public static readonly string Rs256 = Utf8Constants.ToInternedString(Rs256Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Rs384"/>.</summary>
        public static ReadOnlySpan<byte> Rs384Utf8 => "RS384"u8;

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using using SHA-384.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">Digital Signature with RSASSA-PKCS1-v1_5</see>.</remarks>
        public static readonly string Rs384 = Utf8Constants.ToInternedString(Rs384Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Rs512"/>.</summary>
        public static ReadOnlySpan<byte> Rs512Utf8 => "RS512"u8;

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using using SHA-512.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">Digital Signature with RSASSA-PKCS1-v1_5</see>.</remarks>
        public static readonly string Rs512 = Utf8Constants.ToInternedString(Rs512Utf8);

        /// <summary>
        /// EdDSA using Ed25519.
        /// </summary>
        /// <remarks>
        /// See more at <a href="https://datatracker.ietf.org/doc/html/rfc8037">RFC 8037 - CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signaturesin JSON Object Signing and Encryption(JOSE)</a>.
        /// </remarks>

        /// <summary>The UTF-8 source literal of <see cref="EdDsa"/>.</summary>
        public static ReadOnlySpan<byte> EdDsaUtf8 => "EdDSA"u8;

        public static readonly string EdDsa = Utf8Constants.ToInternedString(EdDsaUtf8);


        /// <summary>The UTF-8 source literal of <see cref="Ecdha"/>.</summary>
        public static ReadOnlySpan<byte> EcdhaUtf8 => "ECDH-ES"u8;

        /// <summary>
        /// ECDH-ES key agreement.
        /// </summary>
        public static readonly string Ecdha = Utf8Constants.ToInternedString(EcdhaUtf8);

        /// <summary>The UTF-8 source literal of <see cref="MlDsa44"/>.</summary>
        public static ReadOnlySpan<byte> MlDsa44Utf8 => "ML-DSA-44"u8;

        /// <summary>
        /// ML-DSA-44 post-quantum digital signature (NIST FIPS 204, security level 2).
        /// </summary>
        /// <remarks>
        /// See <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">ML-DSA for JOSE and COSE</see>.
        /// </remarks>
        public static readonly string MlDsa44 = Utf8Constants.ToInternedString(MlDsa44Utf8);

        /// <summary>The UTF-8 source literal of <see cref="MlDsa65"/>.</summary>
        public static ReadOnlySpan<byte> MlDsa65Utf8 => "ML-DSA-65"u8;

        /// <summary>
        /// ML-DSA-65 post-quantum digital signature (NIST FIPS 204, security level 3).
        /// </summary>
        /// <remarks>
        /// See <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">ML-DSA for JOSE and COSE</see>.
        /// </remarks>
        public static readonly string MlDsa65 = Utf8Constants.ToInternedString(MlDsa65Utf8);

        /// <summary>The UTF-8 source literal of <see cref="MlDsa87"/>.</summary>
        public static ReadOnlySpan<byte> MlDsa87Utf8 => "ML-DSA-87"u8;

        /// <summary>
        /// ML-DSA-87 post-quantum digital signature (NIST FIPS 204, security level 5).
        /// </summary>
        /// <remarks>
        /// See <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">ML-DSA for JOSE and COSE</see>.
        /// </remarks>
        public static readonly string MlDsa87 = Utf8Constants.ToInternedString(MlDsa87Utf8);


        //RFC 9784 introduced fully-specified ECDSA in COSE that pins both curve and
        //hash in a single identifier. draft-ietf-jose-fully-specified-algorithms
        //(WG draft) defines the parallel JOSE alg strings — same spellings, used
        //in the JWS protected header. ESP* covers the NIST P-curves and is
        //functionally identical to the older ES* names; ESB* covers the Brainpool
        //r1 curves and has no ES* predecessor.

        /// <summary>The UTF-8 source literal of <see cref="Esb256"/>.</summary>
        public static ReadOnlySpan<byte> Esb256Utf8 => "ESB256"u8;

        /// <summary>
        /// Fully-specified ECDSA with Brainpool P-256r1 and SHA-256 (RFC 9784 + JOSE draft).
        /// </summary>
        public static readonly string Esb256 = Utf8Constants.ToInternedString(Esb256Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Esb320"/>.</summary>
        public static ReadOnlySpan<byte> Esb320Utf8 => "ESB320"u8;

        /// <summary>
        /// Fully-specified ECDSA with Brainpool P-320r1 and SHA-384 (RFC 9784 + JOSE draft).
        /// </summary>
        public static readonly string Esb320 = Utf8Constants.ToInternedString(Esb320Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Esb384"/>.</summary>
        public static ReadOnlySpan<byte> Esb384Utf8 => "ESB384"u8;

        /// <summary>
        /// Fully-specified ECDSA with Brainpool P-384r1 and SHA-384 (RFC 9784 + JOSE draft).
        /// </summary>
        public static readonly string Esb384 = Utf8Constants.ToInternedString(Esb384Utf8);

        /// <summary>The UTF-8 source literal of <see cref="Esb512"/>.</summary>
        public static ReadOnlySpan<byte> Esb512Utf8 => "ESB512"u8;

        /// <summary>
        /// Fully-specified ECDSA with Brainpool P-512r1 and SHA-512 (RFC 9784 + JOSE draft).
        /// </summary>
        public static readonly string Esb512 = Utf8Constants.ToInternedString(Esb512Utf8);


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="None"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="None"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsNone(string alg)
        {
            return Equals(None, alg);
        }

        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Hs256"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Hs256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsHs256(string alg)
        {
            return Equals(Hs256, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Hs384"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Hs384"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsHs384(string alg)
        {
            return Equals(Hs384, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Hs512"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Hs512"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsHs512(string alg)
        {
            return Equals(Hs512, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Es256"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Es256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEs256(string alg)
        {
            return Equals(Es256, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Es384"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Es384"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEs384(string alg)
        {
            return Equals(Es384, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Es512"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Es512"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEs512(string alg)
        {
            return Equals(Es512, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Es256K"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Es256K"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEs256K(string alg)
        {
            return Equals(Es256K, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Ps256"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Ps256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsPs256(string alg)
        {
            return Equals(Ps256, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Ps384"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Ps384"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsPs384(string alg)
        {
            return Equals(Ps384, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Ps512"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Ps512"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsPs512(string alg)
        {
            return Equals(Ps512, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Rs256"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Rs256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRs256(string alg)
        {
            return Equals(Rs256, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Rs384"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Rs384"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRs384(string alg)
        {
            return Equals(Rs384, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Rs512"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Rs512"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRs512(string alg)
        {
            return Equals(Rs512, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="EdDsa"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="alg"/> is <see cref="EdDsa"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEdDsa(string alg)
        {
            return Equals(EdDsa, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is any ECDSA variant — <see cref="Es256"/>,
        /// <see cref="Es384"/>, <see cref="Es512"/>, or <see cref="Es256K"/>.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="alg"/> is any ECDSA variant; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdsa(string alg)
        {
            return IsEs256(alg) || IsEs384(alg) || IsEs512(alg) || IsEs256K(alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Ecdha"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="alg"/> is <see cref="Ecdha"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdha(string alg)
        {
            return Equals(Ecdha, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="MlDsa44"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm.</param>
        /// <returns><see langword="true" /> if <paramref name="alg"/> is <see cref="MlDsa44"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsMlDsa44(string alg)
        {
            return Equals(MlDsa44, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="MlDsa65"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm.</param>
        /// <returns><see langword="true" /> if <paramref name="alg"/> is <see cref="MlDsa65"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsMlDsa65(string alg)
        {
            return Equals(MlDsa65, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="MlDsa87"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm.</param>
        /// <returns><see langword="true" /> if <paramref name="alg"/> is <see cref="MlDsa87"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsMlDsa87(string alg)
        {
            return Equals(MlDsa87, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is any ML-DSA variant.
        /// </summary>
        /// <param name="alg">The algorithm.</param>
        /// <returns><see langword="true" /> if <paramref name="alg"/> is any ML-DSA variant; otherwise, <see langword="false" />.</returns>
        public static bool IsMlDsa(string alg)
        {
            return IsMlDsa44(alg) || IsMlDsa65(alg) || IsMlDsa87(alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Esb256"/>.
        /// </summary>
        public static bool IsEsb256(string alg) => Equals(Esb256, alg);


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Esb320"/>.
        /// </summary>
        public static bool IsEsb320(string alg) => Equals(Esb320, alg);


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Esb384"/>.
        /// </summary>
        public static bool IsEsb384(string alg) => Equals(Esb384, alg);


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Esb512"/>.
        /// </summary>
        public static bool IsEsb512(string alg) => Equals(Esb512, alg);


        /// <summary>
        /// If <paramref name="alg"/> is any RFC 9784 Brainpool ECDSA variant.
        /// </summary>
        public static bool IsEsb(string alg) =>
            IsEsb256(alg) || IsEsb320(alg) || IsEsb384(alg) || IsEsb512(alg);


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="alg">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="alg"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string alg) => alg switch
        {
            string _ when IsNone(alg) => None,
            string _ when IsHs256(alg) => Hs256,
            string _ when IsHs384(alg) => Hs384,
            string _ when IsHs512(alg) => Hs512,
            string _ when IsEs256(alg) => Es256,
            string _ when IsEs384(alg) => Es384,
            string _ when IsEs512(alg) => Es512,
            string _ when IsEs256K(alg) => Es256K,
            string _ when IsPs256(alg) => Ps256,
            string _ when IsPs384(alg) => Ps384,
            string _ when IsPs512(alg) => Ps512,
            string _ when IsRs256(alg) => Rs256,
            string _ when IsRs384(alg) => Rs384,
            string _ when IsRs512(alg) => Rs512,
            string _ when IsEdDsa(alg) => EdDsa,
            string _ when IsMlDsa44(alg) => MlDsa44,
            string _ when IsMlDsa65(alg) => MlDsa65,
            string _ when IsMlDsa87(alg) => MlDsa87,
            string _ when IsEsb256(alg) => Esb256,
            string _ when IsEsb320(alg) => Esb320,
            string _ when IsEsb384(alg) => Esb384,
            string _ when IsEsb512(alg) => Esb512,
            string _ => alg
        };


        /// <summary>
        /// Returns a value that indicates if the algs are the same.
        /// </summary>
        /// <param name="algA">The first alg to compare.</param>
        /// <param name="algB">The second alg to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the <paramref name="algA"/> and <paramref name="algB"/> are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string algA, string algB)
        {
            return object.ReferenceEquals(algA, algB) || StringComparer.InvariantCulture.Equals(algA, algB);
        }
    }
}
