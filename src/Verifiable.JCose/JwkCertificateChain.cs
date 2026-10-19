using System.Buffers.Text;
using System.Formats.Asn1;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>Why a JWK's <c>x5c</c> member is refused under RFC 7517 section 4.7.</summary>
public enum JwkCertificateChainDefect
{
    /// <summary>
    /// The member is no non-empty array of base64 text: "Each string in the array is a base64-encoded (Section 4 of [RFC4648] --
    /// not base64url-encoded) DER [ITU.X690.2008] PKIX certificate value", an empty string, base64url text and text carrying a
    /// character outside the base64 alphabet, whitespace among them (RFC 4648 section 3.3), all refused.
    /// </summary>
    NotBase64Text,

    /// <summary>
    /// An element decodes to bytes that are no DER X.509 certificate of the structure RFC 5280 section 4.1 admits, read as far as
    /// <see cref="JwkCertificateChain"/> reads one.
    /// </summary>
    NotACertificate,

    /// <summary>
    /// The first certificate's subject public key is established not to be the key the JWK's other members represent: "The key
    /// in the first certificate MUST match the public key represented by other members of the JWK." The JWK's members state a key
    /// of a type the judgement compares, and the certificate carries another key, a key of another type, or the JWK's members
    /// state no key of their type at all (EC coordinates naming no point of the curve, a member that is no base64url text).
    /// </summary>
    FirstCertificateNotOfTheKey,

    /// <summary>
    /// The JWK's key is of a type, curve or algorithm whose agreement with a certificate's key the judgement does not compare -
    /// a JWK naming no key type or an unknown one, an EC key on a curve it names none of, an OKP key other than Ed25519, an AKP
    /// key of no ML-DSA parameter set - so whether the first certificate is the key is not established, which is no mismatch.
    /// </summary>
    KeyComparisonUnsupported
}


/// <summary>
/// The judgement of a JWK's <c>x5c</c> member (RFC 7517 section 4.7) against the key the JWK's other members represent: every
/// element base64 text (RFC 4648 section 4, no character outside the alphabet) decoding to one DER X.509 certificate, read
/// structurally as far as the library's certificate parse reads one - its version, its algorithm identifiers and their
/// agreement, its names, its validity and its subject public key info with the parameters of its algorithm (RFC 5280 section
/// 4.1, RFC 8410 section 3) - and the first one's subject public key (RFC 5280 section 4.1.2.7) the very key the JWK states: the
/// same curve and point of an EC key whose coordinates are of the curve's width and name a point of it (RFC 7518 section 6.2),
/// the same modulus and exponent of an RSA key (section 6.3), the same Ed25519 public key of an OKP key (RFC 8037 section 2), the
/// same parameter set and public key of an AKP key.
/// </summary>
/// <remarks>
/// The certification of each certificate by the next ("Each subsequent certificate MUST be the one used to certify the previous
/// one"), each certificate's signature and its extensions' meaning are matters of trust in the chain, which this judgement
/// neither establishes nor implies: a recipient trusting the chain validates it through the certificate-chain seam
/// (<see cref="ValidateCertificateChainAsyncDelegate"/>) against its own trust anchors.
/// </remarks>
public static class JwkCertificateChain
{
    /// <summary>
    /// Why a JWK's <c>x5c</c> breaks RFC 7517 section 4.7, or <see langword="null"/> when every element is base64 text of a DER
    /// certificate and the first one's key is the JWK's.
    /// </summary>
    /// <param name="certificates">The elements of the <c>x5c</c> array, as the JWK carries them.</param>
    /// <param name="keyMembers">The JWK's string members, the key's type, curve and coordinates among them.</param>
    /// <returns>The defect, or <see langword="null"/>.</returns>
    public static JwkCertificateChainDefect? DefectOf(IReadOnlyList<string> certificates, IReadOnlyDictionary<string, string> keyMembers)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(keyMembers);

        if(certificates.Count == 0)
        {
            return JwkCertificateChainDefect.NotBase64Text;
        }

        ManagedCertificate? first = null;

        foreach(var certificate in certificates)
        {
            if(!IsBase64Text(certificate))
            {
                return JwkCertificateChainDefect.NotBase64Text;
            }

            if(CertificateOf(Convert.FromBase64String(certificate)) is not { } parsed)
            {
                return JwkCertificateChainDefect.NotACertificate;
            }

            first ??= parsed;
        }

        return first is null ? JwkCertificateChainDefect.NotBase64Text : KeyDefectOf(first, keyMembers);
    }


    /// <summary>
    /// Whether a text is base64 (RFC 4648 section 4): a non-empty whole number of four-character quanta of the base64 alphabet,
    /// the last quantum padded with at most two <c>=</c>, and no other character - RFC 4648 section 3.3: "Implementations MUST
    /// reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data, unless
    /// the specification referring to this document explicitly states otherwise", and RFC 7517 section 4.7 states no such
    /// allowance, so whitespace and line breaks are refused as any other character outside the alphabet.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns><see langword="true"/> for base64 text.</returns>
    private static bool IsBase64Text(string text)
    {
        if(text.Length == 0 || text.Length % 4 != 0)
        {
            return false;
        }

        var padding = text[^1] != '=' ? 0 : text[^2] != '=' ? 1 : 2;

        for(var index = 0; index < text.Length - padding; index++)
        {
            if(!IsBase64AlphabetCharacter(text[index]))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Whether a character is of the base64 alphabet (RFC 4648 section 4, table 1).</summary>
    /// <param name="character">The character.</param>
    /// <returns><see langword="true"/> for a character of the alphabet.</returns>
    private static bool IsBase64AlphabetCharacter(char character) =>
        character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '+' or '/';


    /// <summary>
    /// Whether a text is base64url as JOSE writes it (RFC 7515 section 2: the URL- and filename-safe alphabet of RFC 4648 section
    /// 5, "with all trailing '=' characters omitted ... and without the inclusion of any line breaks, whitespace, or other
    /// additional characters"): a non-empty text of that alphabet whose length is no whole number of quanta plus one character.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns><see langword="true"/> for base64url text.</returns>
    private static bool IsBase64UrlText(string text) =>
        text.Length > 0 && text.Length % 4 != 1 && text.All(static character => character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_');


    /// <summary>
    /// The structural parse of one DER certificate, or <see langword="null"/> for bytes that are none: the parser's refusal of
    /// the encoding, its <see cref="AsnContentException"/>, or of an RSA key's encoding, its <see cref="RsaPublicKeyException"/>.
    /// </summary>
    /// <param name="der">The decoded bytes.</param>
    /// <returns>The certificate, or <see langword="null"/>.</returns>
    private static ManagedCertificate? CertificateOf(byte[] der)
    {
        try
        {
            return ManagedCertificate.Parse(der);
        }
        catch(Exception exception) when(exception is AsnContentException or RsaPublicKeyException)
        {
            return null;
        }
    }


    /// <summary>
    /// Why a certificate's subject public key is not established to be the key a JWK's members represent, judged by the key's
    /// type, or <see langword="null"/> when the two are one key.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <returns>The defect, or <see langword="null"/>.</returns>
    private static JwkCertificateChainDefect? KeyDefectOf(ManagedCertificate certificate, IReadOnlyDictionary<string, string> keyMembers)
    {
        if(!keyMembers.TryGetValue(WellKnownJwkMemberNames.Kty, out var kty))
        {
            return JwkCertificateChainDefect.KeyComparisonUnsupported;
        }

        return kty switch
        {
            var type when WellKnownKeyTypeValues.IsEc(type) => EllipticCurveKeyDefectOf(certificate, keyMembers),
            var type when WellKnownKeyTypeValues.IsRsa(type) => MismatchUnless(IsRsaKey(certificate, keyMembers)),
            var type when WellKnownKeyTypeValues.IsOkp(type) => OctetKeyPairKeyDefectOf(certificate, keyMembers),
            var type when WellKnownKeyTypeValues.IsAkp(type) => AlgorithmKeyPairKeyDefectOf(certificate, keyMembers),
            _ => JwkCertificateChainDefect.KeyComparisonUnsupported
        };
    }


    /// <summary>The established mismatch unless a comparison found the two keys one.</summary>
    /// <param name="isTheKey">Whether the comparison found the certificate's key the JWK's.</param>
    /// <returns>The defect, or <see langword="null"/>.</returns>
    private static JwkCertificateChainDefect? MismatchUnless(bool isTheKey) => isTheKey ? null : JwkCertificateChainDefect.FirstCertificateNotOfTheKey;


    /// <summary>
    /// Whether a certificate carries the EC key a JWK states (RFC 7518 section 6.2.1): the JWK's curve one the judgement names,
    /// its <c>x</c> and <c>y</c> each the full width of the curve's coordinate and naming a point of the curve (RFC 7518 sections
    /// 6.2.1.2 and 6.2.1.3, NIST SP 800-186 appendix D.1.1.1), and the certificate an <c>id-ecPublicKey</c> on that curve whose
    /// point, uncompressed or compressed as it encodes it (SEC 1 section 2.3.3), is <c>0x04 || x || y</c> once brought to the
    /// uncompressed form. Coordinates naming no point of the curve state no key, which no certificate's key is.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <returns>The defect, or <see langword="null"/>.</returns>
    private static JwkCertificateChainDefect? EllipticCurveKeyDefectOf(ManagedCertificate certificate, IReadOnlyDictionary<string, string> keyMembers)
    {
        if(!keyMembers.TryGetValue(WellKnownJwkMemberNames.Crv, out var crv) || CurveOf(crv) is not { } curve)
        {
            return JwkCertificateChainDefect.KeyComparisonUnsupported;
        }

        if(DecodedMember(keyMembers, WellKnownJwkMemberNames.X) is not { } x
            || DecodedMember(keyMembers, WellKnownJwkMemberNames.Y) is not { } y
            || !EllipticCurveUtilities.CheckPointOnCurve(x, y, curve)
            || !string.Equals(certificate.SubjectPublicKeyAlgorithmOid, WellKnownOids.EcPublicKey, StringComparison.Ordinal)
            || certificate.EllipticCurve != curve)
        {
            return JwkCertificateChainDefect.FirstCertificateNotOfTheKey;
        }

        //The certificate's parse admitted the point as an uncompressed or compressed SEC1 point of the curve's width naming a point
        //of it, so either form is brought to the uncompressed one and compared with the JWK's coordinates.
        var point = EllipticCurveUtilities.NormalizeToUncompressed(certificate.PublicPoint.Span, curve);

        return MismatchUnless(point.Length == 1 + x.Length + y.Length
            && point.AsSpan(1, x.Length).SequenceEqual(x)
            && point.AsSpan(1 + x.Length).SequenceEqual(y));
    }


    /// <summary>
    /// Whether a certificate carries the RSA key a JWK states (RFC 7518 section 6.3.1): an <c>rsaEncryption</c> key of the same
    /// modulus and public exponent, each compared as the unsigned integer it is, leading zero octets aside.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <returns><see langword="true"/> when the certificate carries the key.</returns>
    private static bool IsRsaKey(ManagedCertificate certificate, IReadOnlyDictionary<string, string> keyMembers) =>
        DecodedMember(keyMembers, WellKnownJwkMemberNames.N) is { } modulus
        && DecodedMember(keyMembers, WellKnownJwkMemberNames.E) is { } exponent
        && string.Equals(certificate.SubjectPublicKeyAlgorithmOid, WellKnownOids.RsaEncryption, StringComparison.Ordinal)
        && WithoutLeadingZeros(certificate.RsaModulus.Span).SequenceEqual(WithoutLeadingZeros(modulus))
        && WithoutLeadingZeros(certificate.RsaExponent.Span).SequenceEqual(WithoutLeadingZeros(exponent));


    /// <summary>
    /// Whether a certificate carries the OKP key a JWK states (RFC 8037 section 2): for the <c>Ed25519</c> curve, an
    /// <c>id-Ed25519</c> key (RFC 8410 section 3) whose public key is the JWK's <c>x</c>. A key on another curve, or naming none,
    /// is one whose agreement with a certificate's the judgement does not compare.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <returns>The defect, or <see langword="null"/>.</returns>
    private static JwkCertificateChainDefect? OctetKeyPairKeyDefectOf(ManagedCertificate certificate, IReadOnlyDictionary<string, string> keyMembers)
    {
        if(!keyMembers.TryGetValue(WellKnownJwkMemberNames.Crv, out var crv) || !WellKnownCurveValues.IsEd25519(crv))
        {
            return JwkCertificateChainDefect.KeyComparisonUnsupported;
        }

        return MismatchUnless(DecodedMember(keyMembers, WellKnownJwkMemberNames.X) is { } x
            && string.Equals(certificate.SubjectPublicKeyAlgorithmOid, WellKnownOids.EdDSA25519, StringComparison.Ordinal)
            && certificate.SubjectPublicKeyBitStringContent.Span.SequenceEqual(x));
    }


    /// <summary>
    /// Whether a certificate carries the AKP key a JWK states: the ML-DSA parameter set the JWK's <c>alg</c> names and the public
    /// key its <c>pub</c> carries. A key of an algorithm that is no ML-DSA parameter set, or naming none, is one whose agreement
    /// with a certificate's the judgement does not compare.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <returns>The defect, or <see langword="null"/>.</returns>
    private static JwkCertificateChainDefect? AlgorithmKeyPairKeyDefectOf(ManagedCertificate certificate, IReadOnlyDictionary<string, string> keyMembers)
    {
        if(!keyMembers.TryGetValue(WellKnownJwkMemberNames.Alg, out var alg) || MlDsaParameterSetOf(alg) is not { } parameterSet)
        {
            return JwkCertificateChainDefect.KeyComparisonUnsupported;
        }

        return MismatchUnless(DecodedMember(keyMembers, WellKnownJwkMemberNames.Pub) is { } publicKey
            && string.Equals(certificate.MlDsaAlgorithmOid, parameterSet, StringComparison.Ordinal)
            && certificate.MlDsaPublicKey.Span.SequenceEqual(publicKey));
    }


    /// <summary>The curve a JWK's <c>crv</c> names among those a certificate's EC key is recognised on, or <see langword="null"/>.</summary>
    /// <param name="crv">The curve's name.</param>
    /// <returns>The curve, or <see langword="null"/>.</returns>
    private static EllipticCurveTypes? CurveOf(string crv) => crv switch
    {
        var name when WellKnownCurveValues.IsP256(name) => EllipticCurveTypes.P256,
        var name when WellKnownCurveValues.IsP384(name) => EllipticCurveTypes.P384,
        var name when WellKnownCurveValues.IsP521(name) => EllipticCurveTypes.P521,
        var name when WellKnownCurveValues.IsSecp256k1(name) => EllipticCurveTypes.Secp256k1,
        var name when WellKnownCurveValues.IsBrainpoolP224r1(name) => EllipticCurveTypes.BrainpoolP224r1,
        var name when WellKnownCurveValues.IsBrainpoolP256r1(name) => EllipticCurveTypes.BrainpoolP256r1,
        var name when WellKnownCurveValues.IsBrainpoolP320r1(name) => EllipticCurveTypes.BrainpoolP320r1,
        var name when WellKnownCurveValues.IsBrainpoolP384r1(name) => EllipticCurveTypes.BrainpoolP384r1,
        var name when WellKnownCurveValues.IsBrainpoolP512r1(name) => EllipticCurveTypes.BrainpoolP512r1,
        _ => null
    };


    /// <summary>The object identifier of the ML-DSA parameter set a JWK's <c>alg</c> names, or <see langword="null"/>.</summary>
    /// <param name="alg">The algorithm's name.</param>
    /// <returns>The identifier, or <see langword="null"/>.</returns>
    private static string? MlDsaParameterSetOf(string alg) => alg switch
    {
        var name when WellKnownJwaValues.IsMlDsa44(name) => WellKnownOids.MlDsa44,
        var name when WellKnownJwaValues.IsMlDsa65(name) => WellKnownOids.MlDsa65,
        var name when WellKnownJwaValues.IsMlDsa87(name) => WellKnownOids.MlDsa87,
        _ => null
    };


    /// <summary>
    /// The bytes a JWK member's base64url text names (RFC 7518 section 2, RFC 7515 section 2), or <see langword="null"/> when
    /// absent or no such text, whitespace and padding among what it is not.
    /// </summary>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <param name="name">The member's name.</param>
    /// <returns>The bytes, or <see langword="null"/>.</returns>
    private static byte[]? DecodedMember(IReadOnlyDictionary<string, string> keyMembers, string name) =>
        keyMembers.TryGetValue(name, out var text) && IsBase64UrlText(text) ? Base64Url.DecodeFromChars(text) : null;


    /// <summary>An unsigned big-endian integer's octets without its leading zero octets.</summary>
    /// <param name="octets">The octets.</param>
    /// <returns>The octets from the first nonzero one.</returns>
    private static ReadOnlySpan<byte> WithoutLeadingZeros(ReadOnlySpan<byte> octets)
    {
        var start = 0;

        while(start < octets.Length && octets[start] == 0)
        {
            start++;
        }

        return octets[start..];
    }
}
