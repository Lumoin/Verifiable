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
    /// not base64url-encoded) DER [ITU.X690.2008] PKIX certificate value", an empty string or base64url text among them.
    /// </summary>
    NotBase64Text,

    /// <summary>An element decodes to bytes that are no DER X.509 certificate (RFC 5280 section 4.1).</summary>
    NotACertificate,

    /// <summary>
    /// The first certificate's subject public key is not the key the JWK's other members represent: "The key in the first
    /// certificate MUST match the public key represented by other members of the JWK." A key of a type or curve whose agreement
    /// with a certificate's key this library does not establish is refused under this defect as well, never accepted unjudged.
    /// </summary>
    FirstCertificateNotOfTheKey
}


/// <summary>
/// The judgement of a JWK's <c>x5c</c> member (RFC 7517 section 4.7) against the key the JWK's other members represent: every
/// element base64 text decoding to one DER X.509 certificate (RFC 5280 section 4.1), read structurally, and the first one's
/// subject public key (RFC 5280 section 4.1.2.7) the very key the JWK states - the same curve and point of an EC key (RFC 7518
/// section 6.2), the same modulus and exponent of an RSA key (section 6.3), the same Ed25519 public key of an OKP key (RFC 8037
/// section 2), the same parameter set and public key of an AKP key.
/// </summary>
/// <remarks>
/// The certification of each certificate by the next ("Each subsequent certificate MUST be the one used to certify the previous
/// one") is a matter of trust in the chain, which this judgement neither establishes nor implies: a recipient trusting the chain
/// validates it through the certificate-chain seam (<see cref="ValidateCertificateChainAsyncDelegate"/>) against its own trust
/// anchors.
/// </remarks>
public static class JwkCertificateChain
{
    /// <summary>
    /// Why a JWK's <c>x5c</c> breaks RFC 7517 section 4.7, or <see langword="null"/> when every element is a DER certificate and
    /// the first one's key is the JWK's.
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
            if(string.IsNullOrEmpty(certificate) || !Base64.IsValid(certificate))
            {
                return JwkCertificateChainDefect.NotBase64Text;
            }

            if(CertificateOf(Convert.FromBase64String(certificate)) is not { } parsed)
            {
                return JwkCertificateChainDefect.NotACertificate;
            }

            first ??= parsed;
        }

        return first is not null && IsCertificateOfTheKey(first, keyMembers) ? null : JwkCertificateChainDefect.FirstCertificateNotOfTheKey;
    }


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


    /// <summary>Whether a certificate's subject public key is the key a JWK's members represent, judged by the key's type.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <returns><see langword="true"/> when the two are one key.</returns>
    private static bool IsCertificateOfTheKey(ManagedCertificate certificate, IReadOnlyDictionary<string, string> keyMembers)
    {
        if(!keyMembers.TryGetValue(WellKnownJwkMemberNames.Kty, out var kty))
        {
            return false;
        }

        return kty switch
        {
            var type when WellKnownKeyTypeValues.IsEc(type) => IsEllipticCurveKey(certificate, keyMembers),
            var type when WellKnownKeyTypeValues.IsRsa(type) => IsRsaKey(certificate, keyMembers),
            var type when WellKnownKeyTypeValues.IsOkp(type) => IsOctetKeyPairKey(certificate, keyMembers),
            var type when WellKnownKeyTypeValues.IsAkp(type) => IsAlgorithmKeyPairKey(certificate, keyMembers),
            _ => false
        };
    }


    /// <summary>
    /// Whether a certificate carries the EC key a JWK states (RFC 7518 section 6.2.1): an <c>id-ecPublicKey</c> on the JWK's
    /// curve whose uncompressed point is <c>0x04 || x || y</c>.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <returns><see langword="true"/> when the certificate carries the key.</returns>
    private static bool IsEllipticCurveKey(ManagedCertificate certificate, IReadOnlyDictionary<string, string> keyMembers)
    {
        if(!keyMembers.TryGetValue(WellKnownJwkMemberNames.Crv, out var crv)
            || CurveOf(crv) is not { } curve
            || DecodedMember(keyMembers, WellKnownJwkMemberNames.X) is not { } x
            || DecodedMember(keyMembers, WellKnownJwkMemberNames.Y) is not { } y
            || !string.Equals(certificate.SubjectPublicKeyAlgorithmOid, WellKnownOids.EcPublicKey, StringComparison.Ordinal)
            || certificate.EllipticCurve != curve)
        {
            return false;
        }

        var point = certificate.PublicPoint.Span;

        return point.Length == 1 + x.Length + y.Length
            && point[0] == 0x04
            && point.Slice(1, x.Length).SequenceEqual(x)
            && point[(1 + x.Length)..].SequenceEqual(y);
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
    /// <c>id-Ed25519</c> key (RFC 8410 section 3) whose public key is the JWK's <c>x</c>; a key on another curve is none whose
    /// agreement this library establishes.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <returns><see langword="true"/> when the certificate carries the key.</returns>
    private static bool IsOctetKeyPairKey(ManagedCertificate certificate, IReadOnlyDictionary<string, string> keyMembers) =>
        keyMembers.TryGetValue(WellKnownJwkMemberNames.Crv, out var crv)
        && WellKnownCurveValues.IsEd25519(crv)
        && DecodedMember(keyMembers, WellKnownJwkMemberNames.X) is { } x
        && string.Equals(certificate.SubjectPublicKeyAlgorithmOid, WellKnownOids.EdDSA25519, StringComparison.Ordinal)
        && certificate.SubjectPublicKeyBitStringContent.Span.SequenceEqual(x);


    /// <summary>
    /// Whether a certificate carries the AKP key a JWK states: the ML-DSA parameter set the JWK's <c>alg</c> names and the
    /// public key its <c>pub</c> carries.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <returns><see langword="true"/> when the certificate carries the key.</returns>
    private static bool IsAlgorithmKeyPairKey(ManagedCertificate certificate, IReadOnlyDictionary<string, string> keyMembers) =>
        keyMembers.TryGetValue(WellKnownJwkMemberNames.Alg, out var alg)
        && MlDsaParameterSetOf(alg) is { } parameterSet
        && DecodedMember(keyMembers, WellKnownJwkMemberNames.Pub) is { } publicKey
        && string.Equals(certificate.MlDsaAlgorithmOid, parameterSet, StringComparison.Ordinal)
        && certificate.MlDsaPublicKey.Span.SequenceEqual(publicKey);


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


    /// <summary>The bytes a JWK member's base64url text names (RFC 7518 section 2), or <see langword="null"/> when absent or no such text.</summary>
    /// <param name="keyMembers">The JWK's string members.</param>
    /// <param name="name">The member's name.</param>
    /// <returns>The bytes, or <see langword="null"/>.</returns>
    private static byte[]? DecodedMember(IReadOnlyDictionary<string, string> keyMembers, string name) =>
        keyMembers.TryGetValue(name, out var text) && Base64Url.IsValid(text) ? Base64Url.DecodeFromChars(text) : null;


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
