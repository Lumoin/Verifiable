using System;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using static Verifiable.Tests.TestInfrastructure.ApduWireFixtures;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates card-verifiable certificate (CVC) parsing (BSI TR-03110-3 §C.1): the body and signature are
/// split from the outer <c>7F21</c>, the profile identifier, Certification Authority Reference, public key,
/// Certificate Holder Reference, authorization template, and dates are read from the body, and the signed
/// region is the exact encoded body. Self-signed CVCA (full domain parameters), Document Verifier
/// (inherited curve), and RSA certificates are covered. The certificates are synthetic and owned so the
/// test is committable; the OpenPACE/BSI sample certificates are a local-only real-data cross-check.
/// </summary>
[TestClass]
internal sealed class CardVerifiableCertificateTests
{
    /// <summary>The brainpoolP256r1 field prime p (RFC 5639), the parameter that identifies the curve.</summary>
    private const string BrainpoolP256r1PrimeHex = "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377";

    /// <summary>The id-TA-ECDSA-SHA-256 public-key object identifier value bytes.</summary>
    private const string IdTaEcdsaSha256Hex = "04007F00070202020203";

    /// <summary>The id-TA-RSA-v1-5-SHA-256 public-key object identifier value bytes.</summary>
    private const string IdTaRsaPkcs1Sha256Hex = "04007F00070202020102";

    /// <summary>The id-AT (Authentication Terminal) Certificate Holder Authorization object identifier value bytes.</summary>
    private const string IdAuthenticationTerminalHex = "04007F000703010202";

    /// <summary>The id-IS (Inspection System) Certificate Holder Authorization object identifier value bytes.</summary>
    private const string IdInspectionSystemHex = "04007F000703010201";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public void ParsesSelfSignedEllipticCurveCvcaCertificate()
    {
        byte[] point = BuildUncompressedPoint(0x42);
        byte[] signature = Filled(64, 0xAB);
        byte[] body = Body(
            profileIdentifier: 0x00,
            certificationAuthorityReference: "UTCVCA00001",
            publicKey: EllipticCurvePublicKey(IdTaEcdsaSha256Hex, includeDomainParameters: true, point),
            certificateHolderReference: "UTCVCA00001",
            chat: Chat(IdAuthenticationTerminalHex, [0xFE, 0x0F, 0x01, 0xFF, 0xFF]),
            effectiveDate: Date(2024, 5, 17),
            expirationDate: Date(2027, 5, 16));
        byte[] certificate = Tlv(0x7F21, body, Tlv(0x5F37, signature));

        using CardVerifiableCertificate parsed = CardVerifiableCertificate.Parse(certificate, BaseMemoryPool.Shared);

        Assert.AreEqual(0x00, parsed.CertificateProfileIdentifier, "The certificate profile identifier is version 1 (0x00).");
        Assert.AreEqual("UTCVCA00001", parsed.CertificationAuthorityReference, "The Certification Authority Reference is read from tag 0x42.");
        Assert.AreEqual("UTCVCA00001", parsed.CertificateHolderReference, "A self-signed CVCA names itself as both reference.");
        Assert.AreEqual(new DateOnly(2024, 5, 17), parsed.EffectiveDate, "The effective date is the unpacked-BCD YYMMDD value.");
        Assert.AreEqual(new DateOnly(2027, 5, 16), parsed.ExpirationDate, "The expiration date is the unpacked-BCD YYMMDD value.");

        Assert.IsTrue(parsed.PublicKey.IsEllipticCurve, "The id-TA-ECDSA OID denotes an elliptic-curve key.");
        Assert.AreEqual(CvcSignatureScheme.EcdsaSha256, parsed.PublicKey.SignatureScheme, "The OID arc 0x03 selects ECDSA with SHA-256.");
        Assert.IsTrue(parsed.PublicKey.IncludesDomainParameters, "A self-signed CVCA certificate carries its domain parameters.");
        Assert.AreEqual(Convert.ToHexString(point), Convert.ToHexString(parsed.PublicKey.EllipticCurvePoint!.AsReadOnlySpan()),
            "The parsed public point equals the tag 0x86 value.");
        Assert.IsTrue(parsed.PublicKey.EllipticCurvePoint!.Tag.TryGet(out CryptoAlgorithm curve), "The public point carries a curve algorithm.");
        Assert.IsTrue(curve == CryptoAlgorithm.BrainpoolP256r1, "The prime resolves the curve to brainpoolP256r1.");

        Assert.AreEqual(TerminalType.AuthenticationTerminal, parsed.Chat.TerminalType, "The CHAT object identifier selects an Authentication Terminal.");
        Assert.AreEqual(CertificateRole.CertificationAuthority, parsed.Chat.Role, "The role bits 11 denote a CVCA.");

        Assert.AreEqual(Convert.ToHexString(signature), Convert.ToHexString(parsed.Signature.AsReadOnlySpan()), "The signature equals the tag 0x5F37 value.");
        Assert.AreEqual(Convert.ToHexString(body), Convert.ToHexString(parsed.ToBeSigned.Span), "The signed region is the exact encoded body (tag and length included).");
    }


    [TestMethod]
    public void ParsesDocumentVerifierCertificateWithInheritedCurve()
    {
        byte[] point = BuildUncompressedPoint(0x77);
        byte[] body = Body(
            profileIdentifier: 0x00,
            certificationAuthorityReference: "UTCVCA00001",
            publicKey: EllipticCurvePublicKey(IdTaEcdsaSha256Hex, includeDomainParameters: false, point),
            certificateHolderReference: "UTDVDE00001",
            chat: Chat(IdAuthenticationTerminalHex, [0x80, 0x01, 0x02, 0x03, 0x04]),
            effectiveDate: Date(2024, 5, 17),
            expirationDate: Date(2024, 11, 17));
        byte[] certificate = Tlv(0x7F21, body, Tlv(0x5F37, Filled(64, 0x01)));

        using CardVerifiableCertificate parsed = CardVerifiableCertificate.Parse(
            certificate, BaseMemoryPool.Shared, CryptoTags.BrainpoolP256r1ExchangePublicKey);

        Assert.IsTrue(parsed.PublicKey.IsEllipticCurve, "The certificate carries an elliptic-curve key.");
        Assert.IsFalse(parsed.PublicKey.IncludesDomainParameters, "A Document Verifier certificate omits the domain parameters.");
        Assert.AreEqual(Convert.ToHexString(point), Convert.ToHexString(parsed.PublicKey.EllipticCurvePoint!.AsReadOnlySpan()),
            "The public point equals the tag 0x86 value even without domain parameters.");
        Assert.IsTrue(parsed.PublicKey.EllipticCurvePoint!.Tag.TryGet(out CryptoAlgorithm curve), "The public point carries the inherited curve.");
        Assert.IsTrue(curve == CryptoAlgorithm.BrainpoolP256r1, "The inherited curve is brainpoolP256r1.");
        Assert.AreEqual(CertificateRole.DocumentVerifierOfficialDomestic, parsed.Chat.Role, "The role bits 10 denote an official domestic Document Verifier.");
    }


    [TestMethod]
    public void ParsesRsaCertificate()
    {
        byte[] modulus = new byte[128];
        modulus[0] = 0xA0;
        modulus.AsSpan(1).Fill(0x11);
        byte[] exponent = [0x01, 0x00, 0x01];

        byte[] body = Body(
            profileIdentifier: 0x00,
            certificationAuthorityReference: "UTCVCA00001",
            publicKey: RsaPublicKey(IdTaRsaPkcs1Sha256Hex, modulus, exponent),
            certificateHolderReference: "UTISDE00001",
            chat: Chat(IdInspectionSystemHex, [0x00]),
            effectiveDate: Date(2024, 5, 17),
            expirationDate: Date(2025, 5, 17));
        byte[] certificate = Tlv(0x7F21, body, Tlv(0x5F37, Filled(128, 0x55)));

        using CardVerifiableCertificate parsed = CardVerifiableCertificate.Parse(certificate, BaseMemoryPool.Shared);

        Assert.IsFalse(parsed.PublicKey.IsEllipticCurve, "The id-TA-RSA OID denotes an RSA key.");
        Assert.AreEqual(CvcSignatureScheme.RsaPkcs1Sha256, parsed.PublicKey.SignatureScheme, "The OID arc 0x02 selects RSASSA-PKCS1-v1_5 with SHA-256.");
        Assert.IsNotNull(parsed.PublicKey.RsaKey, "An RSA certificate exposes the RSA public key.");
        Assert.AreEqual(TerminalType.InspectionSystem, parsed.Chat.TerminalType, "The CHAT object identifier selects an Inspection System.");
        Assert.AreEqual(CertificateRole.Terminal, parsed.Chat.Role, "The role bits 00 denote an end-entity terminal.");

        //Independent-oracle carve-out: the RSA key is re-encoded as a DER RSAPublicKey, and an independent
        //framework import recovers the modulus and exponent, proving the library's encoding against an
        //implementation outside the library rather than against itself.
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(parsed.PublicKey.RsaKey!.AsReadOnlySpan(), out int read);
        Assert.AreEqual(parsed.PublicKey.RsaKey!.Length, read, "The whole DER RSAPublicKey is consumed by the import.");
        RSAParameters parameters = rsa.ExportParameters(includePrivateParameters: false);
        Assert.AreEqual(Convert.ToHexString(modulus), Convert.ToHexString(parameters.Modulus!), "The recovered modulus equals the encoded modulus.");
        Assert.AreEqual(Convert.ToHexString(exponent), Convert.ToHexString(parameters.Exponent!), "The recovered exponent equals the encoded exponent.");
    }


    [TestMethod]
    public void RejectsDataWithoutTheCertificateTag()
    {
        byte[] notCertificate = Convert.FromHexString("7F4E03000000");

        Assert.IsTrue(Throws(() => CardVerifiableCertificate.Parse(notCertificate, BaseMemoryPool.Shared)),
            "Parsing must reject data whose outer tag is not 0x7F21.");
    }


    [TestMethod]
    public void RejectsEllipticCurveCertificateWithoutInheritedCurve()
    {
        byte[] body = Body(
            profileIdentifier: 0x00,
            certificationAuthorityReference: "UTCVCA00001",
            publicKey: EllipticCurvePublicKey(IdTaEcdsaSha256Hex, includeDomainParameters: false, BuildUncompressedPoint(0x33)),
            certificateHolderReference: "UTDVDE00001",
            chat: Chat(IdAuthenticationTerminalHex, [0x80, 0x01, 0x02, 0x03, 0x04]),
            effectiveDate: Date(2024, 5, 17),
            expirationDate: Date(2024, 11, 17));
        byte[] certificate = Tlv(0x7F21, body, Tlv(0x5F37, Filled(64, 0x01)));

        Assert.IsTrue(Throws(() => CardVerifiableCertificate.Parse(certificate, BaseMemoryPool.Shared)),
            "A certificate that omits its domain parameters cannot be parsed without the inherited curve.");
    }


    [TestMethod]
    public void RejectsInvalidDateDigit()
    {
        byte[] point = BuildUncompressedPoint(0x42);
        byte[] body = Tlv(0x7F4E,
            Tlv(0x5F29, [0x00]),
            Tlv(0x42, Encoding.ASCII.GetBytes("UTCVCA00001")),
            EllipticCurvePublicKey(IdTaEcdsaSha256Hex, includeDomainParameters: true, point),
            Tlv(0x5F20, Encoding.ASCII.GetBytes("UTCVCA00001")),
            Chat(IdAuthenticationTerminalHex, [0xFE, 0x0F, 0x01, 0xFF, 0xFF]),
            Tlv(0x5F25, [0x02, 0x04, 0x00, 0x0A, 0x01, 0x07]),
            Tlv(0x5F24, [0x02, 0x07, 0x00, 0x05, 0x01, 0x06]));
        byte[] certificate = Tlv(0x7F21, body, Tlv(0x5F37, Filled(64, 0xAB)));

        Assert.IsTrue(Throws(() => CardVerifiableCertificate.Parse(certificate, BaseMemoryPool.Shared)),
            "A date octet greater than 9 is not unpacked BCD and must be rejected.");
    }


    [TestMethod]
    public void RejectsTruncatedPublicPoint()
    {
        //A public point that is only the 0x04 prefix — or any length short of a full uncompressed SEC1 point — is
        //rejected at parse. Left to the prefix-only check it would parse, then throw an uncaught exception when the
        //key was later used to verify a signature; its length is validated here like every other field's.
        byte[] body = Body(
            profileIdentifier: 0x00,
            certificationAuthorityReference: "UTCVCA00001",
            publicKey: EllipticCurvePublicKey(IdTaEcdsaSha256Hex, includeDomainParameters: false, [0x04]),
            certificateHolderReference: "UTDVDE00001",
            chat: Chat(IdAuthenticationTerminalHex, [0x80, 0x01, 0x02, 0x03, 0x04]),
            effectiveDate: Date(2024, 5, 17),
            expirationDate: Date(2024, 11, 17));
        byte[] certificate = Tlv(0x7F21, body, Tlv(0x5F37, Filled(64, 0x01)));

        Assert.IsTrue(Throws(() => CardVerifiableCertificate.Parse(certificate, BaseMemoryPool.Shared, CryptoTags.BrainpoolP256r1ExchangePublicKey)),
            "A public point shorter than a full uncompressed SEC1 point is rejected at parse, not left to crash at signature verification.");
    }


    [TestMethod]
    public void AuthenticationTerminalTemplateGrantsNoInspectionSystemReadAccess()
    {
        //An Authentication Terminal's five-octet relative authorization has a different bit layout than an
        //Inspection System's one-octet one; its first octet's low bits are not the EF.DG3/EF.DG4 read bits. Reading
        //them as such would grant sensitive-data access the terminal was never authorised for, so the eMRTD read
        //access is defined only when the template is an Inspection System — here the first octet's low bits are set.
        byte[] body = Body(
            profileIdentifier: 0x00,
            certificationAuthorityReference: "UTCVCA00001",
            publicKey: EllipticCurvePublicKey(IdTaEcdsaSha256Hex, includeDomainParameters: false, BuildUncompressedPoint(0x77)),
            certificateHolderReference: "UTATDE00001",
            chat: Chat(IdAuthenticationTerminalHex, [0x03, 0x00, 0x00, 0x00, 0x00]),
            effectiveDate: Date(2024, 5, 17),
            expirationDate: Date(2024, 11, 17));
        byte[] certificate = Tlv(0x7F21, body, Tlv(0x5F37, Filled(64, 0x01)));

        using CardVerifiableCertificate parsed = CardVerifiableCertificate.Parse(
            certificate, BaseMemoryPool.Shared, CryptoTags.BrainpoolP256r1ExchangePublicKey);

        Assert.AreEqual(TerminalType.AuthenticationTerminal, parsed.Chat.TerminalType, "The id-AT object identifier selects an Authentication Terminal.");
        Assert.AreEqual(InspectionSystemAccess.None, parsed.Chat.InspectionSystemReadAccess,
            "An Authentication Terminal template grants no Inspection System eMRTD read access, whatever bits its own access value sets.");
    }


    /// <summary>Builds the certificate body (<c>7F4E</c>) from its ordered elements.</summary>
    private static byte[] Body(
        byte profileIdentifier,
        string certificationAuthorityReference,
        byte[] publicKey,
        string certificateHolderReference,
        byte[] chat,
        byte[] effectiveDate,
        byte[] expirationDate)
    {
        return Tlv(0x7F4E,
            Tlv(0x5F29, [profileIdentifier]),
            Tlv(0x42, Encoding.ASCII.GetBytes(certificationAuthorityReference)),
            publicKey,
            Tlv(0x5F20, Encoding.ASCII.GetBytes(certificateHolderReference)),
            chat,
            Tlv(0x5F25, effectiveDate),
            Tlv(0x5F24, expirationDate));
    }


    /// <summary>
    /// Builds an elliptic-curve public key (<c>7F49</c>). When <paramref name="includeDomainParameters"/>
    /// is set, the real brainpoolP256r1 prime is written so the curve resolves; the other parameters are
    /// placeholders the parser consumes but ignores.
    /// </summary>
    private static byte[] EllipticCurvePublicKey(string oidHex, bool includeDomainParameters, byte[] point)
    {
        if(includeDomainParameters)
        {
            return Tlv(0x7F49,
                Tlv(0x06, Convert.FromHexString(oidHex)),
                Tlv(0x81, Convert.FromHexString(BrainpoolP256r1PrimeHex)),
                Tlv(0x82, [0x01]),
                Tlv(0x83, [0x02]),
                Tlv(0x84, BuildUncompressedPoint(0x03)),
                Tlv(0x85, [0x04]),
                Tlv(0x86, point),
                Tlv(0x87, [0x01]));
        }

        return Tlv(0x7F49, Tlv(0x06, Convert.FromHexString(oidHex)), Tlv(0x86, point));
    }


    /// <summary>Builds an RSA public key (<c>7F49</c>): the object identifier, modulus, and exponent.</summary>
    private static byte[] RsaPublicKey(string oidHex, byte[] modulus, byte[] exponent)
    {
        return Tlv(0x7F49, Tlv(0x06, Convert.FromHexString(oidHex)), Tlv(0x81, modulus), Tlv(0x82, exponent));
    }


    /// <summary>Builds a Certificate Holder Authorization Template (<c>7F4C</c>): the terminal-type OID and the discretionary-data value.</summary>
    private static byte[] Chat(string oidHex, byte[] discretionaryData)
    {
        return Tlv(0x7F4C, Tlv(0x06, Convert.FromHexString(oidHex)), Tlv(0x53, discretionaryData));
    }


    /// <summary>Encodes a date as six unpacked-BCD octets in YYMMDD form (year relative to 2000).</summary>
    private static byte[] Date(int year, int month, int day)
    {
        int yy = year - 2000;

        return [(byte)(yy / 10), (byte)(yy % 10), (byte)(month / 10), (byte)(month % 10), (byte)(day / 10), (byte)(day % 10)];
    }


    /// <summary>Builds a byte array of <paramref name="length"/> filled with <paramref name="value"/>.</summary>
    private static byte[] Filled(int length, byte value)
    {
        byte[] result = new byte[length];
        Array.Fill(result, value);

        return result;
    }


    /// <summary>Runs <paramref name="parse"/> and reports whether it threw an <see cref="InvalidOperationException"/>.</summary>
    private static bool Throws(Func<CardVerifiableCertificate> parse)
    {
        try
        {
            using CardVerifiableCertificate _ = parse();

            return false;
        }
        catch(InvalidOperationException)
        {
            return true;
        }
    }


    /// <summary>Wraps the concatenation of <paramref name="content"/> in a BER-TLV element (definite length).</summary>
    private static byte[] Tlv(int tag, params byte[][] content)
    {
        byte[] body = Concat(content);
        byte[] tagBytes = tag > 0xFF ? [(byte)(tag >> 8), (byte)tag] : [(byte)tag];
        byte[] length = EncodeLength(body.Length);

        return Concat(tagBytes, length, body);
    }


    /// <summary>Concatenates byte arrays.</summary>
    private static byte[] Concat(params byte[][] arrays)
    {
        int length = 0;
        foreach(byte[] a in arrays) { length += a.Length; }

        byte[] result = new byte[length];
        int offset = 0;
        foreach(byte[] a in arrays)
        {
            a.CopyTo(result, offset);
            offset += a.Length;
        }

        return result;
    }
}
