using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Apdu.Eac;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Mints card-verifiable certificates (BSI TR-03110-3 §C.1) with the framework's own ECDSA — an independent
/// signer — for the Terminal Authentication tests. The body is built tag by tag with an
/// <see cref="AsnWriter"/> (the CVC application-class tags map directly onto <see cref="Asn1Tag"/>), signed
/// with the issuer key (plain ECDSA <c>r ‖ s</c> over SHA-256, the id-TA-ECDSA-SHA-256 form), assembled into
/// the outer <c>7F21</c> certificate, and parsed back through the library — so the result is a tracked
/// <see cref="CardVerifiableCertificate"/> carrier reconstructed from the wire bytes, never a naked buffer.
/// </summary>
/// <remarks>
/// The subject's public key is elliptic-curve (id-TA-ECDSA-SHA-256, a public point with conditional domain
/// parameters) or RSA (id-TA-RSA-v1-5-SHA-256, a modulus and exponent). The issuer always signs with ECDSA,
/// so an RSA terminal certificate is one whose subject key is RSA while its signature — checked during chain
/// verification — stays elliptic-curve; only the terminal's EXTERNAL AUTHENTICATE possession proof is RSA.
/// </remarks>
internal static class CardVerifiableCertificateMinter
{
    /// <summary>The id-TA-ECDSA-SHA-256 public-key object identifier (value bytes <c>04007F00070202020203</c>).</summary>
    private const string IdTaEcdsaSha256Oid = "0.4.0.127.0.7.2.2.2.2.3";

    /// <summary>The id-TA-RSA-v1-5-SHA-256 public-key object identifier (value bytes <c>04007F00070202020102</c>).</summary>
    private const string IdTaRsaPkcs1Sha256Oid = "0.4.0.127.0.7.2.2.2.1.2";

    /// <summary>The id-AT (Authentication Terminal) Certificate Holder Authorization object identifier (value bytes <c>04007F000703010202</c>).</summary>
    private const string IdAuthenticationTerminalOid = "0.4.0.127.0.7.3.1.2.2";

    /// <summary>The id-IS (Inspection System) Certificate Holder Authorization object identifier (value bytes <c>04007F000703010201</c>).</summary>
    private const string IdInspectionSystemOid = "0.4.0.127.0.7.3.1.2.1";

    /// <summary>The P-256 coordinate length in bytes.</summary>
    private const int CoordinateLength = 32;

    /// <summary>The P-256 IEEE P1363 (<c>r ‖ s</c>) signature length in bytes.</summary>
    private const int SignatureLength = 64;

    /// <summary>Authorization first octet for a Country Verifying Certification Authority (role bits 11).</summary>
    public const byte CvcaRole = 0xC0;

    /// <summary>Authorization first octet for a Document Verifier, official domestic (role bits 10).</summary>
    public const byte DocumentVerifierRole = 0x80;

    /// <summary>Authorization first octet for a terminal (role bits 00).</summary>
    public const byte TerminalRole = 0x00;

    /// <summary>Inspection System relative-authorization bit granting read access to EF.DG3 (fingerprints), bit 2 (<c>0x02</c>); OR it into the authorization octet.</summary>
    public const byte ReadDataGroup3 = 0x02;

    /// <summary>Inspection System relative-authorization bit granting read access to EF.DG4 (iris), bit 1 (<c>0x01</c>); OR it into the authorization octet.</summary>
    public const byte ReadDataGroup4 = 0x01;

    private static readonly Asn1Tag CertificateTag = new(TagClass.Application, 33, isConstructed: true);   // 7F21
    private static readonly Asn1Tag BodyTag = new(TagClass.Application, 78, isConstructed: true);          // 7F4E
    private static readonly Asn1Tag ProfileIdentifierTag = new(TagClass.Application, 41);                  // 5F29
    private static readonly Asn1Tag CertificationAuthorityReferenceTag = new(TagClass.Application, 2);     // 42
    private static readonly Asn1Tag PublicKeyTag = new(TagClass.Application, 73, isConstructed: true);     // 7F49
    private static readonly Asn1Tag CertificateHolderReferenceTag = new(TagClass.Application, 32);         // 5F20
    private static readonly Asn1Tag AuthorizationTemplateTag = new(TagClass.Application, 76, isConstructed: true); // 7F4C
    private static readonly Asn1Tag DiscretionaryDataTag = new(TagClass.Application, 19);                  // 53
    private static readonly Asn1Tag EffectiveDateTag = new(TagClass.Application, 37);                      // 5F25
    private static readonly Asn1Tag ExpirationDateTag = new(TagClass.Application, 36);                     // 5F24
    private static readonly Asn1Tag SignatureTag = new(TagClass.Application, 55);                          // 5F37
    private static readonly Asn1Tag PublicPointTag = new(TagClass.ContextSpecific, 6);                     // 86


    /// <summary>
    /// Mints a card-verifiable certificate: builds the body with the subject key's public point, signs it
    /// with the issuer key, assembles the outer certificate, and parses it back into a tracked carrier.
    /// </summary>
    /// <param name="issuerKey">The key signing the certificate body.</param>
    /// <param name="subjectKey">The key whose public point the certificate carries.</param>
    /// <param name="certificationAuthorityReference">The issuer's holder reference (DO'42').</param>
    /// <param name="certificateHolderReference">The subject's holder reference (DO'5F20').</param>
    /// <param name="authorizationOctet">The first relative-authorization octet: the leading two bits encode the certificate role; for an Inspection System the lower bits also carry the EF.DG3/EF.DG4 read-access grant (OR in <see cref="ReadDataGroup3"/> / <see cref="ReadDataGroup4"/>).</param>
    /// <param name="includeDomainParameters">Whether to embed the curve domain parameters (a self-signed CVCA certificate) or inherit them (a Document Verifier or terminal certificate).</param>
    /// <param name="effective">The certificate effective date.</param>
    /// <param name="expiration">The certificate expiration date.</param>
    /// <param name="inheritedCurve">The issuing curve for a certificate that omits its domain parameters, or <see langword="null"/> for a self-signed CVCA certificate.</param>
    /// <param name="pool">The memory pool for the encoding and the parsed carrier.</param>
    /// <param name="terminalType">The terminal type the Certificate Holder Authorization Template declares, selecting the object identifier and discretionary-data layout (id-AT with a five-octet value, or id-IS with a single octet). Defaults to an Authentication Terminal.</param>
    /// <returns>The parsed certificate. The caller disposes it.</returns>
    public static CardVerifiableCertificate Mint(
        ECDsa issuerKey,
        ECDsa subjectKey,
        string certificationAuthorityReference,
        string certificateHolderReference,
        byte authorizationOctet,
        bool includeDomainParameters,
        DateOnly effective,
        DateOnly expiration,
        Tag? inheritedCurve,
        MemoryPool<byte> pool,
        TerminalType terminalType = TerminalType.AuthenticationTerminal) =>
        MintCore(new IssuerKey(issuerKey), new SubjectPublicKey(subjectKey, includeDomainParameters), certificationAuthorityReference, certificateHolderReference, authorizationOctet, effective, expiration, inheritedCurve, pool, terminalType, tamperSignature: false);


    /// <summary>
    /// Mints a card-verifiable certificate with an RSA subject key (id-TA-RSA-v1-5-SHA-256), signed by the
    /// elliptic-curve issuer. Used for an RSA terminal under an elliptic-curve chain: the subject's key is RSA
    /// while the certificate's own signature stays ECDSA, so only the terminal's EXTERNAL AUTHENTICATE signature
    /// is RSA. An RSA public key carries no domain parameters and inherits no curve, so neither parameter applies.
    /// </summary>
    /// <param name="issuerKey">The elliptic-curve key signing the certificate body.</param>
    /// <param name="subjectKey">The RSA key whose modulus and exponent the certificate carries.</param>
    /// <param name="certificationAuthorityReference">The issuer's holder reference (DO'42').</param>
    /// <param name="certificateHolderReference">The subject's holder reference (DO'5F20').</param>
    /// <param name="authorizationOctet">The first relative-authorization octet (the certificate role and, for an Inspection System, the read-access grant).</param>
    /// <param name="effective">The certificate effective date.</param>
    /// <param name="expiration">The certificate expiration date.</param>
    /// <param name="pool">The memory pool for the encoding and the parsed carrier.</param>
    /// <param name="terminalType">The terminal type the Certificate Holder Authorization Template declares. Defaults to an Authentication Terminal.</param>
    /// <returns>The parsed certificate. The caller disposes it.</returns>
    public static CardVerifiableCertificate Mint(
        ECDsa issuerKey,
        RSA subjectKey,
        string certificationAuthorityReference,
        string certificateHolderReference,
        byte authorizationOctet,
        DateOnly effective,
        DateOnly expiration,
        MemoryPool<byte> pool,
        TerminalType terminalType = TerminalType.AuthenticationTerminal) =>
        MintCore(new IssuerKey(issuerKey), new SubjectPublicKey(subjectKey), certificationAuthorityReference, certificateHolderReference, authorizationOctet, effective, expiration, inheritedCurve: null, pool, terminalType, tamperSignature: false);


    /// <summary>
    /// Mints a card-verifiable certificate with an RSA subject key, signed by an RSA issuer with
    /// id-TA-RSA-v1-5-SHA-256 (PKCS#1 v1.5 over SHA-256). Used to build a full RSA card-verifiable-certificate
    /// chain (a self-signed RSA CVCA, then RSA-issued Document Verifier and terminal certificates), exercising
    /// the RSA issuer path of chain verification. An RSA certificate carries no domain parameters.
    /// </summary>
    /// <param name="issuerKey">The RSA key signing the certificate body.</param>
    /// <param name="subjectKey">The RSA key whose modulus and exponent the certificate carries.</param>
    /// <param name="certificationAuthorityReference">The issuer's holder reference (DO'42').</param>
    /// <param name="certificateHolderReference">The subject's holder reference (DO'5F20').</param>
    /// <param name="authorizationOctet">The first relative-authorization octet (the certificate role and, for an Inspection System, the read-access grant).</param>
    /// <param name="effective">The certificate effective date.</param>
    /// <param name="expiration">The certificate expiration date.</param>
    /// <param name="pool">The memory pool for the encoding and the parsed carrier.</param>
    /// <param name="terminalType">The terminal type the Certificate Holder Authorization Template declares. Defaults to an Authentication Terminal.</param>
    /// <returns>The parsed certificate. The caller disposes it.</returns>
    public static CardVerifiableCertificate Mint(
        RSA issuerKey,
        RSA subjectKey,
        string certificationAuthorityReference,
        string certificateHolderReference,
        byte authorizationOctet,
        DateOnly effective,
        DateOnly expiration,
        MemoryPool<byte> pool,
        TerminalType terminalType = TerminalType.AuthenticationTerminal) =>
        MintCore(new IssuerKey(issuerKey), new SubjectPublicKey(subjectKey), certificationAuthorityReference, certificateHolderReference, authorizationOctet, effective, expiration, inheritedCurve: null, pool, terminalType, tamperSignature: false);


    /// <summary>
    /// Mints a card-verifiable certificate whose signature has been corrupted, for the rejection tests. The
    /// structure parses, but the signature does not verify against the issuer's public key.
    /// </summary>
    public static CardVerifiableCertificate MintWithTamperedSignature(
        ECDsa issuerKey,
        ECDsa subjectKey,
        string certificationAuthorityReference,
        string certificateHolderReference,
        byte authorizationOctet,
        bool includeDomainParameters,
        DateOnly effective,
        DateOnly expiration,
        Tag? inheritedCurve,
        MemoryPool<byte> pool,
        TerminalType terminalType = TerminalType.AuthenticationTerminal) =>
        MintCore(new IssuerKey(issuerKey), new SubjectPublicKey(subjectKey, includeDomainParameters), certificationAuthorityReference, certificateHolderReference, authorizationOctet, effective, expiration, inheritedCurve, pool, terminalType, tamperSignature: true);


    /// <summary>
    /// Mints a full-RSA card-verifiable certificate (RSA issuer, RSA subject) whose signature has been
    /// corrupted, for the RSA chain rejection test. The structure parses, but the RSA signature does not
    /// verify against the issuer's public key.
    /// </summary>
    public static CardVerifiableCertificate MintWithTamperedSignature(
        RSA issuerKey,
        RSA subjectKey,
        string certificationAuthorityReference,
        string certificateHolderReference,
        byte authorizationOctet,
        DateOnly effective,
        DateOnly expiration,
        MemoryPool<byte> pool,
        TerminalType terminalType = TerminalType.AuthenticationTerminal) =>
        MintCore(new IssuerKey(issuerKey), new SubjectPublicKey(subjectKey), certificationAuthorityReference, certificateHolderReference, authorizationOctet, effective, expiration, inheritedCurve: null, pool, terminalType, tamperSignature: true);


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the parsed certificate transfers to the caller, which disposes it; the rented encoding buffers are disposed by their using declarations.")]
    private static CardVerifiableCertificate MintCore(
        IssuerKey issuerKey,
        SubjectPublicKey subjectKey,
        string certificationAuthorityReference,
        string certificateHolderReference,
        byte authorizationOctet,
        DateOnly effective,
        DateOnly expiration,
        Tag? inheritedCurve,
        MemoryPool<byte> pool,
        TerminalType terminalType,
        bool tamperSignature)
    {
        //Build and encode the body (7F4E) into a pooled span — the exact region the signature covers and the
        //outer certificate embeds.
        var bodyWriter = new AsnWriter(AsnEncodingRules.DER);
        WriteBody(bodyWriter, subjectKey, certificationAuthorityReference, certificateHolderReference, authorizationOctet, effective, expiration, terminalType);
        using IMemoryOwner<byte> bodyOwner = pool.Rent(bodyWriter.GetEncodedLength());
        int bodyLength = bodyWriter.Encode(bodyOwner.Memory.Span);
        ReadOnlySpan<byte> body = bodyOwner.Memory.Span[..bodyLength];

        //Sign the body; the issuer key is independent of the library wiring under test (ECDSA r||s, or RSA
        //PKCS#1 v1.5 over SHA-256 for an id-TA-RSA-v1-5-SHA-256 issuer).
        using IMemoryOwner<byte> signatureOwner = SignBody(issuerKey, body, pool, out int signatureLength);
        Span<byte> signature = signatureOwner.Memory.Span[..signatureLength];
        if(tamperSignature)
        {
            signature[signatureLength - 1] ^= 0xFF;
        }

        //Assemble the outer certificate (7F21) over the body and the signature, encode it, and parse it back.
        var outerWriter = new AsnWriter(AsnEncodingRules.DER);
        using(outerWriter.PushSequence(CertificateTag))
        {
            outerWriter.WriteEncodedValue(body);
            outerWriter.WriteOctetString(signature, SignatureTag);
        }

        using IMemoryOwner<byte> certificateOwner = pool.Rent(outerWriter.GetEncodedLength());
        int certificateLength = outerWriter.Encode(certificateOwner.Memory.Span);

        return CardVerifiableCertificate.Parse(certificateOwner.Memory.Span[..certificateLength], pool, inheritedCurve);
    }


    /// <summary>
    /// Signs the certificate body with the issuer key into a pooled buffer: an elliptic-curve issuer produces a
    /// plain <c>r ‖ s</c> ECDSA signature over SHA-256 (the id-TA-ECDSA-SHA-256 form), an RSA issuer a PKCS#1
    /// v1.5 signature over SHA-256 (the id-TA-RSA-v1-5-SHA-256 form). The issuer is independent of the library
    /// wiring under test.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, which disposes it via a using declaration.")]
    private static IMemoryOwner<byte> SignBody(IssuerKey issuerKey, ReadOnlySpan<byte> body, MemoryPool<byte> pool, out int length)
    {
        if(issuerKey.Rsa is RSA rsa)
        {
            IMemoryOwner<byte> rsaOwner = pool.Rent(rsa.KeySize / 8);
            try
            {
                rsa.TrySignData(body, rsaOwner.Memory.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out length);

                return rsaOwner;
            }
            catch
            {
                rsaOwner.Dispose();

                throw;
            }
        }

        IMemoryOwner<byte> ecOwner = pool.Rent(SignatureLength);
        try
        {
            length = issuerKey.EllipticCurve!.SignData(body, ecOwner.Memory.Span, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            return ecOwner;
        }
        catch
        {
            ecOwner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Writes the certificate body (7F4E): profile identifier, certification authority reference, public key,
    /// certificate holder reference, holder authorization template, and the effective and expiration dates.
    /// </summary>
    private static void WriteBody(
        AsnWriter writer,
        SubjectPublicKey subjectKey,
        string certificationAuthorityReference,
        string certificateHolderReference,
        byte authorizationOctet,
        DateOnly effective,
        DateOnly expiration,
        TerminalType terminalType)
    {
        using(writer.PushSequence(BodyTag))
        {
            writer.WriteOctetString([0x00], ProfileIdentifierTag);
            WriteAscii(writer, certificationAuthorityReference, CertificationAuthorityReferenceTag);
            WritePublicKey(writer, subjectKey);
            WriteAscii(writer, certificateHolderReference, CertificateHolderReferenceTag);
            WriteAuthorizationTemplate(writer, authorizationOctet, terminalType);
            WriteDate(writer, effective, EffectiveDateTag);
            WriteDate(writer, expiration, ExpirationDateTag);
        }
    }


    /// <summary>
    /// Writes the public-key element (7F49) of the subject: an elliptic-curve point or an RSA modulus and exponent.
    /// </summary>
    private static void WritePublicKey(AsnWriter writer, SubjectPublicKey subjectKey)
    {
        if(subjectKey.RsaKey is RSA rsaKey)
        {
            WriteRsaPublicKey(writer, rsaKey);

            return;
        }

        WriteEllipticCurvePublicKey(writer, subjectKey.EllipticCurveKey!, subjectKey.IncludeDomainParameters);
    }


    /// <summary>
    /// Writes the elliptic-curve public-key element (7F49): id-TA-ECDSA-SHA-256, the real P-256 prime when
    /// domain parameters are included (so the curve resolves; the other parameters are placeholders), and the
    /// subject's uncompressed public point.
    /// </summary>
    private static void WriteEllipticCurvePublicKey(AsnWriter writer, ECDsa subjectKey, bool includeDomainParameters)
    {
        using(writer.PushSequence(PublicKeyTag))
        {
            writer.WriteObjectIdentifier(IdTaEcdsaSha256Oid);
            if(includeDomainParameters)
            {
                writer.WriteOctetString(EllipticCurveConstants.P256.PrimeBytes, new Asn1Tag(TagClass.ContextSpecific, 1)); // prime
                writer.WriteOctetString([0x01], new Asn1Tag(TagClass.ContextSpecific, 2));                                  // first coefficient
                writer.WriteOctetString([0x02], new Asn1Tag(TagClass.ContextSpecific, 3));                                  // second coefficient
                writer.WriteOctetString([0x03], new Asn1Tag(TagClass.ContextSpecific, 4));                                  // base point
                writer.WriteOctetString([0x04], new Asn1Tag(TagClass.ContextSpecific, 5));                                  // order
                WritePoint(writer, subjectKey);
                writer.WriteOctetString([0x01], new Asn1Tag(TagClass.ContextSpecific, 7));                                  // cofactor
            }
            else
            {
                WritePoint(writer, subjectKey);
            }
        }
    }


    /// <summary>
    /// Writes the RSA public-key element (7F49): id-TA-RSA-v1-5-SHA-256, then the modulus (context tag 1, the
    /// <c>0x81</c> data object) and the public exponent (context tag 2, the <c>0x82</c> data object) as
    /// unsigned big-endian integers (BSI TR-03110-3 §D.3). The exported parameters are transient framework
    /// arrays consumed inline into the writer, never retained.
    /// </summary>
    private static void WriteRsaPublicKey(AsnWriter writer, RSA subjectKey)
    {
        using(writer.PushSequence(PublicKeyTag))
        {
            writer.WriteObjectIdentifier(IdTaRsaPkcs1Sha256Oid);

            RSAParameters parameters = subjectKey.ExportParameters(includePrivateParameters: false);
            writer.WriteOctetString(parameters.Modulus!, new Asn1Tag(TagClass.ContextSpecific, 1));   // modulus
            writer.WriteOctetString(parameters.Exponent!, new Asn1Tag(TagClass.ContextSpecific, 2));  // public exponent
        }
    }


    /// <summary>
    /// Writes the subject's uncompressed SEC1 public point (<c>0x04 ‖ X ‖ Y</c>) under the public-point tag (86).
    /// </summary>
    private static void WritePoint(AsnWriter writer, ECDsa key)
    {
        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        Span<byte> point = stackalloc byte[1 + (2 * CoordinateLength)];
        point[0] = 0x04;
        parameters.Q.X!.CopyTo(point.Slice(1, CoordinateLength));
        parameters.Q.Y!.CopyTo(point.Slice(1 + CoordinateLength, CoordinateLength));

        writer.WriteOctetString(point, PublicPointTag);
    }


    /// <summary>
    /// Writes the Certificate Holder Authorization Template (7F4C): the terminal-type object identifier and
    /// the discretionary-data octets carrying the relative authorization. An Authentication Terminal uses a
    /// five-octet value (the role octet then four further authorization octets); an Inspection System uses a
    /// single octet carrying the role and the EF.DG3/EF.DG4 read-access bits.
    /// </summary>
    private static void WriteAuthorizationTemplate(AsnWriter writer, byte authorizationOctet, TerminalType terminalType)
    {
        using(writer.PushSequence(AuthorizationTemplateTag))
        {
            switch(terminalType)
            {
                case TerminalType.InspectionSystem:
                    writer.WriteObjectIdentifier(IdInspectionSystemOid);
                    writer.WriteOctetString([authorizationOctet], DiscretionaryDataTag);
                    break;
                default:
                    writer.WriteObjectIdentifier(IdAuthenticationTerminalOid);
                    writer.WriteOctetString([authorizationOctet, 0x00, 0x00, 0x00, 0x00], DiscretionaryDataTag);
                    break;
            }
        }
    }


    /// <summary>
    /// Writes a certificate date (six unpacked-BCD octets in <c>YYMMDD</c> form, year relative to 2000).
    /// </summary>
    private static void WriteDate(AsnWriter writer, DateOnly date, Asn1Tag tag)
    {
        int year = date.Year - 2000;
        Span<byte> value =
        [
            (byte)(year / 10), (byte)(year % 10),
            (byte)(date.Month / 10), (byte)(date.Month % 10),
            (byte)(date.Day / 10), (byte)(date.Day % 10)
        ];

        writer.WriteOctetString(value, tag);
    }


    /// <summary>
    /// Writes an ASCII character string (a holder or authority reference) under <paramref name="tag"/>.
    /// </summary>
    private static void WriteAscii(AsnWriter writer, string value, Asn1Tag tag)
    {
        Span<byte> bytes = stackalloc byte[Encoding.ASCII.GetByteCount(value)];
        Encoding.ASCII.GetBytes(value, bytes);

        writer.WriteOctetString(bytes, tag);
    }


    /// <summary>
    /// The subject's public key to embed in a minted certificate: an elliptic-curve key (with whether to
    /// include the curve domain parameters) or an RSA key. Borrows the key for the duration of minting.
    /// </summary>
    private readonly struct SubjectPublicKey
    {
        /// <summary>Initialises an elliptic-curve subject public key.</summary>
        /// <param name="ellipticCurveKey">The subject's elliptic-curve key.</param>
        /// <param name="includeDomainParameters">Whether to embed the curve domain parameters (a self-signed CVCA certificate) or inherit them.</param>
        public SubjectPublicKey(ECDsa ellipticCurveKey, bool includeDomainParameters)
        {
            EllipticCurveKey = ellipticCurveKey;
            IncludeDomainParameters = includeDomainParameters;
            RsaKey = null;
        }


        /// <summary>Initialises an RSA subject public key (no domain parameters, no inherited curve).</summary>
        /// <param name="rsaKey">The subject's RSA key.</param>
        public SubjectPublicKey(RSA rsaKey)
        {
            EllipticCurveKey = null;
            IncludeDomainParameters = false;
            RsaKey = rsaKey;
        }


        /// <summary>Gets the elliptic-curve subject key, or <see langword="null"/> when the subject key is RSA.</summary>
        public ECDsa? EllipticCurveKey { get; }

        /// <summary>Gets whether to embed the curve domain parameters (elliptic-curve subjects only).</summary>
        public bool IncludeDomainParameters { get; }

        /// <summary>Gets the RSA subject key, or <see langword="null"/> when the subject key is elliptic-curve.</summary>
        public RSA? RsaKey { get; }
    }


    /// <summary>
    /// The issuer key that signs a minted certificate's body: an elliptic-curve key (ECDSA <c>r ‖ s</c> over
    /// SHA-256) or an RSA key (PKCS#1 v1.5 over SHA-256). Borrows the key for the duration of minting.
    /// </summary>
    private readonly struct IssuerKey
    {
        /// <summary>Initialises an elliptic-curve issuer key.</summary>
        /// <param name="ellipticCurve">The issuer's elliptic-curve signing key.</param>
        public IssuerKey(ECDsa ellipticCurve)
        {
            EllipticCurve = ellipticCurve;
            Rsa = null;
        }


        /// <summary>Initialises an RSA issuer key.</summary>
        /// <param name="rsa">The issuer's RSA signing key.</param>
        public IssuerKey(RSA rsa)
        {
            EllipticCurve = null;
            Rsa = rsa;
        }


        /// <summary>Gets the elliptic-curve issuer key, or <see langword="null"/> when the issuer key is RSA.</summary>
        public ECDsa? EllipticCurve { get; }

        /// <summary>Gets the RSA issuer key, or <see langword="null"/> when the issuer key is elliptic-curve.</summary>
        public RSA? Rsa { get; }
    }
}
