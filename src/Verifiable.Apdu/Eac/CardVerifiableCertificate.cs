using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;

namespace Verifiable.Apdu.Eac;

/// <summary>
/// A parsed card-verifiable certificate (CVC) — the bespoke ASN.1 certificate format Extended Access
/// Control uses for its certificate chain (CVCA -> Document Verifier -> terminal), distinct from X.509.
/// The terminal presents this chain to the chip during Terminal Authentication to prove its authorization
/// (BSI TR-03110-3 §C.1, ICAO Doc 9303 Part 11 §4.4).
/// </summary>
/// <remarks>
/// <para>
/// The structure is a body (<c>7F4E</c>) and a signature (<c>5F37</c>) wrapped in an outer certificate
/// object (<c>7F21</c>). The body carries the certificate profile identifier (<c>5F29</c>), the
/// Certification Authority Reference (<c>42</c>, the issuer's holder reference), the holder's public key
/// (<c>7F49</c>), the Certificate Holder Reference (<c>5F20</c>), the Certificate Holder Authorization
/// Template (<c>7F4C</c>), and the effective (<c>5F25</c>) and expiration (<c>5F24</c>) dates. The
/// signature is computed over the encoded body including its tag and length (§C.1.8); a verifier checks it
/// against the public key of the certificate the Certification Authority Reference names.
/// </para>
/// <para>
/// A tracked carrier rather than a naked buffer: it owns the encoded certificate bytes, carries
/// <see cref="ApduTags.CardVerifiableCertificate"/> for provenance, and owns its parsed public-key,
/// authorization-template, and signature carriers, disposing them with itself. A self-signed CVCA
/// certificate carries its curve's domain parameters; a Document Verifier or terminal certificate inherits
/// them, so parsing one requires the issuing curve to be supplied.
/// </para>
/// </remarks>
[DebuggerDisplay("CVC({CertificationAuthorityReference} -> {CertificateHolderReference})")]
public sealed class CardVerifiableCertificate: SensitiveMemory
{
    private const int CertificateTag = 0x7F21;
    private const int CertificateBodyTag = 0x7F4E;
    private const int CertificateProfileIdentifierTag = 0x5F29;
    private const int CertificationAuthorityReferenceTag = 0x42;
    private const int PublicKeyTag = 0x7F49;
    private const int CertificateHolderReferenceTag = 0x5F20;
    private const int CertificateHolderAuthorizationTemplateTag = 0x7F4C;
    private const int EffectiveDateTag = 0x5F25;
    private const int ExpirationDateTag = 0x5F24;
    private const int SignatureTag = 0x5F37;
    private const int ObjectIdentifierTag = 0x06;
    private const int DiscretionaryDataTag = 0x53;

    //Public-key object data objects (TR-03110-3 §D.3): an OID then conditional EC domain parameters and
    //the mandatory public point, or the RSA modulus and exponent. The EC parameter tags and the RSA
    //modulus tag share the 0x81 value; the public-key OID disambiguates which encoding follows.
    private const int PrimeTag = 0x81;
    private const int CoefficientATag = 0x82;
    private const int CoefficientBTag = 0x83;
    private const int BasePointTag = 0x84;
    private const int OrderTag = 0x85;
    private const int PublicPointTag = 0x86;
    private const int CofactorTag = 0x87;
    private const int RsaModulusTag = 0x81;
    private const int RsaExponentTag = 0x82;

    private const int DerSequenceTag = 0x30;
    private const int DerIntegerTag = 0x02;

    //BSI TR-03110-3 Terminal Authentication public-key OID value bytes (after the 0x06 tag and length),
    //less the final hash/scheme arc. id-TA-ECDSA = 0.4.0.127.0.7.2.2.2.2, id-TA-RSA = 0.4.0.127.0.7.2.2.2.1.
    private static readonly byte[] IdTaEcdsaPrefix = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02];
    private static readonly byte[] IdTaRsaPrefix = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01];

    //Certificate Holder Authorization terminal-type OID value bytes (TR-03110 Part 4, base 0.4.0.127.0.7.3.1.2).
    private static readonly byte[] IdInspectionSystem = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x02, 0x01];
    private static readonly byte[] IdAuthenticationTerminal = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x02, 0x02];
    private static readonly byte[] IdSignatureTerminal = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x02, 0x03];

    private readonly int bodyOffset;
    private readonly int bodyLength;
    private readonly int contentLength;


    private CardVerifiableCertificate(
        IMemoryOwner<byte> encoded,
        byte certificateProfileIdentifier,
        string certificationAuthorityReference,
        string certificateHolderReference,
        CardVerifiableCertificatePublicKey publicKey,
        CertificateHolderAuthorizationTemplate chat,
        DateOnly effectiveDate,
        DateOnly expirationDate,
        Signature signature,
        int bodyOffset,
        int bodyLength,
        int contentLength)
        : base(encoded, ApduTags.CardVerifiableCertificate)
    {
        CertificateProfileIdentifier = certificateProfileIdentifier;
        CertificationAuthorityReference = certificationAuthorityReference;
        CertificateHolderReference = certificateHolderReference;
        PublicKey = publicKey;
        Chat = chat;
        EffectiveDate = effectiveDate;
        ExpirationDate = expirationDate;
        Signature = signature;
        this.bodyOffset = bodyOffset;
        this.bodyLength = bodyLength;
        this.contentLength = contentLength;
    }


    /// <summary>Gets the certificate profile identifier (<c>5F29</c>); <c>0</c> denotes profile version 1.</summary>
    public byte CertificateProfileIdentifier { get; }

    /// <summary>Gets the Certification Authority Reference (<c>42</c>) — the holder reference of the certificate that issued this one, naming the public key that verifies its signature.</summary>
    public string CertificationAuthorityReference { get; }

    /// <summary>Gets the Certificate Holder Reference (<c>5F20</c>) — this certificate holder's identifier, which the next certificate in the chain names as its Certification Authority Reference.</summary>
    public string CertificateHolderReference { get; }

    /// <summary>Gets the holder's public key (<c>7F49</c>). Owned by this certificate.</summary>
    public CardVerifiableCertificatePublicKey PublicKey { get; }

    /// <summary>Gets the Certificate Holder Authorization Template (<c>7F4C</c>) — the holder's terminal type, role, and access rights. Owned by this certificate.</summary>
    public CertificateHolderAuthorizationTemplate Chat { get; }

    /// <summary>Gets the certificate effective date (<c>5F25</c>, GMT).</summary>
    public DateOnly EffectiveDate { get; }

    /// <summary>Gets the certificate expiration date (<c>5F24</c>, GMT).</summary>
    public DateOnly ExpirationDate { get; }

    /// <summary>Gets the certificate signature (<c>5F37</c>) — for ECDSA the plain <c>r || s</c> form, for RSA the scheme output. Owned by this certificate.</summary>
    public Signature Signature { get; }

    /// <summary>
    /// Gets the certificate body bytes (the <c>7F4E</c> TLV, including its tag and length) over which the
    /// signature is computed — the message a verifier checks against the issuer's public key
    /// (TR-03110-3 §C.1.8). A view into the owned encoded certificate.
    /// </summary>
    public ReadOnlyMemory<byte> ToBeSigned => AsReadOnlyMemory().Slice(bodyOffset, bodyLength);

    /// <summary>
    /// Gets the certificate content (the body <c>7F4E</c> TLV followed by the signature <c>5F37</c> TLV,
    /// without the outer <c>7F21</c> tag and length) — the data field a terminal sends in the PSO:Verify
    /// Certificate command during Terminal Authentication (ICAO Doc 9303 Part 11 §7.1.5). A view into the
    /// owned encoded certificate.
    /// </summary>
    public ReadOnlyMemory<byte> Content => AsReadOnlyMemory().Slice(bodyOffset, contentLength);


    /// <summary>
    /// Parses a card-verifiable certificate from its encoded bytes.
    /// </summary>
    /// <param name="certificate">The encoded certificate (the outer <c>7F21</c> structure).</param>
    /// <param name="pool">The memory pool for the certificate and its parsed carriers.</param>
    /// <param name="inheritedCurve">
    /// The curve tag of the issuing CVCA public key, required to interpret the public point of a Document
    /// Verifier or terminal certificate (which omits its domain parameters). Pass <see langword="null"/>
    /// for a self-signed CVCA certificate, which carries its own domain parameters.
    /// </param>
    /// <returns>The parsed <see cref="CardVerifiableCertificate"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed CV certificate, or an elliptic-curve certificate omits its domain parameters and no inherited curve was supplied.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer and the parsed carriers transfers to the returned certificate; the catch disposes them on a partial parse failure.")]
    public static CardVerifiableCertificate Parse(ReadOnlySpan<byte> certificate, MemoryPool<byte> pool, Tag? inheritedCurve = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new ApduReader(certificate);
        ExpectTag(ref reader, CertificateTag, "CV certificate");
        int outerContentLength = reader.ReadTlvLength();
        int outerHeaderLength = reader.Consumed;
        int totalLength = outerHeaderLength + outerContentLength;
        ReadOnlySpan<byte> outerContent = reader.ReadBytes(outerContentLength);

        //The signature is computed over the encoded body (7F4E) including its tag and length (§C.1.8), so
        //capture that exact span. The body is the first element of the outer content, the signature follows.
        var outer = new ApduReader(outerContent);
        ExpectTag(ref outer, CertificateBodyTag, "certificate body");
        int bodyContentLength = outer.ReadTlvLength();
        int bodyHeaderLength = outer.Consumed;
        int bodyTlvLength = bodyHeaderLength + bodyContentLength;
        ReadOnlySpan<byte> bodyContent = outer.ReadBytes(bodyContentLength);
        ReadOnlySpan<byte> signatureValue = ReadPrimitive(ref outer, SignatureTag, "signature");

        int bodyOffset = outerHeaderLength;
        int bodyLength = bodyTlvLength;

        CardVerifiableCertificatePublicKey? publicKey = null;
        CertificateHolderAuthorizationTemplate? chat = null;
        Signature? signature = null;
        IMemoryOwner<byte>? encoded = null;
        try
        {
            var body = new ApduReader(bodyContent);
            byte profileId = ParseProfileIdentifier(ref body);
            string car = ReadString(ref body, CertificationAuthorityReferenceTag, "Certification Authority Reference");
            publicKey = ParsePublicKey(ref body, pool, inheritedCurve);
            string chr = ReadString(ref body, CertificateHolderReferenceTag, "Certificate Holder Reference");
            chat = ParseChat(ref body, pool);
            DateOnly effectiveDate = ParseDate(ref body, EffectiveDateTag, "effective date");
            DateOnly expirationDate = ParseDate(ref body, ExpirationDateTag, "expiration date");

            signature = CopySignature(signatureValue, pool);
            encoded = pool.Rent(totalLength);
            certificate[..totalLength].CopyTo(encoded.Memory.Span);

            return new CardVerifiableCertificate(
                encoded, profileId, car, chr, publicKey, chat, effectiveDate, expirationDate, signature, bodyOffset, bodyLength, outerContentLength);
        }
        catch
        {
            encoded?.Dispose();
            signature?.Dispose();
            chat?.Dispose();
            publicKey?.Dispose();
            throw;
        }
    }


    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            PublicKey.Dispose();
            Chat.Dispose();
            Signature.Dispose();
        }

        base.Dispose(disposing);
    }


    /// <summary>
    /// Reads the certificate profile identifier (<c>5F29</c>), a single octet.
    /// </summary>
    private static byte ParseProfileIdentifier(ref ApduReader body)
    {
        ReadOnlySpan<byte> value = ReadPrimitive(ref body, CertificateProfileIdentifierTag, "certificate profile identifier");
        if(value.Length != 1)
        {
            throw new InvalidOperationException("A certificate profile identifier must be a single octet.");
        }

        return value[0];
    }


    /// <summary>
    /// Parses the public key (<c>7F49</c>): the algorithm object identifier, then either the elliptic-curve
    /// domain parameters and public point or the RSA modulus and exponent.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the key carrier transfers to the returned public key; the catch disposes it on a partial parse failure.")]
    private static CardVerifiableCertificatePublicKey ParsePublicKey(ref ApduReader body, MemoryPool<byte> pool, Tag? inheritedCurve)
    {
        ApduReader publicKey = ReadConstructed(ref body, PublicKeyTag, "public key");
        ReadOnlySpan<byte> oid = ReadPrimitive(ref publicKey, ObjectIdentifierTag, "public-key object identifier");
        CvcSignatureScheme scheme = DecodeSignatureScheme(oid, out bool isRsa);

        return isRsa
            ? ParseRsaPublicKey(ref publicKey, scheme, pool)
            : ParseEllipticCurvePublicKey(ref publicKey, scheme, pool, inheritedCurve);
    }


    /// <summary>
    /// Parses an elliptic-curve public key: the conditional domain parameters (present in a self-signed CVCA
    /// certificate, inherited otherwise), the mandatory uncompressed public point, and the optional cofactor.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the point carrier transfers to the returned public key; the catch disposes it on a partial parse failure.")]
    private static CardVerifiableCertificatePublicKey ParseEllipticCurvePublicKey(ref ApduReader publicKey, CvcSignatureScheme scheme, MemoryPool<byte> pool, Tag? inheritedCurve)
    {
        bool includesDomainParameters = !publicKey.IsEmpty && publicKey.PeekBytes(1)[0] == PrimeTag;

        Tag curveTag;
        if(includesDomainParameters)
        {
            ReadOnlySpan<byte> prime = ReadPrimitive(ref publicKey, PrimeTag, "prime modulus");
            _ = ReadPrimitive(ref publicKey, CoefficientATag, "first coefficient");
            _ = ReadPrimitive(ref publicKey, CoefficientBTag, "second coefficient");
            _ = ReadPrimitive(ref publicKey, BasePointTag, "base point");
            _ = ReadPrimitive(ref publicKey, OrderTag, "order of the base point");

            EllipticCurveTypes curve = EllipticCurveUtilities.CurveTypeFromPrime(prime);
            if(curve == EllipticCurveTypes.None)
            {
                throw new InvalidOperationException("The CV certificate public key uses an unsupported elliptic curve.");
            }

            curveTag = ExchangeTagFor(curve);
        }
        else
        {
            curveTag = inheritedCurve
                ?? throw new InvalidOperationException("An elliptic-curve CV certificate that omits its domain parameters requires the issuing curve to be supplied.");
        }

        ReadOnlySpan<byte> point = ReadPrimitive(ref publicKey, PublicPointTag, "public point");
        if(point.Length < 1 || point[0] != 0x04)
        {
            throw new InvalidOperationException("A CV certificate public point must be an uncompressed elliptic-curve point.");
        }

        //Every sibling field here is length-validated; validate the point length too. Extracting the coordinates
        //rejects a truncated point — for example the bare 0x04 byte this prefix-only check would otherwise accept —
        //that would only surface as an uncaught exception when the key is later used to verify a signature. The
        //curve-specific length and on-curve checks stay in the cryptographic layer that consumes the key.
        try
        {
            EllipticCurveUtilities.ExtractCoordinates(point, EllipticCurveTypes.None, out _, out _);
        }
        catch(ArgumentOutOfRangeException exception)
        {
            throw new InvalidOperationException("A CV certificate public point must be a supported-length uncompressed elliptic-curve point.", exception);
        }

        if(!publicKey.IsEmpty && publicKey.PeekBytes(1)[0] == CofactorTag)
        {
            _ = ReadPrimitive(ref publicKey, CofactorTag, "cofactor");
        }

        EncodedEcPoint ecPoint = EncodedEcPoint.FromBytes(point, curveTag, pool);
        try
        {
            return CardVerifiableCertificatePublicKey.ForEllipticCurve(scheme, ecPoint, includesDomainParameters);
        }
        catch
        {
            ecPoint.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Parses an RSA public key: the modulus and exponent, re-encoded into a DER <c>RSAPublicKey</c> sequence.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the RSA key carrier transfers to the returned public key; the catch disposes it on a partial parse failure.")]
    private static CardVerifiableCertificatePublicKey ParseRsaPublicKey(ref ApduReader publicKey, CvcSignatureScheme scheme, MemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> modulus = ReadPrimitive(ref publicKey, RsaModulusTag, "RSA modulus");
        ReadOnlySpan<byte> exponent = ReadPrimitive(ref publicKey, RsaExponentTag, "RSA public exponent");

        RsaPublicKey rsaKey = EncodeRsaPublicKey(modulus, exponent, pool);
        try
        {
            return CardVerifiableCertificatePublicKey.ForRsa(scheme, rsaKey);
        }
        catch
        {
            rsaKey.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Re-encodes an unsigned big-endian RSA modulus and exponent into a pooled DER
    /// <c>RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }</c> carrier, the form the
    /// library's RSA verification reconstructs a key from.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned RsaPublicKey; the catch disposes it on failure.")]
    private static RsaPublicKey EncodeRsaPublicKey(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent, MemoryPool<byte> pool)
    {
        int modulusContent = DerIntegerContentLength(modulus);
        int exponentContent = DerIntegerContentLength(exponent);
        int sequenceContent = BerTlvWriter.ElementSize(DerIntegerTag, modulusContent) + BerTlvWriter.ElementSize(DerIntegerTag, exponentContent);
        int total = BerTlvWriter.ElementSize(DerSequenceTag, sequenceContent);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(DerSequenceTag, sequenceContent);
            WriteDerInteger(ref writer, modulus, modulusContent);
            WriteDerInteger(ref writer, exponent, exponentContent);

            return new RsaPublicKey(owner);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Writes a DER INTEGER from an unsigned big-endian value, prepending a <c>0x00</c> sign octet when the
    /// leading bit is set so the value stays positive.
    /// </summary>
    private static void WriteDerInteger(ref BerTlvWriter writer, ReadOnlySpan<byte> value, int contentLength)
    {
        writer.WriteHeader(DerIntegerTag, contentLength);
        if(value.Length > 0 && value[0] >= 0x80)
        {
            writer.WriteValue([0x00]);
        }

        writer.WriteValue(value);
    }


    /// <summary>
    /// The DER INTEGER content length of an unsigned big-endian value — its length plus a sign octet when the leading bit is set.
    /// </summary>
    private static int DerIntegerContentLength(ReadOnlySpan<byte> value) =>
        value.Length + (value.Length > 0 && value[0] >= 0x80 ? 1 : 0);


    /// <summary>
    /// Decodes a Terminal Authentication public-key object identifier into its signature scheme and hash,
    /// reporting whether it is an RSA scheme.
    /// </summary>
    private static CvcSignatureScheme DecodeSignatureScheme(ReadOnlySpan<byte> oid, out bool isRsa)
    {
        if(oid.Length == IdTaEcdsaPrefix.Length + 1)
        {
            ReadOnlySpan<byte> prefix = oid[..^1];
            byte arc = oid[^1];

            if(prefix.SequenceEqual(IdTaEcdsaPrefix))
            {
                isRsa = false;
                return arc switch
                {
                    0x01 => CvcSignatureScheme.EcdsaSha1,
                    0x02 => CvcSignatureScheme.EcdsaSha224,
                    0x03 => CvcSignatureScheme.EcdsaSha256,
                    0x04 => CvcSignatureScheme.EcdsaSha384,
                    0x05 => CvcSignatureScheme.EcdsaSha512,
                    _ => throw new InvalidOperationException("Unsupported id-TA-ECDSA hash arc in the CV certificate public-key object identifier.")
                };
            }

            if(prefix.SequenceEqual(IdTaRsaPrefix))
            {
                isRsa = true;
                return arc switch
                {
                    0x01 => CvcSignatureScheme.RsaPkcs1Sha1,
                    0x02 => CvcSignatureScheme.RsaPkcs1Sha256,
                    0x03 => CvcSignatureScheme.RsaPssSha1,
                    0x04 => CvcSignatureScheme.RsaPssSha256,
                    0x05 => CvcSignatureScheme.RsaPkcs1Sha512,
                    0x06 => CvcSignatureScheme.RsaPssSha512,
                    _ => throw new InvalidOperationException("Unsupported id-TA-RSA scheme arc in the CV certificate public-key object identifier.")
                };
            }
        }

        throw new InvalidOperationException("The CV certificate public-key object identifier is not an id-TA-ECDSA or id-TA-RSA identifier.");
    }


    /// <summary>
    /// Parses the Certificate Holder Authorization Template (<c>7F4C</c>): the terminal-type object
    /// identifier and the discretionary-data value carrying the role and access rights.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned template; the catch disposes it on failure.")]
    private static CertificateHolderAuthorizationTemplate ParseChat(ref ApduReader body, MemoryPool<byte> pool)
    {
        ApduReader chat = ReadConstructed(ref body, CertificateHolderAuthorizationTemplateTag, "Certificate Holder Authorization Template");
        ReadOnlySpan<byte> oid = ReadPrimitive(ref chat, ObjectIdentifierTag, "Certificate Holder Authorization object identifier");
        TerminalType terminalType = DecodeTerminalType(oid);

        ReadOnlySpan<byte> rights = ReadPrimitive(ref chat, DiscretionaryDataTag, "Certificate Holder Authorization discretionary data");
        if(rights.IsEmpty)
        {
            throw new InvalidOperationException("A Certificate Holder Authorization Template must carry at least one discretionary-data octet.");
        }

        CertificateRole role = DecodeRole(rights[0]);

        IMemoryOwner<byte> owner = pool.Rent(rights.Length);
        try
        {
            rights.CopyTo(owner.Memory.Span);

            return new CertificateHolderAuthorizationTemplate(owner, terminalType, role);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Maps a Certificate Holder Authorization terminal-type object identifier to its <see cref="TerminalType"/>.
    /// </summary>
    private static TerminalType DecodeTerminalType(ReadOnlySpan<byte> oid)
    {
        if(oid.SequenceEqual(IdInspectionSystem))
        {
            return TerminalType.InspectionSystem;
        }

        if(oid.SequenceEqual(IdAuthenticationTerminal))
        {
            return TerminalType.AuthenticationTerminal;
        }

        if(oid.SequenceEqual(IdSignatureTerminal))
        {
            return TerminalType.SignatureTerminal;
        }

        throw new InvalidOperationException("The Certificate Holder Authorization Template object identifier is not a known terminal type.");
    }


    /// <summary>
    /// Decodes the certificate role from the leading two bits of the authorization value.
    /// </summary>
    private static CertificateRole DecodeRole(byte firstRightsOctet) => (firstRightsOctet & 0xC0) switch
    {
        0x00 => CertificateRole.Terminal,
        0x40 => CertificateRole.DocumentVerifierNonOfficialOrForeign,
        0x80 => CertificateRole.DocumentVerifierOfficialDomestic,
        _ => CertificateRole.CertificationAuthority
    };


    /// <summary>
    /// Parses a certificate date (<c>5F25</c>/<c>5F24</c>): six octets of unpacked BCD in <c>YYMMDD</c> form,
    /// the year relative to 2000.
    /// </summary>
    private static DateOnly ParseDate(ref ApduReader body, int tag, string elementName)
    {
        ReadOnlySpan<byte> value = ReadPrimitive(ref body, tag, elementName);
        if(value.Length != 6)
        {
            throw new InvalidOperationException($"A certificate {elementName} must be six octets.");
        }

        foreach(byte digit in value)
        {
            if(digit > 9)
            {
                throw new InvalidOperationException($"A certificate {elementName} octet must be a single decimal digit.");
            }
        }

        int year = 2000 + (value[0] * 10) + value[1];
        int month = (value[2] * 10) + value[3];
        int day = (value[4] * 10) + value[5];
        try
        {
            return new DateOnly(year, month, day);
        }
        catch(ArgumentOutOfRangeException exception)
        {
            throw new InvalidOperationException($"A certificate {elementName} is not a valid calendar date.", exception);
        }
    }


    /// <summary>
    /// Copies the signature value (<c>5F37</c>) into a pooled <see cref="Signature"/> carrier; the algorithm
    /// is determined by the issuing key, so the carrier is tagged algorithm-agnostically.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned Signature; the catch disposes it on failure.")]
    private static Signature CopySignature(ReadOnlySpan<byte> value, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(value.Length);
        try
        {
            value.CopyTo(owner.Memory.Span);

            return new Signature(owner, CryptoTags.AlgorithmAgnosticSignature);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Maps a recognised curve to the ECDH exchange-key <see cref="Tag"/> used to carry its uncompressed
    /// public point — the same encoding eMRTD chip-authentication keys use, which the registered
    /// verification functions accept as a verification key.
    /// </summary>
    private static Tag ExchangeTagFor(EllipticCurveTypes curve) => curve switch
    {
        EllipticCurveTypes.P256 => CryptoTags.P256ExchangePublicKey,
        EllipticCurveTypes.P384 => CryptoTags.P384ExchangePublicKey,
        EllipticCurveTypes.P521 => CryptoTags.P521ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP224r1 => CryptoTags.BrainpoolP224r1ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP256r1 => CryptoTags.BrainpoolP256r1ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP320r1 => CryptoTags.BrainpoolP320r1ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP384r1 => CryptoTags.BrainpoolP384r1ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP512r1 => CryptoTags.BrainpoolP512r1ExchangePublicKey,
        _ => throw new InvalidOperationException("The CV certificate public key uses an elliptic curve not supported for Terminal Authentication.")
    };


    /// <summary>
    /// Reads a constructed element of the expected tag and returns a reader over its content.
    /// </summary>
    private static ApduReader ReadConstructed(ref ApduReader reader, int expectedTag, string elementName)
    {
        ExpectTag(ref reader, expectedTag, elementName);

        return new ApduReader(reader.ReadBytes(reader.ReadTlvLength()));
    }


    /// <summary>
    /// Reads a primitive element of the expected tag and returns its value bytes.
    /// </summary>
    private static ReadOnlySpan<byte> ReadPrimitive(ref ApduReader reader, int expectedTag, string elementName)
    {
        ExpectTag(ref reader, expectedTag, elementName);

        return reader.ReadBytes(reader.ReadTlvLength());
    }


    /// <summary>
    /// Reads an ASCII character-string element (a Certification Authority Reference or Certificate Holder Reference).
    /// </summary>
    private static string ReadString(ref ApduReader reader, int expectedTag, string elementName) =>
        Encoding.ASCII.GetString(ReadPrimitive(ref reader, expectedTag, elementName));


    /// <summary>
    /// Reads and checks the expected tag, throwing when it does not match.
    /// </summary>
    private static void ExpectTag(ref ApduReader reader, int expectedTag, string elementName)
    {
        int tag = reader.ReadTag();
        if(tag != expectedTag)
        {
            throw new InvalidOperationException($"Expected a {elementName} element (tag 0x{expectedTag:X2}), found 0x{tag:X2}.");
        }
    }
}
