using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A fully managed implementation of <see cref="VerifyCmsSignedDataDelegate"/> and of its detached counterpart
/// <see cref="VerifyDetachedCmsSignedDataDelegate"/> (which is also what that seam resolves to when a host
/// registers nothing for it): it parses the CMS SignedData
/// structure (RFC 5652) with <see cref="System.Formats.Asn1"/> and verifies the signature through the
/// library's own registered cryptographic seams — the <see cref="VerificationDelegate"/> for the raw
/// elliptic-curve primitive and <see cref="CryptographicKeyEvents.ComputeDigestAsync"/> for the digest — with
/// no dependency on <c>System.Security.Cryptography.Pkcs.SignedCms</c> or a third-party CMS library.
/// </summary>
/// <remarks>
/// <para>
/// This owns the CMS format logic and delegates only the lowest cryptographic primitive, the codebase's
/// "own the format, delegate the primitive" shape, so the same backend works over whichever provider is
/// registered for the elliptic-curve verification. It produces the same <see cref="CmsVerifiedContent"/> as
/// the Microsoft and BouncyCastle backends — content, embedded certificates (signer first), and the signer's
/// signed attributes — so eMRTD Passive Authentication and CAdES verify over it unchanged.
/// </para>
/// <para>
/// This verifies elliptic-curve (ECDSA) signers, the modern eMRTD and eID case; RSASSA-PKCS1-v1_5 RSA
/// signers under SHA-256, SHA-384 or SHA-512 (see <c>VerifyRsaAsync</c> for the exact RSA profile and its
/// key-length band); and ML-DSA signers (NIST FIPS 204, see <c>VerifyMlDsaAsync</c>), the quantum-resistant
/// family, each through its registered verification delegate — so a host's own providers carry every
/// primitive. The signer's signature covers the signed attributes (RFC 5652 §5.4), so the signature is
/// checked over the DER re-encoding of the SignedAttributes (the implicit <c>[0]</c> tag replaced by the
/// universal <c>SET OF</c> tag), and the <c>message-digest</c> attribute is checked to equal the hash of the
/// encapsulated content. As with the other backends, trust in the signer certificate is the separate
/// certificate-chain step.
/// </para>
/// </remarks>
public static class ManagedCmsVerification
{
    /// <summary>The id-signedData content type (RFC 5652 §5.1).</summary>
    private const string SignedDataOid = "1.2.840.113549.1.7.2";

    /// <summary>The id-data content type (RFC 5652 §4), the default eContentType.</summary>
    private const string DataOid = "1.2.840.113549.1.7.1";

    /// <summary>The message-digest signed attribute (RFC 5652 §11.2).</summary>
    private const string MessageDigestOid = "1.2.840.113549.1.9.4";

    /// <summary>The universal <c>SET OF</c> tag octet that replaces the signed attributes' implicit <c>[0]</c> tag for the signature (RFC 5652 §5.4).</summary>
    private const byte SetOfTag = 0x31;

    /// <summary>The RSA public exponent 65537 the registered RSA verification seam assumes.</summary>
    private static ReadOnlySpan<byte> Exponent65537 => [0x01, 0x00, 0x01];

    /// <summary>
    /// The smallest RSA modulus bit length an RSA signer is verified at.
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/01.04.03_60/ts_119312v010403p.pdf">
    /// ETSI TS 119 312 V1.4.3</see> Tables 9 and 10 keep 2048-bit RSA legal for validation while sizing new
    /// keys at 3&#160;000 bits or more after 2025, so the floor admits both without dropping to strengths the
    /// suites specification no longer lists.
    /// </summary>
    private static int MinimumRsaModulusBitLength => 2048;

    /// <summary>
    /// The largest RSA modulus bit length an RSA signer is verified at — the largest the underlying providers
    /// implement — bounding the modular-exponentiation work an untrusted certificate can demand before any
    /// signature mathematics run.
    /// </summary>
    private static int MaximumRsaModulusBitLength => 16384;

    /// <summary>The ML-DSA-44 public key length in octets (NIST FIPS 204 Table 2).</summary>
    private static int MlDsa44PublicKeyLength => 1312;

    /// <summary>The ML-DSA-65 public key length in octets (NIST FIPS 204 Table 2).</summary>
    private static int MlDsa65PublicKeyLength => 1952;

    /// <summary>The ML-DSA-87 public key length in octets (NIST FIPS 204 Table 2).</summary>
    private static int MlDsa87PublicKeyLength => 2592;


    /// <summary>
    /// Implements <see cref="VerifyCmsSignedDataDelegate"/> with managed parsing and the registered
    /// verification and digest seams.
    /// </summary>
    /// <param name="signedData">The CMS SignedData carrier with encapsulated content.</param>
    /// <param name="pool">The memory pool for the content, certificate, and signed-attribute allocations.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verified content and embedded certificates. The caller disposes it.</returns>
    /// <exception cref="CryptographicException">Thrown when the structure is malformed, the signer's key family or parameters are outside the supported profile, the content digest does not match, or the signature does not verify.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the content buffer, certificate memories, and signed-attribute carriers transfers to the returned CmsVerifiedContent, which the caller disposes; the catch disposes them on a partial failure.")]
    public static async ValueTask<CmsVerifiedContent> VerifyCmsSignedDataAsync(
        CmsSignedData signedData,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        ParsedSignedData parsed;
        try
        {
            parsed = ParseSignedData(signedData.AsReadOnlySpan());
        }
        catch(AsnContentException exception)
        {
            throw new CryptographicException("The CMS SignedData is not well-formed DER.", exception);
        }

        ManagedCertificate signerCertificate = MatchSigner(parsed.Certificates, parsed.Signer)
            ?? throw new CryptographicException("The CMS SignedData does not embed the signer certificate.");

        //The signature covers the signed attributes, which must bind the content through message-digest.
        await VerifyMessageDigestAsync(parsed, pool, cancellationToken).ConfigureAwait(false);
        await VerifySignatureAsync(parsed.Signer, signerCertificate, pool, cancellationToken).ConfigureAwait(false);

        return BuildVerifiedContent(parsed, signerCertificate, pool);
    }


    /// <summary>
    /// Verifies a CMS SignedData that encapsulates no content, against content the caller supplies from beside
    /// it — a detached signature, which is what
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
    /// ETSI EN 319 162-1 V1.1.1</see> clause 4.4.4.2 item 3 a) and clause 4.3.3.2 item 4 b) put inside an
    /// Associated Signature Container.
    /// </summary>
    /// <param name="signedData">The CMS SignedData carrier, which encapsulates no content.</param>
    /// <param name="detachedContent">The octets the signature is detached over — the Signer's Document of Table 18 of ETSI EN 319 102-1 clause 5.3.2.</param>
    /// <param name="pool">The memory pool for the content, certificate, and signed-attribute allocations.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verified content and embedded certificates. The caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">Thrown when the structure is malformed, encapsulates content of its own, the supplied content does not match the <c>message-digest</c> attribute, or the signature does not verify.</exception>
    /// <remarks>
    /// <para>
    /// Nothing about the cryptography differs from the encapsulated case: the signature covers the DER
    /// re-encoding of the signed attributes (RFC 5652 §5.4), which is the same octets whether the content
    /// travels inside the structure or beside it, and the <c>message-digest</c> attribute is what binds the
    /// content either way. The one difference is where the content comes from, and that is exactly what this
    /// overload takes as a parameter.
    /// </para>
    /// <para>
    /// A structure that <em>does</em> encapsulate content is refused rather than verified against the supplied
    /// octets: two different contents would then be in play and only one of them checked, which is the shape a
    /// substitution attack takes.
    /// </para>
    /// <para>
    /// This implements <see cref="VerifyDetachedCmsSignedDataDelegate"/> and is what that seam resolves to when
    /// a host registers nothing for it — the same RSA profile this file's encapsulated member accepts (see
    /// <c>VerifyRsaAsync</c>: RSASSA-PKCS1-v1_5 with SHA-256, SHA-384 or SHA-512, exponent 65537, moduli of
    /// 2048 to 16384 bits), so a host whose material is outside that profile — RSASSA-PSS, say — registers a
    /// backend rather than being refused by one.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the content buffer, certificate memories, and signed-attribute carriers transfers to the returned CmsVerifiedContent, which the caller disposes; the catch disposes them on a partial failure.")]
    public static async ValueTask<CmsVerifiedContent> VerifyDetachedCmsSignedDataAsync(
        CmsSignedData signedData,
        SignedContentMemory detachedContent,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(detachedContent);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        ParsedSignedData parsed;
        try
        {
            parsed = ParseSignedData(signedData.AsReadOnlySpan());
        }
        catch(AsnContentException exception)
        {
            throw new CryptographicException("The CMS SignedData is not well-formed DER.", exception);
        }

        if(!parsed.Content.IsEmpty)
        {
            throw new CryptographicException("The CMS SignedData encapsulates content of its own, so it is not a detached signature.");
        }

        ManagedCertificate signerCertificate = MatchSigner(parsed.Certificates, parsed.Signer)
            ?? throw new CryptographicException("The CMS SignedData does not embed the signer certificate.");

        ParsedSignedData withDetachedContent = parsed with { Content = detachedContent.AsReadOnlyMemory() };
        await VerifyMessageDigestAsync(withDetachedContent, pool, cancellationToken).ConfigureAwait(false);
        await VerifySignatureAsync(withDetachedContent.Signer, signerCertificate, pool, cancellationToken).ConfigureAwait(false);

        return BuildVerifiedContent(withDetachedContent, signerCertificate, pool);
    }


    /// <summary>
    /// Verifies the message-digest signed attribute equals the hash of the encapsulated content under the
    /// SignerInfo digest algorithm.
    /// </summary>
    private static async ValueTask VerifyMessageDigestAsync(ParsedSignedData parsed, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        if(!TryGetAttributeValue(parsed.Signer.SignedAttributeList, MessageDigestOid, out ReadOnlyMemory<byte> messageDigestValue))
        {
            throw new CryptographicException("The CMS SignedData signer has no message-digest attribute.");
        }

        byte[] expectedDigest = new AsnReader(messageDigestValue, AsnEncodingRules.DER).ReadOctetString();

        (Tag digestTag, int digestLength) = DigestForOid(parsed.Signer.DigestAlgorithmOid);
        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
            parsed.Content, digestLength, digestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!computed.AsReadOnlySpan().SequenceEqual(expectedDigest))
        {
            throw new CryptographicException("The CMS message-digest attribute does not match the encapsulated content.");
        }
    }


    /// <summary>
    /// Verifies the signer's signature over the DER re-encoding of its signed attributes (the universal
    /// <c>SET OF</c> tag in place of the implicit <c>[0]</c>, RFC 5652 §5.4) against the signer certificate's
    /// public key, through the registered verification function — elliptic-curve, RSA or ML-DSA.
    /// </summary>
    private static async ValueTask VerifySignatureAsync(SignerInfo signer, ManagedCertificate signerCertificate, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> signedMessage = ReencodeSignedAttributes(signer.SignedAttributes.Span, pool, out int messageLength);

        bool verified = signerCertificate.EllipticCurve != EllipticCurveTypes.None
            ? await VerifyEllipticCurveAsync(signer, signerCertificate, signedMessage.Memory[..messageLength], pool, cancellationToken).ConfigureAwait(false)
            : signerCertificate.RsaModulus.Length > 0
                ? await VerifyRsaAsync(signer, signerCertificate, signedMessage.Memory[..messageLength], cancellationToken).ConfigureAwait(false)
                : signerCertificate.MlDsaPublicKey.Length > 0
                    ? await VerifyMlDsaAsync(signer, signerCertificate, signedMessage.Memory[..messageLength], cancellationToken).ConfigureAwait(false)
                    : throw new CryptographicException("The managed CMS verifier supports only elliptic-curve, RSA and ML-DSA signers.");

        if(!verified)
        {
            throw new CryptographicException("The CMS signature did not verify against the signer certificate.");
        }
    }


    /// <summary>
    /// Verifies an elliptic-curve (ECDSA) signature: the DER <c>SEQUENCE { r, s }</c> is converted to the
    /// fixed-width <c>r ‖ s</c> the seam expects, and verified against the certificate's public point.
    /// </summary>
    private static async ValueTask<bool> VerifyEllipticCurveAsync(SignerInfo signer, ManagedCertificate signerCertificate, ReadOnlyMemory<byte> signedMessage, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        CryptoAlgorithm algorithm = CurveAlgorithm(signerCertificate.EllipticCurve);
        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification);

        int fieldWidth = (signerCertificate.PublicPoint.Length - 1) / 2;
        using IMemoryOwner<byte> signature = ConvertDerSignatureToFixedWidth(signer.Signature.Span, fieldWidth, pool);

        (bool isVerified, CryptoEvent? evt) = await verify(
            signedMessage, signature.Memory[..(fieldWidth * 2)], signerCertificate.PublicPoint, null, cancellationToken).ConfigureAwait(false);

        CryptographicKeyEvents.Emit(evt);

        return isVerified;
    }


    /// <summary>
    /// Verifies an RSA (RSASSA-PKCS1-v1_5) signature against the certificate's RSA public key through the
    /// hash-parameterized RSA verification seam. The accepted profile is RSASSA-PKCS1-v1_5 with SHA-256,
    /// SHA-384 or SHA-512, public exponent 65537, and a modulus inside the
    /// <see cref="MinimumRsaModulusBitLength"/>–<see cref="MaximumRsaModulusBitLength"/> band — covering the
    /// algorithms and post-2025 key lengths of
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/01.04.03_60/ts_119312v010403p.pdf">
    /// ETSI TS 119 312 V1.4.3</see> clause A.9 Table A.8 and Tables 9-10 — so other parameters are reported
    /// as unsupported.
    /// </summary>
    private static async ValueTask<bool> VerifyRsaAsync(SignerInfo signer, ManagedCertificate signerCertificate, ReadOnlyMemory<byte> signedMessage, CancellationToken cancellationToken)
    {
        //The signature algorithm is a combined shaNNNWithRSAEncryption that pins its own hash, or the bare
        //rsaEncryption with the hash carried by the digest algorithm (RFC 3370). A combined identifier must
        //agree with the SignerInfo digest algorithm: an inconsistent pair names two different computations at
        //once, the shape an algorithm-substitution attempt takes, and is refused rather than resolved in
        //either identifier's favor.
        string? acceptedDigestOid = signer.SignatureAlgorithmOid switch
        {
            WellKnownOids.Sha256WithRsaEncryption => WellKnownOids.Sha256,
            WellKnownOids.Sha384WithRsaEncryption => WellKnownOids.Sha384,
            WellKnownOids.Sha512WithRsaEncryption => WellKnownOids.Sha512,
            WellKnownOids.RsaEncryption => signer.DigestAlgorithmOid,
            _ => null
        };

        CryptoAlgorithm? algorithm = string.Equals(signer.DigestAlgorithmOid, acceptedDigestOid, StringComparison.Ordinal)
            ? acceptedDigestOid switch
            {
                WellKnownOids.Sha256 => CryptoAlgorithm.RsaSha256,
                WellKnownOids.Sha384 => CryptoAlgorithm.RsaSha384,
                WellKnownOids.Sha512 => CryptoAlgorithm.RsaSha512,
                _ => (CryptoAlgorithm?)null
            }
            : null;
        if(algorithm is null)
        {
            throw new CryptographicException($"The managed CMS verifier supports only RSASSA-PKCS1-v1_5 with SHA-256, SHA-384 or SHA-512 for RSA signers, with the digest algorithm agreeing with the signature algorithm (signature '{signer.SignatureAlgorithmOid}', digest '{signer.DigestAlgorithmOid}').");
        }

        if(!signerCertificate.RsaExponent.Span.SequenceEqual(Exponent65537))
        {
            throw new CryptographicException("The managed CMS verifier supports only RSA public exponent 65537.");
        }

        //A policy band replaces the former 2048-/4096-bit whitelist: any non-degenerate RSA public key from
        //MinimumRsaModulusBitLength to MaximumRsaModulusBitLength verifies, so a 3072-bit key — the natural
        //post-2025 choice under TS 119 312 V1.4.3 Table 10 — is inside the band rather than refused.
        if(!RsaUtilities.IsValidPublicKey(signerCertificate.RsaModulus.Span, signerCertificate.RsaExponent.Span, MinimumRsaModulusBitLength, MaximumRsaModulusBitLength))
        {
            throw new CryptographicException($"The managed CMS verifier accepts RSA moduli from {MinimumRsaModulusBitLength} to {MaximumRsaModulusBitLength} bits.");
        }

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm.Value, Purpose.Verification);

        //The registered RSA seam takes the raw modulus and the RSA signature as-is (no re-encoding).
        (bool isVerified, CryptoEvent? evt) = await verify(
            signedMessage, signer.Signature, signerCertificate.RsaModulus, null, cancellationToken).ConfigureAwait(false);

        CryptographicKeyEvents.Emit(evt);

        return isVerified;
    }


    /// <summary>
    /// Verifies an ML-DSA (NIST FIPS 204) signature against the certificate's raw ML-DSA public key through
    /// the registered ML-DSA verification seam. The <c>SignerInfo</c> signature algorithm must state the same
    /// parameter-set identifier the certificate's <c>SubjectPublicKeyInfo</c> pins — a signature claimed under
    /// a different set names a computation the key does not perform, the substitution shape — and the pure
    /// (non-pre-hashed) signature covers the DER re-encoding of the signed attributes exactly as the other
    /// signer families' do.
    /// </summary>
    private static async ValueTask<bool> VerifyMlDsaAsync(SignerInfo signer, ManagedCertificate signerCertificate, ReadOnlyMemory<byte> signedMessage, CancellationToken cancellationToken)
    {
        if(!string.Equals(signer.SignatureAlgorithmOid, signerCertificate.MlDsaAlgorithmOid, StringComparison.Ordinal))
        {
            throw new CryptographicException($"The managed CMS verifier requires an ML-DSA signature algorithm equal to the certificate key's parameter set (signature '{signer.SignatureAlgorithmOid}', key '{signerCertificate.MlDsaAlgorithmOid}').");
        }

        (CryptoAlgorithm Algorithm, int PublicKeyLength) resolved = signerCertificate.MlDsaAlgorithmOid switch
        {
            WellKnownOids.MlDsa44 => (CryptoAlgorithm.MlDsa44, MlDsa44PublicKeyLength),
            WellKnownOids.MlDsa65 => (CryptoAlgorithm.MlDsa65, MlDsa65PublicKeyLength),
            WellKnownOids.MlDsa87 => (CryptoAlgorithm.MlDsa87, MlDsa87PublicKeyLength),
            _ => throw new CryptographicException($"The ML-DSA parameter set '{signerCertificate.MlDsaAlgorithmOid}' has no verification algorithm.")
        };

        //An ML-DSA public key has one exact length per parameter set, so any other length is a malformed key
        //refused here rather than handed to the registered backend, whose own malformed-encoding failure would
        //surface as an undocumented exception type on attacker-controlled certificate bytes.
        if(signerCertificate.MlDsaPublicKey.Length != resolved.PublicKeyLength)
        {
            throw new CryptographicException($"An ML-DSA public key of the parameter set '{signerCertificate.MlDsaAlgorithmOid}' is exactly {resolved.PublicKeyLength} octets (FIPS 204 Table 2).");
        }

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(resolved.Algorithm, Purpose.Verification);

        //The registered ML-DSA seam takes the raw FIPS 204 public key and signature as-is (no re-encoding).
        (bool isVerified, CryptoEvent? evt) = await verify(
            signedMessage, signer.Signature, signerCertificate.MlDsaPublicKey, null, cancellationToken).ConfigureAwait(false);

        CryptographicKeyEvents.Emit(evt);

        return isVerified;
    }


    /// <summary>
    /// Assembles the verified content: the encapsulated content, the certificates (signer first), and the
    /// signed attributes, each in a pooled carrier.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the content buffer, certificate memories, and signed-attribute carriers transfers to the returned CmsVerifiedContent; the catch disposes them on a partial failure.")]
    private static CmsVerifiedContent BuildVerifiedContent(ParsedSignedData parsed, ManagedCertificate signerCertificate, BaseMemoryPool pool)
    {
        var certificates = new List<PkiCertificateMemory>(parsed.Certificates.Count);
        var signedAttributes = new List<CmsSignedAttribute>(parsed.Signer.SignedAttributeList.Count);
        IMemoryOwner<byte>? contentOwner = null;
        try
        {
            //The signer's certificate first, then the remaining embedded certificates.
            certificates.Add(ToPkiCertificate(signerCertificate.Encoded.Span, pool));
            foreach(ManagedCertificate certificate in parsed.Certificates)
            {
                if(!certificate.Encoded.Span.SequenceEqual(signerCertificate.Encoded.Span))
                {
                    certificates.Add(ToPkiCertificate(certificate.Encoded.Span, pool));
                }
            }

            foreach((string oid, ReadOnlyMemory<byte> value) in parsed.Signer.SignedAttributeList)
            {
                signedAttributes.Add(ToSignedAttribute(oid, value.Span, pool));
            }

            contentOwner = pool.Rent(parsed.Content.Length);
            parsed.Content.Span.CopyTo(contentOwner.Memory.Span);

            return new CmsVerifiedContent(parsed.ContentType, contentOwner, parsed.Content.Length, certificates, signerIndex: 0, signedAttributes);
        }
        catch
        {
            contentOwner?.Dispose();
            foreach(PkiCertificateMemory certificate in certificates)
            {
                certificate.Dispose();
            }

            foreach(CmsSignedAttribute attribute in signedAttributes)
            {
                attribute.Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Parses a CMS SignedData: the content type, the encapsulated content, the embedded certificates, and the
    /// first SignerInfo.
    /// </summary>
    private static ParsedSignedData ParseSignedData(ReadOnlySpan<byte> encoded)
    {
        var outer = new AsnReader(encoded.ToArray(), AsnEncodingRules.DER);
        AsnReader contentInfo = outer.ReadSequence();
        string contentInfoType = contentInfo.ReadObjectIdentifier();
        if(!string.Equals(contentInfoType, SignedDataOid, StringComparison.Ordinal))
        {
            throw new CryptographicException($"The CMS content type '{contentInfoType}' is not id-signedData.");
        }

        AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader signedData = explicitContent.ReadSequence();

        _ = signedData.ReadInteger();                                  //version
        _ = signedData.ReadSetOf();                                    //digestAlgorithms

        AsnReader encapContentInfo = signedData.ReadSequence();
        string eContentType = encapContentInfo.ReadObjectIdentifier();
        byte[] content = [];
        if(encapContentInfo.HasData)
        {
            AsnReader eContent = encapContentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            content = eContent.ReadOctetString();
        }

        var certificates = new List<ManagedCertificate>();
        if(signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            AsnReader certificateSet = signedData.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 0));
            while(certificateSet.HasData)
            {
                certificates.Add(ManagedCertificate.Parse(certificateSet.ReadEncodedValue()));
            }
        }

        if(signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            _ = signedData.ReadEncodedValue();                          //crls, not used
        }

        AsnReader signerInfos = signedData.ReadSetOf();
        SignerInfo signer = ParseSignerInfo(signerInfos.ReadSequence());

        return new ParsedSignedData(eContentType.Length == 0 ? DataOid : eContentType, content, certificates, signer);
    }


    /// <summary>
    /// Parses a SignerInfo: the signer identifier, the digest algorithm, the signed attributes (raw and
    /// itemised), and the signature value.
    /// </summary>
    private static SignerInfo ParseSignerInfo(AsnReader signerInfo)
    {
        _ = signerInfo.ReadInteger();                                  //version
        SignerIdentifier sid = ParseSignerIdentifier(signerInfo);

        AsnReader digestAlgorithm = signerInfo.ReadSequence();
        string digestOid = digestAlgorithm.ReadObjectIdentifier();

        ReadOnlyMemory<byte> signedAttributes = ReadOnlyMemory<byte>.Empty;
        var signedAttributeList = new List<(string, ReadOnlyMemory<byte>)>();
        if(signerInfo.HasData && signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            signedAttributes = signerInfo.ReadEncodedValue();
            ParseAttributes(signedAttributes, new Asn1Tag(TagClass.ContextSpecific, 0), signedAttributeList);
        }

        AsnReader signatureAlgorithm = signerInfo.ReadSequence();
        string signatureAlgorithmOid = signatureAlgorithm.ReadObjectIdentifier();
        byte[] signature = signerInfo.ReadOctetString();

        //unsignedAttrs [1] IMPLICIT OPTIONAL — the signature is not computed over these (CAdES timestamps live here).
        var unsignedAttributeList = new List<(string, ReadOnlyMemory<byte>)>();
        if(signerInfo.HasData && signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            ParseAttributes(signerInfo.ReadEncodedValue(), new Asn1Tag(TagClass.ContextSpecific, 1), unsignedAttributeList);
        }

        return new SignerInfo(sid, digestOid, signatureAlgorithmOid, signedAttributes, signedAttributeList, signature, unsignedAttributeList);
    }


    /// <summary>
    /// Parses the first signer's signature value and unsigned attributes from a CMS SignedData, without
    /// verifying it — the additional material the CAdES layer needs for the timestamp (level T) over a
    /// signature the CMS seam has already verified at the baseline.
    /// </summary>
    /// <param name="signedData">The CMS SignedData bytes.</param>
    /// <returns>The signature value and the unsigned attributes (each type with its first DER value).</returns>
    /// <exception cref="CryptographicException">Thrown when the structure is not well-formed DER.</exception>
    internal static (ReadOnlyMemory<byte> SignatureValue, IReadOnlyList<(string Oid, ReadOnlyMemory<byte> Value)> UnsignedAttributes) ParseSignerExtras(ReadOnlySpan<byte> signedData)
    {
        try
        {
            ParsedSignedData parsed = ParseSignedData(signedData);

            return (parsed.Signer.Signature, parsed.Signer.UnsignedAttributeList);
        }
        catch(AsnContentException exception)
        {
            throw new CryptographicException("The CMS SignedData is not well-formed DER.", exception);
        }
    }


    /// <summary>
    /// Parses the signer identifier: an issuer-and-serial-number, or a subject-key-identifier (<c>[0]</c>).
    /// </summary>
    private static SignerIdentifier ParseSignerIdentifier(AsnReader signerInfo)
    {
        if(signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0))
        {
            byte[] subjectKeyIdentifier = signerInfo.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));

            return new SignerIdentifier(IssuerDer: default, SerialNumber: default, subjectKeyIdentifier);
        }

        AsnReader issuerAndSerial = signerInfo.ReadSequence();
        ReadOnlyMemory<byte> issuer = issuerAndSerial.ReadEncodedValue();
        ReadOnlyMemory<byte> serialNumber = issuerAndSerial.ReadIntegerBytes();

        return new SignerIdentifier(issuer, serialNumber, SubjectKeyIdentifier: ReadOnlyMemory<byte>.Empty);
    }


    /// <summary>
    /// Itemises a set of attributes (the implicit <c>[0]</c> signed or <c>[1]</c> unsigned set), collecting
    /// each attribute's type and first DER value.
    /// </summary>
    private static void ParseAttributes(ReadOnlyMemory<byte> attributes, Asn1Tag setTag, List<(string, ReadOnlyMemory<byte>)> into)
    {
        var reader = new AsnReader(attributes, AsnEncodingRules.DER);
        AsnReader set = reader.ReadSetOf(skipSortOrderValidation: true, setTag);
        while(set.HasData)
        {
            AsnReader attribute = set.ReadSequence();
            string attributeType = attribute.ReadObjectIdentifier();
            AsnReader values = attribute.ReadSetOf();
            if(values.HasData)
            {
                into.Add((attributeType, values.ReadEncodedValue()));
            }
        }
    }


    /// <summary>
    /// Re-encodes the signed attributes for the signature: the implicit <c>[0]</c> tag is replaced by the
    /// universal <c>SET OF</c> tag (RFC 5652 §5.4); the content and length octets are unchanged.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, which disposes it via a using declaration.")]
    private static IMemoryOwner<byte> ReencodeSignedAttributes(ReadOnlySpan<byte> signedAttributes, BaseMemoryPool pool, out int length)
    {
        IMemoryOwner<byte> owner = pool.Rent(signedAttributes.Length);
        try
        {
            signedAttributes.CopyTo(owner.Memory.Span);
            owner.Memory.Span[0] = SetOfTag;
            length = signedAttributes.Length;

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Converts a DER <c>ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }</c> to the fixed-width
    /// <c>r ‖ s</c> form the verification seam expects, left-padding each coordinate to the field width.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, which disposes it via a using declaration.")]
    private static IMemoryOwner<byte> ConvertDerSignatureToFixedWidth(ReadOnlySpan<byte> derSignature, int fieldWidth, BaseMemoryPool pool)
    {
        var reader = new AsnReader(derSignature.ToArray(), AsnEncodingRules.DER);
        AsnReader sequence = reader.ReadSequence();
        ReadOnlySpan<byte> r = StripLeadingZero(sequence.ReadIntegerBytes().Span);
        ReadOnlySpan<byte> s = StripLeadingZero(sequence.ReadIntegerBytes().Span);

        if(r.Length > fieldWidth || s.Length > fieldWidth)
        {
            throw new CryptographicException("The CMS ECDSA signature coordinates exceed the curve field width.");
        }

        IMemoryOwner<byte> owner = pool.Rent(fieldWidth * 2);
        try
        {
            Span<byte> span = owner.Memory.Span[..(fieldWidth * 2)];
            span.Clear();
            r.CopyTo(span[(fieldWidth - r.Length)..fieldWidth]);
            s.CopyTo(span[(fieldWidth * 2 - s.Length)..]);

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Strips a single leading <c>0x00</c> sign octet from a DER INTEGER's two's-complement encoding.
    /// </summary>
    private static ReadOnlySpan<byte> StripLeadingZero(ReadOnlySpan<byte> integer) =>
        integer.Length > 1 && integer[0] == 0x00 ? integer[1..] : integer;


    /// <summary>
    /// Matches the signer identifier to an embedded certificate by issuer-and-serial-number or subject-key-identifier.
    /// </summary>
    private static ManagedCertificate? MatchSigner(IReadOnlyList<ManagedCertificate> certificates, SignerInfo signer)
    {
        foreach(ManagedCertificate certificate in certificates)
        {
            if(!signer.SignerIdentifier.SubjectKeyIdentifier.IsEmpty)
            {
                if(!certificate.SubjectKeyIdentifier.IsEmpty
                    && certificate.SubjectKeyIdentifier.Span.SequenceEqual(signer.SignerIdentifier.SubjectKeyIdentifier.Span))
                {
                    return certificate;
                }
            }
            else if(certificate.IssuerDer.Span.SequenceEqual(signer.SignerIdentifier.IssuerDer.Span)
                && certificate.SerialNumber.Span.SequenceEqual(signer.SignerIdentifier.SerialNumber.Span))
            {
                return certificate;
            }
        }

        return null;
    }


    /// <summary>
    /// Finds a signed attribute's first value by object identifier.
    /// </summary>
    private static bool TryGetAttributeValue(List<(string Oid, ReadOnlyMemory<byte> Value)> attributes, string oid, out ReadOnlyMemory<byte> value)
    {
        foreach((string candidate, ReadOnlyMemory<byte> candidateValue) in attributes)
        {
            if(string.Equals(candidate, oid, StringComparison.Ordinal))
            {
                value = candidateValue;

                return true;
            }
        }

        value = default;

        return false;
    }


    /// <summary>
    /// Copies a DER-encoded certificate into a pooled <see cref="PkiCertificateMemory"/> carrier tagged as an
    /// X.509 certificate.
    /// </summary>
    /// <param name="der">The DER octets of the certificate as they appear in the <c>certificates</c> field.</param>
    /// <param name="pool">The pool the returned carrier rents its memory from.</param>
    /// <returns>A carrier owning a copy of <paramref name="der"/>.</returns>
    /// <remarks>
    /// The octets are copied rather than referenced because the decoded structure the span points into is
    /// released when the enclosing verification returns, while the carrier outlives it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 clause 5.1</see> states the
    /// <c>certificates</c> field the octets are read from.
    /// </remarks>
    private static PkiCertificateMemory ToPkiCertificate(ReadOnlySpan<byte> der, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Copies a signed attribute's DER-encoded value into a pooled <see cref="CmsSignedAttribute"/> carrier.
    /// </summary>
    /// <param name="oid">The object identifier of the attribute type.</param>
    /// <param name="der">The DER octets of the attribute value as they appear in <c>signedAttrs</c>.</param>
    /// <param name="pool">The pool the returned carrier rents its memory from.</param>
    /// <returns>A carrier owning a copy of <paramref name="der"/> under <paramref name="oid"/>.</returns>
    /// <remarks>
    /// The octets are copied for the same reason <see cref="ToPkiCertificate"/> copies its own: the decoded
    /// structure is released when the verification returns.
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652 clause 5.3</see> states the
    /// <c>signedAttrs</c> field the octets are read from.
    /// </remarks>
    private static CmsSignedAttribute ToSignedAttribute(string oid, ReadOnlySpan<byte> der, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new CmsSignedAttribute(oid, owner);
    }


    /// <summary>
    /// The digest <see cref="Tag"/> and output length for a digest-algorithm object identifier.
    /// </summary>
    private static (Tag Tag, int Length) DigestForOid(string digestOid) => digestOid switch
    {
        WellKnownOids.Sha256 => (CryptoTags.Sha256Digest, 32),
        WellKnownOids.Sha384 => (CryptoTags.Sha384Digest, 48),
        WellKnownOids.Sha512 => (CryptoTags.Sha512Digest, 64),
        _ => throw new CryptographicException($"The CMS digest algorithm '{digestOid}' is not supported by the managed verifier.")
    };


    /// <summary>
    /// The <see cref="CryptoAlgorithm"/> of a recognised elliptic curve, for resolving its verification function.
    /// </summary>
    private static CryptoAlgorithm CurveAlgorithm(EllipticCurveTypes curve) => curve switch
    {
        EllipticCurveTypes.P256 => CryptoAlgorithm.P256,
        EllipticCurveTypes.P384 => CryptoAlgorithm.P384,
        EllipticCurveTypes.P521 => CryptoAlgorithm.P521,
        EllipticCurveTypes.Secp256k1 => CryptoAlgorithm.Secp256k1,
        EllipticCurveTypes.BrainpoolP224r1 => CryptoAlgorithm.BrainpoolP224r1,
        EllipticCurveTypes.BrainpoolP256r1 => CryptoAlgorithm.BrainpoolP256r1,
        EllipticCurveTypes.BrainpoolP320r1 => CryptoAlgorithm.BrainpoolP320r1,
        EllipticCurveTypes.BrainpoolP384r1 => CryptoAlgorithm.BrainpoolP384r1,
        EllipticCurveTypes.BrainpoolP512r1 => CryptoAlgorithm.BrainpoolP512r1,
        _ => throw new CryptographicException($"The elliptic curve '{curve}' has no verification algorithm.")
    };


    /// <summary>A parsed CMS SignedData: the content type, encapsulated content, certificates, and signer.</summary>
    private readonly record struct ParsedSignedData(
        string ContentType,
        ReadOnlyMemory<byte> Content,
        IReadOnlyList<ManagedCertificate> Certificates,
        SignerInfo Signer);


    /// <summary>A parsed SignerInfo.</summary>
    private readonly record struct SignerInfo(
        SignerIdentifier SignerIdentifier,
        string DigestAlgorithmOid,
        string SignatureAlgorithmOid,
        ReadOnlyMemory<byte> SignedAttributes,
        List<(string Oid, ReadOnlyMemory<byte> Value)> SignedAttributeList,
        ReadOnlyMemory<byte> Signature,
        List<(string Oid, ReadOnlyMemory<byte> Value)> UnsignedAttributeList);


    /// <summary>A parsed signer identifier: an issuer-and-serial-number, or a subject-key-identifier (when non-empty).</summary>
    private readonly record struct SignerIdentifier(
        ReadOnlyMemory<byte> IssuerDer,
        ReadOnlyMemory<byte> SerialNumber,
        ReadOnlyMemory<byte> SubjectKeyIdentifier);
}
