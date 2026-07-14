using System.Buffers;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Shared test-vector builders for the <c>tpm</c> attestation-verification tests: mints a
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements">section 8.3.1</see>
/// conformant AIK certificate (and every certificate-shaped negative fixture), and marshals TPM
/// wire structures (TPMT_PUBLIC, TPMS_ATTEST, TPMT_SIGNATURE) with <c>Verifiable.Tpm</c>'s own
/// spec-exact wire types (<see cref="TpmtPublic"/>, <see cref="TpmsAttest"/>) — never a hand-rolled
/// duplicate parser/writer — so the minted vectors are genuinely TPM-shaped, mirroring
/// <see cref="Fido2AttestationTestVectors"/>'s "independent oracle" idiom for the certificate/ECDSA
/// half of the fixture.
/// </summary>
internal static class TpmAttestationTestVectors
{
    /// <summary>The dotted OID of <c>tcg-at-tpmManufacturer</c> (TCG EK Credential Profile section 3.1.2).</summary>
    internal const string TpmManufacturerOid = "2.23.133.2.1";

    /// <summary>The dotted OID of <c>tcg-at-tpmModel</c> (TCG EK Credential Profile section 3.1.2).</summary>
    internal const string TpmModelOid = "2.23.133.2.2";

    /// <summary>The dotted OID of <c>tcg-at-tpmVersion</c> (TCG EK Credential Profile section 3.1.2).</summary>
    internal const string TpmVersionOid = "2.23.133.2.3";

    /// <summary>The dotted OID of <c>tcg-kp-AIKCertificate</c>, required in the AIK certificate's Extended Key Usage.</summary>
    internal const string AikCertificateKeyPurposeOid = "2.23.133.8.3";

    /// <summary>The dotted OID of the X.509 Subject Alternative Name extension.</summary>
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    /// <summary>The context-specific GeneralName choice tag number for <c>directoryName</c> (RFC 5280 §4.2.1.6).</summary>
    private const int DirectoryNameGeneralNameTag = 4;

    /// <summary>The conformant default TPM manufacturer identifier device attribute.</summary>
    internal const string DefaultTpmManufacturer = "id:FFFFF1D0";

    /// <summary>The conformant default TPM model device attribute.</summary>
    internal const string DefaultTpmModel = "Verifiable Test TPM";

    /// <summary>The conformant default TPM firmware version device attribute.</summary>
    internal const string DefaultTpmVersion = "id:00010023";

    /// <summary>Gets the default <c>notBefore</c> instant minted AIK certificates carry.</summary>
    private static DateTimeOffset DefaultNotBefore { get; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Gets the default <c>notAfter</c> instant minted AIK certificates carry.</summary>
    private static DateTimeOffset DefaultNotAfter { get; } = new(2029, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// Mints an AIK certificate whose section 8.3.1 profile-relevant fields are individually
    /// controllable, so a single helper produces both the conformant happy-path certificate and
    /// every certificate-shaped negative fixture (non-empty Subject, missing SAN device attribute,
    /// missing EKU, CA-flagged leaf).
    /// </summary>
    /// <param name="issuerCertificate">The issuing CA certificate (private key attached).</param>
    /// <param name="aikKey">The AIK's own P-256 key pair; the private half is the attestation signing key under test.</param>
    /// <param name="emptySubject">Whether the Subject field is empty (the section 8.3.1-conformant value).</param>
    /// <param name="isCertificateAuthority">The Basic Constraints <c>cA</c> value to assert on the leaf.</param>
    /// <param name="includeAikExtendedKeyUsage">Whether to include the <see cref="AikCertificateKeyPurposeOid"/> EKU entry.</param>
    /// <param name="tpmManufacturer">The SAN <c>tcg-at-tpmManufacturer</c> value, or <see langword="null"/> to omit it.</param>
    /// <param name="tpmModel">The SAN <c>tcg-at-tpmModel</c> value, or <see langword="null"/> to omit it.</param>
    /// <param name="tpmVersion">The SAN <c>tcg-at-tpmVersion</c> value, or <see langword="null"/> to omit it.</param>
    /// <param name="includeSubjectAlternativeName">Whether to include the SAN extension at all — the "SAN missing entirely" fixture.</param>
    /// <param name="notBefore">The certificate's <c>notBefore</c> instant. Defaults to a fixed conformant value.</param>
    /// <param name="notAfter">The certificate's <c>notAfter</c> instant. Defaults to a fixed conformant value.</param>
    /// <param name="attachPrivateKey">
    /// Whether to attach <paramref name="aikKey"/>'s private half to the returned certificate via
    /// <see cref="X509Certificate2.CopyWithPrivateKey(ECDsa)"/>. Defaults to <see langword="true"/>
    /// for the ordinary hand-built-KAT fixtures, whose own <paramref name="aikKey"/> signs the
    /// attestation directly; pass <see langword="false"/> when <paramref name="aikKey"/> is a
    /// public-only reconstruction of a key whose private half never leaves a TPM (the live-minted
    /// capstone), for which <c>CopyWithPrivateKey</c> would throw.
    /// </param>
    /// <returns>The AIK certificate.</returns>
    internal static X509Certificate2 CreateAikCertificate(
        X509Certificate2 issuerCertificate,
        ECDsa aikKey,
        bool emptySubject = true,
        bool isCertificateAuthority = false,
        bool includeAikExtendedKeyUsage = true,
        string? tpmManufacturer = DefaultTpmManufacturer,
        string? tpmModel = DefaultTpmModel,
        string? tpmVersion = DefaultTpmVersion,
        bool includeSubjectAlternativeName = true,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool attachPrivateKey = true)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(aikKey);

        string subjectName = emptySubject ? string.Empty : "CN=Non-Conformant AIK Subject";
        var request = new CertificateRequest(subjectName, aikKey, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: isCertificateAuthority, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));

        if(includeAikExtendedKeyUsage)
        {
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new Oid(AikCertificateKeyPurposeOid, "tcg-kp-AIKCertificate")], critical: false));
        }

        if(includeSubjectAlternativeName)
        {
            request.CertificateExtensions.Add(new X509Extension(
                SubjectAlternativeNameOid,
                EncodeTcgSubjectAlternativeName(tpmManufacturer, tpmModel, tpmVersion),
                critical: emptySubject));
        }

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        X509Certificate2 certificate = request.Create(
            issuerCertificate,
            notBefore: notBefore ?? DefaultNotBefore,
            notAfter: notAfter ?? DefaultNotAfter,
            serialNumber);

        if(!attachPrivateKey)
        {
            return certificate;
        }

        using X509Certificate2 certificateOnly = certificate;

        return certificateOnly.CopyWithPrivateKey(aikKey);
    }


    /// <summary>
    /// DER-encodes a Subject Alternative Name extension value carrying the TCG EK Credential
    /// Profile's TPM device attributes (section 3.1.2) inside a single <c>directoryName</c>
    /// <c>GeneralName</c>: <c>SEQUENCE { [4] EXPLICIT Name }</c> where <c>Name</c> is an
    /// RDNSequence with one relative distinguished name per supplied, non-<see langword="null"/>
    /// attribute.
    /// </summary>
    /// <param name="tpmManufacturer">The <c>tcg-at-tpmManufacturer</c> value, or <see langword="null"/> to omit that RDN.</param>
    /// <param name="tpmModel">The <c>tcg-at-tpmModel</c> value, or <see langword="null"/> to omit that RDN.</param>
    /// <param name="tpmVersion">The <c>tcg-at-tpmVersion</c> value, or <see langword="null"/> to omit that RDN.</param>
    /// <returns>The DER bytes of the SAN extension's <c>GeneralNames</c> content.</returns>
    internal static byte[] EncodeTcgSubjectAlternativeName(string? tpmManufacturer, string? tpmModel, string? tpmVersion)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, DirectoryNameGeneralNameTag, true)))
            {
                using(writer.PushSequence())
                {
                    if(tpmManufacturer is not null)
                    {
                        WriteDeviceAttribute(writer, TpmManufacturerOid, tpmManufacturer);
                    }

                    if(tpmModel is not null)
                    {
                        WriteDeviceAttribute(writer, TpmModelOid, tpmModel);
                    }

                    if(tpmVersion is not null)
                    {
                        WriteDeviceAttribute(writer, TpmVersionOid, tpmVersion);
                    }
                }
            }
        }

        return writer.Encode();

        static void WriteDeviceAttribute(AsnWriter writer, string oid, string value)
        {
            using(writer.PushSetOf())
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(oid);
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
                }
            }
        }
    }


    /// <summary>
    /// Marshals a TPMT_PUBLIC (the WebAuthn <c>pubArea</c> field) for a P-256 ECC signing key,
    /// carrying <paramref name="key"/>'s actual public point, via <see cref="TpmtPublic.CreateEccSigningKey"/>
    /// and its own <see cref="TpmtPublic.WriteTo"/> — the production spec-exact writer, never a
    /// hand-rolled duplicate.
    /// </summary>
    /// <param name="key">The P-256 key pair whose public point becomes the public area's <c>unique</c> field.</param>
    /// <param name="nameAlg">The <c>nameAlg</c> the Name computation and the ECDSA scheme's hash both use.</param>
    /// <returns>The marshaled TPMT_PUBLIC bytes.</returns>
    internal static byte[] BuildEccPubAreaBytes(ECDsa key, TpmAlgIdConstants nameAlg = TpmAlgIdConstants.TPM_ALG_SHA256)
    {
        ArgumentNullException.ThrowIfNull(key);

        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        using TpmsEccPoint point = TpmsEccPoint.Create(parameters.Q.X!, parameters.Q.Y!, BaseMemoryPool.Shared);

        const TpmaObject Attributes =
            TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN
            | TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT;

        using TpmtPublic pubArea = TpmtPublic.CreateEccSigningKey(
            nameAlg, Attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(nameAlg), point);

        byte[] buffer = new byte[pubArea.GetSerializedSize()];
        var writer = new TpmWriter(buffer);
        pubArea.WriteTo(ref writer);

        return buffer;
    }


    /// <summary>
    /// Computes the TPM object Name for a marshaled TPMT_PUBLIC: <c>nameAlg (2 bytes, big-endian)
    /// || H_nameAlg(pubArea)</c> (TPM 2.0 Library Part 1, clause 16).
    /// </summary>
    /// <param name="pubAreaBytes">The marshaled TPMT_PUBLIC bytes.</param>
    /// <param name="nameAlg">The name algorithm — only SHA-256 is supported by this helper.</param>
    /// <returns>The computed Name bytes.</returns>
    internal static byte[] ComputeTpmName(byte[] pubAreaBytes, TpmAlgIdConstants nameAlg = TpmAlgIdConstants.TPM_ALG_SHA256)
    {
        ArgumentNullException.ThrowIfNull(pubAreaBytes);
        if(nameAlg != TpmAlgIdConstants.TPM_ALG_SHA256)
        {
            throw new NotSupportedException("Only TPM_ALG_SHA256 is supported by this test helper.");
        }

        byte[] digest = SHA256.HashData(pubAreaBytes);
        byte[] name = new byte[2 + digest.Length];
        name[0] = (byte)((ushort)nameAlg >> 8);
        name[1] = (byte)(ushort)nameAlg;
        digest.CopyTo(name, 2);

        return name;
    }


    /// <summary>
    /// Marshals a TPMS_ATTEST (the WebAuthn <c>certInfo</c> field) of type <c>TPM_ST_ATTEST_CERTIFY</c>,
    /// via <see cref="TpmsAttest.Create"/>/<see cref="TpmuAttest.ForCertify"/>/<see cref="TpmsCertifyInfo.Create"/>
    /// and their own <c>WriteTo</c> methods — the production spec-exact writer.
    /// </summary>
    /// <param name="certifiedObjectName">The certified object's (the credential key's) Name.</param>
    /// <param name="signerName">The signing key's (the AIK's) Name.</param>
    /// <param name="extraData">The <c>extraData</c> bytes — the digest of <c>attToBeSigned</c> under the statement's <c>alg</c>.</param>
    /// <param name="magic">The magic value. Defaults to <see cref="TpmConstants32.TPM_GENERATED_VALUE"/>; a caller passing another value builds the "magic mismatch" negative fixture.</param>
    /// <returns>The marshaled TPMS_ATTEST bytes.</returns>
    internal static byte[] BuildCertifyCertInfoBytes(
        byte[] certifiedObjectName, byte[] signerName, byte[] extraData, uint magic = TpmConstants32.TPM_GENERATED_VALUE)
    {
        ArgumentNullException.ThrowIfNull(certifiedObjectName);
        ArgumentNullException.ThrowIfNull(signerName);
        ArgumentNullException.ThrowIfNull(extraData);

        //Ownership of each object transfers into the next (Tpm2bName pair -> TpmsCertifyInfo -> TpmuAttest ->
        //TpmsAttest), whose Dispose() cascades down; the redundant using declarations here satisfy CA2000 and
        //are safe because every disposal in this chain is idempotent.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using Tpm2bName qualifiedSigner = Tpm2bName.Create(signerName, pool);
        using Tpm2bData extraDataBuffer = Tpm2bData.Create(extraData, pool);
        using Tpm2bName certifiedName = Tpm2bName.Create(certifiedObjectName, pool);
        using Tpm2bName certifiedQualifiedName = Tpm2bName.Create(certifiedObjectName, pool);
        using TpmsCertifyInfo certifyInfo = TpmsCertifyInfo.Create(certifiedName, certifiedQualifiedName);
        using TpmuAttest attested = TpmuAttest.ForCertify(certifyInfo);

        using TpmsAttest attest = TpmsAttest.Create(
            magic, TpmStConstants.TPM_ST_ATTEST_CERTIFY, qualifiedSigner, extraDataBuffer,
            new TpmsClockInfo(0, 0, 0, TpmiYesNo.No), firmwareVersion: 0, attested);

        return MarshalAttest(attest);
    }


    /// <summary>
    /// Marshals a TPMS_ATTEST of type <c>TPM_ST_ATTEST_QUOTE</c> — a well-formed but wrong-type
    /// attestation — the "certInfo.type is not TPM_ST_ATTEST_CERTIFY" negative fixture.
    /// </summary>
    /// <param name="signerName">The signing key's Name.</param>
    /// <param name="extraData">The <c>extraData</c> bytes.</param>
    /// <returns>The marshaled TPMS_ATTEST bytes.</returns>
    internal static byte[] BuildQuoteCertInfoBytes(byte[] signerName, byte[] extraData)
    {
        ArgumentNullException.ThrowIfNull(signerName);
        ArgumentNullException.ThrowIfNull(extraData);

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using Tpm2bName qualifiedSigner = Tpm2bName.Create(signerName, pool);
        using Tpm2bData extraDataBuffer = Tpm2bData.Create(extraData, pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, [0], pool);
        using Tpm2bDigest pcrDigest = Tpm2bDigest.Create(new byte[32], pool);
        using TpmsQuoteInfo quoteInfo = TpmsQuoteInfo.Create(pcrSelection, pcrDigest);
        using TpmuAttest attested = TpmuAttest.ForQuote(quoteInfo);

        using TpmsAttest attest = TpmsAttest.Create(
            TpmConstants32.TPM_GENERATED_VALUE, TpmStConstants.TPM_ST_ATTEST_QUOTE, qualifiedSigner, extraDataBuffer,
            new TpmsClockInfo(0, 0, 0, TpmiYesNo.No), firmwareVersion: 0, attested);

        return MarshalAttest(attest);
    }


    /// <summary>
    /// Marshals a TPMT_SIGNATURE (the WebAuthn <c>sig</c> field) for an ECDSA signature: a
    /// <c>TPMI_ALG_SIG_SCHEME</c> selector (<c>TPM_ALG_ECDSA</c>), the scheme hash algorithm, then
    /// the <c>r</c>/<c>s</c> components each framed as a TPM2B_ECC_PARAMETER (TPM 2.0 Library Part
    /// 2, section 11.3.4).
    /// </summary>
    /// <param name="hashAlg">The scheme hash algorithm carried alongside the ECDSA selector.</param>
    /// <param name="r">The signature's <c>r</c> component.</param>
    /// <param name="s">The signature's <c>s</c> component.</param>
    /// <returns>The marshaled TPMT_SIGNATURE bytes.</returns>
    internal static byte[] BuildEcdsaSignatureBytes(TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        byte[] buffer = new byte[sizeof(ushort) + sizeof(ushort) + (sizeof(ushort) + r.Length) + (sizeof(ushort) + s.Length)];
        var writer = new TpmWriter(buffer);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_ECDSA);
        writer.WriteUInt16((ushort)hashAlg);
        writer.WriteTpm2b(r);
        writer.WriteTpm2b(s);

        return buffer;
    }


    /// <summary>
    /// Signs <paramref name="message"/> with a raw <see cref="ECDsa"/> P-256 key and splits the
    /// fixed-width IEEE P1363 signature into its 32-byte <c>r</c>/<c>s</c> components — the TPM's
    /// own signature component shape (TPM2B_ECC_PARAMETER, unlike WebAuthn's ASN.1 DER wire
    /// convention for other formats).
    /// </summary>
    /// <param name="key">The P-256 private key to sign with.</param>
    /// <param name="message">The bytes to sign — <c>certInfo</c> for a tpm attestation signature.</param>
    /// <returns>The <c>r</c> and <c>s</c> components, each exactly 32 bytes.</returns>
    internal static (byte[] R, byte[] S) SignWithEcdsaP256Components(ECDsa key, byte[] message)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(message);

        byte[] p1363 = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        int componentSize = p1363.Length / 2;

        return (p1363[..componentSize], p1363[componentSize..]);
    }


    /// <summary>Marshals a <see cref="TpmsAttest"/> using its own <c>GetSerializedSize</c>/<c>WriteTo</c>.</summary>
    private static byte[] MarshalAttest(TpmsAttest attest)
    {
        byte[] buffer = new byte[attest.GetSerializedSize()];
        var writer = new TpmWriter(buffer);
        attest.WriteTo(ref writer);

        return buffer;
    }


    /// <summary>
    /// A <see cref="ParseTpmAttestationStatementDelegate"/> stub that ignores the raw CBOR input and
    /// returns a pre-built <see cref="TpmAttestationStatement"/> — the CBOR codec is exercised
    /// separately (<c>TpmAttestationStatementCborReaderTests</c>); these tests exercise the
    /// verification procedure against a directly constructed statement, mirroring
    /// <c>Fido2AttestationTestVectors.CreateStatementParser</c>.
    /// </summary>
    /// <param name="statement">The statement to return regardless of the supplied bytes.</param>
    /// <returns>A delegate that always returns <paramref name="statement"/>.</returns>
    internal static ParseTpmAttestationStatementDelegate CreateStatementParser(TpmAttestationStatement statement) =>
        (_, _) => statement;


    /// <summary>
    /// A <see cref="ParseTpmAttestationStatementDelegate"/> stub that always throws
    /// <see cref="Fido2FormatException"/> — simulates a malformed <c>attStmt</c> CBOR payload.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <returns>A delegate that always throws.</returns>
    internal static ParseTpmAttestationStatementDelegate CreateThrowingParser(string message) =>
        (_, _) => throw new Fido2FormatException(message);
}
