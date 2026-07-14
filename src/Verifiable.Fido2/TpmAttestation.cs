using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Fido2;

/// <summary>
/// Builds the <c>tpm</c> attestation statement format's verification procedure.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3: TPM Attestation Statement Format.</see>
/// and <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements">section 8.3.1: TPM
/// Attestation Statement Certificate Requirements</see>.
/// </para>
/// <para>
/// <c>certInfo</c> (a marshaled TPMS_ATTEST) and <c>pubArea</c> (a marshaled TPMT_PUBLIC) are parsed
/// with <c>Verifiable.Tpm</c>'s spec-exact wire types — <see cref="TpmsAttest"/> and
/// <see cref="TpmtPublic"/> — rather than a hand-rolled duplicate parser: this format is the
/// FIDO2↔TPM rendezvous the wave's dependency ruling exists for.
/// </para>
/// <para>
/// Unlike <see cref="PackedAttestation"/>'s <c>x5c</c> branch, which returns
/// <see cref="AttestationType.Unknown"/> because Basic and Attestation CA attestation share the
/// same certificate-path shape, section 8.3 declares exactly one supported attestation type
/// ("Attestation types supported: AttCA") and its verification procedure's final step returns it
/// unconditionally on success — so this verifier returns <see cref="AttestationType.AttestationCa"/>
/// directly, never <see cref="AttestationType.Unknown"/>.
/// </para>
/// <para>
/// The attestation signature is a TPMT_SIGNATURE (TPM 2.0 Library Part 2, section 11.3.4) — TPM's
/// own wire format, component-wise like IEEE P1363 rather than ASN.1 DER — so, unlike
/// <see cref="PackedAttestation"/> and <see cref="AndroidKeyAttestation"/>, no DER-to-P1363
/// conversion applies here; <see cref="TpmCryptographicProjections.ToSignature"/> projects the
/// parsed <see cref="TpmuSignature"/> directly into the neutral, algorithm-agnostic
/// <see cref="Signature"/> carrier the registered verification seam expects.
/// </para>
/// </remarks>
public static class TpmAttestation
{
    /// <summary>
    /// The key identifier passed to <see cref="CryptographicKeyFactory"/> for the AIK
    /// certificate's leaf key. Not a DID or credential id — this seam has no such identity to
    /// carry, only the key material and its algorithm tag.
    /// </summary>
    private const string LeafCertificateKeyIdentifier = "tpm-attestation:leaf-certificate";

    /// <summary>The dotted OID of the <c>id-fido-gen-ce-aaguid</c> X.509 extension.</summary>
    private const string AaguidExtensionOid = "1.3.6.1.4.1.45724.1.1.4";

    /// <summary>The dotted OID of the X.509 Subject Alternative Name extension (RFC 5280 §4.2.1.6).</summary>
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    /// <summary>The dotted OID of the X.509 Extended Key Usage extension (RFC 5280 §4.2.1.12).</summary>
    private const string ExtendedKeyUsageOid = "2.5.29.37";

    /// <summary>
    /// The dotted OID of <c>tcg-kp-AIKCertificate</c> ("joint-iso-itu-t(2)
    /// internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)"), which section
    /// 8.3.1 requires the leaf's Extended Key Usage extension to contain.
    /// </summary>
    private const string AikCertificateKeyPurposeOid = "2.23.133.8.3";

    /// <summary>The dotted OID of <c>tcg-at-tpmManufacturer</c> (TCG EK Credential Profile section 3.1.2).</summary>
    private const string TpmManufacturerOid = "2.23.133.2.1";

    /// <summary>The dotted OID of <c>tcg-at-tpmModel</c> (TCG EK Credential Profile section 3.1.2).</summary>
    private const string TpmModelOid = "2.23.133.2.2";

    /// <summary>The dotted OID of <c>tcg-at-tpmVersion</c> (TCG EK Credential Profile section 3.1.2).</summary>
    private const string TpmVersionOid = "2.23.133.2.3";

    /// <summary>The context-specific GeneralName choice tag number for <c>directoryName</c> (RFC 5280 §4.2.1.6).</summary>
    private const int DirectoryNameGeneralNameTag = 4;

    /// <summary>The certificate version (RFC 5280 §4.1.2.1) section 8.3.1 requires: version 3.</summary>
    private const int RequiredCertificateVersion = 3;

    /// <summary>The exact byte length of the AAGUID once unwrapped from its OCTET STRING encoding.</summary>
    private const int AaguidByteLength = 16;

    /// <summary>The maximum TPM object Name length: a 2-byte algorithm identifier plus a SHA-512 digest.</summary>
    private const int MaxNameLength = 2 + 64;


    /// <summary>
    /// Builds the <c>tpm</c> attestation statement format's <see cref="AttestationVerifyDelegate"/>.
    /// </summary>
    /// <param name="parseStatement">Decodes the raw <c>attStmt</c> CBOR bytes.</param>
    /// <param name="validateChain">Validates the statement's <c>x5c</c> certificate path against the request's trust anchors.</param>
    /// <param name="readProfile">Reads the AIK certificate's profile-relevant fields for the section 8.3.1 certificate requirements.</param>
    /// <param name="readExtensionValue">Reads the AIK certificate's Subject Alternative Name, Extended Key Usage, and <c>id-fido-gen-ce-aaguid</c> extensions.</param>
    /// <param name="checkRevocation">
    /// An optional revocation-status seam, forwarded to <paramref name="validateChain"/> — see
    /// <see cref="PackedAttestation.Build"/>'s parameter of the same name for the exact semantics;
    /// unchanged here.
    /// </param>
    /// <param name="completeChain">
    /// An optional chain-completion seam — see <see cref="PackedAttestation.Build"/>'s parameter of
    /// the same name for the exact semantics; unchanged here.
    /// </param>
    /// <returns>The verification delegate.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any required parameter is <see langword="null"/>.</exception>
    public static AttestationVerifyDelegate Build(
        ParseTpmAttestationStatementDelegate parseStatement,
        ValidateCertificateChainAsyncDelegate validateChain,
        ReadCertificateProfileDelegate readProfile,
        ReadCertificateExtensionValueDelegate readExtensionValue,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        CompleteCertificateChainAsyncDelegate? completeChain = null)
    {
        ArgumentNullException.ThrowIfNull(parseStatement);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(readProfile);
        ArgumentNullException.ThrowIfNull(readExtensionValue);

        return (request, cancellationToken) =>
            VerifyAsync(request, parseStatement, validateChain, readProfile, readExtensionValue, checkRevocation, completeChain, cancellationToken);
    }


    /// <summary>
    /// Implements the section 8.3 verification procedure, in the order the specification's own
    /// prose lists its steps.
    /// </summary>
    private static async ValueTask<AttestationResult> VerifyAsync(
        AttestationVerificationRequest request,
        ParseTpmAttestationStatementDelegate parseStatement,
        ValidateCertificateChainAsyncDelegate validateChain,
        ReadCertificateProfileDelegate readProfile,
        ReadCertificateExtensionValueDelegate readExtensionValue,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CompleteCertificateChainAsyncDelegate? completeChain,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        //Step 1 (section 8.3): "Verify that attStmt is valid CBOR conforming to the syntax defined
        //above and perform CBOR decoding on it to extract the contained fields." Including the
        //literal "ver" == "2.0" acceptance rule, enforced by the CBOR reader itself.
        TpmAttestationStatement statement;
        try
        {
            statement = parseStatement(request.AttestationStatement, request.Pool);
        }
        catch(Fido2FormatException)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.MalformedStatement);
        }

        if(request.AuthenticatorData.AttestedCredentialData is not { } attestedCredentialData)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.MissingAttestedCredentialData);
        }

        TpmtPublic pubArea;
        try
        {
            var pubAreaReader = new TpmReader(statement.PubArea.Span);
            pubArea = TpmtPublic.Parse(ref pubAreaReader, request.Pool);
        }
        catch(Exception exception) when(IsMalformedTpmWireException(exception))
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.MalformedStatement);
        }

        try
        {
            //Step 2 (section 8.3): "Verify that the public key specified by the parameters and
            //unique fields of pubArea is identical to the credentialPublicKey in the
            //attestedCredentialData in authenticatorData."
            if(!PubAreaKeyMatchesCredentialKey(pubArea, attestedCredentialData.CredentialPublicKey, request.Pool))
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.PublicAreaKeyMismatch);
            }

            //Step 4a (section 8.3, "Verify integrity of certInfo"): "Verify that x5c is present."
            //The CDDL requires at least aikCert when x5c is present, so a decoded, empty array
            //does not conform to the syntax — the tpm format has no self-attestation branch for an
            //absent x5c to fall back to.
            IReadOnlyList<PkiCertificateMemory> x5c = statement.X5c;
            if(x5c.Count == 0)
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.MalformedStatement);
            }

            if(request.TrustAnchors.Count == 0)
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.NoTrustAnchors);
            }

            PublicKeyMemory leafKeyMemory;
            IReadOnlyList<PkiCertificateMemory> chainToValidate = x5c;
            int acquiredCertificateCount = 0;
            try
            {
                if(completeChain is not null)
                {
                    //Chain completion is append-only (see CompleteCertificateChainAsyncDelegate's contract): any
                    //entries beyond x5c's own Count are newly acquired for this call and are this method's to dispose;
                    //x5c's own entries stay caller-owned throughout, exactly as before this parameter existed.
                    chainToValidate = await completeChain(x5c, request.TrustAnchors, request.Pool, cancellationToken).ConfigureAwait(false);
                    acquiredCertificateCount = chainToValidate.Count - x5c.Count;
                }

                leafKeyMemory = await validateChain(chainToValidate, request.TrustAnchors, request.ValidationTime, request.Pool, checkRevocation, cancellationToken).ConfigureAwait(false);
            }
            catch(SecurityException)
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.ChainValidationFailed);
            }
            finally
            {
                for(int acquiredIndex = x5c.Count; acquiredIndex < x5c.Count + acquiredCertificateCount; acquiredIndex++)
                {
                    chainToValidate[acquiredIndex].Dispose();
                }
            }

            //CreatePublicKey takes ownership of leafKeyMemory; disposing leafPublicKey below releases it.
            using PublicKey leafPublicKey = CryptographicKeyFactory.CreatePublicKey(leafKeyMemory, LeafCertificateKeyIdentifier, leafKeyMemory.Tag);
            CryptoAlgorithm leafAlgorithm = leafKeyMemory.Tag.Get<CryptoAlgorithm>();

            PkiCertificateMemory aikCertificate = x5c[0];

            //Step 4b: "Verify that aikCert meets the requirements in section 8.3.1."
            X509CertificateProfile profile = readProfile(aikCertificate);
            if(!ConformsToAikCertificateVersionSubjectAndCaProfile(profile))
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.CertificateProfileViolation);
            }

            if(readExtensionValue(aikCertificate, SubjectAlternativeNameOid) is not { } subjectAlternativeName
                || !HasConformantTcgSubjectAlternativeName(subjectAlternativeName.Value))
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.CertificateProfileViolation);
            }

            if(readExtensionValue(aikCertificate, ExtendedKeyUsageOid) is not { } extendedKeyUsage
                || !ContainsAikCertificateKeyPurpose(extendedKeyUsage.Value))
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.CertificateProfileViolation);
            }

            //Step 4c: "If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4
            //(id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in
            //authenticatorData."
            if(readExtensionValue(aikCertificate, AaguidExtensionOid) is { } aaguidExtension)
            {
                //Defense in depth, mirroring PackedAttestation's own AAGUID extension check: both
                //registered chain validators already reject an unrecognised critical extension
                //during chain building (RFC 5280 section 4.2), so under those backends the chain
                //step above fails first; this check stays so the requirement holds regardless of
                //how permissive the injected chain-validation delegate is.
                if(aaguidExtension.IsCritical)
                {
                    return new RejectedAttestationResult(Fido2AttestationErrors.CertificateProfileViolation);
                }

                if(!TryUnwrapAaguid(aaguidExtension.Value, out Guid extensionAaguid) || extensionAaguid != attestedCredentialData.Aaguid)
                {
                    return new RejectedAttestationResult(Fido2AttestationErrors.AaguidMismatch);
                }
            }

            //Cross-check the statement's declared alg against the AIK leaf key's own algorithm
            //family — not a separately numbered section 8.3 step, but the same defense-in-depth
            //precedent PackedAttestation and AndroidKeyAttestation both apply before trusting alg
            //to select a verification scheme.
            if(CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(statement.Alg) is not { } mappedAlgorithm
                || !IsConsistentAlgorithmFamily(mappedAlgorithm, leafAlgorithm))
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.AlgorithmMismatch);
            }

            if(!TryGetCoseAlgorithmDigest(statement.Alg, out int transcriptDigestLength, out Tag transcriptDigestTag))
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.UnsupportedAlgorithm);
            }

            //Step 3 (section 8.3): "Concatenate authenticatorData and clientDataHash to form attToBeSigned."
            using IMemoryOwner<byte> toBeSignedOwner = RentToBeSigned(request.AuthenticatorDataBytes, request.ClientDataHash, request.Pool, out int toBeSignedLength);
            ReadOnlyMemory<byte> toBeSigned = toBeSignedOwner.Memory[..toBeSignedLength];

            TpmsAttest certInfo;
            try
            {
                var certInfoReader = new TpmReader(statement.CertInfo.Span);
                certInfo = TpmsAttest.Parse(ref certInfoReader, request.Pool);
            }
            catch(Exception exception) when(IsMalformedTpmWireException(exception))
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.MalformedStatement);
            }

            try
            {
                //Step 5a ("Validate that certInfo is valid"): "Verify that magic is set to TPM_GENERATED_VALUE."
                if(!certInfo.IsTpmGenerated)
                {
                    return new RejectedAttestationResult(Fido2AttestationErrors.CertInfoNotTpmGenerated);
                }

                //Step 5b: "Verify that type is set to TPM_ST_ATTEST_CERTIFY."
                if(certInfo.Type != TpmStConstants.TPM_ST_ATTEST_CERTIFY || certInfo.Attested.Certify is not { } certifyInfo)
                {
                    return new RejectedAttestationResult(Fido2AttestationErrors.CertInfoNotCertifyType);
                }

                //Step 4d: "Verify the sig is a valid signature over certInfo using the attestation
                //public key in aikCert with the algorithm specified in alg."
                bool signatureValid;
                try
                {
                    var signatureReader = new TpmReader(statement.Signature.Span);
                    var signatureAlgorithm = (TpmAlgIdConstants)signatureReader.ReadUInt16();
                    using TpmuSignature signatureUnion = TpmuSignature.Parse(signatureAlgorithm, ref signatureReader, request.Pool);
                    using Signature signature = signatureUnion.ToSignature(GetEcdsaComponentSize(leafAlgorithm), CryptoTags.AlgorithmAgnosticSignature, request.Pool);
                    signatureValid = await leafPublicKey.VerifyAsync(statement.CertInfo, signature).ConfigureAwait(false);
                }
                catch(Exception exception) when(exception is ArgumentOutOfRangeException or NotSupportedException or CryptographicException or InvalidOperationException)
                {
                    //A malformed TPMT_SIGNATURE, or one whose scheme does not match the AIK's own
                    //key family: fail-closed to an invalid signature, mirroring how PackedAttestation
                    //and AndroidKeyAttestation fail-closed on a malformed DER wire signature.
                    signatureValid = false;
                }

                if(!signatureValid)
                {
                    return new RejectedAttestationResult(Fido2AttestationErrors.InvalidSignature);
                }

                //Step 5c: "Verify that extraData is set to the hash of attToBeSigned using the hash
                //algorithm employed in 'alg'."
                using DigestValue transcriptDigest = CryptographicKeyEvents.ComputeDigest(toBeSigned.Span, transcriptDigestLength, transcriptDigestTag, request.Pool);
                if(!transcriptDigest.AsReadOnlySpan().SequenceEqual(certInfo.ExtraData.Span))
                {
                    return new RejectedAttestationResult(Fido2AttestationErrors.AttestationDigestMismatch);
                }

                //Step 5d: "Verify that attested contains a TPMS_CERTIFY_INFO structure ... whose
                //name field contains a valid Name for pubArea, as computed using the procedure
                //specified in [TPMv2-Part1] section 16 using the nameAlg in the pubArea."
                if(!TryGetTpmAlgorithmDigest(pubArea.NameAlg, out int nameDigestLength, out Tag nameDigestTag))
                {
                    return new RejectedAttestationResult(Fido2AttestationErrors.UnsupportedAlgorithm);
                }

                using DigestValue pubAreaDigest = CryptographicKeyEvents.ComputeDigest(statement.PubArea.Span, nameDigestLength, nameDigestTag, request.Pool);

                Span<byte> expectedName = stackalloc byte[MaxNameLength];
                BinaryPrimitives.WriteUInt16BigEndian(expectedName, (ushort)pubArea.NameAlg);
                pubAreaDigest.AsReadOnlySpan().CopyTo(expectedName[sizeof(ushort)..]);
                int expectedNameLength = sizeof(ushort) + nameDigestLength;

                if(!expectedName[..expectedNameLength].SequenceEqual(certifyInfo.Name.Span))
                {
                    return new RejectedAttestationResult(Fido2AttestationErrors.CertifiedNameMismatch);
                }

                //Step 5e: "If successful, return implementation-specific values representing
                //attestation type AttCA and attestation trust path x5c."
                return new CertifiedAttestationResult(AttestationType.AttestationCa, x5c);
            }
            finally
            {
                certInfo.Dispose();
            }
        }
        finally
        {
            pubArea.Dispose();
        }
    }


    /// <summary>
    /// Determines whether the public key <paramref name="pubArea"/>'s <c>parameters</c> and
    /// <c>unique</c> fields specify is identical to <paramref name="credentialPublicKey"/> —
    /// section 8.3's first verification step, byte-comparing key material after normalising both
    /// sides to the same canonical form (compressed SEC1 for EC2, DER PKCS#1 <c>RSAPublicKey</c>
    /// for RSA) and comparing algorithm family, mirroring
    /// <see cref="AndroidKeyAttestation"/>'s <c>credCert</c>-key-versus-credentialPublicKey check.
    /// </summary>
    private static bool PubAreaKeyMatchesCredentialKey(TpmtPublic pubArea, CoseKey credentialPublicKey, MemoryPool<byte> pool)
    {
        PublicKeyMemory? pubAreaKeyMemory = null;
        try
        {
            if(!TryBuildPublicAreaKeyMemory(pubArea, pool, out pubAreaKeyMemory, out CryptoAlgorithm pubAreaAlgorithm))
            {
                return false;
            }

            using PublicKeyMemory credentialKeyMemory = credentialPublicKey.ToPublicKeyMemory(pool);
            CryptoAlgorithm credentialAlgorithm = credentialKeyMemory.Tag.Get<CryptoAlgorithm>();

            return IsConsistentAlgorithmFamily(pubAreaAlgorithm, credentialAlgorithm)
                && pubAreaKeyMemory.AsReadOnlySpan().SequenceEqual(credentialKeyMemory.AsReadOnlySpan());
        }
        finally
        {
            pubAreaKeyMemory?.Dispose();
        }
    }


    /// <summary>
    /// Builds a <see cref="PublicKeyMemory"/> from <paramref name="pubArea"/>'s <c>unique</c> and
    /// <c>parameters</c> fields — a compressed SEC1 point for an ECC public area (TPM_ECC_NIST_P256/
    /// P384/P521 only), or a DER PKCS#1 <c>RSAPublicKey</c> for an RSA public area (2048/4096-bit
    /// only) — in the same canonical forms <see cref="CoseKeyExtensions.ToPublicKeyMemory"/>
    /// produces from a COSE_Key, so the two sides of <see cref="PubAreaKeyMatchesCredentialKey"/>'s
    /// comparison are byte-comparable.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> and the built key plus its algorithm tag when <paramref name="pubArea"/>
    /// is an ECC or RSA public area of a curve/key-size this library models; otherwise
    /// <see langword="false"/> — a KEYEDHASH, SYMCIPHER, or unrecognised-curve/key-size public area
    /// cannot be the credential's own signing key.
    /// </returns>
    private static bool TryBuildPublicAreaKeyMemory(
        TpmtPublic pubArea, MemoryPool<byte> pool, [NotNullWhen(true)] out PublicKeyMemory? keyMemory, out CryptoAlgorithm algorithm)
    {
        if(pubArea.Type == TpmAlgIdConstants.TPM_ALG_ECC
            && pubArea.Parameters.EccDetail is { } eccParms
            && pubArea.Unique.Ecc is { } eccPoint)
        {
            (bool supported, CryptoAlgorithm mappedAlgorithm, int componentSize, Tag tag) = eccParms.CurveId switch
            {
                TpmEccCurveConstants.TPM_ECC_NIST_P256 => (true, CryptoAlgorithm.P256, EllipticCurveConstants.P256.PointArrayLength, CryptoTags.P256PublicKey),
                TpmEccCurveConstants.TPM_ECC_NIST_P384 => (true, CryptoAlgorithm.P384, EllipticCurveConstants.P384.PointArrayLength, CryptoTags.P384PublicKey),
                TpmEccCurveConstants.TPM_ECC_NIST_P521 => (true, CryptoAlgorithm.P521, EllipticCurveConstants.P521.PointArrayLength, CryptoTags.P521PublicKey),
                _ => (false, default!, 0, default!)
            };

            if(!supported)
            {
                keyMemory = null;
                algorithm = default!;
                return false;
            }

            keyMemory = eccPoint.ToCompressedPublicKeyMemory(componentSize, tag, pool);
            algorithm = mappedAlgorithm;
            return true;
        }

        if(pubArea.Type == TpmAlgIdConstants.TPM_ALG_RSA && pubArea.Parameters.RsaDetail is { } rsaParms)
        {
            ReadOnlySpan<byte> modulus = pubArea.Unique.GetRsaModulus();
            (bool supported, CryptoAlgorithm mappedAlgorithm, Tag tag) = rsaParms.KeyBits switch
            {
                2048 => (true, CryptoAlgorithm.Rsa2048, CryptoTags.Rsa2048PublicKey),
                4096 => (true, CryptoAlgorithm.Rsa4096, CryptoTags.Rsa4096PublicKey),
                _ => (false, default!, default!)
            };

            if(!supported || modulus.IsEmpty)
            {
                keyMemory = null;
                algorithm = default!;
                return false;
            }

            byte[] rsaPublicKeyDer = BuildRsaPublicKeyDer(modulus, rsaParms.EffectiveExponent);
            IMemoryOwner<byte> owner = pool.Rent(rsaPublicKeyDer.Length);
            rsaPublicKeyDer.CopyTo(owner.Memory.Span);
            keyMemory = new PublicKeyMemory(owner, tag);
            algorithm = mappedAlgorithm;
            return true;
        }

        keyMemory = null;
        algorithm = default!;
        return false;
    }


    /// <summary>
    /// DER-encodes a PKCS#1 <c>RSAPublicKey</c> (<c>SEQUENCE { modulus INTEGER, publicExponent
    /// INTEGER }</c>) from a TPM public area's RSA <c>unique</c> modulus and effective exponent —
    /// the same canonical RSA public-key form <see cref="CoseKeyExtensions.ToPublicKeyMemory"/>
    /// builds from a COSE_Key's <c>n</c>/<c>e</c>.
    /// </summary>
    private static byte[] BuildRsaPublicKeyDer(ReadOnlySpan<byte> modulus, uint exponent)
    {
        Span<byte> exponentBytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(exponentBytes, exponent);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(modulus);
            writer.WriteIntegerUnsigned(exponentBytes);
        }

        return writer.Encode();
    }


    /// <summary>
    /// Determines whether an AIK certificate's profile conforms to the section 8.3.1 requirements
    /// this layer checks directly from <see cref="X509CertificateProfile"/>: version 3, an empty
    /// Subject field, and Basic Constraints CA <see langword="false"/>. The Subject Alternative
    /// Name and Extended Key Usage requirements are checked separately, from the certificate's raw
    /// extension bytes (<see cref="HasConformantTcgSubjectAlternativeName"/>,
    /// <see cref="ContainsAikCertificateKeyPurpose"/>), since they need more than a boolean profile
    /// flag to verify. The Authority Information Access and CRL Distribution Point extensions are
    /// OPTIONAL per section 8.3.1 and are not checked at all.
    /// </summary>
    private static bool ConformsToAikCertificateVersionSubjectAndCaProfile(X509CertificateProfile profile) =>
        profile.Version == RequiredCertificateVersion
        && profile.HasEmptySubject
        && !profile.IsCertificateAuthority;


    /// <summary>
    /// Determines whether a Subject Alternative Name extension value is set as
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements">section 8.3.1</see>
    /// requires: a <c>directoryName</c> <c>GeneralName</c> (RFC 5280 §4.2.1.6) carrying an
    /// RDNSequence with the TCG EK Credential Profile's TPM device attributes — <c>tcg-at-tpmManufacturer</c>,
    /// <c>tcg-at-tpmModel</c>, and <c>tcg-at-tpmVersion</c> (TCG EK Credential Profile for TPM
    /// Family 2.0, section 3.1.2) — each present in some relative distinguished name of that
    /// sequence.
    /// </summary>
    /// <param name="subjectAlternativeNameValue">The SAN extension's raw <c>GeneralNames</c> DER bytes.</param>
    /// <returns><see langword="true"/> when every required TPM device attribute is present; otherwise <see langword="false"/>.</returns>
    private static bool HasConformantTcgSubjectAlternativeName(ReadOnlyMemory<byte> subjectAlternativeNameValue)
    {
        try
        {
            var reader = new AsnReader(subjectAlternativeNameValue, AsnEncodingRules.DER);
            AsnReader generalNames = reader.ReadSequence();
            if(reader.HasData)
            {
                return false;
            }

            while(generalNames.HasData)
            {
                Asn1Tag tag = generalNames.PeekTag();
                if(tag.TagClass == TagClass.ContextSpecific && tag.TagValue == DirectoryNameGeneralNameTag)
                {
                    AsnReader directoryNameContent = generalNames.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, DirectoryNameGeneralNameTag, true));

                    return HasTpmDeviceAttributes(directoryNameContent);
                }

                generalNames.ReadEncodedValue();
            }

            return false;
        }
        catch(AsnContentException)
        {
            return false;
        }
    }


    /// <summary>
    /// Reads a <c>directoryName</c> choice's EXPLICIT content — the Name (RDNSequence) it wraps —
    /// and determines whether its relative distinguished names collectively carry
    /// <see cref="TpmManufacturerOid"/>, <see cref="TpmModelOid"/>, and <see cref="TpmVersionOid"/>.
    /// </summary>
    /// <param name="directoryNameContent">The <c>directoryName</c> choice's content reader, positioned at its one nested Name element.</param>
    private static bool HasTpmDeviceAttributes(AsnReader directoryNameContent)
    {
        AsnReader relativeDistinguishedNames = directoryNameContent.ReadSequence();
        if(directoryNameContent.HasData)
        {
            return false;
        }

        bool hasManufacturer = false;
        bool hasModel = false;
        bool hasVersion = false;

        while(relativeDistinguishedNames.HasData)
        {
            AsnReader relativeDistinguishedName = relativeDistinguishedNames.ReadSetOf();
            while(relativeDistinguishedName.HasData)
            {
                AsnReader attributeTypeAndValue = relativeDistinguishedName.ReadSequence();
                string attributeOid = attributeTypeAndValue.ReadObjectIdentifier();
                attributeTypeAndValue.ReadEncodedValue();
                if(attributeTypeAndValue.HasData)
                {
                    return false;
                }

                _ = attributeOid switch
                {
                    TpmManufacturerOid => hasManufacturer = true,
                    TpmModelOid => hasModel = true,
                    TpmVersionOid => hasVersion = true,
                    _ => false
                };
            }
        }

        return hasManufacturer && hasModel && hasVersion;
    }


    /// <summary>
    /// Determines whether an Extended Key Usage extension value contains
    /// <see cref="AikCertificateKeyPurposeOid"/>, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements">section 8.3.1</see>:
    /// "The Extended Key Usage extension MUST contain the OID 2.23.133.8.3."
    /// </summary>
    /// <param name="extendedKeyUsageValue">The EKU extension's raw <c>ExtKeyUsageSyntax</c> DER bytes.</param>
    private static bool ContainsAikCertificateKeyPurpose(ReadOnlyMemory<byte> extendedKeyUsageValue)
    {
        try
        {
            var reader = new AsnReader(extendedKeyUsageValue, AsnEncodingRules.DER);
            AsnReader keyPurposes = reader.ReadSequence();
            if(reader.HasData)
            {
                return false;
            }

            while(keyPurposes.HasData)
            {
                if(string.Equals(keyPurposes.ReadObjectIdentifier(), AikCertificateKeyPurposeOid, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
        catch(AsnContentException)
        {
            return false;
        }
    }


    /// <summary>
    /// Unwraps the AAGUID extension's value into a <see cref="Guid"/>. Mirrors
    /// <see cref="PackedAttestation"/>'s own AAGUID unwrapping exactly — see its remarks for why
    /// exactly one more OCTET STRING layer is unwrapped here.
    /// </summary>
    private static bool TryUnwrapAaguid(ReadOnlyMemory<byte> extensionValue, out Guid aaguid)
    {
        try
        {
            var reader = new AsnReader(extensionValue, AsnEncodingRules.DER);
            byte[] innerOctetString = reader.ReadOctetString();
            if(innerOctetString.Length != AaguidByteLength || reader.HasData)
            {
                aaguid = default;
                return false;
            }

            //A byte-level Guid comparison against the attested credential data's AAGUID is not a
            //secret-equality check — the AAGUID is public authenticator-model metadata — so a
            //constant-time compare is not required here.
            aaguid = new Guid(innerOctetString, bigEndian: true);
            return true;
        }
        catch(AsnContentException)
        {
            aaguid = default;
            return false;
        }
    }


    /// <summary>
    /// Resolves the hash algorithm section 8.3's signing procedure names "the hash algorithm
    /// corresponding to the 'alg' signature algorithm" — the digest <c>certInfo.extraData</c> must
    /// equal the hash of <c>attToBeSigned</c> under.
    /// </summary>
    /// <returns><see langword="true"/> and the digest length/tag when <paramref name="alg"/> is a recognised ES/RS/PS 256/384/512 family member; otherwise <see langword="false"/>.</returns>
    private static bool TryGetCoseAlgorithmDigest(int alg, out int length, out Tag tag)
    {
        bool isSupported;
        (length, tag, isSupported) = alg switch
        {
            int a when WellKnownCoseAlgorithms.IsEs256(a) || WellKnownCoseAlgorithms.IsRs256(a) || WellKnownCoseAlgorithms.IsPs256(a) => (32, CryptoTags.Sha256Digest, true),
            int a when WellKnownCoseAlgorithms.IsEs384(a) || WellKnownCoseAlgorithms.IsRs384(a) || WellKnownCoseAlgorithms.IsPs384(a) => (48, CryptoTags.Sha384Digest, true),
            int a when WellKnownCoseAlgorithms.IsEs512(a) || WellKnownCoseAlgorithms.IsRs512(a) || WellKnownCoseAlgorithms.IsPs512(a) => (64, CryptoTags.Sha512Digest, true),
            _ => (0, CryptoTags.Sha256Digest, false)
        };

        return isSupported;
    }


    /// <summary>
    /// Resolves the hash algorithm a TPM public area's <c>nameAlg</c> field names, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">section 8.3</see>'s Name
    /// computation, "using the nameAlg in the pubArea."
    /// </summary>
    /// <returns><see langword="true"/> and the digest length/tag when <paramref name="nameAlg"/> is SHA-256, SHA-384, or SHA-512; otherwise <see langword="false"/>.</returns>
    private static bool TryGetTpmAlgorithmDigest(TpmAlgIdConstants nameAlg, out int length, out Tag tag)
    {
        bool isSupported;
        (length, tag, isSupported) = nameAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA256 => (32, CryptoTags.Sha256Digest, true),
            TpmAlgIdConstants.TPM_ALG_SHA384 => (48, CryptoTags.Sha384Digest, true),
            TpmAlgIdConstants.TPM_ALG_SHA512 => (64, CryptoTags.Sha512Digest, true),
            _ => (0, CryptoTags.Sha256Digest, false)
        };

        return isSupported;
    }


    /// <summary>
    /// Gets the curve field width in bytes (32/48/66) the AIK leaf key's algorithm implies, for
    /// projecting a parsed <see cref="TpmuSignature"/>'s ECDSA <c>r</c>/<c>s</c> components into
    /// fixed-width IEEE P1363. Ignored (returns zero) for a non-ECDSA (RSA) leaf algorithm, matching
    /// <see cref="TpmCryptographicProjections.ToSignature"/>'s own contract.
    /// </summary>
    private static int GetEcdsaComponentSize(CryptoAlgorithm algorithm) => algorithm switch
    {
        var a when a.Equals(CryptoAlgorithm.P256) => EllipticCurveConstants.P256.PointArrayLength,
        var a when a.Equals(CryptoAlgorithm.P384) => EllipticCurveConstants.P384.PointArrayLength,
        var a when a.Equals(CryptoAlgorithm.P521) => EllipticCurveConstants.P521.PointArrayLength,
        _ => 0
    };


    /// <summary>
    /// Determines whether <paramref name="mapped"/> is consistent with <paramref name="other"/> at
    /// RSA-family granularity — mirrors <see cref="PackedAttestation"/>'s own algorithm-family
    /// comparison; see its remarks for why RSA family membership, not exact equality, is compared.
    /// </summary>
    private static bool IsConsistentAlgorithmFamily(CryptoAlgorithm mapped, CryptoAlgorithm other)
    {
        if(mapped.Equals(other))
        {
            return true;
        }

        return IsRsaFamily(mapped) && IsRsaFamily(other);
    }


    /// <summary>
    /// Determines whether <paramref name="algorithm"/> is one of the RSA-family
    /// <see cref="CryptoAlgorithm"/> values, at either the key-size or the hash-and-padding
    /// granularity.
    /// </summary>
    private static bool IsRsaFamily(CryptoAlgorithm algorithm) =>
        algorithm.Equals(CryptoAlgorithm.Rsa2048)
        || algorithm.Equals(CryptoAlgorithm.Rsa4096)
        || algorithm.Equals(CryptoAlgorithm.RsaSha256)
        || algorithm.Equals(CryptoAlgorithm.RsaSha256Pss)
        || algorithm.Equals(CryptoAlgorithm.RsaSha384)
        || algorithm.Equals(CryptoAlgorithm.RsaSha384Pss)
        || algorithm.Equals(CryptoAlgorithm.RsaSha512)
        || algorithm.Equals(CryptoAlgorithm.RsaSha512Pss);


    /// <summary>
    /// Rents a buffer sized to <paramref name="authenticatorData"/> plus <paramref name="clientDataHash"/>
    /// and fills it with their concatenation — the bytes every tpm attestation signature's
    /// <c>extraData</c> digest covers.
    /// </summary>
    /// <param name="length">The exact number of meaningful bytes in the returned owner's memory.</param>
    private static IMemoryOwner<byte> RentToBeSigned(ReadOnlyMemory<byte> authenticatorData, DigestValue clientDataHash, MemoryPool<byte> pool, out int length)
    {
        length = authenticatorData.Length + clientDataHash.Length;
        IMemoryOwner<byte> owner = pool.Rent(length);
        authenticatorData.Span.CopyTo(owner.Memory.Span);
        clientDataHash.AsReadOnlySpan().CopyTo(owner.Memory.Span[authenticatorData.Length..]);

        return owner;
    }


    /// <summary>
    /// Determines whether <paramref name="exception"/> is one of the exceptions a malformed
    /// <c>certInfo</c>/<c>pubArea</c> TPM wire structure raises while parsing: a short buffer
    /// (<see cref="ArgumentOutOfRangeException"/> from span slicing), an unmodelled union selector
    /// (<see cref="NotSupportedException"/>), or an otherwise-invalid structural value.
    /// </summary>
    private static bool IsMalformedTpmWireException(Exception exception) =>
        exception is ArgumentOutOfRangeException or NotSupportedException or InvalidOperationException or OverflowException;
}
