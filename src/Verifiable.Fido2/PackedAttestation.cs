using System.Buffers;
using System.Formats.Asn1;
using System.Security;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// Builds the <c>packed</c> attestation statement format's verification procedure.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">section 6.5.5,
/// Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures</see>
/// requires an ECDSA <c>sig</c> value (<c>COSEAlgorithmIdentifier</c> -7 ES256, -35 ES384, -36 ES512) to
/// be encoded as an ASN.1 DER <c>Ecdsa-Sig-Value</c>
/// (<see href="https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3">RFC 3279 section 2.2.3</see>),
/// while the registered EC verification seam this type calls into expects the fixed-width IEEE P1363
/// <c>r ‖ s</c> encoding. Both <see cref="VerifySelfAsync"/> and <see cref="VerifyCertifiedAsync"/>
/// convert an EC signing key's wire signature from DER to P1363, via
/// <see cref="Fido2EcdsaWireSignature.WrapWireSignatureForVerification"/>, before calling the
/// registered verifier, so a spec-conformant DER-encoded attestation signature verifies correctly.
/// RSA and EdDSA signatures carry no such conversion — section 6.5.5 leaves them "not ASN.1
/// wrapped" — so they pass through unchanged. A malformed DER value is caught and reported as
/// <see cref="Fido2AttestationErrors.InvalidSignature"/> the same way any other invalid signature is.
/// </para>
/// </remarks>
public static class PackedAttestation
{
    /// <summary>
    /// The key identifier passed to <see cref="CryptographicKeyFactory"/> for the attestation
    /// certificate's leaf key. Not a DID or credential id — this seam has no such identity to
    /// carry, only the key material and its algorithm tag.
    /// </summary>
    private const string LeafCertificateKeyIdentifier = "packed-attestation:leaf-certificate";

    /// <summary>
    /// The key identifier passed to <see cref="CryptographicKeyFactory"/> for the credential
    /// public key used in self attestation.
    /// </summary>
    private const string CredentialPublicKeyIdentifier = "packed-attestation:credential-public-key";

    /// <summary>
    /// The Subject Organizational Unit value a packed attestation certificate's Subject field
    /// MUST carry.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">W3C Web Authentication Level 3, section 8.2.1: Certificate Requirements for Packed Attestation Statements.</see>
    /// "Subject-OU: Literal string 'Authenticator Attestation' (UTF8String)".
    /// </remarks>
    private const string AttestationCertificateOrganizationalUnit = "Authenticator Attestation";

    /// <summary>
    /// The dotted OID of the <c>id-fido-gen-ce-aaguid</c> X.509 extension.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">W3C Web Authentication Level 3, section 8.2.1: Certificate Requirements for Packed Attestation Statements.</see>
    /// </remarks>
    private const string AaguidExtensionOid = "1.3.6.1.4.1.45724.1.1.4";

    /// <summary>
    /// The dotted OID of the <c>id-fido-gen-ce-sernum</c> X.509 extension.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-enterprise-packed-attestation-cert-requirements">W3C
    /// Web Authentication Level 3, section 8.2.2: Certificate Requirements for Enterprise Packed
    /// Attestation Statements.</see>
    /// </remarks>
    private const string SernumExtensionOid = "1.3.6.1.4.1.45724.1.1.2";

    /// <summary>The certificate version (RFC 5280 §4.1.2.1) section 8.2.1 requires: version 3.</summary>
    private const int RequiredCertificateVersion = 3;

    /// <summary>The exact byte length of the AAGUID once unwrapped from its OCTET STRING encoding.</summary>
    private const int AaguidByteLength = 16;


    /// <summary>
    /// Builds the <c>packed</c> attestation statement format's <see cref="AttestationVerifyDelegate"/>.
    /// </summary>
    /// <param name="parseStatement">Decodes the raw <c>attStmt</c> CBOR bytes.</param>
    /// <param name="validateChain">Validates a certified attestation's <c>x5c</c> certificate path against the request's trust anchors.</param>
    /// <param name="readProfile">Reads the leaf certificate's profile-relevant fields for the section 8.2.1 certificate requirements.</param>
    /// <param name="readExtensionValue">Reads the leaf certificate's <c>id-fido-gen-ce-aaguid</c> extension, if present.</param>
    /// <param name="checkRevocation">
    /// An optional revocation-status seam, forwarded to <paramref name="validateChain"/> as its 6th argument.
    /// When <see langword="null"/> (the default) no revocation is performed, unchanged from before this parameter
    /// existed. When supplied, it is consulted for the leaf AND every intermediate CA certificate the (possibly
    /// completed) chain carries, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication
    /// Level 3, section 7.1</see>'s "the Relying Party MUST have access to certificate status information for the
    /// intermediate CA certificates" — see <see cref="ValidateCertificateChainAsyncDelegate"/>'s <c>checkRevocation</c>
    /// contract for the exact per-certificate semantics.
    /// </param>
    /// <param name="completeChain">
    /// An optional chain-completion seam. When <see langword="null"/> (the default) the statement's <c>x5c</c> is
    /// passed to <paramref name="validateChain"/> unchanged, exactly as before this parameter existed. When
    /// supplied, it is given the chance to append any intermediate certificates <c>x5c</c> omitted, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication
    /// Level 3, section 7.1</see>'s "the Relying Party MUST also be able to build the attestation certificate
    /// chain if the client did not provide this chain in the attestation information."
    /// </param>
    /// <returns>The verification delegate.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any required parameter is <see langword="null"/>.</exception>
    public static AttestationVerifyDelegate Build(
        ParsePackedAttestationStatementDelegate parseStatement,
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
    /// Implements the section 8.2 verification procedure: decodes <c>attStmt</c>, then dispatches
    /// to the certified (<c>x5c</c> present) or self (<c>x5c</c> absent) branch.
    /// </summary>
    private static async ValueTask<AttestationResult> VerifyAsync(
        AttestationVerificationRequest request,
        ParsePackedAttestationStatementDelegate parseStatement,
        ValidateCertificateChainAsyncDelegate validateChain,
        ReadCertificateProfileDelegate readProfile,
        ReadCertificateExtensionValueDelegate readExtensionValue,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CompleteCertificateChainAsyncDelegate? completeChain,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        PackedAttestationStatement statement;
        try
        {
            statement = parseStatement(request.AttestationStatement, request.Pool);
        }
        catch(Fido2FormatException)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.MalformedStatement);
        }

        using IMemoryOwner<byte> toBeSignedOwner = RentToBeSigned(request.AuthenticatorDataBytes, request.ClientDataHash, request.Pool, out int toBeSignedLength);
        ReadOnlyMemory<byte> toBeSigned = toBeSignedOwner.Memory[..toBeSignedLength];

        if(statement.X5c is { } x5c)
        {
            return await VerifyCertifiedAsync(request, statement, x5c, toBeSigned, validateChain, readProfile, readExtensionValue, checkRevocation, completeChain, cancellationToken).ConfigureAwait(false);
        }

        return await VerifySelfAsync(request, statement, toBeSigned).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies the <c>x5c</c>-present branch: a certified attestation whose signature chains
    /// through an X.509 certificate path.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
    /// </remarks>
    private static async ValueTask<AttestationResult> VerifyCertifiedAsync(
        AttestationVerificationRequest request,
        PackedAttestationStatement statement,
        IReadOnlyList<PkiCertificateMemory> x5c,
        ReadOnlyMemory<byte> toBeSigned,
        ValidateCertificateChainAsyncDelegate validateChain,
        ReadCertificateProfileDelegate readProfile,
        ReadCertificateExtensionValueDelegate readExtensionValue,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CompleteCertificateChainAsyncDelegate? completeChain,
        CancellationToken cancellationToken)
    {
        //The CDDL requires at least attestnCert when x5c is present; a non-null but empty array
        //does not conform to that syntax.
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

        PkiCertificateMemory leafCertificate = x5c[0];
        X509CertificateProfile profile = readProfile(leafCertificate);
        if(!ConformsToAttestationCertificateProfile(profile))
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.CertificateProfileViolation);
        }

        X509ExtensionValue? aaguidExtension = readExtensionValue(leafCertificate, AaguidExtensionOid);
        if(aaguidExtension is not null)
        {
            //Section 8.2.1: "The extension MUST NOT be marked as critical." Defense in depth: both
            //registered chain validators already reject an unrecognised critical extension during
            //chain building (RFC 5280 section 4.2), so under those backends the chain step above
            //fails first; this check stays so the section 8.2.1 requirement holds regardless of
            //how permissive the injected chain-validation delegate is.
            if(aaguidExtension.IsCritical)
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.CertificateProfileViolation);
            }

            if(request.AuthenticatorData.AttestedCredentialData is not { } attestedCredentialData)
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.MissingAttestedCredentialData);
            }

            if(!TryUnwrapAaguid(aaguidExtension.Value, out Guid extensionAaguid) || extensionAaguid != attestedCredentialData.Aaguid)
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.AaguidMismatch);
            }
        }

        X509ExtensionValue? sernumExtension = readExtensionValue(leafCertificate, SernumExtensionOid);
        if(sernumExtension is not null)
        {
            //Section 8.2.2: "This extension MUST NOT be marked as critical." Defense in depth,
            //mirroring the AAGUID extension's check above: both registered chain validators
            //already reject an unrecognised critical extension during chain building (RFC 5280
            //section 4.2), so under those backends the chain-validation step above fails first;
            //this check stays so the section 8.2.2 requirement holds regardless of how permissive
            //the injected chain-validation delegate is.
            if(sernumExtension.IsCritical)
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.CertificateProfileViolation);
            }

            if(!request.AcceptsEnterpriseAttestation)
            {
                //Section 8.2.2: "This extension MUST NOT be present in non-enterprise
                //attestations." The CR phrases this as a constraint on the certificate's own
                //contents, not a numbered step of the relying party's verification procedure
                //(see Fido2AttestationErrors.SerialNumberExtensionNotPermitted's remarks) —
                //rejecting here is this codebase's hardening posture, gated on whether the
                //registration ceremony itself requested enterprise attestation.
                return new RejectedAttestationResult(Fido2AttestationErrors.SerialNumberExtensionNotPermitted);
            }
        }

        bool signatureValid;
        try
        {
            using Signature signature = Fido2EcdsaWireSignature.WrapWireSignatureForVerification(
                statement.Signature.Span, leafAlgorithm, request.Pool);
            signatureValid = await leafPublicKey.VerifyAsync(toBeSigned, signature).ConfigureAwait(false);
        }
        catch(CryptographicException)
        {
            //A DER Ecdsa-Sig-Value whose r/s coordinates exceed the curve field width: fail-closed
            //to an invalid signature, per section 8.2's "Verify that sig is a valid signature".
            signatureValid = false;
        }
        catch(AsnContentException)
        {
            //A malformed (non-DER) EC wire signature: fail-closed the same way.
            signatureValid = false;
        }

        if(!signatureValid)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.InvalidSignature);
        }

        if(CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(statement.Alg) is not { } mappedAlgorithm
            || !IsConsistentAlgorithmFamily(mappedAlgorithm, leafAlgorithm))
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.AlgorithmMismatch);
        }

        //Basic versus Attestation CA is indistinguishable without externally supplied authenticator
        //metadata; the verification procedure explicitly permits returning uncertainty here
        //("return implementation-specific values representing attestation type Basic, AttCA or
        //uncertainty"), so AttestationType.Unknown is the correct outcome at this layer.
        return new CertifiedAttestationResult(AttestationType.Unknown, x5c);
    }


    /// <summary>
    /// Verifies the <c>x5c</c>-absent branch: self attestation, signed with the credential's own
    /// private key.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
    /// </remarks>
    private static async ValueTask<AttestationResult> VerifySelfAsync(
        AttestationVerificationRequest request,
        PackedAttestationStatement statement,
        ReadOnlyMemory<byte> toBeSigned)
    {
        if(request.AuthenticatorData.AttestedCredentialData is not { } attestedCredentialData)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.MissingAttestedCredentialData);
        }

        CoseKey credentialPublicKey = attestedCredentialData.CredentialPublicKey;
        if(credentialPublicKey.Alg is not { } credentialAlgorithm || credentialAlgorithm != statement.Alg)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.AlgorithmMismatch);
        }

        //ToPublicKeyMemory rents from the request pool; CreatePublicKey takes ownership of the result,
        //released when credentialKey is disposed below.
        PublicKeyMemory credentialKeyMemory = credentialPublicKey.ToPublicKeyMemory(request.Pool);
        using PublicKey credentialKey = CryptographicKeyFactory.CreatePublicKey(credentialKeyMemory, CredentialPublicKeyIdentifier, credentialKeyMemory.Tag);

        bool signatureValid;
        try
        {
            using Signature signature = Fido2EcdsaWireSignature.WrapWireSignatureForVerification(
                statement.Signature.Span, credentialKeyMemory.Tag.Get<CryptoAlgorithm>(), request.Pool);
            signatureValid = await credentialKey.VerifyAsync(toBeSigned, signature).ConfigureAwait(false);
        }
        catch(CryptographicException)
        {
            //A DER Ecdsa-Sig-Value whose r/s coordinates exceed the curve field width: fail-closed
            //to an invalid signature, per section 8.2's "Verify that sig is a valid signature".
            signatureValid = false;
        }
        catch(AsnContentException)
        {
            //A malformed (non-DER) EC wire signature: fail-closed the same way.
            signatureValid = false;
        }

        return signatureValid
            ? new SelfAttestationResult()
            : new RejectedAttestationResult(Fido2AttestationErrors.InvalidSignature);
    }


    /// <summary>
    /// Rents a buffer sized to <paramref name="authenticatorData"/> plus <paramref name="clientDataHash"/>
    /// and fills it with their concatenation — the bytes every packed attestation signature covers.
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
    /// Determines whether a leaf certificate's profile conforms to the section 8.2.1 certificate
    /// requirements this layer enforces: version 3, not a certificate authority, an Organizational
    /// Unit of "Authenticator Attestation", at least one non-empty Organization and Common Name, and
    /// at least one Country entry where every entry is a structurally valid, non-user-assigned
    /// ISO 3166-1 alpha-2 code.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">W3C Web Authentication Level 3, section 8.2.1: Certificate Requirements for Packed Attestation Statements.</see>
    /// "Subject-C: ISO 3166 code specifying the country where the Authenticator vendor is
    /// incorporated." Subject-O and Subject-CN are the vendor's legal name and a vendor-chosen
    /// value respectively — this layer checks only that each is present and non-empty, not its
    /// content. The Subject-C check is structural only — exactly two ASCII uppercase letters that
    /// ISO 3166-1 has not left user-assigned (<c>AA</c>, <c>QM</c>-<c>QZ</c>, the whole <c>X*</c>
    /// range, and <c>ZZ</c>) — since this layer has no registry of currently assigned codes to check
    /// membership against.
    /// </remarks>
    private static bool ConformsToAttestationCertificateProfile(X509CertificateProfile profile)
    {
        return profile.Version == RequiredCertificateVersion
            && !profile.IsCertificateAuthority
            && profile.SubjectOrganizationalUnits.Contains(AttestationCertificateOrganizationalUnit, StringComparer.Ordinal)
            && profile.SubjectOrganizations.Any(static organization => !string.IsNullOrEmpty(organization))
            && profile.SubjectCommonNames.Any(static commonName => !string.IsNullOrEmpty(commonName))
            && profile.SubjectCountries.Count > 0
            && profile.SubjectCountries.All(IsValidIso3166Alpha2CountryCode);

        //Structural ISO 3166-1 alpha-2 validation only: exactly two ASCII uppercase letters that
        //ISO 3166-1 has not left user-assigned (AA, QM-QZ, XA-XZ, ZZ) — this layer keeps no
        //registry of currently assigned codes to check membership against.
        static bool IsValidIso3166Alpha2CountryCode(string code)
        {
            if(code.Length != 2 || !char.IsAsciiLetterUpper(code[0]) || !char.IsAsciiLetterUpper(code[1]))
            {
                return false;
            }

            return code is not ("AA" or "ZZ")
                && code[0] != 'X'
                && !(code[0] == 'Q' && code[1] is >= 'M' and <= 'Z');
        }
    }


    /// <summary>
    /// Unwraps the AAGUID extension's value into a <see cref="Guid"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">W3C Web Authentication Level 3, section 8.2.1: Certificate Requirements for Packed Attestation Statements.</see>
    /// "Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING.
    /// Thus, the AAGUID MUST be wrapped in two OCTET STRINGS to be valid." The platform-neutral
    /// <see cref="ReadCertificateExtensionValueDelegate"/> already yields the extension's
    /// <c>extnValue</c> OCTET STRING contents — the outer wrapping — so only the one remaining
    /// inner OCTET STRING is unwrapped here.
    /// </remarks>
    /// <returns>
    /// <see langword="true"/> and the decoded <paramref name="aaguid"/> when the value is a
    /// well-formed DER OCTET STRING of exactly 16 bytes with no trailing data; otherwise
    /// <see langword="false"/>.
    /// </returns>
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
            //secret-equality check — the AAGUID is public authenticator-model metadata, not a
            //credential or key — so a constant-time compare is not required here; the fixed-length,
            //big-endian reconstruction is what section 8.2.1 requires.
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
    /// Determines whether <paramref name="mapped"/> — the <see cref="CryptoAlgorithm"/> the
    /// attestation statement's COSE <c>alg</c> maps to — is consistent with
    /// <paramref name="leafAlgorithm"/>, the leaf certificate key's own algorithm tag.
    /// </summary>
    /// <remarks>
    /// The leaf key's <see cref="Tag"/> carries a key-size-only RSA algorithm
    /// (<see cref="CryptoAlgorithm.Rsa2048"/>/<see cref="CryptoAlgorithm.Rsa4096"/>) as read from
    /// the certificate's public key, while the COSE <c>alg</c> maps to a hash-and-padding-specific
    /// RSA algorithm (<see cref="CryptoAlgorithm.RsaSha256"/>/<see cref="CryptoAlgorithm.RsaSha256Pss"/>/...);
    /// both describe the same RSA key family at different granularity, so RSA family membership is
    /// compared rather than requiring exact equality. Every other algorithm this layer maps
    /// (P-256/P-384/P-521/Ed25519) uses one <see cref="CryptoAlgorithm"/> value for both purposes,
    /// so exact equality already covers it.
    /// </remarks>
    private static bool IsConsistentAlgorithmFamily(CryptoAlgorithm mapped, CryptoAlgorithm leafAlgorithm)
    {
        if(mapped.Equals(leafAlgorithm))
        {
            return true;
        }

        return IsRsaFamily(mapped) && IsRsaFamily(leafAlgorithm);
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
}
