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
/// Builds the <c>android-key</c> attestation statement format's verification procedure.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web
/// Authentication Level 3, section 8.4: Android Key Attestation Statement Format.</see>
/// </para>
/// <para>
/// <strong>Deviation from the <see cref="PackedAttestation"/> shape.</strong> Unlike
/// <see cref="PackedAttestation.Build"/>, this <see cref="Build"/> takes no
/// <c>ReadCertificateProfileDelegate</c>: <see href="https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements">
/// section 8.4.1</see>'s entire content is the key description extension's OID and a sentence
/// delegating its schema — it defines no certificate profile (no required version, Subject
/// Organizational Unit, or similar) the way
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">section
/// 8.2.1</see> does for <c>packed</c>, so there is nothing for a profile delegate to check. This
/// mirrors the <c>fido-u2f</c> format's own <c>Build</c>, which likewise omits a profile delegate
/// because <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">section 8.6</see>
/// imposes no certificate profile either.
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">section
/// 6.5.5, Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion
/// Signatures</see> applies to <c>android-key</c>'s EC <c>sig</c> value exactly as it does to
/// <c>packed</c>'s: an ASN.1 DER <c>Ecdsa-Sig-Value</c> on the wire, converted to fixed-width IEEE
/// P1363 via <see cref="Fido2EcdsaWireSignature.WrapWireSignatureForVerification"/> before the
/// registered EC verifier runs.
/// </para>
/// <para>
/// <strong>credCert-key-versus-credentialPublicKey comparison.</strong> The comparison is byte
/// equality of the key material plus algorithm-FAMILY equality of the two sides' key tags, not
/// literal <see cref="Tag"/> equality: the chain-validated leaf key carries a key-size-only RSA tag
/// (<see cref="CryptoAlgorithm.Rsa2048"/>/<see cref="CryptoAlgorithm.Rsa4096"/>), while
/// <see cref="CoseKeyExtensions.ToPublicKeyMemory"/> resolves a hash-and-padding-specific RSA tag
/// (<see cref="CryptoAlgorithm.RsaSha256"/> and siblings) from the credential's own declared
/// <c>alg</c> — the same key-size-versus-hash-family granularity mismatch
/// <see cref="PackedAttestation"/>'s own algorithm cross-check documents. Reusing
/// <see cref="IsConsistentAlgorithmFamily"/> for both checks keeps an RS256 credential from being
/// rejected as a false-positive key mismatch while a genuinely different EC or RSA key still fails
/// on the byte comparison.
/// </para>
/// </remarks>
public static class AndroidKeyAttestation
{
    /// <summary>
    /// The dotted OID of the android key attestation certificate extension.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements">W3C Web
    /// Authentication Level 3, section 8.4.1: Android Key Attestation Statement Certificate
    /// Requirements.</see> "Android Key Attestation attestation certificate's android key
    /// attestation certificate extension data is identified by the OID
    /// 1.3.6.1.4.1.11129.2.1.17."
    /// </remarks>
    private const string KeyDescriptionExtensionOid = "1.3.6.1.4.1.11129.2.1.17";

    /// <summary>
    /// The <c>AuthorizationList.origin</c> value section 8.4's verification procedure requires:
    /// the key was generated on-device, never imported.
    /// </summary>
    /// <remarks>
    /// Recovered from
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-android-key-es256">W3C Web
    /// Authentication Level 3, section 16.14: Android Key Attestation with ES256 Credential</see>'s
    /// own key description bytes (a decoded <c>origin</c> INTEGER value of <c>0</c>) together with
    /// section 8.4's own prose naming the constant <c>KM_ORIGIN_GENERATED</c>.
    /// </remarks>
    private const int KmOriginGenerated = 0;

    /// <summary>
    /// The <c>AuthorizationList.purpose</c> value section 8.4's verification procedure requires to
    /// be present: the key is authorized to sign.
    /// </summary>
    /// <remarks>
    /// Recovered from section 16.14's own key description bytes (a decoded <c>purpose</c> SET
    /// containing the INTEGER value <c>2</c>) together with section 8.4's own prose naming the
    /// constant <c>KM_PURPOSE_SIGN</c>.
    /// </remarks>
    private const int KmPurposeSign = 2;

    /// <summary>
    /// The key identifier passed to <see cref="CryptographicKeyFactory"/> for the attestation
    /// certificate's leaf key. Not a DID or credential id — this seam has no such identity to
    /// carry, only the key material and its algorithm tag.
    /// </summary>
    private const string LeafCertificateKeyIdentifier = "android-key-attestation:leaf-certificate";

    /// <summary>
    /// Builds the <c>android-key</c> attestation statement format's <see cref="AttestationVerifyDelegate"/>.
    /// </summary>
    /// <param name="parseStatement">Decodes the raw <c>attStmt</c> CBOR bytes.</param>
    /// <param name="validateChain">Validates the statement's <c>x5c</c> certificate path against the request's trust anchors.</param>
    /// <param name="readExtensionValue">Reads the leaf certificate's android key attestation certificate extension.</param>
    /// <param name="checkRevocation">
    /// An optional revocation-status seam, forwarded to <paramref name="validateChain"/> — see
    /// <see cref="PackedAttestation.Build"/>'s parameter of the same name for the exact semantics;
    /// unchanged here.
    /// </param>
    /// <param name="completeChain">
    /// An optional chain-completion seam — see <see cref="PackedAttestation.Build"/>'s parameter of
    /// the same name for the exact semantics; unchanged here.
    /// </param>
    /// <param name="requireTeeEnforcedAuthorizations">
    /// When <see langword="true"/>, the <c>origin</c> and <c>purpose</c> checks read only the key
    /// description's <c>teeEnforced</c> authorization list — the RP policy that accepts only keys
    /// attested by a trusted execution environment. When <see langword="false"/> (the default), the
    /// checks pass when EITHER the <c>teeEnforced</c> OR the <c>softwareEnforced</c> authorization
    /// list independently satisfies them, per section 8.4's "otherwise use the union of
    /// <c>teeEnforced</c> and <c>softwareEnforced</c>" — the specification's baseline posture.
    /// </param>
    /// <returns>The verification delegate.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any required parameter is <see langword="null"/>.</exception>
    public static AttestationVerifyDelegate Build(
        ParseAndroidKeyAttestationStatementDelegate parseStatement,
        ValidateCertificateChainAsyncDelegate validateChain,
        ReadCertificateExtensionValueDelegate readExtensionValue,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        CompleteCertificateChainAsyncDelegate? completeChain = null,
        bool requireTeeEnforcedAuthorizations = false)
    {
        ArgumentNullException.ThrowIfNull(parseStatement);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(readExtensionValue);

        return (request, cancellationToken) =>
            VerifyAsync(request, parseStatement, validateChain, readExtensionValue, checkRevocation, completeChain, requireTeeEnforcedAuthorizations, cancellationToken);
    }


    /// <summary>
    /// Implements the section 8.4 verification procedure.
    /// </summary>
    private static async ValueTask<AttestationResult> VerifyAsync(
        AttestationVerificationRequest request,
        ParseAndroidKeyAttestationStatementDelegate parseStatement,
        ValidateCertificateChainAsyncDelegate validateChain,
        ReadCertificateExtensionValueDelegate readExtensionValue,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CompleteCertificateChainAsyncDelegate? completeChain,
        bool requireTeeEnforcedAuthorizations,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        AndroidKeyAttestationStatement statement;
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

        //The CDDL's x5c is mandatory syntax (unlike packed's), but a present, empty array is still
        //a possible decode: android-key has no self-attestation branch to fall back to.
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
                //x5c's own entries stay caller-owned throughout.
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

        if(CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(statement.Alg) is not { } mappedAlgorithm
            || !IsConsistentAlgorithmFamily(mappedAlgorithm, leafAlgorithm))
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.AlgorithmMismatch);
        }

        using IMemoryOwner<byte> toBeSignedOwner = RentToBeSigned(request.AuthenticatorDataBytes, request.ClientDataHash, request.Pool, out int toBeSignedLength);
        ReadOnlyMemory<byte> toBeSigned = toBeSignedOwner.Memory[..toBeSignedLength];

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
            //to an invalid signature, per section 8.4's "Verify that sig is a valid signature".
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

        CoseKey credentialPublicKey = attestedCredentialData.CredentialPublicKey;
        using PublicKeyMemory credentialPublicKeyMemory = credentialPublicKey.ToPublicKeyMemory(request.Pool);
        CryptoAlgorithm credentialKeyAlgorithm = credentialPublicKeyMemory.Tag.Get<CryptoAlgorithm>();
        if(!IsConsistentAlgorithmFamily(leafAlgorithm, credentialKeyAlgorithm)
            || !leafKeyMemory.AsReadOnlySpan().SequenceEqual(credentialPublicKeyMemory.AsReadOnlySpan()))
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.CredentialKeyMismatch);
        }

        PkiCertificateMemory credCert = x5c[0];
        X509ExtensionValue? keyDescriptionExtension = readExtensionValue(credCert, KeyDescriptionExtensionOid);
        if(keyDescriptionExtension is null)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.KeyDescriptionMissing);
        }

        AndroidKeyDescription keyDescription;
        try
        {
            keyDescription = AndroidKeyDescription.Read(keyDescriptionExtension.Value);
        }
        catch(Fido2FormatException)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.MalformedStatement);
        }

        if(!keyDescription.AttestationChallenge.Span.SequenceEqual(request.ClientDataHash.AsReadOnlySpan()))
        {
            //Not a secret-equality check — the attestationChallenge is the (public) clientDataHash
            //echoed back through the attestation certificate, per section 8.4's "identical to
            //clientDataHash" — a plain SequenceEqual is the correct comparison.
            return new RejectedAttestationResult(Fido2AttestationErrors.AttestationChallengeMismatch);
        }

        if(keyDescription.SoftwareEnforced.HasAllApplications || keyDescription.TeeEnforced.HasAllApplications)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.KeyScopedToAllApplications);
        }

        if(!IsOriginGenerated(keyDescription, requireTeeEnforcedAuthorizations))
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.KeyOriginNotGenerated);
        }

        if(!ContainsPurposeSign(keyDescription, requireTeeEnforcedAuthorizations))
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.KeyPurposeNotSign);
        }

        //Attestation types supported: Basic only (section 8.4's own "Attestation types supported:
        //Basic" and the verification procedure's final "return ... attestation type Basic").
        return new CertifiedAttestationResult(AttestationType.Basic, x5c);
    }


    /// <summary>
    /// Determines whether the key description's applicable authorization list(s) report
    /// <c>origin</c> equal to <see cref="KmOriginGenerated"/>, per <paramref name="requireTeeEnforcedAuthorizations"/>'s
    /// teeEnforced-only-versus-union policy.
    /// </summary>
    /// <remarks>
    /// The union branch checks EACH list independently rather than preferring one and falling back
    /// to the other on absence: preferring <c>teeEnforced</c> and only consulting
    /// <c>softwareEnforced</c> when <c>teeEnforced</c>'s <c>origin</c> is entirely absent would let
    /// a <c>teeEnforced</c> list carrying the WRONG origin value silently mask a correct
    /// <c>softwareEnforced</c> one — the union is "either list satisfies it", not "whichever list
    /// answers first".
    /// </remarks>
    private static bool IsOriginGenerated(AndroidKeyDescription keyDescription, bool requireTeeEnforcedAuthorizations)
    {
        if(requireTeeEnforcedAuthorizations)
        {
            return keyDescription.TeeEnforced.Origin == KmOriginGenerated;
        }

        return keyDescription.TeeEnforced.Origin == KmOriginGenerated
            || keyDescription.SoftwareEnforced.Origin == KmOriginGenerated;
    }


    /// <summary>
    /// Determines whether the key description's applicable authorization list(s) report a
    /// <c>purpose</c> set containing <see cref="KmPurposeSign"/>, per
    /// <paramref name="requireTeeEnforcedAuthorizations"/>'s teeEnforced-only-versus-union policy.
    /// </summary>
    /// <remarks>See <see cref="IsOriginGenerated"/>'s remarks — the same either-list-satisfies-it union semantics apply.</remarks>
    private static bool ContainsPurposeSign(AndroidKeyDescription keyDescription, bool requireTeeEnforcedAuthorizations)
    {
        if(requireTeeEnforcedAuthorizations)
        {
            return keyDescription.TeeEnforced.Purposes.Contains(KmPurposeSign);
        }

        return keyDescription.TeeEnforced.Purposes.Contains(KmPurposeSign)
            || keyDescription.SoftwareEnforced.Purposes.Contains(KmPurposeSign);
    }


    /// <summary>
    /// Rents a buffer sized to <paramref name="authenticatorData"/> plus <paramref name="clientDataHash"/>
    /// and fills it with their concatenation — the bytes every android-key attestation signature covers.
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
    /// Determines whether <paramref name="mapped"/> — the <see cref="CryptoAlgorithm"/> the
    /// attestation statement's COSE <c>alg</c> maps to — is consistent with
    /// <paramref name="leafAlgorithm"/>, the leaf certificate key's own algorithm tag.
    /// </summary>
    /// <remarks>
    /// Mirrors <see cref="PackedAttestation"/>'s own algorithm-family comparison: the leaf key's
    /// <see cref="Tag"/> carries a key-size-only RSA algorithm while the COSE <c>alg</c> maps to a
    /// hash-and-padding-specific RSA algorithm, so RSA family membership is compared rather than
    /// requiring exact equality; every other algorithm this layer maps uses one
    /// <see cref="CryptoAlgorithm"/> value for both purposes, so exact equality already covers it.
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
