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
/// Builds the <c>fido-u2f</c> attestation statement format's verification procedure.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication
/// Level 3, section 8.6: FIDO U2F Attestation Statement Format</see>.
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">section 6.5.5,
/// Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures</see>
/// requires the ECDSA <c>sig</c> value to be encoded as an ASN.1 DER <c>Ecdsa-Sig-Value</c>
/// (<see href="https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3">RFC 3279 section 2.2.3</see>),
/// while the registered EC verification seam this type calls into expects the fixed-width IEEE P1363
/// <c>r ‖ s</c> encoding. <see cref="VerifyAsync"/> converts the wire signature from DER to P1363, via
/// <see cref="Fido2EcdsaWireSignature.WrapWireSignatureForVerification"/>, before calling the
/// registered verifier, mirroring <see cref="PackedAttestation"/>'s EC handling exactly. A malformed
/// DER value is caught and reported as <see cref="Fido2AttestationErrors.InvalidSignature"/> the same
/// way any other invalid signature is.
/// </para>
/// </remarks>
public static class FidoU2fAttestation
{
    /// <summary>
    /// The key identifier passed to <see cref="CryptographicKeyFactory"/> for the attestation
    /// certificate's leaf key. Not a DID or credential id — this seam has no such identity to
    /// carry, only the key material and its algorithm tag.
    /// </summary>
    private const string LeafCertificateKeyIdentifier = "fido-u2f-attestation:leaf-certificate";

    /// <summary>
    /// The exact byte length section 8.6 verification procedure step 4 requires of each of the
    /// <c>credentialPublicKey</c>'s <c>x</c> and <c>y</c> coordinates: the P-256 field element width.
    /// </summary>
    private const int ExpectedCoordinateLength = EllipticCurveConstants.P256.PointArrayLength;

    /// <summary>
    /// The leading version byte section 8.6 verification procedure step 5 uses to build
    /// <c>verificationData</c> (<c>0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F</c>).
    /// </summary>
    private const byte VerificationDataVersionPrefix = 0x00;


    /// <summary>
    /// Builds the <c>fido-u2f</c> attestation statement format's <see cref="AttestationVerifyDelegate"/>.
    /// </summary>
    /// <param name="parseStatement">Decodes the raw <c>attStmt</c> CBOR bytes.</param>
    /// <param name="validateChain">Validates the single-certificate <c>x5c</c> path against the request's trust anchors.</param>
    /// <param name="checkRevocation">
    /// An optional revocation-status seam, forwarded to <paramref name="validateChain"/> as its 6th argument,
    /// mirroring <see cref="PackedAttestation.Build"/>'s parameter of the same name exactly. When
    /// <see langword="null"/> (the default) no revocation is performed.
    /// </param>
    /// <param name="completeChain">
    /// An optional chain-completion seam, mirroring <see cref="PackedAttestation.Build"/>'s parameter of
    /// the same name exactly. When <see langword="null"/> (the default) the statement's <c>x5c</c> is
    /// passed to <paramref name="validateChain"/> unchanged.
    /// </param>
    /// <returns>The verification delegate.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="parseStatement"/> or <paramref name="validateChain"/> is <see langword="null"/>.</exception>
    public static AttestationVerifyDelegate Build(
        ParseFidoU2fAttestationStatementDelegate parseStatement,
        ValidateCertificateChainAsyncDelegate validateChain,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        CompleteCertificateChainAsyncDelegate? completeChain = null)
    {
        ArgumentNullException.ThrowIfNull(parseStatement);
        ArgumentNullException.ThrowIfNull(validateChain);

        return (request, cancellationToken) =>
            VerifyAsync(request, parseStatement, validateChain, checkRevocation, completeChain, cancellationToken);
    }


    /// <summary>
    /// Implements the section 8.6 verification procedure.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication Level 3, section 8.6.</see>
    /// The CR's verification procedure is numbered; this implementation follows that order except where
    /// noted. Section 8.6 imposes no certificate profile and no AAGUID check — this format predates
    /// AAGUIDs, and the CR's own §16.16 test vector carries a non-zero AAGUID — so neither
    /// <see cref="ReadCertificateProfileDelegate"/> nor <see cref="ReadCertificateExtensionValueDelegate"/>
    /// is required, unlike <see cref="PackedAttestation"/>.
    /// </remarks>
    private static async ValueTask<AttestationResult> VerifyAsync(
        AttestationVerificationRequest request,
        ParseFidoU2fAttestationStatementDelegate parseStatement,
        ValidateCertificateChainAsyncDelegate validateChain,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CompleteCertificateChainAsyncDelegate? completeChain,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        FidoU2fAttestationStatement statement;
        try
        {
            statement = parseStatement(request.AttestationStatement, request.Pool);
        }
        catch(Fido2FormatException)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.MalformedStatement);
        }

        //Step 3: "Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId
        //and credentialPublicKey from authenticatorData.attestedCredentialData."
        if(request.AuthenticatorData.AttestedCredentialData is not { } attestedCredentialData)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.MissingAttestedCredentialData);
        }

        if(request.TrustAnchors.Count == 0)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.NoTrustAnchors);
        }

        //Step 1 (parse-level): the CDDL fixes x5c at exactly one element; the shipped CBOR default
        //reader and any conforming ParseFidoU2fAttestationStatementDelegate implementation enforce
        //this before this method ever sees the statement.
        IReadOnlyList<PkiCertificateMemory> x5c = statement.X5c;

        PublicKeyMemory leafKeyMemory;
        IReadOnlyList<PkiCertificateMemory> chainToValidate = x5c;
        int acquiredCertificateCount = 0;
        try
        {
            if(completeChain is not null)
            {
                //Chain completion is append-only (see CompleteCertificateChainAsyncDelegate's contract):
                //any entries beyond x5c's own Count are newly acquired for this call and are this
                //method's to dispose; x5c's own entry stays caller-owned throughout.
                chainToValidate = await completeChain(x5c, request.TrustAnchors, request.Pool, cancellationToken).ConfigureAwait(false);
                acquiredCertificateCount = chainToValidate.Count - x5c.Count;
            }

            //Step 2: "Check that x5c has exactly one element and let attCert be that element. Let
            //certificate public key be the public key conveyed by attCert."
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

        //Step 2 (continued): "If certificate public key is not an Elliptic Curve (EC) public key
        //over the P-256 curve, terminate this algorithm and return an appropriate error."
        if(!leafAlgorithm.Equals(CryptoAlgorithm.P256))
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.AttestationCertificateKeyNotP256);
        }

        //Step 4: the "-2"/"-3" coordinate extraction and 32-byte size confirmation.
        CoseKey credentialPublicKey = attestedCredentialData.CredentialPublicKey;
        if(credentialPublicKey.X is not { Length: ExpectedCoordinateLength } x
            || credentialPublicKey.Y is not { Length: ExpectedCoordinateLength } y)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.CredentialCoordinateLengthInvalid);
        }

        bool signatureValid;
        using(IMemoryOwner<byte> verificationDataOwner = RentVerificationData(
            request.AuthenticatorData.RpIdHash, request.ClientDataHash, attestedCredentialData.CredentialId,
            x.Span, y.Span, request.Pool, out int verificationDataLength))
        {
            ReadOnlyMemory<byte> verificationData = verificationDataOwner.Memory[..verificationDataLength];
            try
            {
                //Step 6: "Verify the sig using verificationData and the certificate public key ...".
                using Signature signature = Fido2EcdsaWireSignature.WrapWireSignatureForVerification(statement.Signature.Span, leafAlgorithm, request.Pool);
                signatureValid = await leafPublicKey.VerifyAsync(verificationData, signature).ConfigureAwait(false);
            }
            catch(CryptographicException)
            {
                //A DER Ecdsa-Sig-Value whose r/s coordinates exceed the curve field width: fail-closed
                //to an invalid signature, mirroring PackedAttestation's handling of the same condition.
                signatureValid = false;
            }
            catch(AsnContentException)
            {
                //A malformed (non-DER) EC wire signature: fail-closed the same way.
                signatureValid = false;
            }
        }

        if(!signatureValid)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.InvalidSignature);
        }

        //Steps 7-8: Basic versus AttCA determination is explicitly optional ("Optionally, inspect
        //x5c and consult externally provided knowledge ...") and this layer has no such externally
        //provided knowledge, so AttestationType.Unknown ("uncertainty") is the correct outcome —
        //owner ruling 6, the shipped packed precedent for an indistinguishable certificate-path type.
        return new CertifiedAttestationResult(AttestationType.Unknown, x5c);
    }


    /// <summary>
    /// Rents a buffer sized to and filled with <c>verificationData</c> (section 8.6 verification
    /// procedure step 5): <c>0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F</c>,
    /// where <c>publicKeyU2F</c> (step 4's third sub-bullet) is <c>0x04 || x || y</c>.
    /// </summary>
    /// <param name="length">The exact number of meaningful bytes in the returned owner's memory.</param>
    private static IMemoryOwner<byte> RentVerificationData(
        DigestValue rpIdHash,
        DigestValue clientDataHash,
        CredentialId credentialId,
        ReadOnlySpan<byte> x,
        ReadOnlySpan<byte> y,
        MemoryPool<byte> pool,
        out int length)
    {
        length = 1 + rpIdHash.Length + clientDataHash.Length + credentialId.Length + 1 + x.Length + y.Length;
        IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> destination = owner.Memory.Span;

        int offset = 0;
        destination[offset] = VerificationDataVersionPrefix;
        offset += 1;

        rpIdHash.AsReadOnlySpan().CopyTo(destination[offset..]);
        offset += rpIdHash.Length;

        clientDataHash.AsReadOnlySpan().CopyTo(destination[offset..]);
        offset += clientDataHash.Length;

        credentialId.AsReadOnlySpan().CopyTo(destination[offset..]);
        offset += credentialId.Length;

        destination[offset] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        offset += 1;

        x.CopyTo(destination[offset..]);
        offset += x.Length;

        y.CopyTo(destination[offset..]);

        return owner;
    }
}
