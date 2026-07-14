using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Eac;

/// <summary>
/// Verifies a card-verifiable certificate chain (CVCA -> Document Verifier -> terminal) the way the chip
/// does during Terminal Authentication: starting from a trusted Country Verifying Certification Authority,
/// each certificate's signature is checked with the previous certificate's public key, the holder/authority
/// references link the chain, the role narrows at each step, and every certificate is within its validity
/// period (BSI TR-03110-3 §2.5, ICAO Doc 9303 Part 11 §4.4).
/// </summary>
/// <remarks>
/// <para>
/// The signature of each certificate is computed by its issuer over the encoded body, so it is verified
/// against the issuer's public key with the hash the issuer's key implies (TR-03110-3 §C.1.8). The trust
/// anchor is the CVCA the verifier already trusts (the chip holds it, selected by MSE:Set DST); its own
/// signature is not re-checked here. Verification is fail-closed: any broken reference, role violation,
/// expired certificate, or invalid signature stops the walk with the corresponding result.
/// </para>
/// <para>
/// An elliptic-curve issuer is verified through the registered verification function for its curve; an RSA
/// issuer through the registered function for its <c>id-TA-RSA</c> scheme (PKCS#1 or PSS, SHA-256 or SHA-512).
/// The signature algorithm of each certificate is the one its issuer's public-key object identifier names
/// (TR-03110-3 §C.1.8), so the whole chain may be elliptic-curve, RSA, or a mix. Only the retired SHA-1
/// <c>id-TA-RSA</c> schemes are reported as <see cref="CvcChainVerificationResult.UnsupportedIssuerKey"/>.
/// </para>
/// </remarks>
public static class CardVerifiableCertificateChain
{
    /// <summary>
    /// Verifies a certificate chain presented under a trusted CVCA.
    /// </summary>
    /// <param name="trustAnchor">The trusted Country Verifying Certification Authority certificate.</param>
    /// <param name="chain">The certificates the terminal presents, in issuing order (Document Verifier first, terminal last), each signed by the one before it (the first by the trust anchor).</param>
    /// <param name="referenceDate">The date the validity of each chained certificate is checked against (the chip's effective date in a real inspection).</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see cref="CvcChainVerificationResult.Valid"/> when the whole chain verifies; otherwise the first failure encountered.</returns>
    public static async ValueTask<CvcChainVerificationResult> VerifyAsync(
        CardVerifiableCertificate trustAnchor,
        IReadOnlyList<CardVerifiableCertificate> chain,
        DateOnly referenceDate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trustAnchor);
        ArgumentNullException.ThrowIfNull(chain);

        if(trustAnchor.Chat.Role != CertificateRole.CertificationAuthority)
        {
            return CvcChainVerificationResult.TrustAnchorNotCertificationAuthority;
        }

        if(chain.Count == 0)
        {
            return CvcChainVerificationResult.EmptyChain;
        }

        CardVerifiableCertificate issuer = trustAnchor;
        foreach(CardVerifiableCertificate certificate in chain)
        {
            CvcChainVerificationResult step = await VerifyOneAsync(issuer, certificate, referenceDate, cancellationToken).ConfigureAwait(false);
            if(step != CvcChainVerificationResult.Valid)
            {
                return step;
            }

            issuer = certificate;
        }

        //A Terminal Authentication chain must present the terminal's own certificate as its last link — that is the
        //key EXTERNAL AUTHENTICATE proves possession of. A chain that stops at a Document Verifier links validly but
        //never proves a terminal key, so it is not a complete Terminal Authentication chain.
        if(issuer.Chat.Role != CertificateRole.Terminal)
        {
            return CvcChainVerificationResult.ChainNotTerminatedByTerminal;
        }

        return CvcChainVerificationResult.Valid;
    }


    /// <summary>
    /// Verifies a single certificate against the public key of the certificate that issued it: the
    /// holder/authority reference linkage, the role narrowing, the validity period, and the signature over
    /// the encoded body. This is one step of the chain walk, exposed so the chip can verify each presented
    /// certificate incrementally as it imports keys during Terminal Authentication (PSO:Verify Certificate).
    /// </summary>
    /// <param name="issuer">The certificate (or trust anchor) whose public key signed <paramref name="certificate"/>.</param>
    /// <param name="certificate">The certificate to verify.</param>
    /// <param name="referenceDate">The date validity is checked against.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see cref="CvcChainVerificationResult.Valid"/> when the certificate verifies; otherwise the failure.</returns>
    internal static async ValueTask<CvcChainVerificationResult> VerifyOneAsync(
        CardVerifiableCertificate issuer,
        CardVerifiableCertificate certificate,
        DateOnly referenceDate,
        CancellationToken cancellationToken)
    {
        if(!string.Equals(certificate.CertificationAuthorityReference, issuer.CertificateHolderReference, StringComparison.Ordinal))
        {
            return CvcChainVerificationResult.BrokenChain;
        }

        if(!CanIssue(issuer.Chat.Role, certificate.Chat.Role))
        {
            return CvcChainVerificationResult.InvalidRole;
        }

        if(certificate.ExpirationDate < certificate.EffectiveDate)
        {
            return CvcChainVerificationResult.MalformedValidity;
        }

        if(referenceDate < certificate.EffectiveDate)
        {
            return CvcChainVerificationResult.NotYetValid;
        }

        if(referenceDate > certificate.ExpirationDate)
        {
            return CvcChainVerificationResult.Expired;
        }

        if(issuer.PublicKey.IsEllipticCurve)
        {
            return await VerifyEllipticCurveSignatureAsync(certificate, issuer.PublicKey, cancellationToken: cancellationToken).ConfigureAwait(false)
                ? CvcChainVerificationResult.Valid
                : CvcChainVerificationResult.InvalidSignature;
        }

        if(CardVerifiableCertificatePublicKey.ResolveRsaAlgorithm(issuer.PublicKey.SignatureScheme) is null)
        {
            //An RSA issuer whose scheme this verification does not support — the SHA-1 id-TA-RSA schemes TR-03110 retires.
            return CvcChainVerificationResult.UnsupportedIssuerKey;
        }

        return await VerifyRsaSignatureAsync(certificate, issuer.PublicKey, cancellationToken: cancellationToken).ConfigureAwait(false)
            ? CvcChainVerificationResult.Valid
            : CvcChainVerificationResult.InvalidSignature;
    }


    /// <summary>
    /// Verifies a certificate's signature over its encoded body against an elliptic-curve issuer key, using
    /// the registered verification function for the issuer's curve (which fixes the hash and accepts the
    /// plain <c>r || s</c> signature).
    /// </summary>
    private static async ValueTask<bool> VerifyEllipticCurveSignatureAsync(
        CardVerifiableCertificate certificate,
        CardVerifiableCertificatePublicKey issuerKey,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        if(!issuerKey.EllipticCurvePoint!.Tag.TryGet(out CryptoAlgorithm algorithm))
        {
            return false;
        }

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification);

        try
        {
            //Resolves and invokes the registry delegate directly rather than through PublicKey.VerifyAsync (there
            //is no bound PublicKey here, only the certificate's raw elliptic-curve point), so the
            //VerificationCompletedEvent forwards through the explicit sink seam instead.
            (bool isVerified, CryptoEvent? evt) = await verify(
                certificate.ToBeSigned,
                certificate.Signature.AsReadOnlyMemory(),
                issuerKey.EllipticCurvePoint!.AsReadOnlyMemory(),
                null,
                cancellationToken).ConfigureAwait(false);

            if(evt is not null)
            {
                (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
            }

            return isVerified;
        }
        catch(Exception exception) when(exception is ArgumentException or FormatException or InvalidOperationException or System.Security.Cryptography.CryptographicException)
        {
            //A malformed issuer public key — a point off the curve or one sized for a different curve than its tag
            //names — makes the registered verification function throw rather than report a failed signature. Chain
            //verification is fail-closed: an issuer key that cannot verify a signature stops the walk as if the
            //signature were invalid, never as an uncaught exception out of the chain walk. No event is emitted:
            //verification never actually ran against a key.
            return false;
        }
    }


    /// <summary>
    /// Verifies a certificate's signature over its encoded body against an RSA issuer key, using the registered
    /// verification function for the issuer's <c>id-TA-RSA</c> scheme (which fixes the padding and hash). The
    /// signature algorithm of a certificate is the one the issuer's public-key object identifier names
    /// (TR-03110-3 §C.1.8), so the scheme is taken from the issuer key, not the certificate's own.
    /// </summary>
    private static async ValueTask<bool> VerifyRsaSignatureAsync(
        CardVerifiableCertificate certificate,
        CardVerifiableCertificatePublicKey issuerKey,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        if(CardVerifiableCertificatePublicKey.ResolveRsaAlgorithm(issuerKey.SignatureScheme) is not CryptoAlgorithm algorithm)
        {
            return false;
        }

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification);

        try
        {
            //Forwards the VerificationCompletedEvent through the explicit sink seam for the same reason as the
            //elliptic-curve overload above.
            (bool isVerified, CryptoEvent? evt) = await verify(
                certificate.ToBeSigned,
                certificate.Signature.AsReadOnlyMemory(),
                issuerKey.RsaKey!.AsReadOnlyMemory(),
                null,
                cancellationToken).ConfigureAwait(false);

            if(evt is not null)
            {
                (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
            }

            return isVerified;
        }
        catch(Exception exception) when(exception is ArgumentException or FormatException or InvalidOperationException or System.Security.Cryptography.CryptographicException)
        {
            //A malformed issuer public key makes the registered verification function throw rather than report a
            //failed signature. Chain verification is fail-closed: an unusable issuer key stops the walk as if the
            //signature were invalid, never as an uncaught exception out of the chain walk. No event is emitted:
            //verification never actually ran against a key.
            return false;
        }
    }


    /// <summary>
    /// Whether a certificate of the issuer's role may issue a certificate of the candidate role: a CVCA
    /// issues Document Verifier certificates, a Document Verifier issues terminal certificates.
    /// </summary>
    private static bool CanIssue(CertificateRole issuerRole, CertificateRole subjectRole) => issuerRole switch
    {
        CertificateRole.CertificationAuthority =>
            subjectRole is CertificateRole.DocumentVerifierOfficialDomestic or CertificateRole.DocumentVerifierNonOfficialOrForeign,
        CertificateRole.DocumentVerifierOfficialDomestic or CertificateRole.DocumentVerifierNonOfficialOrForeign =>
            subjectRole == CertificateRole.Terminal,
        _ => false
    };
}


/// <summary>
/// The outcome of verifying a card-verifiable certificate chain. <see cref="Valid"/> is the only success;
/// every other value is the first failure that stopped the walk.
/// </summary>
public enum CvcChainVerificationResult
{
    /// <summary>The whole chain verified.</summary>
    Valid,

    /// <summary>No certificates were presented under the trust anchor.</summary>
    EmptyChain,

    /// <summary>The supplied trust anchor is not a CVCA certificate.</summary>
    TrustAnchorNotCertificationAuthority,

    /// <summary>A certificate's Certification Authority Reference does not match the issuer's Certificate Holder Reference.</summary>
    BrokenChain,

    /// <summary>A certificate's role is not one the issuer is permitted to issue.</summary>
    InvalidRole,

    /// <summary>A certificate's expiration date precedes its effective date.</summary>
    MalformedValidity,

    /// <summary>A certificate's effective date is after the reference date.</summary>
    NotYetValid,

    /// <summary>A certificate's expiration date is before the reference date.</summary>
    Expired,

    /// <summary>A certificate's signature does not verify against the issuer's public key.</summary>
    InvalidSignature,

    /// <summary>An issuer's public key uses a signature scheme chain verification does not support — a retired SHA-1 <c>id-TA-RSA</c> scheme.</summary>
    UnsupportedIssuerKey,

    /// <summary>Every link verified but the chain does not end in a terminal certificate, so no Terminal-Authentication key was presented.</summary>
    ChainNotTerminatedByTerminal
}
