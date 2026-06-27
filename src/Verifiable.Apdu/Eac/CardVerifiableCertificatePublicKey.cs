using System;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Eac;

/// <summary>
/// The public key carried in a card-verifiable certificate's body (<c>7F49</c>, BSI TR-03110-3 §D.3): the
/// key that verifies the signatures of certificates issued under this one (and, for an Inspection System or
/// Authentication Terminal certificate, the terminal's Terminal Authentication signing key). The key is
/// either elliptic-curve (ECDSA, an uncompressed SEC1 point) or RSA (a DER <c>RSAPublicKey</c>); the
/// <see cref="SignatureScheme"/> — read from the object identifier — fixes the algorithm and hash.
/// </summary>
/// <remarks>
/// <para>
/// A self-signed CVCA certificate carries the full domain parameters of its curve, so its
/// <see cref="IncludesDomainParameters"/> is <see langword="true"/> and the curve is resolved from the
/// encoded prime. A Document Verifier or terminal certificate omits the domain parameters (TR-03110-3
/// §D.3.3) — they are inherited from the CVCA public key — so its curve is supplied by the caller when the
/// certificate is parsed, and <see cref="IncludesDomainParameters"/> is <see langword="false"/>.
/// </para>
/// </remarks>
public sealed class CardVerifiableCertificatePublicKey: IDisposable
{
    private bool disposed;


    private CardVerifiableCertificatePublicKey(
        CvcSignatureScheme signatureScheme,
        bool includesDomainParameters,
        EncodedEcPoint? ellipticCurvePoint,
        RsaPublicKey? rsaPublicKey)
    {
        SignatureScheme = signatureScheme;
        IncludesDomainParameters = includesDomainParameters;
        EllipticCurvePoint = ellipticCurvePoint;
        RsaKey = rsaPublicKey;
    }


    /// <summary>Gets the signature scheme and hash this key signs and verifies with, as read from the public-key object identifier.</summary>
    public CvcSignatureScheme SignatureScheme { get; }

    /// <summary>Gets a value indicating whether the certificate carried the curve's domain parameters (a self-signed CVCA certificate) rather than inheriting them (a Document Verifier or terminal certificate).</summary>
    public bool IncludesDomainParameters { get; }

    /// <summary>Gets the elliptic-curve public point (SEC1 uncompressed, tagged with its curve), or <see langword="null"/> when the key is RSA. Owned by this instance.</summary>
    public EncodedEcPoint? EllipticCurvePoint { get; }

    /// <summary>Gets the RSA public key (DER <c>RSAPublicKey</c>: modulus and exponent), or <see langword="null"/> when the key is elliptic-curve. Owned by this instance.</summary>
    public RsaPublicKey? RsaKey { get; }

    /// <summary>Gets a value indicating whether this is an elliptic-curve (ECDSA) key.</summary>
    public bool IsEllipticCurve => EllipticCurvePoint is not null;


    /// <summary>
    /// Maps an <c>id-TA-RSA-*</c> signature scheme to the registered RSA <see cref="CryptoAlgorithm"/> carrying
    /// its padding and hash (PKCS#1 or PSS, SHA-256 or SHA-512), or <see langword="null"/> for a scheme that is
    /// not a supported RSA scheme — the SHA-1 schemes, which TR-03110 marks as not to be used, and every
    /// elliptic-curve scheme. Shared by the Terminal Authentication signature primitive (the terminal's
    /// possession proof) and the card-verifiable-certificate chain verification (an RSA issuer's signature).
    /// </summary>
    internal static CryptoAlgorithm? ResolveRsaAlgorithm(CvcSignatureScheme scheme) => scheme switch
    {
        CvcSignatureScheme.RsaPkcs1Sha256 => CryptoAlgorithm.RsaSha256,
        CvcSignatureScheme.RsaPssSha256 => CryptoAlgorithm.RsaSha256Pss,
        CvcSignatureScheme.RsaPkcs1Sha512 => CryptoAlgorithm.RsaSha512,
        CvcSignatureScheme.RsaPssSha512 => CryptoAlgorithm.RsaSha512Pss,
        _ => null
    };


    /// <summary>
    /// Creates an elliptic-curve public key, taking ownership of the point carrier.
    /// </summary>
    /// <param name="signatureScheme">The ECDSA scheme and hash read from the object identifier.</param>
    /// <param name="ellipticCurvePoint">The uncompressed SEC1 public point, tagged with its curve. Ownership transfers to this instance.</param>
    /// <param name="includesDomainParameters">Whether the certificate carried the curve's domain parameters.</param>
    internal static CardVerifiableCertificatePublicKey ForEllipticCurve(CvcSignatureScheme signatureScheme, EncodedEcPoint ellipticCurvePoint, bool includesDomainParameters)
    {
        ArgumentNullException.ThrowIfNull(ellipticCurvePoint);

        return new CardVerifiableCertificatePublicKey(signatureScheme, includesDomainParameters, ellipticCurvePoint, null);
    }


    /// <summary>
    /// Creates an RSA public key, taking ownership of the key carrier.
    /// </summary>
    /// <param name="signatureScheme">The RSA scheme and hash read from the object identifier.</param>
    /// <param name="rsaPublicKey">The DER <c>RSAPublicKey</c> (modulus and exponent). Ownership transfers to this instance.</param>
    internal static CardVerifiableCertificatePublicKey ForRsa(CvcSignatureScheme signatureScheme, RsaPublicKey rsaPublicKey)
    {
        ArgumentNullException.ThrowIfNull(rsaPublicKey);

        return new CardVerifiableCertificatePublicKey(signatureScheme, includesDomainParameters: false, null, rsaPublicKey);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            EllipticCurvePoint?.Dispose();
            RsaKey?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// The signature scheme and hash a card-verifiable certificate's public key uses, identified by the
/// public-key object identifier (BSI TR-03110-3 Tables 17 and 18: <c>id-TA-RSA-*</c> and
/// <c>id-TA-ECDSA-*</c>). The SHA-1 variants are listed because they appear in legacy test certificates;
/// TR-03110 marks them as not to be used.
/// </summary>
public enum CvcSignatureScheme
{
    /// <summary>ECDSA with SHA-1 (<c>id-TA-ECDSA-SHA-1</c>, deprecated).</summary>
    EcdsaSha1,

    /// <summary>ECDSA with SHA-224 (<c>id-TA-ECDSA-SHA-224</c>).</summary>
    EcdsaSha224,

    /// <summary>ECDSA with SHA-256 (<c>id-TA-ECDSA-SHA-256</c>).</summary>
    EcdsaSha256,

    /// <summary>ECDSA with SHA-384 (<c>id-TA-ECDSA-SHA-384</c>).</summary>
    EcdsaSha384,

    /// <summary>ECDSA with SHA-512 (<c>id-TA-ECDSA-SHA-512</c>).</summary>
    EcdsaSha512,

    /// <summary>RSASSA-PKCS1-v1_5 with SHA-1 (<c>id-TA-RSA-v1-5-SHA-1</c>, deprecated).</summary>
    RsaPkcs1Sha1,

    /// <summary>RSASSA-PKCS1-v1_5 with SHA-256 (<c>id-TA-RSA-v1-5-SHA-256</c>).</summary>
    RsaPkcs1Sha256,

    /// <summary>RSASSA-PKCS1-v1_5 with SHA-512 (<c>id-TA-RSA-v1-5-SHA-512</c>).</summary>
    RsaPkcs1Sha512,

    /// <summary>RSASSA-PSS with SHA-1 (<c>id-TA-RSA-PSS-SHA-1</c>, deprecated).</summary>
    RsaPssSha1,

    /// <summary>RSASSA-PSS with SHA-256 (<c>id-TA-RSA-PSS-SHA-256</c>).</summary>
    RsaPssSha256,

    /// <summary>RSASSA-PSS with SHA-512 (<c>id-TA-RSA-PSS-SHA-512</c>).</summary>
    RsaPssSha512
}
