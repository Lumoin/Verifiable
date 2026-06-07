using Verifiable.Cryptography;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Enumerates the reasons IACA trust resolution can fail. Used by
/// <see cref="MdocIacaTrustResolution.FailureReason"/>.
/// </summary>
public enum MdocIacaTrustFailureReason
{
    /// <summary>No failure; the chain validated and produced a trusted issuer key.</summary>
    None = 0,

    /// <summary>
    /// The IssuerAuth COSE_Sign1 has no <c>x5chain</c> (label 33) entry in
    /// its unprotected header. ISO/IEC 18013-5 §9.1.2.4 requires it.
    /// </summary>
    X5ChainHeaderMissing,

    /// <summary>
    /// The <c>x5chain</c> entry's CBOR shape is neither a bstr (one cert)
    /// nor an array of bstrs (multiple certs) per RFC 9360 §2.
    /// </summary>
    X5ChainMalformed,

    /// <summary>
    /// Chain validation by the configured
    /// <see cref="Verifiable.Cryptography.Pki.ValidateCertificateChainAsyncDelegate"/>
    /// failed — signature chain didn't reach a trusted root, validity
    /// period violations, or other PKI-layer rejections.
    /// </summary>
    ChainValidationFailed,

    /// <summary>
    /// The leaf certificate's public-key algorithm is not one the
    /// validator's <see cref="Verifiable.Cryptography.Pki.ValidateCertificateChainAsyncDelegate"/>
    /// supports for extraction (e.g. an EC curve outside the supported
    /// set, or a key type the validator doesn't recognise).
    /// </summary>
    LeafKeyExtractionFailed
}


/// <summary>
/// Result of IACA trust resolution on an <see cref="MdocIssuerAuth"/>.
/// Carries either the trusted leaf public key (on success) or the failure
/// reason (on failure), in the same shape as
/// <see cref="MdocDigestBindingResult"/>.
/// </summary>
/// <remarks>
/// <para>
/// On success, <see cref="IssuerVerificationKey"/> is non-null and the
/// caller owns it — disposing the resolution disposes the key.
/// </para>
/// </remarks>
public sealed class MdocIacaTrustResolution: IDisposable
{
    private bool disposed;


    private MdocIacaTrustResolution(
        PublicKeyMemory? issuerVerificationKey,
        MdocIacaTrustFailureReason failureReason,
        string? failureMessage)
    {
        IssuerVerificationKey = issuerVerificationKey;
        FailureReason = failureReason;
        FailureMessage = failureMessage;
    }


    /// <summary>
    /// Whether trust resolution succeeded. When <see langword="true"/>,
    /// <see cref="IssuerVerificationKey"/> is non-null.
    /// </summary>
    public bool IsTrusted => FailureReason == MdocIacaTrustFailureReason.None;

    /// <summary>
    /// The leaf certificate's public key, ready to pass to
    /// <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuerAuthVerifier"/>.
    /// Non-null when <see cref="IsTrusted"/> is <see langword="true"/>;
    /// null otherwise.
    /// </summary>
    public PublicKeyMemory? IssuerVerificationKey { get; }

    /// <summary>The failure reason; <see cref="MdocIacaTrustFailureReason.None"/> on success.</summary>
    public MdocIacaTrustFailureReason FailureReason { get; }

    /// <summary>
    /// Optional diagnostic message — typically the inner exception's text
    /// from the chain-validator. Always present when <see cref="IsTrusted"/>
    /// is <see langword="false"/>.
    /// </summary>
    public string? FailureMessage { get; }


    /// <summary>Creates a successful resolution with the supplied issuer key.</summary>
    /// <remarks>Caller transfers ownership of <paramref name="issuerVerificationKey"/> to the resolution.</remarks>
    public static MdocIacaTrustResolution Success(PublicKeyMemory issuerVerificationKey)
    {
        ArgumentNullException.ThrowIfNull(issuerVerificationKey);

        return new(issuerVerificationKey, MdocIacaTrustFailureReason.None, failureMessage: null);
    }


    /// <summary>Creates a failed resolution.</summary>
    public static MdocIacaTrustResolution Failed(
        MdocIacaTrustFailureReason reason,
        string? message = null)
    {
        if(reason == MdocIacaTrustFailureReason.None)
        {
            throw new ArgumentException(
                "Failed resolution must carry a non-None reason.", nameof(reason));
        }

        return new(issuerVerificationKey: null, reason, message);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        IssuerVerificationKey?.Dispose();
        disposed = true;
    }
}


/// <summary>
/// Resolves the leaf public key of an <see cref="MdocIssuerAuth"/>'s
/// <c>x5chain</c> against a trust root, returning a trusted
/// <see cref="MdocIacaTrustResolution"/>.
/// </summary>
/// <remarks>
/// <para>
/// The trust delegate is the wallet/verifier extension point that pulls
/// the IACA trust list, signature-checks the chain, and produces the
/// public key the COSE_Sign1 verifier will use. Production callers bind
/// it to their trust-list source (EUDI national IACA list, etc.); tests
/// bind it to a small in-process trust anchor.
/// </para>
/// </remarks>
/// <param name="issuerAuth">The parsed IssuerAuth to resolve.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// An <see cref="MdocIacaTrustResolution"/> describing the outcome.
/// Ownership transfers to the caller; dispose to release the resolved
/// public-key memory.
/// </returns>
public delegate ValueTask<MdocIacaTrustResolution> ResolveMdocIssuerKeyDelegate(
    MdocIssuerAuth issuerAuth,
    CancellationToken cancellationToken);
