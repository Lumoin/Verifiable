using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the cryptographic verification building block concluded — the outputs of Table 15 of clause 5.2.7.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
[DebuggerDisplay("CryptographicVerificationResult: {Conclusion.Indication}, {Outcome}")]
public sealed record CryptographicVerificationResult
{
    /// <summary>The block's conclusion.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>The format binding's own outcome, which the conclusion maps onto Table 15's rows.</summary>
    public required SignatureCryptographicOutcome Outcome { get; init; }
}


/// <summary>
/// The cryptographic verification building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2.7</see>: it checks the integrity of the signed data by performing the
/// cryptographic verifications.
/// </summary>
/// <remarks>
/// <para>
/// Clause 5.2.7.4 opens by stating that the first two steps and the Data To Be Signed "depend on the signature
/// type" and that the technical details are out of the clause's scope, which is exactly the boundary the
/// format-facts seam draws. This block therefore composes
/// <see cref="VerifySignatureCryptographyAsyncDelegate"/> — the binding that knows the format's own encoding —
/// and maps its outcome onto Table 15's indications and the report data those rows name. Every digest the
/// binding takes goes through the registered digest seam, never a framework hash.
/// </para>
/// <para>
/// A binding that throws instead of reporting is treated as having verified nothing: the signature is
/// attacker-reachable input, and clause 5.2.7.3 defines an indication for every way the checks can fail.
/// </para>
/// </remarks>
public static class CryptographicVerification
{
    /// <summary>
    /// Runs the cryptographic verifications over one signature.
    /// </summary>
    /// <param name="signature">Table 14's mandatory "Signature" input, in the form the engine holds it.</param>
    /// <param name="signingCertificate">Table 14's mandatory "Signing Certificate" input, as the identification building block settled it.</param>
    /// <param name="validatedCertificateChain">Table 14's optional "Validated certificate chain" input; empty when no chain was validated.</param>
    /// <param name="signerDocuments">Table 14's optional "Signer's Document or Signer's Document Representation" input; empty when the signature encapsulates its content.</param>
    /// <param name="verifySignatureCryptography">The format binding's cryptographic verification — <see cref="SignatureFormatSeam.VerifyCryptography"/>.</param>
    /// <param name="pool">The memory pool the binding rents its scratch buffers from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of Table 15, together with the binding's own outcome.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<CryptographicVerificationResult> VerifyAsync(
        SignatureFacts signature,
        PkiCertificateMemory signingCertificate,
        IReadOnlyList<PkiCertificateMemory> validatedCertificateChain,
        IReadOnlyList<SignerDocumentReference> signerDocuments,
        VerifySignatureCryptographyAsyncDelegate verifySignatureCryptography,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(validatedCertificateChain);
        ArgumentNullException.ThrowIfNull(signerDocuments);
        ArgumentNullException.ThrowIfNull(verifySignatureCryptography);
        ArgumentNullException.ThrowIfNull(pool);

        SignatureCryptographicVerification verification;
        try
        {
            verification = await verifySignatureCryptography(
                new SignatureCryptographicVerificationContext
                {
                    Signature = signature,
                    SigningCertificate = signingCertificate,
                    ValidatedCertificateChain = validatedCertificateChain,
                    SignerDocuments = signerDocuments
                },
                pool,
                cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            verification = new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.NotVerified,
                Reason = exception.Message
            };
        }

        BuildingBlockConclusion conclusion = verification.Outcome switch
        {
            SignatureCryptographicOutcome.Verified => BuildingBlockConclusion.Passed,
            SignatureCryptographicOutcome.HashFailure => BuildingBlockConclusion.Failed(
                SignatureValidationSubIndication.HashFailure,
                [new HashFailureReportData(verification.FailingObjectIdentifiers)]),
            SignatureCryptographicOutcome.SignatureValueFailure => BuildingBlockConclusion.Failed(
                SignatureValidationSubIndication.SignatureCryptographicFailure,
                [new SigningCertificateReportData(signingCertificate)]),
            SignatureCryptographicOutcome.SignedDataNotFound => BuildingBlockConclusion.Indeterminate(
                SignatureValidationSubIndication.SignedDataNotFound,
                [new SignedDataNotFoundReportData(verification.FailingObjectIdentifiers)]),
            _ => BuildingBlockConclusion.Indeterminate(
                SignatureValidationSubIndication.Custom,
                [new CustomDiagnosticReportData(verification.Reason ?? "The format binding performed no cryptographic verification.")])
        };

        return new CryptographicVerificationResult { Conclusion = conclusion, Outcome = verification.Outcome };
    }
}
