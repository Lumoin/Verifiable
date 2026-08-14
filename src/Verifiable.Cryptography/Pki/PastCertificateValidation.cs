using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the past certificate validation building block concluded — the outputs of Table 22 of clause 5.6.2.1.3
/// of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>: <c>PASSED</c> with a validation time and a certificate chain, or
/// <c>INDETERMINATE</c> with one of <c>NO_CERTIFICATE_CHAIN_FOUND</c>, <c>NO_POE</c>,
/// <c>CERTIFICATE_CHAIN_GENERAL_FAILURE</c> or <c>CHAIN_CONSTRAINTS_FAILURE</c>.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier this record references belongs to the
/// <see cref="SignatureValidationResources"/> of the run that produced it.
/// </remarks>
[DebuggerDisplay("PastCertificateValidationResult: {Conclusion.Indication}, validation time {ValidationTime}")]
public sealed record PastCertificateValidationResult
{
    /// <summary>The block's conclusion.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>The calculated validation time the validation time sliding process returned in step 3), which the block returns on <c>PASSED</c>; <see langword="null"/> otherwise.</summary>
    public DateTimeOffset? ValidationTime { get; init; }

    /// <summary>The certificate chain the block built, which it returns on <c>PASSED</c> and reports as the last chain built otherwise.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; init; } = [];
}


/// <summary>
/// The past certificate validation building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.6.2.1</see>: it validates a certificate at a date/time which can be in the
/// past, and returns the last value of validation time associated with the target certificate.
/// </summary>
/// <remarks>
/// <para>
/// Clause 5.6.2.1.1 states the rationale: a chain that was usable to validate a certificate at some date in the
/// past can be used at the current time to derive the same validity status, provided each certificate's
/// revocation status can be ascertained either now or from "old" revocation status information proven to have
/// existed while its issuer was still under control of its signing key. The second condition is what the
/// validation time sliding process of clause 5.6.2.2 establishes, which step 3) composes.
/// </para>
/// <para>
/// <strong>One prospective chain per call.</strong> Steps 2)b), 3) and 4) each end in "go to step 1)", which
/// asks for the next prospective chain that has not yet been evaluated. The chain completion seam yields one
/// chain, so those transitions reduce to step 1)a)'s own instruction — return the current status and the last
/// chain built — which is what this block returns. This is the same reading the X.509 certificate validation
/// building block of clause 5.2.6 documents.
/// </para>
/// </remarks>
public static class PastCertificateValidation
{
    /// <summary>
    /// Validates one certificate at a date/time which can be in the past.
    /// </summary>
    /// <param name="targetCertificate">Table 21's mandatory "Target certificate" input.</param>
    /// <param name="x509Constraints">Table 21's "X.509 Validation Parameters including set of trust anchors" and "X.509 Validation Constraints" inputs.</param>
    /// <param name="proofsOfExistence">Table 21's mandatory "A set of POEs" input.</param>
    /// <param name="certificateValidationData">Table 21's mandatory "Certificate Validation Data" input, as the certificates the chain may be built from.</param>
    /// <param name="revocationStatusInformation">Table 21's "Certificate Validation Data" input, as revocation status information about the chain's certificates.</param>
    /// <param name="cryptographicConstraints">Table 21's optional "Cryptographic Constraints" input.</param>
    /// <param name="seams">The chain building and path validation seams steps 1) and 2) compose.</param>
    /// <param name="currentTime">The current date/time, which step 1)b) of clause 5.6.2.2.4 initializes control-time to.</param>
    /// <param name="resources">The ledger the carriers this call creates are tracked in.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of Table 22, and on <c>PASSED</c> the chain and the calculated validation time.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<PastCertificateValidationResult> ValidateAsync(
        PkiCertificateMemory targetCertificate,
        X509ValidationConstraints x509Constraints,
        ProofOfExistenceSet proofsOfExistence,
        IReadOnlyList<PkiCertificateMemory> certificateValidationData,
        IReadOnlyList<RevocationStatusInformation> revocationStatusInformation,
        CryptographicConstraints cryptographicConstraints,
        SignatureValidationSeams seams,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targetCertificate);
        ArgumentNullException.ThrowIfNull(x509Constraints);
        ArgumentNullException.ThrowIfNull(proofsOfExistence);
        ArgumentNullException.ThrowIfNull(certificateValidationData);
        ArgumentNullException.ThrowIfNull(revocationStatusInformation);
        ArgumentNullException.ThrowIfNull(cryptographicConstraints);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(pool);

        List<PkiCertificateMemory> trustAnchors = [];
        for(int i = 0; i < x509Constraints.TrustAnchors.Count; ++i)
        {
            trustAnchors.Add(x509Constraints.TrustAnchors[i].Anchor);
        }

        //Step 1): build a prospective certificate chain that has not yet been evaluated. Table 21 makes the
        //certificate validation data a mandatory input, and it is the material the chain is built from: the
        //issuer links are followed through it exactly as step 2) of clause 5.2.6.4 follows them through its
        //"Other Certificates" input, and the completion seam is then asked to reach a trust anchor from there.
        IReadOnlyList<PkiCertificateMemory> partialChain =
            X509CertificateValidation.BuildPartialChain(targetCertificate, certificateValidationData, trustAnchors);
        IReadOnlyList<PkiCertificateMemory> chain;
        try
        {
            chain = await seams.CompleteCertificateChain(
                partialChain, trustAnchors, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            //Step 1)a): no chain could be built at all.
            return new PastCertificateValidationResult
            {
                Conclusion = BuildingBlockConclusion.Indeterminate(SignatureValidationSubIndication.NoCertificateChainFound, [])
            };
        }

        for(int i = 0; i < chain.Count; ++i)
        {
            if(!ContainsReference(partialChain, chain[i]))
            {
                //A certificate the completion seam newly acquired belongs to the run from here on; one that was
                //supplied to it belongs to the caller and is not tracked twice.
                resources.Track(chain[i]);
            }
        }

        //Step 2): certification path validation of RFC 5280 clause 6.1, at a date the validity model chooses,
        //without revocation checking and without the trust anchor sunset check.
        if(SelectPathValidationTime(chain, targetCertificate, x509Constraints.ValidityModel) is not DateTimeOffset pathValidationTime)
        {
            //The certificates state no interval the path could be validated in, which is the failure indication
            //step 2)b) sets the current status to.
            return ChainFailure(chain, "The certificates of the prospective chain state no common validity interval.");
        }

        try
        {
            using PublicKeyMemory _ = await seams.ValidateCertificateChain(
                chain, trustAnchors, pathValidationTime, pool, checkRevocation: null, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            //Step 2)b).
            return ChainFailure(chain, exception.Message);
        }

        //Step 3): the validation time sliding process, with the sunset date of the trust anchor the chain was
        //built from when the X.509 validation constraints specify one.
        ValidationTimeSlidingResult sliding = await ValidationTimeSliding.SlideAsync(
            chain,
            proofsOfExistence,
            revocationStatusInformation,
            SelectTrustAnchorSunsetDate(chain, x509Constraints),
            cryptographicConstraints,
            x509Constraints,
            currentTime,
            resources,
            pool,
            cancellationToken).ConfigureAwait(false);
        if(sliding.Conclusion.Indication != BuildingBlockIndication.Passed || sliding.ControlTime is not DateTimeOffset controlTime)
        {
            return new PastCertificateValidationResult
            {
                Conclusion = sliding.Conclusion,
                CertificateChain = chain
            };
        }

        //Step 4): the X.509 validation constraints are applied to the chain.
        IReadOnlyList<ValidationConstraintEvaluation> unsatisfied =
            X509CertificateValidation.ApplyCertificateMetadataConstraints(chain, x509Constraints);
        if(unsatisfied.Count > 0)
        {
            return new PastCertificateValidationResult
            {
                Conclusion = BuildingBlockConclusion.Indeterminate(
                    SignatureValidationSubIndication.ChainConstraintsFailure,
                    [new ChainConstraintsFailureReportData(chain, unsatisfied)]),
                CertificateChain = chain
            };
        }

        //Step 5).
        return new PastCertificateValidationResult
        {
            Conclusion = BuildingBlockConclusion.PassedWith([new CertificateChainReportData(chain, CertificateChainReportKind.Validated)]),
            ValidationTime = controlTime,
            CertificateChain = chain
        };
    }


    /// <summary>
    /// Reports whether a list holds the very same carrier instance, which is how a certificate the chain
    /// completion seam newly acquired is told apart from one that was supplied to it.
    /// </summary>
    /// <param name="certificates">The list to search.</param>
    /// <param name="certificate">The carrier to look for.</param>
    /// <returns><see langword="true"/> when the list holds that instance.</returns>
    private static bool ContainsReference(IReadOnlyList<PkiCertificateMemory> certificates, PkiCertificateMemory certificate)
    {
        for(int i = 0; i < certificates.Count; ++i)
        {
            if(ReferenceEquals(certificates[i], certificate))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Chooses the date step 2) runs the certification path validation at: under the shell model "a date from the
    /// intersection of the validity intervals of all the certificates in the prospective certificate chain", and
    /// under the chain model "a date from the validity of the signer's certificate".
    /// </summary>
    /// <param name="chain">The prospective chain.</param>
    /// <param name="targetCertificate">The signer's certificate.</param>
    /// <param name="validityModel">The validity model the validation policy requires.</param>
    /// <returns>The date, or <see langword="null"/> when the intersection is empty or the certificates do not parse.</returns>
    /// <remarks>
    /// The latest <c>notBefore</c> of the interval is chosen, which lies in the intersection whenever the
    /// intersection is non-empty and is the least surprising point in it: it is the first instant at which every
    /// certificate of the chain had come into force.
    /// </remarks>
    private static DateTimeOffset? SelectPathValidationTime(
        IReadOnlyList<PkiCertificateMemory> chain,
        PkiCertificateMemory targetCertificate,
        CertificateValidityModel validityModel)
    {
        if(validityModel == CertificateValidityModel.Chain)
        {
            return TryReadNotBefore(targetCertificate);
        }

        DateTimeOffset? latestNotBefore = null;
        DateTimeOffset? earliestNotAfter = null;
        for(int i = 0; i < chain.Count; ++i)
        {
            ManagedCertificate parsed;
            try
            {
                parsed = ManagedCertificate.Parse(chain[i].AsReadOnlyMemory());
            }
            catch(AsnContentException)
            {
                return null;
            }

            if(latestNotBefore is null || parsed.NotBefore > latestNotBefore)
            {
                latestNotBefore = parsed.NotBefore;
            }

            if(earliestNotAfter is null || parsed.NotAfter < earliestNotAfter)
            {
                earliestNotAfter = parsed.NotAfter;
            }
        }

        return latestNotBefore is DateTimeOffset notBefore && earliestNotAfter is DateTimeOffset notAfter && notBefore <= notAfter
            ? notBefore
            : null;
    }


    /// <summary>
    /// Reads the <c>notBefore</c> date of a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to read.</param>
    /// <returns>The issuance date, or <see langword="null"/> when the certificate does not parse.</returns>
    private static DateTimeOffset? TryReadNotBefore(PkiCertificateMemory certificate)
    {
        try
        {
            return ManagedCertificate.Parse(certificate.AsReadOnlyMemory()).NotBefore;
        }
        catch(AsnContentException)
        {
            return null;
        }
    }


    /// <summary>
    /// States the sunset date of the trust anchor the chain was built from, which step 3) passes to the
    /// validation time sliding process.
    /// </summary>
    /// <param name="chain">The prospective chain.</param>
    /// <param name="x509Constraints">The constraints naming the trust anchors and their sunset dates.</param>
    /// <returns>The sunset date, or <see langword="null"/> when the constraints specify none for that anchor.</returns>
    private static DateTimeOffset? SelectTrustAnchorSunsetDate(
        IReadOnlyList<PkiCertificateMemory> chain,
        X509ValidationConstraints x509Constraints)
    {
        for(int i = chain.Count - 1; i >= 0; --i)
        {
            if(x509Constraints.TryGetTrustAnchorSunsetDate(chain[i], out DateTimeOffset? sunsetDate) && sunsetDate is not null)
            {
                return sunsetDate;
            }
        }

        return null;
    }


    /// <summary>
    /// Builds the <c>CERTIFICATE_CHAIN_GENERAL_FAILURE</c> outcome step 2)b) sets the current status to.
    /// </summary>
    /// <param name="chain">The last chain built.</param>
    /// <param name="reason">What the path validation could state about the failure.</param>
    /// <returns>The result.</returns>
    private static PastCertificateValidationResult ChainFailure(IReadOnlyList<PkiCertificateMemory> chain, string reason) => new()
    {
        Conclusion = BuildingBlockConclusion.Indeterminate(
            SignatureValidationSubIndication.CertificateChainGeneralFailure,
            [new CertificateChainGeneralFailureReportData(chain, reason)]),
        CertificateChain = chain
    };
}
