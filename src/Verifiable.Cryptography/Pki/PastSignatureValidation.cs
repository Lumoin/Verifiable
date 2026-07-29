using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The inputs of Table 26 of clause 5.6.2.4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> that describe the signature (or time-stamp token) whose current-time
/// validation was indeterminate, plus the particulars of that indeterminate status the clause's step 3) branches
/// on.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns.
/// </remarks>
[DebuggerDisplay("PastSignatureValidationInputs: current status {CurrentTimeStatus.Indication}, best-signature-time {BestSignatureTime}")]
public sealed record PastSignatureValidationInputs
{
    /// <summary>The identity of the signature value, the object step 3) asks the set of proofs of existence about.</summary>
    public required ValidationObjectIdentity SignatureValueIdentity { get; init; }

    /// <summary>Table 26's mandatory "The current time status indication/sub-indication" input.</summary>
    public required BuildingBlockConclusion CurrentTimeStatus { get; init; }

    /// <summary>Table 26's mandatory "Target certificate" input — the signing certificate, or the Time-Stamping Authority's certificate when the signature under validation is a time-stamp token.</summary>
    public required PkiCertificateMemory TargetCertificate { get; init; }

    /// <summary>Table 26's mandatory "Best-signature-time" input.</summary>
    public required DateTimeOffset BestSignatureTime { get; init; }

    /// <summary>Table 26's mandatory "A set of POEs" input.</summary>
    public required ProofOfExistenceSet ProofsOfExistence { get; init; }

    /// <summary>Table 26's optional "Certificate Validation Data" input, as the certificates a chain may be built from.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateValidationData { get; init; } = [];

    /// <summary>Table 26's optional "Certificate Validation Data" input, as revocation status information about the chain's certificates.</summary>
    public IReadOnlyList<RevocationStatusInformation> RevocationStatusInformation { get; init; } = [];

    /// <summary>The revocation time of the CA certificate, which the <c>REVOKED_CA_NO_POE</c> branch of step 3) compares a proof of existence against; <see langword="null"/> when the current status is about no CA revocation.</summary>
    public DateTimeOffset? CertificationAuthorityRevocationTime { get; init; }

    /// <summary>Why the current-time validation reported <c>TRY_LATER</c>, which steps 3) and 5) branch on.</summary>
    public RevocationTryLaterReason TryLaterReason { get; init; }

    /// <summary>The instance of revocation status information the current-time status turns on, which step 5)b) hands back to the revocation freshness checker.</summary>
    public RevocationStatusInformation? DecisiveRevocationStatusInformation { get; init; }

    /// <summary>The algorithm assessments a <c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c> current-time status is about, which step 4) asks for proofs of existence about.</summary>
    public IReadOnlyList<AlgorithmReliabilityAssessment> UnreliableAlgorithms { get; init; } = [];
}


/// <summary>
/// What the past signature validation building block concluded — the output of clause 5.6.2.4.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>: "either the same as the current time indication/sub-indication given in the
/// inputs or one of the following: <c>PASSED</c> or <c>FAILED</c>/<c>NOT_YET_VALID</c>".
/// </summary>
[DebuggerDisplay("PastSignatureValidationResult: {Conclusion.Indication}")]
public sealed record PastSignatureValidationResult
{
    /// <summary>The block's conclusion.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>The calculated validation time the past certificate validation building block returned in step 2); <see langword="null"/> when that step did not pass.</summary>
    public DateTimeOffset? ValidationTime { get; init; }

    /// <summary>The certificate chain the past certificate validation building block built in step 2).</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; init; } = [];

    /// <summary>The revocation status information step 1)a) retained — the instances for which the set of proofs of existence holds a proof of the issuer's certificate within its own validity interval.</summary>
    public IReadOnlyList<RevocationStatusInformation> RetainedRevocationStatusInformation { get; init; } = [];
}


/// <summary>
/// The past signature validation building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.6.2.4</see>: it is "used when validation of a signature (or a time-stamp
/// token) fails at the current time with an <c>INDETERMINATE</c> status such that the provided proofs of
/// existence may help to go to a determined status".
/// </summary>
/// <remarks>
/// The block turns on the internal variable <c>sig_cert_revocation_poe-status</c> of step 1), which the NOTE
/// explains is kept internal so that a failure there does not lose the information the current-time status
/// carries. Step 7) returns it, and every branch of step 3) that reaches step 7) therefore reports either
/// <c>PASSED</c> or <c>INDETERMINATE</c>/<c>REVOCATION_OUT_OF_BOUNDS_NO_POE</c>.
/// </remarks>
public static class PastSignatureValidation
{
    /// <summary>
    /// Runs the past signature validation building block.
    /// </summary>
    /// <param name="inputs">The inputs of Table 26.</param>
    /// <param name="constraints">The X.509 and cryptographic constraints of Table 26's optional inputs.</param>
    /// <param name="seams">The chain building and path validation seams step 2) composes.</param>
    /// <param name="currentTime">The current date/time the validation time sliding process of step 2) initializes control-time to.</param>
    /// <param name="resources">The ledger the carriers this call creates are tracked in.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of clause 5.6.2.4.3.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<PastSignatureValidationResult> ValidateAsync(
        PastSignatureValidationInputs inputs,
        SignatureValidationConstraints constraints,
        SignatureValidationSeams seams,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(constraints);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(pool);

        //Step 1): there has to be at least one revocation data instance known to contain revocation status
        //information about the signing certificate for which the set of proofs of existence holds a proof of the
        //signing certificate issuer's certificate, at an instant after that certificate's issuance date and
        //before its expiration date. The certificate the clause names twice is the issuer of the target
        //certificate, which is not in general the issuer of the revocation data itself: the two coincide only in
        //the traditional revocation setting NOTE 5 of clause 5.6.2.2 describes, and a delegated responder
        //(IETF RFC 6960 §4.2.2.2) is the case where they differ.
        bool hasRevocationDataAboutTarget = false;
        for(int i = 0; i < inputs.RevocationStatusInformation.Count; ++i)
        {
            if(inputs.RevocationStatusInformation[i].SubjectCertificate.Equals(inputs.TargetCertificate))
            {
                hasRevocationDataAboutTarget = true;

                break;
            }
        }

        bool hasQualifyingRevocationData = hasRevocationDataAboutTarget
            && await HasTargetIssuerProofWithinValidityAsync(inputs, resources, pool, cancellationToken).ConfigureAwait(false);

        //The qualifying condition is about one certificate — the target certificate's issuer — so it holds for
        //every instance about the target certificate or for none. Step 1)a) therefore removes nothing from the
        //certificate validation data, and step 1)b) leaves it intact by its own words: it sets the internal
        //status and nothing else, so step 2) still sees the revocation data the sliding process of clause
        //5.6.2.2 step 2)a) needs.
        IReadOnlyList<RevocationStatusInformation> retained = inputs.RevocationStatusInformation;

        BuildingBlockConclusion signingCertificateRevocationProofStatus = hasQualifyingRevocationData
            ? BuildingBlockConclusion.Passed
            : BuildingBlockConclusion.Indeterminate(SignatureValidationSubIndication.RevocationOutOfBoundsNoProofOfExistence, []);

        //Step 2): past certificate validation with the retained certificate validation data.
        PastCertificateValidationResult pastCertificate = await PastCertificateValidation.ValidateAsync(
            inputs.TargetCertificate,
            constraints.X509,
            inputs.ProofsOfExistence,
            inputs.CertificateValidationData,
            retained,
            constraints.Cryptographic,
            seams,
            currentTime,
            resources,
            pool,
            cancellationToken).ConfigureAwait(false);
        if(pastCertificate.Conclusion.Indication != BuildingBlockIndication.Passed || pastCertificate.ValidationTime is not DateTimeOffset validationTime)
        {
            return new PastSignatureValidationResult
            {
                Conclusion = inputs.CurrentTimeStatus,
                CertificateChain = pastCertificate.CertificateChain,
                RetainedRevocationStatusInformation = retained
            };
        }

        var outcome = new PastSignatureValidationResult
        {
            Conclusion = inputs.CurrentTimeStatus,
            ValidationTime = validationTime,
            CertificateChain = pastCertificate.CertificateChain,
            RetainedRevocationStatusInformation = retained
        };

        SignatureValidationSubIndication currentSubIndication = inputs.CurrentTimeStatus.SubIndications.Count > 0
            ? inputs.CurrentTimeStatus.SubIndications[0]
            : SignatureValidationSubIndication.Custom;
        CertificateValidityWindow? window = TryReadValidityWindow(inputs.TargetCertificate);
        BuildingBlockConclusion currentStatus = inputs.CurrentTimeStatus;

        //Step 3): the branches the current time indication and sub-indication select, taken only when the
        //signature value is proven to have existed at or before the validation time step 2) returned.
        if(inputs.ProofsOfExistence.ExistsAtOrBefore(inputs.SignatureValueIdentity, validationTime))
        {
            if(currentSubIndication.Equals(SignatureValidationSubIndication.NoCertificateChainFoundNoProofOfExistence))
            {
                if(window is CertificateValidityWindow noChainWindow)
                {
                    if(inputs.BestSignatureTime < noChainWindow.NotBefore)
                    {
                        return outcome with { Conclusion = BuildingBlockConclusion.Failed(SignatureValidationSubIndication.NotYetValid, []) };
                    }

                    if(inputs.BestSignatureTime > noChainWindow.NotAfter)
                    {
                        return outcome with
                        {
                            Conclusion = BuildingBlockConclusion.Indeterminate(SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence, [])
                        };
                    }
                }

                return outcome with { Conclusion = signingCertificateRevocationProofStatus };
            }

            if(currentSubIndication.Equals(SignatureValidationSubIndication.RevokedNoProofOfExistence)
                || currentSubIndication.Equals(SignatureValidationSubIndication.RevocationOutOfBoundsNoProofOfExistence)
                || (currentSubIndication.Equals(SignatureValidationSubIndication.TryLater) && inputs.TryLaterReason == RevocationTryLaterReason.CertificateSuspended))
            {
                if(window is CertificateValidityWindow revokedWindow)
                {
                    if(inputs.BestSignatureTime < revokedWindow.NotBefore)
                    {
                        return outcome with { Conclusion = BuildingBlockConclusion.Failed(SignatureValidationSubIndication.NotYetValid, []) };
                    }

                    if(inputs.BestSignatureTime <= revokedWindow.NotAfter)
                    {
                        return outcome with { Conclusion = signingCertificateRevocationProofStatus };
                    }
                }

                //Step 3)c): the status becomes OUT_OF_BOUNDS_NOT_REVOKED and the process continues.
                currentStatus = BuildingBlockConclusion.Indeterminate(SignatureValidationSubIndication.OutOfBoundsNotRevoked, []);
                currentSubIndication = SignatureValidationSubIndication.OutOfBoundsNotRevoked;
            }
            else if(currentSubIndication.Equals(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence))
            {
                bool provenBeforeAuthorityRevocation = await HasRevocationDataProofAsync(
                    inputs, resources, pool, cancellationToken).ConfigureAwait(false);
                if(!provenBeforeAuthorityRevocation)
                {
                    return outcome with
                    {
                        Conclusion = BuildingBlockConclusion.Indeterminate(
                            SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence, inputs.CurrentTimeStatus.ReportData)
                    };
                }

                DateTimeOffset provenSignatureTime =
                    inputs.ProofsOfExistence.EarliestInstantFor(inputs.SignatureValueIdentity) ?? inputs.BestSignatureTime;
                if(window is CertificateValidityWindow authorityWindow
                    && provenSignatureTime >= authorityWindow.NotBefore
                    && provenSignatureTime <= authorityWindow.NotAfter)
                {
                    return outcome with { Conclusion = signingCertificateRevocationProofStatus };
                }

                currentStatus = BuildingBlockConclusion.Indeterminate(SignatureValidationSubIndication.OutOfBoundsNotRevoked, []);
                currentSubIndication = SignatureValidationSubIndication.OutOfBoundsNotRevoked;
            }

            if(currentSubIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence)
                || currentSubIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNotRevoked))
            {
                DateTimeOffset provenSignatureTime =
                    inputs.ProofsOfExistence.EarliestInstantFor(inputs.SignatureValueIdentity) ?? inputs.BestSignatureTime;
                if(window is CertificateValidityWindow boundsWindow)
                {
                    if(provenSignatureTime < boundsWindow.NotBefore)
                    {
                        return outcome with { Conclusion = BuildingBlockConclusion.Failed(SignatureValidationSubIndication.NotYetValid, []) };
                    }

                    if(provenSignatureTime <= boundsWindow.NotAfter)
                    {
                        return outcome with { Conclusion = signingCertificateRevocationProofStatus };
                    }
                }
            }
        }

        //Step 4): every algorithm concerned by a cryptographic constraints failure has a proof of existence for
        //its material at a time before the instant up to which that algorithm was considered secure.
        if(currentSubIndication.Equals(SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence)
            && HasProofsBeforeAlgorithmExpiry(inputs))
        {
            return outcome with { Conclusion = signingCertificateRevocationProofStatus };
        }

        //Step 5): a TRY_LATER caused by revocation status information that was not fresh enough is re-checked at
        //the earliest time the existence of the signature can be proven.
        if(currentSubIndication.Equals(SignatureValidationSubIndication.TryLater)
            && inputs.TryLaterReason == RevocationTryLaterReason.RevocationStatusNotFresh
            && inputs.DecisiveRevocationStatusInformation is RevocationStatusInformation notFresh)
        {
            DateTimeOffset provenSignatureTime =
                inputs.ProofsOfExistence.EarliestInstantFor(inputs.SignatureValueIdentity) ?? inputs.BestSignatureTime;
            RevocationFreshnessResult freshness = await RevocationFreshnessChecker.CheckAsync(
                notFresh, inputs.TargetCertificate, provenSignatureTime, constraints.X509, cancellationToken).ConfigureAwait(false);

            return freshness.Conclusion.Indication == BuildingBlockIndication.Passed
                ? outcome with { Conclusion = signingCertificateRevocationProofStatus }
                : outcome with
                {
                    Conclusion = BuildingBlockConclusion.Indeterminate(
                        SignatureValidationSubIndication.TryLater,
                        [new TryLaterReportData(notFresh.NextUpdate, pastCertificate.CertificateChain, [notFresh.RevocationData])])
                };
        }

        //Step 6): in all other cases the current time status stands.
        return outcome with { Conclusion = currentStatus };
    }


    /// <summary>
    /// Decides whether the set of proofs of existence holds a proof for the certificate of the issuer of the
    /// target certificate at an instant after that certificate's issuance date and before its expiration date —
    /// the condition step 1) of clause 5.6.2.4.4 qualifies revocation data by.
    /// </summary>
    /// <param name="inputs">The block's inputs.</param>
    /// <param name="resources">The ledger the computed identity is tracked in.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when such a proof is present.</returns>
    /// <remarks>
    /// A target certificate whose issuer's certificate is not among the certificate validation data and is not
    /// identified by any instance of revocation status information qualifies for nothing: no proof can be asked
    /// about a certificate that is not in hand.
    /// </remarks>
    private static async ValueTask<bool> HasTargetIssuerProofWithinValidityAsync(
        PastSignatureValidationInputs inputs,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(FindIssuerCertificate(inputs) is not PkiCertificateMemory issuer)
        {
            return false;
        }

        if(TryReadValidityWindow(issuer) is not CertificateValidityWindow window)
        {
            return false;
        }

        ValidationObjectIdentity issuerIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            issuer.AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ProofOfExistence> proofs = inputs.ProofsOfExistence.For(issuerIdentity);
        for(int i = 0; i < proofs.Count; ++i)
        {
            if(proofs[i].Scope == ProofOfExistenceScope.Object
                && proofs[i].Instant >= window.NotBefore
                && proofs[i].Instant <= window.NotAfter)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Finds the certificate of the issuer of the target certificate among the material the block was given: the
    /// certificate validation data first, then the issuer certificates the instances of revocation status
    /// information identify.
    /// </summary>
    /// <param name="inputs">The block's inputs.</param>
    /// <returns>The issuer's certificate, or <see langword="null"/> when it is not among that material.</returns>
    private static PkiCertificateMemory? FindIssuerCertificate(PastSignatureValidationInputs inputs)
    {
        ManagedCertificate target;
        try
        {
            target = ManagedCertificate.Parse(inputs.TargetCertificate.AsReadOnlyMemory());
        }
        catch(AsnContentException)
        {
            //A target certificate that does not parse names no issuer this block can look for.
            return null;
        }

        for(int i = 0; i < inputs.CertificateValidationData.Count; ++i)
        {
            if(IsIssuerOf(inputs.CertificateValidationData[i], target))
            {
                return inputs.CertificateValidationData[i];
            }
        }

        for(int i = 0; i < inputs.RevocationStatusInformation.Count; ++i)
        {
            if(inputs.RevocationStatusInformation[i].IssuerCertificate is PkiCertificateMemory candidate && IsIssuerOf(candidate, target))
            {
                return candidate;
            }
        }

        return null;

        //Decides whether a candidate certificate's subject is the issuer named by the target certificate.
        static bool IsIssuerOf(PkiCertificateMemory candidate, ManagedCertificate target)
        {
            try
            {
                return ManagedCertificate.Parse(candidate.AsReadOnlyMemory()).SubjectDer.Span.SequenceEqual(target.IssuerDer.Span);
            }
            catch(AsnContentException)
            {
                //A candidate that does not parse cannot be shown to be the issuer.
                return false;
            }
        }
    }


    /// <summary>
    /// Decides whether there is a proof of existence for the revocation data carrying the revocation status
    /// information of the signer's certificate at or before the revocation time of the CA certificate — the
    /// condition step 3)a) of the <c>REVOKED_CA_NO_POE</c> branch turns on.
    /// </summary>
    /// <param name="inputs">The block's inputs.</param>
    /// <param name="resources">The ledger the computed identities are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when such a proof is present.</returns>
    private static async ValueTask<bool> HasRevocationDataProofAsync(
        PastSignatureValidationInputs inputs,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(inputs.CertificationAuthorityRevocationTime is not DateTimeOffset authorityRevocationTime)
        {
            return false;
        }

        for(int i = 0; i < inputs.RevocationStatusInformation.Count; ++i)
        {
            RevocationStatusInformation candidate = inputs.RevocationStatusInformation[i];
            if(!candidate.SubjectCertificate.Equals(inputs.TargetCertificate))
            {
                continue;
            }

            ValidationObjectIdentity revocationIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                candidate.RevocationData.AsReadOnlyMemory(), ValidationObjectKind.RevocationData, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);
            if(inputs.ProofsOfExistence.ExistsAtOrBefore(revocationIdentity, authorityRevocationTime))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Decides whether every algorithm concerned by a cryptographic constraints failure has a proof of existence
    /// for its material at a time before the instant up to which that algorithm was considered secure — the
    /// condition of step 4) of clause 5.6.2.4.4.
    /// </summary>
    /// <param name="inputs">The block's inputs.</param>
    /// <returns><see langword="true"/> when every concerned algorithm's material is proven to predate its expiry.</returns>
    /// <remarks>
    /// The material this step can name through the set of proofs of existence is the signature's own — the
    /// signature value and the digest over the signed attributes — and the proof for it is the earliest instant
    /// the set proves the signature value existed at. Certificate and revocation data material is not asked
    /// about here because step 2) already handled it: the validation time sliding process of clause 5.6.2.2 step
    /// 2)d) slides control-time back to the latest instant those algorithms were all reliable, and step 2) of
    /// this block only passed because that slide succeeded.
    /// </remarks>
    private static bool HasProofsBeforeAlgorithmExpiry(PastSignatureValidationInputs inputs)
    {
        if(inputs.UnreliableAlgorithms.Count == 0)
        {
            return false;
        }

        if(inputs.ProofsOfExistence.EarliestInstantFor(inputs.SignatureValueIdentity) is not DateTimeOffset provenSignatureTime)
        {
            return false;
        }

        for(int i = 0; i < inputs.UnreliableAlgorithms.Count; ++i)
        {
            AlgorithmReliabilityAssessment assessment = inputs.UnreliableAlgorithms[i];
            if(!SignatureMaterialIdentifiers.IsSignatureOwnMaterial(assessment.Use.MaterialIdentifier))
            {
                continue;
            }

            if(assessment.TrustedUntil is not DateTimeOffset trustedUntil || provenSignatureTime >= trustedUntil)
            {
                //An algorithm the constraints assert no reliability period for was never considered secure, so
                //no proof of existence can place the material before the end of one.
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Reads the validity window of a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to read.</param>
    /// <returns>The window, or <see langword="null"/> when the certificate does not parse.</returns>
    private static CertificateValidityWindow? TryReadValidityWindow(PkiCertificateMemory certificate)
    {
        try
        {
            ManagedCertificate parsed = ManagedCertificate.Parse(certificate.AsReadOnlyMemory());

            return new CertificateValidityWindow(parsed.NotBefore, parsed.NotAfter);
        }
        catch(AsnContentException)
        {
            //A certificate whose validity dates cannot be read supports none of the comparisons of step 3), and
            //every branch that needs one therefore asserts nothing.
            return null;
        }
    }


    /// <summary>The validity window of a certificate, as step 3) of clause 5.6.2.4.4 reads it.</summary>
    /// <param name="NotBefore">The issuance date.</param>
    /// <param name="NotAfter">The expiration date.</param>
    private readonly record struct CertificateValidityWindow(DateTimeOffset NotBefore, DateTimeOffset NotAfter);
}
