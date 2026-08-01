using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the validation time sliding process concluded — the output of Table 24 of clause 5.6.2.2.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>: <c>PASSED</c> with a validation time, or <c>INDETERMINATE</c> with
/// <c>NO_POE</c>.
/// </summary>
[DebuggerDisplay("ValidationTimeSlidingResult: {Conclusion.Indication}, control-time {ControlTime}")]
public sealed record ValidationTimeSlidingResult
{
    /// <summary>The block's conclusion.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>The calculated control-time the block returns on <c>PASSED</c>; <see langword="null"/> otherwise.</summary>
    public DateTimeOffset? ControlTime { get; init; }
}


/// <summary>
/// The validation time sliding process of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.6.2.2</see>: it slides control-time from the current time back to some date
/// in the past each time it meets a certificate proven to be revoked, a cryptographic constraints failure or a
/// freshness failure, and returns the last value it holds.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The scope checks of step 2)a).</strong> The clause requires the selected revocation data to be
/// "consistent with the rules conditioning its use to check the revocation status of the considered certificate.
/// In the case of a CRL, it shall satisfy the checks specified in IETF RFC 5280, clause 6.3.3 (b) to (l); with
/// the exception of the verification of whether the control-time is within the validity period of the
/// certificate of the issuer of the CRL". Those checks are over a CRL's own encoding — its issuer, its
/// distribution point, its reasons mask, its own certification path and its signature — and they are performed
/// by the revocation checker that produced a <see cref="RevocationStatusInformation"/>: that record exists
/// precisely because the caller's checker already verified the data. What remains at the level of these facts is
/// the part the clause's own NOTE 3 names — that the status is about the considered certificate, and that the
/// certificate was not already expired when the revocation data was issued unless the issuer states it covers
/// expired certificates — and that is what this block checks. The stated exception is honoured by never
/// comparing control-time against the validity period of the revocation data's issuer certificate here.
/// </para>
/// <para>
/// <strong>Determinism.</strong> The current time is an explicit argument, so a run repeats exactly.
/// </para>
/// </remarks>
public static class ValidationTimeSliding
{
    /// <summary>The <see href="https://www.rfc-editor.org/rfc/rfc5280">RFC 5280</see> §5.3.1 <c>CRLReason</c> value <c>unspecified</c>, which states no reason and is therefore an unknown reason.</summary>
    private const int RevocationReasonUnspecified = 0;

    /// <summary>The RFC 5280 §5.3.1 <c>CRLReason</c> value <c>keyCompromise</c>.</summary>
    private const int RevocationReasonKeyCompromise = 1;


    /// <summary>
    /// Slides the validation time along one prospective certificate chain.
    /// </summary>
    /// <param name="prospectiveChain">Table 23's mandatory "A prospective certificate chain" input, signing certificate first and trust anchor last.</param>
    /// <param name="proofsOfExistence">Table 23's mandatory "A set of POEs" input.</param>
    /// <param name="certificateValidationData">Table 23's mandatory "Certificate Validation Data" input, as revocation status information about the chain's certificates.</param>
    /// <param name="trustAnchorSunsetDate">Table 23's optional "A trust anchor sunset date" input, which step 1)a) initializes control-time to when it is before the current time.</param>
    /// <param name="cryptographicConstraints">Table 23's optional "Cryptographic constraints" input, applied in step 2)d).</param>
    /// <param name="x509Constraints">Table 23's optional "X.509 validation constraints" input, whose validity model step 2)b) branches on and whose freshness value step 2)c) uses.</param>
    /// <param name="currentTime">The current date/time step 1)b) initializes control-time to.</param>
    /// <param name="resources">The ledger the object-identity digests this call computes are tracked in.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of Table 24 and, on <c>PASSED</c>, the calculated control-time.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<ValidationTimeSlidingResult> SlideAsync(
        IReadOnlyList<PkiCertificateMemory> prospectiveChain,
        ProofOfExistenceSet proofsOfExistence,
        IReadOnlyList<RevocationStatusInformation> certificateValidationData,
        DateTimeOffset? trustAnchorSunsetDate,
        CryptographicConstraints cryptographicConstraints,
        X509ValidationConstraints x509Constraints,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(prospectiveChain);
        ArgumentNullException.ThrowIfNull(proofsOfExistence);
        ArgumentNullException.ThrowIfNull(certificateValidationData);
        ArgumentNullException.ThrowIfNull(cryptographicConstraints);
        ArgumentNullException.ThrowIfNull(x509Constraints);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(pool);

        //Step 1): control-time starts at the trust anchor's sunset date when that date has already passed, and at
        //the current date/time in all other cases (NOTE 2: the current time assumes the anchor is still trusted).
        DateTimeOffset controlTime = trustAnchorSunsetDate is DateTimeOffset sunsetDate && sunsetDate < currentTime
            ? sunsetDate
            : currentTime;

        //Step 2): each certificate in the chain starting from the one issued by the trust anchor. The chain is
        //held signing certificate first, so the walk runs from the far end towards the target and skips the trust
        //anchors themselves, which no revocation data is about.
        for(int i = LastCertificateIssuedByTrustAnchor(prospectiveChain, x509Constraints); i >= 0; --i)
        {
            PkiCertificateMemory certificate = prospectiveChain[i];
            PkiCertificateMemory? issuer = i + 1 < prospectiveChain.Count ? prospectiveChain[i + 1] : null;

            //Step 2)a): the revocation data that is in scope, issued before control-time, and proven to have
            //existed at or before control-time together with the certificate it is about.
            List<RevocationStatusInformation> selected = [];
            for(int r = 0; r < certificateValidationData.Count; ++r)
            {
                RevocationStatusInformation candidate = certificateValidationData[r];
                if(!candidate.SubjectCertificate.Equals(certificate) || candidate.ThisUpdate >= controlTime)
                {
                    continue;
                }

                if(!IsInScope(certificate, candidate))
                {
                    continue;
                }

                bool proven = await HasProofsAsync(
                    proofsOfExistence, certificate, candidate.RevocationData, controlTime, resources, pool, cancellationToken).ConfigureAwait(false);
                if(proven)
                {
                    selected.Add(candidate);
                }
            }

            if(selected.Count == 0)
            {
                ValidationObjectIdentity missing = await ProofOfExistenceExtraction.CreateIdentityAsync(
                    certificate.AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);

                return new ValidationTimeSlidingResult
                {
                    Conclusion = BuildingBlockConclusion.Indeterminate(
                        SignatureValidationSubIndication.NoProofOfExistence,
                        [new MissingProofOfExistenceReportData(
                            [missing],
                            "No revocation data about the certificate is in scope, issued before control-time and proven to have existed at or before it.")])
                };
            }

            RevocationStatusInformation latest = SelectLatestIssued(selected);
            if(IsRevoked(selected, out RevocationStatusInformation? revoked))
            {
                //Step 2)b): the latest-issued of the revocation data that marks the certificate revoked decides,
                //and control-time slides to the revocation time under the shell model, or under the chain model
                //when the revocation reason is key compromise or unknown.
                bool slides = x509Constraints.ValidityModel == CertificateValidityModel.Shell
                    || IsKeyCompromiseOrUnknown(revoked.RevocationReason);
                if(slides && revoked.RevocationTime is DateTimeOffset revocationTime)
                {
                    controlTime = revocationTime;
                }
            }
            else
            {
                //Step 2)c): the latest-issued of the selected revocation data has to be fresh at control-time;
                //when it is not, control-time slides to the earlier of control-time and that data's issuance time.
                RevocationFreshnessResult freshness = await RevocationFreshnessChecker.CheckAsync(
                    latest, certificate, controlTime, x509Constraints, cancellationToken).ConfigureAwait(false);
                if(freshness.Conclusion.Indication == BuildingBlockIndication.Failed && latest.ThisUpdate < controlTime)
                {
                    controlTime = latest.ThisUpdate;
                }
            }

            //Step 2)d): the cryptographic constraints are applied to the certificate and its revocation data at
            //control-time, and control-time slides to the latest instant all the listed algorithms were reliable.
            List<AlgorithmUse> uses = MaterialUses(certificate, issuer, latest);
            if(cryptographicConstraints.FindUnreliable(uses, controlTime).Count > 0)
            {
                if(cryptographicConstraints.LatestInstantAllReliable(uses) is not DateTimeOffset reliableUntil)
                {
                    //No instant can be asserted at which the algorithms were all considered reliable, so no
                    //control-time can be calculated for this chain at all. Table 24 admits one indeterminate
                    //outcome, and this is the outcome of a proof that cannot be established.
                    ValidationObjectIdentity unreliable = await ProofOfExistenceExtraction.CreateIdentityAsync(
                        certificate.AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);

                    return new ValidationTimeSlidingResult
                    {
                        Conclusion = BuildingBlockConclusion.Indeterminate(
                            SignatureValidationSubIndication.NoProofOfExistence,
                            [new MissingProofOfExistenceReportData(
                                [unreliable],
                                "The cryptographic constraints assert no instant up to which every algorithm the certificate or its revocation data uses was reliable.")])
                    };
                }

                controlTime = reliableUntil;
            }
        }

        //Step 2)e).
        return new ValidationTimeSlidingResult
        {
            Conclusion = BuildingBlockConclusion.Passed,
            ControlTime = controlTime
        };
    }


    /// <summary>
    /// States the index of the certificate the trust anchor issued — the certificate step 2) starts the walk at
    /// — in a chain held signing certificate first.
    /// </summary>
    /// <param name="chain">The prospective chain.</param>
    /// <param name="x509Constraints">The constraints naming the trust anchors.</param>
    /// <returns>The highest index that is not a trust anchor, or <c>-1</c> when every certificate is one.</returns>
    private static int LastCertificateIssuedByTrustAnchor(IReadOnlyList<PkiCertificateMemory> chain, X509ValidationConstraints x509Constraints)
    {
        for(int i = chain.Count - 1; i >= 0; --i)
        {
            bool isTrustAnchor = false;
            for(int a = 0; a < x509Constraints.TrustAnchors.Count; ++a)
            {
                if(x509Constraints.TrustAnchors[a].Anchor.Equals(chain[i]))
                {
                    isTrustAnchor = true;

                    break;
                }
            }

            if(!isTrustAnchor)
            {
                return i;
            }
        }

        return -1;
    }


    /// <summary>
    /// Decides whether one instance of revocation status information is in scope for a certificate at the level
    /// of the facts this algorithm holds — the part of step 2)a)'s consistency rule that NOTE 3 names.
    /// </summary>
    /// <param name="certificate">The certificate whose revocation status is being checked.</param>
    /// <param name="information">The revocation status information.</param>
    /// <returns><see langword="true"/> when the information may be used to ascertain that certificate's status.</returns>
    private static bool IsInScope(PkiCertificateMemory certificate, RevocationStatusInformation information)
    {
        if(information.CoversExpiredCertificates)
        {
            //The issuer states that it provides revocation status information for expired certificates, which is
            //the exception NOTE 3 names.
            return true;
        }

        try
        {
            ManagedCertificate parsed = ManagedCertificate.Parse(certificate.AsReadOnlyMemory());

            return information.ThisUpdate <= parsed.NotAfter;
        }
        catch(AsnContentException)
        {
            //A certificate whose validity dates cannot be read cannot be shown to have been unexpired when the
            //revocation data was issued, so the data is not selected.
            return false;
        }
    }


    /// <summary>
    /// Decides whether the set of proofs of existence proves both the certificate and the revocation data
    /// existed at or before control-time — the third condition of step 2)a).
    /// </summary>
    /// <param name="proofsOfExistence">The set of proofs.</param>
    /// <param name="certificate">The certificate whose revocation status is being checked.</param>
    /// <param name="revocationData">The revocation data carrying the status information.</param>
    /// <param name="controlTime">The current value of control-time.</param>
    /// <param name="resources">The ledger the computed identities are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when both proofs are present.</returns>
    private static async ValueTask<bool> HasProofsAsync(
        ProofOfExistenceSet proofsOfExistence,
        PkiCertificateMemory certificate,
        PkiCertificateMemory revocationData,
        DateTimeOffset controlTime,
        SignatureValidationResources resources,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ValidationObjectIdentity certificateIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            certificate.AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);
        if(!proofsOfExistence.ExistsAtOrBefore(certificateIdentity, controlTime))
        {
            return false;
        }

        ValidationObjectIdentity revocationIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            revocationData.AsReadOnlyMemory(), ValidationObjectKind.RevocationData, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);

        return proofsOfExistence.ExistsAtOrBefore(revocationIdentity, controlTime);
    }


    /// <summary>
    /// Selects the instance of revocation status information that was issued the latest, which steps 2)b) and
    /// 2)c) both call for.
    /// </summary>
    /// <param name="selected">The instances selected in step 2)a).</param>
    /// <returns>The latest-issued instance.</returns>
    private static RevocationStatusInformation SelectLatestIssued(List<RevocationStatusInformation> selected)
    {
        RevocationStatusInformation latest = selected[0];
        for(int i = 1; i < selected.Count; ++i)
        {
            if(selected[i].ThisUpdate > latest.ThisUpdate)
            {
                latest = selected[i];
            }
        }

        return latest;
    }


    /// <summary>
    /// Decides whether the certificate is marked as revoked in any of the selected revocation data, which is the
    /// condition step 2)b) branches on.
    /// </summary>
    /// <param name="selected">The instances selected in step 2)a).</param>
    /// <param name="revoked">The latest-issued instance that marks the certificate revoked, when there is one.</param>
    /// <returns><see langword="true"/> when at least one instance marks the certificate revoked.</returns>
    private static bool IsRevoked(List<RevocationStatusInformation> selected, [NotNullWhen(true)] out RevocationStatusInformation? revoked)
    {
        revoked = null;
        for(int i = 0; i < selected.Count; ++i)
        {
            if(selected[i].Status == CertificateRevocationStatus.Revoked && (revoked is null || selected[i].ThisUpdate > revoked.ThisUpdate))
            {
                revoked = selected[i];
            }
        }

        return revoked is not null;
    }


    /// <summary>
    /// Decides whether a revocation reason is "key compromise or unknown", which is the condition step 2)b)
    /// slides control-time under the chain model on.
    /// </summary>
    /// <param name="revocationReason">The RFC 5280 §5.3.1 <c>CRLReason</c> value the revocation data stated, or <see langword="null"/> when it stated none.</param>
    /// <returns><see langword="true"/> when the reason is key compromise, or is not known.</returns>
    /// <remarks>
    /// A reason the revocation data did not state is not known, and so is <c>unspecified</c>, which is the
    /// <c>CRLReason</c> value that states no reason.
    /// </remarks>
    private static bool IsKeyCompromiseOrUnknown(int? revocationReason) =>
        revocationReason is null or RevocationReasonUnspecified or RevocationReasonKeyCompromise;


    /// <summary>
    /// Builds the algorithm uses step 2)d) applies the cryptographic constraints to: the certificate and the
    /// revocation data that was used for it.
    /// </summary>
    /// <param name="certificate">The certificate being considered.</param>
    /// <param name="issuer">The certificate of its issuer, when the chain holds one.</param>
    /// <param name="revocationData">The revocation status information selected for it.</param>
    /// <returns>The uses; one per piece of material whose algorithm is in hand.</returns>
    private static List<AlgorithmUse> MaterialUses(
        PkiCertificateMemory certificate,
        PkiCertificateMemory? issuer,
        RevocationStatusInformation revocationData)
    {
        List<AlgorithmUse> uses = [];
        if(X509CertificateValidation.CertificateAlgorithmUse(certificate, issuer) is AlgorithmUse certificateUse)
        {
            uses.Add(certificateUse);
        }

        if(revocationData.SignatureAlgorithm is AlgorithmIdentifier revocationAlgorithm)
        {
            uses.Add(new AlgorithmUse(revocationAlgorithm, revocationData.SignatureKeySizeBits, "revocation status information"));
        }

        return uses;
    }
}
