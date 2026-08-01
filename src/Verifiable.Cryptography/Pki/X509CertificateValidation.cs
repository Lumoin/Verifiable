using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Why the X.509 certificate validation building block reported <c>TRY_LATER</c>, which the validation process
/// for Signatures with Time branches on: steps 6) and 7) of clause 5.5.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> treat "<c>TRY_LATER</c> because the revocation data contained revocation status
/// information that was not fresh enough" and "<c>TRY_LATER</c> because the certificate has been found to be
/// suspended" as two different cases.
/// </summary>
public enum RevocationTryLaterReason
{
    /// <summary>The block did not report <c>TRY_LATER</c>. The value of an unset field, by design.</summary>
    NotApplicable = 0,

    /// <summary>No revocation status information could be obtained for a certificate whose revocation is checked, so nothing about it is established.</summary>
    RevocationStatusUnavailable = 1,

    /// <summary>The certificate is on hold — <c>CRLReason</c> <c>certificateHold</c>, which step 4)c) of clause 5.2.6.4 maps to <c>TRY_LATER</c>.</summary>
    CertificateSuspended = 2,

    /// <summary>The revocation status information that was used is not fresh enough at the validation time.</summary>
    RevocationStatusNotFresh = 3
}


/// <summary>
/// What the X.509 certificate validation building block concluded — the outputs of Table 13 of clause 5.2.6.3
/// of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="CertificateChain"/> holds non-owning references except for the
/// entries also listed in <see cref="AcquiredCertificates"/>: those were newly obtained by the chain completion
/// seam during this call and the caller disposes them once the validation run is complete.
/// </remarks>
[DebuggerDisplay("X509CertificateValidationResult: {Conclusion.Indication}, chain of {CertificateChain.Count}")]
public sealed record X509CertificateValidationResult
{
    /// <summary>The block's conclusion.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>The certificate chain the block reports — "the certificate chain used in the successful validation" on <c>PASSED</c>, and the validated or last-built chain Table 13 names for each <c>INDETERMINATE</c> row.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; init; } = [];

    /// <summary>Whether <see cref="CertificateChain"/> is a validated chain or merely the last one built.</summary>
    public CertificateChainReportKind ChainKind { get; init; }

    /// <summary>The certificates the chain completion seam newly obtained during this call, which the caller owns and disposes. Empty when the chain was complete as supplied.</summary>
    public IReadOnlyList<PkiCertificateMemory> AcquiredCertificates { get; init; } = [];

    /// <summary>The revocation status information the block consulted — Table 13's "Any additional validation data acquired".</summary>
    public IReadOnlyList<RevocationStatusInformation> RevocationStatusInformationUsed { get; init; } = [];

    /// <summary>
    /// Why the block reported <c>TRY_LATER</c>, which steps 6) and 7) of clause 5.5.4 branch on;
    /// <see cref="RevocationTryLaterReason.NotApplicable"/> for every other conclusion.
    /// </summary>
    public RevocationTryLaterReason TryLaterReason { get; init; }

    /// <summary>
    /// The instant the certificate the conclusion is about was revoked or suspended, which clause 5.5.4 step 4)a)
    /// compares with best-signature-time; <see langword="null"/> when the conclusion is about no revocation.
    /// </summary>
    public DateTimeOffset? RevocationTime { get; init; }

    /// <summary>
    /// The instance of revocation status information the conclusion turns on — the "revocation status data
    /// returned in step 2)" that clause 5.5.4 step 6) hands back to the revocation freshness checker;
    /// <see langword="null"/> when no single instance decided the conclusion.
    /// </summary>
    public RevocationStatusInformation? DecisiveRevocationStatusInformation { get; init; }
}


/// <summary>
/// The X.509 certificate validation building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2.6</see>: it validates the signing certificate at the validation time by
/// building a prospective certificate chain, validating it, checking revocation and freshness, and applying the
/// X.509 and cryptographic constraints, reporting each outcome in Table 13's vocabulary.
/// </summary>
/// <remarks>
/// <para>
/// The block composes three caller-supplied seams — <see cref="CompleteCertificateChainAsyncDelegate"/> for
/// step 2), <see cref="ValidateCertificateChainAsyncDelegate"/> for the path validation of step 4), and
/// <see cref="CheckCertificateRevocationStatusAsyncDelegate"/> for the revocation checking step 4) folds into
/// path validation — and maps their outcomes onto the indications of Table 13. The path validation seam signals
/// failure by throwing <see cref="SecurityException"/>, but a seam is arbitrary caller-supplied code over
/// attacker-supplied certificates and the platform implementations shipped alongside this library also raise
/// <see cref="System.Security.Cryptography.CryptographicException"/> from a chain build. Every seam call is
/// therefore wrapped in the same <c>catch(Exception) when(not OperationCanceledException)</c> the format
/// checking, validation context initialization, cryptographic verification and signature acceptance validation
/// blocks already use: an exception from an attacker-reachable certificate never escapes as an exception, it
/// becomes the indication the clause names for that step.
/// </para>
/// <para>
/// <strong>Revocation status comes from the supplied information first.</strong> NOTE 7 of clause 5.2.6.4 states
/// that "the process here assumes that revocation data is supplied by the DA only", and Table 13's rows demand
/// the revocation date and reason, which the three-valued revocation seam does not carry. The supplied
/// <see cref="RevocationStatusInformation"/> is therefore the primary source and the seam is the fallback for a
/// certificate the caller supplied no information about. Where several instances apply to one certificate, the
/// latest-issued one is used, as step 4) requires.
/// </para>
/// <para>
/// <strong>One prospective chain per call.</strong> Steps 2), 3), 4)d), 4)e), 5) and 6) each end in "go to step
/// 2)", which asks for the next prospective chain that has not yet been evaluated. The chain completion seam
/// yields one chain, so those transitions reduce to step 2)a)'s own instruction — "if no new chain can be built,
/// the building block shall return the current status, the last chain built and any additional information
/// saved" — which is what this block returns.
/// </para>
/// </remarks>
public static class X509CertificateValidation
{
    /// <summary>The id-etsi-extvalassured-ST-certs certificate extension of ETSI EN 319 412-1, named in EXAMPLE 2 of clause 5.2.6.4.</summary>
    private const string ExtendedValidationAssuredExtensionOid = "0.4.0.194121.2.1";


    /// <summary>
    /// Validates the signing certificate at the validation time.
    /// </summary>
    /// <param name="signingCertificate">Table 12's mandatory "Signing certificate" input.</param>
    /// <param name="x509Constraints">Table 12's mandatory "X.509 Validation Constraints" input, which also carries the mandatory "Trust Anchors" input.</param>
    /// <param name="cryptographicConstraints">Table 12's optional "Cryptographic Constraints" input, applied to the chain in step 6).</param>
    /// <param name="otherCertificates">Table 12's optional "OtherCertificates" input: the only certificates step 2) may use to build the chain, beyond what the completion seam holds.</param>
    /// <param name="revocationStatusInformation">Table 12's optional "Certificate Validation Data" input, as revocation status information about the chain's certificates.</param>
    /// <param name="completeCertificateChain">The chain building seam of step 2).</param>
    /// <param name="validateCertificateChain">The path validation seam of step 4).</param>
    /// <param name="checkRevocation">The revocation seam consulted for a certificate no <paramref name="revocationStatusInformation"/> covers, or <see langword="null"/> when the caller configures none.</param>
    /// <param name="validationTime">Table 12's "Validation time" input. Clause 5.2.6.1 makes it optional and defaults it to current time; it is mandatory here so nothing reads an ambient clock.</param>
    /// <param name="pool">The memory pool the seams rent from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of Table 13, the chain it is about, and the revocation status information consulted.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<X509CertificateValidationResult> ValidateAsync(
        PkiCertificateMemory signingCertificate,
        X509ValidationConstraints x509Constraints,
        CryptographicConstraints cryptographicConstraints,
        IReadOnlyList<PkiCertificateMemory> otherCertificates,
        IReadOnlyList<RevocationStatusInformation> revocationStatusInformation,
        CompleteCertificateChainAsyncDelegate completeCertificateChain,
        ValidateCertificateChainAsyncDelegate validateCertificateChain,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        DateTimeOffset validationTime,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(x509Constraints);
        ArgumentNullException.ThrowIfNull(cryptographicConstraints);
        ArgumentNullException.ThrowIfNull(otherCertificates);
        ArgumentNullException.ThrowIfNull(revocationStatusInformation);
        ArgumentNullException.ThrowIfNull(completeCertificateChain);
        ArgumentNullException.ThrowIfNull(validateCertificateChain);
        ArgumentNullException.ThrowIfNull(pool);

        List<PkiCertificateMemory> trustAnchors = [];
        for(int i = 0; i < x509Constraints.TrustAnchors.Count; ++i)
        {
            trustAnchors.Add(x509Constraints.TrustAnchors[i].Anchor);
        }

        //Step 1): the signing certificate is itself a trust anchor.
        if(Contains(trustAnchors, signingCertificate))
        {
            _ = x509Constraints.TryGetTrustAnchorSunsetDate(signingCertificate, out DateTimeOffset? anchorSunset);
            if(anchorSunset is DateTimeOffset sunset && validationTime >= sunset)
            {
                //Step 1)a) sets the status and goes to step 2), where no further chain can be built from a trust
                //anchor that is no longer trusted.
                return new X509CertificateValidationResult
                {
                    Conclusion = BuildingBlockConclusion.Indeterminate(
                        SignatureValidationSubIndication.NoCertificateChainFoundNoProofOfExistence,
                        [new CertificateChainReportData([signingCertificate], CertificateChainReportKind.LastBuilt)]),
                    CertificateChain = [signingCertificate]
                };
            }

            //Step 1)b): the trust anchor is trusted at the validation time, which is what a trust anchor means.
            return new X509CertificateValidationResult
            {
                Conclusion = BuildingBlockConclusion.PassedWith(
                    [new CertificateChainReportData([signingCertificate], CertificateChainReportKind.Validated)]),
                CertificateChain = [signingCertificate],
                ChainKind = CertificateChainReportKind.Validated
            };
        }

        //Step 2): build a prospective chain. Only OtherCertificates may contribute, so the links are followed
        //through that set first and the completion seam is asked to reach a trust anchor from there.
        List<PkiCertificateMemory> partialChain = BuildPartialChain(signingCertificate, otherCertificates, trustAnchors);
        IReadOnlyList<PkiCertificateMemory> chain;
        try
        {
            chain = await completeCertificateChain(partialChain, trustAnchors, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            //Step 2)a): no chain has been built at all.
            return new X509CertificateValidationResult
            {
                Conclusion = BuildingBlockConclusion.Indeterminate(SignatureValidationSubIndication.NoCertificateChainFound, [])
            };
        }

        List<PkiCertificateMemory> acquired = [];
        for(int i = 0; i < chain.Count; ++i)
        {
            if(!ContainsReference(partialChain, chain[i]))
            {
                acquired.Add(chain[i]);
            }
        }

        //Step 3): the sunset date of the trust anchor the chain was built from.
        for(int i = 0; i < chain.Count; ++i)
        {
            if(Contains(trustAnchors, chain[i])
                && x509Constraints.TryGetTrustAnchorSunsetDate(chain[i], out DateTimeOffset? chainAnchorSunset)
                && chainAnchorSunset is DateTimeOffset chainSunset
                && validationTime >= chainSunset)
            {
                return Indeterminate(
                    SignatureValidationSubIndication.NoCertificateChainFoundNoProofOfExistence,
                    [new CertificateChainReportData(chain, CertificateChainReportKind.LastBuilt)],
                    chain, CertificateChainReportKind.LastBuilt, acquired, []);
            }
        }

        //Step 4): path validation. The seam collapses every failure into SecurityException, so it is run without
        //revocation and the revocation outcomes step 4)b) to 4)e) distinguish are determined here.
        try
        {
            using PublicKeyMemory _ = await validateCertificateChain(
                chain, trustAnchors, validationTime, pool, checkRevocation: null, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            //Step 4)e): a failure for any reason other than revocation.
            return Indeterminate(
                SignatureValidationSubIndication.CertificateChainGeneralFailure,
                [new CertificateChainGeneralFailureReportData(chain, exception.Message)],
                chain, CertificateChainReportKind.LastBuilt, acquired, []);
        }

        //Step 4) folds revocation checking into the path validation — "the validation shall include revocation
        //checking for each certificate in the chain" — and only then branches: step 4)a) runs the revocation
        //freshness checker "if the certificate path validation returns a success indication", and steps 4)b) to
        //4)e) map the revocation failures. The status of every certificate in the chain is therefore determined
        //first, and only a chain in which none of them failed reaches the freshness pass.
        List<RevocationStatusInformation> consulted = [];
        List<RevocationDetermination> determinations = [];
        for(int i = 0; i < chain.Count; ++i)
        {
            PkiCertificateMemory certificate = chain[i];
            if(Contains(trustAnchors, certificate) || IsExemptFromRevocationChecking(certificate, x509Constraints))
            {
                continue;
            }

            RevocationStatusInformation? status = SelectLatest(revocationStatusInformation, certificate);
            if(status is null)
            {
                CertificateRevocationStatus fallback = CertificateRevocationStatus.Unknown;
                if(checkRevocation is not null)
                {
                    try
                    {
                        fallback = await checkRevocation(certificate, chain, validationTime, pool, cancellationToken).ConfigureAwait(false);
                    }
                    catch(Exception exception) when(exception is not OperationCanceledException)
                    {
                        fallback = CertificateRevocationStatus.Unknown;
                    }
                }

                determinations.Add(new RevocationDetermination(i, certificate, fallback, IsOnHold: false, Status: null));

                continue;
            }

            consulted.Add(status);
            determinations.Add(new RevocationDetermination(i, certificate, status.Status, status.IsOnHold, status));
        }

        //The failure the path validation of step 4) reports. A certificate determined to be revoked is a failure
        //of the path whichever certificate it is, so it decides over a certificate whose status could not be
        //determined at all; between two revoked certificates the one closer to the trust anchor decides, which is
        //the one the IETF RFC 5280 clause 6.1 path processing this step delegates to meets first. A status that
        //could not be determined is not a revocation but leaves the path unvalidated, which is what TRY_LATER
        //reports; the TRY_LATER rows of Table 13 name the last certificate chain built, which is what is
        //returned even where the step's own prose says "the validated chain".
        if(SelectFailure(determinations) is RevocationDetermination failure)
        {
            if(failure.IsOnHold)
            {
                //Step 4)c): a certificate on hold, with the suspension time and the nextUpdate as the suggestion.
                return Indeterminate(
                    SignatureValidationSubIndication.TryLater,
                    [new TryLaterReportData(failure.Status?.NextUpdate, chain, failure.Status is null ? [] : [failure.Status.RevocationData])],
                    chain, CertificateChainReportKind.LastBuilt, acquired, consulted,
                    RevocationTryLaterReason.CertificateSuspended, failure.Status?.RevocationTime, failure.Status);
            }

            if(failure.Determination == CertificateRevocationStatus.Revoked)
            {
                //Steps 4)b) and 4)d). Step 4)b) mandates "the revocation date"; where the source that reported
                //the revocation states none — the three-valued revocation seam never does — no instant is
                //invented for it, because a revocation date that is not known cannot be shown to be posterior to
                //best-signature-time, which is what step 4)a)b of clause 5.5.4 then concludes on.
                return RevokedOutcome(
                    failure.Index == 0, chain, failure.Certificate, failure.Status?.RevocationTime, failure.Status?.RevocationReason,
                    acquired, consulted, failure.Status);
            }

            return Indeterminate(
                SignatureValidationSubIndication.TryLater,
                [new TryLaterReportData(failure.Status?.NextUpdate, chain, failure.Status is null ? [] : [failure.Status.RevocationData])],
                chain, CertificateChainReportKind.LastBuilt, acquired, consulted,
                RevocationTryLaterReason.RevocationStatusUnavailable, decisiveRevocationStatusInformation: failure.Status);
        }

        //Step 4)a): the path validation of step 4) succeeded for every certificate in the chain, so the freshness
        //of each instance of revocation status information that was used is checked.
        for(int i = 0; i < determinations.Count; ++i)
        {
            if(determinations[i].Status is not RevocationStatusInformation used)
            {
                continue;
            }

            RevocationFreshnessResult freshness = await RevocationFreshnessChecker.CheckAsync(
                used, determinations[i].Certificate, validationTime, x509Constraints, cancellationToken).ConfigureAwait(false);
            if(freshness.Conclusion.Indication != BuildingBlockIndication.Passed)
            {
                return Indeterminate(
                    SignatureValidationSubIndication.TryLater,
                    [new TryLaterReportData(used.NextUpdate, chain, [used.RevocationData])],
                    chain, CertificateChainReportKind.LastBuilt, acquired, consulted,
                    RevocationTryLaterReason.RevocationStatusNotFresh, decisiveRevocationStatusInformation: used);
            }
        }

        //Step 5): the X.509 validation constraints are applied to the chain.
        IReadOnlyList<ValidationConstraintEvaluation> unsatisfied = ApplyCertificateMetadataConstraints(chain, x509Constraints);
        if(unsatisfied.Count > 0)
        {
            return Indeterminate(
                SignatureValidationSubIndication.ChainConstraintsFailure,
                [new ChainConstraintsFailureReportData(chain, unsatisfied)],
                chain, CertificateChainReportKind.LastBuilt, acquired, consulted);
        }

        //Step 6): the cryptographic constraints are applied to the chain.
        IReadOnlyList<AlgorithmReliabilityAssessment> unreliable =
            cryptographicConstraints.FindUnreliable(CertificateChainAlgorithmUses(chain), validationTime);
        if(unreliable.Count > 0)
        {
            return Indeterminate(
                SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence,
                [new CryptographicConstraintsFailureReportData(unreliable)],
                chain, CertificateChainReportKind.LastBuilt, acquired, consulted);
        }

        //Step 7): the validation time is in the validity range of the signing certificate.
        ManagedCertificate signingCertificateFacts;
        try
        {
            signingCertificateFacts = ManagedCertificate.Parse(signingCertificate.AsReadOnlyMemory());
        }
        catch(AsnContentException exception)
        {
            return Indeterminate(
                SignatureValidationSubIndication.CertificateChainGeneralFailure,
                [new CertificateChainGeneralFailureReportData(chain, exception.Message)],
                chain, CertificateChainReportKind.LastBuilt, acquired, consulted);
        }

        if(validationTime < signingCertificateFacts.NotBefore || validationTime > signingCertificateFacts.NotAfter)
        {
            //NOTE 8: the certificate is "known to not have been revoked" when revocation status information for
            //it was consulted and stated so.
            bool knownNotRevoked = SelectLatest(consulted, signingCertificate)?.Status == CertificateRevocationStatus.Good;

            return Indeterminate(
                knownNotRevoked
                    ? SignatureValidationSubIndication.OutOfBoundsNotRevoked
                    : SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence,
                [new CertificateChainReportData(chain, CertificateChainReportKind.Validated)],
                chain, CertificateChainReportKind.Validated, acquired, consulted);
        }

        //Step 8): the validation time is within the validity range of the certificate of the issuer of the
        //revocation data.
        for(int i = 0; i < consulted.Count; ++i)
        {
            if(consulted[i].IssuerCertificate is not PkiCertificateMemory revocationIssuer)
            {
                continue;
            }

            try
            {
                ManagedCertificate issuerFacts = ManagedCertificate.Parse(revocationIssuer.AsReadOnlyMemory());
                if(validationTime < issuerFacts.NotBefore || validationTime > issuerFacts.NotAfter)
                {
                    return Indeterminate(
                        SignatureValidationSubIndication.RevocationOutOfBoundsNoProofOfExistence,
                        [new RevocationOutOfBoundsReportData(chain, [consulted[i].RevocationData])],
                        chain, CertificateChainReportKind.Validated, acquired, consulted);
                }
            }
            catch(AsnContentException)
            {
                return Indeterminate(
                    SignatureValidationSubIndication.RevocationOutOfBoundsNoProofOfExistence,
                    [new RevocationOutOfBoundsReportData(chain, [consulted[i].RevocationData])],
                    chain, CertificateChainReportKind.Validated, acquired, consulted);
            }
        }

        //Step 9).
        return new X509CertificateValidationResult
        {
            Conclusion = BuildingBlockConclusion.PassedWith([new CertificateChainReportData(chain, CertificateChainReportKind.Validated)]),
            CertificateChain = chain,
            ChainKind = CertificateChainReportKind.Validated,
            AcquiredCertificates = acquired,
            RevocationStatusInformationUsed = consulted
        };

        //Builds an INDETERMINATE outcome of Table 13 carrying the chain the row names, together with the
        //revocation particulars steps 4)a), 6) and 7) of clause 5.5.4 branch on.
        static X509CertificateValidationResult Indeterminate(
            SignatureValidationSubIndication subIndication,
            IReadOnlyList<SignatureValidationReportData> reportData,
            IReadOnlyList<PkiCertificateMemory> chain,
            CertificateChainReportKind chainKind,
            IReadOnlyList<PkiCertificateMemory> acquired,
            IReadOnlyList<RevocationStatusInformation> consulted,
            RevocationTryLaterReason tryLaterReason = RevocationTryLaterReason.NotApplicable,
            DateTimeOffset? revocationTime = null,
            RevocationStatusInformation? decisiveRevocationStatusInformation = null) => new()
            {
                Conclusion = BuildingBlockConclusion.Indeterminate(subIndication, reportData),
                CertificateChain = chain,
                ChainKind = chainKind,
                AcquiredCertificates = acquired,
                RevocationStatusInformationUsed = consulted,
                TryLaterReason = tryLaterReason,
                RevocationTime = revocationTime,
                DecisiveRevocationStatusInformation = decisiveRevocationStatusInformation
            };

        //Builds step 4)b)'s REVOKED_NO_POE for the signing certificate and step 4)d)'s REVOKED_CA_NO_POE for an
        //intermediate CA certificate, each with the chain, the revocation date and the reason Table 6 mandates.
        static X509CertificateValidationResult RevokedOutcome(
            bool isSigningCertificate,
            IReadOnlyList<PkiCertificateMemory> chain,
            PkiCertificateMemory revoked,
            DateTimeOffset? revocationTime,
            int? revocationReason,
            IReadOnlyList<PkiCertificateMemory> acquired,
            IReadOnlyList<RevocationStatusInformation> consulted,
            RevocationStatusInformation? decisiveRevocationStatusInformation = null) => new()
            {
                Conclusion = BuildingBlockConclusion.Indeterminate(
                    isSigningCertificate
                        ? SignatureValidationSubIndication.RevokedNoProofOfExistence
                        : SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence,
                    [new CertificateRevocationReportData(chain, revoked, revocationTime, revocationReason)]),
                CertificateChain = chain,
                ChainKind = isSigningCertificate ? CertificateChainReportKind.Validated : CertificateChainReportKind.LastBuilt,
                AcquiredCertificates = acquired,
                RevocationStatusInformationUsed = consulted,
                RevocationTime = revocationTime,
                DecisiveRevocationStatusInformation = decisiveRevocationStatusInformation
            };
    }


    /// <summary>
    /// Selects the revocation determination the path validation of step 4) of clause 5.2.6.4 reports as its
    /// failure, or <see langword="null"/> when every certificate of the chain was determined not to be revoked.
    /// </summary>
    /// <param name="determinations">One determination per certificate whose revocation is checked, signing certificate first.</param>
    /// <returns>The deciding determination, or <see langword="null"/> when the path validation succeeded.</returns>
    /// <remarks>
    /// A determined revocation decides over a suspension and both decide over a status that could not be
    /// determined at all: the first two are failure indications the clause's steps 4)b) to 4)d) name, while the
    /// third is the fail-closed reading of a check that could not be completed. Within one kind the certificate
    /// closest to the trust anchor decides, which is the one IETF RFC 5280 clause 6.1 path processing meets
    /// first.
    /// </remarks>
    private static RevocationDetermination? SelectFailure(List<RevocationDetermination> determinations)
    {
        RevocationDetermination? revoked = null;
        RevocationDetermination? suspended = null;
        RevocationDetermination? undetermined = null;
        for(int i = 0; i < determinations.Count; ++i)
        {
            RevocationDetermination determination = determinations[i];
            if(determination.IsOnHold)
            {
                suspended = determination;
            }
            else if(determination.Determination == CertificateRevocationStatus.Revoked)
            {
                revoked = determination;
            }
            else if(determination.Determination == CertificateRevocationStatus.Unknown)
            {
                undetermined = determination;
            }
        }

        return revoked ?? suspended ?? undetermined;
    }


    /// <summary>
    /// Follows the issuer links of one certificate through a set of candidate certificates, producing the
    /// prospective chain the completion seam then reaches a trust anchor from — step 2) of clause 5.2.6.4 ("if
    /// the 'Other Certificates' parameter is present, only certificates contained in that set of certificates may
    /// be used to build the chain") and step 1) of clause 5.6.2.1.4, which builds its chain from the certificate
    /// validation data Table 21 makes mandatory. Iterative and bounded by the size of that set, so an issuer
    /// cycle in attacker-supplied certificates terminates.
    /// </summary>
    /// <param name="signingCertificate">The certificate the chain starts at.</param>
    /// <param name="otherCertificates">The only certificates the chain may be built from.</param>
    /// <param name="trustAnchors">The trust anchors the chain terminates at.</param>
    /// <returns>The chain, signing certificate first. The carriers are the ones passed in; the caller keeps owning them.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static List<PkiCertificateMemory> BuildPartialChain(
        PkiCertificateMemory signingCertificate,
        IReadOnlyList<PkiCertificateMemory> otherCertificates,
        IReadOnlyList<PkiCertificateMemory> trustAnchors)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(otherCertificates);
        ArgumentNullException.ThrowIfNull(trustAnchors);

        List<PkiCertificateMemory> chain = [signingCertificate];
        ManagedCertificate? current;
        try
        {
            current = ManagedCertificate.Parse(signingCertificate.AsReadOnlyMemory());
        }
        catch(AsnContentException)
        {
            return chain;
        }

        for(int step = 0; step < otherCertificates.Count; ++step)
        {
            if(Contains(trustAnchors, chain[^1]) || current.IssuerDer.Span.SequenceEqual(current.SubjectDer.Span))
            {
                break;
            }

            ManagedCertificate? issuer = null;
            PkiCertificateMemory? issuerCarrier = null;
            for(int i = 0; i < otherCertificates.Count; ++i)
            {
                if(ContainsReference(chain, otherCertificates[i]))
                {
                    continue;
                }

                try
                {
                    ManagedCertificate candidate = ManagedCertificate.Parse(otherCertificates[i].AsReadOnlyMemory());
                    if(candidate.SubjectDer.Span.SequenceEqual(current.IssuerDer.Span))
                    {
                        issuer = candidate;
                        issuerCarrier = otherCertificates[i];

                        break;
                    }
                }
                catch(AsnContentException)
                {
                    //A certificate that does not parse cannot be shown to be the issuer.
                    continue;
                }
            }

            if(issuer is null || issuerCarrier is null)
            {
                break;
            }

            chain.Add(issuerCarrier);
            current = issuer;
        }

        return chain;
    }


    /// <summary>
    /// Selects the latest-issued revocation status information about one certificate, per step 4) of clause
    /// 5.2.6.4: "the SVA shall use the latest issued instance that is known to contain revocation status
    /// information about the certificate".
    /// </summary>
    /// <param name="revocationStatusInformation">Every instance available.</param>
    /// <param name="certificate">The certificate to select for.</param>
    /// <returns>The selected instance, or <see langword="null"/> when none is about that certificate.</returns>
    private static RevocationStatusInformation? SelectLatest(
        IReadOnlyList<RevocationStatusInformation> revocationStatusInformation,
        PkiCertificateMemory certificate)
    {
        RevocationStatusInformation? latest = null;
        for(int i = 0; i < revocationStatusInformation.Count; ++i)
        {
            RevocationStatusInformation candidate = revocationStatusInformation[i];
            if(!candidate.SubjectCertificate.Equals(certificate) || !IsIssuedWithinIssuerValidity(candidate))
            {
                continue;
            }

            if(latest is null || candidate.ThisUpdate > latest.ThisUpdate)
            {
                latest = candidate;
            }
        }

        return latest;
    }


    /// <summary>
    /// Decides whether the issuance date of one instance of revocation status information is within the validity
    /// period of the certificate of its issuer — the verification step 4) of clause 5.2.6.4 states the validation
    /// "shall include", paired there with the verification it excludes ("the validation shall not include the
    /// verification of whether the validation time is within the validity period of the certificate of the issuer
    /// of the revocation status information"), which NOTE 6 defers to step 8).
    /// </summary>
    /// <param name="information">The revocation status information.</param>
    /// <returns><see langword="true"/> when the instance may be used to ascertain a certificate's status.</returns>
    /// <remarks>
    /// NOTE 3 of clause 5.2.5.4 makes the issuance date of the revocation <em>data</em> an OCSP response's
    /// <c>producedAt</c>, distinct from the <c>thisUpdate</c> of the revocation <em>status information</em>; a CRL
    /// states one instant for both. An instance whose issuer certificate the caller did not identify states no
    /// validity period to compare against, and is left to step 8), which makes the same distinction.
    /// </remarks>
    private static bool IsIssuedWithinIssuerValidity(RevocationStatusInformation information)
    {
        if(information.IssuerCertificate is not PkiCertificateMemory issuer)
        {
            return true;
        }

        try
        {
            ManagedCertificate parsed = ManagedCertificate.Parse(issuer.AsReadOnlyMemory());
            DateTimeOffset issuance = information.ProducedAt ?? information.ThisUpdate;

            return issuance >= parsed.NotBefore && issuance <= parsed.NotAfter;
        }
        catch(AsnContentException)
        {
            //An issuer certificate that does not parse states no validity period the issuance date can be shown
            //to be within, so the instance is not used.
            return false;
        }
    }


    /// <summary>
    /// Decides whether the X.509 validation constraints except a certificate from revocation checking, per step
    /// 4) of clause 5.2.6.4 and its EXAMPLE 2.
    /// </summary>
    /// <param name="certificate">The certificate to test.</param>
    /// <param name="x509Constraints">The constraints.</param>
    /// <returns><see langword="true"/> when no revocation checking is performed for the certificate.</returns>
    /// <remarks>
    /// EXAMPLE 2 scopes <c>id-pkix-ocsp-nocheck</c> the way
    /// <see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2.1">IETF RFC 6960 §4.2.2.2.1</see> does:
    /// a CA includes it "in the responder's certificate" so that an OCSP client can trust that responder for the
    /// lifetime of its certificate. The extension is non-critical and self-asserted, so honouring it on an end
    /// entity or a CA certificate would turn it into a revocation bypass for the very certificate whose status is
    /// being ascertained. The exemption is therefore given only to a certificate that also asserts the
    /// <c>id-kp-OCSPSigning</c> key purpose, which is what makes a certificate a responder's certificate.
    /// </remarks>
    private static bool IsExemptFromRevocationChecking(PkiCertificateMemory certificate, X509ValidationConstraints x509Constraints)
    {
        if(Contains(x509Constraints.CertificatesExemptFromRevocationChecking, certificate))
        {
            return true;
        }

        if(!x509Constraints.ExemptCertificatesWithOcspNoCheckExtension && !x509Constraints.ExemptCertificatesWithExtendedValidationAssuranceExtension)
        {
            return false;
        }

        List<CertificateExtensionPresence> extensions = ReadExtensions(certificate);
        for(int i = 0; i < extensions.Count; ++i)
        {
            bool isOcspNoCheck = x509Constraints.ExemptCertificatesWithOcspNoCheckExtension
                && string.Equals(extensions[i].Oid, WellKnownOids.OcspNoCheck, StringComparison.Ordinal)
                && IsOcspResponderCertificate(certificate);
            bool isExtendedValidationAssured = x509Constraints.ExemptCertificatesWithExtendedValidationAssuranceExtension
                && string.Equals(extensions[i].Oid, ExtendedValidationAssuredExtensionOid, StringComparison.Ordinal);
            if(isOcspNoCheck || isExtendedValidationAssured)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Decides whether a certificate is an OCSP responder's certificate — the only certificate
    /// <see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2">IETF RFC 6960 §4.2.2.2</see> scopes
    /// <c>id-pkix-ocsp-nocheck</c> to.
    /// </summary>
    /// <param name="certificate">The certificate to test.</param>
    /// <returns><see langword="true"/> when the certificate asserts the <c>id-kp-OCSPSigning</c> key purpose.</returns>
    private static bool IsOcspResponderCertificate(PkiCertificateMemory certificate)
    {
        QualifiedCertificateFacts facts;
        try
        {
            facts = QualifiedCertificateFactsExtractor.Extract(certificate);
        }
        catch(AsnContentException)
        {
            //A certificate whose key purposes cannot be read cannot be shown to be a responder's certificate.
            return false;
        }

        for(int i = 0; i < facts.ExtendedKeyUsageOids.Count; ++i)
        {
            if(string.Equals(facts.ExtendedKeyUsageOids[i], WellKnownOids.OcspSigningKeyPurpose, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Applies the certificate meta-data constraints to a chain, per step 5) of clause 5.2.6.4 — and, because it
    /// is the same check, per step 4) of clause 5.6.2.1, which has the past certificate validation building block
    /// "apply the X.509 validation constraints to the chain".
    /// </summary>
    /// <param name="chain">The chain to apply them to, signing certificate first.</param>
    /// <param name="x509Constraints">The constraints.</param>
    /// <returns>The per-constraint outcomes for the constraints the chain did not meet; empty when it met them all.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static IReadOnlyList<ValidationConstraintEvaluation> ApplyCertificateMetadataConstraints(
        IReadOnlyList<PkiCertificateMemory> chain,
        X509ValidationConstraints x509Constraints)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(x509Constraints);

        List<ValidationConstraintEvaluation> unsatisfied = [];
        for(int i = 0; i < x509Constraints.CertificateMetadataConstraints.Count; ++i)
        {
            CertificateMetadataConstraint constraint = x509Constraints.CertificateMetadataConstraints[i];
            int last = constraint.AppliesToWholeChain ? chain.Count : 1;
            for(int c = 0; c < last && c < chain.Count; ++c)
            {
                string? failure = Evaluate(constraint, chain[c]);
                if(failure is not null)
                {
                    unsatisfied.Add(new ValidationConstraintEvaluation(constraint.Identifier, BuildingBlockIndication.Failed, failure));

                    break;
                }
            }
        }

        return unsatisfied;
    }


    /// <summary>
    /// Evaluates one certificate meta-data constraint against one certificate.
    /// </summary>
    /// <param name="constraint">The constraint.</param>
    /// <param name="certificate">The certificate.</param>
    /// <returns>What the certificate failed to satisfy, or <see langword="null"/> when it satisfies the constraint.</returns>
    private static string? Evaluate(CertificateMetadataConstraint constraint, PkiCertificateMemory certificate)
    {
        QualifiedCertificateFacts facts;
        try
        {
            facts = QualifiedCertificateFactsExtractor.Extract(certificate);
        }
        catch(AsnContentException exception)
        {
            return exception.Message;
        }

        return constraint switch
        {
            RequiredCertificatePolicyConstraint policy => ContainsAny(facts.CertificatePolicyOids, policy.PolicyOids)
                ? null
                : "The certificate asserts none of the required certificate policies.",
            RequiredKeyUsageConstraint keyUsage => SatisfiesKeyUsage(facts, keyUsage)
                ? null
                : "The certificate's key usage does not match the required bits.",
            RequiredExtendedKeyUsageConstraint extendedKeyUsage => ContainsAny(facts.ExtendedKeyUsageOids, extendedKeyUsage.KeyPurposeOids)
                ? null
                : "The certificate names none of the required extended key usage purposes.",
            RequiredCertificateExtensionConstraint required => HasExtension(certificate, required.ExtensionOid, required.MustBeCritical)
                ? null
                : "The certificate does not carry the required extension.",
            ForbiddenCertificateExtensionConstraint forbidden => HasExtension(certificate, forbidden.ExtensionOid, mustBeCritical: false)
                ? "The certificate carries a forbidden extension."
                : null,
            _ => "The certificate meta-data constraint is of a kind this building block does not evaluate."
        };
    }


    /// <summary>
    /// Checks whether a certificate's key usage satisfies every bit assertion of a constraint.
    /// </summary>
    /// <param name="facts">The certificate's facts.</param>
    /// <param name="constraint">The constraint.</param>
    /// <returns><see langword="true"/> when every assertion holds.</returns>
    private static bool SatisfiesKeyUsage(QualifiedCertificateFacts facts, RequiredKeyUsageConstraint constraint)
    {
        for(int i = 0; i < constraint.Bits.Count; ++i)
        {
            bool isSet = false;
            for(int b = 0; b < facts.SetKeyUsageBits.Count; ++b)
            {
                if(facts.SetKeyUsageBits[b] == constraint.Bits[i].Bit)
                {
                    isSet = true;

                    break;
                }
            }

            if(isSet != constraint.Bits[i].Asserted)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Checks whether a certificate carries a named extension, optionally requiring it to be critical.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="extensionOid">The extension's dotted-decimal object identifier.</param>
    /// <param name="mustBeCritical">Whether the extension additionally has to be marked critical.</param>
    /// <returns><see langword="true"/> when the certificate carries it as required.</returns>
    private static bool HasExtension(PkiCertificateMemory certificate, string extensionOid, bool mustBeCritical)
    {
        List<CertificateExtensionPresence> extensions = ReadExtensions(certificate);
        for(int i = 0; i < extensions.Count; ++i)
        {
            if(string.Equals(extensions[i].Oid, extensionOid, StringComparison.Ordinal) && (!mustBeCritical || extensions[i].IsCritical))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Builds the algorithm uses of a chain for the cryptographic constraints of step 6) — each certificate's own
    /// signature algorithm, taken with the key size of the issuer that signed it — which is also the material
    /// step 10) of clause 5.5.4 and step 2)d) of clause 5.6.2.2 assess.
    /// </summary>
    /// <param name="chain">The chain, signing certificate first.</param>
    /// <returns>One use per certificate whose signature algorithm could be read.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="chain"/> is <see langword="null"/>.</exception>
    public static IReadOnlyList<AlgorithmUse> CertificateChainAlgorithmUses(IReadOnlyList<PkiCertificateMemory> chain)
    {
        ArgumentNullException.ThrowIfNull(chain);

        List<AlgorithmUse> uses = [];
        List<ManagedCertificate?> parsed = [];
        for(int i = 0; i < chain.Count; ++i)
        {
            try
            {
                parsed.Add(ManagedCertificate.Parse(chain[i].AsReadOnlyMemory()));
            }
            catch(AsnContentException)
            {
                parsed.Add(null);
            }
        }

        for(int i = 0; i < parsed.Count; ++i)
        {
            if(parsed[i] is not ManagedCertificate certificate)
            {
                continue;
            }

            int? issuerKeySize = i + 1 < parsed.Count ? parsed[i + 1]?.SubjectPublicKeySizeBits : certificate.SubjectPublicKeySizeBits;
            uses.Add(BuildUse(certificate, issuerKeySize));
        }

        return uses;
    }


    /// <summary>
    /// Builds the algorithm use of one certificate: the algorithm it was signed with, taken with the key size of
    /// the issuer that signed it. This is the same material step 6) of clause 5.2.6.4 assesses per chain, exposed
    /// per certificate for step 2)d) of clause 5.6.2.2, which slides control-time one certificate at a time.
    /// </summary>
    /// <param name="certificate">The certificate to describe.</param>
    /// <param name="issuer">The certificate of its issuer, or <see langword="null"/> when the certificate is self-issued or the issuer is not in hand.</param>
    /// <returns>The use, or <see langword="null"/> when the certificate does not parse.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is <see langword="null"/>.</exception>
    public static AlgorithmUse? CertificateAlgorithmUse(PkiCertificateMemory certificate, PkiCertificateMemory? issuer)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        ManagedCertificate parsed;
        try
        {
            parsed = ManagedCertificate.Parse(certificate.AsReadOnlyMemory());
        }
        catch(AsnContentException)
        {
            return null;
        }

        int? issuerKeySize = parsed.SubjectPublicKeySizeBits;
        if(issuer is not null)
        {
            try
            {
                issuerKeySize = ManagedCertificate.Parse(issuer.AsReadOnlyMemory()).SubjectPublicKeySizeBits;
            }
            catch(AsnContentException)
            {
                //An issuer that does not parse states no key size; the certificate's own is the honest fallback,
                //exactly as the chain-wide overload does for the last certificate of a chain.
                issuerKeySize = parsed.SubjectPublicKeySizeBits;
            }
        }

        return BuildUse(parsed, issuerKeySize);
    }


    /// <summary>
    /// Names one certificate's signature algorithm and the key size it was verified under, in the vocabulary a
    /// <see cref="CryptographicConstraintsFailureReportData"/> presents.
    /// </summary>
    /// <param name="certificate">The parsed certificate.</param>
    /// <param name="issuerKeySizeBits">The key size of the key that signed it.</param>
    /// <returns>The use.</returns>
    private static AlgorithmUse BuildUse(ManagedCertificate certificate, int? issuerKeySizeBits) =>
        new(new AlgorithmIdentifier(certificate.SignatureAlgorithmOid),
            issuerKeySizeBits,
            $"certificate {PkiDistinguishedNameText.FromDer(certificate.SubjectDer)}");


    /// <summary>
    /// Reads the object identifiers and criticality flags of a certificate's extensions, so a constraint about
    /// extension presence can be evaluated without a certificate library.
    /// </summary>
    /// <param name="certificate">The certificate to read.</param>
    /// <returns>One entry per extension, in certificate order; empty when the certificate carries none or does not parse.</returns>
    private static List<CertificateExtensionPresence> ReadExtensions(PkiCertificateMemory certificate)
    {
        List<CertificateExtensionPresence> extensions = [];
        try
        {
            var certificateReader = new AsnReader(certificate.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader certificateSequence = certificateReader.ReadSequence();
            AsnReader tbs = certificateSequence.ReadSequence();
            if(tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
            {
                _ = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            }

            _ = tbs.ReadIntegerBytes();
            _ = tbs.ReadSequence();
            _ = tbs.ReadEncodedValue();
            _ = tbs.ReadSequence();
            _ = tbs.ReadEncodedValue();
            _ = tbs.ReadSequence();

            //issuerUniqueID [1] and subjectUniqueID [2] are obsolete but allowed before the extensions.
            if(tbs.HasData && tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
            {
                _ = tbs.ReadEncodedValue();
            }

            if(tbs.HasData && tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true))
            {
                _ = tbs.ReadEncodedValue();
            }

            if(tbs.HasData && tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true))
            {
                AsnReader extensionsWrapper = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                AsnReader extensionList = extensionsWrapper.ReadSequence();
                while(extensionList.HasData)
                {
                    AsnReader extension = extensionList.ReadSequence();
                    string extensionId = extension.ReadObjectIdentifier();
                    bool isCritical = extension.PeekTag() == new Asn1Tag(UniversalTagNumber.Boolean) && extension.ReadBoolean();
                    _ = extension.ReadOctetString();
                    extension.ThrowIfNotEmpty();
                    extensions.Add(new CertificateExtensionPresence(extensionId, isCritical));
                }
            }
        }
        catch(AsnContentException)
        {
            //A certificate whose extensions cannot be read carries none this block can act on; the constraint
            //that asked about them fails closed because the extension it required is then absent.
            return extensions;
        }

        return extensions;
    }


    /// <summary>
    /// Reports whether any of a set of values is present in a list.
    /// </summary>
    /// <param name="values">The values the certificate carries.</param>
    /// <param name="wanted">The values at least one of which has to be present.</param>
    /// <returns><see langword="true"/> when at least one is present.</returns>
    private static bool ContainsAny(IReadOnlyList<string> values, IReadOnlyList<string> wanted)
    {
        for(int i = 0; i < wanted.Count; ++i)
        {
            for(int v = 0; v < values.Count; ++v)
            {
                if(string.Equals(values[v], wanted[i], StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }


    /// <summary>
    /// Reports whether a list holds a certificate byte-equal to the given one.
    /// </summary>
    /// <param name="certificates">The list to search.</param>
    /// <param name="certificate">The certificate to look for.</param>
    /// <returns><see langword="true"/> when the list holds it.</returns>
    private static bool Contains(IReadOnlyList<PkiCertificateMemory> certificates, PkiCertificateMemory certificate)
    {
        for(int i = 0; i < certificates.Count; ++i)
        {
            if(certificates[i].Equals(certificate))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Reports whether a list holds the very same carrier instance, which is how a certificate the chain
    /// completion seam newly acquired is told apart from one that was supplied to it.
    /// </summary>
    /// <param name="certificates">The list to search.</param>
    /// <param name="certificate">The carrier to look for.</param>
    /// <returns><see langword="true"/> when the list holds that instance.</returns>
    private static bool ContainsReference(List<PkiCertificateMemory> certificates, PkiCertificateMemory certificate)
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


    /// <summary>One certificate extension's identity and criticality.</summary>
    /// <param name="Oid">The extension's dotted-decimal object identifier.</param>
    /// <param name="IsCritical">Whether the extension is marked critical.</param>
    private sealed record CertificateExtensionPresence(string Oid, bool IsCritical);


    /// <summary>
    /// What the revocation checking of step 4) of clause 5.2.6.4 determined about one certificate of the chain,
    /// together with the instance of revocation status information that determined it — the "used revocation
    /// data" and "the corresponding certificate for which the revocation status is being checked" step 4)a) hands
    /// to the revocation freshness checker once the path validation has succeeded for the whole chain.
    /// </summary>
    /// <param name="Index">The certificate's position in the chain, signing certificate first; zero is the signing certificate, which is what tells step 4)b) from step 4)d).</param>
    /// <param name="Certificate">A non-owning reference to the certificate.</param>
    /// <param name="Determination">The status that was determined for it.</param>
    /// <param name="IsOnHold">Whether the determination is the suspension step 4)c) names rather than a revocation.</param>
    /// <param name="Status">The revocation status information that determined it, or <see langword="null"/> when the three-valued revocation seam determined it and carries no instance.</param>
    private sealed record RevocationDetermination(
        int Index,
        PkiCertificateMemory Certificate,
        CertificateRevocationStatus Determination,
        bool IsOnHold,
        RevocationStatusInformation? Status);
}
