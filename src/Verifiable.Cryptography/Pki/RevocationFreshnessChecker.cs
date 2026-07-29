using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One instance of revocation status information about one certificate, in the neutral shape the validation
/// algorithm of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> reasons over: Table 11A's "Revocation data" input to the revocation freshness
/// checker, and the material step 4) of clause 5.2.6.4 selects among when it validates a certification path.
/// </summary>
/// <remarks>
/// <para>
/// A caller builds one of these from a CRL entry (<see href="https://www.rfc-editor.org/rfc/rfc5280">RFC
/// 5280</see> §5) or from an OCSP <c>SingleResponse</c> (<see href="https://www.rfc-editor.org/rfc/rfc6960">RFC
/// 6960</see> §4.2.1 — <see cref="OcspSingleResponseFacts"/> maps onto it field for field). The algorithm needs
/// the status, the instants and the identity of what the status is about; it does not re-parse the revocation
/// data, which the caller's own checker already verified.
/// </para>
/// <para>
/// NOTE 3 of clause 5.2.5.4 draws a distinction this record keeps: for an OCSP response the <em>revocation
/// status</em> issuance time is <c>thisUpdate</c> while the <em>revocation data</em> issuance time is
/// <c>producedAt</c>. The freshness check of clause 5.2.5.4 step 2) is about the former, so
/// <see cref="ThisUpdate"/> is what it reads and <see cref="ProducedAt"/> is carried separately for the
/// reporting and proof-of-existence uses that need it.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the caller owns for at
/// least the duration of the validation run.
/// </para>
/// </remarks>
[DebuggerDisplay("RevocationStatusInformation: {Status}, thisUpdate {ThisUpdate}, nextUpdate {NextUpdate}")]
public sealed record RevocationStatusInformation
{
    /// <summary>The DER-encoded revocation data the status was read from — a CRL or an OCSP response, discriminated by its own <see cref="PkiObjectKind"/>.</summary>
    public required PkiCertificateMemory RevocationData { get; init; }

    /// <summary>The certificate this status is about — Table 11A's "certificate for which the revocation is being checked".</summary>
    public required PkiCertificateMemory SubjectCertificate { get; init; }

    /// <summary>The status the revocation data states. <see cref="CertificateRevocationStatus.Unknown"/> is the fail-closed default.</summary>
    public required CertificateRevocationStatus Status { get; init; }

    /// <summary>The issuance time of the revocation status information: a CRL's <c>thisUpdate</c>, or an OCSP <c>SingleResponse</c>'s <c>thisUpdate</c>.</summary>
    public required DateTimeOffset ThisUpdate { get; init; }

    /// <summary>The time by which newer status information will be available: a CRL's or an OCSP <c>SingleResponse</c>'s <c>nextUpdate</c>; <see langword="null"/> when the issuer set none.</summary>
    public required DateTimeOffset? NextUpdate { get; init; }

    /// <summary>The issuance time of the revocation data itself — an OCSP response's <c>producedAt</c>; <see langword="null"/> for a CRL, whose data and status issuance times coincide.</summary>
    public DateTimeOffset? ProducedAt { get; init; }

    /// <summary>The instant the revocation took effect, when <see cref="Status"/> is <see cref="CertificateRevocationStatus.Revoked"/>; <see langword="null"/> otherwise.</summary>
    public DateTimeOffset? RevocationTime { get; init; }

    /// <summary>The RFC 5280 §5.3.1 <c>CRLReason</c> value the revocation data stated, or <see langword="null"/> when it stated none.</summary>
    public int? RevocationReason { get; init; }

    /// <summary>
    /// The algorithm the revocation data was signed with, which step 10) of clause 5.5.4 assesses against the
    /// cryptographic constraints at the current time and step 2)d) of clause 5.6.2.2 assesses against
    /// control-time; <see langword="null"/> when the checker that produced this record did not state it, in which
    /// case those steps assess the certificates alone.
    /// </summary>
    public AlgorithmIdentifier? SignatureAlgorithm { get; init; }

    /// <summary>The key size in bits of the key that signed the revocation data, where it is known; <see langword="null"/> otherwise.</summary>
    public int? SignatureKeySizeBits { get; init; }

    /// <summary>The certificate of the issuer of this revocation data, which step 8) of clause 5.2.6.4 checks the validation time against; <see langword="null"/> when the caller did not identify it.</summary>
    public PkiCertificateMemory? IssuerCertificate { get; init; }

    /// <summary>
    /// Whether the issuer states that it provides revocation status information for certificates that were already
    /// expired when this revocation data was issued — NOTE 3 of clause 5.6.2.2 names the
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280">RFC 5280</see> §5.2.6 <c>expiredCertOnCRL</c> extension
    /// as the example. The validation time sliding process of clause 5.6.2.2 step 2)a) will otherwise not select
    /// revocation data issued after the considered certificate expired, because such data is out of scope for it.
    /// </summary>
    public bool CoversExpiredCertificates { get; init; }


    /// <summary>
    /// Gets whether the certificate is on hold rather than permanently revoked — <c>CRLReason</c> value 6
    /// (<c>certificateHold</c>), which step 4)c) of clause 5.2.6.4 maps to <c>TRY_LATER</c> instead of
    /// <c>REVOKED_NO_POE</c>.
    /// </summary>
    public bool IsOnHold => Status == CertificateRevocationStatus.Revoked && RevocationReason == 6;
}


/// <summary>
/// What the revocation freshness checker concluded — the output of Table 11B of clause 5.2.5.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
[DebuggerDisplay("RevocationFreshnessResult: {Conclusion.Indication}, accepted freshness {AcceptedFreshness}")]
public sealed record RevocationFreshnessResult
{
    /// <summary>The block's conclusion: <c>PASSED</c> when the revocation status information is considered fresh, <c>FAILED</c> when it is not.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>
    /// The maximum accepted revocation freshness the block applied — either the value the X.509 validation
    /// constraints stated, or the <c>nextUpdate</c>-minus-<c>thisUpdate</c> interval of clause 5.2.5.4 step 1)'s
    /// fallback. <see langword="null"/> when neither was available, which is the <c>FAILED</c> that step ends in.
    /// </summary>
    public TimeSpan? AcceptedFreshness { get; init; }
}


/// <summary>
/// The revocation freshness checker of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2.5</see>: it checks that a given revocation status information is "fresh"
/// at a given validation time, where freshness is "the maximum accepted difference between the validation time
/// and the issuance time of the revocation status information".
/// </summary>
/// <remarks>
/// Used by the X.509 certificate validation building block (step 4)a) of clause 5.2.6.4) for every certificate
/// in a chain whose revocation is checked, and by the validation process for Signatures with Time when it
/// re-checks freshness against best-signature-time.
/// </remarks>
public static class RevocationFreshnessChecker
{
    /// <summary>
    /// Checks the freshness of one instance of revocation status information.
    /// </summary>
    /// <param name="revocationStatusInformation">Table 11A's mandatory "Revocation data" input.</param>
    /// <param name="certificate">Table 11A's mandatory "certificate for which the revocation is being checked" input.</param>
    /// <param name="validationTime">Table 11A's mandatory "Validation time" input.</param>
    /// <param name="x509Constraints">Table 11A's mandatory "X.509 validation constraints" input.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of Table 11B, and the freshness the block applied.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// The block is asynchronous for uniformity with the other building blocks of clause 5.2 and completes
    /// synchronously: freshness is a comparison of instants the caller already holds, with no seam to reach.
    /// </remarks>
    public static ValueTask<RevocationFreshnessResult> CheckAsync(
        RevocationStatusInformation revocationStatusInformation,
        PkiCertificateMemory certificate,
        DateTimeOffset validationTime,
        X509ValidationConstraints x509Constraints,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(revocationStatusInformation);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(x509Constraints);
        cancellationToken.ThrowIfCancellationRequested();

        //Step 1): the constraints' value takes precedence; the nextUpdate interval is the fallback the clause
        //allows only when the constraints state no value, and its NOTE 1 makes an absent nextUpdate FAILED.
        TimeSpan? acceptedFreshness = x509Constraints.MaximumAcceptedRevocationFreshness
            ?? (revocationStatusInformation.NextUpdate is DateTimeOffset nextUpdate
                ? nextUpdate - revocationStatusInformation.ThisUpdate
                : null);
        if(acceptedFreshness is not TimeSpan freshness)
        {
            return ValueTask.FromResult(new RevocationFreshnessResult
            {
                Conclusion = Failed("The revocation data sets no nextUpdate and the X.509 validation constraints state no maximum accepted revocation freshness.")
            });
        }

        if(freshness < TimeSpan.Zero)
        {
            //A negative interval is not a maximum accepted difference between two instants. Where it comes from
            //the fallback it means the revocation data states a nextUpdate before its own thisUpdate, which is
            //revocation data no freshness can be asserted from.
            return ValueTask.FromResult(new RevocationFreshnessResult
            {
                Conclusion = Failed("The maximum accepted revocation freshness is a negative interval."),
                AcceptedFreshness = freshness
            });
        }

        //Step 2): "If the issuance time of the revocation status information is after the validation time minus
        //the considered maximum freshness, the building block shall return the indication PASSED." The fallback
        //interval is read out of attacker-reachable DER, where a nextUpdate thousands of years after thisUpdate
        //is a legal encoding, so the subtraction saturates at the start of the representable range instead of
        //leaving it — an interval that long accepts every issuance time either way.
        bool isFresh = revocationStatusInformation.ThisUpdate > PkiInstantArithmetic.SubtractSaturating(validationTime, freshness);

        return ValueTask.FromResult(new RevocationFreshnessResult
        {
            Conclusion = isFresh
                ? BuildingBlockConclusion.Passed
                : Failed("The revocation status information was issued before the validation time minus the maximum accepted revocation freshness."),
            AcceptedFreshness = acceptedFreshness
        });

        //Builds the FAILED outcome of Table 11B, reporting the freshness constraint as the one not met.
        static BuildingBlockConclusion Failed(string description) => new()
        {
            Indication = BuildingBlockIndication.Failed,
            SubIndications = [],
            ReportData = [],
            ConstraintEvaluations =
            [
                new ValidationConstraintEvaluation(ValidationConstraintIdentifier.RevocationFreshness, BuildingBlockIndication.Failed, description)
            ]
        };
    }
}
