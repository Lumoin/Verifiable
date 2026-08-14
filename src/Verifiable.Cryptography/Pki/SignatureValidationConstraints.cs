using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The identity of one validation constraint, so that a building block can report the outcome of each
/// constraint it took into account, as Table 5 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see> asks for ("the validation process may provide the result of the
/// validation for each of the validation constraints", and for a negative or indeterminate outcome it
/// <em>shall</em>).
/// </summary>
/// <remarks>
/// The set is open by design, matching clause 5.1.4.1's NOTE 3 ("the verifier can select a signature
/// validation policy that contains additional constraints, which are not mentioned in the present document").
/// The statics name the constraints the records in this file express; a caller enforcing its own constraint
/// mints its own identifier.
/// </remarks>
/// <param name="Value">The identifier's value.</param>
[DebuggerDisplay("ValidationConstraintIdentifier: {Value}")]
public readonly record struct ValidationConstraintIdentifier(string Value)
{
    /// <summary>The set of trust anchors and their sunset dates (clause 5.2.6.4 steps 1 and 3).</summary>
    public static ValidationConstraintIdentifier TrustAnchors { get; } = new("x509:trust-anchors");

    /// <summary>The shell or chain validity model the path validation follows (clause 5.2.6.4 step 4).</summary>
    public static ValidationConstraintIdentifier CertificateValidityModel { get; } = new("x509:validity-model");

    /// <summary>The maximum accepted revocation freshness (clause 5.2.5.4 step 1).</summary>
    public static ValidationConstraintIdentifier RevocationFreshness { get; } = new("x509:revocation-freshness");

    /// <summary>Whether revocation status is checked for a given certificate at all (clause 5.2.6.4 step 4).</summary>
    public static ValidationConstraintIdentifier RevocationChecking { get; } = new("x509:revocation-checking");

    /// <summary>The certificate meta-data a certificate in the chain has to carry or not carry (clause 5.2.6.4 step 5).</summary>
    public static ValidationConstraintIdentifier CertificateMetadata { get; } = new("x509:certificate-metadata");

    /// <summary>The reliability of the algorithms and key sizes used by the material under validation (clause 5.1.4.3).</summary>
    public static ValidationConstraintIdentifier AlgorithmReliability { get; } = new("crypto:algorithm-reliability");

    /// <summary>The signed attributes the signature is required to carry (clause 5.2.8.4.1).</summary>
    public static ValidationConstraintIdentifier MandatedSignedAttributes { get; } = new("elements:mandated-signed-attributes");

    /// <summary>The signed attributes the signature is required not to carry (clause 5.2.8.4.1).</summary>
    public static ValidationConstraintIdentifier ForbiddenSignedAttributes { get; } = new("elements:forbidden-signed-attributes");

    /// <summary>The signing certificate reference constraint (clause 5.2.8.4.2.1).</summary>
    public static ValidationConstraintIdentifier SigningCertificateReferences { get; } = new("elements:signing-certificate-references");

    /// <summary>The time-stamp delay window applied to the claimed signing time (clause 5.5.4 step 5).</summary>
    public static ValidationConstraintIdentifier TimestampDelay { get; } = new("elements:timestamp-delay");

    /// <summary>Whether a signature time-stamp token is required to validate (clause 5.5.4 step 3)b)).</summary>
    public static ValidationConstraintIdentifier SignatureTimestampValidity { get; } = new("elements:signature-timestamp-validity");

    /// <summary>Whether a content time-stamp attribute is required to validate (clause 5.2.8.4.2.5).</summary>
    public static ValidationConstraintIdentifier ContentTimestampValidity { get; } = new("elements:content-timestamp-validity");

    /// <summary>Whether a countersignature attribute is required to validate (clause 5.2.8.4.2.6).</summary>
    public static ValidationConstraintIdentifier CountersignatureValidity { get; } = new("elements:countersignature-validity");

    /// <summary>The ordering constraints between signature time-stamps and content time-stamps (clause 5.5.4 step 4)e)).</summary>
    public static ValidationConstraintIdentifier TimestampOrder { get; } = new("elements:timestamp-order");
}


/// <summary>
/// The outcome of taking one validation constraint into account, reported per constraint per Table 5 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see>.
/// </summary>
/// <param name="Identifier">The constraint the outcome is about.</param>
/// <param name="Indication">Whether the material met the constraint. <see cref="BuildingBlockIndication.Indeterminate"/> means the block could not decide, not that the constraint was met.</param>
/// <param name="Description">What the block can state about the outcome, for a Driving Application to present; <see langword="null"/> when it has nothing beyond the indication.</param>
[DebuggerDisplay("ValidationConstraintEvaluation: {Identifier.Value} is {Indication}")]
public sealed record ValidationConstraintEvaluation(
    ValidationConstraintIdentifier Identifier,
    BuildingBlockIndication Indication,
    string? Description);


/// <summary>
/// The identity of the signature validation policy, or of the set of validation constraints, the signature was
/// validated against — the output
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see> requires in all cases ("an indication of the policy or an
/// indication of the set of constraints against which the signature has been validated").
/// </summary>
/// <remarks>
/// Clause 5.1.4.1 lets constraints be defined by a formal policy specification, by system-specific control
/// data, or implicitly by the implementation, so this is an open value rather than an enumeration: a caller
/// driven by a formal policy puts that policy's identifier here, and a caller driven by its own configuration
/// puts a stable name of that configuration here.
/// </remarks>
/// <param name="Value">The identifier's value.</param>
[DebuggerDisplay("SignatureValidationPolicyIdentifier: {Value}")]
public readonly record struct SignatureValidationPolicyIdentifier(string Value)
{
    /// <summary>
    /// The identity a caller reports when it supplied its constraints directly rather than through a named
    /// policy — the "explicitly in system specific control data" source of clause 5.1.4.1.
    /// </summary>
    public static SignatureValidationPolicyIdentifier CallerSuppliedConstraints { get; } = new("caller-supplied-constraints");
}


/// <summary>
/// The validity model the certification path validation of clause 5.2.6.4 step 4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> follows. Clause 5.2.6.4 requires the model to be specified as an X.509
/// validation constraint.
/// </summary>
public enum CertificateValidityModel
{
    /// <summary>
    /// All certificates are valid at validation time. The RFC 5280 clause 6.1 model clause 5.2.6.4 names
    /// first, and the default: adopting the chain model instead is an explicit choice a policy makes.
    /// </summary>
    Shell = 0,

    /// <summary>
    /// All certificates are valid at the time they were used for issuing a certificate. Clause 5.2.6.4
    /// requires this model to follow the algorithm of paragraphs 6 and 7 of clause 6, part 9 of common
    /// PKI v2.0, with both instances of "should" read as "shall".
    /// </summary>
    Chain = 1
}


/// <summary>
/// One trust anchor and the instant it stopped being considered reliable, per clause 5.2.6.4 steps 1)a) and 3)
/// of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> and its NOTE 2, which reads the sunset date off TS 119 172-1 Table A.2
/// row (m)1.1's "a time until when these trust anchors were considered reliable".
/// </summary>
/// <param name="Anchor">A non-owning reference to the DER-encoded trust anchor certificate.</param>
/// <param name="SunsetDate">The instant at or after which the anchor is no longer trusted; <see langword="null"/> when the constraints set no sunset date for it.</param>
[DebuggerDisplay("TrustAnchorConstraint: sunset {SunsetDate}")]
public sealed record TrustAnchorConstraint(PkiCertificateMemory Anchor, DateTimeOffset? SunsetDate);


/// <summary>
/// One requirement on the meta-data a certificate in the chain carries, applied to the chain by clause 5.2.6.4
/// step 5 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>, whose failure sets the status to
/// <c>INDETERMINATE/CHAIN_CONSTRAINTS_FAILURE</c>.
/// </summary>
/// <remarks>
/// A DU-ready closed sum: the sibling records declared alongside this base are the requirement kinds this
/// library evaluates, and a block applies them with an exhaustive switch expression. Clause 5.1.4.1 allows a
/// policy to state further constraints; those are the caller's own to check and report under its own
/// <see cref="ValidationConstraintIdentifier"/>.
/// </remarks>
public abstract record CertificateMetadataConstraint
{
    /// <summary>Prevents this closed sum from being extended outside the sibling records declared alongside it.</summary>
    private protected CertificateMetadataConstraint()
    {
    }

    /// <summary>The identity this constraint is reported under in the per-constraint outcomes of a block.</summary>
    public required ValidationConstraintIdentifier Identifier { get; init; }

    /// <summary>Whether the requirement applies to every certificate in the chain, or to the signing certificate alone.</summary>
    public required bool AppliesToWholeChain { get; init; }
}


/// <summary>
/// Requires a certificate to assert at least one of a set of certificate policy object identifiers in its
/// Certificate Policies extension (RFC 5280 §4.2.1.4).
/// </summary>
public sealed record RequiredCertificatePolicyConstraint: CertificateMetadataConstraint
{
    /// <summary>The dotted-decimal certificate policy object identifiers, at least one of which the certificate has to assert.</summary>
    public required IReadOnlyList<string> PolicyOids { get; init; }
}


/// <summary>
/// Requires a certificate's Key Usage extension (RFC 5280 §4.2.1.3) to match a set of bit assertions.
/// </summary>
public sealed record RequiredKeyUsageConstraint: CertificateMetadataConstraint
{
    /// <summary>The bits and the values they have to hold; every assertion has to match.</summary>
    public required IReadOnlyList<KeyUsageBitAssertion> Bits { get; init; }
}


/// <summary>
/// Requires a certificate's Extended Key Usage extension (RFC 5280 §4.2.1.12) to name at least one of a set of
/// key purpose object identifiers.
/// </summary>
public sealed record RequiredExtendedKeyUsageConstraint: CertificateMetadataConstraint
{
    /// <summary>The dotted-decimal key purpose object identifiers, at least one of which the certificate has to name.</summary>
    public required IReadOnlyList<string> KeyPurposeOids { get; init; }
}


/// <summary>
/// Requires a certificate to carry a named extension, optionally requiring it to be marked critical.
/// </summary>
public sealed record RequiredCertificateExtensionConstraint: CertificateMetadataConstraint
{
    /// <summary>The dotted-decimal object identifier of the extension the certificate has to carry.</summary>
    public required string ExtensionOid { get; init; }

    /// <summary>Whether the extension additionally has to be marked critical.</summary>
    public required bool MustBeCritical { get; init; }
}


/// <summary>
/// Requires a certificate not to carry a named extension.
/// </summary>
public sealed record ForbiddenCertificateExtensionConstraint: CertificateMetadataConstraint
{
    /// <summary>The dotted-decimal object identifier of the extension the certificate must not carry.</summary>
    public required string ExtensionOid { get; init; }
}


/// <summary>
/// The X.509 validation constraints of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.4.2</see>: the requirements for revocation checking and for the
/// certificate path validation process, which clause 5.2.6.4 consults at every step and clauses 5.6.2.1 and
/// 5.6.2.2 consult again when validating in the past.
/// </summary>
/// <remarks>
/// <para>
/// Pure caller-supplied declarative input, with no parser for a formal policy artefact: clause 5.1.4.1 allows
/// the constraints to be defined by a formal policy specification, by system-specific control data, or
/// implicitly, and this record is the shape the algorithm consumes whichever of those the caller used.
/// </para>
/// <para>
/// <strong>Ownership.</strong> The certificates referenced here are non-owning references to memory the caller
/// owns for at least the duration of the validation run.
/// </para>
/// </remarks>
[DebuggerDisplay("X509ValidationConstraints: {TrustAnchors.Count} anchors, {ValidityModel} model")]
public sealed record X509ValidationConstraints
{
    /// <summary>
    /// The trust anchors path validation may terminate at, each with its optional sunset date (clause 5.2.6.4
    /// steps 1)a) and 3), NOTE 2).
    /// </summary>
    public required IReadOnlyList<TrustAnchorConstraint> TrustAnchors { get; init; }

    /// <summary>
    /// The validity model path validation follows (clause 5.2.6.4 step 4). Defaults to
    /// <see cref="CertificateValidityModel.Shell"/>, the RFC 5280 clause 6.1 model the clause names first.
    /// </summary>
    public CertificateValidityModel ValidityModel { get; init; } = CertificateValidityModel.Shell;

    /// <summary>
    /// The maximum accepted difference between the validation time and the issuance time of revocation status
    /// information (clause 5.2.5.1). <see langword="null"/> selects the specification's own fallback in clause
    /// 5.2.5.4 step 1: the interval between the revocation data's <c>thisUpdate</c> and <c>nextUpdate</c>
    /// fields, with a <c>FAILED</c> outcome when <c>nextUpdate</c> is not set.
    /// </summary>
    public TimeSpan? MaximumAcceptedRevocationFreshness { get; init; }

    /// <summary>
    /// The requirements on the meta-data of the certificates in the chain, applied in clause 5.2.6.4 step 5.
    /// </summary>
    public IReadOnlyList<CertificateMetadataConstraint> CertificateMetadataConstraints { get; init; } = [];

    /// <summary>
    /// Non-owning references to certificates for which the constraints explicitly state that revocation
    /// checking is not performed, which clause 5.2.6.4 step 4 excepts from both revocation checking and
    /// revocation freshness checking.
    /// </summary>
    public IReadOnlyList<PkiCertificateMemory> CertificatesExemptFromRevocationChecking { get; init; } = [];

    /// <summary>
    /// Whether an OCSP responder's certificate carrying the <c>id-pkix-ocsp-nocheck</c> extension is exempt from
    /// revocation checking. Defaults to <see langword="false"/>: EXAMPLE 2 of clause 5.2.6.4 states that in line
    /// with RFC 6960 a CA <em>may</em> specify by that extension that an OCSP client can trust a responder for
    /// the lifetime of the responder's certificate, so continuing to check it is the choice that skips nothing
    /// the algorithm prescribes — the same reasoning
    /// <see cref="ExemptCertificatesWithExtendedValidationAssuranceExtension"/> carries. The extension is
    /// non-critical and asserted by the certificate itself, so enabling this exempts only a certificate that
    /// also asserts the <c>id-kp-OCSPSigning</c> key purpose
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2">RFC 6960 §4.2.2.2</see>), never an end
    /// entity or a CA certificate that merely carries the extension.
    /// </summary>
    public bool ExemptCertificatesWithOcspNoCheckExtension { get; init; }

    /// <summary>
    /// Whether a certificate carrying the <c>id-etsi-extvalassured-ST-certs</c> extension is exempt from
    /// revocation checking. Defaults to <see langword="false"/>: EXAMPLE 2 of clause 5.2.6.4 states that upon
    /// presence of that extension the relying party <em>can decide</em> not to check revocation status, so
    /// continuing to check it is the choice that skips nothing the algorithm prescribes.
    /// </summary>
    public bool ExemptCertificatesWithExtendedValidationAssuranceExtension { get; init; }


    /// <summary>
    /// Finds the sunset date the constraints associate with a trust anchor, comparing the anchor's DER bytes.
    /// </summary>
    /// <param name="anchor">The trust anchor to look up.</param>
    /// <param name="sunsetDate">The sunset date when this method returns <see langword="true"/> and the constraints set one; <see langword="null"/> when they set none.</param>
    /// <returns><see langword="true"/> when the anchor is one of <see cref="TrustAnchors"/>.</returns>
    public bool TryGetTrustAnchorSunsetDate(PkiCertificateMemory anchor, out DateTimeOffset? sunsetDate)
    {
        ArgumentNullException.ThrowIfNull(anchor);

        for(int i = 0; i < TrustAnchors.Count; ++i)
        {
            if(TrustAnchors[i].Anchor.Equals(anchor))
            {
                sunsetDate = TrustAnchors[i].SunsetDate;

                return true;
            }
        }

        sunsetDate = null;

        return false;
    }
}


/// <summary>
/// The signature elements constraints of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.4.4</see>: the requirements additional to the X.509 and cryptographic
/// constraints, which the signature acceptance validation building block (clause 5.2.8) applies to the
/// signature's attributes and the validation process for Signatures with Time (clause 5.5.4) applies to its
/// time-stamps.
/// </summary>
/// <remarks>
/// Every default here is the branch the specification itself takes when no constraint is stated, so an
/// instance a caller leaves untouched drives the algorithm exactly as an absent constraint set does.
/// </remarks>
[DebuggerDisplay("SignatureElementsConstraints: {MandatedSignedAttributeOids.Count} mandated, {ForbiddenSignedAttributeOids.Count} forbidden, delay {TimestampDelay}")]
public sealed record SignatureElementsConstraints
{
    /// <summary>
    /// The dotted-decimal object identifiers of the signed attributes the signature is required to carry.
    /// Clause 5.2.8.4.1's NOTE 1 makes an attribute that is present but malformed count as missing.
    /// </summary>
    public IReadOnlyList<string> MandatedSignedAttributeOids { get; init; } = [];

    /// <summary>
    /// The dotted-decimal object identifiers of the signed attributes the signature is required not to carry.
    /// </summary>
    public IReadOnlyList<string> ForbiddenSignedAttributeOids { get; init; } = [];

    /// <summary>
    /// The time-stamp delay window of clause 5.5.4 step 5: the claimed time in the signing-time attribute plus
    /// this window has to be after best-signature-time. <see langword="null"/> means the constraints specify no
    /// time-stamp delay, and step 5 does not run.
    /// </summary>
    public TimeSpan? TimestampDelay { get; init; }

    /// <summary>
    /// The earliest claimed signing time the constraints accept (clause 5.2.8.4.2.2, "If the signature elements
    /// constraints contain constraints regarding this property, the SVA shall follow its rules for checking this
    /// signed property"). <see langword="null"/> states no rule, which is the clause's other branch: the value is
    /// made available to the Driving Application and nothing is checked.
    /// </summary>
    public DateTimeOffset? EarliestAcceptedClaimedSigningTime { get; init; }

    /// <summary>
    /// The latest claimed signing time the constraints accept (clause 5.2.8.4.2.2). <see langword="null"/> states
    /// no rule.
    /// </summary>
    public DateTimeOffset? LatestAcceptedClaimedSigningTime { get; init; }

    /// <summary>
    /// Whether the signing certificate identifier attribute is required to reference every certificate in the
    /// certification path (clause 5.2.8.4.2.1). Defaults to <see langword="false"/>: that clause conditions the
    /// check on "the signature policy mandates references to all the certificates in the certification path".
    /// </summary>
    public bool RequireSigningCertificateReferencesForFullPath { get; init; }

    /// <summary>
    /// Whether the signature is required to carry a signed binding of the signing certificate — a signed
    /// reference, or a signed copy where the format expresses one — surfaced by the format binding as
    /// <see cref="SignatureFacts.SigningCertificateReferences"/> and checked under clause 5.2.8.4.2.1.
    /// Defaults to <see langword="false"/>: without a constraint, clause 5.2.3.4's last paragraph accepts the
    /// unsigned copy of the signing certificate the signature carries, which is the branch the specification
    /// itself takes. Constraint (h) of REQ-4.2-03 of
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
    /// ETSI TS 119 172-4 V1.2.1</see> sets this ("the signature elements constraints shall enforce the
    /// presence of a signed reference or signed copy of the signing certificate").
    /// </summary>
    public bool RequireSignedSigningCertificateBinding { get; init; }

    /// <summary>
    /// Whether a signature time-stamp token that fails validation fails the signature. Defaults to
    /// <see langword="false"/>: step 3)b) of clause 5.5.4 removes a failing token from the set and tries the
    /// next one unless "specific constraints mandating the validity of the attribute are specified".
    /// </summary>
    public bool RequireSignatureTimestampValidity { get; init; }

    /// <summary>
    /// Whether content time-stamp attributes are checked against constraints. Defaults to
    /// <see langword="false"/>: clause 5.2.8.4.2.5 conditions the check on the constraints containing specific
    /// constraints for time-stamps on Signed Data Objects.
    /// </summary>
    public bool RequireContentTimestampValidity { get; init; }

    /// <summary>
    /// Whether a countersignature that fails validation fails the signature. Defaults to
    /// <see langword="false"/>, which clause 5.2.8.4.2.6 states outright: without a constraint on
    /// countersignatures the block "shall not consider the signature validation to having failed if the
    /// countersignature cannot be successfully validated".
    /// </summary>
    public bool RequireCountersignatureValidity { get; init; }

    /// <summary>
    /// Whether the attributes for long term availability and integrity of validation material — archive
    /// time-stamps and their equivalents — are required to validate. Defaults to <see langword="false"/>: step
    /// 3) of clause 5.6.3.4 returns <c>PASSED</c> without touching them when "there is no validation constraint
    /// mandating the validation of the attributes for Long Term Availability and integrity of validation
    /// material", and step 5)d) ignores an attribute that fails unless "specific constraints mandating the
    /// validity of the attribute are specified in the validation constraints".
    /// </summary>
    public bool RequireLongTermAvailabilityAttributeValidity { get; init; }

    /// <summary>
    /// Whether the caller accepts a time-stamp whose coverage the format binding cannot state as protecting what
    /// the class of its attribute says it protects. Defaults to <see langword="false"/>, which is the reading of
    /// step 1) of clause 5.6.2.3.4: the set <c>S</c> holds the objects "protected by the time-stamp", and a token
    /// whose <c>messageImprint</c> nothing verified against those objects has not been shown to protect them.
    /// The attribute a token is carried in is not evidence of what it covers — for every class but the content
    /// time-stamp that attribute is unsigned, so anyone who can rewrite the Signed Data Object can attach a
    /// genuine time-stamp token bought over unrelated data and, without this default, obtain proofs of existence
    /// from it.
    /// </summary>
    /// <remarks>
    /// A caller sets this only where it establishes the binding by other means than the format binding — for
    /// instance where it produced the material itself. It exists because a binding may not implement the
    /// message-imprint computation of every time-stamp class its format defines, and it disappears for a format
    /// whose binding states coverage for all of them.
    /// </remarks>
    public bool AcceptsUnverifiableTimestampCoverage { get; init; }


    /// <summary>
    /// Gets the instance that states no signature elements constraint at all — the input the repeated signature
    /// acceptance validations of step 8) of clause 5.5.4 and steps 5)c)ii) and 9) of clause 5.6.3.4 run under.
    /// Each of those steps lists exactly three inputs (the Signed Data Object(s), a validation time and the
    /// cryptographic constraints), and NOTE 6 of both clauses states that "signature elements constraints have
    /// already been dealt with in step 2) and need not be rechecked".
    /// </summary>
    public static SignatureElementsConstraints None { get; } = new();
}


/// <summary>
/// The complete set of validation constraints controlling one run of the validation algorithm, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.4.1</see>, which requires the X.509 validation constraints (clause
/// 5.1.4.2), the cryptographic constraints (clause 5.1.4.3) and the signature elements constraints (clause
/// 5.1.4.4) all to be supported, together with the identity clause 5.1.3 requires the process to report.
/// </summary>
/// <remarks>
/// This is the record the validation context initialization building block (clause 5.2.4) outputs on
/// <c>PASSED</c> and every later block reads. Constructing it from a formal policy artefact is a caller's
/// concern; the algorithm consumes the constraints, not the document they came from.
/// </remarks>
[DebuggerDisplay("SignatureValidationConstraints: {Identifier.Value}")]
public sealed record SignatureValidationConstraints
{
    /// <summary>The identity reported as "the policy or ... the set of constraints against which the signature has been validated" (clause 5.1.3).</summary>
    public required SignatureValidationPolicyIdentifier Identifier { get; init; }

    /// <summary>The X.509 validation constraints (clause 5.1.4.2).</summary>
    public required X509ValidationConstraints X509 { get; init; }

    /// <summary>The cryptographic constraints (clause 5.1.4.3).</summary>
    public required CryptographicConstraints Cryptographic { get; init; }

    /// <summary>The signature elements constraints (clause 5.1.4.4).</summary>
    public required SignatureElementsConstraints SignatureElements { get; init; }

    /// <summary>
    /// The checks the constraints state are not required and that the algorithm therefore skipped, which
    /// clause 5.1.4.1 requires the SVA to return in its final report to the Driving Application. A block adds
    /// an identifier here when it continues "as if the check has succeeded" because the constraints disabled it.
    /// </summary>
    public IReadOnlyList<ValidationConstraintIdentifier> ChecksDisabledByPolicy { get; init; } = [];
}
