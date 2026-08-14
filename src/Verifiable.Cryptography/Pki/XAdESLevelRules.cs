using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One violated XAdES Table 2 (clause 6.3) requirement, as reported by <see cref="XAdESLevelRules.Check"/> and
/// the other MUST-level check methods on that class. A DU-ready closed sum: no external type may derive from
/// it. The MUST-level counterpart to <see cref="XAdESRuleObservation"/>, mirroring
/// <c>CBAdESRuleViolation</c>/<c>JAdESRuleViolation</c>'s own closed-sum shape one document family over.
/// </summary>
[DebuggerDisplay("{RequirementId}: {Message}")]
public abstract record XAdESRuleViolation
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected XAdESRuleViolation()
    {
    }


    /// <summary>Gets the XA-* requirement identifier this violation cites.</summary>
    public abstract string RequirementId { get; }

    /// <summary>Gets a human-readable statement of what was violated.</summary>
    public abstract string Message { get; }
}


/// <summary>
/// Which clause 4.3.1/4.4.1/4.4.2 binding pin a <see cref="XAdESQualifyingPropertiesBindingViolation"/> reports
/// as failed.
/// </summary>
public enum XAdESQualifyingPropertiesBindingFailure
{
    /// <summary>No directly-incorporated <c>QualifyingProperties</c> was found (clause 4.4.1).</summary>
    NoDirectlyIncorporatedQualifyingProperties,

    /// <summary>The discovered <c>QualifyingProperties</c>'s <c>Target</c> does not resolve to the <c>ds:Signature</c> it was discovered within (clause 4.3.1).</summary>
    TargetNotBoundToSignature,

    /// <summary>No <c>ds:Reference</c> whose <c>Type</c> matches the <c>SignedProperties</c> Type-URI was located in <c>ds:SignedInfo</c> (clause 4.4.2).</summary>
    SignedPropertiesReferenceMissing,

    /// <summary>The located <c>Type</c>-matching <c>ds:Reference</c> dereferences to a node other than the EXACT <c>SignedProperties</c> of the discovered container (clause 4.4.2, the anti-wrapping table-identity pin) — the wrapping BLOCKER's own failure mode.</summary>
    SignedPropertiesReferenceNotBoundToDiscoveredNode
}


/// <summary>
/// The clause 4.3.1/4.4.1/4.4.2 discovery/binding pins <see cref="XAdESDiscoveryFact"/> carries were computed
/// but not honoured: a signature is unclassifiable as baseline-conformant while any of them fails, because the
/// facts <see cref="XAdESLevelRules.Check"/> evaluates elsewhere are not provably the ones the <c>ds:Signature</c>
/// actually signed. Extends the anti-wrapping discipline to the classification/promotion path —
/// the wrapping-attack BLOCKER this gate exists to close.
/// </summary>
/// <param name="Failure">Which pin failed.</param>
public sealed record XAdESQualifyingPropertiesBindingViolation(XAdESQualifyingPropertiesBindingFailure Failure) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Failure switch
    {
        XAdESQualifyingPropertiesBindingFailure.NoDirectlyIncorporatedQualifyingProperties => "XA-4.4.1",
        XAdESQualifyingPropertiesBindingFailure.TargetNotBoundToSignature => "XA-4.3.1",
        XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceMissing => "XA-4.4.2",
        XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceNotBoundToDiscoveredNode => "XA-4.4.2",
        _ => throw new NotSupportedException($"Unknown {nameof(XAdESQualifyingPropertiesBindingFailure)} value '{Failure}'.")
    };

    /// <inheritdoc/>
    public override string Message => Failure switch
    {
        XAdESQualifyingPropertiesBindingFailure.NoDirectlyIncorporatedQualifyingProperties =>
            "The signature carries no directly-incorporated QualifyingProperties (ETSI EN 319 132-1 V1.3.1 clause 4.4.1).",
        XAdESQualifyingPropertiesBindingFailure.TargetNotBoundToSignature =>
            "The discovered QualifyingProperties' own Target does not resolve to this ds:Signature (ETSI EN 319 132-1 V1.3.1 clause 4.3.1).",
        XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceMissing =>
            "No ds:Reference whose Type matches the SignedProperties Type-URI was located in ds:SignedInfo (ETSI EN 319 132-1 V1.3.1 clause 4.4.2).",
        XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceNotBoundToDiscoveredNode =>
            "The Type-matching ds:Reference does not dereference to the discovered container's own SignedProperties node (ETSI EN 319 132-1 V1.3.1 clause 4.4.2).",
        _ => throw new NotSupportedException($"Unknown {nameof(XAdESQualifyingPropertiesBindingFailure)} value '{Failure}'.")
    };
}


/// <summary>
/// Clause 6.3's XA-6.3-02: "The XAdES qualifying properties specified in clause 5 shall be incorporated into
/// the signature using only the direct incorporation mechanism specified in clause 4.4" — the signature carries
/// at least one indirectly-incorporated <c>QualifyingPropertiesReference</c>
/// (<see cref="XAdESDiscoveryFact.QualifyingPropertiesReferenceCount"/>), which clause 6.3 forbids at every
/// baseline level regardless of which properties the reference names.
/// </summary>
/// <param name="QualifyingPropertiesReferenceCount">How many <c>QualifyingPropertiesReference</c> instances the signature carries.</param>
public sealed record XAdESIndirectIncorporationViolation(int QualifyingPropertiesReferenceCount) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-02";

    /// <inheritdoc/>
    public override string Message =>
        $"The signature carries {QualifyingPropertiesReferenceCount} indirectly-incorporated QualifyingPropertiesReference " +
        "element(s); XAdES baseline signatures shall use only the direct incorporation mechanism (ETSI EN 319 132-1 " +
        "V1.3.1 clause 6.3, XA-6.3-02).";
}


/// <summary>
/// Clause 6.3's XA-6.3-04: "In XAdES baseline signatures the qualifying properties that act as electronic
/// time-stamps containers shall encapsulate only IETF RFC 3161 ... electronic time-stamps" — a time-stamp
/// container occurrence carries at least one <c>XMLTimeStamp</c> entry
/// (<see cref="XAdESTimestampContainerMetadata.CarriesOnlyRfc3161Tokens"/> <see langword="false"/>), including
/// the degenerate case where the container's sole entry is an <c>XMLTimeStamp</c> and <see cref="XAdESTimestampContainerMetadata.TokenCount"/>
/// is therefore zero.
/// </summary>
/// <param name="Kind">Which qualifying property the offending occurrence is.</param>
/// <param name="Ordinal">The occurrence's position among <see cref="XAdESQualifyingPropertiesFacts.TimestampContainers"/>.</param>
public sealed record XAdESTimestampContainerNotRfc3161OnlyViolation(XAdESTimestampContainerKind Kind, int Ordinal) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-04";

    /// <inheritdoc/>
    public override string Message =>
        $"{Kind} occurrence #{Ordinal} encapsulates a non-RFC-3161 (XMLTimeStamp) electronic time-stamp entry; " +
        "XAdES baseline signatures shall encapsulate only RFC 3161 electronic time-stamps (ETSI EN 319 132-1 " +
        "V1.3.1 clause 6.3, XA-6.3-04).";
}


/// <summary>
/// Letter n): "Each <c>SignatureTimeStamp</c> element shall contain only one electronic time-stamp" — a
/// <c>SignatureTimeStamp</c> occurrence's own <see cref="XAdESTimestampContainerMetadata.TokenCount"/> is other
/// than 1, narrowing the shared <c>XAdESTimeStampType</c> grammar's own one-or-more cardinality down to exactly
/// one for this property alone (the leaf's <c>XAdESSignatureTimeStampCardinality.HasExactlyOneTimeStamp</c>
/// states the same rule over the decoded property directly; this violation is the same check over the
/// already-projected <see cref="XAdESTimestampContainerMetadata.TokenCount"/> fact).
/// </summary>
/// <param name="Ordinal">The occurrence's position among <see cref="XAdESQualifyingPropertiesFacts.TimestampContainers"/>.</param>
/// <param name="TokenCount">The occurrence's own <see cref="XAdESTimestampContainerMetadata.TokenCount"/>.</param>
public sealed record XAdESSignatureTimeStampCardinalityViolation(int Ordinal, int TokenCount) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-t24-n";

    /// <inheritdoc/>
    public override string Message =>
        $"SignatureTimeStamp occurrence #{Ordinal} carries {TokenCount} RFC 3161 electronic time-stamp(s); " +
        "each SignatureTimeStamp shall contain only one (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, " +
        "XA-6.3-t24, letter n).";
}


/// <summary>
/// Letter m): "...Otherwise the <c>SignaturePolicyStore</c> shall not be incorporated into the XAdES signature"
/// — a <c>SignaturePolicyStore</c> occurrence is present while the signature carries no
/// <c>SignaturePolicyIdentifier</c>, or one whose choice is <c>SignaturePolicyImplied</c> rather than the
/// explicit <c>SignaturePolicyId</c> arm (whose <c>SigPolicyHash</c> child clause 5.2.9.1 makes mandatory on
/// every successful read, so "carries SigPolicyHash" collapses to "the explicit arm is present" — the leaf's
/// <c>XAdESSignaturePolicyStoreLegality.IsSignaturePolicyStoreLegal</c> states the identical predicate).
/// </summary>
public sealed record XAdESSignaturePolicyStoreLegalityViolation : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-t23-m";

    /// <inheritdoc/>
    public override string Message =>
        "SignaturePolicyStore is incorporated without a SignaturePolicyIdentifier carrying the explicit " +
        "SignaturePolicyId choice (with its mandatory SigPolicyHash); otherwise SignaturePolicyStore shall not " +
        "be incorporated (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, XA-6.3-t23, letter m).";
}


/// <summary>
/// Letter k): "One <c>DataObjectFormat</c> shall be generated for each signed data object, except the
/// <c>SignedProperties</c> element..." — <see cref="XAdESQualifyingPropertiesFacts.IsDataObjectFormatCoverageSatisfied"/>
/// is <see langword="false"/>: the signature's <c>DataObjectFormat</c> occurrences do not form an exact
/// bijection with its signed data objects (a required object with none, more than one covering the same
/// object, or one targeting an excluded reference — the leaf's <c>XAdESDataObjectFormatCoverage.TryVerify</c>
/// computes the bijection this fact records the outcome of).
/// </summary>
public sealed record XAdESDataObjectFormatCoverageViolation : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-t08-k";

    /// <inheritdoc/>
    public override string Message =>
        "The signature's DataObjectFormat occurrences do not form the required one-per-signed-data-object " +
        "bijection (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, XA-6.3-t08, letter k).";
}


/// <summary>
/// A Table 2 row's own presence requirement was violated at the evaluated level — either a
/// <see cref="AdESPresence.ShallBePresent"/> row with zero wire occurrences, or a
/// <see cref="AdESPresence.ShallNotBePresent"/> row with at least one.
/// </summary>
/// <param name="Row">The violated row.</param>
/// <param name="Level">The level the evaluation was run against.</param>
/// <param name="IsMissing"><see langword="true"/> for the "shall be present but is absent" arm; <see langword="false"/> for the "shall not be present but is" arm.</param>
public sealed record XAdESRowPresenceViolation(AdESTableRow Row, AdESBaselineLevel Level, bool IsMissing) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Row.RequirementId;

    /// <inheritdoc/>
    public override string Message => IsMissing
        ? $"'{Row.Name}' shall be present at level {Level} (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, {Row.RequirementId}) but no occurrence was found."
        : $"'{Row.Name}' shall not be present at level {Level} (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, {Row.RequirementId}) but at least one occurrence was found.";
}


/// <summary>A Table 2 row's own cardinality requirement was violated at the evaluated level's wire occurrence count.</summary>
/// <param name="Row">The violated row.</param>
/// <param name="Level">The level the evaluation was run against.</param>
/// <param name="Expected">The cardinality Table 2 states for <paramref name="Row"/> at <paramref name="Level"/>.</param>
/// <param name="ActualCount">The wire occurrence count actually observed.</param>
public sealed record XAdESRowCardinalityViolation(AdESTableRow Row, AdESBaselineLevel Level, AdESCardinality Expected, int ActualCount) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Row.RequirementId;

    /// <inheritdoc/>
    public override string Message =>
        $"'{Row.Name}' carries {ActualCount} occurrence(s) at level {Level}, violating its cardinality {Expected} " +
        $"(ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, {Row.RequirementId}).";
}


/// <summary>
/// Letters x)/y): the "Incorporation of validation data for electronic time-stamps" service (XA-6.3-t40) is
/// <see cref="AdESPresence.ShallBeProvided"/> at B-LT/B-LTA but none of its three service-provision options
/// (<c>TimeStampValidationData</c>, embedded-in-token material, <c>AnyValidationData</c>) is satisfied.
/// </summary>
/// <param name="ServiceRow">The unsatisfied service row (<see cref="XAdESBaselineLevelTable.ValidationDataForTimestampsService"/>).</param>
/// <param name="Level">The level the evaluation was run against.</param>
public sealed record XAdESValidationDataServiceViolation(AdESTableRow ServiceRow, AdESBaselineLevel Level) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => ServiceRow.RequirementId;

    /// <inheritdoc/>
    public override string Message =>
        $"The validation-data-for-time-stamps service shall be provided at level {Level} (ETSI EN 319 132-1 " +
        "V1.3.1 clause 6.3, Table 2, XA-6.3-t40, letters x/y) but none of its three service-provision options " +
        "is satisfied.";
}


/// <summary>
/// An unrecognized <c>##other</c> child of <c>UnsignedSignatureProperties</c> was observed — clause
/// 6's baseline-level classification cannot be reached over content Table 2 carries no row for. Also reported,
/// defensively, when <see cref="OccurrenceCountFor"/>'s own dictionary lookup finds a
/// <see cref="XAdESQualifyingPropertiesFacts.SignedPropertyOccurrenceCounts"/>/<see cref="XAdESQualifyingPropertiesFacts.UnsignedPropertyOccurrenceCounts"/>
/// key that names no <see cref="XAdESBaselineLevelTable"/> row at all: a delegate implementation other
/// than the shipped one that mis-keys a property fails <see cref="Check"/> closed on its own input rather than
/// the entry being silently ignored.
/// </summary>
/// <param name="Name">The unrecognized element's local name, exact-character, or the unrecognized dictionary key.</param>
public sealed record XAdESUnknownQualifyingPropertyPresentViolation(string Name) : XAdESRuleViolation
{
    /// <summary>
    /// Gets <c>XA-LIB-01</c>: Table 2 of ETSI EN 319 132-1 V1.3.1 clause 6.3 names no row for content this
    /// shape reports, so no ETSI-assigned identifier covers the disposition. <c>XA-LIB-01</c> is this
    /// library's own fail-closed reading anchored to the clause 6.3 tables — content the tables are silent on
    /// is treated as baseline-disqualifying rather than tacitly permitted — not a requirement ETSI itself states.
    /// </summary>
    public override string RequirementId => "XA-LIB-01";

    /// <inheritdoc/>
    public override string Message =>
        $"'{Name}' is not a qualifying property Table 2 of ETSI EN 319 132-1 V1.3.1 clause 6.3 carries a row " +
        "for; this library treats the signature as unclassifiable as a baseline level while it is present.";
}


/// <summary>
/// A deprecated (V1 or v1.3.2-namespace) qualifying property was observed. Defense-in-depth only — a
/// successfully-extracted <see cref="XAdESQualifyingPropertiesFacts"/> never carries one, since the reader
/// refuses deprecated content at read time (<see cref="XAdESQualifyingPropertiesFacts.DeprecatedPropertyObservations"/>'s
/// own remarks).
/// </summary>
/// <param name="Name">The deprecated element's local name, exact-character.</param>
public sealed record XAdESDeprecatedQualifyingPropertyPresentViolation(string Name) : XAdESRuleViolation
{
    /// <summary>
    /// Gets <c>XA-LIB-02</c>. Unlike <see cref="XAdESUnknownQualifyingPropertyPresentViolation"/>'s disposition,
    /// Table 2 of ETSI EN 319 132-1 V1.3.1 clause 6.3 is not silent here — it pins each of the eight deprecated-V1
    /// qualifying properties individually to <c>ShallNotBePresent</c> under its own row-specific requirement id
    /// (e.g. <see cref="XAdESBaselineLevelTable.SigningCertificate"/>'s own <c>XA-6.3-t07</c>). This
    /// defense-in-depth path reports a bare observed name without resolving it back to the one row among the
    /// eight it names, so citing any single one of those eight ids here would misattribute seven times out of
    /// eight; <c>XA-LIB-02</c> is this library's own identifier for "one of the eight deprecated-V1 rows,
    /// unresolved to which", not an ETSI-assigned id.
    /// </summary>
    public override string RequirementId => "XA-LIB-02";

    /// <inheritdoc/>
    public override string Message =>
        $"'{Name}' is a deprecated qualifying property; Table 2 of ETSI EN 319 132-1 V1.3.1 clause 6.3 pins " +
        "'shall not be present' for each deprecated-V1 property at every level, and this library treats the " +
        "signature as unclassifiable as a baseline level while it is present.";
}


/// <summary>
/// Letters r)/s)/w): an attribute-shaped validation-data property (<c>AttrAuthoritiesCertValues</c>,
/// <c>AttributeCertificateRefsV2</c>, <c>AttributeRevocationRefs</c>, or <c>AttributeRevocationValues</c>) is
/// present but the signature carries no attribute certificate or signed assertion
/// (<see cref="AdESSignerAttributes.Certified"/>/<see cref="AdESSignerAttributes.SignedAssertions"/>) for it to
/// describe — "may be used when a at least an attribute certificate or a signed assertion is incorporated"
/// (the source's own grammar, honored verbatim).
/// </summary>
/// <param name="Row">The gated row.</param>
public sealed record XAdESAttributeMaterialGateViolation(AdESTableRow Row) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Row.RequirementId;

    /// <inheritdoc/>
    public override string Message =>
        $"'{Row.Name}' is present but the signature carries no attribute certificate or signed assertion for " +
        $"it to describe (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, {Row.RequirementId}).";
}


/// <summary>
/// Letter a)'s binding half (NOTE 7): the candidate signing certificate's own digest, taken under the
/// algorithm <c>SigningCertificateV2</c>'s signer reference (<c>Cert[0]</c>) states, does not match that
/// reference's stored digest — the certificate <c>ds:KeyInfo/X509Data/X509Certificate</c> carries is not the
/// one <c>SigningCertificateV2</c> identifies as the signer's own.
/// </summary>
public sealed record XAdESSigningCertificateBindingViolation : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-t01-a";

    /// <inheritdoc/>
    public override string Message =>
        "The candidate signing certificate's digest does not match SigningCertificateV2's own signer reference " +
        "(Cert[0]) (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, XA-6.3-t01, letter a, NOTE 7).";
}


/// <summary>
/// Clause 5.2.7.2's digest rule: a <c>CounterSignature</c> qualifying property's own self-reference — located
/// structurally by <c>Verifiable.Xml</c>'s <c>XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference</c>
/// — carries a <c>ds:DigestValue</c> that does not match the digest, taken under the reference's own declared
/// algorithm, of the complete canonicalized <c>ds:SignatureValue</c> element of the countersigned signature:
/// "the content of the <c>ds:DigestValue</c> in the aforementioned <c>ds:Reference</c> element of the
/// countersignature shall be the base-64 encoded digest of the complete (and canonicalized)
/// <c>ds:SignatureValue</c> element ... of the embedding and countersigned XAdES signature."
/// </summary>
public sealed record XAdESCounterSignatureDigestViolation : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-5.2.7.2";

    /// <inheritdoc/>
    public override string Message =>
        "The CounterSignature's self-reference ds:DigestValue does not match the countersigned signature's " +
        "own complete canonicalized ds:SignatureValue element, or the reference's digest algorithm is not " +
        "one this library's registered digest surface can resolve (ETSI EN 319 132-1 V1.3.1 clause 5.2.7.2).";
}


/// <summary>
/// Letter o)'s expiry half: a <c>SignatureTimeStamp</c> token's generation time falls outside the signing
/// certificate's validity window.
/// </summary>
/// <param name="Ordinal">The token's position among the signature's own <c>SignatureTimeStamp</c>-classed tokens.</param>
/// <param name="GenerationTime">The token's own <c>genTime</c>.</param>
/// <param name="NotAfter">The signing certificate's <c>notAfter</c> instant.</param>
public sealed record XAdESSignatureTimeStampCertificateValidityViolation(int Ordinal, DateTimeOffset GenerationTime, DateTimeOffset NotAfter) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-t24-o";

    /// <inheritdoc/>
    public override string Message =>
        $"SignatureTimeStamp token #{Ordinal} was generated at {GenerationTime:O}, outside the signing " +
        $"certificate's validity window (ends {NotAfter:O}) (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, " +
        "XA-6.3-t24, letter o).";
}


/// <summary>
/// Letter o)'s revocation half: a <c>SignatureTimeStamp</c> token's generation time falls at or after the
/// signing certificate's known revocation instant. Only reachable when the caller supplies a revocation
/// instant — revocation-status determination is chain/revocation-source territory this rule surface never
/// performs on its own.
/// </summary>
/// <param name="Ordinal">The token's position among the signature's own <c>SignatureTimeStamp</c>-classed tokens.</param>
/// <param name="GenerationTime">The token's own <c>genTime</c>.</param>
/// <param name="RevokedAt">The caller-supplied revocation instant.</param>
public sealed record XAdESSignatureTimeStampCertificateRevokedViolation(int Ordinal, DateTimeOffset GenerationTime, DateTimeOffset RevokedAt) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-t24-o";

    /// <inheritdoc/>
    public override string Message =>
        $"SignatureTimeStamp token #{Ordinal} was generated at {GenerationTime:O}, at or after the signing " +
        $"certificate's known revocation instant {RevokedAt:O} (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, " +
        "XA-6.3-t24, letter o).";
}


/// <summary>
/// One SHOULD/SHOULD-NOT-level advisory Table 2's lettered requirements state — never a classification-blocking
/// <see cref="XAdESRuleViolation"/>, mirroring how <c>JAdESLevelRules</c>'s own remarks describe letters
/// e)/i)/k) as "SHOULD/SHOULD-NOT, never enforced as violations": this sum exists so those findings still have
/// a reportable home, distinct from the MUST-level sum, rather than being silently dropped or smuggled into it.
/// A DU-ready closed sum: no external type may derive from it.
/// </summary>
[DebuggerDisplay("{RequirementId}: {Message}")]
public abstract record XAdESRuleObservation
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected XAdESRuleObservation()
    {
    }


    /// <summary>Gets the XA-* requirement identifier this observation cites.</summary>
    public abstract string RequirementId { get; }

    /// <summary>Gets a human-readable statement of the advisory finding.</summary>
    public abstract string Message { get; }
}


/// <summary>
/// Letter q): two entries among the signature's own merged <c>CertificateValues</c>/<c>AttrAuthoritiesCertValues</c>/
/// <c>AnyValidationData</c> certificate material (<see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificates"/>)
/// carry byte-identical DER content — "Duplication of certificate values SHOULD be avoided".
/// </summary>
/// <param name="FirstIndex">The first duplicate's position in <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificates"/>.</param>
/// <param name="SecondIndex">The second duplicate's position.</param>
public sealed record XAdESCertificateValueDuplicationObservation(int FirstIndex, int SecondIndex) : XAdESRuleObservation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-t25-q";

    /// <inheritdoc/>
    public override string Message =>
        $"Certificate entries #{FirstIndex} and #{SecondIndex} carry byte-identical DER content; duplication " +
        "of certificate values SHOULD be avoided (ETSI EN 319 132-1 V1.3.1 clause 6.3, Table 2, XA-6.3-t25, letter q).";
}


/// <summary>
/// Letter v): two entries among the signature's own merged <c>RevocationValues</c>/<c>AttributeRevocationValues</c>/
/// <c>AnyValidationData</c> revocation-status material carry byte-identical DER content — "Duplication of
/// certificate status values SHOULD be avoided".
/// </summary>
/// <param name="FirstIndex">The first duplicate's position in its own list.</param>
/// <param name="SecondIndex">The second duplicate's position.</param>
/// <param name="IsCrl">
/// <see langword="true"/> when the duplicate lies in <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificateRevocationLists"/>;
/// <see langword="false"/> when it lies in <see cref="XAdESQualifyingPropertiesFacts.EmbeddedOcspResponses"/>.
/// </param>
public sealed record XAdESRevocationValueDuplicationObservation(int FirstIndex, int SecondIndex, bool IsCrl) : XAdESRuleObservation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-t32-v";

    /// <inheritdoc/>
    public override string Message =>
        $"{(IsCrl ? "CRL" : "OCSP response")} entries #{FirstIndex} and #{SecondIndex} carry byte-identical DER " +
        "content; duplication of certificate status values SHOULD be avoided (ETSI EN 319 132-1 V1.3.1 clause " +
        "6.3, Table 2, XA-6.3-t32/t26, letter v).";
}


/// <summary>
/// Which <c>refs</c>-family Annex A qualifying property a <see cref="XAdESReferencesValidationDataConsistencyViolation"/>
/// names.
/// </summary>
public enum XAdESRefsFamilyDigestSurface
{
    /// <summary>The <c>CompleteCertificateRefsV2</c> qualifying property (Annex A.1.1).</summary>
    CompleteCertificateRefs,

    /// <summary>The <c>AttributeCertificateRefsV2</c> qualifying property (Annex A.1.3).</summary>
    AttributeCertificateRefs,

    /// <summary>The <c>CompleteRevocationRefs</c> qualifying property (Annex A.1.2).</summary>
    CompleteRevocationRefs,

    /// <summary>The <c>AttributeRevocationRefs</c> qualifying property (Annex A.1.4).</summary>
    AttributeRevocationRefs
}


/// <summary>
/// Which kind of validation-data material a <see cref="XAdESReferencesValidationDataConsistencyViolation"/> could
/// not resolve.
/// </summary>
public enum XAdESReferenceMaterialKind
{
    /// <summary>A certificate reference could not be resolved to any candidate certificate.</summary>
    Certificate,

    /// <summary>A CRL reference could not be resolved to any candidate CRL.</summary>
    Crl,

    /// <summary>An OCSP reference could not be resolved to any candidate OCSP response.</summary>
    Ocsp
}


/// <summary>
/// Annex A.1.1/A.1.2/A.1.3/A.1.4's own closing conditional-<c>shall</c> paragraph's CONSEQUENT: once the
/// paragraph's antecedent fires (<see cref="XAdESQualifyingPropertiesFacts.CertificateValidationDataTriggered"/>/
/// <see cref="XAdESQualifyingPropertiesFacts.RevocationValidationDataTriggered"/>), a ref digest that resolves to
/// no candidate value elsewhere in the signature — <see cref="XAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/>'s
/// own async pass, the JAdES <c>CheckReferencesResolveToValidationDataAsync</c>/CB-A.1.1-30 precedent one format
/// over.
/// </summary>
/// <param name="Surface">Which <c>refs</c>-family property carried the unresolved entry.</param>
/// <param name="MaterialKind">Which kind of material the entry names.</param>
[DebuggerDisplay("XAdESReferencesValidationDataConsistencyViolation: {Surface}/{MaterialKind}")]
public sealed record XAdESReferencesValidationDataConsistencyViolation(
    XAdESRefsFamilyDigestSurface Surface, XAdESReferenceMaterialKind MaterialKind) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Surface switch
    {
        XAdESRefsFamilyDigestSurface.CompleteCertificateRefs => "XA-A.1.1",
        XAdESRefsFamilyDigestSurface.AttributeCertificateRefs => "XA-A.1.3",
        XAdESRefsFamilyDigestSurface.CompleteRevocationRefs => "XA-A.1.2",
        XAdESRefsFamilyDigestSurface.AttributeRevocationRefs => "XA-A.1.4",
        _ => throw new NotSupportedException($"Unknown {nameof(XAdESRefsFamilyDigestSurface)} value '{Surface}'.")
    };

    /// <inheritdoc/>
    public override string Message =>
        $"A {Surface} entry's referenced {MaterialKind} material was not found present elsewhere in the " +
        $"signature (ETSI EN 319 132-1 V1.3.1, Annex {RequirementId[3..]}).";
}


/// <summary>
/// Annex A.1.2/A.1.4's own "shall indicate the same time as the referenced OCSP response's own <c>ProducedAt</c>
/// field": a resolved <c>OCSPRef</c> entry's <c>OCSPIdentifier/ProducedAt</c> disagrees with the actual candidate
/// response's own decoded <c>producedAt</c> field (<see cref="XAdESLevelRules.CheckOcspProducedAtConsistencyAsync"/>).
/// Reachable only once resolution itself succeeds — an unresolved reference is
/// <see cref="XAdESReferencesValidationDataConsistencyViolation"/>'s own finding.
/// </summary>
/// <param name="Surface">Which <c>refs</c>-family property carried the disagreeing entry.</param>
/// <param name="Ordinal">The entry's position among the surface's own <c>OCSPRef</c> entries.</param>
public sealed record XAdESOcspProducedAtConsistencyViolation(XAdESRefsFamilyDigestSurface Surface, int Ordinal) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Surface == XAdESRefsFamilyDigestSurface.CompleteRevocationRefs ? "XA-A.1.2" : "XA-A.1.4";

    /// <inheritdoc/>
    public override string Message =>
        $"{Surface} OCSPRef entry #{Ordinal}'s own ProducedAt does not match its resolved OCSP response's own " +
        $"producedAt field (ETSI EN 319 132-1 V1.3.1, Annex {RequirementId[3..]}).";
}


/// <summary>
/// Clause 5.2.9 NOTE 3: "the retrieved policy document is trustworthy only if its digest ... matches the
/// [signed] <c>SigPolicyHash</c>" — a caller-supplied policy document's digest, taken under
/// <c>SigPolicyHash</c>'s own declared algorithm, does not match the signed <c>SigPolicyHash</c> value
/// (<see cref="XAdESLevelRules.CheckSignaturePolicyDocumentDigestAsync"/>).
/// </summary>
public sealed record XAdESSignaturePolicyDocumentDigestViolation : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-5.2.9-NOTE3";

    /// <inheritdoc/>
    public override string Message =>
        "The caller-supplied signature-policy document's digest does not match the signed SigPolicyHash value " +
        "(ETSI EN 319 132-1 V1.3.1 clause 5.2.9 NOTE 3).";
}


/// <summary>
/// Clause 5.5.3's XA-5.5.3-13 validation procedure step 2): a <c>RenewedDigestsV2</c> entry's own
/// <c>OriginalRefDigest</c> — a digest VALUE, not a URI — resolves to no candidate <c>ds:Reference</c> among the
/// signature's signed <c>ds:Manifest</c>(s) (<see cref="XAdESLevelRules.CheckRenewedDigestsV2ReferenceLookupAsync"/>).
/// </summary>
/// <param name="Ordinal">The entry's position among the property's own <c>RecomputedDigestValue</c> entries.</param>
public sealed record XAdESRenewedDigestsV2ReferenceUnresolvedViolation(int Ordinal) : XAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-5.5.3-13";

    /// <inheritdoc/>
    public override string Message =>
        $"RenewedDigestsV2 entry #{Ordinal}'s own OriginalRefDigest does not resolve to any candidate " +
        "ds:Reference among the signature's signed ds:Manifest(s) (ETSI EN 319 132-1 V1.3.1 clause 5.5.3, " +
        "XA-5.5.3-13, step 2).";
}


/// <summary>
/// Letter y)'s own SHOULD: "the validation data for electronic time-stamps should be included either in the
/// <c>TimeStampValidationData</c> [...], or the <c>AnyValidationData</c> [...]" — the validation-data-for-
/// time-stamps service (XA-6.3-t40) was satisfied ONLY via the embedded-in-time-stamp option
/// (<see cref="XAdESLevelRuleContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/>), never via
/// <c>TimeStampValidationData</c>/<c>AnyValidationData</c>. SHOULD-level: an <see cref="XAdESRuleObservation"/>,
/// never a <see cref="XAdESRuleViolation"/> — mirrors the CB-AdES precedent's
/// <c>AdESTableRow.PreferredServiceProvisionOptionRequirementId(s)</c> hook.
/// </summary>
public sealed record XAdESValidationDataServicePreferenceObservation : XAdESRuleObservation
{
    /// <inheritdoc/>
    public override string RequirementId => "XA-6.3-t40-y";

    /// <inheritdoc/>
    public override string Message =>
        "The validation-data-for-time-stamps service was satisfied only via the embedded-in-time-stamp option; " +
        "TimeStampValidationData or AnyValidationData SHOULD be preferred (ETSI EN 319 132-1 V1.3.1 clause 6.3, " +
        "Table 2, XA-6.3-t40, letter y).";
}


/// <summary>
/// The inputs <see cref="XAdESLevelRules.Check"/>/<see cref="XAdESLevelRules.EnsureConformant"/> need — the
/// candidate/target level plus the already-extracted, format-neutral facts (the format-facts seam's own output). No
/// closure capture: every input travels through this value, mirroring <c>JAdESLevelRuleContext</c>'s own shape.
/// </summary>
[DebuggerDisplay("XAdESLevelRuleContext(Level={Level})")]
public readonly record struct XAdESLevelRuleContext
{
    /// <summary>
    /// Gets the <see cref="AdESBaselineLevel"/> this evaluation targets — the level a caller is either
    /// augmenting TO, or the level a caller believes a parsed signature CLAIMS to be at. This rule surface does
    /// not itself classify a signature's achieved level, mirroring <c>JAdESLevelRules</c>'s/<c>CBAdESLevelRules</c>'s
    /// own identical scope note: a caller wanting the strictest read evaluates this surface once per candidate
    /// level and reports accordingly.
    /// </summary>
    public required AdESBaselineLevel Level { get; init; }

    /// <summary>
    /// Gets the signature's extracted, format-neutral qualifying-properties facts (<see cref="XAdESSignatureFacts.CreateSeam"/>'s
    /// own delegate output). BORROWED for the duration of the call — this rule surface never disposes it.
    /// </summary>
    public required XAdESQualifyingPropertiesFacts Facts { get; init; }

    /// <summary>
    /// Gets whether at least one electronic time-stamp token elsewhere in the signature carries its own
    /// embedded certificate/revocation validation material — the letter-x/y "embedded in the electronic
    /// time-stamp itself" service-provision option (XA-6.3-t42). This rule surface never inspects a token's own
    /// encoding to derive this fact itself; the caller (the validation orchestrator) supplies the aggregate,
    /// reduced via OR across every token it inspected. Defaults to <see langword="false"/>.
    /// </summary>
    public bool AnyTimestampTokenCarriesEmbeddedValidationMaterial { get; init; }
}


/// <summary>
/// The XAdES analogue of <c>JAdESLevelRules</c>/<c>CBAdESLevelRules</c> (the rule-evaluation
/// surface <see cref="XAdESBaselineLevelTable"/>'s own remarks point to): evaluates a signature's already-
/// extracted, format-neutral facts
/// (<see cref="XAdESQualifyingPropertiesFacts"/>) against every Table 2 row (<see cref="XAdESBaselineLevelTable.Rows"/>)
/// at a candidate/target <see cref="AdESBaselineLevel"/>, table-driven rather than a hand-maintained per-property
/// switch — Table 2's own registry IS the source of truth this engine walks, unlike CB-AdES/JAdES's own
/// switch-per-<c>etsiU</c>-kind shape, because the format-neutral occurrence inventory
/// (<see cref="XAdESQualifyingPropertiesFacts.SignedPropertyOccurrenceCounts"/>/<see cref="XAdESQualifyingPropertiesFacts.UnsignedPropertyOccurrenceCounts"/>)
/// is already keyed by the exact row <see cref="AdESTableRow.Name"/> strings.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Placement: Pki, not a JCose-style intermediate layer.</strong> CB-AdES's/JAdES's own level-rule
/// surfaces live one layer above <c>Verifiable.Cryptography.Pki</c> (<c>src/Verifiable.JCose</c>) because they
/// consume decoded CBOR/JSON header model types that live there. XAdES has no such layer: this library keeps the
/// qualifying-properties model and reader inside <c>Verifiable.Xml</c>, which <c>Verifiable.Cryptography</c>
/// never references, so this engine consumes only the ALREADY-PROJECTED, XML-type-free
/// <see cref="XAdESQualifyingPropertiesFacts"/> shape the format-facts seam produces — a shape that already lives in
/// this assembly. No new layer is warranted.
/// </para>
/// <para>
/// <strong>Write-strict/read-tolerant, exactly like the precedent.</strong> A soft-negative
/// (<see cref="AdESPresence.ShouldNotBePresent"/>, Table 2's own <c>"*"</c>) presence is never reported as a
/// violation on read. Only <see cref="AdESPresence.ShallBePresent"/> (absent) and
/// <see cref="AdESPresence.ShallNotBePresent"/> (present) failures, <see cref="AdESPresence.ShallBeProvided"/>
/// (the service row, satisfied-by-any-SPO), and every row's own cardinality bound are ever reported by
/// <see cref="Check"/>.
/// </para>
/// <para>
/// <strong>Four rows never reached by <see cref="Check"/>'s main loop.</strong> The four
/// <see cref="AdESTableRowKind.XmlDsigElement"/> rows (t01-t04, <c>ds:KeyInfo/X509Data</c> through
/// <c>ds:Reference/ds:Transforms</c>) are XMLDSIG-core facts a consumer reads off the signature's own
/// <c>ds:SignedInfo</c>/<c>ds:KeyInfo</c> directly, outside <see cref="XAdESQualifyingPropertiesFacts"/>'s own
/// qualifying-property-only inventory (that shape's own disclosed boundary, its remarks) — not evaluated here.
/// <c>DataObjectFormat</c>'s five own child rows (t09-t13: <c>Description</c>, <c>ObjectIdentifier</c>,
/// <c>MimeType</c>, <c>Encoding</c>, the <c>ObjectReference</c> attribute) are counted PER-<c>DataObjectFormat</c>-OCCURRENCE,
/// not per-signature, so the inventory carries no signal for them; letter l)'s own shipped check
/// (<c>XAdESDataObjectFormatChildCardinalityTests</c>) already covers that content. Both exclusions are a
/// disclosed boundary, not a silently-narrowed one.
/// </para>
/// <para>
/// <strong>Letters k), m), n) fold into <see cref="Check"/> itself.</strong> Each has a
/// dedicated shipped leaf-side check consuming the DECODED <c>Verifiable.Xml</c> model directly
/// (<c>XAdESDataObjectFormatCoverage</c>, <c>XAdESSignaturePolicyStoreLegality</c>,
/// <c>XAdESSignatureTimeStampCardinality</c>); the composition-root delegate now runs the first of those over
/// the read signature and carries the RESULT as <see cref="XAdESQualifyingPropertiesFacts.IsDataObjectFormatCoverageSatisfied"/>,
/// the other two are equivalently restated over facts this shape already carries
/// (<see cref="XAdESQualifyingPropertiesFacts.SignaturePolicy"/>/<see cref="XAdESValidationDataCounts.SignaturePolicyStoreCount"/>
/// for letter m; <see cref="XAdESTimestampContainerMetadata.TokenCount"/> for letter n) — so <see cref="Check"/>
/// reports a <see cref="XAdESDataObjectFormatCoverageViolation"/>/<see cref="XAdESSignaturePolicyStoreLegalityViolation"/>/
/// <see cref="XAdESSignatureTimeStampCardinalityViolation"/> rather than staying silent.
/// </para>
/// <para>
/// <strong>Letters d), f), l), z) still checkable elsewhere only; not re-implemented here.</strong> Each has a
/// dedicated shipped leaf-side check consuming the DECODED <c>Verifiable.Xml</c> model directly
/// (<c>XAdESCanonicalizationManagement</c>, <c>XAdESReferenceTransformDispositionTests</c>,
/// <c>XAdESDataObjectFormatChildCardinalityTests</c>, <c>XAdESArchiveTimeStampTests</c>) that this facts shape
/// carries no signal for (letter l)'s own t09-t13 child rows are excluded by the paragraph above; letters
/// d)/f)/z) concern <c>ds:</c>-core/XMLDSIG content this shape's own qualifying-property-only inventory does
/// not reach) — re-checking would need a decoded model this crypto-free engine never takes.
/// </para>
/// <para>
/// <strong>Letters r)/s)/w) fold into <see cref="Check"/> itself.</strong> Their gate ("MAY be used only when
/// at least an attribute certificate or a signed assertion is incorporated") is structurally a conditional
/// MUST-NOT, the same shape <c>JAdESLevelRules</c>'s own letter-h analogue (<c>JAdESAttributeReferencesGateViolation</c>)
/// reports as a hard violation, not an advisory — <see cref="XAdESLevelRuleContext.Facts"/>'s own
/// <see cref="XAdESQualifyingPropertiesFacts.SignerRole"/> already carries the antecedent
/// (<see cref="AdESSignerAttributes.Certified"/>/<see cref="AdESSignerAttributes.SignedAssertions"/>).
/// </para>
/// <para>
/// <strong>Letters a), o), q), v) are separate methods, not folded into <see cref="Check"/>.</strong> Letter a)'s
/// binding half (<see cref="CheckSigningCertificateBindingAsync"/>) needs an async digest computation and a
/// caller-supplied candidate certificate <see cref="XAdESQualifyingPropertiesFacts"/> never carries (the
/// <c>ds:KeyInfo/X509Data/X509Certificate</c> bytes are XMLDSIG-core content, the same disclosed boundary as the
/// four <c>ds:</c>-native rows). Letter o)'s expiry half (<see cref="CheckSignatureTimeStampsWithinSigningCertificateValidity"/>)
/// needs each <c>SignatureTimeStamp</c> token's own parsed <c>genTime</c>, which needs opening the RFC 3161
/// token through <see cref="TimestampTokenInfo.ReadFromTokenAsync"/> — a registered-delegate composition
/// concern this rule surface stays neutral to by taking already-resolved <see cref="DateTimeOffset"/> values
/// instead, mirroring <c>CBAdESLevelRules</c>'s own "composed by the validation orchestrator while a timestamp
/// token is still open" design for its per-token coverage rule. Letters q)/v) (<see cref="CheckValidationDataDuplication"/>)
/// are SHOULD-level and return <see cref="XAdESRuleObservation"/>s, never <see cref="XAdESRuleViolation"/>s.
/// </para>
/// <para>
/// <strong><see cref="Promote"/> is the <see cref="Verified{T}"/> tail.</strong>
/// It mints a <see cref="Verified{XAdESQualifyingPropertiesFacts}"/> when, and only when, ALL THREE of a
/// "checked, conformant, and identity-bound XAdES verification result" hold: <see cref="Check"/> finds zero
/// MUST-level violations, the caller's own clause 5.2.7.4 cryptographic verification
/// (<see cref="XAdESSignatureFacts.VerifyCryptographyAsync"/>'s outcome) concluded
/// <see cref="SignatureCryptographicOutcome.Verified"/>, AND the caller supplies an already-minted
/// <see cref="BoundProvenance"/> witnessing the SAME facts (<see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>,
/// XAdES's own light identify+verify+bind path). Table-2 conformance alone is never sufficient — a document can
/// satisfy every presence/cardinality rule without its <c>ds:SignatureValue</c> ever having been checked — and
/// neither is a checked-but-unbound cryptographic outcome alone: <c>ds:KeyInfo</c> naming a certificate the
/// signature's own <c>SigningCertificateV2</c> never committed to is exactly the forgery the gate closes, so
/// minting proof-of-verification without it would misstate what was actually established.
/// </para>
/// </remarks>
public static class XAdESLevelRules
{
    private static readonly HashSet<string> DataObjectFormatChildRequirementIds =
    [
        "XA-6.3-t09", "XA-6.3-t10", "XA-6.3-t11", "XA-6.3-t12", "XA-6.3-t13"
    ];

    /// <summary>This closed vocabulary: every <see cref="AdESTableRow.Name"/> <see cref="XAdESBaselineLevelTable.Rows"/> registers, the only names <see cref="CheckOccurrenceDictionaryKeys"/> accepts.</summary>
    private static readonly HashSet<string> KnownRowNames = BuildKnownRowNames();

    private static HashSet<string> BuildKnownRowNames()
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        IReadOnlyList<AdESTableRow> rows = XAdESBaselineLevelTable.Rows;
        for(int i = 0; i < rows.Count; ++i)
        {
            names.Add(rows[i].Name);
        }

        return names;
    }


    /// <summary>
    /// Evaluates every MUST-level Table 2 rule against <paramref name="context"/> and returns every violation
    /// found. Never throws on non-conformant content — only a missing required context field is a
    /// caller-contract violation (an exception), not a conformance judgment.
    /// </summary>
    /// <param name="context">The level-rule inputs; see <see cref="XAdESLevelRuleContext"/>.</param>
    /// <returns>Every violation found, in Table 2's own row order; empty when fully conformant.</returns>
    /// <exception cref="ArgumentNullException"><see cref="XAdESLevelRuleContext.Facts"/> is <see langword="null"/> (a default <paramref name="context"/>).</exception>
    public static IReadOnlyList<XAdESRuleViolation> Check(XAdESLevelRuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context.Facts);

        var violations = new List<XAdESRuleViolation>();
        XAdESQualifyingPropertiesFacts facts = context.Facts;
        AdESBaselineLevel level = context.Level;

        CheckQualifyingPropertiesBinding(facts.Discovery, violations);
        CheckTimestampContainers(facts.TimestampContainers, violations);

        if(!facts.IsDataObjectFormatCoverageSatisfied)
        {
            violations.Add(new XAdESDataObjectFormatCoverageViolation());
        }

        bool isSignaturePolicyStoreLegal = facts.SignaturePolicy is { IsImplied: false };
        if(facts.ValidationData.SignaturePolicyStoreCount > 0 && !isSignaturePolicyStoreLegal)
        {
            violations.Add(new XAdESSignaturePolicyStoreLegalityViolation());
        }

        IReadOnlyList<AdESTableRow> rows = XAdESBaselineLevelTable.Rows;
        for(int i = 0; i < rows.Count; ++i)
        {
            AdESTableRow row = rows[i];
            switch(row.Kind)
            {
                case AdESTableRowKind.XmlDsigElement:
                    //t01-t04: outside this facts shape's own qualifying-property-only inventory -- see the
                    //type remarks.
                    continue;

                case AdESTableRowKind.ServiceProvisionOption:
                    //Evaluated as part of their owning Service row below, never independently.
                    continue;

                case AdESTableRowKind.Service:
                    CheckService(row, facts, level, context.AnyTimestampTokenCarriesEmbeddedValidationMaterial, violations);
                    continue;
            }

            if(DataObjectFormatChildRequirementIds.Contains(row.RequirementId))
            {
                //t09-t13: counted per-DataObjectFormat-occurrence, not per-signature -- see the type remarks.
                continue;
            }

            int count = OccurrenceCountFor(row, facts);
            CheckPresenceAndCardinality(row, count, level, violations);
        }

        CheckAttributeMaterialGates(facts, violations);
        CheckOccurrenceDictionaryKeys(facts, violations);

        for(int i = 0; i < facts.UnknownPropertyObservations.Count; ++i)
        {
            violations.Add(new XAdESUnknownQualifyingPropertyPresentViolation(facts.UnknownPropertyObservations[i]));
        }

        for(int i = 0; i < facts.DeprecatedPropertyObservations.Count; ++i)
        {
            violations.Add(new XAdESDeprecatedQualifyingPropertyPresentViolation(facts.DeprecatedPropertyObservations[i]));
        }

        return violations;
    }


    /// <summary>
    /// The augmentation-path throw posture: calls <see cref="Check"/> and raises <see cref="ArgumentException"/>
    /// naming the first violated requirement the moment any level rule fails. Trusted-caller-input semantics —
    /// mirrors <c>JAdESLevelRules.EnsureConformant</c> exactly.
    /// </summary>
    /// <param name="context">The level-rule inputs.</param>
    /// <exception cref="ArgumentException">At least one level rule is violated; the message names the first violated requirement.</exception>
    public static void EnsureConformant(XAdESLevelRuleContext context)
    {
        IReadOnlyList<XAdESRuleViolation> violations = Check(context);
        if(violations.Count == 0)
        {
            return;
        }

        XAdESRuleViolation first = violations[0];
        string suffix = violations.Count > 1
            ? $" ({violations.Count - 1} further level violation(s) also apply.)"
            : string.Empty;

        throw new ArgumentException($"{first.RequirementId}: {first.Message}{suffix}", nameof(context));
    }


    /// <summary>
    /// The <see cref="Verified{T}"/> promotion point: mints a <see cref="Verified{XAdESQualifyingPropertiesFacts}"/> wrapping <paramref name="context"/>'s
    /// own <see cref="XAdESLevelRuleContext.Facts"/> when, and only when, ALL THREE hold — <paramref name="cryptographicVerification"/>
    /// concluded <see cref="SignatureCryptographicOutcome.Verified"/>, <see cref="Check"/> finds zero violations
    /// at <paramref name="context"/>'s own <see cref="XAdESLevelRuleContext.Level"/>, AND <paramref name="signerBinding"/>
    /// witnesses <paramref name="context"/>'s own <see cref="XAdESLevelRuleContext.Facts"/> (<see cref="Verified{T}.TryCreateBound"/>'s
    /// own witness check) — <see langword="null"/> otherwise. A caller that also wants the specific violations
    /// calls <see cref="Check"/> directly — this method never discards them, it simply does not carry them
    /// (mirroring the family's own null-checked-<see cref="Verified{T}"/>-optional convention <see cref="Verified{T}"/>'s
    /// own remarks name: <c>JAdESValidationResult.Verified</c>, <c>DidCommSignedVerificationResult.Verified</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>The forwarder guardrail.</strong> This method takes an ALREADY-MINTED
    /// <see cref="BoundProvenance"/> — it never accepts a caller-authored <see cref="SignatureCryptographicVerification"/>
    /// and calls a binding gate itself. A public promotion point that binds from a caller's own outcome record
    /// would let any assembly holding a <see cref="SignatureCryptographicVerification"/> forge one (the carrier's
    /// public <see langword="init"/> and every certificate/reference/digest type it touches are all public, so an
    /// attacker could author both sides of the recompute). <see cref="BoundProvenance"/> is the safe shape
    /// precisely because the gate that produces it (<see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>)
    /// is <see langword="internal"/> — a non-granted assembly cannot construct a <see cref="BoundProvenance"/>, so
    /// it cannot call this overload of <see cref="Promote"/> at all. The gate call itself belongs in the XAdES
    /// verify COMPOSITION (today the test-side delegates, since no <c>src/</c> composition root exists), inside
    /// the <c>InternalsVisibleTo</c> boundary — never here.
    /// </para>
    /// <para>
    /// <strong>Carrier lifetime.</strong> <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/> reads the
    /// <see cref="SignatureCryptographicVerification.SigningCertificate"/> the caller's own crypto verify ran
    /// under — pooled memory owned by the <see cref="XAdESQualifyingPropertiesFacts"/>/<c>SignatureFacts</c> that
    /// surfaced it. <paramref name="signerBinding"/> must therefore be minted, and this method called, WHILE that
    /// owning facts instance is still alive; a disposed carrier yields a fail-closed refusal at the gate rather
    /// than a spoof, but calling this late is a silent-refusal source, not a security hole.
    /// </para>
    /// <para>
    /// <strong>No new <c>InternalsVisibleTo</c> grant needed.</strong> <see cref="Verified{T}"/>'s constructor is
    /// <see langword="private"/> — reachable from nowhere, not even this assembly — but its two mints,
    /// <see cref="Verified{T}.CreateAsserted"/> and <see cref="Verified{T}.TryCreateBound"/>, are
    /// <see langword="internal"/>, reachable from any type declared in the SAME assembly without a grant — this
    /// method lives in <c>Verifiable.Cryptography</c> itself, the assembly <see cref="Verified{T}"/> is declared
    /// in. This differs from the JAdES precedent (<c>JAdESValidationResult</c>, one assembly up in
    /// <c>Verifiable.JCose</c>), which needed an explicit grant — XAdES's own placement of the level-rule engine
    /// directly in Pki (a consequence of no intermediate model-owning layer) means the promotion point sits
    /// where the mints are already visible.
    /// </para>
    /// <para>
    /// <strong>Ownership: borrowed, not transferred.</strong> <see cref="XAdESLevelRuleContext.Facts"/> stays
    /// borrowed exactly as <see cref="Check"/> already documents it — the returned <see cref="Verified{T}"/>
    /// wraps the SAME reference the caller already owns and disposes; minting a promotion transfers no
    /// ownership and allocates no new disposable resource. A caller that disposes
    /// <see cref="XAdESLevelRuleContext.Facts"/> invalidates any <see cref="Verified{T}"/> still held over it,
    /// exactly as it would invalidate any other reference to the same disposed instance.
    /// </para>
    /// </remarks>
    /// <param name="context">The level-rule inputs — the same shape <see cref="Check"/> takes.</param>
    /// <param name="cryptographicVerification">
    /// The clause 5.2.7.4 cryptographic-verification outcome (<see cref="XAdESSignatureFacts.VerifyCryptographyAsync"/>'s
    /// own return value) — checked here for <see cref="SignatureCryptographicOutcome.Verified"/> independently of
    /// <paramref name="signerBinding"/>'s own validity, so Table 2/crypto gating stays this method's own job while
    /// identity gating lives entirely in the gate that produced <paramref name="signerBinding"/>.
    /// </param>
    /// <param name="signerBinding">
    /// The already-minted identity binding for <paramref name="context"/>'s own <see cref="XAdESLevelRuleContext.Facts"/>
    /// — produced by a <see cref="BoundProvenance"/> gate (<see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>
    /// for XAdES's own light identify+verify+bind path) BEFORE calling this method, while the owning
    /// facts instance is still alive (see the type remarks on carrier lifetime). REQUIRED — this method never
    /// binds internally (the forwarder guardrail above); the recorded <see cref="KeyId"/> on the minted
    /// <see cref="Verified{T}"/> comes from the gate's own recomputed digest of the identified certificate,
    /// numerically identical to the pre-reconciliation wire-claim label (now deleted) whenever the binding
    /// holds — whenever it does not, there is no mint at all, rather than a mint over an unverified label.
    /// </param>
    /// <returns>
    /// A <see cref="Verified{XAdESQualifyingPropertiesFacts}"/> when the cryptographic outcome, Table 2
    /// conformance, and <paramref name="signerBinding"/>'s own witness all hold; otherwise <see langword="null"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <see cref="XAdESLevelRuleContext.Facts"/>, <paramref name="cryptographicVerification"/>, or
    /// <paramref name="signerBinding"/> is <see langword="null"/>.
    /// </exception>
    public static Verified<XAdESQualifyingPropertiesFacts>? Promote(
        XAdESLevelRuleContext context,
        SignatureCryptographicVerification cryptographicVerification,
        BoundProvenance signerBinding)
    {
        ArgumentNullException.ThrowIfNull(context.Facts);
        ArgumentNullException.ThrowIfNull(cryptographicVerification);
        ArgumentNullException.ThrowIfNull(signerBinding);

        if(cryptographicVerification.Outcome != SignatureCryptographicOutcome.Verified)
        {
            return null;
        }

        IReadOnlyList<XAdESRuleViolation> violations = Check(context);
        if(violations.Count != 0)
        {
            return null;
        }

        return Verified<XAdESQualifyingPropertiesFacts>.TryCreateBound(context.Facts, signerBinding);
    }


    /// <summary>
    /// Letters q)/v): finds byte-identical duplicate entries within <paramref name="facts"/>'s own merged
    /// certificate and revocation-status validation-data lists. SHOULD-level: returns advisory
    /// <see cref="XAdESRuleObservation"/>s, never <see cref="XAdESRuleViolation"/>s.
    /// </summary>
    /// <param name="facts">The signature's extracted facts.</param>
    /// <returns>Every duplicate pair found; empty when none exists.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="facts"/> is <see langword="null"/>.</exception>
    public static IReadOnlyList<XAdESRuleObservation> CheckValidationDataDuplication(XAdESQualifyingPropertiesFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        var observations = new List<XAdESRuleObservation>();
        FindCertificateDuplicates(facts.EmbeddedCertificates, observations);
        FindRevocationDuplicates(facts.EmbeddedCertificateRevocationLists, isCrl: true, observations);
        FindRevocationDuplicates(facts.EmbeddedOcspResponses, isCrl: false, observations);

        return observations;
    }


    /// <summary>
    /// Letter a)'s binding half (NOTE 7)'s shared core: resolves <paramref name="signerReference"/>'s own
    /// declared digest algorithm, refuses when its own stored digest's length disagrees with that
    /// algorithm's own output length, recomputes <paramref name="candidateSigningCertificate"/>'s digest under
    /// it through the house digest surface
    /// (<see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>),
    /// and compares it byte-for-byte against the reference's own stored digest — the ONE implementation
    /// <see cref="CheckSigningCertificateBindingAsync"/> and <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>
    /// both delegate to, so the recompute recipe exists exactly once (registry-delegates-to-parameter: never
    /// duplicate the body).
    /// </summary>
    /// <param name="signerReference">The located signer reference (<see cref="SigningCertificateReference.IsSignerReference"/>), or <see langword="null"/> when none was found.</param>
    /// <param name="candidateSigningCertificate">The candidate signing certificate's DER encoding.</param>
    /// <param name="pool">The memory pool the transient digest buffer is rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// The recomputed digest, owned by the caller, when <paramref name="signerReference"/> is present, its own
    /// digest algorithm resolves, its own stored digest length agrees with that algorithm's own output length
    /// and the recompute matches; otherwise <see langword="null"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    internal static async ValueTask<DigestValue?> TryMatchSigningCertificateDigestAsync(
        SigningCertificateReference? signerReference,
        ReadOnlyMemory<byte> candidateSigningCertificate,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(signerReference is null || signerReference.CertificateDigest is not DigestValue referenceDigest)
        {
            return null;
        }

        if(PkiDigestAlgorithm.FromOid(signerReference.DigestAlgorithm.Oid) is not PkiDigestAlgorithm resolvedAlgorithm
            || referenceDigest.Length != resolvedAlgorithm.OutputByteLength)
        {
            //The recompute length comes from the RESOLVED algorithm, never the wire-supplied
            //referenceDigest.Length -- a reference whose length disagrees with its own stated algorithm is
            //refused here, fail-closed, rather than reaching ComputeDigestAsync with a mismatched buffer size
            //(which would throw ArgumentException instead of returning null).
            return null;
        }

        DigestValue candidateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            candidateSigningCertificate, resolvedAlgorithm.OutputByteLength, resolvedAlgorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!candidateDigest.AsReadOnlySpan().SequenceEqual(referenceDigest.AsReadOnlySpan()))
        {
            candidateDigest.Dispose();

            return null;
        }

        return candidateDigest;
    }


    /// <summary>
    /// Letter a)'s binding half (NOTE 7): the shared core (<see cref="TryMatchSigningCertificateDigestAsync"/>)
    /// applied to <paramref name="signingCertificateDigests"/>'s own signer entry.
    /// </summary>
    /// <param name="signingCertificateDigests">The <c>SigningCertificateV2</c> facts (<see cref="XAdESQualifyingPropertiesFacts.SigningCertificateDigests"/>).</param>
    /// <param name="candidateSigningCertificate">The candidate signing certificate's DER encoding — resolved by the caller from <c>ds:KeyInfo/X509Data/X509Certificate</c> (outside this facts shape's own reach).</param>
    /// <param name="pool">The memory pool the transient digest buffer is rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// A single <see cref="XAdESSigningCertificateBindingViolation"/> when no signer reference is present, its
    /// digest algorithm is unresolvable, or the digests do not match; empty when the binding holds.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="signingCertificateDigests"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<IReadOnlyList<XAdESRuleViolation>> CheckSigningCertificateBindingAsync(
        IReadOnlyList<XAdESSigningCertificateDigestFact> signingCertificateDigests,
        ReadOnlyMemory<byte> candidateSigningCertificate,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signingCertificateDigests);
        ArgumentNullException.ThrowIfNull(pool);

        var violations = new List<XAdESRuleViolation>();

        SigningCertificateReference? signerReference = null;
        for(int i = 0; i < signingCertificateDigests.Count; ++i)
        {
            if(signingCertificateDigests[i].Reference.IsSignerReference)
            {
                signerReference = signingCertificateDigests[i].Reference;
                break;
            }
        }

        using DigestValue? candidateDigest = await TryMatchSigningCertificateDigestAsync(
            signerReference, candidateSigningCertificate, pool, cancellationToken).ConfigureAwait(false);

        if(candidateDigest is null)
        {
            violations.Add(new XAdESSigningCertificateBindingViolation());
        }

        return violations;
    }


    /// <summary>
    /// Clause 5.2.7.2's digest rule, the "house digest" half: <paramref name="digestAlgorithm"/>/
    /// <paramref name="expectedDigest"/> are the located self-reference's own <c>DigestMethod</c>/<c>DigestValue</c>
    /// (<c>Verifiable.Xml</c>'s <c>XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference</c> locates
    /// the reference structurally; <c>XmlReferenceProcessing.TryComputeDigestInput</c>, rooted at the
    /// countersignature's OWN embedded signature and that reference's own ordinal, produces
    /// <paramref name="candidateSignatureValueOctets"/> — the composition root's job, since building either
    /// needs the leaf's XML types this crypto-free-of-XML assembly never references). Reuses
    /// <see cref="ResolveCandidateIndexAsync(AlgorithmIdentifier, DigestValue, IReadOnlyList{ReadOnlyMemory{byte}}, BaseMemoryPool, CancellationToken)"/>
    /// with a single-element candidate list — no new digest logic.
    /// </summary>
    /// <param name="digestAlgorithm">The located self-reference's own declared <c>DigestMethod</c> algorithm.</param>
    /// <param name="expectedDigest">The located self-reference's own stored <c>DigestValue</c>.</param>
    /// <param name="candidateSignatureValueOctets">The countersigned signature's own canonicalized <c>ds:SignatureValue</c> element octets.</param>
    /// <param name="pool">The memory pool the transient digest buffer is rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A single <see cref="XAdESCounterSignatureDigestViolation"/> when the algorithm is unresolvable or the digests disagree; empty when they agree.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="expectedDigest"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<IReadOnlyList<XAdESRuleViolation>> CheckCounterSignatureDigestAsync(
        AlgorithmIdentifier digestAlgorithm,
        DigestValue expectedDigest,
        ReadOnlyMemory<byte> candidateSignatureValueOctets,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedDigest);
        ArgumentNullException.ThrowIfNull(pool);

        var violations = new List<XAdESRuleViolation>();
        int matchIndex = await ResolveCandidateIndexAsync(digestAlgorithm, expectedDigest, [candidateSignatureValueOctets], pool, cancellationToken).ConfigureAwait(false);
        if(matchIndex < 0)
        {
            violations.Add(new XAdESCounterSignatureDigestViolation());
        }

        return violations;
    }


    /// <summary>
    /// Letter o): checks every already-resolved <c>SignatureTimeStamp</c> token generation time against the
    /// signing certificate's validity window (the expiry half, always checked) and, when supplied, its known
    /// revocation instant (the revocation half). The caller resolves both inputs beforehand — see the type
    /// remarks for why this method stays synchronous.
    /// </summary>
    /// <param name="signatureTimestampGenerationTimes">Every <c>SignatureTimeStamp</c>-classed token's own resolved <c>genTime</c>, in any order.</param>
    /// <param name="signingCertificateValidity">The signing certificate's validity window (<see cref="CertificateValidityPeriod.TryRead"/>).</param>
    /// <param name="revokedAt">The certificate's known revocation instant, or <see langword="null"/> when unknown — the revocation half is skipped entirely rather than assumed conformant.</param>
    /// <returns>Every violated token, in input order; empty when every token was generated within validity (and, when known, before revocation).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="signatureTimestampGenerationTimes"/> or <paramref name="signingCertificateValidity"/> is <see langword="null"/>.</exception>
    public static IReadOnlyList<XAdESRuleViolation> CheckSignatureTimeStampsWithinSigningCertificateValidity(
        IReadOnlyList<DateTimeOffset> signatureTimestampGenerationTimes,
        CertificateValidityPeriod signingCertificateValidity,
        DateTimeOffset? revokedAt = null)
    {
        ArgumentNullException.ThrowIfNull(signatureTimestampGenerationTimes);
        ArgumentNullException.ThrowIfNull(signingCertificateValidity);

        var violations = new List<XAdESRuleViolation>();
        for(int i = 0; i < signatureTimestampGenerationTimes.Count; ++i)
        {
            DateTimeOffset generationTime = signatureTimestampGenerationTimes[i];
            if(generationTime < signingCertificateValidity.NotBefore || generationTime > signingCertificateValidity.NotAfter)
            {
                violations.Add(new XAdESSignatureTimeStampCertificateValidityViolation(i, generationTime, signingCertificateValidity.NotAfter));
            }

            if(revokedAt is DateTimeOffset revocationInstant && generationTime >= revocationInstant)
            {
                violations.Add(new XAdESSignatureTimeStampCertificateRevokedViolation(i, generationTime, revocationInstant));
            }
        }

        return violations;
    }


    /// <summary>
    /// Annex A.1.1/A.1.2/A.1.3/A.1.4's own closing conditional-<c>shall</c> paragraph, both halves wired
    /// together: the antecedent (<see cref="XAdESQualifyingPropertiesFacts.CertificateValidationDataTriggered"/>/
    /// <see cref="XAdESQualifyingPropertiesFacts.RevocationValidationDataTriggered"/>, computed by the leaf's
    /// <c>XAdESValidationDataTrigger</c> at the composition root) gates the consequent — every ref digest of
    /// <see cref="XAdESQualifyingPropertiesFacts.CompleteCertificateRefs"/>/<see cref="XAdESQualifyingPropertiesFacts.AttributeCertificateRefs"/>/
    /// <see cref="XAdESQualifyingPropertiesFacts.CompleteRevocationCrlRefs"/>/<see cref="XAdESQualifyingPropertiesFacts.CompleteRevocationOcspRefs"/>/
    /// <see cref="XAdESQualifyingPropertiesFacts.AttributeRevocationCrlRefs"/>/<see cref="XAdESQualifyingPropertiesFacts.AttributeRevocationOcspRefs"/>
    /// digested and compared against <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificates"/>/
    /// <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificateRevocationLists"/>/
    /// <see cref="XAdESQualifyingPropertiesFacts.EmbeddedOcspResponses"/> — already the flattened union of every
    /// <c>CertificateValues</c>/<c>RevocationValues</c>/<c>AttrAuthoritiesCertValues</c>/<c>AttributeRevocationValues</c>/
    /// <c>AnyValidationData</c>/<c>TimeStampValidationData</c> candidate the paragraph names (see those members'
    /// own remarks), so no separate candidate-gathering step is needed here. Mirrors
    /// <see cref="CheckSigningCertificateBindingAsync"/>'s shape and the JAdES
    /// <c>JAdESLevelRules.CheckReferencesResolveToValidationDataAsync</c>/CB-A.1.1-30 precedent.
    /// </summary>
    /// <param name="facts">The signature's extracted facts.</param>
    /// <param name="pool">The memory pool transient digest buffers are rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Every unresolved reference, as a <see cref="XAdESReferencesValidationDataConsistencyViolation"/>; empty when every trigger's candidates all resolve or no trigger fires.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="facts"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<IReadOnlyList<XAdESRuleViolation>> CheckReferencesResolveToValidationDataAsync(
        XAdESQualifyingPropertiesFacts facts, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(pool);

        var violations = new List<XAdESRuleViolation>();

        if(facts.CertificateValidationDataTriggered)
        {
            await ResolveCertificateRefsAsync(XAdESRefsFamilyDigestSurface.CompleteCertificateRefs, facts.CompleteCertificateRefs, facts.EmbeddedCertificates, pool, violations, cancellationToken).ConfigureAwait(false);
            await ResolveCertificateRefsAsync(XAdESRefsFamilyDigestSurface.AttributeCertificateRefs, facts.AttributeCertificateRefs, facts.EmbeddedCertificates, pool, violations, cancellationToken).ConfigureAwait(false);
        }

        if(facts.RevocationValidationDataTriggered)
        {
            await ResolveCrlRefsAsync(XAdESRefsFamilyDigestSurface.CompleteRevocationRefs, facts.CompleteRevocationCrlRefs, facts.EmbeddedCertificateRevocationLists, pool, violations, cancellationToken).ConfigureAwait(false);
            await ResolveCrlRefsAsync(XAdESRefsFamilyDigestSurface.AttributeRevocationRefs, facts.AttributeRevocationCrlRefs, facts.EmbeddedCertificateRevocationLists, pool, violations, cancellationToken).ConfigureAwait(false);
            await ResolveOcspRefsAsync(XAdESRefsFamilyDigestSurface.CompleteRevocationRefs, facts.CompleteRevocationOcspRefs, facts.EmbeddedOcspResponses, pool, violations, cancellationToken).ConfigureAwait(false);
            await ResolveOcspRefsAsync(XAdESRefsFamilyDigestSurface.AttributeRevocationRefs, facts.AttributeRevocationOcspRefs, facts.EmbeddedOcspResponses, pool, violations, cancellationToken).ConfigureAwait(false);
        }

        return violations;
    }


    /// <summary>
    /// Annex A.1.2/A.1.4's own "shall indicate the same time" cross-check: for every <c>OCSPRef</c> entry that
    /// carries a <c>DigestAlgAndValue</c> (A.1.2's own "should be included" — an entry without one cannot be
    /// unambiguously identified, so it is silently skipped, "cannot check, so no violation"), resolves the
    /// candidate response by digest (the same resolution <see cref="CheckReferencesResolveToValidationDataAsync"/>
    /// performs; an entry whose digest does not resolve at all is THAT method's own finding, not this one's) and
    /// compares its <c>OCSPIdentifier/ProducedAt</c> against the resolved response's own decoded <c>producedAt</c>
    /// field via <see cref="OcspResponseVerification.TryReadProducedAt"/>.
    /// </summary>
    /// <param name="facts">The signature's extracted facts.</param>
    /// <param name="pool">The memory pool transient digest buffers are rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Every disagreeing entry, as a <see cref="XAdESOcspProducedAtConsistencyViolation"/>; empty when every resolvable entry agrees.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="facts"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<IReadOnlyList<XAdESRuleViolation>> CheckOcspProducedAtConsistencyAsync(
        XAdESQualifyingPropertiesFacts facts, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(pool);

        var violations = new List<XAdESRuleViolation>();
        await CheckOcspProducedAtConsistencyAsync(XAdESRefsFamilyDigestSurface.CompleteRevocationRefs, facts.CompleteRevocationOcspRefs, facts.EmbeddedOcspResponses, pool, violations, cancellationToken).ConfigureAwait(false);
        await CheckOcspProducedAtConsistencyAsync(XAdESRefsFamilyDigestSurface.AttributeRevocationRefs, facts.AttributeRevocationOcspRefs, facts.EmbeddedOcspResponses, pool, violations, cancellationToken).ConfigureAwait(false);

        return violations;
    }


    /// <summary>
    /// Clause 5.2.9 NOTE 3: "the retrieved policy document is trustworthy only if its digest value, computed
    /// with the algorithm indicated, matches the value of the <c>SigPolicyHash</c> element" — digests
    /// <paramref name="policyDocument"/> under <c>SigPolicyHash</c>'s own declared algorithm and compares it
    /// against the signed value. The document itself is the caller's own — this method never fetches one (the
    /// house no-HTTP-in-library rule); it only performs the comparison.
    /// </summary>
    /// <param name="signaturePolicy">The <c>SignaturePolicyIdentifier</c> facts, or <see langword="null"/> when absent — nothing to check.</param>
    /// <param name="policyDocument">The caller-resolved policy document octets.</param>
    /// <param name="pool">The memory pool the transient digest buffer is rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A single <see cref="XAdESSignaturePolicyDocumentDigestViolation"/> when the digests disagree or the algorithm is unresolvable; empty when <paramref name="signaturePolicy"/> is absent/implied (no <c>SigPolicyHash</c> to check) or the digests agree.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<IReadOnlyList<XAdESRuleViolation>> CheckSignaturePolicyDocumentDigestAsync(
        XAdESSignaturePolicyFact? signaturePolicy, ReadOnlyMemory<byte> policyDocument, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var violations = new List<XAdESRuleViolation>();
        if(signaturePolicy is not { IsImplied: false, HashAlgorithm: AlgorithmIdentifier algorithm, Hash: DigestValue hash })
        {
            return violations;
        }

        int matchIndex = await ResolveCandidateIndexAsync(algorithm, hash, [policyDocument], pool, cancellationToken).ConfigureAwait(false);
        if(matchIndex < 0)
        {
            violations.Add(new XAdESSignaturePolicyDocumentDigestViolation());
        }

        return violations;
    }


    /// <summary>
    /// Clause 5.5.3's XA-5.5.3-13 step 2): resolves each <paramref name="originalRefDigests"/> entry's own
    /// digest against <paramref name="candidateReferenceDigestInputs"/> — the "house digest" half of the
    /// digest-VALUE-addressed <c>ds:Reference</c> lookup the leaf's own <c>XAdESRenewedDigestsV2Processing.TryComputeOriginalRefDigestInput</c>
    /// supplies the INPUT octets for (looped over every candidate <c>ds:Reference</c> of every signed
    /// <c>ds:Manifest</c> at the composition root, since building that candidate set needs the leaf's XML types
    /// this crypto-free-of-XML assembly never references — the composition-root-
    /// side resolution this method itself implements).
    /// </summary>
    /// <param name="originalRefDigests">Every <c>RecomputedDigestValue</c> entry's own algorithm/<c>OriginalRefDigest</c> pair, in wire order.</param>
    /// <param name="candidateReferenceDigestInputs">Every candidate <c>ds:Reference</c>'s already-canonicalized digest-input octets, composition-root-supplied.</param>
    /// <param name="pool">The memory pool transient digest buffers are rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Every unresolved entry, as a <see cref="XAdESRenewedDigestsV2ReferenceUnresolvedViolation"/>; empty when every entry resolves.</returns>
    /// <exception cref="ArgumentNullException">Any parameter is <see langword="null"/>.</exception>
    public static async ValueTask<IReadOnlyList<XAdESRuleViolation>> CheckRenewedDigestsV2ReferenceLookupAsync(
        IReadOnlyList<(AlgorithmIdentifier Algorithm, DigestValue OriginalRefDigest)> originalRefDigests,
        IReadOnlyList<ReadOnlyMemory<byte>> candidateReferenceDigestInputs,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(originalRefDigests);
        ArgumentNullException.ThrowIfNull(candidateReferenceDigestInputs);
        ArgumentNullException.ThrowIfNull(pool);

        var violations = new List<XAdESRuleViolation>();
        for(int i = 0; i < originalRefDigests.Count; ++i)
        {
            (AlgorithmIdentifier algorithm, DigestValue digest) = originalRefDigests[i];
            int matchIndex = await ResolveCandidateIndexAsync(algorithm, digest, candidateReferenceDigestInputs, pool, cancellationToken).ConfigureAwait(false);
            if(matchIndex < 0)
            {
                violations.Add(new XAdESRenewedDigestsV2ReferenceUnresolvedViolation(i));
            }
        }

        return violations;
    }


    /// <summary>
    /// Letter y): reports <see cref="XAdESValidationDataServicePreferenceObservation"/> when the validation-data-
    /// for-time-stamps service (XA-6.3-t40) is satisfied ONLY through the embedded-in-time-stamp option — SHOULD-
    /// level, computed independently of <see cref="Check"/> since it needs to distinguish WHICH service-provision
    /// option satisfied the service, not merely whether the service was satisfied.
    /// </summary>
    /// <param name="context">The level-rule inputs; the same shape <see cref="Check"/> takes.</param>
    /// <returns>A single <see cref="XAdESValidationDataServicePreferenceObservation"/> when the service is satisfied only via the embedded option; empty otherwise (including when the service is unsatisfied or B-B/B-T, where letter y does not apply).</returns>
    /// <exception cref="ArgumentNullException"><see cref="XAdESLevelRuleContext.Facts"/> is <see langword="null"/> (a default <paramref name="context"/>).</exception>
    public static IReadOnlyList<XAdESRuleObservation> CheckValidationDataServicePreference(XAdESLevelRuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context.Facts);

        AdESTableRow serviceRow = XAdESBaselineLevelTable.ValidationDataForTimestampsService;
        if(serviceRow.Presence.At(context.Level) != AdESPresence.ShallBeProvided)
        {
            return [];
        }

        bool isSatisfiedOnlyByEmbedded = !context.Facts.ValidationDataForTimestampsHasContent && context.AnyTimestampTokenCarriesEmbeddedValidationMaterial;

        return isSatisfiedOnlyByEmbedded ? [new XAdESValidationDataServicePreferenceObservation()] : [];
    }


    private static async ValueTask CheckOcspProducedAtConsistencyAsync(
        XAdESRefsFamilyDigestSurface surface, IReadOnlyList<XAdESOcspReferenceFact> ocspRefs, IReadOnlyList<PkiCertificateMemory> candidates,
        BaseMemoryPool pool, List<XAdESRuleViolation> violations, CancellationToken cancellationToken)
    {
        var index = new CandidateDigestIndex(candidates, pool);
        for(int i = 0; i < ocspRefs.Count; ++i)
        {
            XAdESOcspReferenceFact ocspRef = ocspRefs[i];
            if(!ocspRef.HasDigestAlgAndValue || ocspRef.DigestAlgorithm is not AlgorithmIdentifier algorithm || ocspRef.Digest is not DigestValue digest)
            {
                continue;
            }

            int matchIndex = await index.ResolveAsync(algorithm, digest, cancellationToken).ConfigureAwait(false);
            if(matchIndex < 0)
            {
                continue;
            }

            if(!OcspResponseVerification.TryReadProducedAt(candidates[matchIndex].AsReadOnlyMemory(), out DateTimeOffset actualProducedAt)
                || ocspRef.ProducedAt != actualProducedAt)
            {
                violations.Add(new XAdESOcspProducedAtConsistencyViolation(surface, i));
            }
        }
    }


    private static async ValueTask ResolveCertificateRefsAsync(
        XAdESRefsFamilyDigestSurface surface, IReadOnlyList<XAdESCertificateReferenceDigestFact> refs, IReadOnlyList<PkiCertificateMemory> candidates,
        BaseMemoryPool pool, List<XAdESRuleViolation> violations, CancellationToken cancellationToken)
    {
        var index = new CandidateDigestIndex(candidates, pool);
        for(int i = 0; i < refs.Count; ++i)
        {
            int matchIndex = await index.ResolveAsync(refs[i].DigestAlgorithm, refs[i].Digest, cancellationToken).ConfigureAwait(false);
            if(matchIndex < 0)
            {
                violations.Add(new XAdESReferencesValidationDataConsistencyViolation(surface, XAdESReferenceMaterialKind.Certificate));
            }
        }
    }


    private static async ValueTask ResolveCrlRefsAsync(
        XAdESRefsFamilyDigestSurface surface, IReadOnlyList<XAdESCrlReferenceFact> refs, IReadOnlyList<PkiCertificateMemory> candidates,
        BaseMemoryPool pool, List<XAdESRuleViolation> violations, CancellationToken cancellationToken)
    {
        var index = new CandidateDigestIndex(candidates, pool);
        for(int i = 0; i < refs.Count; ++i)
        {
            int matchIndex = await index.ResolveAsync(refs[i].DigestAlgorithm, refs[i].Digest, cancellationToken).ConfigureAwait(false);
            if(matchIndex < 0)
            {
                violations.Add(new XAdESReferencesValidationDataConsistencyViolation(surface, XAdESReferenceMaterialKind.Crl));
            }
        }
    }


    private static async ValueTask ResolveOcspRefsAsync(
        XAdESRefsFamilyDigestSurface surface, IReadOnlyList<XAdESOcspReferenceFact> refs, IReadOnlyList<PkiCertificateMemory> candidates,
        BaseMemoryPool pool, List<XAdESRuleViolation> violations, CancellationToken cancellationToken)
    {
        var index = new CandidateDigestIndex(candidates, pool);
        for(int i = 0; i < refs.Count; ++i)
        {
            if(refs[i].DigestAlgorithm is not AlgorithmIdentifier algorithm || refs[i].Digest is not DigestValue digest)
            {
                //A.1.2's own "should be included" -- an OCSPRef without a digest cannot be resolved, so it is
                //silently skipped rather than treated as either resolved or unresolved.
                continue;
            }

            int matchIndex = await index.ResolveAsync(algorithm, digest, cancellationToken).ConfigureAwait(false);
            if(matchIndex < 0)
            {
                violations.Add(new XAdESReferencesValidationDataConsistencyViolation(surface, XAdESReferenceMaterialKind.Ocsp));
            }
        }
    }


    /// <summary>
    /// A digest-value-keyed lookup over one candidate list (<see cref="PkiCertificateMemory"/> entries such as
    /// <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificates"/>), built lazily and cached per distinct
    /// digest algorithm: each of the four family-pass callers (<see cref="ResolveCertificateRefsAsync"/>,
    /// <see cref="ResolveCrlRefsAsync"/>, <see cref="ResolveOcspRefsAsync"/>, the private
    /// <see cref="CheckOcspProducedAtConsistencyAsync(XAdESRefsFamilyDigestSurface, IReadOnlyList{XAdESOcspReferenceFact}, IReadOnlyList{PkiCertificateMemory}, BaseMemoryPool, List{XAdESRuleViolation}, CancellationToken)"/>)
    /// builds one instance over its own candidate list and resolves every reference's digest against it, turning
    /// what was one full candidate-list digest pass PER reference (O(references × candidates)) into one
    /// candidate-list digest pass PER distinct algorithm plus one dictionary lookup per reference
    /// (O(references + candidates)).
    /// </summary>
    private sealed class CandidateDigestIndex(IReadOnlyList<PkiCertificateMemory> candidates, BaseMemoryPool pool)
    {
        private readonly Dictionary<string, Dictionary<string, int>> _digestIndexByAlgorithmOid = new(StringComparer.Ordinal);

        /// <summary>
        /// Resolves <paramref name="digest"/>, declared under <paramref name="algorithm"/>, to the index of the
        /// first candidate whose own digest under that algorithm matches byte-for-byte — building and caching
        /// that algorithm's candidate-digest dictionary on first use, fails closed (returns -1, never throws)
        /// when <paramref name="algorithm"/> is not one this library's registered digest surface can resolve
        /// (<see cref="PkiDigestAlgorithm.FromOid"/>).
        /// </summary>
        public async ValueTask<int> ResolveAsync(AlgorithmIdentifier algorithm, DigestValue digest, CancellationToken cancellationToken)
        {
            if(PkiDigestAlgorithm.FromOid(algorithm.Oid) is not PkiDigestAlgorithm resolvedAlgorithm)
            {
                return -1;
            }

            if(!_digestIndexByAlgorithmOid.TryGetValue(algorithm.Oid, out Dictionary<string, int>? digestToIndex))
            {
                digestToIndex = await BuildIndexAsync(resolvedAlgorithm, cancellationToken).ConfigureAwait(false);
                _digestIndexByAlgorithmOid[algorithm.Oid] = digestToIndex;
            }

            return digestToIndex.TryGetValue(Convert.ToHexStringLower(digest.AsReadOnlySpan()), out int matchIndex) ? matchIndex : -1;
        }


        private async ValueTask<Dictionary<string, int>> BuildIndexAsync(PkiDigestAlgorithm algorithm, CancellationToken cancellationToken)
        {
            var digestToIndex = new Dictionary<string, int>(candidates.Count, StringComparer.Ordinal);
            for(int i = 0; i < candidates.Count; ++i)
            {
                using DigestValue candidateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                    candidates[i].AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                //First-match-wins mirrors the unmemoized loop's own linear-scan semantics: a digest collision
                //across candidates keeps resolving to the earliest one.
                digestToIndex.TryAdd(Convert.ToHexStringLower(candidateDigest.AsReadOnlySpan()), i);
            }

            return digestToIndex;
        }
    }


    /// <summary>The candidate-list overload of <c>ResolveCandidateIndexAsync</c> used where candidates are not (yet) <see cref="PkiCertificateMemory"/>-wrapped — e.g. the leaf-computed <c>ds:Reference</c> digest-input octets <see cref="CheckRenewedDigestsV2ReferenceLookupAsync"/> resolves against.</summary>
    private static async ValueTask<int> ResolveCandidateIndexAsync(
        AlgorithmIdentifier algorithm, DigestValue digest, IReadOnlyList<ReadOnlyMemory<byte>> candidates, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        Tag? tag = PkiDigestAlgorithm.FromOid(algorithm.Oid)?.DigestTag;
        if(tag is null)
        {
            return -1;
        }

        for(int i = 0; i < candidates.Count; ++i)
        {
            using DigestValue candidateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                candidates[i], digest.Length, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            if(candidateDigest.AsReadOnlySpan().SequenceEqual(digest.AsReadOnlySpan()))
            {
                return i;
            }
        }

        return -1;
    }


    private static void CheckService(
        AdESTableRow serviceRow, XAdESQualifyingPropertiesFacts facts, AdESBaselineLevel level,
        bool anyTimestampTokenCarriesEmbeddedValidationMaterial, List<XAdESRuleViolation> violations)
    {
        if(serviceRow.Presence.At(level) != AdESPresence.ShallBeProvided)
        {
            //B-B/B-T: the "*" soft-negative -- never enforced on read, the same write-strict/read-tolerant
            //posture every ShouldNotBePresent cell gets in CheckPresenceAndCardinality.
            return;
        }

        //Measured on CONTENT, not container presence -- an empty TimeStampValidationData/AnyValidationData
        //occurrence does not satisfy this service (clause 6.3 letter x), clause 6.1 c)).
        bool isSatisfied = facts.ValidationDataForTimestampsHasContent || anyTimestampTokenCarriesEmbeddedValidationMaterial;
        if(!isSatisfied)
        {
            violations.Add(new XAdESValidationDataServiceViolation(serviceRow, level));
        }
    }


    private static void CheckPresenceAndCardinality(AdESTableRow row, int count, AdESBaselineLevel level, List<XAdESRuleViolation> violations)
    {
        AdESLevelRuleEngine.CheckRow(row, count, level, includeCardinality: true, XAdESRowFinding, violations);
    }


    private static XAdESRuleViolation XAdESRowFinding(AdESTableRow row, AdESBaselineLevel level, AdESRowCheckKind kind, AdESCardinality? cardinalityExpected, int actualCount) => kind switch
    {
        AdESRowCheckKind.MissingRequired => new XAdESRowPresenceViolation(row, level, IsMissing: true),
        AdESRowCheckKind.PresentButForbidden => new XAdESRowPresenceViolation(row, level, IsMissing: false),
        AdESRowCheckKind.CardinalityMismatch when cardinalityExpected is AdESCardinality expected => new XAdESRowCardinalityViolation(row, level, expected, actualCount),
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown AdES row check kind for XAdES Table 2 evaluation.")
    };


    private static int OccurrenceCountFor(AdESTableRow row, XAdESQualifyingPropertiesFacts facts)
    {
        int signed = facts.SignedPropertyOccurrenceCounts.TryGetValue(row.Name, out int signedCount) ? signedCount : 0;
        int unsigned = facts.UnsignedPropertyOccurrenceCounts.TryGetValue(row.Name, out int unsignedCount) ? unsignedCount : 0;

        //A row's name appears in at most one of the two dictionaries by construction (a qualifying property is
        //either signed or unsigned, never both), so summing is a safe zero-cost union rather than a real
        //addition across two live counts.
        return signed + unsigned;
    }


    /// <summary>
    /// The wrapping BLOCKER: reports every failed clause 4.3.1/4.4.1/4.4.2 binding pin
    /// <paramref name="discovery"/> carries, plus clause 6.3's XA-6.3-02 indirect-incorporation MUST
    /// over the same fact.
    /// </summary>
    private static void CheckQualifyingPropertiesBinding(XAdESDiscoveryFact discovery, List<XAdESRuleViolation> violations)
    {
        if(!discovery.HasQualifyingProperties)
        {
            violations.Add(new XAdESQualifyingPropertiesBindingViolation(XAdESQualifyingPropertiesBindingFailure.NoDirectlyIncorporatedQualifyingProperties));
        }

        if(!discovery.TargetResolvedToSignature)
        {
            violations.Add(new XAdESQualifyingPropertiesBindingViolation(XAdESQualifyingPropertiesBindingFailure.TargetNotBoundToSignature));
        }

        if(!discovery.SignedPropertiesReferencePresent)
        {
            violations.Add(new XAdESQualifyingPropertiesBindingViolation(XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceMissing));
        }

        if(!discovery.SignedPropertiesReferenceResolvedToDiscoveredNode)
        {
            violations.Add(new XAdESQualifyingPropertiesBindingViolation(XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceNotBoundToDiscoveredNode));
        }

        if(discovery.QualifyingPropertiesReferenceCount > 0)
        {
            violations.Add(new XAdESIndirectIncorporationViolation(discovery.QualifyingPropertiesReferenceCount));
        }
    }


    /// <summary>
    /// Clause 6.3's XA-6.3-04 and letter n) (XA-6.3-t24-n), both keyed off the same per-occurrence inventory:
    /// every container whose entries are not ALL RFC 3161 tokens, and every <c>SignatureTimeStamp</c> occurrence
    /// whose own token count is not exactly one.
    /// </summary>
    private static void CheckTimestampContainers(IReadOnlyList<XAdESTimestampContainerMetadata> containers, List<XAdESRuleViolation> violations)
    {
        for(int i = 0; i < containers.Count; ++i)
        {
            XAdESTimestampContainerMetadata container = containers[i];
            if(!container.CarriesOnlyRfc3161Tokens)
            {
                violations.Add(new XAdESTimestampContainerNotRfc3161OnlyViolation(container.Kind, i));
            }

            if(container.Kind == XAdESTimestampContainerKind.SignatureTimeStamp && container.TokenCount != 1)
            {
                violations.Add(new XAdESSignatureTimeStampCardinalityViolation(i, container.TokenCount));
            }
        }
    }


    /// <summary>
    /// Validates every <see cref="XAdESQualifyingPropertiesFacts.SignedPropertyOccurrenceCounts"/>/
    /// <see cref="XAdESQualifyingPropertiesFacts.UnsignedPropertyOccurrenceCounts"/> dictionary key is a known
    /// <see cref="XAdESBaselineLevelTable"/> row <see cref="AdESTableRow.Name"/> — a key that names no row is
    /// reported rather than silently ignored, so a delegate that mis-keys a property cannot evade a
    /// <see cref="AdESPresence.ShallNotBePresent"/> row by keying into the wrong scope or an unrecognized name.
    /// </summary>
    private static void CheckOccurrenceDictionaryKeys(XAdESQualifyingPropertiesFacts facts, List<XAdESRuleViolation> violations)
    {
        CheckKeys(facts.SignedPropertyOccurrenceCounts, violations);
        CheckKeys(facts.UnsignedPropertyOccurrenceCounts, violations);

        static void CheckKeys(IReadOnlyDictionary<string, int> occurrences, List<XAdESRuleViolation> collected)
        {
            foreach(string key in occurrences.Keys)
            {
                if(!KnownRowNames.Contains(key))
                {
                    collected.Add(new XAdESUnknownQualifyingPropertyPresentViolation(key));
                }
            }
        }
    }


    private static void CheckAttributeMaterialGates(XAdESQualifyingPropertiesFacts facts, List<XAdESRuleViolation> violations)
    {
        bool hasAttributeMaterial = facts.SignerRole is AdESSignerAttributes role && (role.Certified is not null || role.SignedAssertions is not null);
        if(hasAttributeMaterial)
        {
            return;
        }

        CheckGate(XAdESBaselineLevelTable.AttrAuthoritiesCertValues, facts.ValidationData.AttrAuthoritiesCertValuesCount, violations);
        CheckGate(XAdESBaselineLevelTable.AttributeCertificateRefsV2, facts.ValidationData.AttributeCertificateRefsV2Count, violations);
        CheckGate(XAdESBaselineLevelTable.AttributeRevocationRefs, facts.ValidationData.AttributeRevocationRefsCount, violations);
        CheckGate(XAdESBaselineLevelTable.AttributeRevocationValues, facts.ValidationData.AttributeRevocationValuesCount, violations);

        static void CheckGate(AdESTableRow row, int count, List<XAdESRuleViolation> collected)
        {
            if(count > 0)
            {
                collected.Add(new XAdESAttributeMaterialGateViolation(row));
            }
        }
    }


    /// <summary>
    /// Groups <paramref name="items"/> by <see cref="PkiCertificateMemory.Equals(PkiCertificateMemory?)"/> — the
    /// same equality the nested-loop shape this replaces compared pairwise — in one O(n) pass (a hash lookup per
    /// item rather than a byte-for-byte comparison against every other item), then reports every within-group
    /// index pair, the sibling of the digest-keyed <see cref="CandidateDigestIndex"/> the reference-resolve loops
    /// above already use.
    /// </summary>
    /// <param name="items">The candidate list to find duplicates within.</param>
    /// <returns>Every group of two or more equal indices, each entry's own indices ascending.</returns>
    private static List<List<int>> GroupDuplicateIndices(IReadOnlyList<PkiCertificateMemory> items)
    {
        var indicesByValue = new Dictionary<PkiCertificateMemory, List<int>>();
        for(int i = 0; i < items.Count; ++i)
        {
            if(!indicesByValue.TryGetValue(items[i], out List<int>? indices))
            {
                indices = [];
                indicesByValue[items[i]] = indices;
            }

            indices.Add(i);
        }

        var duplicateGroups = new List<List<int>>();
        foreach(List<int> indices in indicesByValue.Values)
        {
            if(indices.Count > 1)
            {
                duplicateGroups.Add(indices);
            }
        }

        return duplicateGroups;
    }


    private static void FindCertificateDuplicates(IReadOnlyList<PkiCertificateMemory> items, List<XAdESRuleObservation> collected)
    {
        foreach(List<int> indices in GroupDuplicateIndices(items))
        {
            for(int a = 0; a < indices.Count; ++a)
            {
                for(int b = a + 1; b < indices.Count; ++b)
                {
                    collected.Add(new XAdESCertificateValueDuplicationObservation(indices[a], indices[b]));
                }
            }
        }
    }


    private static void FindRevocationDuplicates(IReadOnlyList<PkiCertificateMemory> items, bool isCrl, List<XAdESRuleObservation> collected)
    {
        foreach(List<int> indices in GroupDuplicateIndices(items))
        {
            for(int a = 0; a < indices.Count; ++a)
            {
                for(int b = a + 1; b < indices.Count; ++b)
                {
                    collected.Add(new XAdESRevocationValueDuplicationObservation(indices[a], indices[b], isCrl));
                }
            }
        }
    }
}
