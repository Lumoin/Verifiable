using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The Table 1 (clause 6.3) row registry — all 30 rows PA-6.3-T01..T30 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see>, transcribed verbatim (zoom-verified) and exposed
/// as static getters (the <c>CBAdESBaselineLevelTable</c> exemplar shape) plus lookup helpers over <see cref="Rows"/>.
/// PDF/CMS-free: this class carries only the presence/cardinality/reference/letters DATA clause 6.3 states, never
/// a wire encoding or a rule-evaluation engine — <see cref="PAdESSignatureCreation"/>/<see cref="PAdESSignatureValidation"/>/
/// <see cref="PAdESSignatureAugmentation"/>/<see cref="PAdESLifecycleValidation"/> enforce the structurally
/// checkable rows/letters; this registry documents every row and letter, enforced or caller-attested alike.
/// </summary>
/// <remarks>
/// <strong>9 of 30 rows are [CAdES-deferred]</strong> (T02-T07, T09, T10, T24): pure by-reference reuse of a
/// signed/unsigned CMS attribute ETSI EN 319 122-1 clause 5 already defines, already modeled/tested by the
/// shipped CAdES surface (RP-3, leg 2 §6.3's own reconciliation note). The remaining 21 rows are PDF-native
/// (an ISO 32000-1 Signature Dictionary key) or PAdES's own clause 5.4 DSS/VRI/DocTimeStamp material.
/// </remarks>
public static class PAdESBaselineLevelTable
{
    /// <summary><c>SignedData.certificates</c> (PA-6.3-T01): shall be present at every level; cardinality 1; ref RFC 5652 §5.1; letters a), b); notes 1, 2.</summary>
    public static AdESTableRow SignedDataCertificates { get; } = new()
    {
        RequirementId = "PA-6.3-T01",
        Name = "SignedData.certificates",
        Kind = AdESTableRowKind.CmsAttribute,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("IETF RFC 5652", "5.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["a", "b"], NoteNumbers = [1, 2] }
    };

    /// <summary><c>content-type</c> [CAdES-deferred] (PA-6.3-T02): shall be present at every level; cardinality 1; ref EN 319 122-1 §5.1.1; letter c).</summary>
    public static AdESTableRow ContentType { get; } = new()
    {
        RequirementId = "PA-6.3-T02",
        Name = "content-type",
        Kind = AdESTableRowKind.CmsAttribute,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("ETSI EN 319 122-1", "5.1.1"),
        IsCAdESDeferred = true,
        Annotations = new AdESRowAnnotations { RequirementLetters = ["c"] }
    };

    /// <summary><c>message-digest</c> [CAdES-deferred] (PA-6.3-T03): shall be present at every level; cardinality 1; ref EN 319 122-1 §5.1.2.</summary>
    public static AdESTableRow MessageDigest { get; } = new()
    {
        RequirementId = "PA-6.3-T03",
        Name = "message-digest",
        Kind = AdESTableRowKind.CmsAttribute,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("ETSI EN 319 122-1", "5.1.2"),
        IsCAdESDeferred = true
    };

    /// <summary><c>signer-attributes-v2</c> [CAdES-deferred] (PA-6.3-T04): may be present; cardinality 0 or 1; ref EN 319 122-1 §5.2.6.</summary>
    public static AdESTableRow SignerAttributesV2 { get; } = new()
    {
        RequirementId = "PA-6.3-T04",
        Name = "signer-attributes-v2",
        Kind = AdESTableRowKind.CmsAttribute,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("ETSI EN 319 122-1", "5.2.6"),
        IsCAdESDeferred = true
    };

    /// <summary><c>content-time-stamp</c> [CAdES-deferred] (PA-6.3-T05): may be present; cardinality &gt;= 0; ref EN 319 122-1 §5.2.8.</summary>
    public static AdESTableRow ContentTimestamp { get; } = new()
    {
        RequirementId = "PA-6.3-T05",
        Name = "content-time-stamp",
        Kind = AdESTableRowKind.CmsAttribute,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESExternalReference("ETSI EN 319 122-1", "5.2.8"),
        IsCAdESDeferred = true
    };

    /// <summary><c>signature-policy-identifier</c> [CAdES-deferred] (PA-6.3-T06): may be present; cardinality 0 or 1; ref EN 319 122-1 §5.2.9.</summary>
    public static AdESTableRow SignaturePolicyIdentifier { get; } = new()
    {
        RequirementId = "PA-6.3-T06",
        Name = "signature-policy-identifier",
        Kind = AdESTableRowKind.CmsAttribute,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("ETSI EN 319 122-1", "5.2.9"),
        IsCAdESDeferred = true
    };

    /// <summary><c>commitment-type-indication</c> [CAdES-deferred] (PA-6.3-T07): conditioned presence; cardinality 0 or 1; ref EN 319 122-1 §5.2.3; letter d).</summary>
    public static AdESTableRow CommitmentTypeIndication { get; } = new()
    {
        RequirementId = "PA-6.3-T07",
        Name = "commitment-type-indication",
        Kind = AdESTableRowKind.CmsAttribute,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("ETSI EN 319 122-1", "5.2.3"),
        IsCAdESDeferred = true,
        Annotations = new AdESRowAnnotations { RequirementLetters = ["d"] }
    };

    /// <summary>SERVICE: protection of the signing certificate (PA-6.3-T08): shall be provided at every level; letters e), f).</summary>
    public static AdESTableRow SigningCertificateProtectionService { get; } = new()
    {
        RequirementId = "PA-6.3-T08",
        Name = "Service: protection of signing certificate",
        Kind = AdESTableRowKind.Service,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBeProvided),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["e", "f"] },
        ServiceProvisionOptionRequirementIds = ["PA-6.3-T09", "PA-6.3-T10"]
    };

    /// <summary>SPO: ESS signing-certificate [CAdES-deferred] (PA-6.3-T09): conditioned presence; cardinality 0 or 1; ref EN 319 122-1 §5.2.2.2.</summary>
    public static AdESTableRow EssSigningCertificate { get; } = new()
    {
        RequirementId = "PA-6.3-T09",
        Name = "SPO: ESS signing-certificate",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("ETSI EN 319 122-1", "5.2.2.2"),
        IsCAdESDeferred = true
    };

    /// <summary>SPO: ESS signing-certificate-v2 [CAdES-deferred] (PA-6.3-T10): conditioned presence; cardinality 0 or 1; ref EN 319 122-1 §5.2.2.3.</summary>
    public static AdESTableRow EssSigningCertificateV2 { get; } = new()
    {
        RequirementId = "PA-6.3-T10",
        Name = "SPO: ESS signing-certificate-v2",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("ETSI EN 319 122-1", "5.2.2.3"),
        IsCAdESDeferred = true
    };

    /// <summary>Service: provide claimed time of signing (PA-6.3-T11): shall be provided at every level; delivered via the <c>M</c> entry (PA-6.3-T12/g).</summary>
    public static AdESTableRow ClaimedSigningTimeService { get; } = new()
    {
        RequirementId = "PA-6.3-T11",
        Name = "Service: provide claimed time of signing",
        Kind = AdESTableRowKind.Service,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBeProvided),
        ServiceProvisionOptionRequirementIds = ["PA-6.3-T12"]
    };

    /// <summary>SPO: entry with key <c>M</c> (PA-6.3-T12): shall be present at every level; cardinality 1; ref ISO 32000-1 §12.8.1; letter g).</summary>
    public static AdESTableRow SigningTimeField { get; } = new()
    {
        RequirementId = "PA-6.3-T12",
        Name = "SPO: entry with key M",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["g"] }
    };

    /// <summary>SPO: <c>signing-time</c> CMS attribute (PA-6.3-T13): shall not be present at every level; cardinality 0.</summary>
    public static AdESTableRow CmsSigningTimeAttribute { get; } = new()
    {
        RequirementId = "PA-6.3-T13",
        Name = "SPO: signing-time attribute in CMS signature",
        Kind = AdESTableRowKind.CmsAttribute,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero)
    };

    /// <summary>Entry with key <c>Contents</c> (PA-6.3-T14): shall be present at every level; cardinality 1; ref ISO 32000-1 §12.8.1; letters h), i).</summary>
    public static AdESTableRow ContentsField { get; } = new()
    {
        RequirementId = "PA-6.3-T14",
        Name = "entry with key Contents",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["h", "i"] }
    };

    /// <summary>Entry with key <c>Filter</c> (PA-6.3-T15): shall be present at every level; cardinality 1; ref ISO 32000-1 §12.8.1; letter j).</summary>
    public static AdESTableRow FilterField { get; } = new()
    {
        RequirementId = "PA-6.3-T15",
        Name = "entry with key Filter",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["j"] }
    };

    /// <summary>Entry with key <c>ByteRange</c> (PA-6.3-T16): shall be present at every level; cardinality 1; ref ISO 32000-1 §12.8.1; letter k).</summary>
    public static AdESTableRow ByteRangeField { get; } = new()
    {
        RequirementId = "PA-6.3-T16",
        Name = "entry with key ByteRange",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["k"] }
    };

    /// <summary>Entry with key <c>SubFilter</c> (PA-6.3-T17): shall be present at every level; cardinality 1; ref ISO 32000-1 §12.8.1; letter l).</summary>
    public static AdESTableRow SubFilterField { get; } = new()
    {
        RequirementId = "PA-6.3-T17",
        Name = "entry with key SubFilter",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["l"] }
    };

    /// <summary>Entry with key <c>Location</c> (PA-6.3-T18): may be present; cardinality 0 or 1; ref ISO 32000-1 §12.8.1.</summary>
    public static AdESTableRow LocationField { get; } = new()
    {
        RequirementId = "PA-6.3-T18",
        Name = "entry with key Location",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1")
    };

    /// <summary>Entry with key <c>Reason</c> (PA-6.3-T19): conditioned presence; cardinality 0 or 1; ref ISO 32000-1 §12.8.1; letter m).</summary>
    public static AdESTableRow ReasonField { get; } = new()
    {
        RequirementId = "PA-6.3-T19",
        Name = "entry with key Reason",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["m"] }
    };

    /// <summary>Entry with key <c>Name</c> (PA-6.3-T20): may be present; cardinality 0 or 1; ref ISO 32000-1 §12.8.1.</summary>
    public static AdESTableRow NameField { get; } = new()
    {
        RequirementId = "PA-6.3-T20",
        Name = "entry with key Name",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1")
    };

    /// <summary>Entry with key <c>ContactInfo</c> (PA-6.3-T21): may be present; cardinality 0 or 1; ref ISO 32000-1 §12.8.1.</summary>
    public static AdESTableRow ContactInfoField { get; } = new()
    {
        RequirementId = "PA-6.3-T21",
        Name = "entry with key ContactInfo",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1")
    };

    /// <summary>Entry with key <c>Cert</c> (PA-6.3-T22): shall not be present at every level; cardinality 0; ref ISO 32000-1 §12.8.1.</summary>
    public static AdESTableRow CertField { get; } = new()
    {
        RequirementId = "PA-6.3-T22",
        Name = "entry with key Cert",
        Kind = AdESTableRowKind.SignatureDictionaryField,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero),
        Reference = new AdESExternalReference("ISO 32000-1", "12.8.1")
    };

    /// <summary>SERVICE: provide trusted time for existence of the signature (PA-6.3-T23): <c>"*"</c> at B-B, shall be provided from B-T; letter n).</summary>
    public static AdESTableRow TrustedSignatureTimeService { get; } = new()
    {
        RequirementId = "PA-6.3-T23",
        Name = "Service: provide trusted time for existence of the signature",
        Kind = AdESTableRowKind.Service,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShallBeProvided,
            BLT = AdESPresence.ShallBeProvided,
            BLTA = AdESPresence.ShallBeProvided
        },
        Annotations = new AdESRowAnnotations { RequirementLetters = ["n"] },
        ServiceProvisionOptionRequirementIds = ["PA-6.3-T24", "PA-6.3-T25"]
    };

    /// <summary>SPO: <c>signature-time-stamp</c> [CAdES-deferred] (PA-6.3-T24): <c>"*"</c> at B-B, conditioned presence from B-T; cardinality &gt;= 0; ref EN 319 122-1 §5.3; letters o), p), q).</summary>
    public static AdESTableRow SignatureTimestamp { get; } = new()
    {
        RequirementId = "PA-6.3-T24",
        Name = "SPO: signature-time-stamp",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ConditionedPresence,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESExternalReference("ETSI EN 319 122-1", "5.3"),
        IsCAdESDeferred = true,
        Annotations = new AdESRowAnnotations { RequirementLetters = ["o", "p", "q"] }
    };

    /// <summary>SPO: <c>document-time-stamp</c> (PA-6.3-T25): <c>"*"</c> at B-B, conditioned presence from B-T; cardinality &gt;= 0; ref clause 5.4.3.</summary>
    public static AdESTableRow DocumentTimestampAsTrustedTimeSpo { get; } = new()
    {
        RequirementId = "PA-6.3-T25",
        Name = "SPO: document-time-stamp",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ConditionedPresence,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.4.3")
    };

    /// <summary>SERVICE: provide certificate and revocation values (PA-6.3-T26): <c>"*"</c> at B-B/B-T, shall be provided from B-LT.</summary>
    public static AdESTableRow CertificateAndRevocationValuesService { get; } = new()
    {
        RequirementId = "PA-6.3-T26",
        Name = "Service: provide certificate and revocation values",
        Kind = AdESTableRowKind.Service,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShallBeProvided,
            BLTA = AdESPresence.ShallBeProvided
        },
        ServiceProvisionOptionRequirementIds = ["PA-6.3-T27", "PA-6.3-T28"]
    };

    /// <summary>SPO: DSS (PA-6.3-T27): <c>"*"</c> at B-B/B-T, shall be present from B-LT; cardinality split {B-B,B-T: &gt;=0}/{B-LT,B-LTA: &gt;=1}; ref clause 5.4.2.2; letters r), s), t), u), v).</summary>
    public static AdESTableRow Dss { get; } = new()
    {
        RequirementId = "PA-6.3-T27",
        Name = "SPO: DSS",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShallBePresent,
            BLTA = AdESPresence.ShallBePresent
        },
        Cardinality = new AdESRowCardinality
        {
            Statements =
            [
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB | AdESBaselineLevelSet.BT, AdESCardinality.ZeroOrMore),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.OneOrMore)
            ]
        },
        Reference = new AdESInternalClauseReference("5.4.2.2"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["r", "s", "t", "u", "v"] }
    };

    /// <summary>SPO: DSS/VRI (PA-6.3-T28): <c>"*"</c> at B-B/B-T, conditioned presence from B-LT; cardinality &gt;= 0; ref clause 5.4.2.3.</summary>
    public static AdESTableRow DssVri { get; } = new()
    {
        RequirementId = "PA-6.3-T28",
        Name = "SPO: DSS/VRI",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.4.2.3")
    };

    /// <summary>SERVICE: provide trusted time for existence of the validation data (PA-6.3-T29): <c>"*"</c> below B-LTA, shall be provided at B-LTA; note 3.</summary>
    public static AdESTableRow TrustedValidationDataTimeService { get; } = new()
    {
        RequirementId = "PA-6.3-T29",
        Name = "Service: provide trusted time for existence of the validation data",
        Kind = AdESTableRowKind.Service,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShouldNotBePresent,
            BLTA = AdESPresence.ShallBeProvided
        },
        Annotations = new AdESRowAnnotations { NoteNumbers = [3] },
        ServiceProvisionOptionRequirementIds = ["PA-6.3-T30"]
    };

    /// <summary>SPO: document-time-stamp (PA-6.3-T30): <c>"*"</c> below B-LTA, shall be present at B-LTA; cardinality split {B-B,B-T,B-LT: &gt;=0}/{B-LTA: &gt;=1}; ref clause 5.4.3; letters w), x), y).</summary>
    public static AdESTableRow DocumentTimestampForLta { get; } = new()
    {
        RequirementId = "PA-6.3-T30",
        Name = "SPO: document-time-stamp",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShouldNotBePresent,
            BLTA = AdESPresence.ShallBePresent
        },
        Cardinality = new AdESRowCardinality
        {
            Statements =
            [
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB | AdESBaselineLevelSet.BT | AdESBaselineLevelSet.BLT, AdESCardinality.ZeroOrMore),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLTA, AdESCardinality.OneOrMore)
            ]
        },
        Reference = new AdESInternalClauseReference("5.4.3"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["w", "x", "y"] }
    };


    /// <summary>Gets every Table 1 row, in the source table's own order (PA-6.3-T01..T30).</summary>
    public static IReadOnlyList<AdESTableRow> Rows { get; } =
    [
        SignedDataCertificates, ContentType, MessageDigest, SignerAttributesV2, ContentTimestamp,
        SignaturePolicyIdentifier, CommitmentTypeIndication, SigningCertificateProtectionService,
        EssSigningCertificate, EssSigningCertificateV2, ClaimedSigningTimeService, SigningTimeField,
        CmsSigningTimeAttribute, ContentsField, FilterField, ByteRangeField, SubFilterField, LocationField,
        ReasonField, NameField, ContactInfoField, CertField, TrustedSignatureTimeService, SignatureTimestamp,
        DocumentTimestampAsTrustedTimeSpo, CertificateAndRevocationValuesService, Dss, DssVri,
        TrustedValidationDataTimeService, DocumentTimestampForLta
    ];


    /// <summary>Finds the registered row whose <see cref="AdESTableRow.RequirementId"/> matches <paramref name="requirementId"/>.</summary>
    /// <param name="requirementId">The requirement identifier to look up (e.g. <c>"PA-6.3-T27"</c>).</param>
    /// <returns>The matching row, or <see langword="null"/> when none is registered.</returns>
    public static AdESTableRow? FindByRequirementId(string requirementId) =>
        AdESBaselineLevelTables.FindByRequirementId(Rows, requirementId);
}
