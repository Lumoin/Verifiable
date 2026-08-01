using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Names why an augmentation of a CAdES signature could not be performed.
/// </summary>
/// <remarks>
/// These are generator-side faults: an input the caller supplied that the level being reached cannot be built
/// from. They are deliberately not the indication and sub-indication vocabulary of the validation processes,
/// which describes what a verifier concludes about a signature it did not make.
/// </remarks>
public enum CAdESAugmentationFailureKind
{
    /// <summary>No failure has been classified.</summary>
    NotEvaluated = 0,

    /// <summary>The Signed Data Object could not be walked, or holds no signer at the index addressed.</summary>
    SignedDataMalformed = 1,

    /// <summary>A certificate, CRL, or OCSP response the caller supplied could not be read.</summary>
    ValidationObjectMalformed = 2,

    /// <summary>A supplied object is not of the kind the placement it was offered for admits.</summary>
    UnsupportedValidationObject = 3,

    /// <summary>
    /// A Delta CRL was supplied without the complete CRL set clause 5.5.3 of ETSI EN 319 122-1 requires
    /// alongside it.
    /// </summary>
    DeltaCrlWithoutCompleteSet = 4,

    /// <summary>
    /// The signature carries a legacy long-term-availability attribute, so clause 5.5.3 places new validation
    /// material inside the latest archive time-stamp's token, and there is no such token to place it in.
    /// </summary>
    NoArchiveTimestampToAugment = 5,

    /// <summary>
    /// The latest legacy long-term-availability attribute is a <c>long-term-validation</c> attribute rather
    /// than an archive time-stamp, whose internal structure this surface does not author material into.
    /// </summary>
    LegacyAttributePlacementUnsupported = 6,

    /// <summary>
    /// Table 1 requirement m) is violated: the acquired time-stamp token's generation time falls outside the
    /// signing certificate's validity window (before <c>notBefore</c> or after <c>notAfter</c>).
    /// </summary>
    SigningCertificateNotValidAtTimestamp = 7,

    /// <summary>
    /// Table 1 requirement m) is violated: the acquired time-stamp token's generation time falls at or after
    /// the caller-supplied instant the signing certificate is known to have been revoked.
    /// </summary>
    SigningCertificateRevokedBeforeTimestamp = 8,

    /// <summary>
    /// Table 1 requirement k) is violated: <c>signature-policy-store</c> was requested without a
    /// <c>signature-policy-identifier</c> attribute carrying a non-zero <c>sigPolicyHash</c>.
    /// </summary>
    SignaturePolicyStoreRequirementNotMet = 9,

    /// <summary>
    /// The signature carries a legacy long-term-availability attribute, and clause 5.5.3 of ETSI EN 319 122-1
    /// then admits nothing but an <c>archive-time-stamp-v3</c> or an Annex B attribute into <c>unsignedAttrs</c>:
    /// "If an ATSv2, or other earlier form of archive time-stamp or a <c>long-term-validation</c> attribute, is
    /// present then no other attributes than ATSv3 or attributes specified as per annex B shall be added to the
    /// <c>unsignedAttrs</c>."
    /// </summary>
    LegacyAttributeForbidsFurtherAttributes = 10
}


/// <summary>
/// The generator-side fault of a CAdES augmentation.
/// </summary>
/// <remarks>
/// Creation and augmentation report faults as exceptions, following the signing surfaces already in this
/// library, because a generator handing in material a level cannot be built from is a composition fault of the
/// caller rather than an adversarial input to be classified and reported.
/// </remarks>
[DebuggerDisplay("CAdESAugmentationException({FailureKind}): {Message}")]
public sealed class CAdESAugmentationException: Exception
{
    /// <summary>Gets what could not be done.</summary>
    public CAdESAugmentationFailureKind FailureKind { get; }


    /// <summary>Initializes a new <see cref="CAdESAugmentationException"/> with an unclassified malformed input.</summary>
    public CAdESAugmentationException(): this(CAdESAugmentationFailureKind.SignedDataMalformed, "The CAdES signature could not be augmented.")
    {
    }


    /// <summary>Initializes a new <see cref="CAdESAugmentationException"/> with an unclassified malformed input.</summary>
    /// <param name="message">The message describing the fault.</param>
    public CAdESAugmentationException(string message): this(CAdESAugmentationFailureKind.SignedDataMalformed, message)
    {
    }


    /// <summary>Initializes a new <see cref="CAdESAugmentationException"/> with an unclassified malformed input.</summary>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public CAdESAugmentationException(string message, Exception innerException): this(CAdESAugmentationFailureKind.SignedDataMalformed, message, innerException)
    {
    }


    /// <summary>Initializes a new <see cref="CAdESAugmentationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    public CAdESAugmentationException(CAdESAugmentationFailureKind failureKind, string message): base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a new <see cref="CAdESAugmentationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public CAdESAugmentationException(CAdESAugmentationFailureKind failureKind, string message, Exception innerException): base(message, innerException)
    {
        FailureKind = failureKind;
    }
}


/// <summary>
/// Where new validation material goes, per the two mutually exclusive strategies of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.5.3</see>.
/// </summary>
public enum CAdESValidationDataPlacement
{
    /// <summary>The placement has not been determined.</summary>
    NotDetermined = 0,

    /// <summary>
    /// No legacy long-term-availability attribute is present in any <c>SignerInfo</c> of the root
    /// <c>SignedData</c>, so "the new validation material shall be included within the root
    /// <c>SignedData.certificates</c>, or <c>SignedData.crls</c> as applicable".
    /// </summary>
    RootSignedData = 1,

    /// <summary>
    /// A legacy archive time-stamp or <c>long-term-validation</c> attribute is present, so "the root
    /// <c>SignedData.certificates</c> and <c>SignedData.crls</c> contents shall not be modified" and the new
    /// material is provided within the time-stamp token of the latest archive time-stamp, as
    /// <c>certificate-values</c> and <c>revocation-values</c> unsigned attributes of that token's own signer.
    /// </summary>
    LatestArchiveTimestampToken = 2
}


/// <summary>
/// The validation material an augmentation places into a signature: the certificates and revocation
/// information ETSI EN 319 122-1 Table 1 requirements d) and o) call the full set used to validate the
/// signature, the signing certificate, any attribute certificate, any revocation-information-signing
/// certificate, and any embedded time-stamping authority certificate.
/// </summary>
/// <remarks>
/// The carriers belong to the caller for the whole call and are not disposed by anything here: an augmentation
/// copies the octets it places and never takes ownership of what it was shown.
/// </remarks>
public sealed record CAdESValidationMaterial
{
    /// <summary>Gets the certificates to place, each a DER-encoded X.509 certificate.</summary>
    public IReadOnlyList<PkiCertificateMemory> Certificates { get; init; } = [];

    /// <summary>Gets the certificate revocation lists to place, each a DER-encoded <c>CertificateList</c>.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateRevocationLists { get; init; } = [];

    /// <summary>Gets the OCSP responses to place, each a DER-encoded <c>OCSPResponse</c> or <c>BasicOCSPResponse</c>.</summary>
    public IReadOnlyList<PkiCertificateMemory> OcspResponses { get; init; } = [];

    /// <summary>Gets whether this material names nothing to place.</summary>
    public bool IsEmpty => Certificates.Count == 0 && CertificateRevocationLists.Count == 0 && OcspResponses.Count == 0;

    /// <summary>Gets material naming nothing to place, for an archive time-stamp over a signature already carrying everything it needs.</summary>
    public static CAdESValidationMaterial None { get; } = new();
}


/// <summary>
/// What one <see cref="CAdESSignatureAugmentation.AddSignatureTimestampAsync"/> call needs: the signature, the
/// algorithm the imprint is computed under, and how to reach a Time-Stamping Authority.
/// </summary>
public sealed record CAdESSignatureTimestampContext
{
    /// <summary>Gets the signature the time-stamp is added to.</summary>
    public required CmsSignedData SignedData { get; init; }

    /// <summary>Gets the zero-based index of the <c>SignerInfo</c> whose signature value is time-stamped.</summary>
    public int SignerIndex { get; init; }

    /// <summary>Gets the algorithm the message imprint is computed under, which the authority echoes in its token.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchResponse { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? ReqPolicyOid { get; init; }

    /// <summary>Gets the nonce length in octets the request carries.</summary>
    public int NonceByteLength { get; init; } = 32;

    /// <summary>Gets whether the request carries a nonce.</summary>
    public bool IncludeNonce { get; init; } = true;

    /// <summary>
    /// Gets the signer's own certificate, whose validity window Table 1 requirement m) checks the acquired
    /// token's generation time against. Required when <see cref="EnforceSigningCertificateValidity"/> is
    /// <see langword="true"/> (the default).
    /// </summary>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>
    /// Gets the instant the signing certificate is known to have been revoked, or <see langword="null"/> when
    /// none is known. When supplied, requirement m) additionally requires the acquired token's generation time
    /// to precede it.
    /// </summary>
    public DateTimeOffset? SigningCertificateRevokedAt { get; init; }

    /// <summary>
    /// Gets whether the acquired token's generation time is checked against <see cref="SigningCertificate"/>'s
    /// validity window and <see cref="SigningCertificateRevokedAt"/> (Table 1 requirement m). Default
    /// <see langword="true"/> — the secure default; a caller opts out explicitly.
    /// </summary>
    public bool EnforceSigningCertificateValidity { get; init; } = true;
}


/// <summary>
/// What one <see cref="CAdESSignatureAugmentation.AddArchiveTimestampAsync"/> call needs: the signature, the
/// validation material requirement s) of ETSI EN 319 122-1 Table 1 has included before a new archive
/// time-stamp is generated, the algorithm the imprint and hash index are computed under, how to reach a
/// Time-Stamping Authority, and — for a detached signature — the signed data or its hash.
/// </summary>
public sealed record CAdESArchiveTimestampContext
{
    /// <summary>Gets the signature the archive time-stamp is added to.</summary>
    public required CmsSignedData SignedData { get; init; }

    /// <summary>Gets the zero-based index of the <c>SignerInfo</c> the archive time-stamp corresponds to.</summary>
    public int SignerIndex { get; init; }

    /// <summary>Gets the algorithm the message imprint and every hash-index value are computed under, which clause 5.5.2 requires to be one and the same.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchResponse { get; init; }

    /// <summary>
    /// Gets the validation material placed into the signature before the archive time-stamp is generated —
    /// requirement s)'s "all the validation material required to validate the signature and that is not already
    /// present ... including the validation material required to validate any previous archive time-stamp".
    /// <see cref="CAdESValidationMaterial.None"/> states that everything needed is already there.
    /// </summary>
    public required CAdESValidationMaterial ValidationMaterial { get; init; }

    /// <summary>Gets the detached signed content, for a signature that encapsulates none (clause 5.5.3 NOTE 1).</summary>
    public SignedContentMemory? DetachedSignedContent { get; init; }

    /// <summary>Gets the hash of the detached signed content under <see cref="MessageImprintAlgorithm"/>, when only the hash is available.</summary>
    public DigestValue? DetachedSignedContentDigest { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? ReqPolicyOid { get; init; }

    /// <summary>Gets the nonce length in octets the request carries.</summary>
    public int NonceByteLength { get; init; } = 32;

    /// <summary>Gets whether the request carries a nonce.</summary>
    public bool IncludeNonce { get; init; } = true;

    /// <summary>
    /// Gets the signer's own certificate, checked the same way <see cref="CAdESSignatureTimestampContext.SigningCertificate"/>
    /// is. Table 1 requirement m) is textually scoped to <c>signature-time-stamp</c>; this surface applies the
    /// same secure-default check to the archive time-stamp token as defense in depth, opt-out-able because a
    /// CAdES-B-LTA raised long after the signing certificate's own validity window is the normal case an
    /// archive time-stamp exists to survive — see <see cref="EnforceSigningCertificateValidity"/>.
    /// </summary>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>Gets the instant the signing certificate is known to have been revoked, or <see langword="null"/> when none is known.</summary>
    public DateTimeOffset? SigningCertificateRevokedAt { get; init; }

    /// <summary>
    /// Gets whether the acquired archive time-stamp token's generation time is checked against
    /// <see cref="SigningCertificate"/>'s validity window and <see cref="SigningCertificateRevokedAt"/>.
    /// Default <see langword="true"/> — the secure default; a caller raising a signature to B-LTA long after the
    /// signing certificate expired (the normal long-term-preservation case) opts out explicitly.
    /// </summary>
    public bool EnforceSigningCertificateValidity { get; init; } = true;
}


/// <summary>
/// What one <see cref="CAdESSignatureAugmentation.AddCountersignatureAsync"/> call needs: the signature being
/// countersigned, which of its signers is countersigned, and the counter signer's own certificate, key and
/// signing time — the inputs clause 5.2.7 of ETSI EN 319 122-1 and
/// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-11.4">RFC 5652 §11.4</see> together determine a
/// <c>countersignature</c> attribute from.
/// </summary>
/// <remarks>
/// The carriers belong to the caller for the whole call and are not disposed by anything here, matching
/// <see cref="CAdESValidationMaterial"/>'s own ownership rule.
/// </remarks>
public sealed record CAdESCountersignatureContext
{
    /// <summary>Gets the signature being countersigned. Not modified; the augmented result is a new carrier.</summary>
    public required CmsSignedData SignedData { get; init; }

    /// <summary>
    /// Gets the zero-based index of the <c>SignerInfo</c> being countersigned — the one whose <c>signature</c>
    /// value octets the countersignature's <c>message-digest</c> covers and whose <c>unsignedAttrs</c> the
    /// <c>countersignature</c> attribute is appended to. Both are the same signer, which is what RFC 5652 §11.4's
    /// "the <c>SignerInfo</c> value with which the attribute is associated" means.
    /// </summary>
    public int SignerIndex { get; init; }

    /// <summary>Gets the counter signer's own certificate.</summary>
    public required PkiCertificateMemory CountersignerCertificate { get; init; }

    /// <summary>Gets the counter signer's private key material; its tag resolves the signing delegate and the algorithm identities.</summary>
    public required PrivateKeyMemory CountersignerPrivateKey { get; init; }

    /// <summary>Gets the <c>signing-time</c> attribute value the countersignature states.</summary>
    public required DateTimeOffset SigningTime { get; init; }

    /// <summary>Gets a caller-supplied dated cryptographic-constraints table the counter signer's digest algorithm is assessed against, or <see langword="null"/> to apply only the unconditional refusals.</summary>
    public CryptographicConstraints? AlgorithmConstraints { get; init; }

    /// <summary>Gets whether the countersignature carries the opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211).</summary>
    public bool IncludeCmsAlgorithmProtection { get; init; }

    /// <summary>
    /// Gets whether the counter signer's own certificate is added to the countersigned signature's
    /// <c>SignedData.certificates</c> alongside the attribute (default <see langword="true"/>).
    /// </summary>
    /// <remarks>
    /// A verifier reaching the countersignature has to find the counter signer's certificate somewhere, and
    /// <c>SignedData.certificates</c> is where RFC 5652 §5.1 puts the certificates of a signature's signers;
    /// Table 1 requirements d) and e) name the full certificate set and have duplication avoided, which the
    /// underlying <see cref="CmsSignedDataAugmentation.AddCertificates"/> does by construction. A caller that
    /// distributes the counter signer's certificate out of band sets this <see langword="false"/>.
    /// </remarks>
    public bool IncludeCountersignerCertificate { get; init; } = true;
}


/// <summary>
/// One <c>signature-policy-store</c> attribute value (clause 5.2.10):
/// <c>SignaturePolicyStore ::= SEQUENCE { spDocSpec SPDocSpecification, spDocument SignaturePolicyDocument }</c>,
/// each field a two-alternative CHOICE. Table 1 requirement k) gates the whole attribute, enforced by
/// <see cref="CAdESSignatureAugmentation.AddSignaturePolicyStore"/>, not by this record.
/// </summary>
public sealed record CAdESSignaturePolicyStore
{
    /// <summary>Gets the <c>spDocSpec</c> as an object identifier, or <see langword="null"/> when <see cref="DocumentSpecificationUri"/> is used instead. Exactly one of the two must be set.</summary>
    public string? DocumentSpecificationOid { get; init; }

    /// <summary>Gets the <c>spDocSpec</c> as a URI, or <see langword="null"/> when <see cref="DocumentSpecificationOid"/> is used instead.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "This value is an IA5String CHOICE alternative written verbatim into the attribute, not parsed or dereferenced here; promoting to System.Uri would impose platform URI semantics the ASN.1 syntax does not require, matching TimestampFetchContext.TsaUri's precedent.")]
    public string? DocumentSpecificationUri { get; init; }

    /// <summary>Gets the encoded signature policy document (<c>spDocument.sigPolicyEncoded</c>), or <see langword="null"/> when <see cref="LocalDocumentUri"/> is used instead. Exactly one of the two must be set.</summary>
    public ReadOnlyMemory<byte>? EncodedDocument { get; init; }

    /// <summary>Gets a URI to a local store where the document can be retrieved (<c>spDocument.sigPolicyLocalURI</c>), or <see langword="null"/> when <see cref="EncodedDocument"/> is used instead.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "This value is an IA5String CHOICE alternative written verbatim into the attribute, not parsed or dereferenced here; promoting to System.Uri would impose platform URI semantics the ASN.1 syntax does not require, matching TimestampFetchContext.TsaUri's precedent.")]
    public string? LocalDocumentUri { get; init; }
}


/// <summary>
/// Raises an existing CAdES signature to the baseline levels above B-B of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 6.1</see>: B-T by adding a <c>signature-time-stamp</c> (clause 5.3), B-LT by
/// placing validation material (clause 5.5.3 and Table 1 requirements o) to r)), and B-LTA by adding an
/// <c>archive-time-stamp-v3</c> with its <c>ats-hash-index-v3</c> (clauses 5.5.2 and 5.5.3).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every step appends; nothing is re-encoded.</strong> Each level is reached through the byte-preserving
/// splice of <see cref="CmsSignedDataAugmentation"/>, because clause 5.5.3 requires an augmentation to
/// "preserve the binary encoding of already present unsigned attributes and any component contributing to the
/// archive time-stamp's message imprint computation input" — re-serializing one element covered by an earlier
/// archive time-stamp would break it (NOTE 7). New material is DER, which the same clause requires of anything
/// an augmentation adds and requirement l) requires of a <c>signature-time-stamp</c> in particular.
/// </para>
/// <para>
/// <strong>The three message imprints are never conflated.</strong> A <c>signature-time-stamp</c>'s imprint is
/// the hash of the <c>SignerInfo.signature</c> value octets alone, "without the ASN.1 tag and length" (clause
/// 5.3), while an <c>archive-time-stamp-v3</c>'s is the hash of a four-part concatenation of whole encodings,
/// tag and length octets included (clause 5.5.3). This surface computes the first here and delegates the second
/// to <see cref="ArchiveTimestampV3"/>, which is also what the validation side calls, so the two directions
/// cannot drift.
/// </para>
/// <para>
/// <strong>Deprecated attributes are recognised and never emitted.</strong> Clause A.2 deprecates the v2 archive
/// time-stamp, the <c>long-term-validation</c> attribute, and the pre-v3 hash indexes. No augmentation performed
/// here writes one. Their presence selects the second placement strategy of clause 5.5.3 and, by the same
/// clause's attribute-addition lockdown, closes the outer <c>unsignedAttrs</c> to everything but an
/// <c>archive-time-stamp-v3</c> or an Annex B attribute — which is why every write path that adds an outer
/// unsigned attribute of its own gates on it: <see cref="AddSignatureTimestampAsync"/>,
/// <see cref="AddCountersignatureAsync"/>, and <see cref="AddSignaturePolicyStore"/> all refuse such a signature
/// (<see cref="CAdESAugmentationFailureKind.LegacyAttributeForbidsFurtherAttributes"/>) rather than writing an
/// attribute the clause forbids. <see cref="AddArchiveTimestampAsync"/> and <see cref="AddValidationData"/> are
/// the two genuinely exempt surfaces — see <see cref="EnsureLegacyAttributeLockdownPermits"/>'s own remarks for
/// why.
/// </para>
/// <para>
/// <strong>Not every act here raises a level.</strong> <see cref="AddSignaturePolicyStore"/> (clause 5.2.10) and
/// <see cref="AddCountersignatureAsync"/> (clause 5.2.7) add unsigned attributes that carry no level of their own;
/// they are here rather than on the creation surface because an unsigned attribute is by definition added after
/// the signature exists, through the same byte-preserving splice, under the same preservation rule.
/// </para>
/// <para>
/// <strong>A token is verified before it is attached.</strong> Acquisition goes through
/// <see cref="TimestampAcquisition"/>, which checks the authority's status, the token's own CMS signature, the
/// message imprint against the digest the request carried, and the nonce; a token failing any of those is never
/// attached to anything.
/// </para>
/// <para>
/// <strong>Synchronous where nothing cryptographic happens.</strong> Placing validation material is DER
/// assembly over octets the caller already holds — no digest, no signature, no transport — so it is a
/// synchronous operation, while the two time-stamp levels reach the digest seam and a Time-Stamping Authority
/// and are asynchronous.
/// </para>
/// </remarks>
public static class CAdESSignatureAugmentation
{
    /// <summary>
    /// The <c>id-ri-ocsp-response</c> object identifier that types a whole <c>OCSPResponse</c> inside
    /// <c>RevocationInfoChoices.other</c> (<see href="https://www.rfc-editor.org/rfc/rfc5940#section-2">RFC 5940
    /// §2</see>) and inside <c>RevocationValues.otherRevVals</c> (ETSI EN 319 122-1 clause A.1.2.2). Sourced
    /// from <see cref="WellKnownOids.OcspResponseRevocationInfo"/> — the single definition
    /// <see cref="CAdESSignatureFacts"/> reads by and this surface writes by, so the two can never drift.
    /// </summary>
    private const string OcspResponseRevocationInfoOid = WellKnownOids.OcspResponseRevocationInfo;

    /// <summary>The <c>deltaCRLIndicator</c> certificate-list extension (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-5.2.4">RFC 5280 §5.2.4</see>).</summary>
    private const string DeltaCrlIndicatorOid = "2.5.29.27";

    /// <summary>The largest number of <c>TBSCertList</c> fields walked while looking for the extensions, bounding a hostile list's cost.</summary>
    private const int MaximumCertificateListFields = 8;

    /// <summary>The largest number of extensions walked in one certificate list.</summary>
    private const int MaximumCertificateListExtensions = 64;

    /// <summary>The <c>[0]</c> constructed context tag: <c>TBSCertList.crlExtensions</c> and <c>RevocationValues.crlVals</c>.</summary>
    private static Asn1Tag ContextConstructed0 { get; } = new(TagClass.ContextSpecific, 0, isConstructed: true);

    /// <summary>The <c>[1]</c> constructed context tag: <c>RevocationInfoChoice.other</c> and <c>RevocationValues.ocspVals</c>.</summary>
    private static Asn1Tag ContextConstructed1 { get; } = new(TagClass.ContextSpecific, 1, isConstructed: true);

    /// <summary>The <c>[2]</c> constructed context tag: <c>RevocationValues.otherRevVals</c>.</summary>
    private static Asn1Tag ContextConstructed2 { get; } = new(TagClass.ContextSpecific, 2, isConstructed: true);


    /// <summary>
    /// Raises a signature to CAdES-B-T: obtains a time-stamp token over the <c>SignerInfo.signature</c> value
    /// octets from the caller's Time-Stamping Authority, verifies it, and attaches it as the
    /// <c>signature-time-stamp</c> unsigned attribute (clause 5.3, Table 1 requirement l).
    /// </summary>
    /// <param name="context">The signature, the imprint algorithm, and the authority to contact.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the context's signer index is negative.</exception>
    /// <exception cref="CAdESAugmentationException">When the signature cannot be walked or holds no signer at that index.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or the token it returned does not verify.</exception>
    /// <exception cref="InvalidOperationException">When no <see cref="ComputeDigestDelegate"/> has been registered — a composition fault of the host.</exception>
    /// <remarks>
    /// Table 1 requirement m) has the token created before the signing certificate has been revoked or has
    /// expired. <see cref="EnsureRequirementMSatisfied"/> enforces this against the acquired token's own
    /// generation time and <see cref="CAdESSignatureTimestampContext.SigningCertificate"/>'s validity window
    /// (plus <see cref="CAdESSignatureTimestampContext.SigningCertificateRevokedAt"/> when supplied) before the
    /// token is attached to anything; <see cref="CAdESSignatureTimestampContext.EnforceSigningCertificateValidity"/>
    /// is the explicit opt-out (default enforced).
    /// </remarks>
    public static async ValueTask<CmsSignedData> AddSignatureTimestampAsync(
        CAdESSignatureTimestampContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(context.SignerIndex);
        EnsureLegacyAttributeLockdownPermits(context.SignedData, "signature-time-stamp");

        PkiDigestAlgorithm algorithm = context.MessageImprintAlgorithm;
        ReadOnlyMemory<byte> signatureValue;
        try
        {
            signatureValue = CmsSignedDataAugmentation.ReadSignatureValue(context.SignedData, context.SignerIndex);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The signature value a signature-time-stamp is computed over could not be read from the Signed Data Object (ETSI EN 319 122-1 clause 5.3).",
                exception);
        }

        using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
            signatureValue, algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        using AcquiredTimestampToken token = await TimestampAcquisition.AcquireAsync(
            imprint, context.TsaUri, context.FetchResponse, pool,
            context.ReqPolicyOid, context.NonceByteLength, context.IncludeNonce, cancellationToken).ConfigureAwait(false);
        EnsureRequirementMSatisfied(
            token, context.SigningCertificate, context.SigningCertificateRevokedAt, context.EnforceSigningCertificateValidity);
        using CmsAttribute attribute = CmsAttribute.Create(
            CAdESSignatureFacts.SignatureTimestampAttributeOid, token.Token.AsReadOnlySpan(), pool);

        return CmsSignedDataAugmentation.AppendUnsignedAttributes(context.SignedData, context.SignerIndex, [attribute], pool);
    }


    /// <summary>
    /// Adds a <c>countersignature</c> unsigned attribute (clause 5.2.7,
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-11.4">RFC 5652 §11.4</see>): produces the counter
    /// signer's own <c>SignerInfo</c> over the countersigned <c>SignerInfo.signature</c> value octets through
    /// <see cref="CAdESSignatureCreation"/>'s three phases, and attaches it through the byte-preserving splice.
    /// </summary>
    /// <param name="context">The signature, the signer being countersigned, and the counter signer's certificate, key and signing time.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The countersigned signature. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the context's signer index is negative.</exception>
    /// <exception cref="CAdESAugmentationException">When the signature cannot be walked or holds no signer at that index.</exception>
    /// <exception cref="NotSupportedException">When the counter signer's algorithm or digest is one the creation surface refuses.</exception>
    /// <exception cref="InvalidOperationException">When no <see cref="ComputeDigestDelegate"/> has been registered — a composition fault of the host.</exception>
    /// <remarks>
    /// <para>
    /// <strong>Cardinality is <c>&gt;= 0</c> and repetition is supported both ways.</strong> Table 1 gives
    /// <c>countersignature</c> cardinality <c>&gt;= 0</c>, and clause 5.5.3 NOTE 6 states that a further
    /// countersignature may be added "in the same attribute or as a new <c>countersignature</c> attribute". Each
    /// call here appends a new attribute, which the splice does without touching the attributes already present;
    /// several values of one attribute are
    /// <see cref="CmsAttribute.Create(string, IReadOnlyList{ReadOnlyMemory{byte}}, MemoryPool{byte})"/> over
    /// several <see cref="CAdESSignatureCreation.CompleteCountersignature"/> results, appended once.
    /// </para>
    /// <para>
    /// <strong>Both forms leave an existing <c>archive-time-stamp-v3</c> valid; mutating a countersignature does
    /// not.</strong> Clause 5.5.3 NOTE 6 draws exactly that line: a sibling countersignature is new material with
    /// no entry in the earlier <c>ats-hash-index-v3</c>, which clause 5.5.2's asymmetric membership check does not
    /// treat as an error, whereas adding an unsigned attribute <em>inside</em> a countersignature the index already
    /// names changes that attribute value's octets and so breaks the archive time-stamp. Clause 5.5.3 NOTE 4 is the
    /// other half of the same fact: a countersignature needs no archive time-stamp of its own, being protected as
    /// an unsigned attribute of the signature that carries it.
    /// </para>
    /// <para>
    /// <strong>The counter signer's digest algorithm and <c>SignedData.digestAlgorithms</c>.</strong> RFC 5652
    /// §5.1 has that set "list the message digest algorithms employed by all of the signers" and notes
    /// implementations MAY fail to validate a signature using an algorithm absent from it. This augmentation does
    /// not modify the set: it is a mandatory field of <c>SignedData</c> whose re-encoding the preservation rule of
    /// clause 5.5.3 exists to avoid, and the counter signer's algorithm is resolved from its own key, which for the
    /// SHA-256-based profiles this library creates under is the algorithm an outer signer already listed. A caller
    /// countersigning under a digest the countersigned signature does not list accepts that MAY.
    /// </para>
    /// </remarks>
    public static async ValueTask<CmsSignedData> AddCountersignatureAsync(
        CAdESCountersignatureContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(context.SignerIndex);
        EnsureLegacyAttributeLockdownPermits(context.SignedData, "countersignature");

        CmsAttribute attribute;
        try
        {
            attribute = await CAdESSignatureCreation.CountersignAsync(
                context.SignedData, context.SignerIndex, context.CountersignerCertificate, context.CountersignerPrivateKey,
                context.SigningTime, context.AlgorithmConstraints, context.IncludeCmsAlgorithmProtection, pool,
                cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The signature value a countersignature is computed over could not be read from the Signed Data Object (ETSI EN 319 122-1 clause 5.2.7, RFC 5652 §11.4).",
                exception);
        }

        using(attribute)
        {
            using CmsSignedData countersigned = CmsSignedDataAugmentation.AppendUnsignedAttributes(
                context.SignedData, context.SignerIndex, [attribute], pool);
            if(!context.IncludeCountersignerCertificate)
            {
                return CmsSignedData.FromBytes(countersigned.AsReadOnlySpan(), pool);
            }

            return CmsSignedDataAugmentation.AddCertificates(
                countersigned, [context.CountersignerCertificate.AsReadOnlyMemory()], pool);
        }
    }


    /// <summary>
    /// Adds the <c>signature-policy-store</c> unsigned attribute (clause 5.2.10), gated exactly per Table 1
    /// requirement k): incorporated only when the signer's <c>signature-policy-identifier</c> signed attribute
    /// (clause 5.2.9.1) is present AND its <c>sigPolicyHash</c> carries a real, non-zero digest — a zero-hash
    /// value states the policy hash is not known, and clause k) states the store "shall not be incorporated"
    /// in that case, otherwise.
    /// </summary>
    /// <param name="signedData">The signature to augment. Not modified; the result is a new carrier.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> being augmented.</param>
    /// <param name="store">The signature policy document or its local-store URI, and the technical specification identifying it.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The augmented signature. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="store"/> does not name exactly one alternative of <c>spDocSpec</c> or exactly one of <c>spDocument</c>.</exception>
    /// <exception cref="CAdESAugmentationException">When the signature cannot be walked, or requirement k)'s precondition is not met (<see cref="CAdESAugmentationFailureKind.SignaturePolicyStoreRequirementNotMet"/>).</exception>
    /// <remarks>
    /// The check reads the signer's OWN signed attributes from <paramref name="signedData"/> rather than
    /// trusting a caller-supplied flag: a caller cannot request this attribute for a signature the requirement
    /// does not actually hold for, however it was produced.
    /// </remarks>
    public static CmsSignedData AddSignaturePolicyStore(
        CmsSignedData signedData,
        int signerIndex,
        CAdESSignaturePolicyStore store,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        EnsureLegacyAttributeLockdownPermits(signedData, "signature-policy-store");

        ReadOnlyMemory<byte>? sigPolicyHash = ReadSignaturePolicyHashValue(signedData, signerIndex);
        if(sigPolicyHash is not { } hash || IsZeroHashValue(hash.Span))
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignaturePolicyStoreRequirementNotMet,
                "signature-policy-store may be incorporated only if signature-policy-identifier is also incorporated and its sigPolicyHash carries a real, non-zero digest value of the signature policy document (ETSI EN 319 122-1 Table 1 requirement k); otherwise it shall not be incorporated.");
        }

        using CmsAttribute attribute = BuildSignaturePolicyStoreAttribute(store, pool);

        return CmsSignedDataAugmentation.AppendUnsignedAttributes(signedData, signerIndex, [attribute], pool);
    }


    /// <summary>
    /// Reads the <c>sigPolicyHash.hashValue</c> octets of the signer's <c>signature-policy-identifier</c>
    /// signed attribute, for the requirement k) gate <see cref="AddSignaturePolicyStore"/> applies.
    /// </summary>
    /// <param name="signedData">The signature.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <returns>The hash value octets, or <see langword="null"/> when the attribute is absent or states <c>signaturePolicyImplied</c> (which carries no hash to check).</returns>
    /// <exception cref="CAdESAugmentationException">When the signed attributes cannot be walked, or the attribute value is not a well-formed <c>SignaturePolicyIdentifier</c>.</exception>
    private static ReadOnlyMemory<byte>? ReadSignaturePolicyHashValue(CmsSignedData signedData, int signerIndex)
    {
        ReadOnlyMemory<byte>? attributeValue;
        try
        {
            attributeValue = CmsSignedDataAugmentation.ReadSignedAttributeValue(
                signedData, signerIndex, CAdESSignatureFacts.SignaturePolicyIdentifierAttributeOid);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The signed attributes could not be walked to find the signature-policy-identifier attribute (ETSI EN 319 122-1 clause 5.2.9.1).",
                exception);
        }

        if(attributeValue is not { } value)
        {
            return null;
        }

        try
        {
            //SignaturePolicyIdentifier ::= CHOICE { signaturePolicyId SignaturePolicyId, signaturePolicyImplied
            //NULL }; the NULL alternative carries no hash to check requirement k) against.
            var reader = new AsnReader(value, AsnEncodingRules.DER);
            if(reader.PeekTag() == Asn1Tag.Null)
            {
                return null;
            }

            AsnReader signaturePolicyId = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            _ = signaturePolicyId.ReadObjectIdentifier();          //sigPolicyId
            AsnReader sigPolicyHash = signaturePolicyId.ReadSequence(); //sigPolicyHash: OtherHashAlgAndValue
            _ = sigPolicyHash.ReadSequence();                      //hashAlgorithm AlgorithmIdentifier
            byte[] hashValue = sigPolicyHash.ReadOctetString();    //hashValue

            return hashValue;
        }
        catch(AsnContentException exception)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The signature-policy-identifier attribute value is not a well-formed SignaturePolicyIdentifier (ETSI EN 319 122-1 clause 5.2.9.1).",
                exception);
        }
    }


    /// <summary>
    /// States whether a <c>sigPolicyHash.hashValue</c> is a zero-hash value: "an octet string of any length
    /// (including zero length) whose octets all have the value zero" (clause 5.2.9.1).
    /// </summary>
    /// <param name="hashValue">The hash value octets.</param>
    /// <returns><see langword="true"/> when every octet is zero (vacuously true for a zero-length value).</returns>
    private static bool IsZeroHashValue(ReadOnlySpan<byte> hashValue)
    {
        for(int i = 0; i < hashValue.Length; ++i)
        {
            if(hashValue[i] != 0)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Builds the <c>signature-policy-store</c> attribute value (clause 5.2.10):
    /// <c>SignaturePolicyStore ::= SEQUENCE { spDocSpec SPDocSpecification, spDocument SignaturePolicyDocument }</c>.
    /// </summary>
    private static CmsAttribute BuildSignaturePolicyStoreAttribute(CAdESSignaturePolicyStore store, MemoryPool<byte> pool)
    {
        if(store.DocumentSpecificationOid is null == store.DocumentSpecificationUri is null)
        {
            throw new ArgumentException(
                "A signature-policy-store's spDocSpec is exactly one of an object identifier or a URI (ETSI EN 319 122-1 clause 5.2.9.2).",
                nameof(store));
        }

        if(store.EncodedDocument is null == store.LocalDocumentUri is null)
        {
            throw new ArgumentException(
                "A signature-policy-store's spDocument is exactly one of the encoded document or a local URI (ETSI EN 319 122-1 clause 5.2.10).",
                nameof(store));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                //SignaturePolicyStore
        {
            if(store.DocumentSpecificationOid is { } oid)
            {
                writer.WriteObjectIdentifier(oid);
            }
            else
            {
                writer.WriteCharacterString(UniversalTagNumber.IA5String, store.DocumentSpecificationUri!);
            }

            if(store.EncodedDocument is { } encoded)
            {
                writer.WriteOctetString(encoded.Span);
            }
            else
            {
                writer.WriteCharacterString(UniversalTagNumber.IA5String, store.LocalDocumentUri!);
            }
        }

        return EncodeAttribute(CAdESSignatureFacts.SignaturePolicyStoreAttributeOid, writer, pool);
    }


    /// <summary>
    /// Refuses to add an unsigned attribute that is neither an <c>archive-time-stamp-v3</c> nor an Annex B
    /// attribute to a signature carrying a legacy long-term-availability attribute — clause 5.5.3: "If an ATSv2,
    /// or other earlier form of archive time-stamp or a <c>long-term-validation</c> attribute, is present then no
    /// other attributes than ATSv3 or attributes specified as per annex B shall be added to the
    /// <c>unsignedAttrs</c>."
    /// </summary>
    /// <param name="signedData">The signature the attribute would be added to.</param>
    /// <param name="attributeName">The attribute being refused, for the message.</param>
    /// <exception cref="CAdESAugmentationException">When a legacy attribute is present (<see cref="CAdESAugmentationFailureKind.LegacyAttributeForbidsFurtherAttributes"/>), or the signature cannot be walked.</exception>
    /// <remarks>
    /// <para>
    /// <strong>Three write paths call this gate</strong>, each before it does anything else that would be
    /// wasted on a refused call: <see cref="AddSignatureTimestampAsync"/> (before the digest and the
    /// Time-Stamping Authority round trip, so a refused call fetches or bills no token),
    /// <see cref="AddCountersignatureAsync"/>, and <see cref="AddSignaturePolicyStore"/>. All three add an
    /// outer unsigned attribute the clause's closed set does not name.
    /// </para>
    /// <para>
    /// The two level-raising surfaces this does not gate are the ones the clause itself exempts: the
    /// <c>archive-time-stamp-v3</c> of <see cref="AddArchiveTimestampAsync"/> is the named exception, and
    /// <see cref="AddValidationData"/> adds no outer unsigned attribute at all under the same condition — it
    /// switches to the nested placement of <see cref="CAdESValidationDataPlacement.LatestArchiveTimestampToken"/>,
    /// whose <c>certificate-values</c>/<c>revocation-values</c> attributes land inside the time-stamp token's own
    /// <c>SignerInfo</c> rather than the signature's. <see cref="DetectValidationDataPlacement"/> is the one
    /// detector for both decisions, so the lockdown and the placement can never disagree about what "legacy
    /// attribute present" means.
    /// </para>
    /// </remarks>
    private static void EnsureLegacyAttributeLockdownPermits(CmsSignedData signedData, string attributeName)
    {
        if(DetectValidationDataPlacement(signedData) == CAdESValidationDataPlacement.LatestArchiveTimestampToken)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.LegacyAttributeForbidsFurtherAttributes,
                $"The signature carries a legacy long-term-availability attribute, so no attribute other than archive-time-stamp-v3 or an Annex B attribute shall be added to its unsignedAttrs; '{attributeName}' is neither (ETSI EN 319 122-1 clause 5.5.3).");
        }
    }


    /// <summary>
    /// States which of the two placements of clause 5.5.3 applies to a signature: the root <c>SignedData</c>
    /// when no legacy long-term-availability attribute is present in <em>any</em> of its signers, and the latest
    /// archive time-stamp's own token when one is.
    /// </summary>
    /// <param name="signedData">The signature.</param>
    /// <returns>The placement clause 5.5.3 selects.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="CAdESAugmentationException">When the signature cannot be walked.</exception>
    /// <remarks>
    /// The scan covers every <c>SignerInfo</c> because the clause makes the whole root <c>SignedData</c> the
    /// unit of the decision: "If an ATSv2, or other earlier form of archive time-stamp or a
    /// <c>long-term-validation</c> attribute, is present in any <c>SignerInfo</c> of the root
    /// <c>SignedData</c> then the root <c>SignedData.certificates</c> and <c>SignedData.crls</c> contents shall
    /// not be modified". The deprecated hash-index attributes of clause A.2.6 count as evidence of such an
    /// earlier form, which is the conservative reading: it can only move a signature to the placement that
    /// leaves the root untouched, never the other way.
    /// </remarks>
    public static CAdESValidationDataPlacement DetectValidationDataPlacement(CmsSignedData signedData)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        try
        {
            int signers = CmsSignedDataAugmentation.CountSigners(signedData);
            for(int signerIndex = 0; signerIndex < signers; ++signerIndex)
            {
                IReadOnlyList<CmsUnsignedAttributeValueLocation> locations =
                    CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex);
                for(int i = 0; i < locations.Count; ++i)
                {
                    if(IsLegacyLongTermAvailabilityAttribute(locations[i].AttributeType))
                    {
                        return CAdESValidationDataPlacement.LatestArchiveTimestampToken;
                    }
                }
            }

            return CAdESValidationDataPlacement.RootSignedData;
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The Signed Data Object could not be walked to determine where validation material is placed (ETSI EN 319 122-1 clause 5.5.3).",
                exception);
        }
    }


    /// <summary>
    /// Raises a signature to CAdES-B-LT: places the caller's validation material where clause 5.5.3 and Table 1
    /// requirements o) to r) put it, avoiding duplication of what is already there.
    /// </summary>
    /// <param name="signedData">The signature to augment. Not modified; the result is a new carrier.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> being raised, which selects the token addressed by the second placement.</param>
    /// <param name="material">The certificates and revocation information to place.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The augmented signature. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="material"/> names nothing to place.</exception>
    /// <exception cref="CAdESAugmentationException">When the signature or a supplied object cannot be read, an object is of an unusable kind, a Delta CRL arrives without the complete set, or the placement has no archive time-stamp token to write into.</exception>
    /// <remarks>
    /// <para>
    /// Under the first placement, CRLs go into <c>SignedData.crls.crl</c> (requirement q) and OCSP responses
    /// into <c>SignedData.crls.other</c> per RFC 5940 (requirement r), while certificates go into
    /// <c>SignedData.certificates</c> (requirement d). Under the second, the root sets are left untouched and
    /// the material is written as <c>certificate-values</c> (clause A.1.1.2) and <c>revocation-values</c>
    /// (clause A.1.2.2) unsigned attributes of the latest archive time-stamp token's own signer.
    /// </para>
    /// <para>
    /// Clause 5.5.3 states that when the validation data contains a Delta CRL "then the whole set of CRLs shall
    /// be included to provide a complete revocation list": a Delta CRL offered with no complete CRL among the
    /// material or already in the signature is refused rather than written.
    /// </para>
    /// </remarks>
    public static CmsSignedData AddValidationData(
        CmsSignedData signedData,
        int signerIndex,
        CAdESValidationMaterial material,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        if(material.IsEmpty)
        {
            throw new ArgumentException("Placing validation data places at least one certificate, certificate revocation list, or OCSP response.", nameof(material));
        }

        EnsureCompleteCrlSet(signedData, material);

        return DetectValidationDataPlacement(signedData) switch
        {
            CAdESValidationDataPlacement.LatestArchiveTimestampToken => PlaceInLatestArchiveTimestamp(signedData, signerIndex, material, pool),
            _ => PlaceInRootSignedData(signedData, material, pool)
        };
    }


    /// <summary>
    /// Raises a signature to CAdES-B-LTA: places whatever validation material requirement s) needs first,
    /// computes the <c>ats-hash-index-v3</c> and the four-part message imprint input of clause 5.5.3, obtains
    /// and verifies a time-stamp token over it, grafts the index into that token's own unsigned attributes as
    /// the clause requires, and attaches the completed <c>archive-time-stamp-v3</c>.
    /// </summary>
    /// <param name="context">The signature, the material, the imprint algorithm, and the authority to contact.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the context's signer index is negative.</exception>
    /// <exception cref="CAdESAugmentationException">When the signature or the supplied material cannot be used, per <see cref="AddValidationData"/>; when the signature cannot be read to compute the <c>ats-hash-index-v3</c> or the message imprint input (clauses 5.5.2/5.5.3), including a signature that encapsulates no content when neither the detached content nor its digest was supplied; or when Table 1 requirement m) is not satisfied.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or the token it returned does not verify.</exception>
    /// <exception cref="InvalidOperationException">When no <see cref="ComputeDigestDelegate"/> has been registered — a composition fault of the host.</exception>
    /// <remarks>
    /// <para>
    /// The order is the one requirement s) states: the material goes in first, so the hash index covers it and
    /// the archive time-stamp protects it. The index is computed over the signature as it stands at that moment
    /// — "as present at the time when the corresponding archive time-stamp is requested" — which is before the
    /// new <c>archive-time-stamp-v3</c> attribute itself is attached, since an attribute cannot index itself.
    /// </para>
    /// <para>
    /// Grafting the index into the returned token changes octets outside that token's own signature: the
    /// unsigned attributes of a time-stamp token are not covered by the authority's signature over its
    /// <c>TSTInfo</c>, which is exactly why clause 5.5.3 can require the token to carry the index at all.
    /// </para>
    /// <para>
    /// <see cref="EnsureRequirementMSatisfied"/> checks the acquired token's generation time before it is
    /// grafted or attached — Table 1 requirement m)'s secure default applied here as defense in depth (see
    /// <see cref="CAdESArchiveTimestampContext.EnforceSigningCertificateValidity"/> for the opt-out a caller
    /// raising an already-expired signature to B-LTA needs).
    /// </para>
    /// <para>
    /// A raw <see cref="AsnContentException"/> or <see cref="CryptographicException"/> from
    /// <see cref="ArchiveTimestampV3.ComputeHashIndexAsync"/> or
    /// <see cref="ArchiveTimestampV3.BuildMessageImprintInputAsync"/> — a malformed, truncated, or
    /// indefinite-length-BER Signed Data Object; see the class remarks on the DER-only scope of that
    /// computation — is caught and reported as <see cref="CAdESAugmentationFailureKind.SignedDataMalformed"/>,
    /// the same typed-failure discipline every other splice in this class keeps.
    /// </para>
    /// </remarks>
    public static async ValueTask<CmsSignedData> AddArchiveTimestampAsync(
        CAdESArchiveTimestampContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(context.SignerIndex);

        PkiDigestAlgorithm algorithm = context.MessageImprintAlgorithm;
        CmsSignedData extended = context.ValidationMaterial.IsEmpty
            ? CmsSignedData.FromBytes(context.SignedData.AsReadOnlySpan(), pool)
            : AddValidationData(context.SignedData, context.SignerIndex, context.ValidationMaterial, pool);
        try
        {
            using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
                extended, context.SignerIndex, algorithm, pool, cancellationToken).ConfigureAwait(false);
            using SignedContentMemory imprintInput = await ArchiveTimestampV3.BuildMessageImprintInputAsync(
                new ArchiveTimestampImprintContext
                {
                    SignedData = extended,
                    HashIndex = hashIndex,
                    MessageImprintAlgorithm = algorithm,
                    SignerIndex = context.SignerIndex,
                    DetachedSignedContent = context.DetachedSignedContent,
                    DetachedSignedContentDigest = context.DetachedSignedContentDigest
                },
                pool,
                cancellationToken).ConfigureAwait(false);

            using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                imprintInput.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
            using AcquiredTimestampToken token = await TimestampAcquisition.AcquireAsync(
                imprint, context.TsaUri, context.FetchResponse, pool,
                context.ReqPolicyOid, context.NonceByteLength, context.IncludeNonce, cancellationToken).ConfigureAwait(false);
            EnsureRequirementMSatisfied(
                token, context.SigningCertificate, context.SigningCertificateRevokedAt, context.EnforceSigningCertificateValidity);

            using CmsSignedData tokenAsSignedData = CmsSignedData.FromBytes(token.Token.AsReadOnlySpan(), pool);
            using CmsAttribute indexAttribute = CmsAttribute.Create(
                CAdESSignatureFacts.AtsHashIndexV3AttributeOid, hashIndex.AsReadOnlySpan(), pool);
            using CmsSignedData grafted = CmsSignedDataAugmentation.AppendUnsignedAttributes(
                tokenAsSignedData, signerIndex: 0, [indexAttribute], pool);
            using CmsAttribute archiveAttribute = CmsAttribute.Create(
                CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, grafted.AsReadOnlySpan(), pool);

            return CmsSignedDataAugmentation.AppendUnsignedAttributes(extended, context.SignerIndex, [archiveAttribute], pool);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The signature could not be read to compute the ats-hash-index-v3 or the archive time-stamp's message imprint input (ETSI EN 319 122-1 clauses 5.5.2, 5.5.3).",
                exception);
        }
        finally
        {
            extended.Dispose();
        }
    }


    /// <summary>
    /// Writes the material into the root <c>SignedData</c>: certificates into <c>certificates</c>, CRLs into
    /// <c>crls</c> as the <c>crl</c> alternative, and OCSP responses into <c>crls</c> as the <c>other</c>
    /// alternative typed by <c>id-ri-ocsp-response</c>.
    /// </summary>
    /// <param name="signedData">The signature to augment.</param>
    /// <param name="material">The material to place.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The augmented signature. The caller owns and disposes it.</returns>
    private static CmsSignedData PlaceInRootSignedData(CmsSignedData signedData, CAdESValidationMaterial material, MemoryPool<byte> pool)
    {
        List<ReadOnlyMemory<byte>> certificates = CollectCertificateEncodings(material);
        List<PooledMemory> wrappedResponses = [];
        try
        {
            List<ReadOnlyMemory<byte>> revocationInformation = [];
            for(int i = 0; i < material.CertificateRevocationLists.Count; ++i)
            {
                PkiCertificateMemory crl = material.CertificateRevocationLists[i];
                EnsureKind(crl.IsCrl, "A certificate revocation list placed in SignedData.crls is a DER-encoded CertificateList (ETSI EN 319 122-1 Table 1 requirement q).");
                revocationInformation.Add(crl.AsReadOnlyMemory());
            }

            for(int i = 0; i < material.OcspResponses.Count; ++i)
            {
                PkiCertificateMemory response = material.OcspResponses[i];
                EnsureKind(response.IsOcspResponse, "An OCSP response placed in SignedData.crls is a DER-encoded OCSP response (ETSI EN 319 122-1 Table 1 requirement r).");
                if(ReadOcspResponseForm(response.AsReadOnlyMemory()) != OcspResponseForm.Response)
                {
                    throw new CAdESAugmentationException(
                        CAdESAugmentationFailureKind.UnsupportedValidationObject,
                        "SignedData.crls carries an OCSP response as the OCSPResponse type its RFC 5940 encoding names (ETSI EN 319 122-1 clause 5.4.2.2); a bare BasicOCSPResponse has no place there.");
                }

                PooledMemory wrapped = WrapOcspResponseAsRevocationInfoChoice(response.AsReadOnlySpan(), pool);
                wrappedResponses.Add(wrapped);
                revocationInformation.Add(wrapped.AsReadOnlyMemory());
            }

            CmsSignedData withCertificates = certificates.Count > 0
                ? CmsSignedDataAugmentation.AddCertificates(signedData, certificates, pool)
                : CmsSignedData.FromBytes(signedData.AsReadOnlySpan(), pool);
            if(revocationInformation.Count == 0)
            {
                return withCertificates;
            }

            using(withCertificates)
            {
                return CmsSignedDataAugmentation.AddRevocationInformation(withCertificates, revocationInformation, pool);
            }
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The validation material could not be placed into the root SignedData (ETSI EN 319 122-1 clause 5.5.3).",
                exception);
        }
        finally
        {
            for(int i = 0; i < wrappedResponses.Count; ++i)
            {
                wrappedResponses[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Writes the material into the time-stamp token of the latest archive time-stamp, as the
    /// <c>certificate-values</c> and <c>revocation-values</c> unsigned attributes of that token's own signer —
    /// the second placement of clause 5.5.3, which leaves the root <c>SignedData</c> untouched.
    /// </summary>
    /// <param name="signedData">The signature to augment.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> whose archive time-stamp is addressed.</param>
    /// <param name="material">The material to place.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The augmented signature. The caller owns and disposes it.</returns>
    private static CmsSignedData PlaceInLatestArchiveTimestamp(
        CmsSignedData signedData,
        int signerIndex,
        CAdESValidationMaterial material,
        MemoryPool<byte> pool)
    {
        CmsUnsignedAttributeValueLocation location = SelectLatestArchiveTimestamp(signedData, signerIndex);
        ReadOnlyMemory<byte> tokenEncoding = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(
            signedData, signerIndex, location.AttributeIndex, location.ValueIndex);

        using CmsSignedData token = CmsSignedData.FromBytes(tokenEncoding.Span, pool);
        List<CmsAttribute> attributes = [];
        try
        {
            //Clauses A.1.1.2 and A.1.2.2 make both attributes closed sets whose members are the ones not
            //already stored in the SignedData they belong to: what the root signature or the token already
            //carries is not repeated here.
            List<ReadOnlyMemory<byte>> knownCertificates = [.. CmsSignedDataAugmentation.ReadCertificates(signedData), .. CmsSignedDataAugmentation.ReadCertificates(token)];
            List<ReadOnlyMemory<byte>> certificates = ExcludeKnown(CollectCertificateEncodings(material), knownCertificates);
            if(certificates.Count > 0)
            {
                attributes.Add(BuildCertificateValuesAttribute(certificates, pool));
            }

            if(material.CertificateRevocationLists.Count > 0 || material.OcspResponses.Count > 0)
            {
                attributes.Add(BuildRevocationValuesAttribute(material, pool));
            }

            if(attributes.Count == 0)
            {
                //Every candidate was already stored where the closed-set rule says it belongs, so the signature
                //stands as it was; the copy keeps the caller's ownership contract the same either way.
                return CmsSignedData.FromBytes(signedData.AsReadOnlySpan(), pool);
            }

            using CmsSignedData augmentedToken = CmsSignedDataAugmentation.AppendUnsignedAttributes(token, signerIndex: 0, attributes, pool);

            return CmsSignedDataAugmentation.ReplaceUnsignedAttributeValue(
                signedData, signerIndex, location.AttributeIndex, location.ValueIndex, augmentedToken.AsReadOnlySpan(), pool);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The validation material could not be placed into the latest archive time-stamp's token (ETSI EN 319 122-1 clause 5.5.3).",
                exception);
        }
        finally
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                attributes[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Selects the archive time-stamp clause 5.5.3 calls "the latest ... already contained in the
    /// <c>SignerInfo</c>", which is the last one in the encoding order of the unsigned attribute set.
    /// </summary>
    /// <param name="signedData">The signature.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <returns>The location of the archive time-stamp token's attribute value.</returns>
    /// <exception cref="CAdESAugmentationException">When the signer carries no archive time-stamp, or the latest legacy attribute is one whose internal structure this surface does not author material into.</exception>
    /// <remarks>
    /// Encoding order is addition order for anything this library produced, because every augmentation here
    /// appends and none re-sorts the set; NOTE 6 of the clause describes the same succession from the
    /// generator's side, an added ATSv3 becoming "the latest archive time-stamp" for the next augmentation.
    /// </remarks>
    private static CmsUnsignedAttributeValueLocation SelectLatestArchiveTimestamp(CmsSignedData signedData, int signerIndex)
    {
        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations;
        try
        {
            locations = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The unsigned attributes of the signer being augmented could not be walked (RFC 5652 §5.3).",
                exception);
        }

        CmsUnsignedAttributeValueLocation? latest = null;
        for(int i = 0; i < locations.Count; ++i)
        {
            if(IsLegacyLongTermAvailabilityAttribute(locations[i].AttributeType)
                || string.Equals(locations[i].AttributeType, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, StringComparison.Ordinal))
            {
                latest = locations[i];
            }
        }

        if(latest is not CmsUnsignedAttributeValueLocation selected)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.NoArchiveTimestampToAugment,
                "The signature carries a legacy long-term-availability attribute, so ETSI EN 319 122-1 clause 5.5.3 places new validation material inside the latest archive time-stamp's token, and the signer being augmented carries none.");
        }

        if(!string.Equals(selected.AttributeType, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid, StringComparison.Ordinal)
            && !string.Equals(selected.AttributeType, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, StringComparison.Ordinal))
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.LegacyAttributePlacementUnsupported,
                $"The latest long-term-availability attribute of the signer is '{selected.AttributeType}', whose value is not a time-stamp token this surface can place validation material inside (ETSI EN 319 122-1 clause 5.5.3).");
        }

        return selected;
    }


    /// <summary>
    /// Builds the <c>certificate-values</c> attribute of clause A.1.1.2: <c>SEQUENCE OF Certificate</c>, DER
    /// encoded as everything an augmentation adds is.
    /// </summary>
    /// <param name="certificates">The whole encodings of the certificates the attribute states.</param>
    /// <param name="pool">The memory pool the attribute is rented from.</param>
    /// <returns>The attribute. The caller disposes it.</returns>
    private static CmsAttribute BuildCertificateValuesAttribute(List<ReadOnlyMemory<byte>> certificates, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            for(int i = 0; i < certificates.Count; ++i)
            {
                writer.WriteEncodedValue(certificates[i].Span);
            }
        }

        return EncodeAttribute(CAdESSignatureFacts.CertificateValuesAttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the <c>revocation-values</c> attribute of clause A.1.2.2: CRLs in <c>crlVals</c>, a
    /// <c>BasicOCSPResponse</c> in <c>ocspVals</c>, and a whole <c>OCSPResponse</c> in <c>otherRevVals</c> under
    /// the <c>id-ri-ocsp-response</c> object identifier the clause names for exactly that case. The Annex D
    /// module (<c>ETSI-CAdES-ExplicitSyntax97</c>) opens <c>DEFINITIONS EXPLICIT TAGS</c>, so each <c>[n]</c>
    /// field tag is written CONSTRUCTED and ENCLOSES the tagged type's own tag rather than replacing it:
    /// <c>crlVals [0] { SEQUENCE OF CertificateList }</c>, <c>ocspVals [1] { SEQUENCE OF BasicOCSPResponse }</c>,
    /// and <c>otherRevVals [2] { OtherRevVals SEQUENCE { OID, SEQUENCE OF OCSPResponse } }</c>.
    /// </summary>
    /// <param name="material">The material whose revocation information the attribute states.</param>
    /// <param name="pool">The memory pool the attribute is rented from.</param>
    /// <returns>The attribute. The caller disposes it.</returns>
    /// <exception cref="CAdESAugmentationException">When a supplied object is not of a kind the attribute admits.</exception>
    private static CmsAttribute BuildRevocationValuesAttribute(CAdESValidationMaterial material, MemoryPool<byte> pool)
    {
        List<ReadOnlyMemory<byte>> basicResponses = [];
        List<ReadOnlyMemory<byte>> wholeResponses = [];
        for(int i = 0; i < material.OcspResponses.Count; ++i)
        {
            PkiCertificateMemory response = material.OcspResponses[i];
            EnsureKind(response.IsOcspResponse, "An OCSP response placed in revocation-values is a DER-encoded OCSP response (ETSI EN 319 122-1 clause A.1.2.2).");
            if(ReadOcspResponseForm(response.AsReadOnlyMemory()) == OcspResponseForm.BasicResponse)
            {
                basicResponses.Add(response.AsReadOnlyMemory());
            }
            else
            {
                wholeResponses.Add(response.AsReadOnlyMemory());
            }
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                    //RevocationValues
        {
            if(material.CertificateRevocationLists.Count > 0)
            {
                using(writer.PushSequence(ContextConstructed0))          //crlVals [0] EXPLICIT (the Annex D module is DEFINITIONS EXPLICIT TAGS)
                {
                    using(writer.PushSequence())                        //SEQUENCE OF CertificateList
                    {
                        for(int i = 0; i < material.CertificateRevocationLists.Count; ++i)
                        {
                            PkiCertificateMemory crl = material.CertificateRevocationLists[i];
                            EnsureKind(crl.IsCrl, "A certificate revocation list placed in revocation-values is a DER-encoded CertificateList (ETSI EN 319 122-1 clause A.1.2.2).");
                            writer.WriteEncodedValue(crl.AsReadOnlySpan());
                        }
                    }
                }
            }

            if(basicResponses.Count > 0)
            {
                using(writer.PushSequence(ContextConstructed1))          //ocspVals [1] EXPLICIT
                {
                    using(writer.PushSequence())                        //SEQUENCE OF BasicOCSPResponse
                    {
                        for(int i = 0; i < basicResponses.Count; ++i)
                        {
                            writer.WriteEncodedValue(basicResponses[i].Span);
                        }
                    }
                }
            }

            if(wholeResponses.Count > 0)
            {
                using(writer.PushSequence(ContextConstructed2))          //otherRevVals [2] EXPLICIT
                {
                    using(writer.PushSequence())                        //OtherRevVals ::= SEQUENCE { otherRevValType OID, otherRevVals SEQUENCE OF OCSPResponse }
                    {
                        writer.WriteObjectIdentifier(OcspResponseRevocationInfoOid);
                        using(writer.PushSequence())                    //SEQUENCE OF OCSPResponse
                        {
                            for(int i = 0; i < wholeResponses.Count; ++i)
                            {
                                writer.WriteEncodedValue(wholeResponses[i].Span);
                            }
                        }
                    }
                }
            }
        }

        return EncodeAttribute(CAdESSignatureFacts.RevocationValuesAttributeOid, writer, pool);
    }


    /// <summary>
    /// Wraps a whole <c>OCSPResponse</c> as the <c>other</c> alternative of <c>RevocationInfoChoice</c>, the
    /// encoding RFC 5940 §2 defines and clause 5.4.2.2 of ETSI EN 319 122-1 requires for an OCSP response
    /// carried in <c>SignedData.crls</c>.
    /// </summary>
    /// <param name="response">The DER-encoded <c>OCSPResponse</c>.</param>
    /// <param name="pool">The memory pool the encoding is rented from.</param>
    /// <returns>The encoded <c>RevocationInfoChoice</c>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static PooledMemory WrapOcspResponseAsRevocationInfoChoice(ReadOnlySpan<byte> response, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence(ContextConstructed1))
        {
            writer.WriteObjectIdentifier(OcspResponseRevocationInfoOid);
            writer.WriteEncodedValue(response);
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return new PooledMemory(owner, written, CryptoTags.CmsEncodedAttribute);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Encodes a writer's single value as one DER attribute value of an attribute.
    /// </summary>
    /// <param name="attributeType">The attribute's <c>attrType</c> object identifier.</param>
    /// <param name="valueWriter">The writer holding exactly the attribute's value.</param>
    /// <param name="pool">The memory pool the attribute is rented from.</param>
    /// <returns>The attribute. The caller disposes it.</returns>
    private static CmsAttribute EncodeAttribute(string attributeType, AsnWriter valueWriter, MemoryPool<byte> pool)
    {
        int encodedLength = valueWriter.GetEncodedLength();
        byte[]? rented = null;
        Span<byte> scratch = encodedLength <= 512 ? stackalloc byte[512] : (rented = new byte[encodedLength]);
        try
        {
            _ = valueWriter.TryEncode(scratch, out int written);

            return CmsAttribute.Create(attributeType, scratch[..written], pool);
        }
        finally
        {
            if(rented is not null)
            {
                Array.Clear(rented);
            }
        }
    }


    /// <summary>
    /// Returns the whole encodings of the material's certificates, refusing anything that is not one.
    /// </summary>
    /// <param name="material">The material.</param>
    /// <returns>The encodings, in the order they were supplied.</returns>
    /// <exception cref="CAdESAugmentationException">When an object is not an X.509 certificate.</exception>
    private static List<ReadOnlyMemory<byte>> CollectCertificateEncodings(CAdESValidationMaterial material)
    {
        List<ReadOnlyMemory<byte>> certificates = [];
        for(int i = 0; i < material.Certificates.Count; ++i)
        {
            PkiCertificateMemory certificate = material.Certificates[i];
            EnsureKind(certificate.IsX509Certificate, "A certificate placed as validation material is a DER-encoded X.509 certificate (ETSI EN 319 122-1 Table 1 requirement d).");
            certificates.Add(certificate.AsReadOnlyMemory());
        }

        return certificates;
    }


    /// <summary>
    /// Returns the candidates whose encoding is not among the ones already stored somewhere the closed-set rules
    /// of clauses A.1.1.2 and A.1.2.2 count as stored.
    /// </summary>
    /// <param name="candidates">The candidate encodings.</param>
    /// <param name="known">The encodings already stored.</param>
    /// <returns>The candidates not already stored, in the order they were offered, each at most once.</returns>
    private static List<ReadOnlyMemory<byte>> ExcludeKnown(List<ReadOnlyMemory<byte>> candidates, List<ReadOnlyMemory<byte>> known)
    {
        List<ReadOnlyMemory<byte>> selected = [];
        for(int i = 0; i < candidates.Count; ++i)
        {
            bool alreadyStored = false;
            for(int j = 0; j < known.Count && !alreadyStored; ++j)
            {
                alreadyStored = known[j].Span.SequenceEqual(candidates[i].Span);
            }

            for(int j = 0; j < selected.Count && !alreadyStored; ++j)
            {
                alreadyStored = selected[j].Span.SequenceEqual(candidates[i].Span);
            }

            if(!alreadyStored)
            {
                selected.Add(candidates[i]);
            }
        }

        return selected;
    }


    /// <summary>
    /// Enforces clause 5.5.3's rule that a Delta CRL is only placed together with the whole set of CRLs: a
    /// complete revocation list has to be among the material or already in the signature.
    /// </summary>
    /// <param name="signedData">The signature the material is placed into.</param>
    /// <param name="material">The material to place.</param>
    /// <exception cref="CAdESAugmentationException">When a Delta CRL arrives without a complete list, or a supplied list cannot be read.</exception>
    private static void EnsureCompleteCrlSet(CmsSignedData signedData, CAdESValidationMaterial material)
    {
        bool hasDelta = false;
        bool hasComplete = false;
        for(int i = 0; i < material.CertificateRevocationLists.Count; ++i)
        {
            PkiCertificateMemory crl = material.CertificateRevocationLists[i];
            EnsureKind(crl.IsCrl, "A certificate revocation list placed as validation material is a DER-encoded CertificateList (ETSI EN 319 122-1 clause 5.4.3).");
            if(IsDeltaCertificateRevocationList(crl.AsReadOnlyMemory()))
            {
                hasDelta = true;
            }
            else
            {
                hasComplete = true;
            }
        }

        if(!hasDelta || hasComplete)
        {
            return;
        }

        IReadOnlyList<ReadOnlyMemory<byte>> present;
        try
        {
            present = CmsSignedDataAugmentation.ReadRevocationInformation(signedData);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SignedDataMalformed,
                "The revocation information already in the signature could not be read while checking that a Delta CRL comes with the whole set (ETSI EN 319 122-1 clause 5.5.3).",
                exception);
        }

        for(int i = 0; i < present.Count && !hasComplete; ++i)
        {
            //Only the crl alternative of RevocationInfoChoice is a certificate list at all; the other
            //alternative is context-tagged and carries an OCSP response, which no Delta CRL is completed by.
            if(present[i].Length > 0 && present[i].Span[0] == 0x30 && !IsDeltaCertificateRevocationList(present[i]))
            {
                hasComplete = true;
            }
        }

        if(!hasComplete)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.DeltaCrlWithoutCompleteSet,
                "A Delta CRL is placed only together with the whole set of CRLs, so that the revocation list the signature carries is complete (ETSI EN 319 122-1 clause 5.5.3).");
        }
    }


    /// <summary>
    /// States whether a <c>CertificateList</c> carries the <c>deltaCRLIndicator</c> extension, which makes it a
    /// Delta CRL (RFC 5280 §5.2.4).
    /// </summary>
    /// <param name="certificateList">The DER-encoded <c>CertificateList</c>.</param>
    /// <returns><see langword="true"/> when the list is a Delta CRL.</returns>
    /// <exception cref="CAdESAugmentationException">When the list cannot be read.</exception>
    private static bool IsDeltaCertificateRevocationList(ReadOnlyMemory<byte> certificateList)
    {
        try
        {
            var outer = new AsnReader(certificateList, AsnEncodingRules.DER);
            AsnReader list = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            AsnReader tbs = list.ReadSequence();

            AsnReader? extensions = null;
            int walked = 0;
            while(tbs.HasData && extensions is null)
            {
                if(walked == MaximumCertificateListFields)
                {
                    throw new AsnContentException($"A TBSCertList is walked with at most {MaximumCertificateListFields} fields.");
                }

                if(tbs.PeekTag() == ContextConstructed0)
                {
                    extensions = tbs.ReadSequence(ContextConstructed0).ReadSequence();

                    break;
                }

                _ = tbs.ReadEncodedValue();
                ++walked;
            }

            if(extensions is null)
            {
                return false;
            }

            int read = 0;
            while(extensions.HasData)
            {
                if(read == MaximumCertificateListExtensions)
                {
                    throw new AsnContentException($"A TBSCertList is walked with at most {MaximumCertificateListExtensions} extensions.");
                }

                AsnReader extension = extensions.ReadSequence();
                if(string.Equals(extension.ReadObjectIdentifier(), DeltaCrlIndicatorOid, StringComparison.Ordinal))
                {
                    return true;
                }

                ++read;
            }

            return false;
        }
        catch(AsnContentException exception)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.ValidationObjectMalformed,
                "A certificate revocation list supplied as validation material is not a well-formed CertificateList (RFC 5280 §5.1).",
                exception);
        }
    }


    /// <summary>
    /// States which of the two OCSP response types a carrier holds, by the type of the first field: an
    /// <c>OCSPResponse</c> begins with its <c>responseStatus</c> enumeration, a <c>BasicOCSPResponse</c> with
    /// its <c>tbsResponseData</c> sequence (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC
    /// 6960 §4.2.1</see>).
    /// </summary>
    /// <param name="response">The DER-encoded response.</param>
    /// <returns>The form the response is in.</returns>
    /// <exception cref="CAdESAugmentationException">When the response is neither, or cannot be read.</exception>
    private static OcspResponseForm ReadOcspResponseForm(ReadOnlyMemory<byte> response)
    {
        try
        {
            var outer = new AsnReader(response, AsnEncodingRules.DER);
            AsnReader sequence = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            Asn1Tag first = sequence.PeekTag();

            return first == Asn1Tag.Enumerated
                ? OcspResponseForm.Response
                : first == Asn1Tag.Sequence
                    ? OcspResponseForm.BasicResponse
                    : throw new CAdESAugmentationException(
                        CAdESAugmentationFailureKind.UnsupportedValidationObject,
                        "An OCSP response is either an OCSPResponse beginning with its responseStatus or a BasicOCSPResponse beginning with its tbsResponseData (RFC 6960 §4.2.1).");
        }
        catch(AsnContentException exception)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.ValidationObjectMalformed,
                "An OCSP response supplied as validation material is not well-formed DER (RFC 6960 §4.2.1).",
                exception);
        }
    }


    /// <summary>
    /// States whether an attribute type is one of the deprecated long-term-availability attributes whose
    /// presence selects the second placement of clause 5.5.3.
    /// </summary>
    /// <param name="attributeType">The attribute's <c>attrType</c> object identifier.</param>
    /// <returns><see langword="true"/> when the attribute is a legacy long-term-availability attribute.</returns>
    private static bool IsLegacyLongTermAvailabilityAttribute(string attributeType) => attributeType switch
    {
        var type when string.Equals(type, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid, StringComparison.Ordinal) => true,
        var type when string.Equals(type, CAdESSignatureFacts.LongTermValidationAttributeOid, StringComparison.Ordinal) => true,
        var type when string.Equals(type, CAdESSignatureFacts.AtsHashIndexAttributeOid, StringComparison.Ordinal) => true,
        var type when string.Equals(type, CAdESSignatureFacts.AtsHashIndexV2AttributeOid, StringComparison.Ordinal) => true,
        _ => false
    };


    /// <summary>
    /// Enforces Table 1 requirement m) — "the time-stamp tokens inside <c>signature-time-stamp</c> shall be
    /// created before the signing certificate has been revoked or has expired" — against an acquired token
    /// before <see cref="AddSignatureTimestampAsync"/> or <see cref="AddArchiveTimestampAsync"/> attaches it.
    /// Secure by default: both context records' <c>EnforceSigningCertificateValidity</c> defaults to
    /// <see langword="true"/>, so a caller opts out explicitly rather than by omission — the shape a caller
    /// raising a long-preserved, already-expired signature to B-LTA (the normal case an archive time-stamp
    /// exists to survive) needs to set deliberately.
    /// </summary>
    /// <param name="token">The already-verified token.</param>
    /// <param name="signingCertificate">The signer's own certificate, or <see langword="null"/> when <paramref name="enforce"/> is <see langword="false"/>.</param>
    /// <param name="revokedAt">The instant the certificate is known revoked, or <see langword="null"/> when none is known.</param>
    /// <param name="enforce">Whether the check runs at all.</param>
    /// <exception cref="ArgumentException">When <paramref name="enforce"/> is <see langword="true"/> and <paramref name="signingCertificate"/> is <see langword="null"/> — enforcement needs a certificate to check against; omitting one silently would defeat the secure default.</exception>
    /// <exception cref="CAdESAugmentationException">When the token's generation time falls outside the certificate's validity window, or at or after <paramref name="revokedAt"/>.</exception>
    private static void EnsureRequirementMSatisfied(
        AcquiredTimestampToken token, PkiCertificateMemory? signingCertificate, DateTimeOffset? revokedAt, bool enforce)
    {
        if(!enforce)
        {
            return;
        }

        if(signingCertificate is null)
        {
            throw new ArgumentException(
                "Requirement m) enforcement requires the signing certificate to check the acquired token's generation time against (ETSI EN 319 122-1 Table 1 requirement m); supply SigningCertificate or set EnforceSigningCertificateValidity = false explicitly.",
                nameof(signingCertificate));
        }

        ManagedCertificate certificate = ManagedCertificate.Parse(signingCertificate.AsReadOnlyMemory());
        DateTimeOffset generationTime = token.Info.GenerationTime;
        if(generationTime < certificate.NotBefore || generationTime > certificate.NotAfter)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp,
                $"The acquired time-stamp token was generated at {generationTime:O}, outside the signing certificate's validity window {certificate.NotBefore:O} to {certificate.NotAfter:O} (ETSI EN 319 122-1 Table 1 requirement m).");
        }

        if(revokedAt is { } revocationInstant && generationTime >= revocationInstant)
        {
            throw new CAdESAugmentationException(
                CAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp,
                $"The acquired time-stamp token was generated at {generationTime:O}, at or after the signing certificate's revocation instant {revocationInstant:O} (ETSI EN 319 122-1 Table 1 requirement m).");
        }
    }


    /// <summary>
    /// Refuses a supplied object that is not of the kind a placement admits.
    /// </summary>
    /// <param name="isOfKind">Whether the object is of the kind.</param>
    /// <param name="message">The message naming what the placement admits.</param>
    /// <exception cref="CAdESAugmentationException">When the object is not of the kind.</exception>
    private static void EnsureKind(bool isOfKind, string message)
    {
        if(!isOfKind)
        {
            throw new CAdESAugmentationException(CAdESAugmentationFailureKind.UnsupportedValidationObject, message);
        }
    }


    /// <summary>The two types an OCSP response is carried as.</summary>
    private enum OcspResponseForm
    {
        /// <summary>A whole <c>OCSPResponse</c>, status envelope included.</summary>
        Response = 1,

        /// <summary>A bare <c>BasicOCSPResponse</c>.</summary>
        BasicResponse = 2
    }
}
