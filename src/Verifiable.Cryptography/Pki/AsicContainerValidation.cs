using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What validating a container, one of its manifests, or one of its protective objects concluded.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised status never reads as a successful
/// validation, and <see cref="Valid"/> is the only success — the same shape every status enumeration of this wave
/// has.
/// </remarks>
public enum AsicContainerValidationStatus
{
    /// <summary>No validation has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>Everything this library checks held.</summary>
    Valid = 1,

    /// <summary>The octets are not a container this library reads; <see cref="AsicContainerValidationResult.ReadStatus"/> states which rule refused them.</summary>
    ContainerNotRead = 2,

    /// <summary>A manifest file's name matches more than one of the three manifest patterns, so no single rule set applies to it (see <see cref="AsicManifestRole.Ambiguous"/>).</summary>
    ManifestRoleAmbiguous = 3,

    /// <summary>The container carries a manifest file and no manifest parsing seam was supplied, so its content cannot be read at all.</summary>
    ManifestParserMissing = 4,

    /// <summary>The manifest parsing seam refused the document.</summary>
    ManifestParseFailed = 5,

    /// <summary>A manifest carries an <c>Extension</c> marked <c>Critical</c> that the caller's policy does not recognise.</summary>
    ManifestExtensionRefused = 6,

    /// <summary>A <c>URI</c> attribute does not resolve to a container entry name (Annex A.6).</summary>
    ReferenceNotResolvable = 7,

    /// <summary>A reference resolves to a name the container carries no entry under.</summary>
    ReferencedObjectMissing = 8,

    /// <summary>
    /// A <c>ds:DigestValue</c> does not equal the digest computed over the referenced file object — the error
    /// clause 4.4.4.2 item d makes unconditional.
    /// </summary>
    DigestMismatch = 9,

    /// <summary>A manifest's <c>SigReference</c> names an entry the container does not carry.</summary>
    ProtectiveObjectMissing = 10,

    /// <summary>A manifest's <c>SigReference</c> names an entry whose name is none of the four kinds clause 4.4.4.2 items 3 and 4 admit.</summary>
    ProtectiveObjectNotRecognized = 11,

    /// <summary>The validation process of ETSI EN 319 102-1 clause 5 did not reach <c>TOTAL-PASSED</c> for a CAdES object the container carries.</summary>
    SignatureNotValid = 12,

    /// <summary>A time assertion does not bind the octets it is stated to protect, or its own validation did not pass.</summary>
    TimeAssertionNotValid = 13,

    /// <summary>An Evidence Record does not prove the objects the manifest naming it states it protects.</summary>
    EvidenceRecordNotVerified = 14,

    /// <summary>
    /// The container carries an Evidence Record in the XML form of clause 4.4.4.2 item 4 b) and the caller
    /// supplied no seam to read or canonicalize it with, so it was not verified. Refused rather than skipped: a
    /// validator that ignored it would report a container as valid while one of the objects the container relies
    /// on for long-term integrity was never checked.
    /// </summary>
    /// <remarks>
    /// This is the outcome of a missing seam, not of a missing capability. The verification of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see> Evidence Records ships in
    /// <see cref="XmlEvidenceRecords"/>; what does not ship, for the same reason no other XML binding of this
    /// library does, is the parsing and the canonicalization it needs. A caller that supplies
    /// <see cref="AsicContainerValidationContext.ParseXmlEvidenceRecord"/> and
    /// <see cref="AsicContainerValidationContext.CanonicalizeXml"/> gets the record verified; a caller that does
    /// not gets this status.
    /// </remarks>
    XmlEvidenceRecordNotSupported = 15,

    /// <summary>The Annex A.7 archive manifest chain cannot be walked: a link's backward pointer names no archive manifest, or the chain revisits one.</summary>
    ArchiveManifestChainBroken = 16,

    /// <summary>The container carries no protective object at all — no CAdES object, no time assertion and no Evidence Record — so there is nothing to validate it against.</summary>
    NoProtectiveObject = 17
}


/// <summary>
/// What one <c>DataObjectReference</c> of a manifest concluded about the file object it names.
/// </summary>
public enum AsicDataObjectReferenceStatus
{
    /// <summary>No comparison has been performed. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The digest computed over the referenced file object equals the <c>ds:DigestValue</c> the manifest states.</summary>
    Matched = 1,

    /// <summary>The <c>URI</c> attribute does not resolve to a container entry name (Annex A.6).</summary>
    ReferenceNotResolvable = 2,

    /// <summary>The reference resolves to a name the container carries no entry under.</summary>
    ObjectMissing = 3,

    /// <summary>The digest does not match — the unconditional error of clause 4.4.4.2 item d.</summary>
    DigestMismatch = 4
}


/// <summary>
/// What one <c>DataObjectReference</c> was found to state.
/// </summary>
[DebuggerDisplay("AsicDataObjectReferenceValidation: {Status}, {EntryName}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "Annex A.6 item 2 makes a manifest reference a relative URI resolved against the container ROOT. System.Uri cannot hold a relative reference without a base, and constructing one against a base is exactly the resolution that annex forbids; the value is reported verbatim, as the manifest whose octets a signature commits to writes it.")]
public sealed record AsicDataObjectReferenceValidation
{
    /// <summary>The <c>URI</c> attribute as the manifest writes it.</summary>
    public required string Uri { get; init; }

    /// <summary>The container entry name the reference resolves to, or <see langword="null"/> when it does not resolve.</summary>
    public string? EntryName { get; init; }

    /// <summary>The algorithm the manifest's <c>ds:DigestMethod</c> names.</summary>
    public required PkiDigestAlgorithm DigestAlgorithm { get; init; }

    /// <summary>What the comparison concluded.</summary>
    public required AsicDataObjectReferenceStatus Status { get; init; }
}


/// <summary>
/// What one manifest file of a container was found to state, and whether every reference it makes holds.
/// </summary>
[DebuggerDisplay("AsicManifestValidation: {Role}, {Status}, {EntryName}")]
public sealed record AsicManifestValidation
{
    /// <summary>The entry the manifest is stored as.</summary>
    public required string EntryName { get; init; }

    /// <summary>The role the entry's name gives it.</summary>
    public required AsicManifestRole Role { get; init; }

    /// <summary>What validating this manifest concluded.</summary>
    public required AsicContainerValidationStatus Status { get; init; }

    /// <summary>The entry name the manifest's <c>SigReference</c> resolves to, or <see langword="null"/> when it does not resolve.</summary>
    public string? ProtectiveObjectEntryName { get; init; }

    /// <summary>What each <c>DataObjectReference</c> concluded, in the order the manifest carries them.</summary>
    public IReadOnlyList<AsicDataObjectReferenceValidation> DataObjectReferences { get; init; } = [];

    /// <summary>A short, human-readable reason, present on every non-<see cref="AsicContainerValidationStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }
}


/// <summary>
/// What validating one CAdES object of a container concluded — the "shall be validated against the ASiCManifest
/// file content" of clause 4.4.4.2 item a) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see>, performed by the validation process of ETSI EN 319 102-1 clause 5.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns <see cref="Outcome"/>, which owns every carrier that run
/// created. The <see cref="AsicContainerValidationResult"/> holding it disposes it.
/// </remarks>
[DebuggerDisplay("AsicSignatureValidation: {Status}, {EntryName}")]
public sealed class AsicSignatureValidation: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>The entry the CAdES object is stored as.</summary>
    public required string EntryName { get; init; }

    /// <summary>The entry whose octets the signature is detached over — the manifest file for ASiC-E (Annex A.4.1), the single root data file for ASiC-S (clause 4.3.3.2 item 4 b).</summary>
    public string? DetachedContentEntryName { get; init; }

    /// <summary>What validating the object concluded.</summary>
    public required AsicContainerValidationStatus Status { get; init; }

    /// <summary>What the validation process of EN 319 102-1 clause 5 returned, or <see langword="null"/> when the run supplied no inputs to validate signatures with. Owned by this instance.</summary>
    public SignatureValidationOutcome? Outcome { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="AsicContainerValidationStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }


    /// <summary>Disposes the validation run this result owns.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Outcome?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// What validating one time assertion of a container concluded — the "shall be validated against the ASiCManifest
/// file content" of clause 4.4.4.2 item b).
/// </summary>
[DebuggerDisplay("AsicTimeAssertionValidation: {Status}, {EntryName}")]
public sealed record AsicTimeAssertionValidation
{
    /// <summary>The entry the time-stamp token is stored as.</summary>
    public required string EntryName { get; init; }

    /// <summary>The entry whose octets the token's message imprint binds.</summary>
    public string? ProtectedEntryName { get; init; }

    /// <summary>What validating the token concluded.</summary>
    public required AsicContainerValidationStatus Status { get; init; }

    /// <summary>The <c>genTime</c> the token asserts, when its <c>TSTInfo</c> was read.</summary>
    public DateTimeOffset? GenerationTime { get; init; }

    /// <summary>
    /// What the time-stamp validation building block of EN 319 102-1 clause 5.4 concluded, or
    /// <see langword="null"/> when it did not run — a run that supplied no inputs or no seams, which reports
    /// <see cref="Status"/> as <see cref="AsicContainerValidationStatus.NotEvaluated"/>, and a token whose
    /// message imprint does not bind the octets it is stated to protect, which is refused before clause 5.4 is
    /// reached at all.
    /// </summary>
    public TimestampValidationResult? TokenValidation { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="AsicContainerValidationStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }
}


/// <summary>
/// What validating one Evidence Record of a container concluded — the dispatch rule of clause 4.4.4.2 item 4
/// carried out.
/// </summary>
[DebuggerDisplay("AsicEvidenceRecordValidation: {Form}, {Status}, {EntryName}")]
public sealed record AsicEvidenceRecordValidation
{
    /// <summary>The entry the Evidence Record is stored as.</summary>
    public required string EntryName { get; init; }

    /// <summary>Which of the two forms of clause 4.4.4.2 item 4 the entry's name states, which is what the dispatch turns on.</summary>
    public required AsicEvidenceRecordForm Form { get; init; }

    /// <summary>The <c>ASiCEvidenceRecordManifest</c> naming the record, or <see langword="null"/> for an ASiC-S container, which names its Evidence Record by the fixed entry name instead.</summary>
    public string? ManifestEntryName { get; init; }

    /// <summary>What validating the record concluded.</summary>
    public required AsicContainerValidationStatus Status { get; init; }

    /// <summary>
    /// What <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">RFC 4998 clause 5.3</see> made of the
    /// record over the objects it is stated to protect. Meaningful for
    /// <see cref="AsicEvidenceRecordForm.Binary"/> alone.
    /// </summary>
    public EvidenceRecordVerificationStatus VerificationStatus { get; init; }

    /// <summary>
    /// What <see href="https://www.rfc-editor.org/rfc/rfc6283#appendix-A">RFC 6283 Appendix A</see> made of the
    /// record over the objects it is stated to protect. Meaningful for <see cref="AsicEvidenceRecordForm.Xml"/>
    /// alone.
    /// </summary>
    /// <remarks>
    /// The two forms report through two properties rather than one because they conclude in two enumerations
    /// whose members do not correspond: there is no canonicalization to fail in the ASN.1 form and no
    /// distinct-encoding rule to break in the XML one. A caller reads whichever one <see cref="Form"/> names.
    /// </remarks>
    public XmlEvidenceRecordVerificationStatus XmlVerificationStatus { get; init; }

    /// <summary>
    /// The entries the record proves — the <c>DataObjectReference</c> targets of the manifest naming it, and
    /// never that manifest file itself (clause 4.4.4.2 NOTE 2).
    /// </summary>
    public IReadOnlyList<string> ProtectedEntryNames { get; init; } = [];

    /// <summary>The <c>genTime</c> of the record's initial Archive Timestamp — the instant the record proves its protected objects existed at.</summary>
    public DateTimeOffset? InitialArchiveTime { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="AsicContainerValidationStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }
}


/// <summary>
/// One link of the Annex A.7 archive manifest chain, as the walk found it.
/// </summary>
/// <param name="EntryName">The archive manifest's entry name.</param>
/// <param name="TimestampEntryName">The entry name of the time-stamp token the manifest's <c>SigReference</c> names, or <see langword="null"/> when it names none the container carries.</param>
/// <param name="PreviousEntryName">The entry name of the archive manifest this link's <c>Rootfile="true"</c> reference points back at, or <see langword="null"/> for the first link ever added.</param>
public readonly record struct AsicArchiveManifestChainLink(string EntryName, string? TimestampEntryName, string? PreviousEntryName);


/// <summary>
/// Which kind of object protects a file object of a container.
/// </summary>
public enum AsicProtectionKind
{
    /// <summary>No protection stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>A CAdES object, <c>META-INF/*signature*.p7s</c>.</summary>
    CAdESSignature = 1,

    /// <summary>A time assertion, <c>META-INF/*timestamp*.tst</c>.</summary>
    TimeAssertion = 2,

    /// <summary>An Evidence Record, in either form.</summary>
    EvidenceRecord = 3,

    /// <summary>A time assertion applied to an <c>ASiCArchiveManifest</c> file — the container-level long-term chain of Annex A.7.</summary>
    ArchiveTimeAssertion = 4
}


/// <summary>
/// One statement about what protects one file object of a container.
/// </summary>
/// <remarks>
/// The report is what a Driving Application asks a container: which of my files does this container actually
/// protect, with what, and since when. It is built from what validated — an object whose digest did not match, or
/// whose protective object did not verify, does not appear.
/// </remarks>
[DebuggerDisplay("AsicProtectedObject: {EntryName} by {ProtectedBy} {ProtectiveObjectEntryName}")]
public sealed record AsicProtectedObject
{
    /// <summary>The file object that is protected.</summary>
    public required string EntryName { get; init; }

    /// <summary>What protects it.</summary>
    public required AsicProtectionKind ProtectedBy { get; init; }

    /// <summary>The entry name of the object that protects it.</summary>
    public required string ProtectiveObjectEntryName { get; init; }

    /// <summary>The manifest whose <c>DataObjectReference</c> states the digest that ties the two together, or <see langword="null"/> when the protective object applies to the file object directly (every ASiC-S container).</summary>
    public string? ThroughManifestEntryName { get; init; }

    /// <summary>The instant the protection proves the object existed at, when the protective object asserts one — a time assertion's <c>genTime</c>, an Evidence Record's initial Archive Timestamp.</summary>
    public DateTimeOffset? ProvenAt { get; init; }
}


/// <summary>
/// Everything one container validation is given.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The signature inputs are a template.</strong> A container carries its own Signed Data Objects and its
/// own detached content, so <see cref="SignatureInputs"/>'s <c>SignedDataObject</c>, <c>SignerDocuments</c> and
/// <c>EvidenceRecords</c> are replaced per embedded object; everything else the caller states — the constraints,
/// the trust anchors, the certificate validation data, the revocation status information — applies to every
/// signature the container carries. This is the same shape the time-stamp validation building block of EN 319
/// 102-1 clause 5.4 already uses for a token.
/// </para>
/// <para>
/// Supplying no <see cref="SignatureInputs"/> or no <see cref="SignatureSeams"/> validates the container's
/// structure alone: every manifest is parsed, every <c>DataObjectReference</c> digest recomputed and every
/// Evidence Record verified, and the CAdES objects and time-stamp tokens are reported as not evaluated rather
/// than as valid.
/// </para>
/// </remarks>
[DebuggerDisplay("AsicContainerValidationContext: {Container.Length} octets at {CurrentTime}")]
public sealed record AsicContainerValidationContext
{
    /// <summary>The container's octets.</summary>
    public required ReadOnlyMemory<byte> Container { get; init; }

    /// <summary>The instant the container is validated at.</summary>
    public required DateTimeOffset CurrentTime { get; init; }

    /// <summary>The bounds the archive is read within.</summary>
    public AsicZipReadLimits ReadLimits { get; init; } = AsicZipReadLimits.Conformant;

    /// <summary>The seam every manifest document is read through; required for a container carrying a manifest file.</summary>
    public ParseAsicManifestDelegate? ParseManifest { get; init; }

    /// <summary>The bounds a manifest document is parsed within.</summary>
    public AsicManifestParseLimits ManifestParseLimits { get; init; } = AsicManifestParseLimits.Conformant;

    /// <summary>
    /// The seam an Evidence Record in the XML form of clause 4.4.4.2 item 4 b) is read through; required,
    /// together with <see cref="CanonicalizeXml"/>, for a container carrying one.
    /// </summary>
    public ParseEvidenceRecordXmlDelegate? ParseXmlEvidenceRecord { get; init; }

    /// <summary>
    /// The seam producing the canonical binary representation of an element of an XML-form Evidence Record;
    /// required, together with <see cref="ParseXmlEvidenceRecord"/>, for a container carrying one.
    /// </summary>
    public CanonicalizeXmlEvidenceRecordDelegate? CanonicalizeXml { get; init; }

    /// <summary>The bounds an XML-form Evidence Record is parsed within.</summary>
    public XmlEvidenceRecordParseLimits XmlEvidenceRecordParseLimits { get; init; } = XmlEvidenceRecordParseLimits.Conformant;

    /// <summary>
    /// Whether the first <c>Sequence</c> of every Archive Time-Stamp of an XML-form Evidence Record may hold
    /// nothing beyond the values that Archive Time-Stamp protects — Appendix A step 5.b's own reading, and this
    /// library's default. See
    /// <see cref="XmlEvidenceRecordVerificationContext.RequireDataObjectGroupExclusivity"/> for what the
    /// departure gives up.
    /// </summary>
    public bool RequireXmlEvidenceRecordGroupExclusivity { get; init; } = true;

    /// <summary>The policy deciding what an unrecognised <c>Extension</c> marked <c>Critical</c> means; strict by default.</summary>
    public AsicManifestExtensionPolicy ExtensionPolicy { get; init; } = AsicManifestExtensionPolicy.Strict;

    /// <summary>The inputs every embedded CAdES object and time-stamp token is validated under, or <see langword="null"/> to validate the container's structure alone.</summary>
    public SignatureValidationInputs? SignatureInputs { get; init; }

    /// <summary>The certificate seams every embedded object's validation composes, or <see langword="null"/> to validate the container's structure alone.</summary>
    public SignatureValidationSeams? SignatureSeams { get; init; }

    /// <summary>Which validation process of EN 319 102-1 clause 5.1.2 each embedded CAdES object is validated by.</summary>
    public SignatureValidationProcessSelection ProcessSelection { get; init; } = SignatureValidationProcessSelection.Automatic;

    /// <summary>Which validation processes the Signature Validation Application supports.</summary>
    public SignatureValidationCapabilities Capabilities { get; init; } = SignatureValidationCapabilities.All;
}


/// <summary>
/// What validating one container concluded, in every dimension clause 4.4.4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> gives a validation application an obligation about.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns the container facts, every signature validation run and every
/// carrier those runs were given. Disposing it releases them all; nothing it exposes may be read afterwards.
/// </remarks>
[DebuggerDisplay("AsicContainerValidationResult: {Status}")]
public sealed class AsicContainerValidationResult: IDisposable
{
    /// <summary>The carriers this validation created and therefore owns, released in reverse order.</summary>
    private readonly List<IDisposable> owned = [];

    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Initialises a new result owning a list of carriers.</summary>
    /// <param name="owned">The carriers the validation created, in creation order. Ownership transfers to this instance.</param>
    internal AsicContainerValidationResult(List<IDisposable> owned)
    {
        this.owned = owned;
    }


    /// <summary>The overall conclusion: <see cref="AsicContainerValidationStatus.Valid"/> only when every manifest, every protective object and every reference held.</summary>
    public required AsicContainerValidationStatus Status { get; init; }

    /// <summary>Why the archive was refused, when <see cref="Status"/> is <see cref="AsicContainerValidationStatus.ContainerNotRead"/>.</summary>
    public AsicZipReadStatus ReadStatus { get; init; }

    /// <summary>The container's facts; non-<see langword="null"/> whenever the archive was read. Owned by this instance.</summary>
    public AsicContainerFacts? Facts { get; init; }

    /// <summary>What each manifest file concluded, in container order.</summary>
    public IReadOnlyList<AsicManifestValidation> Manifests { get; init; } = [];

    /// <summary>What each CAdES object concluded, in container order. Owned by this instance.</summary>
    public IReadOnlyList<AsicSignatureValidation> Signatures { get; init; } = [];

    /// <summary>What each time assertion concluded, in container order.</summary>
    public IReadOnlyList<AsicTimeAssertionValidation> TimeAssertions { get; init; } = [];

    /// <summary>What each Evidence Record concluded, in container order.</summary>
    public IReadOnlyList<AsicEvidenceRecordValidation> EvidenceRecords { get; init; } = [];

    /// <summary>The Annex A.7 chain, newest link first; empty when the container carries no archive manifest.</summary>
    public IReadOnlyList<AsicArchiveManifestChainLink> ArchiveManifestChain { get; init; } = [];

    /// <summary>What the container protects, and with what.</summary>
    public IReadOnlyList<AsicProtectedObject> ProtectedObjects { get; init; } = [];

    /// <summary>A short, human-readable reason, present on every non-<see cref="AsicContainerValidationStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Whether everything this library checks held.</summary>
    public bool IsValid => Status == AsicContainerValidationStatus.Valid;


    /// <summary>Releases the facts, the signature validation runs and every carrier they were given.</summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        for(int i = owned.Count - 1; i >= 0; --i)
        {
            owned[i].Dispose();
        }

        owned.Clear();
    }
}


/// <summary>
/// The validation of an Associated Signature Container: the obligations clause 4.4.4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> places on a validation application, composed with the validation process of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5</see> for the signatures and
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">IETF RFC 4998 clause 5.3</see> for the Evidence
/// Records.
/// </summary>
/// <remarks>
/// <para>
/// <strong>A digest mismatch is terminal, without exception.</strong> Clause 4.4.4.2 item d states that a
/// validation application "shall raise an error whenever a digest value mismatch is detected", with no partial
/// success and no policy knob anywhere near it. Every reference is still recomputed and reported — a report that
/// stops at the first mismatch tells an operator less than one that names all of them — but the container's own
/// conclusion is <see cref="AsicContainerValidationStatus.DigestMismatch"/> and nothing raises it back.
/// </para>
/// <para>
/// <strong>The Evidence Record dispatch is by file name, and both forms are verified.</strong> Clause 4.4.4.2
/// item 4 admits two: a <c>*evidencerecord*.ers</c> entry is verified per
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">IETF RFC 4998 clause 5.3</see>, and a
/// <c>*evidencerecord*.xml</c> entry per
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#appendix-A">IETF RFC 6283 Appendix A</see> — the latter
/// through the parse and canonicalization seams <see cref="AsicContainerValidationContext.ParseXmlEvidenceRecord"/>
/// and <see cref="AsicContainerValidationContext.CanonicalizeXml"/>, since this library ships no XML binding for
/// any profile. A run that supplies neither refuses the record with
/// <see cref="AsicContainerValidationStatus.XmlEvidenceRecordNotSupported"/> rather than passing over it: the
/// record is one of the objects the container's long-term integrity rests on, so a validator that ignored it
/// would state a conclusion it has no basis for.
/// </para>
/// <para>
/// <strong>The two forms are checked by two different algorithms, deliberately.</strong> The ASN.1 form proves
/// one data object at a time along a tree path and tolerates a first list holding more than the object being
/// proved; the XML form proves a whole data object group at once and, per Appendix A step 5.b, refuses a first
/// sequence holding anything else. Nothing here abstracts over the two — a shared "archive index" would have to
/// pick one of the two membership semantics and would then be wrong about the other form.
/// </para>
/// <para>
/// <strong>NOTE 2 of clause 4.4.4.2 is implemented in the protected-objects report.</strong> An Evidence Record
/// named by an <c>ASiCEvidenceRecordManifest</c> protects that manifest's <c>DataObjectReference</c> targets and
/// not the manifest file itself, so the manifest never appears among the objects its own record protects. The
/// digest comparison still runs over every reference, because that is what ties the targets to the octets the
/// record's hash tree was built over.
/// </para>
/// <para>
/// <strong>The Annex A.7 chain walk is this wave's reconstruction.</strong> The annex states how a chain is
/// built and never how it is walked; the walk here starts at the file literally named
/// <c>META-INF/ASiCArchiveManifest.xml</c> — the name item 1 c a) fixes and item 2 a) reclaims at every renewal —
/// and follows each link's single <c>Rootfile="true"</c> reference backwards until a link has none. It is an
/// explicit loop over a visited set bounded by the container's manifest count, never a recursion, and a chain
/// that revisits a link or points at a file that is not an archive manifest is
/// <see cref="AsicContainerValidationStatus.ArchiveManifestChainBroken"/>.
/// </para>
/// </remarks>
public static class AsicContainerValidation
{
    /// <summary>
    /// Validates one container.
    /// </summary>
    /// <param name="context">The container, the instant, the seams and the inputs.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static async ValueTask<AsicContainerValidationResult> ValidateAsync(
        AsicContainerValidationContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        List<IDisposable> owned = [];
        try
        {
            AsicContainerReadResult read = AsicContainerReading.Read(context.Container, context.ReadLimits, pool);
            owned.Add(read);
            if(!read.IsRead || read.Facts is null)
            {
                return new AsicContainerValidationResult(owned)
                {
                    Status = AsicContainerValidationStatus.ContainerNotRead,
                    ReadStatus = read.Status,
                    FailureReason = string.Create(
                        CultureInfo.InvariantCulture,
                        $"The octets are not a container this library reads ({read.Status}{(read.RejectedEntryName is null ? string.Empty : $", entry '{read.RejectedEntryName}'")}).")
                };
            }

            var run = new ContainerValidationRun(context, read.Facts, owned, pool);
            await run.ValidateManifestsAsync(cancellationToken).ConfigureAwait(false);
            await run.ValidateEvidenceRecordsAsync(cancellationToken).ConfigureAwait(false);
            await run.ValidateTimeAssertionsAsync(cancellationToken).ConfigureAwait(false);
            await run.ValidateSignaturesAsync(cancellationToken).ConfigureAwait(false);
            run.WalkArchiveManifestChain();
            run.StateProtectedObjects();

            return run.Conclude();
        }
        catch
        {
            for(int i = owned.Count - 1; i >= 0; --i)
            {
                owned[i].Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// The state one container validation accumulates: the parsed manifests, the per-object conclusions and the
    /// carriers the run created.
    /// </summary>
    /// <remarks>
    /// A run is a private object rather than a chain of parameters because the steps genuinely share state —
    /// which manifest names which protective object, which Evidence Record proved which entries — and because
    /// every carrier a step rents has to reach one owner. Nothing here is reachable from outside; the shipped
    /// surface is <see cref="AsicContainerValidation.ValidateAsync"/> alone.
    /// </remarks>
    private sealed class ContainerValidationRun
    {
        /// <summary>The run's inputs.</summary>
        private readonly AsicContainerValidationContext context;

        /// <summary>The container's facts.</summary>
        private readonly AsicContainerFacts facts;

        /// <summary>The carriers the run created, in creation order.</summary>
        private readonly List<IDisposable> owned;

        /// <summary>The memory pool every allocation is rented from.</summary>
        private readonly MemoryPool<byte> pool;

        /// <summary>The per-manifest conclusions, in container order.</summary>
        private readonly List<AsicManifestValidation> manifests = [];

        /// <summary>The parsed manifests, keyed by entry name; a manifest that did not parse is absent.</summary>
        private readonly Dictionary<string, AsicManifest> parsedManifests = new(StringComparer.Ordinal);

        /// <summary>The per-Evidence-Record conclusions, in container order.</summary>
        private readonly List<AsicEvidenceRecordValidation> evidenceRecords = [];

        /// <summary>The per-time-assertion conclusions, in container order.</summary>
        private readonly List<AsicTimeAssertionValidation> timeAssertions = [];

        /// <summary>The per-signature conclusions, in container order.</summary>
        private readonly List<AsicSignatureValidation> signatures = [];

        /// <summary>The chain links, newest first.</summary>
        private readonly List<AsicArchiveManifestChainLink> chain = [];

        /// <summary>What the container protects.</summary>
        private readonly List<AsicProtectedObject> protectedObjects = [];

        /// <summary>The Evidence Record carriers the run read, keyed by the entry each was read from.</summary>
        private readonly Dictionary<string, EvidenceRecord> readEvidenceRecords = new(StringComparer.Ordinal);


        /// <summary>Initialises a run.</summary>
        /// <param name="context">The run's inputs.</param>
        /// <param name="facts">The container's facts.</param>
        /// <param name="owned">The list every carrier the run creates is added to.</param>
        /// <param name="pool">The memory pool every allocation is rented from.</param>
        public ContainerValidationRun(
            AsicContainerValidationContext context,
            AsicContainerFacts facts,
            List<IDisposable> owned,
            MemoryPool<byte> pool)
        {
            this.context = context;
            this.facts = facts;
            this.owned = owned;
            this.pool = pool;
        }


        /// <summary>
        /// Parses every manifest file and recomputes every <c>DataObjectReference</c> digest — the obligations of
        /// clause 4.4.4.2's validation intro and of item d).
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        public async ValueTask ValidateManifestsAsync(CancellationToken cancellationToken)
        {
            for(int i = 0; i < facts.Manifests.Count; ++i)
            {
                AsicManifestFile manifest = facts.Manifests[i];
                if(manifest.Role == AsicManifestRole.Ambiguous)
                {
                    manifests.Add(new AsicManifestValidation
                    {
                        EntryName = manifest.Entry.Name,
                        Role = manifest.Role,
                        Status = AsicContainerValidationStatus.ManifestRoleAmbiguous,
                        FailureReason = "The file name matches more than one of the three manifest patterns, so no single rule set of clause 4.4.4.2, clause 4.4.3.2 item 4 or Annex A.7 applies to it."
                    });

                    continue;
                }

                if(context.ParseManifest is null)
                {
                    manifests.Add(new AsicManifestValidation
                    {
                        EntryName = manifest.Entry.Name,
                        Role = manifest.Role,
                        Status = AsicContainerValidationStatus.ManifestParserMissing,
                        FailureReason = "The container carries a manifest file and no manifest parsing seam was supplied; this library ships no XML implementation."
                    });

                    continue;
                }

                AsicManifestParseResult parsed = await context.ParseManifest(
                    new AsicManifestParseContext { Document = manifest.Entry.Content, Limits = context.ManifestParseLimits },
                    pool,
                    cancellationToken).ConfigureAwait(false);
                if(!parsed.IsValid || parsed.Manifest is null)
                {
                    using(parsed)
                    {
                        manifests.Add(new AsicManifestValidation
                        {
                            EntryName = manifest.Entry.Name,
                            Role = manifest.Role,
                            Status = AsicContainerValidationStatus.ManifestParseFailed,
                            FailureReason = string.Create(
                                CultureInfo.InvariantCulture,
                                $"The manifest parsing seam refused the document ({parsed.Status}): {parsed.FailureReason ?? "no reason stated"}.")
                        });
                    }

                    continue;
                }

                //Ownership of the parsed manifest transfers to the run: the references it carries are read by
                //every later step and the digests it holds live in its own carriers, so the parse result is
                //deliberately not disposed here — the manifest it held is now the run's, and the result owns
                //nothing else.
                AsicManifest model = parsed.Manifest;
                owned.Add(model);
                parsedManifests[manifest.Entry.Name] = model;

                AsicManifestExtensionEvaluation extensions = context.ExtensionPolicy.Evaluate(model);
                if(!extensions.IsAccepted)
                {
                    manifests.Add(new AsicManifestValidation
                    {
                        EntryName = manifest.Entry.Name,
                        Role = manifest.Role,
                        Status = AsicContainerValidationStatus.ManifestExtensionRefused,
                        FailureReason = string.Create(
                            CultureInfo.InvariantCulture,
                            $"The manifest carries an extension the caller's policy refuses ({extensions.Status}).")
                    });

                    continue;
                }

                AsicContainerUriResolution protectiveReference = ResolveReference(model.SignatureReference.Uri);
                string? protectiveEntryName = protectiveReference.Status == AsicContainerUriStatus.Resolved ? protectiveReference.EntryName : null;
                var references = new List<AsicDataObjectReferenceValidation>(model.DataObjectReferences.Count);
                AsicContainerValidationStatus status = AsicContainerValidationStatus.Valid;
                string? reason = null;

                for(int referenceIndex = 0; referenceIndex < model.DataObjectReferences.Count; ++referenceIndex)
                {
                    AsicDataObjectReference reference = model.DataObjectReferences[referenceIndex];
                    AsicDataObjectReferenceValidation evaluated = await EvaluateReferenceAsync(reference, cancellationToken).ConfigureAwait(false);
                    references.Add(evaluated);

                    //Clause 4.4.4.2 item d) is unconditional, so a mismatch outranks every other reference fault
                    //and is never overwritten by a later reference that happened to resolve.
                    if(evaluated.Status == AsicDataObjectReferenceStatus.DigestMismatch)
                    {
                        status = AsicContainerValidationStatus.DigestMismatch;
                        reason = string.Create(
                            CultureInfo.InvariantCulture,
                            $"The digest stated for '{evaluated.EntryName}' does not equal the digest computed over the entry (clause 4.4.4.2 item d).");
                    }
                    else if(status != AsicContainerValidationStatus.DigestMismatch && evaluated.Status == AsicDataObjectReferenceStatus.ObjectMissing)
                    {
                        status = AsicContainerValidationStatus.ReferencedObjectMissing;
                        reason = string.Create(CultureInfo.InvariantCulture, $"The manifest references '{evaluated.EntryName}', which the container does not carry.");
                    }
                    else if(status != AsicContainerValidationStatus.DigestMismatch && evaluated.Status == AsicDataObjectReferenceStatus.ReferenceNotResolvable)
                    {
                        status = AsicContainerValidationStatus.ReferenceNotResolvable;
                        reason = string.Create(CultureInfo.InvariantCulture, $"The reference '{evaluated.Uri}' does not name a container entry (Annex A.6).");
                    }
                }

                if(status == AsicContainerValidationStatus.Valid)
                {
                    if(protectiveEntryName is null)
                    {
                        status = AsicContainerValidationStatus.ReferenceNotResolvable;
                        reason = string.Create(
                            CultureInfo.InvariantCulture,
                            $"The SigReference '{model.SignatureReference.Uri}' does not name a container entry ({protectiveReference.Status}).");
                    }
                    else if(facts.FindEntry(protectiveEntryName) is null)
                    {
                        status = AsicContainerValidationStatus.ProtectiveObjectMissing;
                        reason = string.Create(CultureInfo.InvariantCulture, $"The SigReference names '{protectiveEntryName}', which the container does not carry.");
                    }
                    else if(!IsRecognizedProtectiveObjectName(protectiveEntryName))
                    {
                        status = AsicContainerValidationStatus.ProtectiveObjectNotRecognized;
                        reason = string.Create(
                            CultureInfo.InvariantCulture,
                            $"The SigReference names '{protectiveEntryName}', whose name is none of the four kinds clause 4.4.4.2 items 3 and 4 admit.");
                    }
                }

                manifests.Add(new AsicManifestValidation
                {
                    EntryName = manifest.Entry.Name,
                    Role = manifest.Role,
                    Status = status,
                    ProtectiveObjectEntryName = protectiveEntryName,
                    DataObjectReferences = references,
                    FailureReason = reason
                });
            }
        }


        /// <summary>
        /// Carries out the dispatch rule of clause 4.4.4.2 item 4 for every Evidence Record the container
        /// carries: a <c>.ers</c> entry is verified per RFC 4998 against the objects the manifest naming it
        /// states, and an XML-form entry is refused.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        public async ValueTask ValidateEvidenceRecordsAsync(CancellationToken cancellationToken)
        {
            for(int i = 0; i < facts.EvidenceRecords.Count; ++i)
            {
                AsicEvidenceRecordFile file = facts.EvidenceRecords[i];
                string? manifestEntryName = FindManifestNaming(file.Entry.Name);
                if(file.Form == AsicEvidenceRecordForm.Xml)
                {
                    evidenceRecords.Add(await ValidateXmlEvidenceRecordAsync(file, manifestEntryName, cancellationToken).ConfigureAwait(false));

                    continue;
                }

                List<string> protectedEntryNames = StateEvidenceRecordTargets(manifestEntryName);
                EvidenceRecord? record = TryReadEvidenceRecord(file.Entry);
                if(record is null)
                {
                    evidenceRecords.Add(new AsicEvidenceRecordValidation
                    {
                        EntryName = file.Entry.Name,
                        Form = file.Form,
                        ManifestEntryName = manifestEntryName,
                        Status = AsicContainerValidationStatus.EvidenceRecordNotVerified,
                        VerificationStatus = EvidenceRecordVerificationStatus.Malformed,
                        ProtectedEntryNames = protectedEntryNames,
                        FailureReason = "The entry's octets are not an Evidence Record this library can read (RFC 4998 Appendix B)."
                    });

                    continue;
                }

                readEvidenceRecords[file.Entry.Name] = record;
                if(protectedEntryNames.Count == 0)
                {
                    evidenceRecords.Add(new AsicEvidenceRecordValidation
                    {
                        EntryName = file.Entry.Name,
                        Form = file.Form,
                        ManifestEntryName = manifestEntryName,
                        Status = AsicContainerValidationStatus.EvidenceRecordNotVerified,
                        VerificationStatus = EvidenceRecordVerificationStatus.NotVerified,
                        FailureReason = "No manifest of the container names this Evidence Record, and the container is not the ASiC-S shape whose fixed names state what a record protects, so what the record is claimed to protect is not stated."
                    });

                    continue;
                }

                var proven = new List<string>(protectedEntryNames.Count);
                EvidenceRecordVerificationStatus verificationStatus = EvidenceRecordVerificationStatus.Verified;
                DateTimeOffset? initialArchiveTime = null;
                for(int targetIndex = 0; targetIndex < protectedEntryNames.Count; ++targetIndex)
                {
                    AsicZipEntry? target = facts.FindEntry(protectedEntryNames[targetIndex]);
                    if(target is null)
                    {
                        verificationStatus = EvidenceRecordVerificationStatus.DataObjectNotCovered;

                        continue;
                    }

                    using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
                        new EvidenceRecordVerificationContext { EvidenceRecord = record, DataObject = target.Content.AsReadOnlyMemory() },
                        pool,
                        cancellationToken).ConfigureAwait(false);
                    initialArchiveTime ??= verification.InitialArchiveTime;
                    if(verification.Status == EvidenceRecordVerificationStatus.Verified)
                    {
                        proven.Add(target.Name);
                    }
                    else
                    {
                        verificationStatus = verification.Status;
                    }
                }

                bool provedEverything = proven.Count == protectedEntryNames.Count && verificationStatus == EvidenceRecordVerificationStatus.Verified;
                evidenceRecords.Add(new AsicEvidenceRecordValidation
                {
                    EntryName = file.Entry.Name,
                    Form = file.Form,
                    ManifestEntryName = manifestEntryName,
                    Status = provedEverything ? AsicContainerValidationStatus.Valid : AsicContainerValidationStatus.EvidenceRecordNotVerified,
                    VerificationStatus = verificationStatus,
                    ProtectedEntryNames = proven,
                    InitialArchiveTime = initialArchiveTime,
                    FailureReason = provedEverything
                        ? null
                        : string.Create(
                            CultureInfo.InvariantCulture,
                            $"The Evidence Record does not prove every object the container states it protects ({verificationStatus}).")
                });
            }
        }


        /// <summary>
        /// Carries out the second arm of the dispatch rule of clause 4.4.4.2 item 4: an Evidence Record whose
        /// entry name matches <c>*evidencerecord*.xml</c> is verified per
        /// <see href="https://www.rfc-editor.org/rfc/rfc6283#appendix-A">IETF RFC 6283 Appendix A</see>, through
        /// the parse and canonicalization seams the caller supplied.
        /// </summary>
        /// <param name="file">The Evidence Record entry.</param>
        /// <param name="manifestEntryName">The <c>ASiCEvidenceRecordManifest</c> naming it, or <see langword="null"/>.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>What validating the record concluded.</returns>
        /// <remarks>
        /// <para>
        /// <strong>The whole target set is one archive object.</strong> Clause 3.1.1 of RFC 6283 makes the first
        /// hash list of a data object group hold "the hash values of all its data objects", so the record is
        /// verified once over every entry the manifest naming it references — not once per entry, which is how
        /// the ASN.1 form's per-object tree-path proofs are checked. The two forms genuinely differ here and the
        /// dispatch is what keeps them apart.
        /// </para>
        /// <para>
        /// <strong>Container entries are never treated as XML archive data.</strong> Clause 4.1.2's
        /// canonicalize-XML-archive-data rule is about the archived object's own binary representation being
        /// ambiguous; a file object inside a container is a sequence of octets whose digest clause 4.4.4.2 item d
        /// already compares against a manifest, so canonicalizing it would compare two different things.
        /// </para>
        /// </remarks>
        private async ValueTask<AsicEvidenceRecordValidation> ValidateXmlEvidenceRecordAsync(
            AsicEvidenceRecordFile file,
            string? manifestEntryName,
            CancellationToken cancellationToken)
        {
            if(context.ParseXmlEvidenceRecord is not ParseEvidenceRecordXmlDelegate parse
                || context.CanonicalizeXml is not CanonicalizeXmlEvidenceRecordDelegate canonicalize)
            {
                return new AsicEvidenceRecordValidation
                {
                    EntryName = file.Entry.Name,
                    Form = file.Form,
                    ManifestEntryName = manifestEntryName,
                    Status = AsicContainerValidationStatus.XmlEvidenceRecordNotSupported,
                    FailureReason = "Clause 4.4.4.2 item 4 b) names the XML Evidence Record Syntax of IETF RFC 6283; this run supplied no parsing or canonicalization seam to read one with, so the record is refused rather than passed over."
                };
            }

            List<string> protectedEntryNames = StateEvidenceRecordTargets(manifestEntryName);
            if(protectedEntryNames.Count == 0)
            {
                return new AsicEvidenceRecordValidation
                {
                    EntryName = file.Entry.Name,
                    Form = file.Form,
                    ManifestEntryName = manifestEntryName,
                    Status = AsicContainerValidationStatus.EvidenceRecordNotVerified,
                    XmlVerificationStatus = XmlEvidenceRecordVerificationStatus.NotVerified,
                    FailureReason = "No manifest of the container names this Evidence Record, and the container is not the ASiC-S shape whose fixed names state what a record protects, so what the record is claimed to protect is not stated."
                };
            }

            var dataObjects = new List<XmlEvidenceRecordDataObject>(protectedEntryNames.Count);
            for(int i = 0; i < protectedEntryNames.Count; ++i)
            {
                AsicZipEntry? target = facts.FindEntry(protectedEntryNames[i]);
                if(target is null)
                {
                    return new AsicEvidenceRecordValidation
                    {
                        EntryName = file.Entry.Name,
                        Form = file.Form,
                        ManifestEntryName = manifestEntryName,
                        Status = AsicContainerValidationStatus.EvidenceRecordNotVerified,
                        XmlVerificationStatus = XmlEvidenceRecordVerificationStatus.DataObjectNotCovered,
                        FailureReason = string.Create(CultureInfo.InvariantCulture, $"The container carries no entry named '{protectedEntryNames[i]}', which the manifest states the Evidence Record protects.")
                    };
                }

                dataObjects.Add(new XmlEvidenceRecordDataObject { Content = target.Content.AsReadOnlyMemory(), Name = target.Name });
            }

            using XmlEvidenceRecordParseResult parsed = await parse(
                new XmlEvidenceRecordParseContext
                {
                    Document = file.Entry.Content.AsReadOnlyMemory(),
                    Limits = context.XmlEvidenceRecordParseLimits
                },
                pool,
                cancellationToken).ConfigureAwait(false);
            if(!parsed.IsValid || parsed.EvidenceRecord is not XmlEvidenceRecord evidenceRecord)
            {
                return new AsicEvidenceRecordValidation
                {
                    EntryName = file.Entry.Name,
                    Form = file.Form,
                    ManifestEntryName = manifestEntryName,
                    Status = AsicContainerValidationStatus.EvidenceRecordNotVerified,
                    XmlVerificationStatus = XmlEvidenceRecordVerificationStatus.Malformed,
                    FailureReason = string.Create(CultureInfo.InvariantCulture, $"The entry's octets are not an Evidence Record this library can read ({parsed.Status}: {parsed.FailureReason}).")
                };
            }

            using XmlEvidenceRecordVerification verification = await XmlEvidenceRecords.VerifyAsync(
                new XmlEvidenceRecordVerificationContext
                {
                    EvidenceRecord = evidenceRecord,
                    Document = file.Entry.Content.AsReadOnlyMemory(),
                    DataObjects = dataObjects,
                    Canonicalize = canonicalize,
                    RequireDataObjectGroupExclusivity = context.RequireXmlEvidenceRecordGroupExclusivity
                },
                pool,
                cancellationToken).ConfigureAwait(false);

            bool verified = verification.Status == XmlEvidenceRecordVerificationStatus.Verified;

            return new AsicEvidenceRecordValidation
            {
                EntryName = file.Entry.Name,
                Form = file.Form,
                ManifestEntryName = manifestEntryName,
                Status = verified ? AsicContainerValidationStatus.Valid : AsicContainerValidationStatus.EvidenceRecordNotVerified,
                XmlVerificationStatus = verification.Status,
                ProtectedEntryNames = verified ? protectedEntryNames : [],
                InitialArchiveTime = verification.InitialArchiveTime,
                FailureReason = verified
                    ? null
                    : string.Create(CultureInfo.InvariantCulture, $"The Evidence Record does not prove every object the container states it protects ({verification.Status}).")
            };
        }


        /// <summary>
        /// Validates every time assertion against the octets it is stated to protect — clause 4.4.4.2 item b) for
        /// an ASiC-E container, clause 4.3.3.2 item 4 a) for an ASiC-S one — and through the time-stamp
        /// validation building block of EN 319 102-1 clause 5.4.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <remarks>
        /// The two checks are ordered and neither substitutes for the other. A token whose message imprint does
        /// not bind the octets it is stated to protect is refused before anything else is asked, because that is
        /// a fact about the container that no trust material can repair. A token that binds them is then
        /// validated through clause 5.4, and a run that supplied no inputs or no seams reports it as
        /// <see cref="AsicContainerValidationStatus.NotEvaluated"/> — the status
        /// <see cref="ValidateSignaturesAsync"/> gives a CAdES object under the same condition. Reporting the
        /// imprint recomputation alone as <see cref="AsicContainerValidationStatus.Valid"/> would state a
        /// proof-of-existence instant read out of a token whose signer certificate, chain, revocation state and
        /// trust anchor were never looked at.
        /// </remarks>
        public async ValueTask ValidateTimeAssertionsAsync(CancellationToken cancellationToken)
        {
            for(int i = 0; i < facts.TimeAssertions.Count; ++i)
            {
                AsicZipEntry token = facts.TimeAssertions[i];
                AsicZipEntry? protectedEntry = ResolveProtectedEntry(token.Name);
                if(protectedEntry is null)
                {
                    timeAssertions.Add(new AsicTimeAssertionValidation
                    {
                        EntryName = token.Name,
                        Status = AsicContainerValidationStatus.TimeAssertionNotValid,
                        FailureReason = "No manifest of the container names this time assertion, and the container is not the ASiC-S shape whose single root data file states what a bare token protects."
                    });

                    continue;
                }

                using PkiCertificateMemory tokenCarrier = CopyToken(token.Content.AsReadOnlySpan());
                using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(tokenCarrier, pool, cancellationToken).ConfigureAwait(false);
                if(!info.IsRead || info.MessageImprint is not DigestValue imprint)
                {
                    timeAssertions.Add(new AsicTimeAssertionValidation
                    {
                        EntryName = token.Name,
                        ProtectedEntryName = protectedEntry.Name,
                        Status = AsicContainerValidationStatus.TimeAssertionNotValid,
                        FailureReason = string.Create(CultureInfo.InvariantCulture, $"The token's TSTInfo could not be read ({info.Status}).")
                    });

                    continue;
                }

                PkiDigestAlgorithm? imprintAlgorithm = PkiDigestAlgorithm.FromOid(info.MessageImprintAlgorithm.Oid);
                bool binds = false;
                if(imprintAlgorithm is PkiDigestAlgorithm algorithm)
                {
                    using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
                        protectedEntry.Content.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    binds = computed.AsReadOnlySpan().SequenceEqual(imprint.AsReadOnlySpan());
                }

                if(!binds)
                {
                    timeAssertions.Add(new AsicTimeAssertionValidation
                    {
                        EntryName = token.Name,
                        ProtectedEntryName = protectedEntry.Name,
                        Status = AsicContainerValidationStatus.TimeAssertionNotValid,
                        GenerationTime = info.GenerationTime,
                        FailureReason = string.Create(CultureInfo.InvariantCulture, $"The token's message imprint does not bind '{protectedEntry.Name}'.")
                    });

                    continue;
                }

                //The imprint binding is necessary and not sufficient: it states WHICH octets the token binds and
                //nothing about who minted it. Clause 4.4.4.2 item b) says the token "shall be validated", and
                //validating a token is the building block of EN 319 102-1 clause 5.4, which needs the inputs and
                //the seams. A run that supplied neither reports the token as not evaluated — the same status
                //ValidateSignaturesAsync gives a CAdES object under the same condition, and what this type's own
                //documentation promises — rather than as valid, because a Valid here would enter the token's own
                //genTime into the protected-objects report as an instant nothing authenticated.
                if(context.SignatureInputs is not SignatureValidationInputs inputs || context.SignatureSeams is not SignatureValidationSeams seams)
                {
                    timeAssertions.Add(new AsicTimeAssertionValidation
                    {
                        EntryName = token.Name,
                        ProtectedEntryName = protectedEntry.Name,
                        Status = AsicContainerValidationStatus.NotEvaluated,
                        GenerationTime = info.GenerationTime,
                        FailureReason = "The run supplied no signature validation inputs, so the token's message imprint was recomputed and the token itself was not validated."
                    });

                    continue;
                }

                var resources = new SignatureValidationResources();
                owned.Add(resources);
                TimestampValidationResult tokenValidation = await TimestampValidation.ValidateAsync(
                    tokenCarrier, inputs, CAdESSeams(seams), context.CurrentTime, resources, pool, cancellationToken).ConfigureAwait(false);

                bool tokenValid = tokenValidation.Conclusion.Indication == BuildingBlockIndication.Passed;
                timeAssertions.Add(new AsicTimeAssertionValidation
                {
                    EntryName = token.Name,
                    ProtectedEntryName = protectedEntry.Name,
                    Status = tokenValid ? AsicContainerValidationStatus.Valid : AsicContainerValidationStatus.TimeAssertionNotValid,
                    GenerationTime = info.GenerationTime,
                    TokenValidation = tokenValidation,
                    FailureReason = tokenValid
                        ? null
                        : string.Create(CultureInfo.InvariantCulture, $"The token did not validate ({tokenValidation.Conclusion.Indication}).")
                });
            }
        }


        /// <summary>
        /// Validates every CAdES object the container carries through the validation process of EN 319 102-1
        /// clause 5, detached over the octets clause 4.4.4.2 item a) or clause 4.3.3.2 item 4 b) makes its signed
        /// content, and with every Evidence Record that proved the object as a proof-of-existence input.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        public async ValueTask ValidateSignaturesAsync(CancellationToken cancellationToken)
        {
            for(int i = 0; i < facts.Signatures.Count; ++i)
            {
                AsicZipEntry signature = facts.Signatures[i];
                AsicZipEntry? detachedContent = ResolveProtectedEntry(signature.Name);
                if(detachedContent is null)
                {
                    AddSignatureValidation(new AsicSignatureValidation
                    {
                        EntryName = signature.Name,
                        Status = AsicContainerValidationStatus.ProtectiveObjectMissing,
                        FailureReason = "No manifest of the container names this CAdES object, and the container is not the ASiC-S shape whose single root data file states what a detached signature covers."
                    });

                    continue;
                }

                if(context.SignatureInputs is not SignatureValidationInputs inputs || context.SignatureSeams is not SignatureValidationSeams seams)
                {
                    AddSignatureValidation(new AsicSignatureValidation
                    {
                        EntryName = signature.Name,
                        DetachedContentEntryName = detachedContent.Name,
                        Status = AsicContainerValidationStatus.NotEvaluated,
                        FailureReason = "The run supplied no signature validation inputs, so the container's structure alone was validated."
                    });

                    continue;
                }

                CmsSignedData signedData = CmsSignedData.FromBytes(signature.Content.AsReadOnlySpan(), pool);
                owned.Add(signedData);
                SignedContentMemory content = SignedContentMemory.FromBytes(detachedContent.Content.AsReadOnlySpan(), pool);
                owned.Add(content);

                SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
                    inputs with
                    {
                        SignedDataObject = signedData,
                        SignerDocuments = [new SignerDocumentReference { Identifier = detachedContent.Name, Content = content }],
                        EvidenceRecords = EvidenceRecordInputsFor(signature.Name)
                    },
                    CAdESSeams(seams),
                    context.ProcessSelection,
                    context.Capabilities,
                    context.CurrentTime,
                    pool,
                    cancellationToken).ConfigureAwait(false);

                bool passed = outcome.Conclusion.Indication == SignatureValidationIndication.TotalPassed;
                AddSignatureValidation(new AsicSignatureValidation
                {
                    EntryName = signature.Name,
                    DetachedContentEntryName = detachedContent.Name,
                    Status = passed ? AsicContainerValidationStatus.Valid : AsicContainerValidationStatus.SignatureNotValid,
                    Outcome = outcome,
                    FailureReason = passed
                        ? null
                        : string.Create(
                            CultureInfo.InvariantCulture,
                            $"The validation process of EN 319 102-1 clause 5 returned {outcome.Conclusion.Indication}{StateSubIndications(outcome.Conclusion.SubIndications)}.")
                });
            }
        }


        /// <summary>
        /// Renders the sub-indications a conclusion carries, so a container-level failure names what the
        /// signature's own process concluded rather than only that it did not pass.
        /// </summary>
        /// <param name="subIndications">The sub-indications.</param>
        /// <returns>The rendered list, or an empty string when there are none.</returns>
        private static string StateSubIndications(IReadOnlyList<SignatureValidationSubIndication> subIndications)
        {
            if(subIndications.Count == 0)
            {
                return string.Empty;
            }

            var rendered = new List<string>(subIndications.Count);
            for(int i = 0; i < subIndications.Count; ++i)
            {
                rendered.Add(subIndications[i].Value);
            }

            return string.Create(CultureInfo.InvariantCulture, $" ({string.Join(", ", rendered)})");
        }


        /// <summary>
        /// Records one signature's conclusion and takes ownership of the validation run it holds.
        /// </summary>
        /// <param name="validation">The conclusion. Ownership transfers to the run.</param>
        private void AddSignatureValidation(AsicSignatureValidation validation)
        {
            signatures.Add(validation);
            owned.Add(validation);
        }


        /// <summary>
        /// Walks the Annex A.7 archive manifest chain backwards from the fixed name, following each link's single
        /// <c>Rootfile="true"</c> reference.
        /// </summary>
        public void WalkArchiveManifestChain()
        {
            if(facts.FixedArchiveManifest is not AsicZipEntry newest)
            {
                return;
            }

            var visited = new HashSet<string>(StringComparer.Ordinal);
            string? current = newest.Name;
            while(current is not null && visited.Add(current))
            {
                if(!parsedManifests.TryGetValue(current, out AsicManifest? model))
                {
                    chain.Add(new AsicArchiveManifestChainLink(current, TimestampEntryName: null, PreviousEntryName: null));

                    break;
                }

                AsicContainerUriResolution tokenReference = ResolveReference(model.SignatureReference.Uri);
                string? tokenEntryName = tokenReference.Status == AsicContainerUriStatus.Resolved ? tokenReference.EntryName : null;
                string? previous = null;
                for(int i = 0; i < model.DataObjectReferences.Count; ++i)
                {
                    AsicDataObjectReference reference = model.DataObjectReferences[i];

                    //Annex A.7 item 2 b) iv): exactly one reference of a renewal's manifest carries
                    //Rootfile="true", and it names the manifest that was renamed out of the fixed name. Item 2 b)
                    //iii) states every other reference either omits the attribute or sets it false.
                    if(reference.IsRootFile != true)
                    {
                        continue;
                    }

                    AsicContainerUriResolution resolution = ResolveReference(reference.Uri);
                    previous = resolution.Status == AsicContainerUriStatus.Resolved ? resolution.EntryName : null;

                    break;
                }

                chain.Add(new AsicArchiveManifestChainLink(current, tokenEntryName, previous));
                current = previous;
            }
        }


        /// <summary>
        /// States what the container protects and with what, applying NOTE 2 of clause 4.4.4.2: an Evidence
        /// Record protects the targets its manifest names and not that manifest file.
        /// </summary>
        public void StateProtectedObjects()
        {
            for(int i = 0; i < manifests.Count; ++i)
            {
                AsicManifestValidation manifest = manifests[i];
                if(manifest.Status != AsicContainerValidationStatus.Valid || manifest.ProtectiveObjectEntryName is not string protectiveObject)
                {
                    continue;
                }

                AsicProtectionKind kind = StateProtectionKind(protectiveObject, manifest.Role);
                if(!ProtectiveObjectValidated(protectiveObject, kind))
                {
                    continue;
                }

                DateTimeOffset? provenAt = ProtectiveObjectInstant(protectiveObject, kind);
                for(int referenceIndex = 0; referenceIndex < manifest.DataObjectReferences.Count; ++referenceIndex)
                {
                    AsicDataObjectReferenceValidation reference = manifest.DataObjectReferences[referenceIndex];
                    if(reference.Status != AsicDataObjectReferenceStatus.Matched || reference.EntryName is not string entryName)
                    {
                        continue;
                    }

                    protectedObjects.Add(new AsicProtectedObject
                    {
                        EntryName = entryName,
                        ProtectedBy = kind,
                        ProtectiveObjectEntryName = protectiveObject,
                        ThroughManifestEntryName = manifest.EntryName,
                        ProvenAt = provenAt
                    });
                }

                //The manifest file is itself covered by the CAdES object or the time-stamp token its SigReference
                //names (Annex A.4.1), and is NOT covered by an Evidence Record it names — clause 4.4.4.2 NOTE 2
                //states exactly that, and a protected-objects report that listed it would claim an integrity
                //guarantee the record does not make.
                if(kind != AsicProtectionKind.EvidenceRecord)
                {
                    protectedObjects.Add(new AsicProtectedObject
                    {
                        EntryName = manifest.EntryName,
                        ProtectedBy = kind,
                        ProtectiveObjectEntryName = protectiveObject,
                        ProvenAt = provenAt
                    });
                }
            }

            //An ASiC-S container carries no manifest: clause 4.3.3.2 item 4 makes the fixed names apply to the
            //single data file at the container root directly.
            if(facts.Shape != AsicContainerShape.Simple || facts.Manifests.Count > 0 || facts.DataObjects.Count != 1)
            {
                return;
            }

            string dataFile = facts.DataObjects[0].Name;
            for(int i = 0; i < signatures.Count; ++i)
            {
                if(signatures[i].Status == AsicContainerValidationStatus.Valid)
                {
                    protectedObjects.Add(new AsicProtectedObject
                    {
                        EntryName = dataFile,
                        ProtectedBy = AsicProtectionKind.CAdESSignature,
                        ProtectiveObjectEntryName = signatures[i].EntryName
                    });
                }
            }

            for(int i = 0; i < timeAssertions.Count; ++i)
            {
                if(timeAssertions[i].Status == AsicContainerValidationStatus.Valid)
                {
                    protectedObjects.Add(new AsicProtectedObject
                    {
                        EntryName = dataFile,
                        ProtectedBy = AsicProtectionKind.TimeAssertion,
                        ProtectiveObjectEntryName = timeAssertions[i].EntryName,
                        ProvenAt = timeAssertions[i].GenerationTime
                    });
                }
            }

            for(int i = 0; i < evidenceRecords.Count; ++i)
            {
                if(evidenceRecords[i].Status == AsicContainerValidationStatus.Valid)
                {
                    protectedObjects.Add(new AsicProtectedObject
                    {
                        EntryName = dataFile,
                        ProtectedBy = AsicProtectionKind.EvidenceRecord,
                        ProtectiveObjectEntryName = evidenceRecords[i].EntryName,
                        ProvenAt = evidenceRecords[i].InitialArchiveTime
                    });
                }
            }
        }


        /// <summary>
        /// States the container's overall conclusion from every per-object conclusion the run reached.
        /// </summary>
        /// <returns>The result, which owns everything the run created.</returns>
        public AsicContainerValidationResult Conclude()
        {
            AsicContainerValidationStatus status = AsicContainerValidationStatus.Valid;
            string? reason = null;

            //A digest mismatch is unconditional (clause 4.4.4.2 item d) and therefore outranks every other
            //status: it is looked for first and never replaced.
            for(int i = 0; i < manifests.Count; ++i)
            {
                if(manifests[i].Status == AsicContainerValidationStatus.DigestMismatch)
                {
                    return Result(AsicContainerValidationStatus.DigestMismatch, manifests[i].FailureReason);
                }
            }

            for(int i = 0; i < manifests.Count && status == AsicContainerValidationStatus.Valid; ++i)
            {
                if(manifests[i].Status != AsicContainerValidationStatus.Valid)
                {
                    status = manifests[i].Status;
                    reason = manifests[i].FailureReason;
                }
            }

            for(int i = 0; i < evidenceRecords.Count && status == AsicContainerValidationStatus.Valid; ++i)
            {
                if(evidenceRecords[i].Status != AsicContainerValidationStatus.Valid)
                {
                    status = evidenceRecords[i].Status;
                    reason = evidenceRecords[i].FailureReason;
                }
            }

            for(int i = 0; i < timeAssertions.Count && status == AsicContainerValidationStatus.Valid; ++i)
            {
                if(timeAssertions[i].Status != AsicContainerValidationStatus.Valid)
                {
                    status = timeAssertions[i].Status;
                    reason = timeAssertions[i].FailureReason;
                }
            }

            for(int i = 0; i < signatures.Count && status == AsicContainerValidationStatus.Valid; ++i)
            {
                if(signatures[i].Status != AsicContainerValidationStatus.Valid)
                {
                    status = signatures[i].Status;
                    reason = signatures[i].FailureReason;
                }
            }

            if(status == AsicContainerValidationStatus.Valid && ChainIsBroken())
            {
                status = AsicContainerValidationStatus.ArchiveManifestChainBroken;
                reason = "The Annex A.7 chain does not walk back from META-INF/ASiCArchiveManifest.xml to a first link through Rootfile references naming archive manifests the container carries.";
            }

            if(status == AsicContainerValidationStatus.Valid
                && facts.Signatures.Count == 0
                && facts.TimeAssertions.Count == 0
                && facts.EvidenceRecords.Count == 0)
            {
                status = AsicContainerValidationStatus.NoProtectiveObject;
                reason = "The container carries no CAdES object, no time assertion and no Evidence Record, so nothing in it is protected.";
            }

            return Result(status, reason);
        }


        /// <summary>Builds the result carrying one status.</summary>
        /// <param name="status">The overall conclusion.</param>
        /// <param name="reason">Why, when it is not <see cref="AsicContainerValidationStatus.Valid"/>.</param>
        /// <returns>The result.</returns>
        private AsicContainerValidationResult Result(AsicContainerValidationStatus status, string? reason) =>
            new(owned)
            {
                Status = status,
                ReadStatus = AsicZipReadStatus.Read,
                Facts = facts,
                Manifests = manifests,
                Signatures = signatures,
                TimeAssertions = timeAssertions,
                EvidenceRecords = evidenceRecords,
                ArchiveManifestChain = chain,
                ProtectedObjects = protectedObjects,
                FailureReason = status == AsicContainerValidationStatus.Valid ? null : reason
            };


        /// <summary>
        /// Resolves one manifest reference against the container root under the bounds THIS run states — the
        /// manifest parse limits' character bound and the read limits' entry-name octet bound.
        /// </summary>
        /// <param name="reference">The <c>URI</c> attribute value, or <see langword="null"/>.</param>
        /// <returns>The resolution.</returns>
        /// <remarks>
        /// Both bounds are the run's own so that the resolver admits exactly the names this run's reader admitted
        /// (<see cref="AsicZipReading"/> checks every entry name against
        /// <see cref="AsicZipReadLimits.MaximumEntryNameByteLength"/>). A resolver held at the conformant value
        /// while the reader took the caller's would report a reference to an entry the container demonstrably
        /// carries as <see cref="AsicDataObjectReferenceStatus.ReferenceNotResolvable"/>, blaming the manifest for
        /// a disagreement between two of this library's own caps.
        /// </remarks>
        private AsicContainerUriResolution ResolveReference(string? reference) =>
            AsicContainerUri.Resolve(reference, context.ManifestParseLimits.MaximumUriLength, context.ReadLimits.MaximumEntryNameByteLength);


        /// <summary>
        /// Recomputes one <c>DataObjectReference</c>'s digest over the entry it names and compares it with what
        /// the manifest states.
        /// </summary>
        /// <param name="reference">The reference.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>What the comparison concluded.</returns>
        private async ValueTask<AsicDataObjectReferenceValidation> EvaluateReferenceAsync(
            AsicDataObjectReference reference,
            CancellationToken cancellationToken)
        {
            AsicContainerUriResolution resolution = ResolveReference(reference.Uri);
            if(resolution.Status != AsicContainerUriStatus.Resolved || resolution.EntryName is not string entryName)
            {
                return new AsicDataObjectReferenceValidation
                {
                    Uri = reference.Uri,
                    DigestAlgorithm = reference.DigestAlgorithm,
                    Status = AsicDataObjectReferenceStatus.ReferenceNotResolvable
                };
            }

            AsicZipEntry? entry = facts.FindEntry(entryName);
            if(entry is null)
            {
                return new AsicDataObjectReferenceValidation
                {
                    Uri = reference.Uri,
                    EntryName = entryName,
                    DigestAlgorithm = reference.DigestAlgorithm,
                    Status = AsicDataObjectReferenceStatus.ObjectMissing
                };
            }

            using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
                entry.Content.AsReadOnlyMemory(), reference.DigestAlgorithm.OutputByteLength, reference.DigestAlgorithm.DigestTag, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            return new AsicDataObjectReferenceValidation
            {
                Uri = reference.Uri,
                EntryName = entryName,
                DigestAlgorithm = reference.DigestAlgorithm,
                Status = computed.AsReadOnlySpan().SequenceEqual(reference.Digest.AsReadOnlySpan())
                    ? AsicDataObjectReferenceStatus.Matched
                    : AsicDataObjectReferenceStatus.DigestMismatch
            };
        }


        /// <summary>
        /// States the entries an Evidence Record protects: the <c>DataObjectReference</c> targets of the manifest
        /// naming it, or the single root data file of an ASiC-S container.
        /// </summary>
        /// <param name="manifestEntryName">The manifest naming the record, or <see langword="null"/> when none does.</param>
        /// <returns>The entry names; empty when nothing states what the record protects.</returns>
        private List<string> StateEvidenceRecordTargets(string? manifestEntryName)
        {
            if(manifestEntryName is null)
            {
                return facts.Shape == AsicContainerShape.Simple && facts.DataObjects.Count == 1
                    ? [facts.DataObjects[0].Name]
                    : [];
            }

            for(int i = 0; i < manifests.Count; ++i)
            {
                if(!string.Equals(manifests[i].EntryName, manifestEntryName, StringComparison.Ordinal))
                {
                    continue;
                }

                var targets = new List<string>(manifests[i].DataObjectReferences.Count);
                for(int referenceIndex = 0; referenceIndex < manifests[i].DataObjectReferences.Count; ++referenceIndex)
                {
                    if(manifests[i].DataObjectReferences[referenceIndex].EntryName is string entryName)
                    {
                        targets.Add(entryName);
                    }
                }

                return targets;
            }

            return [];
        }


        /// <summary>
        /// Finds the manifest whose <c>SigReference</c> names one entry.
        /// </summary>
        /// <param name="entryName">The protective object's entry name.</param>
        /// <returns>The manifest's entry name, or <see langword="null"/> when none names it.</returns>
        private string? FindManifestNaming(string entryName)
        {
            for(int i = 0; i < manifests.Count; ++i)
            {
                if(string.Equals(manifests[i].ProtectiveObjectEntryName, entryName, StringComparison.Ordinal))
                {
                    return manifests[i].EntryName;
                }
            }

            return null;
        }


        /// <summary>
        /// Resolves the octets a protective object applies to: the manifest file naming it (Annex A.4.1), or the
        /// single root data file of an ASiC-S container (clause 4.3.3.2 item 4).
        /// </summary>
        /// <param name="protectiveObjectEntryName">The CAdES object's or time assertion's entry name.</param>
        /// <returns>The entry, or <see langword="null"/> when nothing states what the object applies to.</returns>
        private AsicZipEntry? ResolveProtectedEntry(string protectiveObjectEntryName)
        {
            if(FindManifestNaming(protectiveObjectEntryName) is string manifestEntryName)
            {
                return facts.FindEntry(manifestEntryName);
            }

            return facts.Shape == AsicContainerShape.Simple && facts.Manifests.Count == 0 && facts.DataObjects.Count == 1
                ? facts.DataObjects[0]
                : null;
        }


        /// <summary>
        /// Builds the Evidence Record inputs one embedded signature's own validation run is given: every record
        /// the container carries that proved that signature's octets.
        /// </summary>
        /// <param name="signatureEntryName">The CAdES object's entry name.</param>
        /// <returns>The inputs; empty when no record of the container proves the object.</returns>
        private List<EvidenceRecordValidationInput> EvidenceRecordInputsFor(string signatureEntryName)
        {
            List<EvidenceRecordValidationInput>? inputs = null;
            for(int i = 0; i < evidenceRecords.Count; ++i)
            {
                AsicEvidenceRecordValidation record = evidenceRecords[i];
                if(record.Status != AsicContainerValidationStatus.Valid
                    || !readEvidenceRecords.TryGetValue(record.EntryName, out EvidenceRecord? carrier)
                    || !Protects(record, signatureEntryName)
                    || facts.FindEntry(signatureEntryName) is not AsicZipEntry signature)
                {
                    continue;
                }

                inputs ??= [];
                inputs.Add(new EvidenceRecordValidationInput
                {
                    EvidenceRecord = carrier,
                    Identifier = record.EntryName,
                    ProtectedObjects =
                    [
                        new EvidenceRecordProtectedObject
                        {
                            Object = signature.Content,
                            Kind = ValidationObjectKind.Signature,
                            Reference = signature.Name
                        }
                    ]
                });
            }

            return inputs ?? [];

            //Reports whether one record's proved set holds one entry name.
            static bool Protects(AsicEvidenceRecordValidation record, string entryName)
            {
                for(int i = 0; i < record.ProtectedEntryNames.Count; ++i)
                {
                    if(string.Equals(record.ProtectedEntryNames[i], entryName, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }

                return false;
            }
        }


        /// <summary>
        /// Reads one entry's octets as an Evidence Record.
        /// </summary>
        /// <param name="entry">The entry.</param>
        /// <returns>The record, owned by the run, or <see langword="null"/> when the octets are not one.</returns>
        private EvidenceRecord? TryReadEvidenceRecord(AsicZipEntry entry)
        {
            try
            {
                EvidenceRecord record = EvidenceRecord.Read(entry.Content.AsReadOnlySpan(), pool);
                owned.Add(record);

                return record;
            }
            catch(Exception exception) when(exception is System.Formats.Asn1.AsnContentException or ArgumentException or InvalidOperationException)
            {
                //A container's Evidence Record is attacker-reachable input: a structure this library cannot read
                //is a status, never an exception leaving the validation (contract R-10).
                return null;
            }
        }


        /// <summary>
        /// States which kind of object protects through one manifest.
        /// </summary>
        /// <param name="protectiveObjectEntryName">The protective object's entry name.</param>
        /// <param name="role">The manifest's role, which is what tells an archive chain's token from a bare time assertion.</param>
        /// <returns>The kind.</returns>
        private static AsicProtectionKind StateProtectionKind(string protectiveObjectEntryName, AsicManifestRole role) =>
            AsicManifestNaming.IsSignatureEntryName(protectiveObjectEntryName) ? AsicProtectionKind.CAdESSignature
                : AsicManifestNaming.IsTimestampEntryName(protectiveObjectEntryName)
                    ? role == AsicManifestRole.Archive ? AsicProtectionKind.ArchiveTimeAssertion : AsicProtectionKind.TimeAssertion
                    : AsicProtectionKind.EvidenceRecord;


        /// <summary>
        /// Reports whether the protective object a manifest names validated.
        /// </summary>
        /// <param name="protectiveObjectEntryName">The protective object's entry name.</param>
        /// <param name="kind">What kind of object it is.</param>
        /// <returns><see langword="true"/> when it validated.</returns>
        private bool ProtectiveObjectValidated(string protectiveObjectEntryName, AsicProtectionKind kind)
        {
            if(kind == AsicProtectionKind.CAdESSignature)
            {
                for(int i = 0; i < signatures.Count; ++i)
                {
                    if(string.Equals(signatures[i].EntryName, protectiveObjectEntryName, StringComparison.Ordinal))
                    {
                        return signatures[i].Status == AsicContainerValidationStatus.Valid;
                    }
                }

                return false;
            }

            if(kind == AsicProtectionKind.EvidenceRecord)
            {
                for(int i = 0; i < evidenceRecords.Count; ++i)
                {
                    if(string.Equals(evidenceRecords[i].EntryName, protectiveObjectEntryName, StringComparison.Ordinal))
                    {
                        return evidenceRecords[i].Status == AsicContainerValidationStatus.Valid;
                    }
                }

                return false;
            }

            for(int i = 0; i < timeAssertions.Count; ++i)
            {
                if(string.Equals(timeAssertions[i].EntryName, protectiveObjectEntryName, StringComparison.Ordinal))
                {
                    return timeAssertions[i].Status == AsicContainerValidationStatus.Valid;
                }
            }

            return false;
        }


        /// <summary>
        /// States the instant a protective object asserts, when it asserts one.
        /// </summary>
        /// <param name="protectiveObjectEntryName">The protective object's entry name.</param>
        /// <param name="kind">What kind of object it is.</param>
        /// <returns>The instant, or <see langword="null"/> when the object asserts none.</returns>
        private DateTimeOffset? ProtectiveObjectInstant(string protectiveObjectEntryName, AsicProtectionKind kind)
        {
            if(kind == AsicProtectionKind.EvidenceRecord)
            {
                for(int i = 0; i < evidenceRecords.Count; ++i)
                {
                    if(string.Equals(evidenceRecords[i].EntryName, protectiveObjectEntryName, StringComparison.Ordinal))
                    {
                        return evidenceRecords[i].InitialArchiveTime;
                    }
                }

                return null;
            }

            if(kind == AsicProtectionKind.CAdESSignature)
            {
                //A CAdES object asserts no instant of its own; what it proves is the conclusion of its own
                //validation run, which the report carries separately.
                return null;
            }

            for(int i = 0; i < timeAssertions.Count; ++i)
            {
                if(string.Equals(timeAssertions[i].EntryName, protectiveObjectEntryName, StringComparison.Ordinal))
                {
                    return timeAssertions[i].GenerationTime;
                }
            }

            return null;
        }


        /// <summary>
        /// Reports whether the Annex A.7 chain the walk found is broken: a link the walk could not read, a
        /// backward pointer naming something that is not an archive manifest the container carries, or a chain
        /// that did not reach every archive manifest the container carries.
        /// </summary>
        /// <returns><see langword="true"/> when the chain is broken.</returns>
        private bool ChainIsBroken()
        {
            int archiveManifests = 0;
            for(int i = 0; i < facts.Manifests.Count; ++i)
            {
                archiveManifests += facts.Manifests[i].Role == AsicManifestRole.Archive ? 1 : 0;
            }

            if(archiveManifests == 0)
            {
                return false;
            }

            if(facts.FixedArchiveManifest is null || chain.Count != archiveManifests)
            {
                return true;
            }

            for(int i = 0; i < chain.Count; ++i)
            {
                AsicArchiveManifestChainLink link = chain[i];
                if(link.TimestampEntryName is null)
                {
                    return true;
                }

                if(link.PreviousEntryName is string previous
                    && !AsicManifestNaming.IsArchiveManifestEntryName(previous))
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>
        /// Copies a time-stamp token's octets into a carrier the run can hand the token surfaces.
        /// </summary>
        /// <param name="token">The token's octets.</param>
        /// <returns>The carrier, which the caller disposes.</returns>
        private PkiCertificateMemory CopyToken(ReadOnlySpan<byte> token)
        {
            IMemoryOwner<byte> owner = pool.Rent(Math.Max(token.Length, 1));
            try
            {
                token.CopyTo(owner.Memory.Span);

                return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
            }
            catch
            {
                owner.Dispose();

                throw;
            }
        }


        /// <summary>
        /// States the seams an embedded object is validated with: the caller's certificate seams, with the format
        /// binding fixed to this library's CAdES one.
        /// </summary>
        /// <param name="seams">The caller's seam bundle.</param>
        /// <returns>The bundle the run uses.</returns>
        /// <remarks>
        /// Clause 4.4.4.2 item 3 a) and clause 4.3.3.2 item 4 b) both state what a <c>*signature*.p7s</c> entry
        /// is — a CAdES object — and a time-stamp token is a CMS object too, so the format binding is not a
        /// caller's choice here: a bundle naming another format would be validating something the container does
        /// not carry.
        /// </remarks>
        private static SignatureValidationSeams CAdESSeams(SignatureValidationSeams seams) =>
            seams.Format.Format.Equals(CAdESSignatureFacts.Seam.Format)
                ? seams
                : seams with { Format = CAdESSignatureFacts.Seam };


        /// <summary>
        /// Reports whether a name is one of the four kinds clause 4.4.4.2 items 3 and 4 admit for the target of a
        /// <c>SigReference</c>.
        /// </summary>
        /// <param name="entryName">The entry name.</param>
        /// <returns><see langword="true"/> when the name is one of the four.</returns>
        private static bool IsRecognizedProtectiveObjectName(string entryName) =>
            AsicManifestNaming.IsSignatureEntryName(entryName)
            || AsicManifestNaming.IsTimestampEntryName(entryName)
            || AsicManifestNaming.IsBinaryEvidenceRecordEntryName(entryName)
            || AsicManifestNaming.IsXmlEvidenceRecordEntryName(entryName);
    }
}
