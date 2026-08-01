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
/// The two selection methods <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">RFC 4998
/// Appendix A</see> distinguishes for an Evidence Record carried inside a CMS object, and which of the two
/// attribute identifiers of <see cref="EvidenceRecordWellKnown"/> names each.
/// </summary>
/// <remarks>
/// The appendix defines both identifiers "depending on the selection method" and never states the mapping in
/// prose. The mapping this library applies was settled structurally and then checked against third-party CMS
/// objects carrying these attributes; see <see cref="EvidenceRecordWellKnown.IsInternalEvidenceRecordAttribute"/>
/// for what it was checked against.
/// </remarks>
public enum EvidenceRecordCmsSelectionMethod
{
    /// <summary>No selection method has been stated. The value of an unset field, by design.</summary>
    NotStated = 0,

    /// <summary>
    /// The first selection method: "The CMS Object as a whole including contentInfo is selected as data object
    /// and archive timestamped. This means that a hash value of the CMS object MUST be located in the first list
    /// of hash values of Archive Timestamps." Carried by <c>id-aa-er-internal</c>.
    /// </summary>
    CmsObject = 1,

    /// <summary>
    /// The second selection method: "The CMS Object and the signed or encrypted content are included in the
    /// Archive Timestamp as separated objects. In this case, the hash value of the CMS Object as well as the
    /// hash value of the content have to be stored in the first list of hash values as a group of data objects."
    /// Carried by <c>id-aa-er-external</c>.
    /// </summary>
    CmsObjectAndContent = 2
}


/// <summary>
/// How many Evidence Record attributes an attachment is willing to leave on one signature, which is the
/// <c>SHOULD</c> of <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">RFC 4998 Appendix A</see> and
/// the sentence that follows it.
/// </summary>
/// <remarks>
/// "The attributes SHOULD only occur once. If they appear several times, they have to be stored within the first
/// signature in chronological order." The first sentence is the conformant default and the second states what a
/// producer that departs from it owes, so the departure is a choice the caller states rather than one the library
/// makes silently.
/// </remarks>
public enum EvidenceRecordCmsAttachmentPolicy
{
    /// <summary>
    /// The attribute occurs once, as the <c>SHOULD</c> asks. Attaching to a signature that already carries an
    /// Evidence Record attribute is refused.
    /// </summary>
    SingleOccurrence = 0,

    /// <summary>
    /// Several attributes are permitted, each appended after the ones already there, which is the chronological
    /// order the sentence after the <c>SHOULD</c> requires of a producer that emits more than one.
    /// </summary>
    ChronologicalSequence = 1
}


/// <summary>
/// Where one Evidence Record sits inside a CMS object's <c>unsignedAttrs</c> set, and which selection method of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">RFC 4998 Appendix A</see> the attribute
/// identifier carrying it names.
/// </summary>
/// <param name="Location">The attribute and value indices the record's octets sit at.</param>
/// <param name="SelectionMethod">The selection method the attribute identifier names.</param>
[DebuggerDisplay("EvidenceRecordCmsPlacement({SelectionMethod}, attribute {Location.AttributeIndex}, value {Location.ValueIndex})")]
public readonly record struct EvidenceRecordCmsPlacement(
    CmsUnsignedAttributeValueLocation Location,
    EvidenceRecordCmsSelectionMethod SelectionMethod);


/// <summary>
/// What a verifier concluded about the Evidence Records a CMS object carries.
/// </summary>
public enum EvidenceRecordCmsVerificationStatus
{
    /// <summary>No verification has been attempted. The value of an unset field, by design.</summary>
    NotVerified = 0,

    /// <summary>Every Evidence Record the object carries proved a reconstructed view of that object, and their asserted times ascend with the views they prove.</summary>
    Verified = 1,

    /// <summary>The object carries no Evidence Record attribute at all, so there is nothing here to verify.</summary>
    NoEvidenceRecord = 2,

    /// <summary>The Signed Data Object could not be walked, so where its attributes sit could not be established.</summary>
    SignedDataMalformed = 3,

    /// <summary>An Evidence Record attribute value could not be decoded as an <c>EvidenceRecord</c>.</summary>
    EvidenceRecordMalformed = 4,

    /// <summary>An Evidence Record proved none of the reconstructed views of the object it is carried by.</summary>
    EvidenceRecordNotVerified = 5,

    /// <summary>
    /// The object carries more Evidence Record attribute values than this verification reconstructs views for.
    /// Appendix A states the attributes "SHOULD only occur once"; the bound is an attacker-reachable-input
    /// limit, not a conformance rule.
    /// </summary>
    TooManyEvidenceRecords = 6,

    /// <summary>
    /// Appendix A: "The verification of the nth one EvidenceRecord must result in a point of time when the
    /// document must have existed with the first n attributes. The verification of the n+1th attribute must
    /// prove that this requirement has been met." A record proving a view that holds more Evidence Record
    /// attributes asserts an instant no later than one proving a view that holds fewer, and these do not.
    /// </summary>
    ChronologyBroken = 7
}


/// <summary>
/// What a verifier concluded about one Evidence Record a CMS object carries.
/// </summary>
[DebuggerDisplay("EvidenceRecordCmsRecordVerification({Status}, position {ChronologicalPosition}, over {ProvedViewEvidenceRecordCount} records)")]
public sealed class EvidenceRecordCmsRecordVerification: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new conclusion about one embedded Evidence Record.
    /// </summary>
    /// <param name="placement">Where the record sits and which selection method carries it.</param>
    /// <param name="status">What the verifier concluded.</param>
    /// <param name="chronologicalPosition">The record's discovered chronological position, or <c>-1</c> when no view was proved.</param>
    /// <param name="provedViewEvidenceRecordCount">How many Evidence Record attribute values the proved view holds, or <c>-1</c> when no view was proved.</param>
    /// <param name="verification">The conclusion the Evidence Record Syntax verification reached. Ownership transfers to this instance.</param>
    internal EvidenceRecordCmsRecordVerification(
        EvidenceRecordCmsPlacement placement,
        EvidenceRecordCmsVerificationStatus status,
        int chronologicalPosition,
        int provedViewEvidenceRecordCount,
        EvidenceRecordVerification? verification)
    {
        Placement = placement;
        Status = status;
        ChronologicalPosition = chronologicalPosition;
        ProvedViewEvidenceRecordCount = provedViewEvidenceRecordCount;
        Verification = verification;
    }


    /// <summary>Gets where the record sits and which selection method of Appendix A carries it.</summary>
    public EvidenceRecordCmsPlacement Placement { get; }

    /// <summary>Gets what the verifier concluded about this record.</summary>
    public EvidenceRecordCmsVerificationStatus Status { get; }

    /// <summary>
    /// Gets the record's chronological position, counting from zero, or <c>-1</c> when the record proved no view.
    /// </summary>
    /// <remarks>
    /// Appendix A verifies the first record against the object with every Evidence Record removed and the
    /// <c>n</c>th against the object where "the first n-1 attributes should remain", so a record's position is
    /// which of those views it proves. The position is DISCOVERED rather than read off the attribute's place in
    /// the set: <c>unsignedAttrs</c> is a <c>SET OF</c>, a conformant producer sorts it into the canonical order
    /// DER states, and that order is the encodings' — not the records' chronology. Third-party objects exist
    /// whose two Evidence Records, both carried by the same identifier, sit in the set in exactly the reverse of
    /// the order they were created in, which is what makes "in chronological order" unenforceable on the wire.
    /// Two records may share a position when each proves the same view, which is a production the appendix does
    /// not describe but third-party objects carry.
    /// </remarks>
    public int ChronologicalPosition { get; }

    /// <summary>
    /// Gets how many Evidence Record attribute values the reconstructed view this record proved still holds, or
    /// <c>-1</c> when the record proved no view.
    /// </summary>
    public int ProvedViewEvidenceRecordCount { get; }

    /// <summary>
    /// Gets the conclusion the Evidence Record Syntax verification reached for the view named by
    /// <see cref="ChronologicalPosition"/>, or for the deepest view the discovery reached when the record proved
    /// none of them. It is <see langword="null"/> only when the record could not be decoded at all.
    /// </summary>
    public EvidenceRecordVerification? Verification { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Verification?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// What a verifier concluded about every Evidence Record a CMS object carries.
/// </summary>
[DebuggerDisplay("EvidenceRecordCmsVerification({Status}, {EvidenceRecords.Count} records)")]
public sealed class EvidenceRecordCmsVerification: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new conclusion.
    /// </summary>
    /// <param name="status">What the verifier concluded overall.</param>
    /// <param name="evidenceRecords">One conclusion per embedded Evidence Record, in the order the attribute values are encoded. Ownership transfers to this instance.</param>
    internal EvidenceRecordCmsVerification(EvidenceRecordCmsVerificationStatus status, IReadOnlyList<EvidenceRecordCmsRecordVerification> evidenceRecords)
    {
        Status = status;
        EvidenceRecords = evidenceRecords;
    }


    /// <summary>Gets what the verifier concluded overall.</summary>
    public EvidenceRecordCmsVerificationStatus Status { get; }

    /// <summary>Gets one conclusion per embedded Evidence Record, in the order the attribute values are encoded. Owned by this instance.</summary>
    public IReadOnlyList<EvidenceRecordCmsRecordVerification> EvidenceRecords { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            for(int i = 0; i < EvidenceRecords.Count; ++i)
            {
                EvidenceRecords[i].Dispose();
            }

            disposed = true;
        }
    }
}


/// <summary>
/// What one <see cref="EvidenceRecordCmsIntegration.VerifyEmbeddedAsync"/> call needs: the CMS object whose
/// Evidence Records are to be verified, which of its signers carries them, and the detached content when the
/// second selection method of Appendix A is being claimed.
/// </summary>
public sealed record EvidenceRecordCmsVerificationContext
{
    /// <summary>Gets the CMS object. The caller owns it.</summary>
    public required CmsSignedData SignedData { get; init; }

    /// <summary>
    /// Gets the zero-based index of the <c>SignerInfo</c> whose <c>unsignedAttrs</c> set carries the records.
    /// Appendix A places them on the first signature; a reader states which one it is looking at.
    /// </summary>
    public int SignerIndex { get; init; }

    /// <summary>
    /// Gets the detached content the CMS object signs, or <see langword="null"/> when there is none to state.
    /// </summary>
    /// <remarks>
    /// Supplying it turns on the group check of the second selection method for every record carried by
    /// <c>id-aa-er-external</c>: the record's first list of hash values then has to hold the hash of the
    /// reconstructed CMS object and the hash of this content and nothing else, which is what "as a group of data
    /// objects" states. Leaving it out verifies only that the record covers the CMS object.
    /// </remarks>
    public ReadOnlyMemory<byte>? DetachedContent { get; init; }
}


/// <summary>
/// Carrying an Evidence Record inside a CMS object, per
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">IETF RFC 4998 Appendix A</see>: attaching one
/// as an unsigned attribute of the first signature, reconstructing the view of the object a record was computed
/// over, and verifying every record the object carries.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The archived data object is a reconstruction, not the file.</strong> "In case of verification, if
/// only one EvidenceRecord is contained in the CMS object, the hash value must be generated over the CMS object
/// without the one EvidenceRecord. This means that the attribute has to be removed before verification. The
/// length of fields containing tags has to be adapted. Apart from that, the existing coding must not be
/// modified." That removal is <see cref="CmsSignedDataReduction.RemoveUnsignedAttributeValues"/>, the inverse of
/// the splice that attached the attribute, and it is the only edit this surface makes to an object it did not
/// build.
/// </para>
/// <para>
/// <strong>Several records nest.</strong> "During verification of the first (in chronological order)
/// EvidenceRecord, all EvidenceRecord have to be removed in order to generate the data object. During
/// verification of the nth one EvidenceRecord, the first n-1 attributes should remain within the CMS object."
/// The views are therefore a nested family: the object with none of the records, with the first, with the first
/// two, and so on. <see cref="VerifyEmbeddedAsync"/> walks that family for every record and reports which view
/// each proved, rather than assuming a record's chronological position from where its attribute happens to sit
/// in the <c>SET OF</c> — third-party objects exist whose two records are encoded in the reverse of the order
/// they were created in, which the appendix's "in chronological order" cannot bind once a producer canonicalises
/// the set.
/// </para>
/// <para>
/// <strong>An object carrying no Evidence Record is hashed as it stands.</strong> "If the CMS object doesn't
/// have the EvidenceRecord Attributes -- which indicates that the EvidenceRecord has been provided externally --
/// the archive timestamped data object has to be generated over the complete CMS object within the existing
/// coding." <see cref="BuildArchivedDataObject"/> returns the object's own octets in that case, which is what a
/// record kept beside the object rather than inside it is verified against.
/// </para>
/// </remarks>
public static class EvidenceRecordCmsIntegration
{
    /// <summary>
    /// The largest number of Evidence Record attribute values one verification reconstructs views for. Appendix
    /// A's attributes "SHOULD only occur once"; this bounds the work an attacker-supplied object can provoke,
    /// which grows with the square of the count because every record is tried against every view.
    /// </summary>
    private const int MaximumEvidenceRecords = 16;


    /// <summary>
    /// The attribute identifier that carries a given selection method.
    /// </summary>
    /// <param name="selectionMethod">The selection method.</param>
    /// <returns>The dotted-decimal <c>attrType</c> object identifier.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the selection method is not one Appendix A defines.</exception>
    public static string SelectionMethodAttributeOid(EvidenceRecordCmsSelectionMethod selectionMethod) => selectionMethod switch
    {
        EvidenceRecordCmsSelectionMethod.CmsObject => EvidenceRecordWellKnown.InternalEvidenceRecordAttributeOid,
        EvidenceRecordCmsSelectionMethod.CmsObjectAndContent => EvidenceRecordWellKnown.ExternalEvidenceRecordAttributeOid,
        _ => throw new ArgumentOutOfRangeException(nameof(selectionMethod), selectionMethod, "RFC 4998 Appendix A defines two selection methods, and an Evidence Record attribute states one of them.")
    };


    /// <summary>
    /// The selection method a given attribute identifier names.
    /// </summary>
    /// <param name="attributeType">The dotted-decimal <c>attrType</c> object identifier.</param>
    /// <returns>The selection method, or <see cref="EvidenceRecordCmsSelectionMethod.NotStated"/> when the identifier is neither of Appendix A's.</returns>
    public static EvidenceRecordCmsSelectionMethod SelectionMethodOfAttribute(string attributeType) => attributeType switch
    {
        _ when EvidenceRecordWellKnown.IsInternalEvidenceRecordAttribute(attributeType) => EvidenceRecordCmsSelectionMethod.CmsObject,
        _ when EvidenceRecordWellKnown.IsExternalEvidenceRecordAttribute(attributeType) => EvidenceRecordCmsSelectionMethod.CmsObjectAndContent,
        _ => EvidenceRecordCmsSelectionMethod.NotStated
    };


    /// <summary>
    /// Attaches an Evidence Record to a CMS object as an unsigned attribute of its first signature, preserving
    /// every octet of the object exactly and appending after whatever unsigned attributes are already there.
    /// </summary>
    /// <param name="signedData">The CMS object. Not modified; the result is a new carrier.</param>
    /// <param name="evidenceRecord">The Evidence Record to carry, whose octets become the attribute's single value.</param>
    /// <param name="selectionMethod">Which selection method of Appendix A the record was built under, which chooses the attribute identifier.</param>
    /// <param name="policy">Whether the signature is permitted to end up carrying more than one Evidence Record attribute.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The CMS object carrying the record. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/>, <paramref name="evidenceRecord"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="selectionMethod"/> is not one Appendix A defines.</exception>
    /// <exception cref="EvidenceRecordCreationException">When the signature already carries an Evidence Record attribute and the policy is <see cref="EvidenceRecordCmsAttachmentPolicy.SingleOccurrence"/>.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a signature.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or carries octets after the outer ContentInfo.</exception>
    /// <remarks>
    /// <para>
    /// Appendix A: "the Evidence Record has to be added to the first signature of the CMS Object of signed
    /// data", so this surface takes no signer index — there is one place the appendix admits.
    /// </para>
    /// <para>
    /// <strong>Each record becomes its own <c>Attribute</c>.</strong> The appendix says the attributes "SHOULD
    /// only occur once" and, in the same breath, "If they appear several times, they have to be stored within
    /// the first signature in chronological order". A chronological order is only expressible across
    /// <c>Attribute</c> instances of a set this library appends to and never re-sorts; several values inside one
    /// <c>attrValues</c> <c>SET OF</c> would be ordered by their encodings instead, which carries no chronology
    /// at all. Emitting one attribute per record is therefore the reading that satisfies the sentence that binds
    /// the multi-record case.
    /// </para>
    /// <para>
    /// <strong>Neither order survives the wire, and this surface does not pretend otherwise.</strong> A
    /// conformant DER producer sorts <c>unsignedAttrs</c> into the canonical order of its members' encodings, so
    /// two Evidence Record attributes carried by the same identifier come out ordered by their values. Attaching
    /// in chronological order is what a producer owes; a verifier discovers the order instead of trusting it, and
    /// <see cref="VerifyEmbeddedAsync"/> does.
    /// </para>
    /// </remarks>
    public static CmsSignedData Attach(
        CmsSignedData signedData,
        EvidenceRecord evidenceRecord,
        EvidenceRecordCmsSelectionMethod selectionMethod,
        EvidenceRecordCmsAttachmentPolicy policy,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(evidenceRecord);
        ArgumentNullException.ThrowIfNull(pool);

        if(policy == EvidenceRecordCmsAttachmentPolicy.SingleOccurrence && LocateEvidenceRecords(signedData, signerIndex: 0).Count != 0)
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.EvidenceRecordAlreadyAttached,
                "The signature already carries an Evidence Record attribute, and RFC 4998 Appendix A states the attributes SHOULD only occur once. Attaching a further one is the documented departure that EvidenceRecordCmsAttachmentPolicy.ChronologicalSequence states.");
        }

        using CmsAttribute attribute = CmsAttribute.Create(SelectionMethodAttributeOid(selectionMethod), evidenceRecord.AsReadOnlySpan(), pool);

        return CmsSignedDataAugmentation.AppendUnsignedAttributes(signedData, signerIndex: 0, [attribute], pool);
    }


    /// <summary>
    /// Enumerates the Evidence Records one signer of a CMS object carries, in the order their attribute values
    /// are encoded.
    /// </summary>
    /// <param name="signedData">The CMS object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <returns>The placements, or an empty list when the signer carries no Evidence Record attribute.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a <c>SignerInfo</c> at that index.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or exceeds the bounds the walk stays within.</exception>
    public static IReadOnlyList<EvidenceRecordCmsPlacement> LocateEvidenceRecords(CmsSignedData signedData, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex);
        var placements = new List<EvidenceRecordCmsPlacement>();
        for(int i = 0; i < locations.Count; ++i)
        {
            EvidenceRecordCmsSelectionMethod selectionMethod = SelectionMethodOfAttribute(locations[i].AttributeType);
            if(selectionMethod != EvidenceRecordCmsSelectionMethod.NotStated)
            {
                placements.Add(new EvidenceRecordCmsPlacement(locations[i], selectionMethod));
            }
        }

        return placements;
    }


    /// <summary>
    /// Reconstructs the view of a CMS object one of its Evidence Records was computed over: the object with the
    /// named Evidence Record attribute values left in place and every other one removed, the definite lengths of
    /// the containers that shrank re-derived, and every other octet bit-identical.
    /// </summary>
    /// <param name="signedData">The CMS object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> carrying the records.</param>
    /// <param name="retainedEvidenceRecords">The Evidence Records the view keeps, as <see cref="LocateEvidenceRecords"/> reports them. An empty list produces the view holding none.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The reconstructed object. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/>, <paramref name="retainedEvidenceRecords"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a <c>SignerInfo</c> at that index, a retained record is not one the signer carries, or a container whose length has to be re-derived carries a non-minimally encoded definite length.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or exceeds the bounds the walk stays within.</exception>
    /// <remarks>
    /// <para>
    /// The appendix names two members of this family explicitly. Retaining none is the view "during verification
    /// of the first (in chronological order) EvidenceRecord", where "all EvidenceRecord have to be removed in
    /// order to generate the data object"; retaining the records that came before one is the view where "the
    /// first n-1 attributes should remain within the CMS object".
    /// </para>
    /// <para>
    /// <strong>The set is stated, not counted.</strong> Which records "came before" is a chronological fact and
    /// <c>unsignedAttrs</c> is a <c>SET OF</c> whose canonical order is its members' encodings, so a count taken
    /// in encoding order names the wrong view whenever the two orders differ — and third-party objects exist
    /// where they are exact reverses of each other. <see cref="VerifyEmbeddedAsync"/> discovers the sets rather
    /// than counting.
    /// </para>
    /// <para>
    /// Retaining every record the object carries returns the object's own octets, which is also what an object
    /// carrying no Evidence Record at all returns — the case the appendix describes as the record having "been
    /// provided externally", where "the archive timestamped data object has to be generated over the complete
    /// CMS object within the existing coding".
    /// </para>
    /// </remarks>
    public static CmsSignedData BuildArchivedDataObject(
        CmsSignedData signedData,
        int signerIndex,
        IReadOnlyList<EvidenceRecordCmsPlacement> retainedEvidenceRecords,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(retainedEvidenceRecords);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        IReadOnlyList<EvidenceRecordCmsPlacement> placements = LocateEvidenceRecords(signedData, signerIndex);
        var removed = new List<CmsUnsignedAttributeValueLocation>(placements.Count);
        for(int i = 0; i < placements.Count; ++i)
        {
            if(!IsRetained(retainedEvidenceRecords, placements[i].Location))
            {
                removed.Add(placements[i].Location);
            }
        }

        if(removed.Count + retainedEvidenceRecords.Count != placements.Count)
        {
            throw new CryptographicException(
                "A retained Evidence Record is not one the CMS SignerInfo carries, so the view being reconstructed is not one the object ever had (RFC 4998 Appendix A).");
        }

        return CmsSignedDataReduction.RemoveUnsignedAttributeValues(signedData, signerIndex, removed, pool);

        static bool IsRetained(IReadOnlyList<EvidenceRecordCmsPlacement> retained, CmsUnsignedAttributeValueLocation location)
        {
            for(int i = 0; i < retained.Count; ++i)
            {
                if(retained[i].Location.AttributeIndex == location.AttributeIndex && retained[i].Location.ValueIndex == location.ValueIndex)
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Verifies every Evidence Record a CMS object carries against the reconstructed views of that object, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">RFC 4998 Appendix A</see>.
    /// </summary>
    /// <param name="context">The object, the signer to look at, and the detached content when there is one.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion, which the caller disposes in every case.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// Nothing an attacker-supplied object can state escapes this call as an exception: a structure that cannot
    /// be walked, an attribute value that is not an <c>EvidenceRecord</c>, and a record that proves nothing all
    /// become statuses of the returned conclusion.
    /// </para>
    /// <para>
    /// <strong>The chronological order is discovered, level by level.</strong> The view holding no Evidence
    /// Record is reconstructed first and every record is tried against it; those that prove it are the earliest
    /// ones. The view holding exactly those is reconstructed next and the records still unplaced are tried
    /// against that, and so on until a level places nothing or every record is placed. This is what Appendix A
    /// prescribes — "During verification of the first (in chronological order) EvidenceRecord, all EvidenceRecord
    /// have to be removed ... During verification of the nth one EvidenceRecord, the first n-1 attributes should
    /// remain" — read as a statement about a chronology rather than about the encoding, because a conformant DER
    /// producer sorts <c>unsignedAttrs</c> by its members' encodings and third-party objects exist whose two
    /// records come out in exactly the reverse of the order they were created in.
    /// </para>
    /// <para>
    /// <strong>Discovering concedes nothing.</strong> Each view is an exact reconstruction of a state the object
    /// genuinely had, so a record that proves one has proved that state existed at the instant its time-stamps
    /// assert, whichever level it was reached at. Several records may prove the same view, which the appendix
    /// does not describe but third-party objects carry, and a verifier that insisted on a strict chain would
    /// refuse those. The discovered positions are then checked against each other for the appendix's own
    /// consistency requirement — a record proving a view that holds more Evidence Records cannot assert an
    /// earlier instant than one proving a view that holds fewer.
    /// </para>
    /// <para>
    /// <strong>A value that is not an Evidence Record is never retained.</strong> It cannot be a member of a
    /// chronology it cannot be read into, so no view keeps it, and the whole verification reports
    /// <see cref="EvidenceRecordCmsVerificationStatus.EvidenceRecordMalformed"/> rather than a conclusion drawn
    /// from views that leave attacker-supplied octets out.
    /// </para>
    /// </remarks>
    public static async ValueTask<EvidenceRecordCmsVerification> VerifyEmbeddedAsync(
        EvidenceRecordCmsVerificationContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        IReadOnlyList<EvidenceRecordCmsPlacement> placements;
        try
        {
            placements = LocateEvidenceRecords(context.SignedData, context.SignerIndex);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            return new EvidenceRecordCmsVerification(EvidenceRecordCmsVerificationStatus.SignedDataMalformed, []);
        }

        if(placements.Count == 0)
        {
            return new EvidenceRecordCmsVerification(EvidenceRecordCmsVerificationStatus.NoEvidenceRecord, []);
        }

        if(placements.Count > MaximumEvidenceRecords)
        {
            return new EvidenceRecordCmsVerification(EvidenceRecordCmsVerificationStatus.TooManyEvidenceRecords, []);
        }

        var records = new List<EvidenceRecord?>(placements.Count);
        try
        {
            for(int i = 0; i < placements.Count; ++i)
            {
                records.Add(ReadRecord(context, placements[i], pool));
            }

            return await DiscoverChronologyAsync(context, placements, records, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            return new EvidenceRecordCmsVerification(EvidenceRecordCmsVerificationStatus.SignedDataMalformed, []);
        }
        finally
        {
            for(int i = 0; i < records.Count; ++i)
            {
                records[i]?.Dispose();
            }
        }

        static EvidenceRecord? ReadRecord(EvidenceRecordCmsVerificationContext context, EvidenceRecordCmsPlacement placement, BaseMemoryPool pool)
        {
            ReadOnlyMemory<byte> encoded = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(
                context.SignedData, context.SignerIndex, placement.Location.AttributeIndex, placement.Location.ValueIndex);

            try
            {
                return EvidenceRecord.Read(encoded.Span, pool);
            }
            catch(Exception exception) when(exception is AsnContentException or CryptographicException)
            {
                //An attribute value that is not an Evidence Record is a conclusion about the object, not a fault
                //of the call: the walk that found it is the same one a conformant reader performs.
                return null;
            }
        }
    }


    /// <summary>
    /// Discovers which reconstructed view each embedded Evidence Record proves, by reconstructing the views in
    /// chronological order — the one holding no record first, then the one holding exactly the records already
    /// placed — and trying every record still unplaced against each.
    /// </summary>
    /// <param name="context">The verification context, for the detached content the second selection method groups.</param>
    /// <param name="placements">Where the records sit, in the order their attribute values are encoded.</param>
    /// <param name="records">The decoded records, positionally matching <paramref name="placements"/>, with <see langword="null"/> where the value was not an Evidence Record. Owned by the caller.</param>
    /// <param name="pool">The memory pool every buffer rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion, which the caller disposes.</returns>
    /// <exception cref="CryptographicException">When a view cannot be reconstructed from the object.</exception>
    /// <exception cref="AsnContentException">When the object is malformed, truncated, or exceeds the bounds the walk stays within.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Each reconstructed view is owned by the using statement of the level that built it and is disposed when that level ends; the rule's data flow does not follow ownership across the awaited verifications inside the loop.")]
    private static async ValueTask<EvidenceRecordCmsVerification> DiscoverChronologyAsync(
        EvidenceRecordCmsVerificationContext context,
        IReadOnlyList<EvidenceRecordCmsPlacement> placements,
        List<EvidenceRecord?> records,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        int[] positions = new int[placements.Count];
        int[] provedViewCounts = new int[placements.Count];
        var reported = new EvidenceRecordVerification?[placements.Count];
        Array.Fill(positions, -1);
        Array.Fill(provedViewCounts, -1);

        var retained = new List<EvidenceRecordCmsPlacement>(placements.Count);
        try
        {
            for(int position = 0; position < placements.Count && CountUnplaced(records, positions) != 0; ++position)
            {
                var placedHere = new List<EvidenceRecordCmsPlacement>();
                int viewRecordCount = retained.Count;
                using(CmsSignedData view = BuildArchivedDataObject(context.SignedData, context.SignerIndex, retained, pool))
                {
                    for(int i = 0; i < placements.Count; ++i)
                    {
                        if(records[i] is not EvidenceRecord record || positions[i] >= 0)
                        {
                            continue;
                        }

                        EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
                            new EvidenceRecordVerificationContext
                            {
                                EvidenceRecord = record,
                                DataObject = view.AsReadOnlyMemory(),
                                DataObjectGroup = StateDataObjectGroup(context, placements[i], view)
                            },
                            pool,
                            cancellationToken).ConfigureAwait(false);

                        if(verification.Status == EvidenceRecordVerificationStatus.Verified)
                        {
                            reported[i]?.Dispose();
                            reported[i] = verification;
                            positions[i] = position;
                            provedViewCounts[i] = viewRecordCount;
                            placedHere.Add(placements[i]);

                            continue;
                        }

                        if(position == 0)
                        {
                            //The view the appendix names first — "all EvidenceRecord have to be removed" — is the
                            //one whose reason is reported when a record proves none of them.
                            reported[i] = verification;

                            continue;
                        }

                        verification.Dispose();
                    }
                }

                if(placedHere.Count == 0)
                {
                    break;
                }

                retained.AddRange(placedHere);
            }

            var conclusions = new List<EvidenceRecordCmsRecordVerification>(placements.Count);
            for(int i = 0; i < placements.Count; ++i)
            {
                conclusions.Add(new EvidenceRecordCmsRecordVerification(placements[i], StateRecordStatus(records[i], positions[i]), positions[i], provedViewCounts[i], reported[i]));
                reported[i] = null;
            }

            return new EvidenceRecordCmsVerification(StateOverallStatus(conclusions), conclusions);
        }
        finally
        {
            for(int i = 0; i < reported.Length; ++i)
            {
                reported[i]?.Dispose();
            }
        }

        static int CountUnplaced(List<EvidenceRecord?> records, int[] positions)
        {
            int unplaced = 0;
            for(int i = 0; i < positions.Length; ++i)
            {
                if(records[i] is not null && positions[i] < 0)
                {
                    ++unplaced;
                }
            }

            return unplaced;
        }

        static EvidenceRecordCmsVerificationStatus StateRecordStatus(EvidenceRecord? record, int position) => (record, position) switch
        {
            (null, _) => EvidenceRecordCmsVerificationStatus.EvidenceRecordMalformed,
            (_, < 0) => EvidenceRecordCmsVerificationStatus.EvidenceRecordNotVerified,
            _ => EvidenceRecordCmsVerificationStatus.Verified
        };
    }


    /// <summary>
    /// The data object group one record is checked for exclusively: the reconstructed CMS object and the
    /// detached content it signs, for a record carried by the identifier that names Appendix A's second
    /// selection method and a caller that stated the content; otherwise an empty list, which skips the check.
    /// </summary>
    /// <param name="context">The verification context.</param>
    /// <param name="placement">The record's placement, whose selection method decides whether a group applies.</param>
    /// <param name="view">The reconstructed view being verified against.</param>
    /// <returns>The group, or an empty list.</returns>
    private static IReadOnlyList<ReadOnlyMemory<byte>> StateDataObjectGroup(
        EvidenceRecordCmsVerificationContext context,
        EvidenceRecordCmsPlacement placement,
        CmsSignedData view)
    {
        if(placement.SelectionMethod != EvidenceRecordCmsSelectionMethod.CmsObjectAndContent || context.DetachedContent is not ReadOnlyMemory<byte> content)
        {
            return [];
        }

        return [view.AsReadOnlyMemory(), content];
    }


    /// <summary>
    /// Folds the per-record conclusions into one: every record has to have proved a view, and Appendix A's
    /// consistency requirement has to hold across the positions they proved.
    /// </summary>
    /// <param name="conclusions">The per-record conclusions.</param>
    /// <returns>The overall status.</returns>
    private static EvidenceRecordCmsVerificationStatus StateOverallStatus(List<EvidenceRecordCmsRecordVerification> conclusions)
    {
        for(int i = 0; i < conclusions.Count; ++i)
        {
            if(conclusions[i].Status != EvidenceRecordCmsVerificationStatus.Verified)
            {
                return conclusions[i].Status;
            }
        }

        for(int i = 0; i < conclusions.Count; ++i)
        {
            for(int j = 0; j < conclusions.Count; ++j)
            {
                if(conclusions[i].ProvedViewEvidenceRecordCount >= conclusions[j].ProvedViewEvidenceRecordCount)
                {
                    continue;
                }

                //The record proving the view with fewer Evidence Records in it existed first, so the one proving
                //the wider view cannot assert an earlier instant than it does.
                if(conclusions[i].Verification?.InitialArchiveTime is DateTimeOffset earlier
                    && conclusions[j].Verification?.InitialArchiveTime is DateTimeOffset later
                    && later < earlier)
                {
                    return EvidenceRecordCmsVerificationStatus.ChronologyBroken;
                }
            }
        }

        return EvidenceRecordCmsVerificationStatus.Verified;
    }
}
