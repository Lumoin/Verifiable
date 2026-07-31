using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One <c>CryptographicInformation</c> element of a time-stamp (clause 3.1.3 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.1.3">IETF RFC 6283</see>): material a verifier
/// needs to establish the formal validity of the time-stamp token beside it.
/// </summary>
/// <remarks>
/// The content is carried verbatim, never interpreted here. Clause 3.1.3 states the four registered
/// <see cref="InformationType"/> values and what each one's base64 content decodes to, and this library reads a
/// certificate or a revocation object through the surfaces that already exist for them; nothing about an
/// Evidence Record's own integrity rests on this element, because clause 2.2 scopes it to time-stamp validation
/// material alone and clause 9.4 states that material added here after the fact "must rely on its own
/// authenticity and integrity protection mechanism".
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordCryptographicInformation: {InformationType}, order {Order}, {Content.Length} octets")]
public sealed record XmlEvidenceRecordCryptographicInformation: IDisposable
{
    /// <summary>The <c>Order</c> attribute clause 3.1.3 makes required on every one of these elements.</summary>
    public required int Order { get; init; }

    /// <summary>
    /// The <c>Type</c> attribute clause 3.1.3 makes required, one of the four values
    /// <see cref="XmlEvidenceRecordWellKnown.IsRegisteredCryptographicInformationType"/> recognises.
    /// </summary>
    public required string InformationType { get; init; }

    /// <summary>The element's decoded content, tagged <see cref="XmlEvidenceRecordTags.CryptographicInformation"/>. Owned by this instance.</summary>
    public required PooledMemory Content { get; init; }


    /// <summary>Releases <see cref="Content"/>.</summary>
    public void Dispose() => Content.Dispose();
}


/// <summary>
/// One <c>Attribute</c> element of an Archive Time-Stamp, or one <c>SupportingInformation</c> element of the
/// record (clause 2.1 of <see href="https://www.rfc-editor.org/rfc/rfc6283#section-2.1">IETF RFC 6283</see>).
/// </summary>
/// <remarks>
/// Clause 8's schema types both as lax-processed any content with an optional or required <c>Type</c> attribute
/// and states nothing at all about what the content may be, so no model could describe it: the element's own
/// serialised octets are carried and the caller decides what, if anything, they mean. The two are one type
/// because they differ only in which of <c>Order</c> and <c>Type</c> the schema requires, and the distinction
/// between them is where the element sits, which is what the property carrying it says.
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordInformation: order {Order}, type {InformationType}, {Content.Length} octets")]
public sealed record XmlEvidenceRecordInformation: IDisposable
{
    /// <summary>
    /// The <c>Order</c> attribute, required on an <c>Attribute</c> element and absent from a
    /// <c>SupportingInformation</c> element, which clause 8's schema gives no <c>Order</c> at all.
    /// </summary>
    public int? Order { get; init; }

    /// <summary>The <c>Type</c> attribute: optional on an <c>Attribute</c> element, required on a <c>SupportingInformation</c> element.</summary>
    public string? InformationType { get; init; }

    /// <summary>The element's serialised octets, tagged <see cref="XmlEvidenceRecordTags.OpaqueInformation"/>. Owned by this instance.</summary>
    public required PooledMemory Content { get; init; }


    /// <summary>Releases <see cref="Content"/>.</summary>
    public void Dispose() => Content.Dispose();
}


/// <summary>
/// The <c>TimeStamp</c> element of an Archive Time-Stamp (clause 3.1.2 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.1.2">IETF RFC 6283</see>): the token itself
/// together with whatever material clause 3.1.3 places beside it.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The whole element, not the token, is what a renewal hashes.</strong> Clause 4.2.1 step 2 takes the
/// "binary representation of the <c>TimeStamp</c> element of the last <c>ArchiveTimeStamp</c> element
/// <em>including added cryptographic information</em>", so a verifier walking a Time-Stamp Renewal needs the
/// canonical octets of this element — which is why the canonicalization seam names an element to canonicalize
/// rather than being handed one to hash. This is the XML analogue of the whole-<c>timeStamp</c>-element reading
/// the ASN.1 form of the mechanism was empirically confirmed to take.
/// </para>
/// <para>
/// <strong>Only the RFC 3161 format is read.</strong> Clause 3.1.2 registers two;
/// <see cref="XmlEvidenceRecordWellKnown.XmlEntrustTimeStampTokenType"/> names the other so a document using it
/// is refused for its format rather than for being unreadable, and <see cref="Rfc3161Token"/> is then
/// <see langword="null"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordTimeStamp: {TokenType}, {CryptographicInformation.Count} cryptographic information elements")]
public sealed record XmlEvidenceRecordTimeStamp: IDisposable
{
    /// <summary>The <c>Type</c> attribute of the <c>TimeStampToken</c> element, which clause 3.1.2 makes required.</summary>
    public required string TokenType { get; init; }

    /// <summary>
    /// The DER <c>TimeStampToken</c> of IETF RFC 3161 the element's base64 content decodes to, tagged
    /// <see cref="PkiCertificateTags.TimestampToken"/>; <see langword="null"/> when
    /// <see cref="TokenType"/> names a format this library does not read. Owned by this instance.
    /// </summary>
    public PkiCertificateMemory? Rfc3161Token { get; init; }

    /// <summary>The <c>CryptographicInformation</c> elements, in <c>Order</c>. Owned by this instance.</summary>
    public IReadOnlyList<XmlEvidenceRecordCryptographicInformation> CryptographicInformation { get; init; } = [];


    /// <summary>Releases the token and every cryptographic information element.</summary>
    public void Dispose()
    {
        Rfc3161Token?.Dispose();
        for(int i = 0; i < CryptographicInformation.Count; ++i)
        {
            CryptographicInformation[i].Dispose();
        }
    }
}


/// <summary>
/// One <c>Sequence</c> element of a hash tree (clause 3.1.1 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.1.1">IETF RFC 6283</see>): one list of hash
/// values at one level of the reduced tree.
/// </summary>
/// <remarks>
/// The values are held decoded. Clause 3.1.1 requires the base64 text to be decoded "to obtain a binary value
/// (representing the hash value)" before anything is done with it, and clause 3.2.2 requires the order within a
/// sequence to be "binary ascending (by base64 decoded values)" — a rule about the decoded octets that cannot
/// be checked on the encoded text, since base64 does not preserve order across every octet pattern.
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordSequence: order {Order}, {DigestValues.Count} values")]
public sealed record XmlEvidenceRecordSequence: IDisposable
{
    /// <summary>The <c>Order</c> attribute clause 3.1.1's schema makes required, at least 1.</summary>
    public required int Order { get; init; }

    /// <summary>The decoded hash values, in the order the document lists them. Owned by this instance.</summary>
    public required IReadOnlyList<DigestValue> DigestValues { get; init; }


    /// <summary>Releases every hash value.</summary>
    public void Dispose()
    {
        for(int i = 0; i < DigestValues.Count; ++i)
        {
            DigestValues[i].Dispose();
        }
    }
}


/// <summary>
/// The <c>HashTree</c> element of an Archive Time-Stamp (clause 3.1.1 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.1.1">IETF RFC 6283</see>): the reduced hash tree
/// that binds the time-stamped value to the objects the Archive Time-Stamp protects.
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordHashTree: {Sequences.Count} sequences")]
public sealed record XmlEvidenceRecordHashTree: IDisposable
{
    /// <summary>The <c>Sequence</c> elements in ascending <c>Order</c>. Owned by this instance.</summary>
    public required IReadOnlyList<XmlEvidenceRecordSequence> Sequences { get; init; }


    /// <summary>Releases every sequence.</summary>
    public void Dispose()
    {
        for(int i = 0; i < Sequences.Count; ++i)
        {
            Sequences[i].Dispose();
        }
    }
}


/// <summary>
/// One <c>ArchiveTimeStamp</c> element (clause 3.1 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.1">IETF RFC 6283</see>).
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordArchiveTimeStamp: order {Order}, hash tree {HashTree != null}")]
public sealed record XmlEvidenceRecordArchiveTimeStamp: IDisposable
{
    /// <summary>The <c>Order</c> attribute clause 2.1 makes required, at least 1.</summary>
    public required int Order { get; init; }

    /// <summary>
    /// The hash tree, or <see langword="null"/> when the element carries none — which clause 4.2.1 permits for a
    /// Time-Stamp Renewal ("the new ATS MAY not contain a hash tree") and clause 4.3 step 1 then makes the
    /// time-stamped value the digest of the single object directly. Owned by this instance.
    /// </summary>
    public XmlEvidenceRecordHashTree? HashTree { get; init; }

    /// <summary>The <c>TimeStamp</c> element clause 2.1 makes required. Owned by this instance.</summary>
    public required XmlEvidenceRecordTimeStamp TimeStamp { get; init; }

    /// <summary>The <c>Attribute</c> elements, in <c>Order</c>; empty when the element carries no <c>Attributes</c>. Owned by this instance.</summary>
    public IReadOnlyList<XmlEvidenceRecordInformation> Attributes { get; init; } = [];


    /// <summary>Releases the hash tree, the time-stamp and every attribute.</summary>
    public void Dispose()
    {
        HashTree?.Dispose();
        TimeStamp.Dispose();
        for(int i = 0; i < Attributes.Count; ++i)
        {
            Attributes[i].Dispose();
        }
    }
}


/// <summary>
/// One <c>ArchiveTimeStampChain</c> element (clause 4.1 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-4.1">IETF RFC 6283</see>): the run of Archive
/// Time-Stamps produced by Time-Stamp Renewal under one digest algorithm and one canonicalization method.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The chain is where the two algorithm axes live, and they are not alike.</strong> Clause 4.1.1 makes
/// the digest algorithm identical for every hash tree and every time-stamp token of one chain, and requires a
/// NEW chain to be started with an equal or stronger algorithm when it changes — so the chain boundary IS the
/// algorithm change, and a Hash-Tree Renewal is exactly what crossing it means. Clause 4.1.2's canonicalization
/// method has no such rule: "the canonicalization method is unlikely to change over time as it does not impose
/// the same constraints as the digest method", and a succeeding chain's method is used even for the digest of
/// the preceding chains.
/// </para>
/// <para>
/// The digest algorithm is <em>resolved</em> here rather than carried as text, the same stance the ASiC manifest
/// model takes: a chain naming an algorithm this library cannot compute is refused at the parse seam, because a
/// hash tree nothing can recompute proves nothing that could be reported. The identifier as written is kept
/// beside it so a refusal or a report can say what the document actually said.
/// </para>
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordArchiveTimeStampChain: order {Order}, {ArchiveTimeStamps.Count} archive time-stamps")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "An algorithm identifier is compared as written: RFC 6283 clause 4.1.1 and clause 4.1.2 identify an algorithm by the URI string, and System.Uri normalises case, escaping and default ports, which would make two identifiers that name different algorithms compare equal.")]
public sealed record XmlEvidenceRecordArchiveTimeStampChain: IDisposable
{
    /// <summary>The <c>Order</c> attribute clause 4.1 makes required, at least 1.</summary>
    public required int Order { get; init; }

    /// <summary>The <c>DigestMethod</c> element's <c>Algorithm</c> attribute, as the document writes it.</summary>
    public required string DigestMethodUri { get; init; }

    /// <summary>The algorithm <see cref="DigestMethodUri"/> resolves to, which every hash calculation of this chain uses (clause 4.1.1).</summary>
    public required PkiDigestAlgorithm DigestAlgorithm { get; init; }

    /// <summary>The <c>CanonicalizationMethod</c> element's <c>Algorithm</c> attribute, as the document writes it (clause 4.1.2).</summary>
    public required string CanonicalizationMethodUri { get; init; }

    /// <summary>The <c>ArchiveTimeStamp</c> elements in ascending <c>Order</c>. Owned by this instance.</summary>
    public required IReadOnlyList<XmlEvidenceRecordArchiveTimeStamp> ArchiveTimeStamps { get; init; }


    /// <summary>Releases every Archive Time-Stamp.</summary>
    public void Dispose()
    {
        for(int i = 0; i < ArchiveTimeStamps.Count; ++i)
        {
            ArchiveTimeStamps[i].Dispose();
        }
    }
}


/// <summary>
/// The serialisation-agnostic model of an <c>EvidenceRecord</c> document conformant to
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-8">IETF RFC 6283 clause 8</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Nothing here is XML.</strong> The model is what a parse seam produces and what
/// <see cref="XmlEvidenceRecords.VerifyAsync"/> consumes; this project references no XML package and never will,
/// exactly as it does not for the Trusted List profile or for the ASiC manifest. Everything the verification
/// algorithm needs from the document's <em>serialisation</em> — the canonical octets of a <c>TimeStamp</c>
/// element, the canonical octets of a prefix of the <c>ArchiveTimeStampSequence</c> — is reached through
/// <see cref="CanonicalizeXmlEvidenceRecordDelegate"/> instead, with the document's own octets travelling in the
/// context.
/// </para>
/// <para>
/// <strong>This library creates no Evidence Record in this syntax.</strong> The surface is validation-side: a
/// producer that needs to emit one emits the ASN.1 syntax of IETF RFC 4998, which this library does create.
/// Clause 1.1 of RFC 6283 states the two are not transformations of one another, and nothing in
/// EN 319 162-1 obliges a producer to be able to write both.
/// </para>
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecord: version {Version}, {Chains.Count} chains")]
public sealed record XmlEvidenceRecord: IDisposable
{
    /// <summary>
    /// The <c>Version</c> attribute clause 2.1 makes required. Clause 8's schema fixes it to
    /// <see cref="XmlEvidenceRecordWellKnown.Version10"/>, so clause 6's major/minor comparison never applies to
    /// a schema-valid document; the value is read and reported rather than assumed.
    /// </summary>
    public required string Version { get; init; }

    /// <summary>
    /// Whether the document carries an <c>EncryptionInformation</c> element (clause 5). Verification fails
    /// closed when it does: clause 5 requires the data objects to be re-encrypted before the hash values can be
    /// recomputed, and this library cannot do that, so a record whose covered octets it cannot reconstruct is
    /// refused rather than verified against octets that are not what it covers.
    /// </summary>
    public bool HasEncryptionInformation { get; init; }

    /// <summary>The <c>SupportingInformation</c> elements, in document order; empty when the record carries no list. Owned by this instance.</summary>
    public IReadOnlyList<XmlEvidenceRecordInformation> SupportingInformation { get; init; } = [];

    /// <summary>The <c>ArchiveTimeStampChain</c> elements in ascending <c>Order</c> (clause 4.1). Owned by this instance.</summary>
    public required IReadOnlyList<XmlEvidenceRecordArchiveTimeStampChain> Chains { get; init; }


    /// <summary>Releases every chain and every supporting information element.</summary>
    public void Dispose()
    {
        for(int i = 0; i < Chains.Count; ++i)
        {
            Chains[i].Dispose();
        }

        for(int i = 0; i < SupportingInformation.Count; ++i)
        {
            SupportingInformation[i].Dispose();
        }
    }
}
