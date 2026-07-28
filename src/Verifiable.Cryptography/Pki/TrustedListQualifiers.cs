using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// How the children of a <see cref="CriteriaListCondition"/> combine, per the <c>assert</c> attribute of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.9.2.2</see>'s <c>CriteriaList</c> — a schema-enumerated closed set of
/// exactly three values, unlike the open-ended URI vocabularies elsewhere in this model.
/// </summary>
public enum QualifierAssertion
{
    /// <summary>Every child condition must hold (logical AND).</summary>
    All = 0,

    /// <summary>At least one child condition must hold (logical OR).</summary>
    AtLeastOne = 1,

    /// <summary>No child condition may hold (logical NOR).</summary>
    None = 2
}


/// <summary>
/// Maps the <c>assert</c> attribute's wire values to and from <see cref="QualifierAssertion"/>.
/// </summary>
public static class QualifierAssertionMapping
{
    /// <summary>Maps the wire value of the <c>assert</c> attribute to a <see cref="QualifierAssertion"/>.</summary>
    /// <param name="assert">The attribute's raw value (<c>"all"</c>, <c>"atLeastOne"</c>, or <c>"none"</c>).</param>
    /// <returns>The matching assertion, or <see langword="null"/> when the value is none of the three.</returns>
    public static QualifierAssertion? FromWireValue(string assert) => assert switch
    {
        "all" => QualifierAssertion.All,
        "atLeastOne" => QualifierAssertion.AtLeastOne,
        "none" => QualifierAssertion.None,
        _ => null
    };


    /// <summary>Maps a <see cref="QualifierAssertion"/> to its wire value.</summary>
    /// <param name="assertion">The assertion to map.</param>
    /// <returns>The <c>assert</c> attribute wire value.</returns>
    public static string ToWireValue(QualifierAssertion assertion) => assertion switch
    {
        QualifierAssertion.All => "all",
        QualifierAssertion.AtLeastOne => "atLeastOne",
        QualifierAssertion.None => "none",
        _ => "all"
    };
}


/// <summary>
/// The Key Usage bit names a <see cref="KeyUsageCondition"/> asserts against, per RFC 5280 §4.2.1.3 as
/// restricted by
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.9.2.2.1</see>'s <c>KeyUsageBit</c> schema enumeration — a closed set of
/// the nine RFC 5280 Key Usage bits.
/// </summary>
public enum KeyUsageBitName
{
    /// <summary>The <c>digitalSignature</c> bit.</summary>
    DigitalSignature = 0,

    /// <summary>The <c>nonRepudiation</c> (contentCommitment) bit.</summary>
    NonRepudiation = 1,

    /// <summary>The <c>keyEncipherment</c> bit.</summary>
    KeyEncipherment = 2,

    /// <summary>The <c>dataEncipherment</c> bit.</summary>
    DataEncipherment = 3,

    /// <summary>The <c>keyAgreement</c> bit.</summary>
    KeyAgreement = 4,

    /// <summary>The <c>keyCertSign</c> bit.</summary>
    KeyCertSign = 5,

    /// <summary>The <c>crlSign</c> bit.</summary>
    CrlSign = 6,

    /// <summary>The <c>encipherOnly</c> bit.</summary>
    EncipherOnly = 7,

    /// <summary>The <c>decipherOnly</c> bit.</summary>
    DecipherOnly = 8
}


/// <summary>
/// One asserted Key Usage bit within a <see cref="KeyUsageCondition"/> — the bit and whether the condition
/// requires it set or unset.
/// </summary>
/// <param name="Bit">The Key Usage bit named.</param>
/// <param name="Asserted">
/// The value the certificate's bit must equal for this assertion to hold (schema: the element's boolean
/// content).
/// </param>
public sealed record KeyUsageBitAssertion(KeyUsageBitName Bit, bool Asserted);


/// <summary>
/// A qualifier condition — one node of the criteria tree that decides whether a
/// <see cref="QualificationElement"/>'s <see cref="ServiceQualifier"/> set applies to a certificate, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.9.2.2</see>. This is a DU-ready closed sum: the tree is walked
/// iteratively (never recursively) by a caller evaluating a certificate against it, both because the
/// document is attacker-reachable and because the schema itself permits nesting <see cref="CriteriaListCondition"/>
/// to unbounded depth.
/// </summary>
public abstract record QualifierCondition
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected QualifierCondition()
    {
    }
}


/// <summary>
/// A composite condition: <see cref="Children"/> combined by <see cref="Assert"/>. The recursive case of the
/// criteria tree — a child may itself be a <see cref="CriteriaListCondition"/>.
/// </summary>
/// <param name="Assert">How <see cref="Children"/> combine.</param>
/// <param name="Description">The optional human-readable <c>Description</c> element, when the document supplied one.</param>
/// <param name="Children">The nested conditions <see cref="Assert"/> combines.</param>
public sealed record CriteriaListCondition(QualifierAssertion Assert, string? Description, IReadOnlyList<QualifierCondition> Children) : QualifierCondition;


/// <summary>
/// A leaf condition matching a certificate's Key Usage extension against one or more asserted bits, per
/// clause 5.5.9.2.2.1.
/// </summary>
/// <param name="Bits">The asserted bits; all must match for this leaf to hold (the element itself has no <c>assert</c> attribute — it is always a conjunction of its own bits).</param>
public sealed record KeyUsageCondition(IReadOnlyList<KeyUsageBitAssertion> Bits) : QualifierCondition;


/// <summary>
/// A leaf condition matching a certificate's policy OIDs against a <c>PolicySet</c>, per clause 5.5.9.2.2.2.
/// </summary>
/// <param name="PolicyOids">The dotted-decimal certificate policy object identifiers the set names.</param>
public sealed record PolicySetCondition(IReadOnlyList<string> PolicyOids) : QualifierCondition;


/// <summary>
/// A leaf condition matching a certificate's Extended Key Usage extension against one or more key purpose
/// OIDs, carried in the schema's <c>otherCriteriaList</c> extension point
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 additional-types schema, <c>ExtendedKeyUsage</c></see>).
/// </summary>
/// <param name="KeyPurposeOids">The dotted-decimal Extended Key Usage OIDs.</param>
public sealed record ExtendedKeyUsageCondition(IReadOnlyList<string> KeyPurposeOids) : QualifierCondition;


/// <summary>
/// A leaf condition matching an attribute present in a certificate's Subject distinguished name, carried in
/// the schema's <c>otherCriteriaList</c> extension point
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 additional-types schema, <c>CertSubjectDNAttribute</c></see>).
/// </summary>
/// <param name="AttributeOids">The dotted-decimal Subject RDN attribute type OIDs the certificate must (or, under <see cref="QualifierAssertion.None"/>, must not) carry.</param>
public sealed record CertSubjectDistinguishedNameAttributeCondition(IReadOnlyList<string> AttributeOids) : QualifierCondition;


/// <summary>
/// A leaf condition carried in the schema's <c>otherCriteriaList</c> extension point that this model does
/// not otherwise recognise. Nothing about the condition's semantics is modelled; only that one was present,
/// so a caller evaluating the tree can see it and fail closed (a criteria list with an unrecognised leaf
/// cannot be soundly evaluated as passing) rather than the leaf silently vanishing.
/// </summary>
/// <param name="LocalName">The local (unqualified) element name the test-side XML binding found.</param>
public sealed record OtherQualifierCondition(string LocalName) : QualifierCondition;


/// <summary>
/// One qualification element of a service's <c>Qualifications</c> extension: the <see cref="Qualifiers"/>
/// a matching certificate is asserted to carry, gated by <see cref="Condition"/>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.9.2.1</see>.
/// </summary>
public sealed record QualificationElement
{
    /// <summary>The qualifiers asserted when <see cref="Condition"/> holds for a certificate.</summary>
    public required IReadOnlyList<ServiceQualifier> Qualifiers { get; init; }

    /// <summary>The root of the criteria tree gating <see cref="Qualifiers"/>.</summary>
    public required CriteriaListCondition Condition { get; init; }
}
