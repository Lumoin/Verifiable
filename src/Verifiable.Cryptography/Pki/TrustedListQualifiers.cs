using System.Collections.Generic;
using System.Diagnostics;

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
[DebuggerDisplay("KeyUsageBitAssertion: {Bit}={Asserted}")]
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
public abstract class QualifierCondition
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected QualifierCondition()
    {
    }
}


/// <summary>
/// A composite condition: <see cref="Children"/> combined by <see cref="Assert"/>. The recursive case of the
/// criteria tree — a child may itself be a <see cref="CriteriaListCondition"/>.
/// </summary>
[DebuggerDisplay("CriteriaListCondition: {Assert}, {Children.Count} children")]
public sealed class CriteriaListCondition : QualifierCondition
{
    /// <summary>Initializes a new <see cref="CriteriaListCondition"/>.</summary>
    /// <param name="assert">How <see cref="Children"/> combine.</param>
    /// <param name="description">The optional human-readable <c>Description</c> element, when the document supplied one.</param>
    /// <param name="children">The nested conditions <see cref="Assert"/> combines.</param>
    public CriteriaListCondition(QualifierAssertion assert, string? description, IReadOnlyList<QualifierCondition> children)
    {
        Assert = assert;
        Description = description;
        Children = children;
    }

    /// <summary>How <see cref="Children"/> combine.</summary>
    public QualifierAssertion Assert { get; }

    /// <summary>The optional human-readable <c>Description</c> element, when the document supplied one.</summary>
    public string? Description { get; }

    /// <summary>The nested conditions <see cref="Assert"/> combines.</summary>
    public IReadOnlyList<QualifierCondition> Children { get; }
}


/// <summary>
/// A leaf condition matching a certificate's Key Usage extension against one or more asserted bits, per
/// clause 5.5.9.2.2.1.
/// </summary>
[DebuggerDisplay("KeyUsageCondition: {Bits.Count} bits")]
public sealed class KeyUsageCondition : QualifierCondition
{
    /// <summary>Initializes a new <see cref="KeyUsageCondition"/>.</summary>
    /// <param name="bits">The asserted bits; all must match for this leaf to hold (the element itself has no <c>assert</c> attribute — it is always a conjunction of its own bits).</param>
    public KeyUsageCondition(IReadOnlyList<KeyUsageBitAssertion> bits)
    {
        Bits = bits;
    }

    /// <summary>The asserted bits; all must match for this leaf to hold (the element itself has no <c>assert</c> attribute — it is always a conjunction of its own bits).</summary>
    public IReadOnlyList<KeyUsageBitAssertion> Bits { get; }
}


/// <summary>
/// A leaf condition matching a certificate's policy OIDs against a <c>PolicySet</c>, per clause 5.5.9.2.2.2.
/// </summary>
[DebuggerDisplay("PolicySetCondition: {PolicyOids.Count} policies")]
public sealed class PolicySetCondition : QualifierCondition
{
    /// <summary>Initializes a new <see cref="PolicySetCondition"/>.</summary>
    /// <param name="policyOids">The dotted-decimal certificate policy object identifiers the set names.</param>
    public PolicySetCondition(IReadOnlyList<string> policyOids)
    {
        PolicyOids = policyOids;
    }

    /// <summary>The dotted-decimal certificate policy object identifiers the set names.</summary>
    public IReadOnlyList<string> PolicyOids { get; }
}


/// <summary>
/// A leaf condition matching a certificate's Extended Key Usage extension against one or more key purpose
/// OIDs, carried in the schema's <c>otherCriteriaList</c> extension point
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 additional-types schema, <c>ExtendedKeyUsage</c></see>).
/// </summary>
[DebuggerDisplay("ExtendedKeyUsageCondition: {KeyPurposeOids.Count} purposes")]
public sealed class ExtendedKeyUsageCondition : QualifierCondition
{
    /// <summary>Initializes a new <see cref="ExtendedKeyUsageCondition"/>.</summary>
    /// <param name="keyPurposeOids">The dotted-decimal Extended Key Usage OIDs.</param>
    public ExtendedKeyUsageCondition(IReadOnlyList<string> keyPurposeOids)
    {
        KeyPurposeOids = keyPurposeOids;
    }

    /// <summary>The dotted-decimal Extended Key Usage OIDs.</summary>
    public IReadOnlyList<string> KeyPurposeOids { get; }
}


/// <summary>
/// A leaf condition matching an attribute present in a certificate's Subject distinguished name, carried in
/// the schema's <c>otherCriteriaList</c> extension point
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 additional-types schema, <c>CertSubjectDNAttribute</c></see>).
/// </summary>
[DebuggerDisplay("CertSubjectDistinguishedNameAttributeCondition: {AttributeOids.Count} attributes")]
public sealed class CertSubjectDistinguishedNameAttributeCondition : QualifierCondition
{
    /// <summary>Initializes a new <see cref="CertSubjectDistinguishedNameAttributeCondition"/>.</summary>
    /// <param name="attributeOids">The dotted-decimal Subject RDN attribute type OIDs the certificate must (or, under <see cref="QualifierAssertion.None"/>, must not) carry.</param>
    public CertSubjectDistinguishedNameAttributeCondition(IReadOnlyList<string> attributeOids)
    {
        AttributeOids = attributeOids;
    }

    /// <summary>The dotted-decimal Subject RDN attribute type OIDs the certificate must (or, under <see cref="QualifierAssertion.None"/>, must not) carry.</summary>
    public IReadOnlyList<string> AttributeOids { get; }
}


/// <summary>
/// A leaf condition carried in the schema's <c>otherCriteriaList</c> extension point that this model does
/// not otherwise recognise. Nothing about the condition's semantics is modelled; only that one was present,
/// so a caller evaluating the tree can see it and fail closed (a criteria list with an unrecognised leaf
/// cannot be soundly evaluated as passing) rather than the leaf silently vanishing.
/// </summary>
/// <remarks>
/// The leaf holds one fact — which element name was seen — and equality is that name, compared ordinally
/// because XML local names are case-sensitive. Two unrecognised leaves of the same element name are one and
/// the same unmodelled condition.
/// </remarks>
[DebuggerDisplay("OtherQualifierCondition: {LocalName}")]
public sealed class OtherQualifierCondition : QualifierCondition, IEquatable<OtherQualifierCondition>
{
    /// <summary>Initializes a new <see cref="OtherQualifierCondition"/>.</summary>
    /// <param name="localName">The local (unqualified) element name the test-side XML binding found.</param>
    public OtherQualifierCondition(string localName)
    {
        LocalName = localName;
    }

    /// <summary>The local (unqualified) element name the test-side XML binding found.</summary>
    public string LocalName { get; }

    /// <inheritdoc/>
    public bool Equals(OtherQualifierCondition? other)
    {
        return other is not null && string.Equals(LocalName, other.LocalName, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as OtherQualifierCondition);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(LocalName);
    }

    /// <summary>Reports whether two leaves name the same unrecognised element.</summary>
    public static bool operator ==(OtherQualifierCondition? left, OtherQualifierCondition? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two leaves name a different unrecognised element.</summary>
    public static bool operator !=(OtherQualifierCondition? left, OtherQualifierCondition? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// One qualification element of a service's <c>Qualifications</c> extension: the <see cref="Qualifiers"/>
/// a matching certificate is asserted to carry, gated by <see cref="Condition"/>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.9.2.1</see>.
/// </summary>
[DebuggerDisplay("QualificationElement: {Qualifiers.Count} qualifiers, critical={IsCritical}")]
public sealed class QualificationElement
{
    /// <summary>The qualifiers asserted when <see cref="Condition"/> holds for a certificate.</summary>
    public required IReadOnlyList<ServiceQualifier> Qualifiers { get; init; }

    /// <summary>The root of the criteria tree gating <see cref="Qualifiers"/>.</summary>
    public required CriteriaListCondition Condition { get; init; }

    /// <summary>
    /// The <c>Critical</c> attribute of the <c>Qualifications</c> extension this element was carried in, per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
    /// ETSI TS 119 612 V2.4.1 clause 5.5.9</see>'s <c>ExtensionType</c>. ETSI TS 119 615 V1.4.1
    /// PRO-4.5.4-04 (b) branches on it: an unrecognised qualifier in a critical extension fails the QSCD
    /// determination outright, while the same qualifier in a non-critical extension only warns.
    /// </summary>
    public required bool IsCritical { get; init; }
}
