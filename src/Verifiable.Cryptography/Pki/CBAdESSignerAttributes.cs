using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>srAts</c> (label 264, clause 5.2.1 Table 1) signed header parameter: attributes the
/// signer claims, has certified by an Attribute Authority, or has as third-party-signed assertions, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.5.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.2.5): <c>srAts = { ?1 =&gt; CertifiedAttrs, ?2 =&gt; AttrArrays, ?3 =&gt; AttrArrays }</c>. Table 4
/// (clause 5.2.5) assigns the map key values: <c>certified</c> = <c>1</c>, <c>signedAssertions</c> = <c>2</c>,
/// <c>claimed</c> = <c>3</c>. All three members are independently optional and, when present, the CDDL <c>+</c>
/// occurrence operator on <c>CertifiedAttrs</c>/<c>AttrArrays</c> requires at least one entry (clause 5.2.5: "The
/// <c>certified</c> member shall contain a non-empty array ...", and likewise for <c>signedAssertions</c> and
/// <c>claimed</c>) — constructor-enforced below (CB-5.2.5-05/06/07). Clause 5.2.5 further states "Empty
/// <c>srAts</c> header parameters shall not be generated" — at least one of the three shall be non-empty
/// (CB-5.2.5-14); mirroring <see cref="CBAdESSignerCommitments"/>'s "at least one present" convention, that
/// wider invariant is documented here rather than runtime-enforced by this record — the codec/builder layer
/// that produces <c>srAts</c> is that invariant's enforcement point.
/// </para>
/// <para>
/// <c>srAts</c> is a signer-qualifying header parameter (clause 5.2.5, "The <c>srAts</c> header parameter shall
/// be a signed header parameter that qualifies the signer"). Placing it in the protected headers map at the
/// signer layer of a <c>COSE_Sign</c> structure (clause 5.2.5) is the signature builder's responsibility — this
/// type models only the parameter's own content.
/// </para>
/// <para>
/// <strong>D3 (owner flag, wavecb-contract.md R-6):</strong> <see cref="SignedAssertions"/> and
/// <see cref="Claimed"/> carry <see cref="CBAdESSignerAttributeNotCertifiedItem"/> instances whose
/// qualifying-values collection is modelled OPAQUE — see the D3 remarks on
/// <see cref="CBAdESSignerAttributeNotCertifiedItem"/> for why.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSignerAttributes: {Certified?.Count} certified, {SignedAssertions?.Count} signedAssertions, {Claimed?.Count} claimed")]
public sealed record CBAdESSignerAttributes
{
    /// <summary>The <c>certified</c> member's map key (Table 4, clause 5.2.5).</summary>
    public const int CertifiedKey = 1;

    /// <summary>The <c>signedAssertions</c> member's map key (Table 4, clause 5.2.5).</summary>
    public const int SignedAssertionsKey = 2;

    /// <summary>The <c>claimed</c> member's map key (Table 4, clause 5.2.5).</summary>
    public const int ClaimedKey = 3;

    /// <summary>
    /// Initializes a new <see cref="CBAdESSignerAttributes"/>.
    /// </summary>
    /// <param name="certified">
    /// The certified attributes (<c>certified</c>, map key 1), or <see langword="null"/> to omit it. When
    /// present, must be non-empty (CB-5.2.5-05).
    /// </param>
    /// <param name="signedAssertions">
    /// The third-party-signed assertions (<c>signedAssertions</c>, map key 2), or <see langword="null"/> to
    /// omit it. When present, must be non-empty (CB-5.2.5-06).
    /// </param>
    /// <param name="claimed">
    /// The signer-claimed attributes (<c>claimed</c>, map key 3), or <see langword="null"/> to omit it. When
    /// present, must be non-empty (CB-5.2.5-07).
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="certified"/>, <paramref name="signedAssertions"/>, or
    /// <paramref name="claimed"/> is non-null but empty.
    /// </exception>
    public CBAdESSignerAttributes(
        IReadOnlyList<CBAdESSignerAttributeCertifiedAttribute>? certified = null,
        IReadOnlyList<CBAdESSignerAttributeNotCertifiedItem>? signedAssertions = null,
        IReadOnlyList<CBAdESSignerAttributeNotCertifiedItem>? claimed = null)
    {
        if(certified is not null && certified.Count == 0)
        {
            throw new ArgumentException(
                "When present, srAts's 'certified' member shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.2.5, CB-5.2.5-05).",
                nameof(certified));
        }

        if(signedAssertions is not null && signedAssertions.Count == 0)
        {
            throw new ArgumentException(
                "When present, srAts's 'signedAssertions' member shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.2.5, CB-5.2.5-06).",
                nameof(signedAssertions));
        }

        if(claimed is not null && claimed.Count == 0)
        {
            throw new ArgumentException(
                "When present, srAts's 'claimed' member shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.2.5, CB-5.2.5-07).",
                nameof(claimed));
        }

        Certified = certified;
        SignedAssertions = signedAssertions;
        Claimed = claimed;
    }


    /// <summary>
    /// Gets the certified attributes (<c>certified</c>, map key 1, clause 5.2.5, Table 4): X.509 or
    /// other-syntax attribute certificates issued by an Attribute Authority. <see langword="null"/> when
    /// absent; non-empty when present (constructor-enforced, CB-5.2.5-05).
    /// </summary>
    public IReadOnlyList<CBAdESSignerAttributeCertifiedAttribute>? Certified { get; }

    /// <summary>
    /// Gets the third-party-signed assertions (<c>signedAssertions</c>, map key 2, clause 5.2.5, Table 4).
    /// <see langword="null"/> when absent; non-empty when present (constructor-enforced, CB-5.2.5-06).
    /// </summary>
    public IReadOnlyList<CBAdESSignerAttributeNotCertifiedItem>? SignedAssertions { get; }

    /// <summary>
    /// Gets the signer-claimed attributes (<c>claimed</c>, map key 3, clause 5.2.5, Table 4) — neither
    /// certified by an Attribute Authority nor signed by any assertion-issuing entity, the lowest-trust tier
    /// of the three. <see langword="null"/> when absent; non-empty when present (constructor-enforced,
    /// CB-5.2.5-07).
    /// </summary>
    public IReadOnlyList<CBAdESSignerAttributeNotCertifiedItem>? Claimed { get; }
}


/// <summary>
/// One element of <see cref="CBAdESSignerAttributes.Certified"/> (<c>CertifiedAttr</c>, clause 5.2.5): a
/// two-arm discriminated union over whether the encapsulated attribute certificate is X.509 or another
/// syntax. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// CDDL (clause 5.2.5): <c>CertifiedAttrChoice = ( 1 =&gt; pkiObj // 2 =&gt; pkiObj )</c>, wrapped in a one-member
/// map (<c>CertifiedAttr = { CertifiedAttrChoice }</c>). Table 4 assigns the choice keys:
/// <c>x509AttrCert</c> (in <c>CertifiedAttrChoice</c>) = <c>1</c>, <c>otherAttrCert</c> (in
/// <c>CertifiedAttrChoice</c>) = <c>2</c>.
/// </remarks>
public abstract record CBAdESSignerAttributeCertifiedAttribute
{
    /// <summary>The <c>x509AttrCert</c> choice arm's map key (Table 4, clause 5.2.5, <c>CertifiedAttrChoice</c>).</summary>
    public const int X509AttrCertKey = 1;

    /// <summary>The <c>otherAttrCert</c> choice arm's map key (Table 4, clause 5.2.5, <c>CertifiedAttrChoice</c>).</summary>
    public const int OtherAttrCertKey = 2;

    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESSignerAttributeCertifiedAttribute()
    {
    }
}


/// <summary>
/// The <c>x509AttrCert</c> arm of <c>CertifiedAttrChoice</c> (clause 5.2.5, map key 1, Table 4): a DER-encoded
/// X.509 attribute certificate (ITU-T X.509 [11]) encapsulated in a <see cref="CBAdESPkiObject"/>.
/// </summary>
/// <param name="Certificate">The encapsulated X.509 attribute certificate.</param>
[DebuggerDisplay("CBAdESSignerAttributeX509AttributeCertificate: {Certificate}")]
public sealed record CBAdESSignerAttributeX509AttributeCertificate(CBAdESPkiObject Certificate)
    : CBAdESSignerAttributeCertifiedAttribute;


/// <summary>
/// The <c>otherAttrCert</c> arm of <c>CertifiedAttrChoice</c> (clause 5.2.5, map key 2, Table 4): an attribute
/// certificate in a non-X.509 syntax (definition out of this document's scope) encapsulated in a
/// <see cref="CBAdESPkiObject"/>.
/// </summary>
/// <param name="Certificate">The encapsulated non-X.509 attribute certificate.</param>
[DebuggerDisplay("CBAdESSignerAttributeOtherAttributeCertificate: {Certificate}")]
public sealed record CBAdESSignerAttributeOtherAttributeCertificate(CBAdESPkiObject Certificate)
    : CBAdESSignerAttributeCertifiedAttribute;


/// <summary>
/// One element of <see cref="CBAdESSignerAttributes.SignedAssertions"/> or
/// <see cref="CBAdESSignerAttributes.Claimed"/> (<c>NotCertifiedItem</c>, clause 5.2.5, <c>AttrArrays =
/// [+NotCertifiedItem]</c>).
/// </summary>
/// <remarks>
/// <para>
/// <strong>D3 (owner flag, wavecb-contract.md R-6):</strong> clause 5.2.5's prose names a <c>qVals</c> member
/// ("The <c>qVals</c> member ... shall be a CBOR array of at least one item") and an <c>encoding</c> member
/// ("the values of the signed assertions or claimed attributes, encoded as indicated within the <c>encoding</c>
/// member"), but the CDDL for <c>NotCertifiedItem</c> defines only <c>mediaType: tstr</c> followed by an
/// unparseable <c>*label =&gt; any the not certified item</c> fragment — neither <c>qVals</c> nor
/// <c>encoding</c> is a named CDDL label, and it is not specified which (if any) catch-all label values they
/// correspond to. A byte-exact codec for this type cannot be written from clause 5.2.5 alone (CB-AdES
/// preflight leg 2, "Traps and cross-references": "<c>srAts</c>'s <c>NotCertifiedItem</c> CDDL is internally
/// inconsistent with its own prose ... Flag for owner/spec-liaison follow-up"). Pending ETSI clarification,
/// <see cref="QualifyingValues"/> models the "qualifying-values collection" the prose describes
/// (CB-5.2.5-10/12/13) as an array of OPAQUE encoded items — each carrying its own
/// <see cref="CBAdESSignerAttributeOpaqueQualifyingValue.Kind"/> discriminator rather than a decoded value —
/// so a producer/consumer using this library today emits/reads well-formed bytes without this library
/// silently asserting a decoding it cannot substantiate.
/// </para>
/// <para>
/// <see cref="QualifyingValues"/> should contain at least one entry when present (CB-5.2.5-12); mirroring
/// <see cref="CBAdESSignerCommitments"/>'s convention, that invariant is documented here rather than
/// runtime-enforced — this type owns no disposable resources, so no constructor is otherwise required.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSignerAttributeNotCertifiedItem: {MediaType}, {QualifyingValues.Count} values")]
public sealed record CBAdESSignerAttributeNotCertifiedItem
{
    /// <summary>
    /// Gets the media type identifying the type of the values in <see cref="QualifyingValues"/>
    /// (<c>mediaType</c>, clause 5.2.5), per the IANA media-types registry.
    /// </summary>
    public required string MediaType { get; init; }

    /// <summary>
    /// Gets the qualifying-values collection (the prose's <c>qVals</c>, clause 5.2.5). See the D3 remarks on
    /// this type for why each element is opaque.
    /// </summary>
    public required IReadOnlyList<CBAdESSignerAttributeOpaqueQualifyingValue> QualifyingValues { get; init; }
}


/// <summary>
/// What encoding convention a <see cref="CBAdESSignerAttributeOpaqueQualifyingValue"/>'s
/// <see cref="CBAdESSignerAttributeOpaqueQualifyingValue.EncodedValue"/> is known to follow — see the D3
/// remarks on <see cref="CBAdESSignerAttributeNotCertifiedItem"/>.
/// </summary>
public enum CBAdESSignerAttributeOpaqueQualifyingValueKind
{
    /// <summary>
    /// The encoding convention clause 5.2.5's prose calls the <c>encoding</c> member is unspecified —
    /// <see cref="CBAdESSignerAttributeOpaqueQualifyingValue.EncodedValue"/> is a well-formed CBOR data item
    /// exactly as it appeared in the wire <c>qVals</c> array, uninterpreted. This is the only kind this
    /// library produces or expects until D3 is resolved.
    /// </summary>
    Unspecified = 0
}


/// <summary>
/// One opaque element of <see cref="CBAdESSignerAttributeNotCertifiedItem.QualifyingValues"/> — the raw
/// encoded bytes of one <c>qVals</c> item plus a <see cref="Kind"/> discriminator, per the D3 remarks on
/// <see cref="CBAdESSignerAttributeNotCertifiedItem"/>.
/// </summary>
/// <param name="Kind">What <paramref name="EncodedValue"/>'s encoding convention is known to be.</param>
/// <param name="EncodedValue">
/// The item's raw encoded bytes. <strong>Borrowed</strong> view — the caller (creation path) or the wire-bytes
/// source (parse path) owns the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESSignerAttributeOpaqueQualifyingValue: {Kind}, {EncodedValue.Length} bytes")]
public sealed record CBAdESSignerAttributeOpaqueQualifyingValue(
    CBAdESSignerAttributeOpaqueQualifyingValueKind Kind,
    ReadOnlyMemory<byte> EncodedValue);
