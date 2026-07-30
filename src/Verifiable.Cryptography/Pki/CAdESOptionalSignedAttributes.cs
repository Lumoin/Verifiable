using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The optional, opt-in Table 1 signed-attribute set a caller may add to a CAdES-B-B signature through
/// <see cref="CAdESSignatureCreation.PrepareAsync"/> — the "may be present" / "should be present" rows of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see> clause 6.3 that stage 4 of this wave left out of the mandatory attribute
/// assembly (<c>content-type</c>, <c>message-digest</c>, <c>signing-time</c>, <c>signing-certificate-v2</c>).
/// </summary>
/// <remarks>
/// This is the "options record for the OPTIONAL attribute set only" the wave's contract (R-2) authorizes when
/// <see cref="CAdESSignatureCreation.PrepareAsync"/>'s parameter count becomes untenable: every member here is
/// independently optional, so a caller supplies only the ones it needs, and <see langword="null"/> as a whole
/// (the parameter's own default) means none of them. The mandatory attributes and the digest/signing-time/
/// algorithm parameters stay flat parameters of <see cref="CAdESSignatureCreation.PrepareAsync"/> itself,
/// unaffected by this record.
/// </remarks>
public sealed record CAdESOptionalSignedAttributes
{
    /// <summary>
    /// Gets the <c>commitment-type-indication</c> attribute (clause 5.2.3) to add, or <see langword="null"/>
    /// to add none.
    /// </summary>
    public CAdESCommitmentType? CommitmentType { get; init; }

    /// <summary>
    /// Gets the <c>content-hints</c> attribute (clause 5.2.4.1) to add, or <see langword="null"/> to add none.
    /// One of this and <see cref="MimeType"/> answers the "identifying the signed data type" service of Table 1
    /// requirement t).
    /// </summary>
    public CAdESContentHints? ContentHints { get; init; }

    /// <summary>
    /// Gets the <c>mime-type</c> attribute value (clause 5.2.4.2, a bare <c>UTF8String</c>) to add, or
    /// <see langword="null"/> to add none.
    /// </summary>
    public string? MimeType { get; init; }

    /// <summary>
    /// Gets the <c>signer-location</c> attribute (clause 5.2.5) to add, or <see langword="null"/> to add none.
    /// </summary>
    public CAdESSignerLocation? SignerLocation { get; init; }

    /// <summary>
    /// Gets the <c>content-reference</c> attribute (clause 5.2.11) to add, or <see langword="null"/> to add
    /// none.
    /// </summary>
    public CAdESContentReference? ContentReference { get; init; }

    /// <summary>
    /// Gets the <c>content-identifier</c> attribute value (clause 5.2.12, a bare <c>OCTET STRING</c>) to add,
    /// or <see langword="null"/> to add none.
    /// </summary>
    public ReadOnlyMemory<byte>? ContentIdentifier { get; init; }

    /// <summary>
    /// Gets the <c>signature-policy-identifier</c> attribute (clause 5.2.9.1) to add, or <see langword="null"/>
    /// to add none.
    /// </summary>
    public CAdESSignaturePolicyIdentifier? SignaturePolicyIdentifier { get; init; }

    /// <summary>
    /// Gets the <c>signer-attributes-v2</c> attribute (clause 5.2.6.1) to add, or <see langword="null"/> to add
    /// none. Only the <c>claimedAttributes</c> arm is offered — see <see cref="CAdESSignerAttributesV2"/>.
    /// </summary>
    public CAdESSignerAttributesV2? SignerAttributes { get; init; }

    /// <summary>
    /// Gets the <c>content-time-stamp</c> requests (clause 5.2.8) to acquire and embed, cardinality
    /// <c>&gt;= 0</c>: zero, one, or several tokens, each obtained through
    /// <see cref="TimestampAcquisition.AcquireAsync"/> over the same raw message-digest octets and algorithm
    /// <see cref="CAdESSignatureCreation.PrepareAsync"/> uses for the <c>message-digest</c> attribute — the
    /// RAW-value imprint convention clause 5.2.8 states, never the <c>archive-time-stamp-v3</c> TLV
    /// concatenation of clause 5.5.3. <see langword="null"/> or empty adds none.
    /// </summary>
    public IReadOnlyList<CAdESContentTimestampRequest>? ContentTimestampRequests { get; init; }
}


/// <summary>
/// One <c>commitment-type-indication</c> attribute value (clause 5.2.3):
/// <c>CommitmentTypeIndication ::= SEQUENCE { commitmentTypeId CommitmentTypeIdentifier, commitmentTypeQualifier
/// SEQUENCE SIZE (1..MAX) OF CommitmentTypeQualifier OPTIONAL }</c>.
/// </summary>
public sealed record CAdESCommitmentType
{
    /// <summary>Gets the <c>commitmentTypeId</c> object identifier naming the commitment made.</summary>
    public required string CommitmentTypeId { get; init; }

    /// <summary>
    /// Gets the whole pre-encoded DER <c>SEQUENCE SIZE (1..MAX) OF CommitmentTypeQualifier</c>, or
    /// <see langword="null"/> to omit it. The qualifier's own open-type syntax
    /// (<c>COMMITMENT-QUALIFIER</c>, clause 5.2.3) is not separately modelled this wave; a caller that needs
    /// one encodes it and supplies the whole octets, spliced in verbatim.
    /// </summary>
    public ReadOnlyMemory<byte>? Qualifiers { get; init; }
}


/// <summary>
/// One <c>content-hints</c> attribute value (clause 5.2.4.1, ESS
/// <see href="https://www.rfc-editor.org/rfc/rfc2634#section-2.9">RFC 2634 §2.9</see>):
/// <c>ContentHints ::= SEQUENCE { contentDescription UTF8String OPTIONAL, contentType ContentType }</c>.
/// </summary>
public sealed record CAdESContentHints
{
    /// <summary>Gets the optional <c>contentDescription</c> text.</summary>
    public string? ContentDescription { get; init; }

    /// <summary>Gets the <c>contentType</c> object identifier of the innermost signed content.</summary>
    public required string ContentType { get; init; }
}


/// <summary>
/// One <c>signer-location</c> attribute value (clause 5.2.5):
/// <c>SignerLocation ::= SEQUENCE { countryName [0] DirectoryString OPTIONAL, localityName [1] DirectoryString
/// OPTIONAL, postalAddress [2] PostalAddress OPTIONAL }</c>, at least one field present. Every
/// <c>DirectoryString</c> is written as <c>UTF8String</c> — the CHOICE's other alternatives
/// (<c>TeletexString</c>, <c>PrintableString</c>, <c>UniversalString</c>, <c>BMPString</c>) are not modelled
/// this wave.
/// </summary>
public sealed record CAdESSignerLocation
{
    /// <summary>Gets the <c>countryName</c>, or <see langword="null"/> to omit it.</summary>
    public string? CountryName { get; init; }

    /// <summary>Gets the <c>localityName</c>, or <see langword="null"/> to omit it.</summary>
    public string? LocalityName { get; init; }

    /// <summary>Gets the <c>postalAddress</c> lines (<c>PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString</c>), or <see langword="null"/> to omit it.</summary>
    public IReadOnlyList<string>? PostalAddress { get; init; }
}


/// <summary>
/// One <c>content-reference</c> attribute value (clause 5.2.11, ESS
/// <see href="https://www.rfc-editor.org/rfc/rfc2634#section-2.11">RFC 2634 §2.11</see>):
/// <c>ContentReference ::= SEQUENCE { contentType ContentType, signedContentIdentifier ContentIdentifier,
/// originatorSignatureValue OCTET STRING }</c>.
/// </summary>
public sealed record CAdESContentReference
{
    /// <summary>Gets the <c>contentType</c> of the <c>SignedData</c> being referenced.</summary>
    public required string ContentType { get; init; }

    /// <summary>Gets the referenced <c>SignedData</c>'s own <c>content-identifier</c> attribute value.</summary>
    public required ReadOnlyMemory<byte> SignedContentIdentifier { get; init; }

    /// <summary>Gets the referenced <c>SignedData</c>'s signature value.</summary>
    public required ReadOnlyMemory<byte> OriginatorSignatureValue { get; init; }
}


/// <summary>
/// One <c>signature-policy-identifier</c> attribute value (clause 5.2.9.1), always the <c>signaturePolicyId</c>
/// alternative — the clause states <c>signaturePolicyImplied</c> shall not be used:
/// <c>SignaturePolicyId ::= SEQUENCE { sigPolicyId SigPolicyId, sigPolicyHash SigPolicyHash, sigPolicyQualifiers
/// SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo OPTIONAL }</c>.
/// </summary>
public sealed record CAdESSignaturePolicyIdentifier
{
    /// <summary>Gets the <c>sigPolicyId</c> object identifier of the signature policy.</summary>
    public required string SigPolicyId { get; init; }

    /// <summary>Gets the hash algorithm <see cref="SigPolicyHash"/> was computed under.</summary>
    public required PkiDigestAlgorithm HashAlgorithm { get; init; }

    /// <summary>
    /// Gets the <c>sigPolicyHash.hashValue</c> octets: the digest of the signature policy document, or a
    /// zero-hash value (every octet zero, any length including zero) stating the hash is not known — clause
    /// 5.2.9.1's own backward-compatibility convention, and the value Table 1 requirement k) checks for
    /// <c>signature-policy-store</c> gating.
    /// </summary>
    public required ReadOnlyMemory<byte> SigPolicyHash { get; init; }

    /// <summary>
    /// Gets the whole pre-encoded DER <c>SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo</c>, or
    /// <see langword="null"/> to omit it. The qualifier types of clause 5.2.9.2 (<c>SPuri</c>,
    /// <c>SPUserNotice</c>, <c>SPDocSpecification</c>) are not separately modelled this wave; a caller that
    /// needs one encodes it and supplies the whole octets, spliced in verbatim.
    /// </summary>
    public ReadOnlyMemory<byte>? Qualifiers { get; init; }
}


/// <summary>
/// One <c>signer-attributes-v2</c> attribute value (clause 5.2.6.1):
/// <c>SignerAttributeV2 ::= SEQUENCE { claimedAttributes [0] ClaimedAttributes OPTIONAL, certifiedAttributesV2
/// [1] CertifiedAttributesV2 OPTIONAL, signedAssertions [2] SignedAssertions OPTIONAL }</c>, of which this
/// record offers the <c>claimedAttributes</c> arm alone.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The other two arms are a deliberate, recorded pass, not an oversight.</strong>
/// <c>certifiedAttributesV2</c> carries <c>AttributeCertificate</c> instances
/// (<see href="https://www.rfc-editor.org/rfc/rfc5755">RFC 5755</see>) issued by an Attribute Authority, and
/// <c>signedAssertions</c> carries assertions signed by a third party — both of which need attribute-certificate
/// infrastructure this library does not yet have anywhere: an <c>AttributeCertificate</c> parser and profile, a
/// path-building and revocation story for the Attribute Authority's own certificate (Table 1 requirements d) and
/// o) name "any attribute certificate" and its revocation-signing certificates as validation material), and the
/// clause A.1.1.1/A.1.2.1 <c>attribute-certificate-references</c>/<c>attribute-revocation-references</c>
/// vocabulary Table 1 requirement n) ties to exactly those two arms. That is its own arc, not a corner of a
/// creation surface. Consequences of the pass, both of which hold by construction: a signature this surface
/// produces never carries a certified signer attribute or a signed assertion, so requirement n) forbids the two
/// reference attributes for it — which this library never emits in any case — and clause 5.2.6.1's "Empty
/// <c>signer-attributes-v2</c> shall not be created" is enforced by requiring a non-empty
/// <see cref="ClaimedAttributes"/>.
/// </para>
/// <para>
/// Each claimed attribute is a whole DER <c>Attribute</c> (clause 5.2.6.1: "These signer attributes are expressed
/// using <c>Attribute</c> types"), which is exactly what a <see cref="CmsAttribute"/> carries — so a caller builds
/// a claimed role with <see cref="CmsAttribute.Create(string, ReadOnlySpan{byte}, System.Buffers.MemoryPool{byte})"/>
/// and hands the carrier over, rather than passing naked octets. The attribute types themselves are open: clause
/// 5.2.6.1 NOTE 1 suggests <c>RoleAttribute</c> and clause 5.2.6.2 defines <c>claimed-SAML-assertion</c> for a
/// SAML assertion, neither of which this surface models — it places whatever <c>Attribute</c> the caller built.
/// </para>
/// </remarks>
public sealed record CAdESSignerAttributesV2
{
    /// <summary>
    /// Gets the claimed attributes, at least one: the <c>ClaimedAttributes ::= SEQUENCE OF Attribute</c> the
    /// <c>[0]</c> arm carries. The carriers belong to the caller and are not disposed by the creation surface,
    /// which copies the octets it places.
    /// </summary>
    public required IReadOnlyList<CmsAttribute> ClaimedAttributes { get; init; }
}


/// <summary>
/// What one <c>content-time-stamp</c> token acquisition needs (clause 5.2.8): the Time-Stamping Authority to
/// contact and how to reach it. The message imprint algorithm and digest are supplied by the caller of
/// <see cref="CAdESSignatureCreation.PrepareAsync"/>, not repeated per request — see
/// <see cref="CAdESOptionalSignedAttributes.ContentTimestampRequests"/>.
/// </summary>
public sealed record CAdESContentTimestampRequest
{
    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the same reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchResponse { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? ReqPolicyOid { get; init; }

    /// <summary>Gets the nonce length in octets the request carries.</summary>
    public int NonceByteLength { get; init; } = 32;

    /// <summary>Gets whether the request carries a nonce.</summary>
    public bool IncludeNonce { get; init; } = true;
}
