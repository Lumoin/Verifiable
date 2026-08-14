using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>xVals</c> shared JSON-array shape of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.3.5.2</see> — a non-empty, ordered list of certificate values
/// (JA-5.3.5.2-13/-14). Reused verbatim by <c>axVals</c> (clause 5.3.5.4, Annex B.1 schema
/// <c>"axVals": {"$ref": "#/definitions/xVals"}</c>) — see <see cref="JAdESSignatureCertificateValues"/> and
/// <see cref="JAdESAttributeCertificateValues"/> for the two <c>etsiU</c> kinds that hold this shared shape.
/// </summary>
/// <remarks>
/// <para>JSON Schema (clause 5.3.5.2, copied from Annex B.1):</para>
/// <code>
/// "xVals": {
///   "type": "array",
///   "items": {
///     "type":"object",
///     "properties": { "x509Cert": {"$ref": "#/definitions/pkiOb"}, "otherCert": {"$ref": "#/definitions/pkiOb"} },
///     "oneOf": [ { "required": ["x509Cert"] }, { "required": ["otherCert"] } ],
///     "additionalProperties": false
///   },
///   "minItems": 1
/// },
/// </code>
/// <para>
/// <strong>Content-selection rules (semantics, items 1-6) are a later validation-stage concern, not enforced
/// here.</strong> Clause 5.3.5.2's own semantics (JA-5.3.5.2-01..-12) state which certificates a conformant
/// <c>xVals</c> shall/should(-not) contain — trust anchor, CA path, signing certificate, revocation-signer
/// certificates, and the exclusions/inclusions around each — all cross-referential ("if not already present
/// within another component of the JAdES signature") facts this shape-only model cannot check from its own
/// contents alone. This type enforces only the schema-level array cardinality (JA-5.3.5.2-13, non-empty).
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every <see cref="AdESPkiObject"/> reachable through <see cref="Items"/> carries
/// a borrowed <see cref="ReadOnlyMemory{T}"/> view (see <see cref="AdESPkiObject.Val"/>'s ownership remarks);
/// this type owns nothing of its own and therefore implements no <see cref="IDisposable"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESCertificateValues({Items.Count} items)")]
public sealed record JAdESCertificateValues
{
    /// <summary>
    /// Initializes a new <see cref="JAdESCertificateValues"/>.
    /// </summary>
    /// <param name="items">The certificate-choice items, in wire order. Must be non-empty (JA-5.3.5.2-13).</param>
    /// <exception cref="ArgumentNullException"><paramref name="items"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="items"/> is empty.</exception>
    public JAdESCertificateValues(IReadOnlyList<JAdESCertificateChoice> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        if(items.Count == 0)
        {
            throw new ArgumentException(
                "xVals shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, clause 5.3.5.2, JA-5.3.5.2-13; Annex B.1 schema 'minItems: 1').",
                nameof(items));
        }

        Items = items;
    }


    /// <summary>Gets the certificate-choice items, in wire order (JA-5.3.5.2-13). Non-empty.</summary>
    public IReadOnlyList<JAdESCertificateChoice> Items { get; }
}


/// <summary>
/// One item of <see cref="JAdESCertificateValues.Items"/> (clause 5.3.5.2, Annex B.1 schema
/// <c>oneOf</c>): a certificate, either DER-encoded X.509 or in another, declared-extensible format. A
/// DU-ready closed sum: no external type may derive from it.
/// </summary>
public abstract record JAdESCertificateChoice
{
    /// <summary>The <c>x509Cert</c> choice arm's JSON key name (clause 5.3.5.2, Annex B.1 schema).</summary>
    public const string X509CertMemberName = "x509Cert";

    /// <summary>The <c>otherCert</c> choice arm's JSON key name (clause 5.3.5.2, Annex B.1 schema).</summary>
    public const string OtherCertMemberName = "otherCert";

    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected JAdESCertificateChoice()
    {
    }
}


/// <summary>
/// The <c>x509Cert</c> choice arm (clause 5.3.5.2, JA-5.3.5.2-14): one DER-encoded X.509 certificate
/// encapsulated within a <see cref="AdESPkiObject"/>.
/// </summary>
/// <param name="Certificate">
/// The encapsulating <see cref="AdESPkiObject"/> instance. "An <c>x509Cert</c> item shall contain the base64
/// encoding of one DER-encoded X.509 certificate" — since <see cref="Certificate"/> carries no explicit
/// <see cref="AdESPkiObject.Encoding"/>, DER is the default per clause 5.4.2 (JA-5.4.2-06).
/// </param>
[DebuggerDisplay("JAdESX509Certificate({Certificate.Val.Length} bytes)")]
public sealed record JAdESX509Certificate(AdESPkiObject Certificate): JAdESCertificateChoice;


/// <summary>
/// The <c>otherCert</c> choice arm (clause 5.3.5.2): a certificate in a format other than DER-encoded X.509 —
/// "a placeholder for potential future new formats of certificates", a declared extensibility placeholder, not
/// itself a fully-specified requirement.
/// </summary>
/// <param name="Certificate">
/// The encapsulating <see cref="AdESPkiObject"/> instance, whose <see cref="AdESPkiObject.Encoding"/> and
/// <see cref="AdESPkiObject.SpecRef"/> identify the format.
/// </param>
[DebuggerDisplay("JAdESOtherCertificate({Certificate.Val.Length} bytes)")]
public sealed record JAdESOtherCertificate(AdESPkiObject Certificate): JAdESCertificateChoice;


/// <summary>
/// The <c>rVals</c> shared JSON-object shape of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.3.5.3</see> — three independently-optional non-empty lists of
/// <see cref="AdESPkiObject"/> instances (CRLs, OCSP responses, and other-format revocation data). Reused
/// verbatim by <c>arVals</c> (clause 5.3.5.5, Annex B.1 schema <c>"arVals": {"$ref": "#/definitions/rVals"}</c>)
/// — see <see cref="JAdESSignatureRevocationValues"/> and <see cref="JAdESAttributeRevocationValues"/> for the
/// two <c>etsiU</c> kinds that hold this shared shape.
/// </summary>
/// <remarks>
/// <para>JSON Schema (clause 5.3.5.3, copied from Annex B.1):</para>
/// <code>
/// "rVals": {
///   "type": "object",
///   "properties":{
///     "crlVals": { "type": "array", "items": {"$ref":"#/definitions/pkiOb"}, "minItems": 1 },
///     "ocspVals": { "type": "array", "items": {"$ref":"#/definitions/pkiOb"}, "minItems": 1 },
///     "otherVals": { "type": "array", "items": {"type":"object"}, "minItems": 1 }
///   },
///   "minProperties": 1 ,
///   "additionalProperties": false
/// },
/// </code>
/// <para>
/// <strong>Item 3's "present already present".</strong>
/// Clause 5.3.5.3's semantics, item 3: "may contain revocation values corresponding to certificates used to
/// sign CRLs or OCSP responses of 1) and 2) ...; the revocation values present already present within another
/// component of the JAdES signature should not be included" — every structurally parallel sentence in the
/// same sub-clause (items 1/2) reads "present within another component ... should not be included" (single
/// "present"); item 3's doubled wording is read as the same rule ("already present elsewhere should not be
/// included"). This — like every other item-1..5 content-selection rule in clause 5.3.5.3 — is a
/// cross-referential validation-stage concern, not enforced by this shape-only model, matching
/// <see cref="CBAdESRevocationValues.CrlValues"/>'s own "not enforced here" precedent for the parallel Delta-CRL
/// completeness rule.
/// </para>
/// <para>
/// <strong>At least one member (JA-5.3.5.3-12, schema <c>minProperties: 1</c>), enforced at construction.</strong>
/// A genuine cross-member invariant not expressible in the schema's per-array <c>minItems</c> alone.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESRevocationValues(Crl={CrlValues?.Count}, Ocsp={OcspValues?.Count}, Other={OtherValues?.Count})")]
public sealed record JAdESRevocationValues
{
    /// <summary>The <c>crlVals</c> member's JSON key name (clause 5.3.5.3, Annex B.1 schema).</summary>
    public const string CrlValsMemberName = "crlVals";

    /// <summary>The <c>ocspVals</c> member's JSON key name (clause 5.3.5.3, Annex B.1 schema).</summary>
    public const string OcspValsMemberName = "ocspVals";

    /// <summary>The <c>otherVals</c> member's JSON key name (clause 5.3.5.3, Annex B.1 schema).</summary>
    public const string OtherValsMemberName = "otherVals";

    /// <summary>
    /// Initializes a new <see cref="JAdESRevocationValues"/>.
    /// </summary>
    /// <param name="crlValues">
    /// The <c>crlVals</c> member, or <see langword="null"/> to omit it. When supplied, must be non-empty
    /// (JA-5.3.5.3-13, schema <c>minItems: 1</c>).
    /// </param>
    /// <param name="ocspValues">
    /// The <c>ocspVals</c> member, or <see langword="null"/> to omit it. When supplied, must be non-empty
    /// (JA-5.3.5.3-16, schema <c>minItems: 1</c>).
    /// </param>
    /// <param name="otherValues">
    /// The <c>otherVals</c> member, or <see langword="null"/> to omit it. When supplied, must be non-empty (the
    /// schema's <c>minItems: 1</c> — the prose does not separately restate this member's non-emptiness the way
    /// it does for <c>crlVals</c>/<c>ocspVals</c>, matching <see cref="CBAdESRevocationValues.OtherValues"/>'s
    /// own asymmetric citation).
    /// </param>
    /// <exception cref="ArgumentException">
    /// All three parameters are <see langword="null"/> (JA-5.3.5.3-12); or one of them is non-null but empty.
    /// </exception>
    public JAdESRevocationValues(
        IReadOnlyList<AdESPkiObject>? crlValues = null,
        IReadOnlyList<AdESPkiObject>? ocspValues = null,
        IReadOnlyList<AdESPkiObject>? otherValues = null)
    {
        if(crlValues is null && ocspValues is null && otherValues is null)
        {
            throw new ArgumentException(
                "rVals shall have at least one member (ETSI TS 119 182-1 V1.2.1, clause 5.3.5.3, JA-5.3.5.3-12; Annex B.1 schema 'minProperties: 1').");
        }

        ThrowIfEmpty(crlValues, nameof(crlValues), CrlValsMemberName, "JA-5.3.5.3-13");
        ThrowIfEmpty(ocspValues, nameof(ocspValues), OcspValsMemberName, "JA-5.3.5.3-16");
        ThrowIfEmpty(otherValues, nameof(otherValues), OtherValsMemberName, "Annex B.1 schema 'minItems: 1'");

        CrlValues = crlValues;
        OcspValues = ocspValues;
        OtherValues = otherValues;

        static void ThrowIfEmpty(IReadOnlyList<AdESPkiObject>? candidate, string paramName, string wireName, string citation)
        {
            if(candidate is not null && candidate.Count == 0)
            {
                throw new ArgumentException(
                    $"When present, '{wireName}' shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, clause 5.3.5.3, {citation}).",
                    paramName);
            }
        }
    }


    /// <summary>
    /// Gets the <c>crlVals</c> member: a non-empty array of DER-encoded X.509 CRLs, each encapsulated in a
    /// <see cref="AdESPkiObject"/> (JA-5.3.5.3-13/-14), or <see langword="null"/> when absent.
    /// </summary>
    /// <remarks>
    /// <strong>Delta-CRL completeness (JA-5.3.5.3-15), not enforced here.</strong> "If the validation data
    /// contain one or more Delta CRLs, the <c>crlVals</c> member shall contain the set of CRLs required to
    /// provide complete revocation lists" — a semantic-validation invariant this list's shape alone cannot
    /// check, owned by a later validation stage, matching <see cref="CBAdESRevocationValues.CrlValues"/>'s own
    /// precedent.
    /// </remarks>
    public IReadOnlyList<AdESPkiObject>? CrlValues { get; }

    /// <summary>
    /// Gets the <c>ocspVals</c> member: a non-empty array of DER-encoded
    /// <see href="https://www.rfc-editor.org/rfc/rfc6960">IETF RFC 6960</see> <c>OCSPResponse</c> instances,
    /// each encapsulated in a <see cref="AdESPkiObject"/> (JA-5.3.5.3-16/-17), or <see langword="null"/> when
    /// absent.
    /// </summary>
    public IReadOnlyList<AdESPkiObject>? OcspValues { get; }

    /// <summary>
    /// Gets the <c>otherVals</c> member: other revocation information in a format other than DER-encoded CRL
    /// or OCSP response, or <see langword="null"/> when absent. "The <c>otherVals</c> member provides a
    /// placeholder for other revocation information that can be used in the future. Their semantics and syntax
    /// are outside the scope of the present document" — a declared extensibility placeholder.
    /// </summary>
    public IReadOnlyList<AdESPkiObject>? OtherValues { get; }
}


/// <summary>
/// The <c>validationVals</c> shared JSON-object shape of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see> — certificate values, revocation values, or both. Reused verbatim by BOTH
/// <c>anyValData</c> (clause 5.3.5.6, JA-5.3.5.6-02) and <c>tstVD</c> (clause 5.3.6.1, JA-5.3.6.1-04), each
/// Annex B.1 schema-typed as <c>{"$ref": "#/definitions/validationVals"}</c> — see
/// <see cref="JAdESAnyValidationData"/> and <see cref="JAdESTimestampValidationData"/> for the two <c>etsiU</c>
/// kinds that hold this shared shape.
/// </summary>
/// <remarks>
/// <para>JSON Schema (copied from Annex B.1):</para>
/// <code>
/// "validationVals": {
///   "type": "object",
///   "properties": { "xVals": {"$ref": "#/definitions/xVals"}, "rVals": {"$ref": "#/definitions/rVals"} },
///   "minProperties": 1 ,
///   "additionalProperties": false
/// },
/// </code>
/// <para>
/// <strong><c>anyValData</c>'s own semantics (JA-5.3.5.6-01).</strong> "The <c>anyValData</c> JSON object
/// shall contain the certificates identified in 1), or the revocation data identified in 2), or both of them" —
/// certificates/revocation material for validating ANY digital signature present within ANY component of the
/// JAdES signature, regardless of what that signature is signing (clause 5.3.5.6, NOTE 1's CAdES/PAdES
/// analogy).
/// </para>
/// <para>
/// <strong><c>tstVD</c>'s own semantics (JA-5.3.6.1-01/-02/-03).</strong> A container for validation data
/// required to fully verify the electronic time-stamp(s) embedded within any <c>tstContainer</c>-shaped
/// component this document defines — a distinct usage of the identical wire shape.
/// </para>
/// <para>
/// <strong>At least one member (schema <c>minProperties: 1</c>), enforced at construction.</strong> Neither
/// member's own array cardinality (<see cref="JAdESCertificateValues"/>'s non-emptiness,
/// <see cref="JAdESRevocationValues"/>'s own at-least-one-member invariant) implies this cross-member
/// constraint.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESValidationData(CertificateValues={CertificateValues != null}, RevocationValues={RevocationValues != null})")]
public sealed record JAdESValidationData
{
    /// <summary>The <c>xVals</c> member's JSON key name (Annex B.1 schema).</summary>
    public const string XValsMemberName = "xVals";

    /// <summary>The <c>rVals</c> member's JSON key name (Annex B.1 schema).</summary>
    public const string RValsMemberName = "rVals";

    /// <summary>
    /// Initializes a new <see cref="JAdESValidationData"/>.
    /// </summary>
    /// <param name="certificateValues">The <c>xVals</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="revocationValues">The <c>rVals</c> member, or <see langword="null"/> to omit it.</param>
    /// <exception cref="ArgumentException">
    /// Both <paramref name="certificateValues"/> and <paramref name="revocationValues"/> are
    /// <see langword="null"/> (schema <c>minProperties: 1</c>).
    /// </exception>
    public JAdESValidationData(JAdESCertificateValues? certificateValues = null, JAdESRevocationValues? revocationValues = null)
    {
        if(certificateValues is null && revocationValues is null)
        {
            throw new ArgumentException(
                "validationVals shall have at least one member: 'xVals' or 'rVals' (ETSI TS 119 182-1 V1.2.1, Annex B.1 schema 'minProperties: 1').");
        }

        CertificateValues = certificateValues;
        RevocationValues = revocationValues;
    }


    /// <summary>Gets the <c>xVals</c> member, or <see langword="null"/> when absent.</summary>
    public JAdESCertificateValues? CertificateValues { get; }

    /// <summary>Gets the <c>rVals</c> member, or <see langword="null"/> when absent.</summary>
    public JAdESRevocationValues? RevocationValues { get; }
}
