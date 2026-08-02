using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>valData</c> unsigned-component type of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.4</see>, Table 10 — the CB-AdES analogue of the CAdES/PAdES
/// "certificate/revocation values" containers: an unsigned <c>uHeaders</c> element (label 2, Table 8) that
/// carries certificate values, revocation values, or both, for validating any digital signature present
/// within any component of the CB-AdES signature.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope (CB-5.3.4-01).</strong> "The <c>valData</c> CBOR map shall contain the certificates
/// identified in 1) below, or the revocation data identified in 2) below, or both of them" — where 1) is
/// "Certificate values that are used for validating any digital signature present within any component of
/// the CB-AdES signature regardless the objects that they are signing (these can be, for instance, the COSE
/// signature value within the <c>signature</c> component itself, any counter signature of the CB-AdES
/// signature, or the digital signatures within any time-stamp token, attribute certificate, signed assertion,
/// OCSP response, or CRL, or any other digital signature), without any restrictions" and 2) is "Revocation
/// value(s) of the certificate(s) supporting any signature present within any component of the CB-AdES
/// signature mentioned in the previous bullet." <see cref="CertificateValues"/> validates signatures ANYWHERE
/// in the CB-AdES structure, not only the top-level signature.
/// </para>
/// <para>CDDL (clause 5.3.4, Table 10 keys):</para>
/// <code>
/// valData = {
///     ? 1 =&gt; xVals,   ; CertificateValues
///     ? 2 =&gt; rVals    ; RevocationValues
/// }
/// xVals = [ +X509OrOther ]
/// </code>
/// <para>
/// <strong>CB-5.3.4-02.</strong> "CB-AdES signatures shall not incorporate empty <c>valData</c> maps" —
/// enforced at construction: at least one of <see cref="CertificateValues"/> and
/// <see cref="RevocationValues"/> must be supplied.
/// </para>
/// <para>
/// <strong>CB-5.3.4-03.</strong> "<c>xVals</c> map shall have at least one member." <c>xVals</c> is
/// CDDL-typed as an array (<c>[+X509OrOther]</c>), not a map, so the prose's "map"/"member" wording is
/// imprecise (CB-AdES preflight leg 3, Traps); the real, mechanically-enforced constraint is that a present
/// <see cref="CertificateValues"/> list is non-empty, reiterating the CDDL's <c>+</c> cardinality rather than
/// adding to it — enforced here nonetheless, since the model must not be able to represent an illegal
/// zero-length list any more than an absent one.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every <see cref="CBAdESPkiObject"/> reachable through
/// <see cref="CertificateValues"/> or <see cref="RevocationValues"/> carries a borrowed
/// <see cref="ReadOnlyMemory{T}"/> view (see <see cref="CBAdESPkiObject.Val"/>'s ownership remarks); this type
/// owns nothing of its own and therefore implements no <see cref="IDisposable"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESValidationData(CertificateValues={CertificateValues?.Count}, RevocationValues={RevocationValues != null})")]
public sealed record CBAdESValidationData
{
    /// <summary>The <c>xVals</c> member's map key (Table 10, clause 5.3.4).</summary>
    public const int XValsKey = 1;

    /// <summary>The <c>rVals</c> member's map key (Table 10, clause 5.3.4).</summary>
    public const int RValsKey = 2;

    /// <summary>
    /// Initializes a new <see cref="CBAdESValidationData"/>.
    /// </summary>
    /// <param name="certificateValues">
    /// The <c>xVals</c> member (map key 1), or <see langword="null"/> to omit it. When supplied, must be
    /// non-empty (CB-5.3.4-03).
    /// </param>
    /// <param name="revocationValues">
    /// The <c>rVals</c> member (map key 2), or <see langword="null"/> to omit it.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Both <paramref name="certificateValues"/> and <paramref name="revocationValues"/> are
    /// <see langword="null"/> (CB-5.3.4-01/02); or <paramref name="certificateValues"/> is non-null but empty
    /// (CB-5.3.4-03).
    /// </exception>
    public CBAdESValidationData(
        IReadOnlyList<CBAdESX509OrOtherCertificate>? certificateValues = null,
        CBAdESRevocationValues? revocationValues = null)
    {
        if(certificateValues is null && revocationValues is null)
        {
            throw new ArgumentException(
                "CB-AdES signatures shall not incorporate empty 'valData' maps; at least one of 'xVals' or " +
                "'rVals' shall be present (ETSI TS 119 152-1 V1.1.1, clause 5.3.4, CB-5.3.4-01/02).");
        }

        if(certificateValues is not null && certificateValues.Count == 0)
        {
            throw new ArgumentException(
                "When present, 'xVals' shall have at least one member (ETSI TS 119 152-1 V1.1.1, clause 5.3.4, CB-5.3.4-03).",
                nameof(certificateValues));
        }

        CertificateValues = certificateValues;
        RevocationValues = revocationValues;
    }


    /// <summary>
    /// Gets the <c>xVals</c> member (map key 1): certificate values used for validating any digital signature
    /// present within any component of the CB-AdES signature (CB-5.3.4-01), or <see langword="null"/> when
    /// absent. Non-empty when present (CB-5.3.4-03, enforced at construction).
    /// </summary>
    public IReadOnlyList<CBAdESX509OrOtherCertificate>? CertificateValues { get; }

    /// <summary>
    /// Gets the <c>rVals</c> member (map key 2): revocation value(s) of the certificate(s) supporting any
    /// signature present within any component of the CB-AdES signature (CB-5.3.4-01), or
    /// <see langword="null"/> when absent.
    /// </summary>
    public CBAdESRevocationValues? RevocationValues { get; }
}


/// <summary>
/// The <c>X509OrOther</c> shared choice of <see cref="CBAdESValidationData.CertificateValues"/> (clause 5.3.4,
/// Table 10): each <c>xVals</c> entry is exactly one of an X.509 DER certificate or a certificate in another,
/// declared-extensible format. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// <para>CDDL (clause 5.3.4):</para>
/// <code>
/// X509OrOther = {
///     1 =&gt; pkiOb, // ; x509Cert
///     2 =&gt; pkiOb    ; otherCert
/// }
/// </code>
/// <para>
/// The source CDDL mixes a <c>//</c> group-choice separator on the first arm with a trailing <c>,</c> on the
/// second (CB-AdES preflight leg 3, Traps) — the prose ("An <c>x509Cert</c> item shall contain ..."; "An
/// <c>otherCert</c> item is a placeholder ...") makes clear both are meant as an exclusive group choice,
/// exactly the shape reproduced by <see cref="CBAdESX509Certificate"/>/<see cref="CBAdESOtherCertificate"/>.
/// </para>
/// </remarks>
public abstract record CBAdESX509OrOtherCertificate
{
    /// <summary>The <c>x509Cert</c> choice arm's map key (Table 10, clause 5.3.4).</summary>
    public const int X509CertKey = 1;

    /// <summary>The <c>otherCert</c> choice arm's map key (Table 10, clause 5.3.4).</summary>
    public const int OtherCertKey = 2;

    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESX509OrOtherCertificate()
    {
    }
}


/// <summary>
/// The <c>x509Cert</c> choice arm (clause 5.3.4, map key 1, Table 10): one DER-encoded X.509 certificate
/// (CB-5.3.4-04).
/// </summary>
/// <param name="Certificate">
/// The encapsulating <see cref="CBAdESPkiObject"/> instance. "An <c>x509Cert</c> item shall contain one
/// DER-encoded X.509 certificate encapsulated within an instance of <c>pkiOb</c> type" — since
/// <see cref="Certificate"/> carries no explicit <see cref="CBAdESPkiObject.Encoding"/>, DER is the default
/// per clause 5.4.2 (CB-5.4.2-03).
/// </param>
[DebuggerDisplay("CBAdESX509Certificate({Certificate.Val.Length} bytes)")]
public sealed record CBAdESX509Certificate(CBAdESPkiObject Certificate) : CBAdESX509OrOtherCertificate;


/// <summary>
/// The <c>otherCert</c> choice arm (clause 5.3.4, map key 2, Table 10): a certificate in a format other than
/// DER-encoded X.509.
/// </summary>
/// <param name="Certificate">
/// The encapsulating <see cref="CBAdESPkiObject"/> instance, whose <see cref="CBAdESPkiObject.Encoding"/> and
/// <see cref="CBAdESPkiObject.SpecRef"/> identify the format. "An <c>otherCert</c> item is a placeholder for
/// potential future new formats of certificates" — a declared extensibility placeholder, not itself a
/// fully-specified requirement (CB-AdES preflight leg 3, Traps).
/// </param>
[DebuggerDisplay("CBAdESOtherCertificate({Certificate.Val.Length} bytes)")]
public sealed record CBAdESOtherCertificate(CBAdESPkiObject Certificate) : CBAdESX509OrOtherCertificate;


/// <summary>
/// The <c>rVals</c> CBOR map of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.4</see>, Table 10 — revocation validation material: three
/// independently-optional non-empty lists of <see cref="CBAdESPkiObject"/> instances (CRLs, OCSP responses,
/// and other-format revocation data).
/// </summary>
/// <remarks>
/// <para>CDDL (clause 5.3.4, Table 10 keys):</para>
/// <code>
/// rVals = {
///     ? 1 =&gt; [+pkiOb],   ; CrlValues
///     ? 2 =&gt; [+pkiOb],   ; OcspValues
///     ? 3 =&gt; [+pkiOb]    ; OtherValues
/// }
/// </code>
/// <para>
/// <strong>CB-5.3.4-05.</strong> "<c>rVals</c> map shall have at least one member" — unlike <c>xVals</c>
/// (CB-5.3.4-03, a CDDL-array cardinality restated in prose), <c>rVals</c> is a genuine CDDL map with three
/// independently-optional members, so this is a real cross-member invariant not expressible in the CDDL
/// alone: enforced at construction, requiring at least one of <see cref="CrlValues"/>,
/// <see cref="OcspValues"/>, <see cref="OtherValues"/> to be supplied.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESRevocationValues(Crl={CrlValues?.Count}, Ocsp={OcspValues?.Count}, Other={OtherValues?.Count})")]
public sealed record CBAdESRevocationValues
{
    /// <summary>The <c>crlVals</c> member's map key (Table 10, clause 5.3.4).</summary>
    public const int CrlValsKey = 1;

    /// <summary>The <c>ocspVals</c> member's map key (Table 10, clause 5.3.4).</summary>
    public const int OcspValsKey = 2;

    /// <summary>The <c>otherVals</c> member's map key (Table 10, clause 5.3.4).</summary>
    public const int OtherValsKey = 3;

    /// <summary>
    /// Initializes a new <see cref="CBAdESRevocationValues"/>.
    /// </summary>
    /// <param name="crlValues">
    /// The <c>crlVals</c> member (map key 1), or <see langword="null"/> to omit it. When supplied, must be
    /// non-empty (CB-5.3.4-06).
    /// </param>
    /// <param name="ocspValues">
    /// The <c>ocspVals</c> member (map key 2), or <see langword="null"/> to omit it. When supplied, must be
    /// non-empty (CB-5.3.4-09).
    /// </param>
    /// <param name="otherValues">
    /// The <c>otherVals</c> member (map key 3), or <see langword="null"/> to omit it. When supplied, must be
    /// non-empty (the CDDL's <c>+</c> cardinality on <c>[+pkiOb]</c> — the prose does not separately restate
    /// this member's non-emptiness the way it does for <c>crlVals</c>/<c>ocspVals</c>).
    /// </param>
    /// <exception cref="ArgumentException">
    /// All three of <paramref name="crlValues"/>, <paramref name="ocspValues"/>, and
    /// <paramref name="otherValues"/> are <see langword="null"/> (CB-5.3.4-05); or one of them is non-null but
    /// empty.
    /// </exception>
    public CBAdESRevocationValues(
        IReadOnlyList<CBAdESPkiObject>? crlValues = null,
        IReadOnlyList<CBAdESPkiObject>? ocspValues = null,
        IReadOnlyList<CBAdESPkiObject>? otherValues = null)
    {
        if(crlValues is null && ocspValues is null && otherValues is null)
        {
            throw new ArgumentException(
                "'rVals' map shall have at least one member (ETSI TS 119 152-1 V1.1.1, clause 5.3.4, CB-5.3.4-05).");
        }

        ThrowIfEmpty(crlValues, nameof(crlValues), "crlVals", "CB-5.3.4-06");
        ThrowIfEmpty(ocspValues, nameof(ocspValues), "ocspVals", "CB-5.3.4-09");
        ThrowIfEmpty(otherValues, nameof(otherValues), "otherVals", "the CDDL '+' cardinality on '[+pkiOb]'");

        CrlValues = crlValues;
        OcspValues = ocspValues;
        OtherValues = otherValues;

        static void ThrowIfEmpty(IReadOnlyList<CBAdESPkiObject>? candidate, string paramName, string wireName, string citation)
        {
            if(candidate is not null && candidate.Count == 0)
            {
                throw new ArgumentException(
                    $"When present, '{wireName}' shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.3.4, {citation}).",
                    paramName);
            }
        }
    }


    /// <summary>
    /// Gets the <c>crlVals</c> member (map key 1): a non-empty array of DER-encoded X.509 CRLs, each
    /// encapsulated in a <see cref="CBAdESPkiObject"/> (CB-5.3.4-06/07), or <see langword="null"/> when absent.
    /// </summary>
    /// <remarks>
    /// <strong>CB-5.3.4-08 (Delta-CRL completeness, not enforced here).</strong> "If the validation data
    /// contain one or more Delta CRLs, the <c>crlVals</c> member shall contain the set of CRLs required to
    /// provide complete revocation lists." This is a semantic-validation invariant — whether the array
    /// actually contains every base CRL a present Delta CRL depends on — that cannot be checked from this
    /// list's shape alone; it is owned by a later validation stage, not this model.
    /// </remarks>
    public IReadOnlyList<CBAdESPkiObject>? CrlValues { get; }

    /// <summary>
    /// Gets the <c>ocspVals</c> member (map key 2): a non-empty array of DER-encoded
    /// <see href="https://www.rfc-editor.org/rfc/rfc6960">IETF RFC 6960</see> <c>OCSPResponse</c> instances,
    /// each encapsulated in a <see cref="CBAdESPkiObject"/> (CB-5.3.4-09/10, RFC 6960 clause 4.2.1), or
    /// <see langword="null"/> when absent.
    /// </summary>
    public IReadOnlyList<CBAdESPkiObject>? OcspValues { get; }

    /// <summary>
    /// Gets the <c>otherVals</c> member (map key 3): other revocation information in a format other than
    /// DER-encoded CRL or OCSP response, or <see langword="null"/> when absent. "The <c>otherVals</c> member
    /// provides a placeholder for other revocation information that can be used in the future. Their
    /// semantics and syntax are outside the scope of the present document" — a declared extensibility
    /// placeholder, not itself a fully-specified requirement.
    /// </summary>
    public IReadOnlyList<CBAdESPkiObject>? OtherValues { get; }
}
