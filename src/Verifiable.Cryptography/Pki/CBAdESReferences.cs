using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>refs</c> unsigned-component type of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, Annex A.1.1</see> — references to certificates and revocation data (as opposed to
/// the full values <see cref="CBAdESValidationData"/> carries), an unsigned <c>uHeaders</c> element (label 4,
/// clause 5.3.1 Table 8) that is part of the B-B/B-T-only reference-and-timestamp mechanism together with
/// <see cref="CBAdESSignatureAndReferencesTimestamp"/>/<see cref="CBAdESReferencesTimestamp"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope (CB-A.1.1-01/03).</strong> "The <c>refs</c> CBOR map may contain references to certificate
/// values that are used for validating any digital signature present within any component of the CB-AdES
/// signature regardless the objects that they are signing (these can be, for instance, the COSE signature
/// value within the <c>signature</c> component itself, any counter signature of the CB-AdES signature, or the
/// digital signatures within any time-stamp token, attribute certificate, signed assertion, OCSP response, or
/// CRL, or any other digital signature), without any restrictions", and "may contain the references to the
/// revocation value(s) of the certificate(s) supporting any signature present within any component of the
/// CB-AdES signature" mentioned in the previous sentence. <see cref="CertificateReferences"/> and
/// <see cref="RevocationReferences"/> are therefore a general-purpose reference bag scoped to the whole
/// signature object graph, never assumed to name only "the" top-level signature.
/// </para>
/// <para>
/// <strong>CB-A.1.1-02 (owned by a later stage, not this model).</strong> "The <c>refs</c> CBOR map shall not
/// contain the signing certificate of the CB-AdES signature itself." This type cannot see which certificate
/// signed the enclosing CB-AdES signature, so it cannot self-enforce this rule; it is a build/validation-time
/// invariant owned by the stage that assembles <c>uHeaders</c> against the concrete signing certificate.
/// </para>
/// <para>
/// <strong>CB-A.1.1-30 (owned by a later stage, not this model).</strong> "If at least one of the following:
/// <c>valData</c> or the <c>arcTst</c>, is incorporated into the signature, all the certificates and validation
/// data referenced in <c>refs</c> shall be present elsewhere in the signature." This is a cross-component
/// consistency check over the whole signature's component collection — every entry reachable through
/// <see cref="CertificateReferences"/>/<see cref="RevocationReferences"/> must resolve to material actually
/// present in a <see cref="CBAdESValidationData"/> instance or reachable through <c>arcTst</c>'s protected
/// material — owned by the finalize/validate stage, not by this type's construction.
/// </para>
/// <para>CDDL (Annex A.1.1, Table A.1 keys):</para>
/// <code>
/// refs = {
///     ? 1 =&gt; xRefs,   ; CertificateReferences
///     ? 2 =&gt; rRefs     ; RevocationReferences
/// }
/// xRefs = [ +CertId ]
/// </code>
/// <para>
/// <strong>CB-A.1.1-04/05.</strong> "CB-AdES signatures shall not incorporate empty <c>refs</c> CBOR maps" and
/// "Empty <c>xRefs</c> shall not be incorporated" — both enforced at construction: at least one of
/// <see cref="CertificateReferences"/> and <see cref="RevocationReferences"/> must be supplied, and a supplied
/// <see cref="CertificateReferences"/> must be non-empty.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Owns every <see cref="CBAdESCertificateReference"/> reachable through
/// <see cref="CertificateReferences"/>, and <see cref="RevocationReferences"/> itself. Disposing this instance
/// disposes all of them.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESReferences(CertificateReferences={CertificateReferences?.Count}, RevocationReferences={RevocationReferences != null})")]
public sealed record CBAdESReferences: IDisposable
{
    /// <summary>The <c>xRefs</c> member's map key (Table A.1, Annex A.1.1).</summary>
    public const int CertificateReferencesKey = 1;

    /// <summary>The <c>rRefs</c> member's map key (Table A.1, Annex A.1.1).</summary>
    public const int RevocationReferencesKey = 2;

    /// <summary>
    /// Initializes a new <see cref="CBAdESReferences"/>. Ownership of every entry in
    /// <paramref name="certificateReferences"/>, and of <paramref name="revocationReferences"/>, transfers to
    /// this instance.
    /// </summary>
    /// <param name="certificateReferences">
    /// The <c>xRefs</c> member (map key 1), or <see langword="null"/> to omit it. When supplied, must be
    /// non-empty (CB-A.1.1-05).
    /// </param>
    /// <param name="revocationReferences">
    /// The <c>rRefs</c> member (map key 2), or <see langword="null"/> to omit it.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Both <paramref name="certificateReferences"/> and <paramref name="revocationReferences"/> are
    /// <see langword="null"/> (CB-A.1.1-04); or <paramref name="certificateReferences"/> is non-null but empty
    /// (CB-A.1.1-05).
    /// </exception>
    public CBAdESReferences(
        IReadOnlyList<CBAdESCertificateReference>? certificateReferences = null,
        CBAdESRevocationReferences? revocationReferences = null)
    {
        if(certificateReferences is null && revocationReferences is null)
        {
            throw new ArgumentException(
                "CB-AdES signatures shall not incorporate empty 'refs' CBOR maps; at least one of 'xRefs' or " +
                "'rRefs' shall be present (ETSI TS 119 152-1 V1.1.1, Annex A.1.1, CB-A.1.1-04).");
        }

        if(certificateReferences is not null && certificateReferences.Count == 0)
        {
            throw new ArgumentException(
                "When present, 'xRefs' shall not be empty (ETSI TS 119 152-1 V1.1.1, Annex A.1.1, CB-A.1.1-05).",
                nameof(certificateReferences));
        }

        CertificateReferences = certificateReferences;
        RevocationReferences = revocationReferences;
    }


    /// <summary>
    /// Gets the <c>xRefs</c> member (map key 1): references to certificate values (CB-A.1.1-01/02), in wire
    /// order, or <see langword="null"/> when absent. Non-empty when present (constructor-enforced,
    /// CB-A.1.1-05).
    /// </summary>
    public IReadOnlyList<CBAdESCertificateReference>? CertificateReferences { get; }

    /// <summary>
    /// Gets the <c>rRefs</c> member (map key 2): references to revocation data (CB-A.1.1-03), or
    /// <see langword="null"/> when absent.
    /// </summary>
    public CBAdESRevocationReferences? RevocationReferences { get; }


    /// <summary>
    /// Disposes every <see cref="CBAdESCertificateReference"/> reachable through
    /// <see cref="CertificateReferences"/>, and <see cref="RevocationReferences"/>.
    /// </summary>
    public void Dispose()
    {
        if(CertificateReferences is not null)
        {
            for(int i = 0; i < CertificateReferences.Count; ++i)
            {
                CertificateReferences[i].Dispose();
            }
        }

        RevocationReferences?.Dispose();
    }
}


/// <summary>
/// The <c>CertId</c> type of Annex A.1.1, Table A.1 — one certificate reference within
/// <see cref="CBAdESReferences.CertificateReferences"/>: a mandatory digest-pair identifying the certificate
/// plus two optional hints.
/// </summary>
/// <remarks>
/// <para>CDDL (Annex A.1.1):</para>
/// <code>
/// CertId = {
///     1 =&gt; COSE_CertHash,        ; Thumbprint
///     ? 2 =&gt; int / tstr / bstr,  ; KeyIdentifier
///     ? 3 =&gt; #6.32(tstr)         ; LocationHint
/// }
/// </code>
/// <para>
/// <strong>CB-A.1.1-06.</strong> "Within <c>xRefs</c>, the <c>x5t</c> member (specified in IETF RFC 9360 [3],
/// clause 2) shall identify the digest algorithm and the digest value computed on the DER-encoded
/// certificate." <c>x5t</c> is the same <c>COSE_CertHash</c> shape the <c>x5ts</c> signed header parameter uses
/// (<see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>, clause 5.1.7); this type
/// reuses <see cref="CBAdESCertificateThumbprint"/> verbatim as <see cref="Thumbprint"/> rather than
/// introducing a second digest-pair type for the identical wire shape — the digest is computed exclusively
/// through the registered digest delegate, never a direct framework hash call.
/// </para>
/// <para>
/// <strong>CB-A.1.1-07.</strong> "The content of <c>kid</c> member should be a DER-encoded instance of type
/// <c>IssuerSerial</c> type defined in IETF RFC 5035 [10] wrapped in a CBOR byte string." This is a SHOULD, not
/// a SHALL, and only one of the CDDL's three <c>kid</c> choice arms (<c>int</c>/<c>tstr</c>/<c>bstr</c>) — see
/// <see cref="CBAdESCertificateReferenceKeyIdentifier"/>, whose <c>bstr</c> arm
/// (<see cref="CBAdESCertificateReferenceKeyIdentifierBytes"/>) carries the recommended-but-optional
/// <see href="https://www.rfc-editor.org/rfc/rfc5035">IssuerSerial</see> payload opaque, never force-parsed by
/// this library (NOTE 1, Annex A.1.1: "the binding information is the digest of the certificate", not
/// <c>kid</c>).
/// </para>
/// <para>
/// <strong>CB-A.1.1-08.</strong> "The <c>x5u</c> member shall provide an indication of where the referenced
/// certificate can be found." NOTE 2 (Annex A.1.1) clarifies <c>x5u</c> "is used as a hint, as implementations
/// can have alternative ways for retrieving the referenced certificate if it is not found at the referenced
/// place" — <see cref="LocationHint"/> is therefore never a validation source of truth, only a retrieval hint.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Owns <see cref="Thumbprint"/>. Disposing this instance disposes it;
/// <see cref="KeyIdentifier"/> and <see cref="LocationHint"/> own no disposable resources of their own.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESCertificateReference: {Thumbprint}")]
public sealed record CBAdESCertificateReference: IDisposable
{
    /// <summary>The <c>x5t</c> member's map key (Table A.1, Annex A.1.1, <c>CertId</c>).</summary>
    public const int ThumbprintKey = 1;

    /// <summary>The <c>kid</c> member's map key (Table A.1, Annex A.1.1, <c>CertId</c>).</summary>
    public const int KeyIdentifierKey = 2;

    /// <summary>The <c>x5u</c> member's map key (Table A.1, Annex A.1.1, <c>CertId</c>).</summary>
    public const int LocationHintKey = 3;

    /// <summary>
    /// Initializes a new <see cref="CBAdESCertificateReference"/>. Ownership of <paramref name="thumbprint"/>
    /// transfers to this instance.
    /// </summary>
    /// <param name="thumbprint">The mandatory <c>x5t</c> digest pair identifying the certificate (CB-A.1.1-06).</param>
    /// <param name="keyIdentifier">
    /// The optional <c>kid</c> member, or <see langword="null"/> to omit it. See
    /// <see cref="CBAdESCertificateReferenceKeyIdentifier"/> for the CDDL's <c>int / tstr / bstr</c> union this
    /// parameter models.
    /// </param>
    /// <param name="locationHint">
    /// The optional <c>x5u</c> member — a retrieval hint (CB-A.1.1-08), or <see langword="null"/> to omit it.
    /// </param>
    /// <exception cref="ArgumentNullException">When <paramref name="thumbprint"/> is <see langword="null"/>.</exception>
    public CBAdESCertificateReference(
        CBAdESCertificateThumbprint thumbprint,
        CBAdESCertificateReferenceKeyIdentifier? keyIdentifier = null,
        Uri? locationHint = null)
    {
        ArgumentNullException.ThrowIfNull(thumbprint);

        Thumbprint = thumbprint;
        KeyIdentifier = keyIdentifier;
        LocationHint = locationHint;
    }


    /// <summary>
    /// Gets the mandatory <c>x5t</c> digest pair identifying the certificate (CB-A.1.1-06). Owned by this
    /// instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public CBAdESCertificateThumbprint Thumbprint { get; }

    /// <summary>
    /// Gets the optional <c>kid</c> member, or <see langword="null"/> when absent. See the type remarks for
    /// CB-A.1.1-07's SHOULD-level <c>IssuerSerial</c> recommendation on the <c>bstr</c> arm.
    /// </summary>
    public CBAdESCertificateReferenceKeyIdentifier? KeyIdentifier { get; }

    /// <summary>
    /// Gets the optional <c>x5u</c> member — a retrieval hint, never a validation source of truth
    /// (CB-A.1.1-08, NOTE 2) — or <see langword="null"/> when absent.
    /// </summary>
    public Uri? LocationHint { get; }


    /// <summary>
    /// Disposes <see cref="Thumbprint"/>.
    /// </summary>
    public void Dispose()
    {
        Thumbprint.Dispose();
    }
}


/// <summary>
/// The <c>kid</c> member's <c>int / tstr / bstr</c> CDDL union within <c>CertId</c> (Annex A.1.1) — a closed
/// three-arm sum. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// No key labels apply to this type's own arms: the CDDL union selects between three item major types
/// directly, matching the pattern already used for <see cref="CBAdESDigestAlgorithmIdentifier"/>'s <c>int /
/// tstr</c> union.
/// </remarks>
public abstract record CBAdESCertificateReferenceKeyIdentifier
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESCertificateReferenceKeyIdentifier()
    {
    }
}


/// <summary>The <c>int</c> arm of the <c>kid</c> CDDL union (Annex A.1.1, <c>CertId</c>).</summary>
/// <param name="Value">The integer key identifier.</param>
[DebuggerDisplay("CBAdESCertificateReferenceKeyIdentifierInteger: {Value}")]
public sealed record CBAdESCertificateReferenceKeyIdentifierInteger(int Value)
    : CBAdESCertificateReferenceKeyIdentifier;


/// <summary>The <c>tstr</c> arm of the <c>kid</c> CDDL union (Annex A.1.1, <c>CertId</c>).</summary>
/// <param name="Value">The textual key identifier.</param>
[DebuggerDisplay("CBAdESCertificateReferenceKeyIdentifierText: {Value}")]
public sealed record CBAdESCertificateReferenceKeyIdentifierText(string Value)
    : CBAdESCertificateReferenceKeyIdentifier;


/// <summary>
/// The <c>bstr</c> arm of the <c>kid</c> CDDL union (Annex A.1.1, <c>CertId</c>) — recommended, per
/// CB-A.1.1-07, to carry a DER-encoded <see href="https://www.rfc-editor.org/rfc/rfc5035">IssuerSerial (IETF
/// RFC 5035)</see> wrapped in the CBOR byte string, but a SHOULD rather than a SHALL, and never force-parsed by
/// this library — see the CB-A.1.1-07 remarks on <see cref="CBAdESCertificateReference"/>.
/// </summary>
/// <param name="Value">
/// The raw byte-string payload. <strong>Borrowed</strong> view — the caller (creation path) or the wire-bytes
/// source (parse path) owns the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESCertificateReferenceKeyIdentifierBytes: {Value.Length} bytes")]
public sealed record CBAdESCertificateReferenceKeyIdentifierBytes(ReadOnlyMemory<byte> Value)
    : CBAdESCertificateReferenceKeyIdentifier;


/// <summary>
/// The <c>rRefs</c> CBOR map of Annex A.1.1, Table A.1 — revocation-data references: three
/// independently-optional non-empty lists (CRL references, OCSP references, and opaque "other" references).
/// </summary>
/// <remarks>
/// <para>CDDL (Annex A.1.1):</para>
/// <code>
/// rRefs = {
///     ? 1 =&gt; [+CRLRef],   ; CrlReferences
///     ? 2 =&gt; [+OCSPRef],  ; OcspReferences
///     ? 3 =&gt; [+any]       ; OtherReferences
/// }
/// </code>
/// <para>
/// <strong>CB-A.1.1-09.</strong> "Empty <c>rRefs</c> shall not be incorporated" — a genuine cross-member
/// invariant (like <c>rVals</c>'s CB-5.3.4-05 in <see cref="CBAdESRevocationValues"/>), enforced at
/// construction: at least one of <see cref="CrlReferences"/>, <see cref="OcspReferences"/>,
/// <see cref="OtherReferences"/> must be supplied.
/// </para>
/// <para>
/// <strong>Leg-5 trap 3 — <c>otherRefs</c>'s CDDL comment is a spec-original copy-paste defect.</strong> The
/// CDDL comment for <c>? 3 =&gt; [+any]</c> literally reads "array of references to OCSP responses" — a
/// copy-paste leftover from the <c>ocspRefs</c> comment immediately above it. The prose immediately below the
/// CDDL block is authoritative instead: "References to alternative forms of validation data may be included in
/// this component making use of the <c>otherRefs</c> member, a sequence whose items may contain any kind of
/// information. Their semantics and syntax are outside the scope of the present document" (CB-A.1.1-29).
/// <see cref="OtherReferences"/> is therefore never modelled as OCSP-only.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Owns every entry reachable through <see cref="CrlReferences"/> and
/// <see cref="OcspReferences"/>. <see cref="OtherReferences"/> elements are borrowed
/// <see cref="ReadOnlyMemory{T}"/> views (opaque raw CBOR item bytes, CB-A.1.1-29) and own nothing.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESRevocationReferences(Crl={CrlReferences?.Count}, Ocsp={OcspReferences?.Count}, Other={OtherReferences?.Count})")]
public sealed record CBAdESRevocationReferences: IDisposable
{
    /// <summary>The <c>crlRefs</c> member's map key (Table A.1, Annex A.1.1, <c>rRefs</c>).</summary>
    public const int CrlReferencesKey = 1;

    /// <summary>The <c>ocspRefs</c> member's map key (Table A.1, Annex A.1.1, <c>rRefs</c>).</summary>
    public const int OcspReferencesKey = 2;

    /// <summary>The <c>otherRefs</c> member's map key (Table A.1, Annex A.1.1, <c>rRefs</c>).</summary>
    public const int OtherReferencesKey = 3;

    /// <summary>
    /// Initializes a new <see cref="CBAdESRevocationReferences"/>. Ownership of every entry in
    /// <paramref name="crlReferences"/> and <paramref name="ocspReferences"/> transfers to this instance.
    /// </summary>
    /// <param name="crlReferences">
    /// The <c>crlRefs</c> member (map key 1), or <see langword="null"/> to omit it. When supplied, must be
    /// non-empty (CB-A.1.1-10).
    /// </param>
    /// <param name="ocspReferences">
    /// The <c>ocspRefs</c> member (map key 2), or <see langword="null"/> to omit it. When supplied, must be
    /// non-empty (CB-A.1.1-19).
    /// </param>
    /// <param name="otherReferences">
    /// The <c>otherRefs</c> member (map key 3): opaque raw CBOR item bytes, borrowed, or <see langword="null"/>
    /// to omit it. When supplied, must be non-empty (the CDDL's <c>+</c> cardinality on <c>[+any]</c>).
    /// </param>
    /// <exception cref="ArgumentException">
    /// All three of <paramref name="crlReferences"/>, <paramref name="ocspReferences"/>, and
    /// <paramref name="otherReferences"/> are <see langword="null"/> (CB-A.1.1-09); or one of them is non-null
    /// but empty.
    /// </exception>
    public CBAdESRevocationReferences(
        IReadOnlyList<CBAdESCrlReference>? crlReferences = null,
        IReadOnlyList<CBAdESOcspReference>? ocspReferences = null,
        IReadOnlyList<ReadOnlyMemory<byte>>? otherReferences = null)
    {
        if(crlReferences is null && ocspReferences is null && otherReferences is null)
        {
            throw new ArgumentException(
                "Empty 'rRefs' shall not be incorporated; at least one of 'crlRefs', 'ocspRefs', or " +
                "'otherRefs' shall be present (ETSI TS 119 152-1 V1.1.1, Annex A.1.1, CB-A.1.1-09).");
        }

        ThrowIfEmpty(crlReferences, nameof(crlReferences), "crlRefs", "CB-A.1.1-10");
        ThrowIfEmpty(ocspReferences, nameof(ocspReferences), "ocspRefs", "CB-A.1.1-19");
        ThrowIfEmpty(otherReferences, nameof(otherReferences), "otherRefs", "the CDDL '+' cardinality on '[+any]'");

        CrlReferences = crlReferences;
        OcspReferences = ocspReferences;
        OtherReferences = otherReferences;

        static void ThrowIfEmpty<T>(IReadOnlyList<T>? candidate, string paramName, string wireName, string citation)
        {
            if(candidate is not null && candidate.Count == 0)
            {
                throw new ArgumentException(
                    $"When present, '{wireName}' shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, Annex A.1.1, {citation}).",
                    paramName);
            }
        }
    }


    /// <summary>
    /// Gets the <c>crlRefs</c> member (map key 1): a non-empty array of CRL references (CB-A.1.1-10/11), or
    /// <see langword="null"/> when absent. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    /// <remarks>
    /// <strong>CB-A.1.1-18 (Delta-CRL expansion, not enforced here).</strong> "If one or more of the identified
    /// CRLs are a Delta CRL, this component shall include references to the set of CRLs required to provide
    /// complete revocation lists." Whether this array actually contains every base-CRL reference a present
    /// Delta-CRL reference depends on is a semantic-validation invariant that cannot be checked from this
    /// list's shape alone; it is owned by a later validation stage, not this model — mirroring
    /// <see cref="CBAdESRevocationValues.CrlValues"/>'s CB-5.3.4-08 remarks.
    /// </remarks>
    public IReadOnlyList<CBAdESCrlReference>? CrlReferences { get; }

    /// <summary>
    /// Gets the <c>ocspRefs</c> member (map key 2): a non-empty array of OCSP references (CB-A.1.1-19/20), or
    /// <see langword="null"/> when absent. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public IReadOnlyList<CBAdESOcspReference>? OcspReferences { get; }

    /// <summary>
    /// Gets the <c>otherRefs</c> member (map key 3): opaque raw CBOR item bytes referencing alternative forms
    /// of validation data whose semantics and syntax are outside the scope of the present document
    /// (CB-A.1.1-29; see the leg-5 trap 3 remarks on this type for why this is not OCSP-only), or
    /// <see langword="null"/> when absent. Each element is a <strong>borrowed</strong> view; this instance owns
    /// none of them.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>>? OtherReferences { get; }


    /// <summary>
    /// Disposes every entry reachable through <see cref="CrlReferences"/> and <see cref="OcspReferences"/>.
    /// </summary>
    public void Dispose()
    {
        if(CrlReferences is not null)
        {
            for(int i = 0; i < CrlReferences.Count; ++i)
            {
                CrlReferences[i].Dispose();
            }
        }

        if(OcspReferences is not null)
        {
            for(int i = 0; i < OcspReferences.Count; ++i)
            {
                OcspReferences[i].Dispose();
            }
        }
    }
}


/// <summary>
/// The <c>CRLRef</c> type of Annex A.1.1, Table A.1 — one reference to one CRL (CB-A.1.1-11): a mandatory
/// digest pair over the DER-encoded CRL plus an optional identifier.
/// </summary>
/// <remarks>
/// <para>CDDL (Annex A.1.1):</para>
/// <code>
/// CRLRef = {
///     1 =&gt; DigAlgVal,  ; HashAlgorithm + Digest
///     ? 2 =&gt; CRLId      ; CrlIdentifier
/// }
/// </code>
/// <para>
/// <c>digAlgVal</c>'s two-element array is flattened onto this record as <see cref="HashAlgorithm"/> and
/// <see cref="Digest"/>, mirroring <see cref="CBAdESSignaturePolicyIdentifier"/>'s flattening of its own
/// <c>digAlgVal</c> member and <see cref="CBAdESCertificateThumbprint"/>'s flattening of <c>COSE_CertHash</c> —
/// the same <c>[hashAlg, hashValue]</c> shape reused a third time.
/// </para>
/// <para>
/// <strong>CB-A.1.1-12.</strong> "The <c>digAlgVal</c> member within the <c>crlRefs</c> array shall contain
/// indication of a digest algorithm, and the digest value of the DER-encoded referenced CRL wrapped in a CBOR
/// byte string" — computed exclusively through the registered digest delegate, never a direct framework hash
/// call.
/// </para>
/// <para>
/// <strong>CB-A.1.1-13.</strong> "The <c>crlId</c> member needs not to be present if the referenced CRL can be
/// inferred from other information" — a genuinely optional member, matching the CDDL's <c>?</c>.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Owns <see cref="Digest"/>. Disposing this instance disposes it;
/// <see cref="CrlIdentifier"/> owns no disposable resources of its own.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESCrlReference: HashAlgorithm={HashAlgorithm}")]
public sealed record CBAdESCrlReference: IDisposable
{
    /// <summary>The <c>digAlgVal</c> member's map key (Table A.1, Annex A.1.1, <c>CRLRef</c>).</summary>
    public const int DigAlgValKey = 1;

    /// <summary>The <c>crlId</c> member's map key (Table A.1, Annex A.1.1, <c>CRLRef</c>).</summary>
    public const int CrlIdentifierKey = 2;

    /// <summary>
    /// Initializes a new <see cref="CBAdESCrlReference"/>. Ownership of <paramref name="digest"/> transfers to
    /// this instance.
    /// </summary>
    /// <param name="hashAlgorithm">The <c>digAlgVal.hashAlg</c> element — the digest algorithm identifier.</param>
    /// <param name="digest">The <c>digAlgVal.hashValue</c> element — the digest of the DER-encoded CRL (CB-A.1.1-12).</param>
    /// <param name="crlIdentifier">The optional <c>crlId</c> member, or <see langword="null"/> to omit it (CB-A.1.1-13).</param>
    /// <exception cref="ArgumentNullException">
    /// When <paramref name="hashAlgorithm"/> or <paramref name="digest"/> is <see langword="null"/>.
    /// </exception>
    public CBAdESCrlReference(
        CBAdESDigestAlgorithmIdentifier hashAlgorithm,
        DigestValue digest,
        CBAdESCrlIdentifier? crlIdentifier = null)
    {
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(digest);

        HashAlgorithm = hashAlgorithm;
        Digest = digest;
        CrlIdentifier = crlIdentifier;
    }


    /// <summary>Gets the <c>digAlgVal.hashAlg</c> element — the digest algorithm identifier.</summary>
    public CBAdESDigestAlgorithmIdentifier HashAlgorithm { get; }

    /// <summary>
    /// Gets the <c>digAlgVal.hashValue</c> element — the digest of the DER-encoded CRL (CB-A.1.1-12). Owned by
    /// this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public DigestValue Digest { get; }

    /// <summary>
    /// Gets the optional <c>crlId</c> member (CB-A.1.1-13), or <see langword="null"/> when absent.
    /// </summary>
    public CBAdESCrlIdentifier? CrlIdentifier { get; }


    /// <summary>
    /// Disposes <see cref="Digest"/>.
    /// </summary>
    public void Dispose()
    {
        Digest.Dispose();
    }
}


/// <summary>
/// The <c>CRLId</c> type of Annex A.1.1, Table A.1 — identifies a referenced CRL: a mandatory issuer and
/// issuance time, plus two optional hints.
/// </summary>
/// <remarks>
/// <para>CDDL (Annex A.1.1):</para>
/// <code>
/// CRLId = {
///     1 =&gt; bstr,           ; Issuer
///     2 =&gt; #6.0(tstr),     ; IssueTime
///     ? 3 =&gt; uint,         ; Number
///     ? 4 =&gt; #6.32(tstr)   ; LocationHint
/// }
/// </code>
/// <para>
/// <strong>CB-A.1.1-14.</strong> "The <c>crlId</c> member of the items within the <c>crlRefs</c> array shall
/// include the name issuer in its <c>issuer</c> member" — the DER-encoded issuer <c>Name</c>, carried as a
/// <strong>borrowed</strong> view in <see cref="Issuer"/>.
/// </para>
/// <para>
/// <strong>CB-A.1.1-15.</strong> "... shall include the time when the CRL was issued in its <c>issueTime</c>
/// member" — a CBOR tag-0 (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.1">RFC 8949
/// §3.4.1</see>) date-time.
/// </para>
/// <para>
/// <strong>CB-A.1.1-16.</strong> "... may include the number of the CRL in its <c>number</c> member" — NOTE 3
/// (Annex A.1.1) clarifies this is "an optional hint helping to get the CRL whose digest matches the value
/// present in the reference", not authoritative.
/// </para>
/// <para>
/// <strong>CB-A.1.1-17.</strong> "The <c>crlId</c>'s <c>uri</c> member shall indicate one place where the
/// referenced CRL can be found" — NOTE 4 (Annex A.1.1) clarifies this is a retrieval hint, not authoritative,
/// matching <see cref="CBAdESCertificateReference.LocationHint"/>'s CB-A.1.1-08 convention.
/// </para>
/// <para>
/// <strong>Ownership.</strong> <see cref="Issuer"/> is a borrowed view — the caller (creation path) or the
/// wire-bytes source (parse path) owns the underlying memory — so this type owns nothing of its own and
/// therefore implements no <see cref="IDisposable"/>, matching <see cref="CBAdESPkiObject"/>'s convention.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESCrlIdentifier: {Issuer.Length} bytes issuer, IssueTime={IssueTime}")]
public sealed record CBAdESCrlIdentifier
{
    /// <summary>The <c>issuer</c> member's map key (Table A.1, Annex A.1.1, <c>CRLId</c>).</summary>
    public const int IssuerKey = 1;

    /// <summary>The <c>issueTime</c> member's map key (Table A.1, Annex A.1.1, <c>CRLId</c>).</summary>
    public const int IssueTimeKey = 2;

    /// <summary>The <c>number</c> member's map key (Table A.1, Annex A.1.1, <c>CRLId</c>).</summary>
    public const int NumberKey = 3;

    /// <summary>The <c>uri</c> member's map key (Table A.1, Annex A.1.1, <c>CRLId</c>).</summary>
    public const int LocationHintKey = 4;

    /// <summary>
    /// Gets the mandatory <c>issuer</c> member: the DER-encoded issuer <c>Name</c> of the CRL (CB-A.1.1-14).
    /// <strong>Borrowed</strong> view — the caller (creation path) or the wire-bytes source (parse path) owns
    /// the underlying memory.
    /// </summary>
    public required ReadOnlyMemory<byte> Issuer { get; init; }

    /// <summary>
    /// Gets the mandatory <c>issueTime</c> member: the date and time of issuance of the CRL (CB-A.1.1-15).
    /// </summary>
    public required DateTimeOffset IssueTime { get; init; }

    /// <summary>
    /// Gets the optional <c>number</c> member: the issuance number of the CRL, a hint (CB-A.1.1-16), or
    /// <see langword="null"/> when absent.
    /// </summary>
    public ulong? Number { get; init; }

    /// <summary>
    /// Gets the optional <c>uri</c> member: a retrieval hint (CB-A.1.1-17), or <see langword="null"/> when
    /// absent.
    /// </summary>
    public Uri? LocationHint { get; init; }
}


/// <summary>
/// The <c>OCSPRef</c> type of Annex A.1.1, Table A.1 — one reference to one OCSP response (CB-A.1.1-20): a
/// mandatory digest pair over the full DER-encoded <c>OCSPResponse</c> plus a mandatory identifier.
/// </summary>
/// <remarks>
/// <para>CDDL (Annex A.1.1):</para>
/// <code>
/// OCSPRef = {
///     1 =&gt; DigAlgVal,  ; HashAlgorithm + Digest
///     2 =&gt; OCSPId       ; OcspIdentifier
/// }
/// </code>
/// <para>
/// <c>digAlgVal</c>'s two-element array is flattened onto this record as <see cref="HashAlgorithm"/> and
/// <see cref="Digest"/>, mirroring <see cref="CBAdESCrlReference"/>'s and
/// <see cref="CBAdESSignaturePolicyIdentifier"/>'s flattening of the same <c>[hashAlg, hashValue]</c> shape.
/// </para>
/// <para>
/// <strong>CB-A.1.1-28.</strong> "The <c>digAlgVal</c> member within the <c>ocspRefs</c> array shall contain
/// indication of a digest algorithm, and the digest value of the DER-encoded <c>OCSPResponse</c> field defined
/// in <see href="https://www.rfc-editor.org/rfc/rfc6960">IETF RFC 6960</see>, wrapped in a CBOR byte string" —
/// the digest covers the full DER <c>OCSPResponse</c>, not just its <c>ResponderID</c> or
/// <c>tbsResponseData</c>, computed exclusively through the registered digest delegate.
/// </para>
/// <para>
/// <strong><c>ocspId</c> is mandatory, unlike <c>CRLRef</c>'s <c>crlId</c>.</strong> The CDDL's <c>2 =&gt;
/// OCSPId</c> carries no <c>?</c> — every <c>OCSPRef</c> shall carry an <see cref="OcspIdentifier"/>.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Owns <see cref="Digest"/>. Disposing this instance disposes it;
/// <see cref="OcspIdentifier"/> owns no disposable resources of its own.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESOcspReference: HashAlgorithm={HashAlgorithm}")]
public sealed record CBAdESOcspReference: IDisposable
{
    /// <summary>The <c>digAlgVal</c> member's map key (Table A.1, Annex A.1.1, <c>OCSPRef</c>).</summary>
    public const int DigAlgValKey = 1;

    /// <summary>The <c>ocspId</c> member's map key (Table A.1, Annex A.1.1, <c>OCSPRef</c>).</summary>
    public const int OcspIdentifierKey = 2;

    /// <summary>
    /// Initializes a new <see cref="CBAdESOcspReference"/>. Ownership of <paramref name="digest"/> transfers to
    /// this instance.
    /// </summary>
    /// <param name="hashAlgorithm">The <c>digAlgVal.hashAlg</c> element — the digest algorithm identifier.</param>
    /// <param name="digest">
    /// The <c>digAlgVal.hashValue</c> element — the digest of the full DER-encoded <c>OCSPResponse</c>
    /// (CB-A.1.1-28).
    /// </param>
    /// <param name="ocspIdentifier">The mandatory <c>ocspId</c> member.</param>
    /// <exception cref="ArgumentNullException">
    /// When <paramref name="hashAlgorithm"/>, <paramref name="digest"/>, or <paramref name="ocspIdentifier"/> is
    /// <see langword="null"/>.
    /// </exception>
    public CBAdESOcspReference(
        CBAdESDigestAlgorithmIdentifier hashAlgorithm,
        DigestValue digest,
        CBAdESOcspIdentifier ocspIdentifier)
    {
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(digest);
        ArgumentNullException.ThrowIfNull(ocspIdentifier);

        HashAlgorithm = hashAlgorithm;
        Digest = digest;
        OcspIdentifier = ocspIdentifier;
    }


    /// <summary>Gets the <c>digAlgVal.hashAlg</c> element — the digest algorithm identifier.</summary>
    public CBAdESDigestAlgorithmIdentifier HashAlgorithm { get; }

    /// <summary>
    /// Gets the <c>digAlgVal.hashValue</c> element — the digest of the full DER-encoded <c>OCSPResponse</c>
    /// (CB-A.1.1-28). Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public DigestValue Digest { get; }

    /// <summary>Gets the mandatory <c>ocspId</c> member.</summary>
    public CBAdESOcspIdentifier OcspIdentifier { get; }


    /// <summary>
    /// Disposes <see cref="Digest"/>.
    /// </summary>
    public void Dispose()
    {
        Digest.Dispose();
    }
}


/// <summary>
/// The <c>OCSPId</c> type of Annex A.1.1, Table A.1 — identifies a referenced OCSP response: a mandatory
/// responder identifier and generation time, plus an optional hint.
/// </summary>
/// <remarks>
/// <para>CDDL (Annex A.1.1):</para>
/// <code>
/// OCSPId = {
///     1 =&gt; ResponderIdChoice,  ; Responder
///     2 =&gt; #6.0(tstr),         ; ProducedAt
///     ? 3 =&gt; #6.32(tstr)       ; LocationHint
/// }
/// </code>
/// <para>
/// <strong>CB-A.1.1-21.</strong> "The <c>ocspId</c> member of the items within the <c>ocspRefs</c> array shall
/// include an identifier of the responder wrapped in a CBOR byte string" — <see cref="Responder"/>, see
/// <see cref="CBAdESOcspResponderIdentifier"/> for the by-name/by-key closed sum this member selects between
/// (CB-A.1.1-22/23).
/// </para>
/// <para>
/// <strong>CB-A.1.1-25.</strong> "... shall include the generation time of the OCSP response in its
/// <c>producedAt</c> member" — a CBOR tag-0 date-time.
/// </para>
/// <para>
/// <strong>CB-A.1.1-26 (owned by a later stage, not this model).</strong> "The value in <c>ocspId</c>'s
/// <c>producedAt</c> member shall indicate the same time as the time indicated by the <c>ProducedAt</c> field
/// of the referenced OCSP response." This type cannot see the OCSP response it references, so it cannot
/// self-enforce the cross-check; <see cref="ProducedAt"/> is supplied by the caller (creation path) or read
/// from the wire (parse path) and compared against the actual parsed <c>OCSPResponse</c> at a later validation
/// stage.
/// </para>
/// <para>
/// <strong>CB-A.1.1-27.</strong> "The <c>ocspId</c>'s <c>uri</c> member shall indicate one place where the
/// referenced OCSP response can be found" — NOTE 5 (Annex A.1.1) clarifies this is "not the address where the
/// OCSP service can be reached" and is intended as a retrieval hint, matching
/// <see cref="CBAdESCertificateReference.LocationHint"/>'s CB-A.1.1-08 convention.
/// </para>
/// <para>
/// <strong>Ownership.</strong> <see cref="Responder"/>'s sibling records carry only borrowed byte views (see
/// <see cref="CBAdESOcspResponderIdentifier"/>), so this type owns nothing of its own and therefore implements
/// no <see cref="IDisposable"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESOcspIdentifier: {Responder}, ProducedAt={ProducedAt}")]
public sealed record CBAdESOcspIdentifier
{
    /// <summary>The <c>responderChoice</c> member's map key (Table A.1, Annex A.1.1, <c>OCSPId</c>).</summary>
    public const int ResponderKey = 1;

    /// <summary>The <c>producedAt</c> member's map key (Table A.1, Annex A.1.1, <c>OCSPId</c>).</summary>
    public const int ProducedAtKey = 2;

    /// <summary>The <c>uri</c> member's map key (Table A.1, Annex A.1.1, <c>OCSPId</c> map).</summary>
    public const int LocationHintKey = 3;

    /// <summary>
    /// Initializes a new <see cref="CBAdESOcspIdentifier"/>.
    /// </summary>
    /// <param name="responder">The mandatory responder identifier (CB-A.1.1-21).</param>
    /// <param name="producedAt">The mandatory OCSP response generation time (CB-A.1.1-25).</param>
    /// <param name="locationHint">The optional retrieval hint, or <see langword="null"/> to omit it (CB-A.1.1-27).</param>
    /// <exception cref="ArgumentNullException">When <paramref name="responder"/> is <see langword="null"/>.</exception>
    public CBAdESOcspIdentifier(
        CBAdESOcspResponderIdentifier responder,
        DateTimeOffset producedAt,
        Uri? locationHint = null)
    {
        ArgumentNullException.ThrowIfNull(responder);

        Responder = responder;
        ProducedAt = producedAt;
        LocationHint = locationHint;
    }


    /// <summary>Gets the mandatory responder identifier (CB-A.1.1-21). See <see cref="CBAdESOcspResponderIdentifier"/>.</summary>
    public CBAdESOcspResponderIdentifier Responder { get; }

    /// <summary>
    /// Gets the mandatory OCSP response generation time (CB-A.1.1-25). See the CB-A.1.1-26 remarks on this
    /// type for the cross-check owned by a later validation stage.
    /// </summary>
    public DateTimeOffset ProducedAt { get; }

    /// <summary>
    /// Gets the optional retrieval hint (CB-A.1.1-27), or <see langword="null"/> when absent.
    /// </summary>
    public Uri? LocationHint { get; }
}


/// <summary>
/// The <c>ResponderIdChoice</c> type of Annex A.1.1 — a closed two-arm sum identifying an OCSP responder,
/// either by name or by public-key digest. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// <para>CDDL (Annex A.1.1):</para>
/// <code>
/// ResponderIdChoice = (
///     1 =&gt; bstr //  ; ByName
///     2 =&gt; bstr      ; ByKey
/// )
/// </code>
/// <para>
/// <strong>CB-A.1.1-22/23.</strong> "If the identifier is the digest of the server's public key computed as
/// mandated in IETF RFC 6960 [14], the member <c>responderIdByKey</c> shall be present. If the identifier is
/// the DER-encoded name of the responder, the member <c>responderIdByName</c> shall be present" — mutually
/// exclusive selection rules, modelled as a two-case discriminated union rather than two independently-nullable
/// fields, matching <see href="https://www.rfc-editor.org/rfc/rfc6960">IETF RFC 6960</see>'s own <c>ResponderID
/// ::= CHOICE { byName [1] Name, byKey [2] KeyHash }</c> ASN.1 type this CDDL group sources from.
/// </para>
/// </remarks>
public abstract record CBAdESOcspResponderIdentifier
{
    /// <summary>The <c>responderIdByName</c> choice arm's key (Table A.1, Annex A.1.1, <c>ResponderIdChoice</c>).</summary>
    public const int ByNameKey = 1;

    /// <summary>The <c>responderIdByKey</c> choice arm's key (Table A.1, Annex A.1.1, <c>ResponderIdChoice</c>).</summary>
    public const int ByKeyKey = 2;

    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESOcspResponderIdentifier()
    {
    }
}


/// <summary>
/// The <c>responderIdByName</c> arm of <c>ResponderIdChoice</c> (Annex A.1.1, key 1): identifies the OCSP
/// responder by its DER-encoded name (CB-A.1.1-23).
/// </summary>
/// <param name="Name">
/// The DER-encoded name of the responder, wrapped in the CBOR byte string. <strong>Borrowed</strong> view — the
/// caller (creation path) or the wire-bytes source (parse path) owns the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESOcspResponderIdentifierByName: {Name.Length} bytes")]
public sealed record CBAdESOcspResponderIdentifierByName(ReadOnlyMemory<byte> Name)
    : CBAdESOcspResponderIdentifier;


/// <summary>
/// The <c>responderIdByKey</c> arm of <c>ResponderIdChoice</c> (Annex A.1.1, key 2): identifies the OCSP
/// responder by the digest of its public key (CB-A.1.1-22).
/// </summary>
/// <remarks>
/// <strong>D8 (contract R-6, RULED).</strong> The prose additionally says: "If the responder is identified by
/// the digest of the server's public key computed as mandated in IETF RFC 6960 [14], then the base64 [17]
/// encoding of the DER-encoded of <c>byKey</c> field specified in IETF RFC 6960 [14] shall appear within the
/// <c>responderID</c>'s <c>byKey</c> member." Every other digest/DER field in this annex (<c>x5t</c>,
/// <c>crlId.issuer</c>, both <c>digAlgVal</c> pairs) is specified as raw bytes with no base64 step, and the
/// CDDL type of this arm is a plain <c>bstr</c> — a raw CBOR byte string, not CBOR text. Ruled:
/// <see cref="KeyDigest"/> carries the raw DER
/// <see href="https://www.rfc-editor.org/rfc/rfc6960">IETF RFC 6960</see> <c>ResponderID.byKey</c>
/// (<c>KeyHash</c>) bytes directly in the <c>bstr</c> — CBOR needs no base64 step; the base64 wording is a
/// JAdES copy-residue, flagged for ETSI feedback, not implemented literally.
/// </remarks>
/// <param name="KeyDigest">
/// The raw DER <c>KeyHash</c> bytes (RFC 6960 <c>ResponderID.byKey</c>). <strong>Borrowed</strong> view — the
/// caller (creation path) or the wire-bytes source (parse path) owns the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESOcspResponderIdentifierByKey: {KeyDigest.Length} bytes")]
public sealed record CBAdESOcspResponderIdentifierByKey(ReadOnlyMemory<byte> KeyDigest)
    : CBAdESOcspResponderIdentifier;
