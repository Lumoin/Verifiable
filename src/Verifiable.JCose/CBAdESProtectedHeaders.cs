using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The CB-AdES <c>COSE_Sign1</c> body-layer signed-header-set aggregate: every protected (signed) header
/// parameter clause 5.1 and clause 5.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> may place at the body layer of a <c>COSE_Sign1</c> structure, per Table 14
/// (clause 6.3)'s B-B column.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Placement (wavecb-contract.md ruling R-1(c), S3 coordinator ruling (1)):</strong> layer placement
/// and header-map composition are COSE-structure semantics, not PKI semantics, so this aggregate lives in
/// <c>Verifiable.JCose</c> beside <see cref="Cose"/>/<see cref="CoseSign1Message"/> rather than in
/// <c>Verifiable.Cryptography.Pki</c> beside the component models it holds. Every clause-5.2 member below is
/// one of the S1-shipped Pki models (<see cref="CBAdESCertificateThumbprints"/>,
/// <see cref="CBAdESSignerCommitments"/>, <see cref="CBAdESSignatureProductionPlace"/>,
/// <see cref="CBAdESSignerAttributes"/>, <see cref="CBAdESPayloadTimestamp"/>,
/// <see cref="CBAdESSignaturePolicyIdentifier"/>, <see cref="CBAdESDetachedObjects"/>), reached through the
/// existing <c>Verifiable.JCose</c> → <c>Verifiable.Cryptography</c> project reference — this type does not
/// duplicate their shape, only aggregates them at the COSE body layer.
/// </para>
/// <para>
/// <strong>Scope: LOCAL shape only.</strong> This type's constructor enforces exactly the invariants a single
/// member can violate on its own — non-null required members, non-empty optional collections, and label
/// collisions in <see cref="UnprofiledHeaders"/>. It deliberately does NOT enforce cross-header B-B
/// conformance (the x5t/x5ts/x5chain tri-way, the content-type/<c>sigD</c> exclusion, the <c>sigD</c>/<c>crit</c>
/// coupling, the MD5 denylist, ...) — <see cref="CBAdESHeaderRules"/> owns every one of those, consumed by both
/// the creation path (throw posture) and the validation path (collect posture, S3 coordinator ruling (2)). This
/// split is deliberate: a validator parsing untrusted wire bytes must be able to represent a well-formed but
/// non-conformant parsed message, which a constructor-side cross-header guard would make impossible to hold in
/// memory at all.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="X5T"/>, <see cref="CertificateDigests"/>,
/// <see cref="PayloadTimestamps"/>, <see cref="SignaturePolicyIdentifier"/>, and <see cref="DetachedObjects"/>
/// when present — <see cref="Dispose"/> disposes each. <see cref="ContentType"/>, <see cref="X5Chain"/>,
/// <see cref="SignerCommitments"/>, <see cref="SignatureProductionPlace"/>, <see cref="SignerAttributes"/>, and
/// <see cref="CwtClaims"/> own no disposable resources of their own (matching each wrapped model's own
/// ownership remarks — see e.g. <see cref="CBAdESUnsignedHeaders"/>'s identical split). No separate
/// disposed-flag field is kept here, mirroring <see cref="CBAdESPayloadTimestamp"/>'s reasoning: a private
/// field would participate in this record's compiler-synthesized equality, making two otherwise-equal
/// instances compare unequal once one of them is disposed, so <see cref="Dispose"/> forwards unconditionally
/// and relies on every owned member's own <c>Dispose</c> being idempotent.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESProtectedHeaders: alg={Algorithm}, iat={CwtClaims?.IssuedAt}")]
public sealed record CBAdESProtectedHeaders: IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="CBAdESProtectedHeaders"/>. Ownership of every disposable member supplied
    /// non-null (see the type remarks) transfers to this instance.
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> member — see <see cref="Algorithm"/>.</param>
    /// <param name="cwtClaims">
    /// The CWT Claims member — see <see cref="CwtClaims"/>. <see langword="null"/> is a LEGAL local shape: a
    /// wire message decoded with no <c>iat</c> (CWT Claims absent entirely, or present with no <c>iat</c>
    /// member) is a well-formed, non-conformant B-B message, not a malformed one (wavecb S3 FX-E) —
    /// <see cref="CBAdESHeaderRules.Check"/> reports the absence as <see cref="CBAdESCwtClaimsMissingViolation"/>
    /// (CB-6.3-10), never this constructor.
    /// </param>
    /// <param name="contentType">The <c>content type</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="keyId">The <c>kid</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="x5u">The <c>x5u</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="x5t">The <c>x5t</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="x5chain">The signed <c>x5chain</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="certificateDigests">The <c>x5ts</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="signerCommitments">The <c>srCms</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="signatureProductionPlace">The <c>sigPl</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="signerAttributes">The <c>srAts</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="payloadTimestamps">The <c>adoTst</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="signaturePolicyIdentifier">The <c>sigPId</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="detachedObjects">The <c>sigD</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="criticalLabels">
    /// The <c>crit</c> member, in wire order, or <see langword="null"/> to omit it. When present, must be
    /// non-empty (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>: "This
    /// parameter MUST NOT be empty"). Each entry is a <see cref="CoseHeaderLabel"/> — the general
    /// <c>int / tstr</c> label union RFC 9052 §3.1's <c>crit</c> syntax reuses unnarrowed (wavecb S3 FX-H).
    /// </param>
    /// <param name="unprofiledHeaders">
    /// The open <c>*label =&gt; value</c> extension set (CB-4.4-07, CB-6.3-03), keyed by <see cref="CoseHeaderLabel"/>
    /// with each value the label's already-encoded CBOR bytes, or <see langword="null"/> to omit it. When
    /// present, must be non-empty, and none of its <see cref="CoseHeaderIntegerLabel"/> keys may collide with a
    /// label this aggregate itself profiles (see <see cref="UnprofiledHeaders"/>) — a <see cref="CoseHeaderTextLabel"/>
    /// key never collides, since every label this aggregate profiles is itself an integer.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="criticalLabels"/> or <paramref name="unprofiledHeaders"/> is non-null but empty; or
    /// <paramref name="unprofiledHeaders"/> carries an integer-arm key colliding with a profiled label.
    /// </exception>
    public CBAdESProtectedHeaders(
        int algorithm,
        CBAdESCwtClaims? cwtClaims,
        CBAdESContentTypeIndicator? contentType = null,
        ReadOnlyMemory<byte>? keyId = null,
        Uri? x5u = null,
        CBAdESCertificateThumbprint? x5t = null,
        CBAdESX5Chain? x5chain = null,
        CBAdESCertificateThumbprints? certificateDigests = null,
        CBAdESSignerCommitments? signerCommitments = null,
        CBAdESSignatureProductionPlace? signatureProductionPlace = null,
        CBAdESSignerAttributes? signerAttributes = null,
        CBAdESPayloadTimestamp? payloadTimestamps = null,
        CBAdESSignaturePolicyIdentifier? signaturePolicyIdentifier = null,
        CBAdESDetachedObjects? detachedObjects = null,
        IReadOnlyList<CoseHeaderLabel>? criticalLabels = null,
        IReadOnlyDictionary<CoseHeaderLabel, ReadOnlyMemory<byte>>? unprofiledHeaders = null)
    {
        if(criticalLabels is not null && criticalLabels.Count == 0)
        {
            throw new ArgumentException(
                "When present, 'crit' shall be a non-empty array (IETF RFC 9052 §3.1).",
                nameof(criticalLabels));
        }

        if(unprofiledHeaders is not null)
        {
            if(unprofiledHeaders.Count == 0)
            {
                throw new ArgumentException(
                    "When present, the unprofiled-header extension set shall be non-empty.",
                    nameof(unprofiledHeaders));
            }

            foreach(CoseHeaderLabel label in unprofiledHeaders.Keys)
            {
                if(label is CoseHeaderIntegerLabel integerLabel && IsProfiledLabel(integerLabel.Value))
                {
                    throw new ArgumentException(
                        $"Label {integerLabel.Value} is profiled by this document (ETSI TS 119 152-1 V1.1.1, " +
                        "clause 4.4, CB-4.4-06/07) and shall not also be carried as an unprofiled-header " +
                        "extension entry.",
                        nameof(unprofiledHeaders));
                }
            }
        }

        Algorithm = algorithm;
        CwtClaims = cwtClaims;
        ContentType = contentType;
        KeyId = keyId;
        X5U = x5u;
        X5T = x5t;
        X5Chain = x5chain;
        CertificateDigests = certificateDigests;
        SignerCommitments = signerCommitments;
        SignatureProductionPlace = signatureProductionPlace;
        SignerAttributes = signerAttributes;
        PayloadTimestamps = payloadTimestamps;
        SignaturePolicyIdentifier = signaturePolicyIdentifier;
        DetachedObjects = detachedObjects;
        CriticalLabels = criticalLabels;
        UnprofiledHeaders = unprofiledHeaders;

        /// <summary>
        /// Determines whether <paramref name="label"/> is one of the labels this aggregate already profiles as
        /// a named member — the eight IANA COSE/RFC 9360/RFC 9597 labels this aggregate exposes as typed
        /// properties (<c>alg</c>=1, <c>crit</c>=2, <c>content type</c>=3, <c>kid</c>=4, CWT Claims=15,
        /// <c>x5chain</c>=33, <c>x5t</c>=34, <c>x5u</c>=35) — or one of the eight CB-AdES-specific labels
        /// 261-268 (<see cref="CBAdESHeaderParameters"/>). <c>x5bag</c> (32,
        /// <see cref="CoseHeaderParameters.X5Bag"/>) is deliberately NOT profiled here (wavecb S3 FX-G,
        /// CB-4.4-07): <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
        /// ETSI TS 119 152-1 V1.1.1</see> never mentions <c>x5bag</c> anywhere in its text, so it is exactly the
        /// "header parameter defined elsewhere and not further profiled by this document" case CB-4.4-07
        /// describes — a caller carrying <c>x5bag</c> on a CB-AdES signature reaches it only through
        /// <see cref="UnprofiledHeaders"/>, like any other label this document is silent on.
        /// </summary>
        /// <param name="label">The candidate label.</param>
        /// <returns><see langword="true"/> when <paramref name="label"/> is already profiled.</returns>
        static bool IsProfiledLabel(int label) => label switch
        {
            CoseHeaderParameters.Alg => true,
            CoseHeaderParameters.Crit => true,
            CoseHeaderParameters.ContentType => true,
            CoseHeaderParameters.Kid => true,
            CoseHeaderParameters.CwtClaims => true,
            CoseHeaderParameters.X5Chain => true,
            CoseHeaderParameters.X5T => true,
            CoseHeaderParameters.X5U => true,
            _ => CBAdESHeaderParameters.IsCBAdESLabel(label)
        };
    }


    /// <summary>
    /// Gets the <c>alg</c> member (label 1, mandatory, all four Table 14 levels, CB-6.3-04): the IANA COSE
    /// Algorithms identifier of the signature algorithm.
    /// </summary>
    /// <remarks>
    /// <strong>Representation decision.</strong> RFC 9052 §3.1 permits <c>alg</c> to be <c>int</c> or
    /// <c>tstr</c>, the same CDDL shape <see cref="CBAdESDigestAlgorithmIdentifier"/> models as a two-arm
    /// closed sum for digest-algorithm identifiers. This member is narrowed to <see langword="int"/> instead:
    /// every algorithm identifier this library resolves, signs with, or verifies against
    /// (<see cref="WellKnownCoseAlgorithms"/>, <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>)
    /// is an <see langword="int"/>, and no call site anywhere in this library ever produces or consumes a
    /// <c>tstr</c> signature-algorithm identifier — introducing the union's <c>tstr</c> arm here would add a
    /// producer-less, consumer-less code path. See <see cref="WellKnownCoseAlgorithms"/> for the identifier
    /// registry (ETSI TS 119 312 [19]'s recommended-algorithm pointer, CB-5.1.2-04, is a policy-layer concern
    /// external to this carrier).
    /// </remarks>
    public int Algorithm { get; }

    /// <summary>
    /// Gets the <c>content type</c> member (label 3, conditioned presence, CB-6.3-05), or <see langword="null"/>
    /// when absent. Mutually exclusive with <see cref="DetachedObjects"/> (CB-5.1.3-03) — enforced by
    /// <see cref="CBAdESHeaderRules"/>, not by this constructor (see the type remarks).
    /// </summary>
    public CBAdESContentTypeIndicator? ContentType { get; }

    /// <summary>
    /// Gets the <c>kid</c> member (label 4, may be present, CB-6.3-06): an opaque key-identifier hint, per
    /// clause 5.1.4 (SHOULD be a DER-encoded <c>IssuerSerial</c>, RFC 5035, carried uninterpreted here — the
    /// S1 opaque-bytes convention). <strong>Borrowed</strong> view — the caller (creation path) or the
    /// wire-bytes source (parse path) owns the underlying memory. <see langword="null"/> when absent.
    /// </summary>
    public ReadOnlyMemory<byte>? KeyId { get; }

    /// <summary>
    /// Gets the <c>x5u</c> member (label 35, may be present, CB-6.3-07): a URI hint for retrieving the
    /// signing certificate, per <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>.
    /// <see langword="null"/> when absent.
    /// </summary>
    public Uri? X5U { get; }

    /// <summary>
    /// Gets the <c>x5t</c> member (label 34, conditioned presence, CB-6.3-11): the signing certificate's
    /// digest, reusing the S1 <c>COSE_CertHash</c> model. Owned by this instance when present; disposed via
    /// <see cref="Dispose"/>. Part of the x5t/x5ts/x5chain tri-way (CB-5.2.2-07, D9) enforced by
    /// <see cref="CBAdESHeaderRules"/>. <see langword="null"/> when absent.
    /// </summary>
    public CBAdESCertificateThumbprint? X5T { get; }

    /// <summary>
    /// Gets the SIGNED <c>x5chain</c> member (label 33, conditioned presence, CB-6.3-08): the signing
    /// certificate chain, present here only when <c>x5chain</c> is signed (clause 5.1.8/5.2.2) — contrast with
    /// the UNSIGNED occurrence, carried opaque as a <c>uHeaders</c> element
    /// (<see cref="CBAdESUnsignedHeaderElementCertificateChain"/>, S2). Part of the x5t/x5ts/x5chain tri-way
    /// (CB-5.2.2-07, D9) enforced by <see cref="CBAdESHeaderRules"/>. <see langword="null"/> when absent.
    /// </summary>
    public CBAdESX5Chain? X5Chain { get; }

    /// <summary>
    /// Gets the <c>x5ts</c> member (label 261, conditioned presence, CB-6.3-12, clause 5.2.2): the ordered
    /// certificate-reference collection alternative to <see cref="X5T"/>/<see cref="X5Chain"/>. Owned by this
    /// instance when present; disposed via <see cref="Dispose"/>. Part of the x5t/x5ts/x5chain tri-way
    /// (CB-5.2.2-07, D9) enforced by <see cref="CBAdESHeaderRules"/>. <see langword="null"/> when absent.
    /// </summary>
    public CBAdESCertificateThumbprints? CertificateDigests { get; }

    /// <summary>
    /// Gets the <c>srCms</c> member (label 262, may be present, CB-6.3-15): the signer's commitments.
    /// <see langword="null"/> when absent.
    /// </summary>
    public CBAdESSignerCommitments? SignerCommitments { get; }

    /// <summary>
    /// Gets the <c>sigPl</c> member (label 263, may be present, CB-6.3-16): the signer's production place.
    /// <see langword="null"/> when absent.
    /// </summary>
    public CBAdESSignatureProductionPlace? SignatureProductionPlace { get; }

    /// <summary>
    /// Gets the <c>srAts</c> member (label 264, may be present, clause 5.2.5): the signer's attributes.
    /// <see langword="null"/> when absent.
    /// </summary>
    public CBAdESSignerAttributes? SignerAttributes { get; }

    /// <summary>
    /// Gets the <c>adoTst</c> member (label 265, may be present, CB-6.3-19): pre-signing time-stamp token(s)
    /// over the COSE Payload. Owned by this instance when present; disposed via <see cref="Dispose"/>.
    /// <see langword="null"/> when absent.
    /// </summary>
    public CBAdESPayloadTimestamp? PayloadTimestamps { get; }

    /// <summary>
    /// Gets the <c>sigPId</c> member (label 266, may be present, CB-6.3-17): the signature policy identifier.
    /// Gates the unsigned <c>sigPSt</c> component's presence (CB-6.3-b) — enforced by
    /// <see cref="CBAdESHeaderRules"/>, not by this constructor. Owned by this instance when present; disposed
    /// via <see cref="Dispose"/>. <see langword="null"/> when absent.
    /// </summary>
    public CBAdESSignaturePolicyIdentifier? SignaturePolicyIdentifier { get; }

    /// <summary>
    /// Gets the <c>sigD</c> member (label 267, may be present, CB-6.3-13): the detached-payload reference and
    /// mechanism. Mutually exclusive with <see cref="ContentType"/> (CB-5.1.3-03); requires
    /// <see cref="CriticalLabels"/> to include label 267 (CB-5.1.10-04); legal only with a detached payload
    /// (CB-5.2.8-03/04) — all enforced by <see cref="CBAdESHeaderRules"/>, not by this constructor. Owned by
    /// this instance when present; disposed via <see cref="Dispose"/>. <see langword="null"/> when absent.
    /// </summary>
    public CBAdESDetachedObjects? DetachedObjects { get; }

    /// <summary>
    /// Gets the CWT Claims member (label 15, shall be present at all four Table 14 levels, CB-6.3-10): the
    /// claimed signing time (<c>iat</c>), carried signed-only (D10 — no legal unsigned path exists; see the
    /// <see cref="CBAdESCwtClaims"/> remarks). <see langword="null"/> when CWT Claims is absent entirely, or
    /// present with no <c>iat</c> member — both legal, non-conformant parsed states (wavecb S3 FX-E) that
    /// <see cref="CBAdESHeaderRules.Check"/> reports as <see cref="CBAdESCwtClaimsMissingViolation"/>
    /// (CB-6.3-10), never a parse failure.
    /// </summary>
    public CBAdESCwtClaims? CwtClaims { get; }

    /// <summary>
    /// Gets the <c>crit</c> member (label 2, conditioned presence, CB-6.3-09), in wire order, or
    /// <see langword="null"/> when absent. Non-empty when present (constructor-enforced, RFC 9052 §3.1). Each
    /// entry is a <see cref="CoseHeaderLabel"/> — the general <c>int / tstr</c> union (wavecb S3 FX-H). Must
    /// include a <see cref="CoseHeaderIntegerLabel"/> equal to label 267 whenever <see cref="DetachedObjects"/>
    /// is present (CB-5.1.10-04, enforced by <see cref="CBAdESHeaderRules"/>).
    /// </summary>
    public IReadOnlyList<CoseHeaderLabel>? CriticalLabels { get; }

    /// <summary>
    /// Gets the open <c>*label =&gt; value</c> extension set (CB-4.4-07, CB-6.3-03): any RFC 9052/RFC 9360
    /// header parameter this document does not itself profile, keyed by its <see cref="CoseHeaderLabel"/> with
    /// each value the label's already-encoded CBOR bytes (at most one instance per label — CB-6.3-03's
    /// "cardinality 0 or 1", structurally guaranteed by the dictionary key space). <see langword="null"/> when
    /// absent; non-empty and collision-free with every profiled label when present (constructor-enforced — see
    /// the type remarks).
    /// </summary>
    public IReadOnlyDictionary<CoseHeaderLabel, ReadOnlyMemory<byte>>? UnprofiledHeaders { get; }


    /// <summary>
    /// Disposes <see cref="X5T"/>, <see cref="CertificateDigests"/>, <see cref="PayloadTimestamps"/>,
    /// <see cref="SignaturePolicyIdentifier"/>, and <see cref="DetachedObjects"/> when present. See the type
    /// remarks for why no disposed-flag guard is kept.
    /// </summary>
    public void Dispose()
    {
        X5T?.Dispose();
        CertificateDigests?.Dispose();
        PayloadTimestamps?.Dispose();
        SignaturePolicyIdentifier?.Dispose();
        DetachedObjects?.Dispose();
    }
}


/// <summary>
/// The mandatory CWT Claims header member (label 15, CB-6.3-10) — the claimed UTC signing time (<c>iat</c>),
/// per <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.1.9</see> and clause 6.3's additional requirement (a) (CB-6.3-a).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Not <see cref="CwtPayload"/>.</strong> <see cref="CwtPayload"/> is a general, untyped
/// <see cref="Dictionary{TKey, TValue}"/> bag with no required-ness or type safety of its own — CB-AdES's
/// contract is stricter: <c>iat</c> is MANDATORY at every Table 14 level (CB-6.3-10), carries the caller's
/// claimed UTC signing instant (never an ambient clock read — CB-6.3-a, the entropy/no-ambient-clock working
/// convention), and is carried signed-only (D10, wavecb-contract.md R-6: "no legal unsigned path exists" for
/// the tension between CB-5.1.9-01's "signed or unsigned" and CB-5.1.9-06's "shall be incorporated ... as a
/// signed header parameter"). A strongly-typed record enforces the mandatory/UTC shape at compile time and
/// construction, exactly like every other required-member CB-AdES component this wave models (e.g.
/// <see cref="CBAdESSignaturePolicyIdentifier"/>'s required <c>id</c>/<c>digAlgVal</c>) — reusing the untyped
/// <see cref="CwtPayload"/> bag here would let a caller build a CB-AdES signature with no <c>iat</c> at all, or
/// with the wrong CBOR type, and only fail at the CBOR codec layer instead of at the point of construction.
/// The RFC 8392 <c>iat</c> claim key (<see cref="WellKnownCwtClaimNames.Iat"/>, <c>6</c>) and its
/// <c>NumericDate</c> wire encoding remain the CBOR codec's concern, not this model's — mirroring every other
/// S1/S2 component's decoded-model/wire-codec split.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESCwtClaims: IssuedAt={IssuedAt}")]
public sealed record CBAdESCwtClaims
{
    /// <summary>
    /// Initializes a new <see cref="CBAdESCwtClaims"/>.
    /// </summary>
    /// <param name="issuedAt">
    /// The claimed UTC time at which the signer performed the signing process (CB-6.3-a) — caller-supplied,
    /// never an ambient clock read. Must carry a zero UTC offset.
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="issuedAt"/>'s offset is not <see cref="TimeSpan.Zero"/>.</exception>
    public CBAdESCwtClaims(DateTimeOffset issuedAt)
    {
        if(issuedAt.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "The claimed signing time shall be UTC (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional " +
                "requirement (a), CB-6.3-a); the supplied value carries a non-zero offset.",
                nameof(issuedAt));
        }

        IssuedAt = issuedAt;
    }


    /// <summary>
    /// Gets the claimed UTC signing time (<c>iat</c>, RFC 8392 clause 3.1.6, <c>NumericDate</c>) — the
    /// signer's self-asserted claim, distinct from any trusted timestamp-token component
    /// (<see cref="CBAdESPayloadTimestamp"/>, the unsigned archive/signature timestamps) (CB-5.1.9-03).
    /// </summary>
    public DateTimeOffset IssuedAt { get; }
}


/// <summary>
/// The <c>content type</c> header member's <c>tstr</c>/<c>uint</c> CDDL union
/// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>), as carried by
/// <see cref="CBAdESProtectedHeaders.ContentType"/>. A DU-ready closed sum: no external type may derive from
/// it.
/// </summary>
public abstract record CBAdESContentTypeIndicator
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESContentTypeIndicator()
    {
    }
}


/// <summary>
/// The <c>tstr</c> arm of the <c>content type</c> CDDL union — a media type, the common case (a MIME type
/// naming the COSE Payload's content).
/// </summary>
/// <param name="Value">The media-type string.</param>
[DebuggerDisplay("CBAdESContentTypeText: {Value}")]
public sealed record CBAdESContentTypeText(string Value) : CBAdESContentTypeIndicator;


/// <summary>
/// The <c>uint</c> arm of the <c>content type</c> CDDL union — a CoAP Content-Format identifier
/// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>).
/// </summary>
/// <param name="Value">The CoAP Content-Format identifier.</param>
[DebuggerDisplay("CBAdESContentTypeNumeric: {Value}")]
public sealed record CBAdESContentTypeNumeric(uint Value) : CBAdESContentTypeIndicator;


/// <summary>
/// The SIGNED <c>x5chain</c> header member's <c>COSE_X509</c> CDDL union
/// (<see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>: <c>bstr / [2*certs: bstr]</c>),
/// as carried by <see cref="CBAdESProtectedHeaders.X5Chain"/>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.1.8</see>. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// A distinct type from <see cref="CBAdESUnsignedHeaderElementCertificateChain"/> (S2), which carries the
/// UNSIGNED <c>x5chain</c> occurrence's raw encoded bytes opaque pending the S6 COSE_X509 substrate landing —
/// this SIGNED occurrence gets a structured closed sum now because it is this stage's own concern (clause
/// 5.1.8's <c>x5chain</c> signedness choice, CB-5.1.8-01/02/05), not deferred substrate capability.
/// </remarks>
public abstract record CBAdESX5Chain
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESX5Chain()
    {
    }
}


/// <summary>
/// The <c>bstr</c> arm of the <c>COSE_X509</c> CDDL union (RFC 9360 §2): a single DER-encoded certificate —
/// the signing certificate alone, no further chain.
/// </summary>
/// <param name="Certificate">
/// The DER-encoded certificate bytes. <strong>Borrowed</strong> view — the caller (creation path) or the
/// wire-bytes source (parse path) owns the underlying memory (the S1 opaque-bytes convention).
/// </param>
[DebuggerDisplay("CBAdESX5ChainSingleCertificate: {Certificate.Length} bytes")]
public sealed record CBAdESX5ChainSingleCertificate(ReadOnlyMemory<byte> Certificate) : CBAdESX5Chain;


/// <summary>
/// The <c>[2*certs: bstr]</c> arm of the <c>COSE_X509</c> CDDL union (RFC 9360 §2): an ordered chain of at
/// least <see cref="MinimumCertificateCount"/> DER-encoded certificates, the signing certificate first.
/// </summary>
[DebuggerDisplay("CBAdESX5ChainCertificatePath: {Certificates.Count} certificates")]
public sealed record CBAdESX5ChainCertificatePath : CBAdESX5Chain
{
    /// <summary>The minimum number of entries the CDDL <c>2*certs</c> occurrence operator requires (RFC 9360 §2).</summary>
    public const int MinimumCertificateCount = 2;

    /// <summary>
    /// Initializes a new <see cref="CBAdESX5ChainCertificatePath"/>.
    /// </summary>
    /// <param name="certificates">
    /// The DER-encoded certificates, in path order, the signing certificate first. Must contain at least
    /// <see cref="MinimumCertificateCount"/> entries. <strong>Borrowed</strong> view over each entry — the
    /// caller (creation path) or the wire-bytes source (parse path) owns the underlying memory.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="certificates"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="certificates"/> has fewer than <see cref="MinimumCertificateCount"/> entries.
    /// </exception>
    public CBAdESX5ChainCertificatePath(IReadOnlyList<ReadOnlyMemory<byte>> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        if(certificates.Count < MinimumCertificateCount)
        {
            throw new ArgumentException(
                $"A signed x5chain certificate path requires at least {MinimumCertificateCount} entries per " +
                $"the CDDL '2*certs' occurrence operator (IETF RFC 9360 §2); got {certificates.Count}.",
                nameof(certificates));
        }

        Certificates = certificates;
    }


    /// <summary>Gets the DER-encoded certificates, in path order, the signing certificate first.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Certificates { get; }
}
