using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The JAdES JWS Protected Header signed-header-set aggregate: every profiled JOSE header parameter clause 5.1
/// of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see> reuses/restricts, plus every new signed header parameter clause 5.2 defines.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Placement.</strong> Layer
/// placement and header-set composition are JWS-structure semantics, not PKI semantics, so this aggregate lives
/// in <c>Verifiable.JCose</c> beside <see cref="Jose"/>/<see cref="JwsMessage"/> rather than in
/// <c>Verifiable.Cryptography.Pki</c> beside the component models it holds — mirroring
/// <see cref="CBAdESProtectedHeaders"/>'s identical split. Every clause-5.2 member below is one of the
/// existing Pki models (<see cref="AdESCertificateThumbprint"/>, <see cref="AdESCertificateThumbprints"/>,
/// <see cref="AdESSignerCommitments"/>, <see cref="AdESSignatureProductionPlace"/>,
/// <see cref="AdESSignerAttributes"/>, <see cref="AdESTimestampContainer"/>,
/// <see cref="AdESSignaturePolicyIdentifier"/>, <see cref="JAdESDetachedDataObjectReference"/>), reached
/// through the existing <c>Verifiable.JCose</c> → <c>Verifiable.Cryptography</c> project reference — this type
/// does not duplicate their shape, only aggregates them at the JWS Protected Header layer.
/// </para>
/// <para>
/// <strong>Scope: LOCAL shape only, no trust state.</strong> This is a MODEL — the signed-component surface
/// this type charters, not a creation/validation orchestrator (a distinct type) and not a wire-parsed, trust-carrying type (no
/// <c>Unverified*</c>/<see cref="Verified{T}"/> promotion applies here; that promotion machinery governs surfaces that carry
/// verification state, which this aggregate does not yet). This constructor enforces exactly the invariants a
/// single member can violate on its own — <see cref="Algorithm"/>'s non-emptiness, non-empty optional
/// collections — deliberately NOT cross-header conformance (the four-way signing-certificate-identification
/// disjunction of JA-5.1.7-04, <see cref="ContentType"/>'s SHOULD-NOT-with-<see cref="SigD"/> coupling of
/// JA-5.1.3-03, <c>adoTst</c>'s forbidden <c>canonAlg</c> of JA-5.2.6-08, the <c>b64</c>=false coupling of
/// JA-5.1.10-04, ...) — a future JAdES header-rules type (mirroring <see cref="CBAdESHeaderRules"/>) owns every
/// one of those, consumed by both the creation path (throw posture) and the validation path (collect posture).
/// This split is deliberate: a validator parsing untrusted wire bytes must be able to represent a well-formed
/// but non-conformant parsed message, which a constructor-side cross-header guard would make impossible to hold
/// in memory at all.
/// </para>
/// <para>
/// <strong>No <c>x5t</c> member — forbidden by construction; the read path stays a named forward obligation.</strong>
/// "JAdES signatures shall not contain the <c>x5t</c> header parameter specified in clause 4.1.7 of IETF RFC
/// 7515" (JA-5.1.6-01) is an outright, unconditional document-level prohibition — not a "sometimes legal" case
/// like the cross-header rules above. This aggregate exposes no <c>X5t</c> property at all, so a well-formed
/// <see cref="JAdESProtectedHeaders"/> instance cannot represent the forbidden parameter, a stronger guarantee
/// than a runtime check could give for the CREATION path. The READ path is different: a wire decoder
/// parsing untrusted JSON will encounter a present <c>x5t</c> member on some non-conformant wire message, and
/// that decoder — not yet built — must COLLECT the violation (JA-5.1.6-01's own SHALL, reported rather than
/// silently dropped) at decode time, the same "well-formed but non-conformant parsed message" posture this
/// type's own cross-header rules use elsewhere in these remarks. This is a forward obligation on that future
/// decoder, not silence: nothing here builds it, but nothing here forecloses it either.
/// </para>
/// <para>
/// <strong><see cref="IssuedAt"/>/<see cref="SigT"/>.</strong> <c>iat</c> and <c>sigT</c> both
/// carry a claimed signing time (<see cref="JAdESClaimedSigningTime"/>) but are mandatory-optional-flipped as of
/// 2025-07-15T00:00:00Z, a date already passed: creation surfaces treat <see cref="IssuedAt"/> as MANDATORY;
/// <see cref="SigT"/> is legacy/validation-only, read-tolerated but never emitted by a creation surface built
/// against this document version. Both stay independently nullable here — the mandatory/legacy split is a
/// validation-layer concern, not this constructor's.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="X5tHashS256"/>, <see cref="X5tHashO"/>,
/// <see cref="SigX5ts"/>, <see cref="PayloadTimestamps"/>, <see cref="SignaturePolicyIdentifier"/>, and
/// <see cref="SigD"/> when present (and disposable) — <see cref="Dispose"/> disposes each.
/// <see cref="ContentType"/>, <see cref="KeyId"/>, <see cref="X5U"/>, <see cref="X5Chain"/>,
/// <see cref="CriticalLabels"/>, <see cref="B64"/>, <see cref="IssuedAt"/>, <see cref="SigT"/>,
/// <see cref="SignerCommitments"/>, <see cref="SignatureProductionPlace"/>, and <see cref="SignerAttributes"/>
/// own no disposable resources of their own. No separate disposed-flag field is kept here, mirroring
/// <see cref="CBAdESProtectedHeaders"/>'s identical reasoning: <see cref="Dispose"/> forwards unconditionally
/// and relies on every owned member's own <c>Dispose</c> being idempotent.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESProtectedHeaders: alg={Algorithm}, iat={IssuedAt}")]
public sealed class JAdESProtectedHeaders: IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="JAdESProtectedHeaders"/>. Ownership of every disposable member supplied
    /// non-null (see the type remarks) transfers to this instance.
    /// </summary>
    /// <param name="algorithm">
    /// The <c>alg</c> member (JA-5.1.2-01/-02/-03/-05): the IANA "JSON Web Signature and Encryption Algorithms"
    /// identifier of the signature algorithm (see <see cref="WellKnownJwaValues"/>).
    /// </param>
    /// <param name="contentType">The <c>cty</c> member, or <see langword="null"/> to omit it — see <see cref="ContentType"/>.</param>
    /// <param name="keyId">The <c>kid</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="x5u">The <c>x5u</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="x5tHashS256">The <c>x5t#S256</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="x5chain">The <c>x5c</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="criticalLabels">The <c>crit</c> member, in wire order, or <see langword="null"/> to omit it. When present, must be non-empty (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11">RFC 7515 §4.1.11</see>: "Producers MUST NOT use the empty list \"[]\" as the \"crit\" value").</param>
    /// <param name="b64">The <c>b64</c> member, or <see langword="null"/> to mean absent (equivalent to <see langword="true"/> per RFC 7797 §3).</param>
    /// <param name="issuedAt">The <c>iat</c> member, or <see langword="null"/> to omit it — see the type remarks above.</param>
    /// <param name="sigT">The legacy <c>sigT</c> member, or <see langword="null"/> to omit it — see the type remarks above.</param>
    /// <param name="x5tHashO">The <c>x5t#o</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="sigX5ts">The <c>sigX5ts</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="signerCommitments">The <c>srCms</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="signatureProductionPlace">The <c>sigPl</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="signerAttributes">The <c>srAts</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="payloadTimestamps">The <c>adoTst</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="signaturePolicyIdentifier">The <c>sigPId</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="sigD">The <c>sigD</c> member, or <see langword="null"/> to omit it.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="algorithm"/> is <see langword="null"/> or empty; or <paramref name="criticalLabels"/> is
    /// non-null but empty.
    /// </exception>
    public JAdESProtectedHeaders(
        string algorithm,
        string? contentType = null,
        string? keyId = null,
        Uri? x5u = null,
        DigestValue? x5tHashS256 = null,
        IReadOnlyList<ReadOnlyMemory<byte>>? x5chain = null,
        IReadOnlyList<string>? criticalLabels = null,
        bool? b64 = null,
        JAdESClaimedSigningTime? issuedAt = null,
        JAdESClaimedSigningTime? sigT = null,
        AdESCertificateThumbprint? x5tHashO = null,
        AdESCertificateThumbprints? sigX5ts = null,
        AdESSignerCommitments? signerCommitments = null,
        AdESSignatureProductionPlace? signatureProductionPlace = null,
        AdESSignerAttributes? signerAttributes = null,
        AdESTimestampContainer? payloadTimestamps = null,
        AdESSignaturePolicyIdentifier? signaturePolicyIdentifier = null,
        JAdESDetachedDataObjectReference? sigD = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);

        if(criticalLabels is not null && criticalLabels.Count == 0)
        {
            throw new ArgumentException(
                "When present, 'crit' shall be a non-empty array (IETF RFC 7515 §4.1.11).",
                nameof(criticalLabels));
        }

        Algorithm = algorithm;
        ContentType = contentType;
        KeyId = keyId;
        X5U = x5u;
        X5tHashS256 = x5tHashS256;
        X5Chain = x5chain;
        CriticalLabels = criticalLabels;
        B64 = b64;
        IssuedAt = issuedAt;
        SigT = sigT;
        X5tHashO = x5tHashO;
        SigX5ts = sigX5ts;
        SignerCommitments = signerCommitments;
        SignatureProductionPlace = signatureProductionPlace;
        SignerAttributes = signerAttributes;
        PayloadTimestamps = payloadTimestamps;
        SignaturePolicyIdentifier = signaturePolicyIdentifier;
        SigD = sigD;
    }


    /// <summary>
    /// Gets the <c>alg</c> member (JA-5.1.2-01/-02/-03): the IANA "JSON Web Signature and Encryption Algorithms"
    /// identifier of the signature algorithm (JA-5.1.2-05). See <see cref="WellKnownJwaValues"/> for the
    /// identifier registry (ETSI TS 119 312's recommended-algorithm pointer, JA-5.1.2-04, is a policy-layer
    /// concern external to this carrier).
    /// </summary>
    public string Algorithm { get; }

    /// <summary>
    /// Gets the <c>cty</c> member (JA-5.1.3-01/-02/-06), or <see langword="null"/> when absent. Should not be
    /// present when <see cref="SigD"/> is present (JA-5.1.3-03) or the content type is implied (JA-5.1.3-04);
    /// shall not be present when the JWS Payload is a (counter-signed) signature (JA-5.1.3-05) — enforced by a
    /// future JAdES header-rules type, not by this constructor (see the type remarks).
    /// </summary>
    public string? ContentType { get; }

    /// <summary>
    /// Gets the <c>kid</c> member (JA-5.1.4-01/-02/-04/-05): a hint identifying the signing certificate, per
    /// RFC 7515 §4.1.4 — should be the base64 encoding of a DER-encoded <c>IssuerSerial</c> (RFC 5035,
    /// JA-5.1.4-03). <see langword="null"/> when absent.
    /// </summary>
    public string? KeyId { get; }

    /// <summary>
    /// Gets the <c>x5u</c> member (JA-5.1.5-01/-02/-03/-04): a URI hint for retrieving the signing certificate,
    /// per RFC 7515 §4.1.5. <see langword="null"/> when absent.
    /// </summary>
    public Uri? X5U { get; }

    /// <summary>
    /// Gets the <c>x5t#S256</c> member (JA-5.1.7-01/-02/-03): the signing certificate's SHA-256 digest, per RFC
    /// 7515 §4.1.8 — the algorithm is fixed by the header parameter's own name, unlike <see cref="X5tHashO"/>.
    /// Owned by this instance when present; disposed via <see cref="Dispose"/>. One of the four disjunctive
    /// signing-certificate-identification options a JAdES signature carries at least one of (JA-5.1.7-04,
    /// enforced by a future JAdES header-rules type, not by this constructor). <see langword="null"/> when
    /// absent.
    /// </summary>
    public DigestValue? X5tHashS256 { get; }

    /// <summary>
    /// Gets the <c>x5c</c> member (JA-5.1.8-01/-02/-03): the signing certificate chain, per RFC 7515 §4.1.6 —
    /// each entry a base64-encoded (not base64url) DER certificate, the signing certificate first.
    /// <see langword="null"/> when absent.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>>? X5Chain { get; }

    /// <summary>
    /// Gets the <c>crit</c> member (JA-5.1.9-01/-02/-03), in wire order, or <see langword="null"/> when absent.
    /// Non-empty when present (constructor-enforced, RFC 7515 §4.1.11). Shall include <c>"sigD"</c> whenever
    /// <see cref="SigD"/> is present (JA-5.1.9-04/-05) — enforced by a future JAdES header-rules type, not by
    /// this constructor.
    /// </summary>
    public IReadOnlyList<string>? CriticalLabels { get; }

    /// <summary>
    /// Gets the <c>b64</c> member (JA-5.1.10-01/-02/-03), per RFC 7797 §3, or <see langword="null"/> when
    /// absent (equivalent to <see langword="true"/>). Shall be present and <see langword="false"/> when
    /// <see cref="SigD"/> uses the <c>HttpHeaders</c> mechanism (JA-5.1.10-04) — enforced by a future JAdES
    /// header-rules type, not by this constructor.
    /// </summary>
    public bool? B64 { get; }

    /// <summary>
    /// Gets the <c>iat</c> member (JA-5.1.11-01/-02): the claimed signing time, RFC 7519 §4.1.6's
    /// <c>NumericDateValue</c> wire form. <see langword="null"/> when absent — a legal, non-conformant local
    /// shape when creation-mandatory — see the type remarks.
    /// </summary>
    public JAdESClaimedSigningTime? IssuedAt { get; }

    /// <summary>
    /// Gets the legacy <c>sigT</c> member (clause 5.2.1, JA-5.2.1-01/-02): the claimed signing time, an RFC
    /// 3339 string wire form, superseded by <see cref="IssuedAt"/>. <see langword="null"/> when absent.
    /// </summary>
    public JAdESClaimedSigningTime? SigT { get; }

    /// <summary>
    /// Gets the <c>x5t#o</c> member (clause 5.2.2.2, JA-5.2.2.2-01): the signing certificate's digest under an
    /// algorithm other than SHA-256. Owned by this instance when present; disposed via <see cref="Dispose"/>.
    /// One of the four disjunctive signing-certificate-identification options (JA-5.1.7-04). <see langword="null"/>
    /// when absent.
    /// </summary>
    public AdESCertificateThumbprint? X5tHashO { get; }

    /// <summary>
    /// Gets the <c>sigX5ts</c> member (clause 5.2.2.3, JA-5.2.2.3-01): the certification-path digest
    /// collection. Owned by this instance when present; disposed via <see cref="Dispose"/>. One of the four
    /// disjunctive signing-certificate-identification options (JA-5.1.7-04). <see langword="null"/> when
    /// absent.
    /// </summary>
    public AdESCertificateThumbprints? SigX5ts { get; }

    /// <summary>
    /// Gets the <c>srCms</c> member (clause 5.2.3, JA-5.2.3-01): the signer's commitments. <see langword="null"/>
    /// when absent.
    /// </summary>
    public AdESSignerCommitments? SignerCommitments { get; }

    /// <summary>
    /// Gets the <c>sigPl</c> member (clause 5.2.4, JA-5.2.4-01): the signer's production place.
    /// <see langword="null"/> when absent.
    /// </summary>
    public AdESSignatureProductionPlace? SignatureProductionPlace { get; }

    /// <summary>
    /// Gets the <c>srAts</c> member (clause 5.2.5, JA-5.2.5-01): the signer's attributes. <see langword="null"/>
    /// when absent.
    /// </summary>
    public AdESSignerAttributes? SignerAttributes { get; }

    /// <summary>
    /// Gets the <c>adoTst</c> member (clause 5.2.6, JA-5.2.6-01/-02): pre-signing time-stamp token(s) over the
    /// JWS Payload. Shall never carry a <c>canonAlg</c> member (JA-5.2.6-08) — enforced by a future JAdES
    /// header-rules type, not by this constructor. Owned by this instance when present; disposed via
    /// <see cref="Dispose"/>. <see langword="null"/> when absent.
    /// </summary>
    public AdESTimestampContainer? PayloadTimestamps { get; }

    /// <summary>
    /// Gets the <c>sigPId</c> member (clause 5.2.7.1, JA-5.2.7.1-01): the signature policy identifier. Owned by
    /// this instance when present; disposed via <see cref="Dispose"/>. <see langword="null"/> when absent.
    /// </summary>
    public AdESSignaturePolicyIdentifier? SignaturePolicyIdentifier { get; }

    /// <summary>
    /// Gets the <c>sigD</c> member (clause 5.2.8.1, JA-5.2.8.1-01): the detached-payload reference and
    /// mechanism. Mutually exclusive with an attached JWS Payload (JA-5.2.8.1-02); requires
    /// <see cref="CriticalLabels"/> to include <c>"sigD"</c> (JA-5.1.9-04/-05) — enforced by a future JAdES
    /// header-rules type, not by this constructor. Owned by this instance when present and disposable (see
    /// <see cref="JAdESObjectIdByUriReference"/>/<see cref="JAdESObjectIdByUriHashReference"/>); disposed via
    /// <see cref="Dispose"/>. <see langword="null"/> when absent.
    /// </summary>
    public JAdESDetachedDataObjectReference? SigD { get; }


    /// <summary>
    /// Disposes <see cref="X5tHashS256"/>, <see cref="X5tHashO"/>, <see cref="SigX5ts"/>,
    /// <see cref="PayloadTimestamps"/>, <see cref="SignaturePolicyIdentifier"/>, and <see cref="SigD"/> when
    /// present. See the type remarks for why no disposed-flag guard is kept.
    /// </summary>
    public void Dispose()
    {
        X5tHashS256?.Dispose();
        X5tHashO?.Dispose();
        SigX5ts?.Dispose();
        PayloadTimestamps?.Dispose();
        SignaturePolicyIdentifier?.Dispose();
        (SigD as IDisposable)?.Dispose();
    }
}
