using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>tstContainer</c> shared-syntax type, unifying
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3</see> (CB-AdES) and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.4.3.3</see> (JAdES, JA-5.4.3.3-01/-02/-03) — a non-empty, ordered set of
/// one or more electronic time-stamp tokens computed over the same message imprint (e.g. one token per
/// Time-Stamping Authority, for redundancy), plus an optional canonicalization-algorithm identifier that
/// governs how the time-stamped components are folded into the message-imprint input. Reused verbatim by
/// <c>sigTst</c>/<c>arcTst</c> in both specs and by <c>adoTst</c> (JAdES clause 5.2.6), and, per Annex A,
/// by <c>sigRTst</c>/<c>rfsTst</c>.
/// </summary>
/// <remarks>
/// <para>CB-AdES CDDL (clause 5.4.3.3, Table 13 keys):</para>
/// <code>
/// tstContainer = {
///     1 =&gt; [ +TstToken ]   ; tstTokens
/// }
/// </code>
/// <para>JAdES JSON Schema (clause 5.4.3.3, copied from Annex B.1):</para>
/// <code>
/// "tstContainer": {
///   "type": "object",
///   "properties": {
///     "canonAlg": {"type": "string", "format": "uri"},
///     "tstTokens": {
///       "type": "array",
///       "items": {"$ref": "#/definitions/tstToken"},
///       "minItems": 1
///     }
///   },
///   "required": ["tstTokens"],
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// <strong><see cref="TstTokens"/> non-emptiness</strong> is enforced by the validating constructor: CB-AdES's
/// CDDL <c>+</c> cardinality and JAdES's schema <c>minItems: 1</c> both require at least one entry (clause
/// 5.4.3.3 in both specifications; JA-5.4.3.3-05).
/// </para>
/// <para>
/// <strong><see cref="CanonAlg"/> is JAdES-only.</strong> CB-AdES's <c>tstContainer</c> CDDL carries only
/// <c>tstTokens</c> — no member states a canonicalization-algorithm identifier, so <see cref="CanonAlg"/> is
/// always <see langword="null"/> in a CB-AdES container, and the CBOR codec refuses to serialize a non-null
/// value. In JAdES, <see cref="CanonAlg"/> switches the message-imprint byte-selection rule
/// (JA-5.4.3.3-16/-17/-18): when present, the imprint input is the <em>canonicalized</em> bytes of
/// each time-stamped component; when absent, it is the <em>original wire bytes</em> of each time-stamped
/// component, unmodified — the same byte-exact-preservation discipline this library applies to
/// <c>etsiU</c> elements in their base64url-opaque carrier mode. Combined with
/// JA-5.4.3.3-14/-15 — the container carries no further disambiguating information, since every JAdES
/// component already lives inside the JAdES signature itself — this establishes the imprint-input selection
/// rule the message-imprint algorithms build against; it is not itself an imprint computation and is not
/// performed here.
/// </para>
/// <para>
/// <strong>Ownership.</strong> <see cref="AdESTimestampToken.Val"/> is a borrowed view today (see that
/// type's remarks), so <see cref="Dispose"/> currently has nothing of its own to release; the type still
/// implements <see cref="IDisposable"/> so callers that own a container through a composed
/// <c>adoTst</c>/<c>sigTst</c>/<c>arcTst</c> parameter need no signature change once a later stage introduces
/// owned, pooled token buffers. Idempotent.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESTimestampContainer({TstTokens.Count} tokens)")]
public sealed class AdESTimestampContainer: IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="AdESTimestampContainer"/>.
    /// </summary>
    /// <param name="tstTokens">The encapsulated time-stamp tokens, in wire order — see the remarks on <see cref="TstTokens"/>.</param>
    /// <param name="canonAlg">
    /// The canonicalization-algorithm identifier, or <see langword="null"/> to omit it — see the type remarks
    /// on <see cref="CanonAlg"/> for the byte-selection rule this switches and its JAdES-only status.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="tstTokens"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="tstTokens"/> is empty.</exception>
    public AdESTimestampContainer(IReadOnlyList<AdESTimestampToken> tstTokens, string? canonAlg = null)
    {
        ArgumentNullException.ThrowIfNull(tstTokens);

        if(tstTokens.Count == 0)
        {
            throw new ArgumentException(
                "tstContainer's 'tstTokens' member shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3, CDDL '+' cardinality; ETSI TS 119 182-1 V1.2.1, clause 5.4.3.3, JA-5.4.3.3-05, Annex B.1 schema 'minItems: 1').",
                nameof(tstTokens));
        }

        TstTokens = tstTokens;
        CanonAlg = canonAlg;
    }


    /// <summary>
    /// Gets the encapsulated time-stamp tokens (ETSI TS 119 152-1 clause 5.4.3.3; ETSI TS 119 182-1 clause
    /// 5.4.3.3, JA-5.4.3.3-05), in the order they appear on the wire. Non-empty (constructor-enforced).
    /// </summary>
    public IReadOnlyList<AdESTimestampToken> TstTokens { get; }

    /// <summary>
    /// Gets the identifier of the canonicalization algorithm (ETSI TS 119 182-1 clause 5.4.3.3,
    /// JA-5.4.3.3-16), carried as an exact character sequence — not <see cref="Uri"/> (<see cref="System.Uri"/>
    /// normalizes on construction, and the canonicalization
    /// algorithm this identifies is looked up by exact spelling) — or <see langword="null"/> when absent. See
    /// the type remarks for the JAdES-only status of this member and the message-imprint byte-selection rule
    /// it switches between.
    /// </summary>
    public string? CanonAlg { get; }


    /// <summary>
    /// Releases every owned resource reachable through <see cref="TstTokens"/>. A no-op today — see the
    /// type remarks — kept idempotent and safe to call any number of times.
    /// </summary>
    public void Dispose()
    {
    }
}


/// <summary>
/// The <c>TstToken</c>/<c>tstToken</c> shared-syntax type, unifying
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3</see> (CB-AdES) and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.4.3.3</see> (JAdES) — one electronic time-stamp token. Format-agile by
/// design: besides the encoded token octets, it carries an optional token type, an optional encoding, and an
/// optional defining-specification reference, so a future time-stamp format needs no new wire type.
/// </summary>
/// <remarks>
/// <para>CB-AdES CDDL (clause 5.4.3.3, Table 13 keys; the source spells the <c>val</c> member's separator as a
/// bare <c>:</c> rather than the document's otherwise-uniform <c>=&gt;</c> — reproduced here as <c>=&gt;</c>,
/// the form used everywhere else in the document, pending upstream confirmation):</para>
/// <code>
/// TstToken = {
///     1 =&gt; bstr,               ; val
///     ? 2 =&gt; tstr,             ; type
///     ? 3 =&gt; #6.32(tstr),      ; encoding
///     ? 4 =&gt; #6.32(tstr)       ; specRef
/// }
/// </code>
/// <para>JAdES JSON Schema (clause 5.4.3.3, copied from Annex B.1):</para>
/// <code>
/// "tstToken": {
///   "type": "object",
///   "properties": {
///     "type": {"type": "string"},
///     "encoding": {"type": "string", "format": "uri"},
///     "specRef": {"type": "string"},
///     "val": {"type": "string", "contentEncoding": "base64"}
///   },
///   "required": ["val"],
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// For an <see href="https://www.rfc-editor.org/rfc/rfc3161">IETF RFC 3161</see> time-stamp token — profiled by
/// <see href="https://www.rfc-editor.org/rfc/rfc5816">RFC 5816</see> and, per the ruling on requirement
/// CB-6.3-02 (mirrored by the JAdES-side ruling on its own equivalent requirement), currently the
/// only format both documents' baseline conformance accepts — <see cref="Type"/>, <see cref="Encoding"/>, and
/// <see cref="SpecRef"/> shall all be absent (CB-AdES clause 5.4.3.3; JAdES JA-5.4.3.3-07/-09/-11) and
/// <see cref="Val"/> shall be the DER-encoded token itself (JAdES JA-5.4.3.3-13). That narrowing is a
/// validation rule owned by a later stage, not a restriction this model imposes: the three members stay
/// available here so a differently-formatted token can still be represented.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESTimestampToken({Val.Length} bytes, Type={Type})")]
public sealed class AdESTimestampToken
{
    /// <summary>
    /// Gets the encoded time-stamp token's octets (ETSI TS 119 152-1 clause 5.4.3.3; ETSI TS 119 182-1 clause
    /// 5.4.3.3, JA-5.4.3.3-12 — base64-encoded on the JAdES wire). <strong>Borrowed</strong> view — the caller
    /// (creation path) or the wire-bytes source (parse path) owns the underlying memory.
    /// </summary>
    /// <remarks>
    /// For an RFC 3161 token these are the DER-encoded token itself (JA-5.4.3.3-13). Owned, pooled-memory
    /// carrier variants for the creation path arrive with the stage that acquires tokens from a
    /// Time-Stamping Authority, and are not modelled here.
    /// </remarks>
    public required ReadOnlyMemory<byte> Val { get; init; }

    /// <summary>
    /// Gets the string identifying the time-stamp token's type (ETSI TS 119 152-1 clause 5.4.3.3; ETSI TS 119
    /// 182-1 clause 5.4.3.3, JA-5.4.3.3-06), or <see langword="null"/> when absent — always absent for an RFC
    /// 3161 token (JA-5.4.3.3-07).
    /// </summary>
    public string? Type { get; init; }

    /// <summary>
    /// Gets the identifier of the encoding used for <see cref="Val"/> (ETSI TS 119 152-1 clause 5.4.3.3; ETSI
    /// TS 119 182-1 clause 5.4.3.3, JA-5.4.3.3-08), carried as an exact character sequence — not
    /// <see cref="Uri"/> (<see cref="System.Uri"/> normalizes on
    /// construction, collapsing spellings the "once assigned, never re-assigned" invariant treats as distinct)
    /// — or <see langword="null"/> when absent — always absent for an RFC 3161 token (JA-5.4.3.3-09). The
    /// CB-AdES wire carries this as CBOR tag 32 (RFC 8949 §3.4.4.4), applied by the CBOR codec.
    /// </summary>
    public string? Encoding { get; init; }

    /// <summary>
    /// Gets the identifier of the technical specification that defines this time-stamp token's format (ETSI TS
    /// 119 152-1 clause 5.4.3.3; ETSI TS 119 182-1 clause 5.4.3.3, JA-5.4.3.3-10), carried as an exact character
    /// sequence — not <see cref="Uri"/> — or <see langword="null"/> when
    /// absent — always absent for an RFC 3161 token (JA-5.4.3.3-11).
    /// </summary>
    /// <remarks>
    /// CB-AdES carries this as a CBOR tag-32 URI (<c>#6.32(tstr)</c>) on the wire. JAdES's own Annex B.1 schema
    /// types <c>tstToken</c>'s <c>specRef</c> member as a plain <c>{"type": "string"}</c>, with no
    /// <c>"format": "uri"</c> assertion (contrast <see cref="Encoding"/>'s schema fragment, which does carry
    /// that assertion). Which registry/format governs a given value, and whether the CBOR tag applies, is a
    /// property of the containing signature's format, enforced by that format's codec; the carrier preserves
    /// the identifier verbatim either way, per the exact-character-sequence rationale above.
    /// </remarks>
    public string? SpecRef { get; init; }
}
