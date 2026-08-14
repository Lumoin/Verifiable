using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>pkiOb</c> shared-syntax type common to
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.4.2</see> (CB-AdES) and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.4.2</see> (JAdES, JA-5.4.2-01) — the single opaque carrier for any PKI
/// object (an X.509 certificate, a CRL, an OCSP response, an attribute certificate, or another format — JAdES's
/// clause 5.4.2 NOTE also names an electronic time-stamp) that gets encapsulated into a signature. Reused
/// verbatim wherever either document encapsulates such an object, e.g. CB-AdES's <c>valData</c>'s
/// <c>xVals</c>/<c>rVals</c> members (clause 5.3.4).
/// </summary>
/// <remarks>
/// <para>CB-AdES CDDL (clause 5.4.2, Table 12 keys):</para>
/// <code>
/// pkiOb = {
///     1 =&gt; bstr,               ; val
///     ? 2 =&gt; #6.32(tstr),      ; encoding
///     ? 3 =&gt; #6.32(tstr)       ; specRef
/// }
/// </code>
/// <para>JAdES JSON Schema (clause 5.4.2, copied from Annex B.1):</para>
/// <code>
/// "pkiOb": {
///   "type": "object",
///   "properties": {
///     "encoding": {"type": "string", "format": "uri"},
///     "specRef": {"type": "string"},
///     "val": {"type": "string", "contentEncoding": "base64"}
///   },
///   "required": ["val"],
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// The map/wire keys for the CB-AdES CBOR encoding and the JAdES JSON member names are per-format
/// serialization facts, not part of this semantic type — see <see cref="CBAdESWireKeys.PkiObject"/> and
/// <see cref="JAdESWireNames.PkiObject"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESPkiObject({Val.Length} bytes, Encoding={Encoding})")]
public sealed record AdESPkiObject
{
    /// <summary>
    /// Gets the encapsulated PKI object's encoded octets (CB-AdES clause 5.4.2; JAdES clause 5.4.2,
    /// JA-5.4.2-03 — base64-encoded on the JAdES wire). <strong>Borrowed</strong> view — the caller (creation
    /// path) or the wire-bytes source (parse path) owns the underlying memory.
    /// </summary>
    /// <remarks>
    /// When <see cref="Encoding"/> is <see langword="null"/>, these octets are the DER-encoded ASN.1 data per
    /// both clauses (CB-AdES clause 5.4.2; JAdES clause 5.4.2, JA-5.4.2-06 — the default encoding when
    /// <c>encoding</c> is absent); otherwise they are encoded as <see cref="Encoding"/> states. Owned,
    /// pooled-memory carrier variants for the creation path are introduced alongside the stage that builds this
    /// material, and are not modelled here.
    /// </remarks>
    public required ReadOnlyMemory<byte> Val { get; init; }

    /// <summary>
    /// Gets the identifier of the encoding used for <see cref="Val"/> (CB-AdES clause 5.4.2; JAdES clause
    /// 5.4.2, JA-5.4.2-04), carried as an exact character sequence — not <see cref="Uri"/>:
    /// <see cref="System.Uri"/> normalizes on construction, and two spellings differing
    /// only by escaping or case would name different encodings — or <see langword="null"/> to mean DER, the
    /// default when <c>encoding</c> is absent (JA-5.4.2-06).
    /// </summary>
    /// <remarks>
    /// <strong>Legal value set.</strong> The
    /// legal value set for this string is
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1, clause 5.1.3</see>'s five <c>EncapsulatedPKIDataType</c> <c>Encoding</c>
    /// values — DER, BER, CER, PER, XER, each a fixed <c>http://uri.etsi.org/01903/v1.2.2#</c>-rooted URI, DER
    /// being the default this member's own <see langword="null"/> case states. This member itself stays an
    /// opaque string with NO shape validation performed against that value set — CB-AdES/JAdES's own wire
    /// type is an open <c>tstr</c>/JSON string, not a closed enumeration, so a value outside the five is a
    /// legal, if unrecognized, identifier this library still carries verbatim. <see cref="AdESPkiObjectEncoding"/>
    /// and <see cref="AdESPkiObjectEncodingUris"/> classify a carried value against the five when a caller
    /// needs that classification (<see cref="AdESPkiObjectEncodingUris.FromUri"/>).
    /// </remarks>
    public string? Encoding { get; init; }

    /// <summary>
    /// Gets the identifier of the technical specification that defines the encapsulated PKI object (CB-AdES
    /// clause 5.4.2), or <see langword="null"/> when absent, carried as an exact character sequence (rule 2 —
    /// see <see cref="Encoding"/>'s remarks for the same rationale).
    /// </summary>
    /// <remarks>
    /// <strong>SpecRef no-semantic-sentence contrast.</strong>
    /// JAdES's clause 5.4.2 types this member in its Annex B.1 schema fragment but states no semantic sentence
    /// for it: only <c>val</c> and <c>encoding</c> get one there — contrast
    /// <see cref="AdESTimestampToken.SpecRef"/>, whose own clause 5.4.3.3 DOES state "shall identify the
    /// technical specification that has defined" its token (JA-5.4.3.3-10), a sentence this member's prior
    /// JAdES-only documentation had borrowed by analogy without disclosing that clause 5.4.2 itself never says
    /// it. JAdES's Annex B.1 schema also types <c>specRef</c> as a plain <c>{"type": "string"}</c>, with no
    /// <c>"format": "uri"</c> assertion (contrast <see cref="Encoding"/>'s schema fragment, which does carry
    /// that assertion) — carried here as a plain string per the schema's own text, not upgraded to
    /// <see cref="Uri"/> to avoid asserting a constraint JAdES's own specification does not, and consistent with
    /// rule 2's exact-character-sequence treatment for identifier-valued members where the formats disagree.
    /// </remarks>
    public string? SpecRef { get; init; }
}
