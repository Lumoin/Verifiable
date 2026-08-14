using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>oId</c> shared-syntax type common to
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.4.1</see> (CB-AdES) and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.4.1</see> (JAdES, JA-5.4.1-01) — a permanent, unique identifier for one
/// data object, together with an optional textual description (JA-5.4.1-02) and optional pointers to documents
/// describing the identified object (JA-5.4.1-03). Reused throughout both documents wherever a technical
/// specification or data object needs a permanent identifier, e.g. CB-AdES's <c>sigPSt</c>'s <c>spDSpec</c>
/// member (clause 5.3.2) and JAdES's <c>srCms</c>'s <c>commId</c> member (clause 5.2.3, JA-5.2.3-05/-07).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Spelling, ruled.</strong> CB-AdES's clause 5.4.1 heading and prose call the type
/// <c>obId</c>, but its own CDDL production, and every other point of use of it in that document, spell it
/// <c>oId</c>. JAdES's clause 5.4.1 prose names the type <c>objectId</c> exactly
/// once ("...qualified by the instance of the <c>objectId</c> data type, can be found") against every other
/// sentence in the same sub-clause — including the immediately preceding sentence and the type's own JSON
/// Schema fragment (clause B.1) — consistently naming it <c>oId</c> (a slip sitting wholly within JAdES's own
/// clause 5.4.1, not something inherited from or introduced by CB-AdES). Both documents are ruled read as
/// <c>oId</c>; this type mirrors that wire spelling.
/// </para>
/// <para>CB-AdES CDDL (clause 5.4.1, Table 11 keys):</para>
/// <code>
/// oId = {
///     1 =&gt; #6.32(tstr),         ; id
///     ? 2 =&gt; tstr,              ; desc
///     ? 3 =&gt; [ +#6.32(tstr) ]   ; docRefs
/// }
/// </code>
/// <para>JAdES JSON Schema (clause 5.4.1, copied from Annex B.1):</para>
/// <code>
/// "oId": {
///   "type": "object",
///   "properties": {
///     "id": {"type": "string", "format": "uri"},
///     "desc": {"type": "string"},
///     "docRefs": {
///       "type": "array",
///       "items": {"type": "string", "format": "uri"},
///       "minItems": 1
///     }
///   },
///   "required": ["id"],
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// The map/wire keys for the CB-AdES CBOR encoding and the JAdES JSON member names are per-format
/// serialization facts, not part of this semantic type — see <see cref="CBAdESWireKeys.ObjectIdentifier"/> and
/// <see cref="JAdESWireNames.ObjectIdentifier"/>.
/// </para>
/// <para>
/// <strong>Equality.</strong> Equality compares this type's value — <see cref="Id"/> and <see cref="Desc"/>
/// ordinally, and <see cref="DocRefs"/> element-wise, with <see langword="null"/> and an empty list treated
/// as distinct — never list-instance identity, so two instances decoded from the same wire bytes are equal
/// regardless of which <see cref="DocRefs"/> list instance backs them. Each element compares under
/// <see cref="Uri"/> equality, which disregards the fragment — two references differing only in fragment
/// compare equal, matching how <see cref="Uri"/> itself defines "the same resource".
/// </para>
/// </remarks>
[DebuggerDisplay("AdESObjectIdentifier({Id})")]
public sealed record AdESObjectIdentifier
{
    /// <summary>
    /// Initializes a new <see cref="AdESObjectIdentifier"/>.
    /// </summary>
    /// <param name="id">The permanent identifier of the object — see the remarks on <see cref="Id"/>.</param>
    /// <param name="desc">The short, informal description of the identified object, or <see langword="null"/> to omit it.</param>
    /// <param name="docRefs">
    /// The URIs of documents that describe the identified object, or <see langword="null"/> to omit it. When
    /// present, must be non-empty (CB-AdES's CDDL <c>+</c> occurrence operator on <c>docRefs</c>; JAdES's
    /// Annex B.1 schema <c>minItems: 1</c> constraint on <c>docRefs</c>).
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="id"/> is <see langword="null"/> or empty; or <paramref name="docRefs"/> is non-null but empty.
    /// </exception>
    public AdESObjectIdentifier(string id, string? desc = null, IReadOnlyList<Uri>? docRefs = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        if(docRefs is not null && docRefs.Count == 0)
        {
            throw new ArgumentException(
                "When present, oId's 'docRefs' member shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.4.1, CDDL '+' occurrence operator; ETSI TS 119 182-1 V1.2.1, clause 5.4.1, Annex B.1 schema 'minItems: 1').",
                nameof(docRefs));
        }

        Id = id;
        Desc = desc;
        DocRefs = docRefs;
    }


    /// <summary>
    /// Gets the permanent identifier of the object (CB-AdES clause 5.4.1; JAdES clause 5.4.1, JA-5.4.1-07),
    /// carried as an exact character sequence — not <see cref="Uri"/>:
    /// <see cref="System.Uri"/> normalizes on construction, so two spellings differing only by escaping or case
    /// would name different identifiers under the "once assigned, never re-assigned" invariant below, yet
    /// compare equal as <see cref="System.Uri"/> instances. On the CB-AdES CBOR wire this value rides as a
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.4.4">CBOR tag 32 (RFC 8949 §3.4.4.4)</see>
    /// URI string — applied by that format's codec, not asserted here.
    /// </summary>
    /// <remarks>
    /// Both clauses (CB-AdES clause 5.4.1; JAdES clause 5.4.1, JA-5.4.1-06) state that once the identifier is
    /// assigned it shall not be re-assigned again — a registry-level invariant across instances minted over
    /// time, not something a single value object can self-enforce. When the identifier is an OID rather than a
    /// native URI it shall be encoded as an OID URN per
    /// <see href="https://www.rfc-editor.org/rfc/rfc3061">RFC 3061</see> (e.g. <c>urn:oid:1.2.3.4</c>;
    /// JA-5.4.1-08); when both an OID and a URI identify the same object, the URI form should be used here
    /// (JA-5.4.1-09).
    /// </remarks>
    public string Id { get; }

    /// <summary>
    /// Gets the short, informal description of the identified object (CB-AdES clause 5.4.1; JAdES clause 5.4.1,
    /// JA-5.4.1-10), or <see langword="null"/> when absent.
    /// </summary>
    public string? Desc { get; }

    /// <summary>
    /// Gets the URIs of documents that describe the identified object (CB-AdES clause 5.4.1; JAdES clause 5.4.1,
    /// JA-5.4.1-11), or <see langword="null"/> when absent. Non-empty when present (constructor-enforced — both
    /// specs' non-emptiness constraint; see the constructor's <paramref name="docRefs"/> remarks). Both formats
    /// agree this member is <see cref="Uri"/>-typed, so it keeps that type.
    /// </summary>
    public IReadOnlyList<Uri>? DocRefs { get; }


    /// <summary>
    /// Compares <see cref="Id"/> and <see cref="Desc"/> ordinally and <see cref="DocRefs"/> element-wise,
    /// suppressing the record's synthesized reference-based comparison of <see cref="DocRefs"/> so that two
    /// instances decoded from the same wire bytes compare equal regardless of which list instance backs them.
    /// </summary>
    public bool Equals(AdESObjectIdentifier? other)
    {
        return other is not null
            && string.Equals(Id, other.Id, StringComparison.Ordinal)
            && string.Equals(Desc, other.Desc, StringComparison.Ordinal)
            && DocRefsEqual(DocRefs, other.DocRefs);
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Id, StringComparer.Ordinal);
        hash.Add(Desc is null ? 0 : StringComparer.Ordinal.GetHashCode(Desc));
        hash.Add(DocRefs is null);

        if(DocRefs is not null)
        {
            foreach(Uri docRef in DocRefs)
            {
                hash.Add(docRef);
            }
        }

        return hash.ToHashCode();
    }


    /// <summary>
    /// Compares two <c>docRefs</c> members element-wise: both <see langword="null"/> compares equal, exactly
    /// one <see langword="null"/> compares unequal (null and empty are distinct), and otherwise every element
    /// must compare equal, in order, under <see cref="Uri.Equals(object?)"/>.
    /// </summary>
    /// <param name="left">The left-hand <c>docRefs</c> member.</param>
    /// <param name="right">The right-hand <c>docRefs</c> member.</param>
    /// <returns><see langword="true"/> when the two members carry the same document references in the same order.</returns>
    private static bool DocRefsEqual(IReadOnlyList<Uri>? left, IReadOnlyList<Uri>? right)
    {
        if(left is null || right is null)
        {
            return left is null && right is null;
        }

        if(left.Count != right.Count)
        {
            return false;
        }

        for(int i = 0; i < left.Count; i++)
        {
            if(!EqualityComparer<Uri>.Default.Equals(left[i], right[i]))
            {
                return false;
            }
        }

        return true;
    }
}
