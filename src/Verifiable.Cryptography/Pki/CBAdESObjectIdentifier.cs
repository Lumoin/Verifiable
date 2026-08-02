using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>oId</c> shared-syntax type of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.4.1</see> — a permanent, unique identifier for one data object (the
/// clause's heading and prose call the type <c>obId</c>, but its own CDDL production, and every other point of
/// use of it in the document, spell it <c>oId</c>; this type mirrors the CDDL/wire spelling), together with an
/// optional textual description and optional pointers to documents describing the identified object.
/// </summary>
/// <remarks>
/// <para>CDDL (clause 5.4.1, Table 11 keys):</para>
/// <code>
/// oId = {
///     1 =&gt; #6.32(tstr),         ; id
///     ? 2 =&gt; tstr,              ; desc
///     ? 3 =&gt; [ +#6.32(tstr) ]   ; docRefs
/// }
/// </code>
/// <para>
/// Reused throughout the document wherever a technical specification or data object needs a permanent
/// identifier, e.g. as <c>sigPSt</c>'s <c>spDSpec</c> member (clause 5.3.2).
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESObjectIdentifier({Id})")]
public sealed record CBAdESObjectIdentifier
{
    /// <summary>The <c>id</c> member's map key (Table 11, clause 5.4.1).</summary>
    public const int IdKey = 1;

    /// <summary>The <c>desc</c> member's map key (Table 11, clause 5.4.1).</summary>
    public const int DescKey = 2;

    /// <summary>The <c>docRefs</c> member's map key (Table 11, clause 5.4.1).</summary>
    public const int DocRefsKey = 3;

    /// <summary>
    /// Initializes a new <see cref="CBAdESObjectIdentifier"/>.
    /// </summary>
    /// <param name="id">The permanent identifier of the object — see the remarks on <see cref="Id"/>.</param>
    /// <param name="desc">The short, informal description of the identified object, or <see langword="null"/> to omit it.</param>
    /// <param name="docRefs">
    /// The URIs of documents that completely specify the identified object, or <see langword="null"/> to omit
    /// it. When present, must be non-empty (the CDDL's <c>+</c> cardinality).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="id"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="docRefs"/> is non-null but empty.</exception>
    public CBAdESObjectIdentifier(Uri id, string? desc = null, IReadOnlyList<Uri>? docRefs = null)
    {
        ArgumentNullException.ThrowIfNull(id);

        if(docRefs is not null && docRefs.Count == 0)
        {
            throw new ArgumentException(
                "When present, oId's 'docRefs' member shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.4.1, CDDL '+' occurrence operator).",
                nameof(docRefs));
        }

        Id = id;
        Desc = desc;
        DocRefs = docRefs;
    }


    /// <summary>
    /// Gets the permanent identifier of the object, carried as a
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.4.4">CBOR tag 32 (RFC 8949 §3.4.4.4)</see>
    /// URI string on the wire.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.1</see> states that once the identifier is assigned it shall not be
    /// re-assigned again — a registry-level invariant across instances minted over time, not something a single
    /// value object can self-enforce. When the identifier is an OID rather than a native URI it shall be encoded
    /// as an OID URN per <see href="https://www.rfc-editor.org/rfc/rfc3061">RFC 3061</see> (e.g.
    /// <c>urn:oid:1.2.3.4</c>); when both an OID and a URI identify the same object, the URI form should be used
    /// here.
    /// </remarks>
    public Uri Id { get; }

    /// <summary>
    /// Gets the short, informal description of the identified object (clause 5.4.1), or <see langword="null"/>
    /// when absent.
    /// </summary>
    public string? Desc { get; }

    /// <summary>
    /// Gets the URIs of documents that completely specify the identified object (clause 5.4.1), or
    /// <see langword="null"/> when absent. Non-empty when present (constructor-enforced — the CDDL's <c>+</c>
    /// cardinality).
    /// </summary>
    public IReadOnlyList<Uri>? DocRefs { get; }
}
