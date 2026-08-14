using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>sigPSt</c> unsigned <c>etsiU</c> component — a signature-policy store carrying either the signature
/// policy document itself or a local-store pointer to it, for offline and long-term validation, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.3.3</see> (JA-5.3.3-01). The JAdES-side counterpart of
/// <see cref="CBAdESSignaturePolicyStore"/>; see <see cref="Content"/>'s remarks for the one member whose
/// carrier diverges from that type's own choice.
/// </summary>
/// <remarks>
/// <para>JSON Schema (clause 5.3.3, copied from Annex B.1):</para>
/// <code>
/// "sigPSt": {
///   "type":"object",
///   "properties": {
///     "sigPolDoc": {"type": "string", "contentEncoding": "base64"},
///     "sigPolLocalURI": {"type": "string", "format": "uri-reference"},
///     "spDSpec": {"$ref": "#/definitions/oId"}
///   },
///   "oneOf": [ { "required": ["sigPolDoc"] }, { "required": ["sigPolLocalURI"] } ],
///   "minProperties": 1,
///   "additionalProperties": false
/// },
/// </code>
/// <para>
/// <strong>Exclusive two-case choice (JA-5.3.3-01), enforced at construction.</strong> "The <c>sigPSt</c> JSON
/// object shall contain either: the signature policy document ...; or a URI referencing a local store where
/// the signature policy document can be retrieved" — the schema's <c>oneOf</c> makes this an exclusive choice,
/// not an independently-optional pair: this constructor rejects both a wholly-absent and a both-present
/// <see cref="Content"/>.
/// </para>
/// <para>
/// (JA-5.3.3-06) <see cref="SpDSpec"/> — the <c>spDSpec</c> member — identifies the technical specification
/// that defines the syntax used for producing the signature policy document, typed as
/// <see cref="AdESObjectIdentifier"/> (clause 5.4.1), reused verbatim.
/// </para>
/// <para>
/// <strong>Tamper detection despite being unsigned (clause 5.3.3, NOTE 3).</strong> "Being an unsigned JSON
/// object, it is not protected by the digital signature. If the <c>sigPId</c> JSON object is incorporated into
/// the signature and contains the <c>digVal</c> member with the digest value of the signature policy document,
/// any alteration of the signature policy document present within <c>sigPSt</c> or within a local store, would
/// be detected by the failure of the digests comparison." This model carries no digest of its own — the tamper
/// check compares <see cref="Content"/>'s bytes (or the bytes retrieved through its local-store pointer)
/// against the signed <c>sigPId</c> instance's own digest, a cross-component check owned by validation, not by
/// this type.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="Content"/> when it is a
/// <see cref="JAdESSignaturePolicyStoreDocument"/>; <see cref="Dispose"/> disposes it. <see cref="SpDSpec"/>
/// and a <see cref="JAdESSignaturePolicyStoreLocalUri"/> <see cref="Content"/> own no disposable resources.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESSignaturePolicyStore: {Content}")]
public sealed class JAdESSignaturePolicyStore: IDisposable
{
    /// <summary>The <c>sigPolDoc</c> member's JSON key name (clause 5.3.3, Annex B.1 schema).</summary>
    public const string SigPolDocMemberName = "sigPolDoc";

    /// <summary>The <c>sigPolLocalURI</c> member's JSON key name (clause 5.3.3, Annex B.1 schema).</summary>
    public const string SigPolLocalUriMemberName = "sigPolLocalURI";

    /// <summary>The <c>spDSpec</c> member's JSON key name (clause 5.3.3, Annex B.1 schema).</summary>
    public const string SpDSpecMemberName = "spDSpec";

    /// <summary>
    /// Initializes a new <see cref="JAdESSignaturePolicyStore"/>.
    /// </summary>
    /// <param name="content">
    /// Either the signature policy document itself (<see cref="JAdESSignaturePolicyStoreDocument"/>) or a
    /// local-store pointer to it (<see cref="JAdESSignaturePolicyStoreLocalUri"/>) — JA-5.3.3-01's exclusive
    /// choice.
    /// </param>
    /// <param name="spDSpec">The <c>spDSpec</c> member, or <see langword="null"/> to omit it (JA-5.3.3-06).</param>
    /// <exception cref="ArgumentNullException"><paramref name="content"/> is <see langword="null"/>.</exception>
    public JAdESSignaturePolicyStore(JAdESSignaturePolicyStoreContent content, AdESObjectIdentifier? spDSpec = null)
    {
        ArgumentNullException.ThrowIfNull(content);

        Content = content;
        SpDSpec = spDSpec;
    }


    /// <summary>
    /// Gets either the signature policy document itself (<see cref="JAdESSignaturePolicyStoreDocument"/>) or a
    /// local-store pointer to it (<see cref="JAdESSignaturePolicyStoreLocalUri"/>) (JA-5.3.3-01).
    /// </summary>
    public JAdESSignaturePolicyStoreContent Content { get; }

    /// <summary>
    /// Gets the <c>spDSpec</c> member: the technical specification defining the syntax of the signature policy
    /// document (JA-5.3.3-06), or <see langword="null"/> when absent.
    /// </summary>
    public AdESObjectIdentifier? SpDSpec { get; }


    /// <summary>Disposes <see cref="Content"/> when it owns pooled memory.</summary>
    public void Dispose()
    {
        if(Content is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The exclusive two-case choice carried by <see cref="JAdESSignaturePolicyStore.Content"/> (JA-5.3.3-01,
/// Annex B.1 schema <c>oneOf</c>): the signature policy document, or a local-store pointer to it. A DU-ready
/// closed sum: no external type may derive from it.
/// </summary>
public abstract class JAdESSignaturePolicyStoreContent
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected JAdESSignaturePolicyStoreContent()
    {
    }
}


/// <summary>
/// The <c>sigPolDoc</c> choice arm (clause 5.3.3, JA-5.3.3-04): the signature policy document itself, carried
/// verbatim.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="Document"/>; <see cref="Dispose"/> returns it to
/// its pool. Pooled per this project's "no naked bytes" carrier discipline — a deliberate departure from
/// <see cref="CBAdESSignaturePolicyStoreDocument.Document"/>'s own borrowed-<see cref="ReadOnlyMemory{T}"/>
/// choice, which predates that ruling.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESSignaturePolicyStoreDocument({Document.Length} bytes)")]
public sealed class JAdESSignaturePolicyStoreDocument: JAdESSignaturePolicyStoreContent, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESSignaturePolicyStoreDocument"/>.</summary>
    public JAdESSignaturePolicyStoreDocument(PooledMemory document)
    {
        Document = document;
    }

    public PooledMemory Document { get; }

    /// <summary>Disposes <see cref="Document"/>, returning its pooled buffer.</summary>
    public void Dispose() => Document.Dispose();
}


/// <summary>
/// The <c>sigPolLocalURI</c> choice arm (clause 5.3.3, JA-5.3.3-05): a URI pointing to a <em>local</em> store
/// where the signature policy document can be retrieved — contrast with <c>spURI</c> (clause 5.2.7.2), a
/// remote/network pointer.
/// </summary>
/// <remarks>
/// The arm carries a pointer and owns nothing, so equality is <see cref="Location"/>'s own component-wise
/// comparison: two arms addressing the same local store are the same arm, whether one was parsed from a
/// serialized header and the other built by a caller.
/// </remarks>
[DebuggerDisplay("JAdESSignaturePolicyStoreLocalUri: {Location}")]
public sealed class JAdESSignaturePolicyStoreLocalUri : JAdESSignaturePolicyStoreContent, IEquatable<JAdESSignaturePolicyStoreLocalUri>
{
    /// <summary>Initializes a new <see cref="JAdESSignaturePolicyStoreLocalUri"/>.</summary>
    /// <param name="location">
    /// The local-store URI. NOTE 1 of clause 5.3.3: "Contrary to the <c>spURI</c>, the <c>sigPolLocalURI</c>
    /// points to a local file."
    /// </param>
    public JAdESSignaturePolicyStoreLocalUri(Uri location)
    {
        Location = location;
    }

    /// <summary>
    /// The local-store URI. NOTE 1 of clause 5.3.3: "Contrary to the <c>spURI</c>, the <c>sigPolLocalURI</c>
    /// points to a local file."
    /// </summary>
    public Uri Location { get; }

    /// <inheritdoc/>
    public bool Equals(JAdESSignaturePolicyStoreLocalUri? other)
    {
        return other is not null && Location == other.Location;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as JAdESSignaturePolicyStoreLocalUri);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Location);
    }

    /// <summary>Reports whether two local-URI arms point at the same location.</summary>
    public static bool operator ==(JAdESSignaturePolicyStoreLocalUri? left, JAdESSignaturePolicyStoreLocalUri? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two local-URI arms point at different locations.</summary>
    public static bool operator !=(JAdESSignaturePolicyStoreLocalUri? left, JAdESSignaturePolicyStoreLocalUri? right)
    {
        return !(left == right);
    }
}
