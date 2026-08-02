using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One referenced detached data object within the <c>sigD</c> signed header parameter — the model-level
/// collapse of the wire's positionally-coupled <c>pars</c>/<c>hashV</c>/<c>ctys</c> parallel arrays into a
/// single per-object record, so a reference, its optional digest and its optional content type can never
/// drift out of index alignment.
/// </summary>
/// <remarks>
/// <para>
/// See
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1</see>.
/// </para>
/// <para>
/// <see cref="Reference"/> corresponds to one element of the wire's <c>pars</c> array — a URI-reference to one
/// data object (CB-5.2.8-17/18). <see cref="Digest"/> corresponds to the element of <c>hashV</c> at the same
/// position (CB-5.2.8-21), present only when the detached-object mechanism identified by
/// <see cref="CBAdESDetachedObjects.MechanismIdentifier"/> incorporates digests (e.g.
/// <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>); its algorithm identity is not restated here —
/// wire-level <c>hashM</c> (CB-5.2.8-19/20/22) is a single value for the whole <c>sigD</c> structure, carried
/// once at the mechanism level as <see cref="CBAdESDetachedObjects.HashAlgorithm"/>, not per entry.
/// <see cref="ContentType"/> corresponds to the element of <c>ctys</c> at the same position (CB-5.2.8-23); a
/// <see langword="null"/> value covers both "the wire's <c>ctys</c> member is entirely absent" and "the content
/// type is implied by the data object, or the object is a counter-signed signature" — CB-5.2.8-25's explicit
/// CBOR-null (<c>#7.22</c>) sentinel case — with the choice between those two wire shapes left to the codec.
/// </para>
/// <para>
/// Dereferencing <see cref="Reference"/> — resolving the URI-reference to the bytes of the data object it
/// names — is out of scope for this model; it is a delegate seam wired at a later CB-AdES stage (clause
/// 5.2.8.2.1: locator classification per IETF RFC 3986 clause 1.1.3, HTTP dereferencing mandatory-to-implement,
/// other schemes optional).
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="Digest"/>, when supplied; disposing this instance
/// disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESDetachedObjectEntry: {Reference}, Digest={Digest != null}")]
public sealed class CBAdESDetachedObjectEntry: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="CBAdESDetachedObjectEntry"/> class. Ownership of
    /// <paramref name="digest"/>, when supplied, transfers to this instance.
    /// </summary>
    /// <param name="reference">The URI-reference to the detached data object (one <c>pars</c> element).</param>
    /// <param name="digest">
    /// The digest of the referenced object (the <c>hashV</c> element at the same position), or
    /// <see langword="null"/> when the mechanism in force does not incorporate digests.
    /// </param>
    /// <param name="contentType">
    /// The content type of the referenced object (the <c>ctys</c> element at the same position), or
    /// <see langword="null"/> when absent or implied.
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="reference"/> is <see langword="null"/> or empty.</exception>
    public CBAdESDetachedObjectEntry(string reference, DigestValue? digest = null, string? contentType = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(reference);

        Reference = reference;
        Digest = digest;
        ContentType = contentType;
    }


    /// <summary>
    /// Gets the URI-reference to the detached data object (CB-5.2.8-17/18).
    /// </summary>
    public string Reference { get; }

    /// <summary>
    /// Gets the digest of the referenced object, owned by this instance, or <see langword="null"/> when the
    /// mechanism identified by <see cref="CBAdESDetachedObjects.MechanismIdentifier"/> does not incorporate
    /// digests (CB-5.2.8-12, CB-5.2.8-21).
    /// </summary>
    public DigestValue? Digest { get; }

    /// <summary>
    /// Gets the content type of the referenced object, or <see langword="null"/> when absent or implied
    /// (CB-5.2.8-23/25).
    /// </summary>
    public string? ContentType { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Digest?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// The <c>sigD</c> signed header parameter — a reference to one or more detached data objects together with
/// the mechanism identifying how they are resolved and processed into the COSE Payload, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// Its wire label is <c>267</c> (<c>sigD</c>, clause 5.2.1 Table 1).
/// </para>
/// <para>
/// CDDL (clause 5.2.8.1; the source spec prints <c>sigD :</c>, a CDDL syntax error corrected here to
/// <c>sigD =</c> per spec-defect resolution D4):
/// </para>
/// <code>
/// sigD = {
///     1 =&gt; #6.32(tstr),  ;mId: URI identifying the mechanism used for referencing and processing each
///                         ;referenced data object
///     2 =&gt; [+tstr],      ;pars: References to data objects as per the mechanism identified by mId
///     ? 3 =&gt; (int / tstr) ;hashM: Digest algorithm identifier
///     ? 4 =&gt; [+bstr],    ;hashV: Digest values of referenced data objects as per algorithm identified by hashM
///     ? 5 =&gt; [+tstr]     ;ctys: Indication of the content type of each referenced object
/// }
/// </code>
/// <para>
/// <c>pars</c>, <c>hashV</c> and <c>ctys</c> are three positionally-coupled parallel arrays on the wire
/// (CB-5.2.8-21/24) that must stay index-synchronized. This model collapses them into one ordered
/// <see cref="DetachedObjects"/> list of <see cref="CBAdESDetachedObjectEntry"/> — one tuple per referenced
/// object — so the coupling is structural rather than an invariant three independently-mutable arrays could
/// drift out of. Projecting <see cref="DetachedObjects"/> back onto the wire's three-array split (and deciding
/// whether <c>hashM</c>/<c>hashV</c>/<c>ctys</c> are present at all) is the CBOR codec's job, not this model's.
/// </para>
/// <para>
/// <c>sigD</c> does not qualify a single named target the way the other clause 5.2 header parameters do
/// (CB-5.2.8-01); it shall not appear in a signature with an attached COSE Payload (CB-5.2.8-03), may appear
/// in one with a detached payload (CB-5.2.8-04), and — in a <c>COSE_Sign</c> structure — is placed at the
/// signer layer (CB-5.2.8-26), with at most one occurrence per protected header (CB-5.2.8-05) and never on a
/// counter signature (CB-5.2.8-09). <see cref="MechanismIdentifier"/> is an open extension point
/// (CB-5.2.8-15): see <see cref="CBAdESDetachedMechanisms"/> for the two mechanisms this document itself
/// defines. Chaining is never allowed — only the objects <see cref="DetachedObjects"/> names directly
/// contribute to the COSE Payload, even when a referenced object itself contains further references
/// (CB-5.2.8-10/11).
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns every element of <see cref="DetachedObjects"/>; disposing
/// this instance disposes them all.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESDetachedObjects: {MechanismIdentifier}, {DetachedObjects.Count} objects")]
public sealed class CBAdESDetachedObjects: IDisposable
{
    private bool disposed;

    /// <summary>The <c>mId</c> member's map key (clause 5.2.8.1).</summary>
    public const int MechanismIdentifierKey = 1;

    /// <summary>The <c>pars</c> member's map key (clause 5.2.8.1).</summary>
    public const int ReferencesKey = 2;

    /// <summary>The <c>hashM</c> member's map key (clause 5.2.8.1).</summary>
    public const int DigestAlgorithmKey = 3;

    /// <summary>The <c>hashV</c> member's map key (clause 5.2.8.1).</summary>
    public const int DigestValuesKey = 4;

    /// <summary>The <c>ctys</c> member's map key (clause 5.2.8.1).</summary>
    public const int ContentTypesKey = 5;


    /// <summary>
    /// Initializes a new instance of the <see cref="CBAdESDetachedObjects"/> class. Ownership of every element
    /// of <paramref name="detachedObjects"/> transfers to this instance.
    /// </summary>
    /// <param name="mechanismIdentifier">
    /// The <c>mId</c> URI identifying the mechanism used for referencing and processing each referenced data
    /// object (CB-5.2.8-14/15).
    /// </param>
    /// <param name="detachedObjects">
    /// The referenced detached data objects, in wire order (CB-5.2.8.2.2-05: order is load-bearing — it is the
    /// COSE Payload byte order under the <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> mechanism).
    /// </param>
    /// <param name="hashAlgorithm">
    /// The <c>hashM</c> member (map key 3, clause 5.2.8.1): the digest-algorithm identifier shared by every
    /// entry that carries a digest, or <see langword="null"/> when no entry does. Must be
    /// <see langword="null"/> when, and only when, no element of <paramref name="detachedObjects"/> carries a
    /// <see cref="CBAdESDetachedObjectEntry.Digest"/> (CB-5.2.8-19/20/22: <c>hashM</c> and <c>hashV</c> are
    /// present together or absent together).
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="mechanismIdentifier"/> is <see langword="null"/> or empty; when
    /// <paramref name="detachedObjects"/> is empty (CB-5.2.8-06: <c>sigD</c> shall reference one or more
    /// detached data objects); or when <paramref name="hashAlgorithm"/>'s presence does not match whether any
    /// element of <paramref name="detachedObjects"/> carries a digest.
    /// </exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="detachedObjects"/> is <see langword="null"/>.</exception>
    public CBAdESDetachedObjects(
        string mechanismIdentifier,
        IReadOnlyList<CBAdESDetachedObjectEntry> detachedObjects,
        CBAdESDigestAlgorithmIdentifier? hashAlgorithm = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(mechanismIdentifier);
        ArgumentNullException.ThrowIfNull(detachedObjects);
        if(detachedObjects.Count == 0)
        {
            throw new ArgumentException(
                "sigD shall reference one or more detached data objects (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1, CB-5.2.8-06).",
                nameof(detachedObjects));
        }

        bool anyDigest = false;
        for(int i = 0; i < detachedObjects.Count; ++i)
        {
            if(detachedObjects[i].Digest is not null)
            {
                anyDigest = true;
                break;
            }
        }

        if(anyDigest && hashAlgorithm is null)
        {
            throw new ArgumentException(
                "sigD's hashM shall be present when at least one entry carries a digest (ETSI TS 119 152-1 " +
                "V1.1.1, clause 5.2.8.1, CB-5.2.8-19/20/22).",
                nameof(hashAlgorithm));
        }

        if(!anyDigest && hashAlgorithm is not null)
        {
            throw new ArgumentException(
                "sigD's hashM shall be absent when no entry carries a digest (ETSI TS 119 152-1 V1.1.1, " +
                "clause 5.2.8.1, CB-5.2.8-19/20/22).",
                nameof(hashAlgorithm));
        }

        MechanismIdentifier = mechanismIdentifier;
        DetachedObjects = detachedObjects;
        HashAlgorithm = hashAlgorithm;
    }


    /// <summary>
    /// Gets the <c>mId</c> URI identifying the detached-object mechanism (CB-5.2.8-14/15). See
    /// <see cref="CBAdESDetachedMechanisms"/> for the two mechanisms this document defines by name.
    /// </summary>
    public string MechanismIdentifier { get; }

    /// <summary>
    /// Gets the referenced detached data objects, in wire order. Owned by this instance; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public IReadOnlyList<CBAdESDetachedObjectEntry> DetachedObjects { get; }

    /// <summary>
    /// Gets the <c>hashM</c> member (map key 3, clause 5.2.8.1): the digest-algorithm identifier shared by
    /// every entry in <see cref="DetachedObjects"/> that carries a digest, or <see langword="null"/> when no
    /// entry carries one. Present if and only if at least one entry carries a digest (constructor-enforced).
    /// </summary>
    public CBAdESDigestAlgorithmIdentifier? HashAlgorithm { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            foreach(CBAdESDetachedObjectEntry entry in DetachedObjects)
            {
                entry.Dispose();
            }

            disposed = true;
        }
    }
}


/// <summary>
/// The two <c>sigD</c> detached-object mechanisms this document defines by name — <c>ObjectIdByURI</c> and
/// <c>ObjectIdByURIHash</c> — each identified by a URI and selected through
/// <see cref="CBAdESDetachedObjects.MechanismIdentifier"/>.
/// </summary>
/// <remarks>
/// <para>
/// See
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clauses 5.2.8.2.2 and 5.2.8.2.3</see>.
/// </para>
/// <para>
/// <c>mId</c> is an open extension point (CB-5.2.8-15): a specification other than this one may define further
/// mechanism identifiers, each with its own COSE-Payload-retrieval rule (CB-5.2.6-07, clause 5.2.8.1). The two
/// members below are the only mechanisms this document itself defines; <see cref="IsKnownMechanism(string?)"/>
/// recognizes exactly these two rather than treating every unrecognized value as an error — a third-party
/// mechanism is not malformed, only outside this registry's vocabulary.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive.</strong> A mechanism identifier is a URI compared as an
/// exact character sequence, consistent with <c>mId</c>'s wire type (<c>#6.32(tstr)</c>) carrying no
/// case-folding or normalization contract of its own.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The mechanism identifier is compared and written as an exact character sequence — two spellings differing by escaping or case name two different mechanisms under CB-5.2.8-15's open extension point. System.Uri normalizes both, which would make them compare equal.")]
public static class CBAdESDetachedMechanisms
{
    /// <summary>
    /// The <c>ObjectIdByURI</c> mechanism identifier, <c>http://uri.etsi.org/19152/ObjectIdByURI</c>
    /// (CB-5.2.8.2.2-01). Neither <c>hashM</c> nor <c>hashV</c> is present for this mechanism
    /// (CB-5.2.8.2.2-02); the COSE Payload is the ordered concatenation of the dereferenced objects
    /// (CB-5.2.8.2.2-05).
    /// </summary>
    public static string ObjectIdByURI => "http://uri.etsi.org/19152/ObjectIdByURI";

    /// <summary>
    /// The <c>ObjectIdByURIHash</c> mechanism identifier, <c>http://uri.etsi.org/19152/ObjectIdByURIHash</c>
    /// (CB-5.2.8.2.3-01). Both <c>hashM</c> and <c>hashV</c> are present for this mechanism
    /// (CB-5.2.8.2.3-02); the COSE Payload contributes as an empty stream to the signature-value computation
    /// (CB-5.2.8.2.3-06) — integrity of the referenced objects rides entirely on the signed digest values,
    /// though when the COSE Payload is separately needed (e.g. for <c>adoTst</c>/<c>arcTst</c>) it is still
    /// generated by the <see cref="ObjectIdByURI"/> concatenation procedure (CB-5.2.8.2.3-07, CB-5.2.6-06).
    /// </summary>
    public static string ObjectIdByURIHash => "http://uri.etsi.org/19152/ObjectIdByURIHash";


    /// <summary>
    /// Determines whether a mechanism identifier is <see cref="ObjectIdByURI"/>.
    /// </summary>
    /// <param name="mechanismIdentifier">The <c>mId</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is exactly <see cref="ObjectIdByURI"/>.</returns>
    public static bool IsObjectIdByURI(string? mechanismIdentifier) =>
        string.Equals(mechanismIdentifier, ObjectIdByURI, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a mechanism identifier is <see cref="ObjectIdByURIHash"/>.
    /// </summary>
    /// <param name="mechanismIdentifier">The <c>mId</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is exactly <see cref="ObjectIdByURIHash"/>.</returns>
    public static bool IsObjectIdByURIHash(string? mechanismIdentifier) =>
        string.Equals(mechanismIdentifier, ObjectIdByURIHash, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a mechanism identifier is one of the two this document defines.
    /// </summary>
    /// <param name="mechanismIdentifier">The <c>mId</c> value, or <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the value is <see cref="ObjectIdByURI"/> or <see cref="ObjectIdByURIHash"/>;
    /// <see langword="false"/> for a third-party mechanism (CB-5.2.8-15) or an unset value.
    /// </returns>
    public static bool IsKnownMechanism(string? mechanismIdentifier) =>
        IsObjectIdByURI(mechanismIdentifier) || IsObjectIdByURIHash(mechanismIdentifier);
}
