using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One referenced detached data object under the <see cref="JAdESObjectIdByUriReference"/> or
/// <see cref="JAdESObjectIdByUriHashReference"/> mechanisms of <c>sigD</c> — the model-level collapse of the
/// wire's positionally-coupled <c>pars</c>/<c>hashV</c>/<c>ctys</c> parallel arrays
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1</see>) into a single per-object type, so a reference, its optional
/// digest, and its optional content type can never drift out of index alignment. Mirrors
/// <see cref="CBAdESDetachedObjectEntry"/>'s identical collapse.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Reference"/> corresponds to one element of the wire's <c>pars</c> array (JA-5.2.8.1-16/-17):
/// dereferencing it to bytes is out of scope for this model — a delegate seam wired at the stage that consumes
/// it (clause 5.2.8.3.1's dereferencing obligation). <see cref="Digest"/>
/// corresponds to the element of <c>hashV</c> at the same position (JA-5.2.8.1-23), present only under
/// <see cref="JAdESObjectIdByUriHashReference"/> — its algorithm identity is not restated here; wire-level
/// <c>hashM</c> is a single value for the whole mechanism, carried once at
/// <see cref="JAdESObjectIdByUriHashReference.HashAlgorithm"/>, not per entry (JA-5.2.8.1-18/-19/-20). Absence
/// vs. presence of <see cref="Digest"/> is what distinguishes the two mechanisms structurally — see the
/// constructor remarks on each. <see cref="ContentType"/> corresponds to the element of <c>ctys</c> at the same
/// position (JA-5.2.8.1-26/-27/-28/-29), or <see langword="null"/> when the wire's <c>ctys</c> member is
/// entirely absent, or the content type is implied by the data object, or the object is a counter-signed
/// signature (JA-5.2.8.1-29's explicit empty-string sentinel case), with the choice between those two absent-vs-
/// empty wire shapes left to the codec.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="Digest"/>, when supplied; disposing this instance
/// disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESReferencedDataObject: {Reference}, Digest={Digest != null}")]
public sealed class JAdESReferencedDataObject: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="JAdESReferencedDataObject"/> class. Ownership of
    /// <paramref name="digest"/>, when supplied, transfers to this instance.
    /// </summary>
    /// <param name="reference">The URI-reference to the detached data object (one <c>pars</c> element, JA-5.2.8.3.1-02).</param>
    /// <param name="contentType">The content type of the referenced object (the <c>ctys</c> element at the same position), or <see langword="null"/> when absent or implied.</param>
    /// <param name="digest">The digest of the referenced object (the <c>hashV</c> element at the same position), or <see langword="null"/> when the mechanism in force does not incorporate digests.</param>
    /// <exception cref="ArgumentException"><paramref name="reference"/> is <see langword="null"/> or empty.</exception>
    public JAdESReferencedDataObject(string reference, string? contentType = null, DigestValue? digest = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(reference);

        Reference = reference;
        ContentType = contentType;
        Digest = digest;
    }


    /// <summary>
    /// Gets the URI-reference to the detached data object (JA-5.2.8.1-16/-17, JA-5.2.8.3.1-02), carried as an
    /// exact character sequence — not <see cref="Uri"/> (mirroring
    /// <see cref="CBAdESDetachedMechanisms"/>'s CA1056 justification): <see cref="System.Uri"/> normalizes on
    /// construction, and the dereferencing seam clause 5.2.8.3.1 owns (see the type remarks below) resolves
    /// exactly the string the signer wrote, not a normalized re-spelling of it.
    /// </summary>
    public string Reference { get; }

    /// <summary>
    /// Gets the content type of the referenced object, or <see langword="null"/> when absent or implied
    /// (JA-5.2.8.1-26/-29).
    /// </summary>
    public string? ContentType { get; }

    /// <summary>
    /// Gets the digest of the referenced object, owned by this instance, or <see langword="null"/> when the
    /// enclosing mechanism does not incorporate digests (JA-5.2.8.3.2-02, JA-5.2.8.3.3-02).
    /// </summary>
    public DigestValue? Digest { get; }


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
/// The <c>sigD</c> signed header parameter of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1</see> (JA-5.2.8.1-01): a reference to one or more detached data
/// objects together with the mechanism identifying how they are resolved and processed into the JWS Payload. A
/// closed, four-arm sum: the three mechanisms clause 5.2.8 itself defines
/// (<see cref="JAdESHttpHeadersReference"/>, <see cref="JAdESObjectIdByUriReference"/>,
/// <see cref="JAdESObjectIdByUriHashReference"/>) plus <see cref="JAdESUnknownDetachedDataObjectReference"/>,
/// the open arm clause 5.2.8.1 item 3 itself reserves (JA-5.2.8.1-C1). A DU-ready closed sum: no external type
/// may derive from it — the fourth arm IS the extension point, not a door left open beside it.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The mechanism family is OPEN (correcting the prior
/// "CLOSED sum, no unrecognized fourth" reading).</strong> JA-5.2.8.1-04's "shall:" list requires <c>mId</c> to
/// "3) Allow to define different mechanisms for meeting the two aforementioned requirements" (JA-5.2.8.1-C1) —
/// an extensibility SHALL, not a restriction to the three named mechanisms. JA-5.2.8.1-14's own next sentence
/// confirms the three below are what THIS document defines, not an exhaustive universe: "The present document
/// defines 3 referencing mechanisms with their corresponding identifiers in clauses 5.2.8.2, 5.2.8.3.2 and
/// 5.2.8.3.3" (a sentence a prior transcription dropped; restored here). So <c>mId</c> is open exactly as
/// <see cref="CBAdESDetachedObjects"/>'s own <c>mId</c> is (CB-5.2.8-15) — this type's C# sum stays closed
/// (every value is one of exactly four arms, DU-ready), but the fourth arm,
/// <see cref="JAdESUnknownDetachedDataObjectReference"/>, represents any mechanism outside
/// <see cref="JAdESDetachedMechanisms"/>'s vocabulary rather than rejecting it: "a third-party mechanism is not
/// malformed, only outside this registry's vocabulary" (<see cref="CBAdESDetachedMechanisms"/>'s own remarks,
/// reused verbatim here). Each of the three named arms' own <c>MechanismIdentifier</c> static member is the
/// wire <c>mId</c> value the codec writes for that arm; <see cref="JAdESDetachedMechanisms"/> is the registry
/// that dispatches on them.
/// </para>
/// <para>
/// <c>sigD</c> shall not appear in a signature with an attached JWS Payload (JA-5.2.8.1-02); may appear in one
/// with a detached payload (JA-5.2.8.1-M1); at most one occurrence per JWS Protected Header (JA-5.2.8.1-03).
/// Chaining is never allowed — only the objects a mechanism's own references name directly contribute to the
/// JWS Payload, even when a referenced object itself contains further references (JA-5.2.8.1-08/-09/-10).
/// Placing this parameter in the JWS Protected Header (JA-5.2.8.1-11) is the signature builder's responsibility,
/// not this type's.
/// </para>
/// <para>
/// <strong>Dereferencing seam.</strong>
/// <see cref="JAdESHttpHeadersReference"/> dereferences nothing — it is pure canonicalization over
/// application-supplied HTTP message facts (method, target URI, header name/value pairs) the signer already
/// holds locally (clause 5.2.8.2's own text contains zero <c>dereferenc*</c> occurrences); it lives fully
/// in-library, no seam. The dereferencing obligation belongs to clause 5.2.8.3.1, shared by
/// <see cref="JAdESObjectIdByUriReference"/> and <see cref="JAdESObjectIdByUriHashReference"/>
/// (JA-5.2.8.3.2-C3, JA-5.2.8.3.3-04) — THAT is where a future stage's no-HTTP-in-library delegate seam binds,
/// mirroring <see cref="CBAdESDetachedObjectEntry"/>'s identical seam. This model carries the dereference-seam-
/// shaped members (<see cref="JAdESReferencedDataObject.Reference"/> as an unresolved, exact-character-sequence
/// string — see that member's own remarks) without performing any dereferencing itself.
/// </para>
/// </remarks>
public abstract class JAdESDetachedDataObjectReference
{
    /// <summary>The <c>mId</c> member's JSON key name (clause 5.2.8.1, Annex B.1 schema).</summary>
    public const string MechanismIdentifierMemberName = "mId";

    /// <summary>The <c>pars</c> member's JSON key name (clause 5.2.8.1, Annex B.1 schema).</summary>
    public const string ReferencesMemberName = "pars";

    /// <summary>The <c>hashM</c> member's JSON key name (clause 5.2.8.1, Annex B.1 schema).</summary>
    public const string HashAlgorithmMemberName = "hashM";

    /// <summary>The <c>hashV</c> member's JSON key name (clause 5.2.8.1, Annex B.1 schema).</summary>
    public const string DigestsMemberName = "hashV";

    /// <summary>The <c>ctys</c> member's JSON key name (clause 5.2.8.1, Annex B.1 schema).</summary>
    public const string ContentTypesMemberName = "ctys";

    /// <summary>Restricts direct subtyping to a type declared in this assembly.</summary>
    private protected JAdESDetachedDataObjectReference()
    {
    }
}


/// <summary>
/// The <c>HttpHeaders</c> mechanism of <c>sigD</c>
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.2</see>): the JWS Payload is built from a canonicalized concatenation
/// of named HTTP message facts (method/target URI, status line, header name/value pairs) the signer already
/// holds — no dereferencing, no seam. See the <see cref="JAdESDetachedDataObjectReference"/> remarks for the
/// dereferencing-obligation seam this arm satisfies by construction.
/// </summary>
/// <remarks>
/// <para>
/// If this mechanism is used, the <c>b64</c> header parameter shall be present and set to <see langword="false"/>
/// (JA-5.2.8.2-02); neither <c>hashV</c>, <c>hashM</c>, nor <c>ctys</c> shall be present (JA-5.2.8.2-03) — this
/// arm carries no members for any of the three, satisfying that prohibition by construction. The
/// canonicalization procedure itself (JA-5.2.8.2-C1..C4, JA-5.2.8.2-06) is out of this model's scope — it is a
/// pure byte-transformation the creation/validation orchestrator performs over
/// <see cref="HeaderNames"/> plus caller-supplied HTTP message facts, not something this carrier computes.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESHttpHeadersReference: {HeaderNames.Count} headers")]
public sealed class JAdESHttpHeadersReference : JAdESDetachedDataObjectReference
{
    /// <summary>The wire <c>mId</c> value identifying this mechanism (JA-5.2.8.2-01).</summary>
    public static string MechanismIdentifier => "http://uri.etsi.org/19182/HttpHeaders";


    /// <summary>
    /// Initializes a new <see cref="JAdESHttpHeadersReference"/>.
    /// </summary>
    /// <param name="headerNames">
    /// The <c>pars</c> member: lowercased HTTP header field names, in the order they contribute to the JWS
    /// Payload (JA-5.2.8.2-04/-05). Must be non-empty (JA-5.2.8.1-16, the base <c>pars</c> requirement).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="headerNames"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="headerNames"/> is empty.</exception>
    public JAdESHttpHeadersReference(IReadOnlyList<string> headerNames)
    {
        ArgumentNullException.ThrowIfNull(headerNames);
        if(headerNames.Count == 0)
        {
            throw new ArgumentException(
                "sigD's 'pars' member shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, " +
                "JA-5.2.8.1-16).",
                nameof(headerNames));
        }

        HeaderNames = headerNames;
    }


    /// <summary>
    /// Gets the lowercased HTTP header field names, in wire order (JA-5.2.8.2-04/-05). Non-empty
    /// (constructor-enforced).
    /// </summary>
    public IReadOnlyList<string> HeaderNames { get; }
}


/// <summary>
/// The <c>ObjectIdByURI</c> mechanism of <c>sigD</c>
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.2</see>): the JWS Payload is the ordered concatenation of the
/// dereferenced (and, per <c>b64</c>, base64url-re-encoded) referenced objects. Neither <c>hashV</c> nor
/// <c>hashM</c> is present for this mechanism (JA-5.2.8.3.2-02) — every <see cref="JAdESReferencedDataObject.Digest"/>
/// across <see cref="References"/> is <see langword="null"/> (constructor-enforced).
/// </summary>
[DebuggerDisplay("JAdESObjectIdByUriReference: {References.Count} references")]
public sealed class JAdESObjectIdByUriReference : JAdESDetachedDataObjectReference, IDisposable
{
    /// <summary>The wire <c>mId</c> value identifying this mechanism (JA-5.2.8.3.2-01).</summary>
    public static string MechanismIdentifier => "http://uri.etsi.org/19182/ObjectIdByURI";


    /// <summary>
    /// Initializes a new <see cref="JAdESObjectIdByUriReference"/>. Ownership of every element of
    /// <paramref name="references"/> transfers to this instance.
    /// </summary>
    /// <param name="references">
    /// The referenced detached data objects, in wire order (JA-5.2.8.1-16/-17). Must be non-empty
    /// (JA-5.2.8.1-16). Every element's <see cref="JAdESReferencedDataObject.Digest"/> must be
    /// <see langword="null"/> (JA-5.2.8.3.2-02: neither <c>hashV</c> nor <c>hashM</c> is present for this
    /// mechanism).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="references"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="references"/> is empty; or an element carries a non-null
    /// <see cref="JAdESReferencedDataObject.Digest"/>.
    /// </exception>
    public JAdESObjectIdByUriReference(IReadOnlyList<JAdESReferencedDataObject> references)
    {
        ArgumentNullException.ThrowIfNull(references);
        if(references.Count == 0)
        {
            throw new ArgumentException(
                "sigD's 'pars' member shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, " +
                "JA-5.2.8.1-16).",
                nameof(references));
        }

        for(int i = 0; i < references.Count; ++i)
        {
            if(references[i].Digest is not null)
            {
                throw new ArgumentException(
                    "ObjectIdByURI shall carry neither 'hashV' nor 'hashM' (ETSI TS 119 182-1 V1.2.1, clause " +
                    "5.2.8.3.2, JA-5.2.8.3.2-02); the referenced object at position " +
                    i.ToString(System.Globalization.CultureInfo.InvariantCulture) + " carries a digest.",
                    nameof(references));
            }
        }

        References = references;
    }


    /// <summary>
    /// Gets the referenced detached data objects, in wire order. Owned by this instance; disposed via
    /// <see cref="Dispose"/>. Non-empty; no element carries a digest (constructor-enforced).
    /// </summary>
    public IReadOnlyList<JAdESReferencedDataObject> References { get; }


    /// <summary>Disposes every element of <see cref="References"/>.</summary>
    public void Dispose()
    {
        for(int i = 0; i < References.Count; ++i)
        {
            References[i].Dispose();
        }
    }
}


/// <summary>
/// The <c>ObjectIdByURIHash</c> mechanism of <c>sigD</c>
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.3</see>): the JWS Payload contributes as an empty stream to the
/// JWS Signature Value computation (JA-5.2.8.3.3-05) — integrity of the referenced objects rides entirely on the
/// signed digest values. Both <c>hashV</c> and <c>hashM</c> are present for this mechanism (JA-5.2.8.3.3-02) —
/// every <see cref="JAdESReferencedDataObject.Digest"/> across <see cref="References"/> is non-null
/// (constructor-enforced).
/// </summary>
/// <remarks>
/// When the JWS Payload is separately needed for other purposes (e.g. <c>adoTst</c>/<c>arcTst</c>) it is still
/// generated by the <see cref="JAdESObjectIdByUriReference"/> concatenation procedure (JA-5.2.8.3.3-06) — a
/// creation/validation orchestrator concern, not modelled here.
/// </remarks>
[DebuggerDisplay("JAdESObjectIdByUriHashReference: HashAlgorithm={HashAlgorithm}, {References.Count} references")]
public sealed class JAdESObjectIdByUriHashReference : JAdESDetachedDataObjectReference, IDisposable
{
    /// <summary>The wire <c>mId</c> value identifying this mechanism (JA-5.2.8.3.3-01).</summary>
    public static string MechanismIdentifier => "http://uri.etsi.org/19182/ObjectIdByURIHash";


    /// <summary>
    /// Initializes a new <see cref="JAdESObjectIdByUriHashReference"/>. Ownership of every element of
    /// <paramref name="references"/> transfers to this instance.
    /// </summary>
    /// <param name="hashAlgorithm">
    /// The <c>hashM</c> member: the digest-algorithm identifier shared by every entry in
    /// <paramref name="references"/> (JA-5.2.8.1-18/-19).
    /// </param>
    /// <param name="references">
    /// The referenced detached data objects, in wire order (JA-5.2.8.1-16/-17). Must be non-empty
    /// (JA-5.2.8.1-16). Every element's <see cref="JAdESReferencedDataObject.Digest"/> must be non-null
    /// (JA-5.2.8.3.3-02/-04).
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="hashAlgorithm"/> is <see langword="null"/> or empty; or <paramref name="references"/> is empty, or an element carries a <see langword="null"/> <see cref="JAdESReferencedDataObject.Digest"/>.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="references"/> is <see langword="null"/>.</exception>
    public JAdESObjectIdByUriHashReference(string hashAlgorithm, IReadOnlyList<JAdESReferencedDataObject> references)
    {
        ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(references);
        if(references.Count == 0)
        {
            throw new ArgumentException(
                "sigD's 'pars' member shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, " +
                "JA-5.2.8.1-16).",
                nameof(references));
        }

        for(int i = 0; i < references.Count; ++i)
        {
            if(references[i].Digest is null)
            {
                throw new ArgumentException(
                    "ObjectIdByURIHash shall carry 'hashV' for every referenced object (ETSI TS 119 182-1 " +
                    "V1.2.1, clause 5.2.8.3.3, JA-5.2.8.3.3-02/-04); the referenced object at position " +
                    i.ToString(System.Globalization.CultureInfo.InvariantCulture) + " carries no digest.",
                    nameof(references));
            }
        }

        HashAlgorithm = hashAlgorithm;
        References = references;
    }


    /// <summary>Gets the <c>hashM</c> member shared by every entry in <see cref="References"/>.</summary>
    public string HashAlgorithm { get; }

    /// <summary>
    /// Gets the referenced detached data objects, in wire order. Owned by this instance; disposed via
    /// <see cref="Dispose"/>. Non-empty; every element carries a digest (constructor-enforced).
    /// </summary>
    public IReadOnlyList<JAdESReferencedDataObject> References { get; }


    /// <summary>Disposes every element of <see cref="References"/>.</summary>
    public void Dispose()
    {
        for(int i = 0; i < References.Count; ++i)
        {
            References[i].Dispose();
        }
    }
}


/// <summary>
/// A <c>sigD</c> detached-object reference identified by a mechanism this document does not itself define —
/// the open arm JA-5.2.8.1-C1 reserves ("3) Allow to define different mechanisms for meeting the two
/// aforementioned requirements"). <see cref="MechanismIdentifier"/> carries the wire <c>mId</c> value VERBATIM,
/// and every other <c>sigD</c> member this arm carries is an opaque fact: a third-party mechanism defines its
/// own <c>pars</c>/<c>hashM</c>/<c>hashV</c>/<c>ctys</c> semantics this model cannot assume. Mirrors
/// <see cref="CBAdESDetachedObjects"/>'s own open <c>mId</c> extension point (CB-5.2.8-15) — one arm of a C#
/// sum here rather than that type's single open-string carrier, per the type remarks on
/// <see cref="JAdESDetachedDataObjectReference"/>.
/// </summary>
/// <remarks>
/// <para>
/// The base <c>pars</c> non-empty requirement (JA-5.2.8.1-16) is the one invariant every mechanism — known or
/// not — shares, so it is the only one this arm's constructor enforces beyond <see cref="MechanismIdentifier"/>
/// itself not naming one of the three known mechanisms (which have their own dedicated arms).
/// <see cref="HashAlgorithm"/> and each <see cref="JAdESReferencedDataObject.Digest"/>/
/// <see cref="JAdESReferencedDataObject.ContentType"/> carry whatever presence pattern the unrecognized
/// mechanism defines, unvalidated (JA-5.2.8.1-M3: "may also incorporate any additional information for meeting
/// requirements 1) and 2) as required by the mechanisms mentioned in 3)" — the additional-information allowance
/// this arm represents for a third-party mechanism, mirroring how <c>hashM</c>/<c>hashV</c>/<c>ctys</c> are the
/// same allowance for the three the document itself names).
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns every element of <see cref="References"/>; disposing this
/// instance disposes them all.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESUnknownDetachedDataObjectReference: {MechanismIdentifier}, {References.Count} references")]
public sealed class JAdESUnknownDetachedDataObjectReference : JAdESDetachedDataObjectReference, IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="JAdESUnknownDetachedDataObjectReference"/>. Ownership of every element of
    /// <paramref name="references"/> transfers to this instance.
    /// </summary>
    /// <param name="mechanismIdentifier">
    /// The <c>mId</c> value, verbatim, of a mechanism this document does not itself define. Must not be one of
    /// <see cref="JAdESDetachedMechanisms"/>'s three known identifiers — those have their own dedicated arms.
    /// </param>
    /// <param name="references">
    /// The referenced detached data objects, in wire order (JA-5.2.8.1-16/-17). Must be non-empty
    /// (JA-5.2.8.1-16) — the one invariant every mechanism shares. Each entry's <see cref="JAdESReferencedDataObject.Digest"/>/
    /// <see cref="JAdESReferencedDataObject.ContentType"/> is carried as-is, unvalidated.
    /// </param>
    /// <param name="hashAlgorithm">
    /// The <c>hashM</c> member, or <see langword="null"/> — carried as an opaque fact; this arm enforces no
    /// presence coupling with any entry's digest, since a third-party mechanism defines its own rule.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="references"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="mechanismIdentifier"/> is <see langword="null"/> or empty, or is one of
    /// <see cref="JAdESDetachedMechanisms"/>'s three known identifiers; or <paramref name="references"/> is
    /// empty.
    /// </exception>
    public JAdESUnknownDetachedDataObjectReference(
        string mechanismIdentifier,
        IReadOnlyList<JAdESReferencedDataObject> references,
        string? hashAlgorithm = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(mechanismIdentifier);
        if(JAdESDetachedMechanisms.IsKnownMechanism(mechanismIdentifier))
        {
            throw new ArgumentException(
                "'" + mechanismIdentifier + "' is one of the three mechanisms this document defines by name " +
                "(ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, JA-5.2.8.1-14) and shall be represented by its own " +
                "dedicated arm, not this open-extension carrier.",
                nameof(mechanismIdentifier));
        }

        ArgumentNullException.ThrowIfNull(references);
        if(references.Count == 0)
        {
            throw new ArgumentException(
                "sigD's 'pars' member shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, " +
                "JA-5.2.8.1-16) — the one invariant every mechanism, known or not, shares.",
                nameof(references));
        }

        MechanismIdentifier = mechanismIdentifier;
        References = references;
        HashAlgorithm = hashAlgorithm;
    }


    /// <summary>Gets the <c>mId</c> value, verbatim, of the unrecognized mechanism.</summary>
    public string MechanismIdentifier { get; }

    /// <summary>
    /// Gets the referenced detached data objects, in wire order. Owned by this instance; disposed via
    /// <see cref="Dispose"/>. Non-empty (constructor-enforced); each entry's digest/content-type presence is an
    /// unvalidated, mechanism-defined fact.
    /// </summary>
    public IReadOnlyList<JAdESReferencedDataObject> References { get; }

    /// <summary>Gets the <c>hashM</c> member, or <see langword="null"/> when absent — an opaque, unvalidated fact.</summary>
    public string? HashAlgorithm { get; }


    /// <summary>Disposes every element of <see cref="References"/>.</summary>
    public void Dispose()
    {
        for(int i = 0; i < References.Count; ++i)
        {
            References[i].Dispose();
        }
    }
}


/// <summary>
/// The three <c>sigD</c> detached-object mechanisms clause 5.2.8 itself defines by name — <c>HttpHeaders</c>,
/// <c>ObjectIdByURI</c>, and <c>ObjectIdByURIHash</c> — each identified by the URI its own arm's
/// <c>MechanismIdentifier</c> static member carries. Mirrors <see cref="CBAdESDetachedMechanisms"/>'s identical
/// registry shape, one document removed.
/// </summary>
/// <remarks>
/// <para>
/// <c>mId</c> is an open extension point (JA-5.2.8.1-C1: "Allow to define different mechanisms..."): a
/// specification other than this one may define further mechanism identifiers, represented locally by
/// <see cref="JAdESUnknownDetachedDataObjectReference"/>. <see cref="IsKnownMechanism(string?)"/> recognizes
/// exactly the three arms clause 5.2.8 itself defines rather than treating every unrecognized value as an
/// error — a third-party mechanism is not malformed, only outside this registry's vocabulary (mirroring
/// <see cref="CBAdESDetachedMechanisms.IsKnownMechanism(string?)"/>'s identical posture verbatim-in-shape).
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive.</strong> A mechanism identifier is a URI compared as an
/// exact character sequence, consistent with each arm's own <see cref="Uri"/>-free <c>string</c>
/// <c>MechanismIdentifier</c>: <see cref="System.Uri"/> normalizes,
/// which would make two spellings differing by escaping compare equal as different mechanisms under
/// JA-5.2.8.1-C1's open extension point. This registry reuses each arm's own constant rather than restating
/// the three literal strings.
/// </para>
/// </remarks>
public static class JAdESDetachedMechanisms
{
    /// <summary>Determines whether a mechanism identifier is <see cref="JAdESHttpHeadersReference.MechanismIdentifier"/>.</summary>
    /// <param name="mechanismIdentifier">The <c>mId</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is exactly the <c>HttpHeaders</c> mechanism identifier.</returns>
    public static bool IsHttpHeaders(string? mechanismIdentifier) =>
        string.Equals(mechanismIdentifier, JAdESHttpHeadersReference.MechanismIdentifier, StringComparison.Ordinal);


    /// <summary>Determines whether a mechanism identifier is <see cref="JAdESObjectIdByUriReference.MechanismIdentifier"/>.</summary>
    /// <param name="mechanismIdentifier">The <c>mId</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is exactly the <c>ObjectIdByURI</c> mechanism identifier.</returns>
    public static bool IsObjectIdByUri(string? mechanismIdentifier) =>
        string.Equals(mechanismIdentifier, JAdESObjectIdByUriReference.MechanismIdentifier, StringComparison.Ordinal);


    /// <summary>Determines whether a mechanism identifier is <see cref="JAdESObjectIdByUriHashReference.MechanismIdentifier"/>.</summary>
    /// <param name="mechanismIdentifier">The <c>mId</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is exactly the <c>ObjectIdByURIHash</c> mechanism identifier.</returns>
    public static bool IsObjectIdByUriHash(string? mechanismIdentifier) =>
        string.Equals(mechanismIdentifier, JAdESObjectIdByUriHashReference.MechanismIdentifier, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a mechanism identifier is one of the three this document defines.
    /// </summary>
    /// <param name="mechanismIdentifier">The <c>mId</c> value, or <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the value is <see cref="JAdESHttpHeadersReference.MechanismIdentifier"/>,
    /// <see cref="JAdESObjectIdByUriReference.MechanismIdentifier"/>, or
    /// <see cref="JAdESObjectIdByUriHashReference.MechanismIdentifier"/>; <see langword="false"/> for a
    /// third-party mechanism (JA-5.2.8.1-C1) or an unset value.
    /// </returns>
    public static bool IsKnownMechanism(string? mechanismIdentifier) =>
        IsHttpHeaders(mechanismIdentifier) || IsObjectIdByUri(mechanismIdentifier) || IsObjectIdByUriHash(mechanismIdentifier);
}
