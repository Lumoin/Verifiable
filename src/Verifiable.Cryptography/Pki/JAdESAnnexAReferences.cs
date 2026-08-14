using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>x5Ids</c> shared JSON-array shape backing Annex A.1.1's <c>xRefs</c> and Annex A.1.3's <c>axRefs</c>
/// (schema <c>"axRefs": {"$ref": "#/definitions/x5Ids"}</c>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see> — a non-empty, ordered list of certificate digest references (the
/// <c>CertId</c> item shape's mandatory <c>digAlg</c>/<c>digVal</c> core, JA-A.1.1-07/-09).
/// </summary>
/// <remarks>
/// <strong>Minimal, raw-preserving.</strong>
/// <c>CertId</c>'s optional <c>kid</c>/<c>x5u</c> hint members (JA-A.1.1-10/-11) are a disclosed residue left
/// to a later stage, the same posture already applied to <see cref="AdESPkiObject.Encoding"/> — only the
/// mandatory digest identity is modeled, reusing <see cref="AdESCertificateThumbprint"/>'s own
/// <c>digAlg</c>/<c>digVal</c> shape verbatim rather than reinventing it (the two occurrences of the shape are
/// structurally identical: JA-A.1.1-07/-09 word <c>CertId</c>'s core exactly as JA-5.2.2.2-05/-07 word
/// <c>x5t#o</c>'s). The Annex A.1.1/A.1.3 content-selection semantics (which certificates belong in the list,
/// JA-A.1.1-01..-05) are the identical cross-referential, later-validation-stage concern
/// <see cref="JAdESCertificateValues"/>'s own remarks already establish for <c>xVals</c>; this type enforces
/// only the array's non-emptiness.
/// </remarks>
[DebuggerDisplay("JAdESCertificateReferenceCollection({Items.Count} items)")]
public sealed class JAdESCertificateReferenceCollection: IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="JAdESCertificateReferenceCollection"/>. Ownership of every entry in
    /// <paramref name="items"/> transfers to this instance.
    /// </summary>
    /// <param name="items">The certificate digest references, in wire order. Must be non-empty.</param>
    /// <exception cref="ArgumentNullException"><paramref name="items"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="items"/> is empty.</exception>
    public JAdESCertificateReferenceCollection(IReadOnlyList<AdESCertificateThumbprint> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        if(items.Count == 0)
        {
            throw new ArgumentException(
                "xRefs/axRefs shall be a non-empty array of certificate references (ETSI TS 119 182-1 V1.2.1, Annex A.1.1/A.1.3).",
                nameof(items));
        }

        Items = items;
    }


    /// <summary>Gets the certificate digest references, in wire order. Non-empty.</summary>
    public IReadOnlyList<AdESCertificateThumbprint> Items { get; }


    /// <summary>Disposes every entry this instance owns.</summary>
    public void Dispose()
    {
        for(int i = 0; i < Items.Count; ++i)
        {
            Items[i].Dispose();
        }
    }
}


/// <summary>
/// The <c>rRefs</c> shared JSON-object shape backing Annex A.1.2's <c>rRefs</c> and Annex A.1.4's <c>arRefs</c>
/// (schema <c>"arRefs": {"$ref": "#/definitions/rRefs"}</c>) — three independently-optional non-empty lists:
/// CRL references, OCSP references (both minimally modeled as digest references, mirroring
/// <see cref="JAdESCertificateReferenceCollection"/>'s own minimal posture), and opaque "other" references.
/// </summary>
/// <remarks>
/// <strong>Minimal, raw-preserving.</strong>
/// The <c>crlId</c>/<c>ocspId</c> identifying-hint members (JA-A.1.2-16..-30) are a disclosed residue, matching
/// <see cref="JAdESCertificateReferenceCollection"/>'s own <c>kid</c>/<c>x5u</c> omission — each
/// <c>CRLRef</c>/<c>OCSPRef</c>'s mandatory <c>digAlgVal</c> core is the same digest shape
/// <see cref="AdESCertificateThumbprint"/> already models. "Empty <c>rRefs</c> shall not be incorporated"
/// (JA-A.1.2-10) — at least one member required, enforced at construction, mirroring
/// <see cref="JAdESRevocationValues"/>'s own at-least-one-member invariant.
/// </remarks>
[DebuggerDisplay("JAdESRevocationReferenceCollection(Crl={CrlReferences.Count}, Ocsp={OcspReferences.Count}, Other={OtherReferences.Count})")]
public sealed class JAdESRevocationReferenceCollection: IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="JAdESRevocationReferenceCollection"/>. Ownership of every entry in
    /// <paramref name="crlReferences"/> and <paramref name="ocspReferences"/> transfers to this instance.
    /// </summary>
    /// <param name="crlReferences">
    /// The <c>crlRefs</c> member, or <see langword="null"/> to omit it. When supplied, must be non-empty.
    /// </param>
    /// <param name="ocspReferences">
    /// The <c>ocspRefs</c> member, or <see langword="null"/> to omit it. When supplied, must be non-empty.
    /// </param>
    /// <param name="otherReferences">
    /// The <c>otherRefs</c> member: opaque raw item bytes, borrowed, or <see langword="null"/> to omit it. When
    /// supplied, must be non-empty.
    /// </param>
    /// <exception cref="ArgumentException">
    /// All three parameters are <see langword="null"/> (JA-A.1.2-10); or one of them is non-null but empty.
    /// </exception>
    public JAdESRevocationReferenceCollection(
        IReadOnlyList<AdESCertificateThumbprint>? crlReferences = null,
        IReadOnlyList<AdESCertificateThumbprint>? ocspReferences = null,
        IReadOnlyList<ReadOnlyMemory<byte>>? otherReferences = null)
    {
        if(crlReferences is null && ocspReferences is null && otherReferences is null)
        {
            throw new ArgumentException(
                "Empty 'rRefs'/'arRefs' shall not be incorporated; at least one of crlRefs/ocspRefs/otherRefs " +
                "shall be present (ETSI TS 119 182-1 V1.2.1, Annex A.1.2, JA-A.1.2-10).");
        }

        ThrowIfEmpty(crlReferences, nameof(crlReferences), "crlRefs");
        ThrowIfEmpty(ocspReferences, nameof(ocspReferences), "ocspRefs");
        if(otherReferences is not null && otherReferences.Count == 0)
        {
            throw new ArgumentException(
                "When present, 'otherRefs' shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, Annex A.1.2).",
                nameof(otherReferences));
        }

        CrlReferences = crlReferences ?? [];
        OcspReferences = ocspReferences ?? [];
        OtherReferences = otherReferences ?? [];

        static void ThrowIfEmpty(IReadOnlyList<AdESCertificateThumbprint>? candidate, string paramName, string wireName)
        {
            if(candidate is not null && candidate.Count == 0)
            {
                throw new ArgumentException(
                    $"When present, '{wireName}' shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, Annex A.1.2).",
                    paramName);
            }
        }
    }


    /// <summary>Gets the <c>crlRefs</c> member, or an empty list when absent.</summary>
    public IReadOnlyList<AdESCertificateThumbprint> CrlReferences { get; }

    /// <summary>Gets the <c>ocspRefs</c> member, or an empty list when absent.</summary>
    public IReadOnlyList<AdESCertificateThumbprint> OcspReferences { get; }

    /// <summary>
    /// Gets the <c>otherRefs</c> member: opaque, raw item bytes, or an empty list when absent. Borrowed views —
    /// the caller (creation path) or the wire-bytes source (parse path) owns the underlying memory.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> OtherReferences { get; }


    /// <summary>Disposes every entry <see cref="CrlReferences"/>/<see cref="OcspReferences"/> own.</summary>
    public void Dispose()
    {
        for(int i = 0; i < CrlReferences.Count; ++i)
        {
            CrlReferences[i].Dispose();
        }

        for(int i = 0; i < OcspReferences.Count; ++i)
        {
            OcspReferences[i].Dispose();
        }
    }
}
