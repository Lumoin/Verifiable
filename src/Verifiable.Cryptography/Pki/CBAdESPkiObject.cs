using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>pkiOb</c> shared-syntax type of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.4.2</see> — the single opaque carrier for any PKI object (an X.509
/// certificate, a CRL, an OCSP response, or another format), reused verbatim wherever the document encapsulates
/// such an object, e.g. <c>valData</c>'s <c>xVals</c>/<c>rVals</c> members (clause 5.3.4).
/// </summary>
/// <remarks>
/// <para>CDDL (clause 5.4.2, Table 12 keys):</para>
/// <code>
/// pkiOb = {
///     1 =&gt; bstr,               ; val
///     ? 2 =&gt; #6.32(tstr),      ; encoding
///     ? 3 =&gt; #6.32(tstr)       ; specRef
/// }
/// </code>
/// </remarks>
[DebuggerDisplay("CBAdESPkiObject({Val.Length} bytes, Encoding={Encoding})")]
public sealed record CBAdESPkiObject
{
    /// <summary>The <c>val</c> member's map key (Table 12, clause 5.4.2).</summary>
    public const int ValKey = 1;

    /// <summary>The <c>encoding</c> member's map key (Table 12, clause 5.4.2).</summary>
    public const int EncodingKey = 2;

    /// <summary>The <c>specRef</c> member's map key (Table 12, clause 5.4.2).</summary>
    public const int SpecRefKey = 3;

    /// <summary>
    /// Gets the encapsulated PKI object's encoded octets (clause 5.4.2). <strong>Borrowed</strong> view — the
    /// caller (creation path) or the wire-bytes source (parse path) owns the underlying memory.
    /// </summary>
    /// <remarks>
    /// When <see cref="Encoding"/> is <see langword="null"/>, these octets are the DER-encoded ASN.1 data per
    /// clause 5.4.2 (the default encoding when <c>encoding</c> is absent); otherwise they are encoded as
    /// <see cref="Encoding"/> states. Owned, pooled-memory carrier variants for the creation path are introduced
    /// alongside the stage that builds <c>valData</c>, and are not modelled here.
    /// </remarks>
    public required ReadOnlyMemory<byte> Val { get; init; }

    /// <summary>
    /// Gets the URI identifying the encoding used for <see cref="Val"/> (clause 5.4.2), or <see langword="null"/>
    /// to mean DER — the default when <c>encoding</c> is absent. The legal value set for this URI is defined by
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.01.01_60/en_31913201v010101p.pdf">
    /// ETSI EN 319 132-1 (JAdES), clause 5.1.3</see>, not by the present document.
    /// </summary>
    public Uri? Encoding { get; init; }

    /// <summary>
    /// Gets the URI identifying the technical specification that defines the encapsulated PKI object (clause
    /// 5.4.2), or <see langword="null"/> when absent.
    /// </summary>
    public Uri? SpecRef { get; init; }
}
