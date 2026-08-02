using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>tstContainer</c> shared-syntax type of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3</see> — a non-empty, ordered set of one or more electronic
/// time-stamp tokens computed over the same message imprint (e.g. one token per Time-Stamping Authority, for
/// redundancy). Reused verbatim by <c>sigTst</c> (clause 5.3.3) and <c>arcTst</c> (clause 5.3.5.1), and, per
/// Annex A (out of this stage), by <c>sigRTst</c>/<c>rfsTst</c>.
/// </summary>
/// <remarks>
/// <para>CDDL (clause 5.4.3.3, Table 13 keys):</para>
/// <code>
/// tstContainer = {
///     1 =&gt; [ +TstToken ]   ; tstTokens
/// }
/// </code>
/// <para>
/// <strong>Ownership.</strong> <see cref="CBAdESTimestampToken.Val"/> is a borrowed view in this stage (see
/// that type's remarks), so <see cref="Dispose"/> currently has nothing of its own to release; the type
/// still implements <see cref="IDisposable"/> so callers that own a container through the composed
/// <c>adoTst</c>/<c>sigTst</c>/<c>arcTst</c> parameters (e.g. <see cref="CBAdESPayloadTimestamp"/>, which
/// documents forwarding disposal here and relies on this method being idempotent) need no signature change
/// once a later stage introduces owned, pooled token buffers.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESTimestampContainer({TstTokens.Count} tokens)")]
public sealed record CBAdESTimestampContainer: IDisposable
{
    /// <summary>The <c>tstTokens</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    public const int TstTokensKey = 1;

    /// <summary>
    /// Gets the encapsulated time-stamp tokens (clause 5.4.3.3), in the order they appear on the wire. The
    /// CDDL's <c>+</c> cardinality requires at least one entry.
    /// </summary>
    public required IReadOnlyList<CBAdESTimestampToken> TstTokens { get; init; }


    /// <summary>
    /// Releases every owned resource reachable through <see cref="TstTokens"/>. A no-op today — see the
    /// type remarks — kept idempotent and safe to call any number of times.
    /// </summary>
    public void Dispose()
    {
    }
}


/// <summary>
/// The <c>TstToken</c> shared-syntax type of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3</see> — one electronic time-stamp token. Format-agile by design:
/// besides the encoded token octets, it carries an optional token type, an optional encoding, and an optional
/// defining-specification URI, so a future time-stamp format needs no new wire type.
/// </summary>
/// <remarks>
/// <para>CDDL (clause 5.4.3.3, Table 13 keys; the source spells the <c>val</c> member's separator as a bare
/// <c>:</c> rather than the document's otherwise-uniform <c>=&gt;</c> — reproduced here as <c>=&gt;</c>, the
/// form used everywhere else in the document, pending upstream confirmation):</para>
/// <code>
/// TstToken = {
///     1 =&gt; bstr,               ; val
///     ? 2 =&gt; tstr,             ; type
///     ? 3 =&gt; #6.32(tstr),      ; encoding
///     ? 4 =&gt; #6.32(tstr)       ; specRef
/// }
/// </code>
/// <para>
/// For an <see href="https://www.rfc-editor.org/rfc/rfc3161">IETF RFC 3161</see> time-stamp token — profiled by
/// <see href="https://www.rfc-editor.org/rfc/rfc5816">RFC 5816</see> and, per this wave's ruling on
/// requirement CB-6.3-02, currently the only format the document's baseline conformance accepts —
/// <see cref="Type"/>, <see cref="Encoding"/>, and <see cref="SpecRef"/> shall all be absent (clause 5.4.3.3)
/// and <see cref="Val"/> shall be the DER-encoded token itself. That narrowing is a validation rule owned by a
/// later stage, not a restriction this model imposes: the three members stay available here so a
/// differently-formatted token can still be represented.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESTimestampToken({Val.Length} bytes, Type={Type})")]
public sealed record CBAdESTimestampToken
{
    /// <summary>The <c>val</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    public const int ValKey = 1;

    /// <summary>The <c>type</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    public const int TypeKey = 2;

    /// <summary>The <c>encoding</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    public const int EncodingKey = 3;

    /// <summary>The <c>specRef</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    public const int SpecRefKey = 4;

    /// <summary>
    /// Gets the encoded time-stamp token's octets (clause 5.4.3.3). <strong>Borrowed</strong> view — the caller
    /// (creation path) or the wire-bytes source (parse path) owns the underlying memory.
    /// </summary>
    /// <remarks>
    /// For an RFC 3161 token these are the DER-encoded token itself. Owned, pooled-memory carrier variants for
    /// the creation path arrive with the stage that acquires tokens from a Time-Stamping Authority, and are not
    /// modelled here.
    /// </remarks>
    public required ReadOnlyMemory<byte> Val { get; init; }

    /// <summary>
    /// Gets the string identifying the time-stamp token's type (clause 5.4.3.3), or <see langword="null"/> when
    /// absent — always absent for an RFC 3161 token.
    /// </summary>
    public string? Type { get; init; }

    /// <summary>
    /// Gets the URI identifying the encoding used for <see cref="Val"/> (clause 5.4.3.3), or
    /// <see langword="null"/> when absent — always absent for an RFC 3161 token.
    /// </summary>
    public Uri? Encoding { get; init; }

    /// <summary>
    /// Gets the URI identifying the technical specification that defines this time-stamp token's format
    /// (clause 5.4.3.3), or <see langword="null"/> when absent — always absent for an RFC 3161 token.
    /// </summary>
    public Uri? SpecRef { get; init; }
}
