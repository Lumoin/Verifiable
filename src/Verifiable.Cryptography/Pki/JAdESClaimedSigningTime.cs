using System;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A claimed signing time, shared by both signed header parameters that carry one across
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>: <c>iat</c> (clause 5.1.11, RFC 7519 §4.1.6's <c>NumericDateValue</c>
/// integer wire form) and its legacy predecessor <c>sigT</c> (clause 5.2.1, an RFC 3339 string wire form).
/// </summary>
/// <remarks>
/// <para>
/// <strong>The mandatory-optional flip.</strong> The two header
/// parameters' mandatory-optional status flipped at 2025-07-15T00:00:00Z, a date already passed:
/// <c>iat</c> is MANDATORY on every creation surface from the outset; <c>sigT</c> is legacy/validation-only,
/// read-tolerated but never emitted by a creation surface built against this document version
/// (JA-5.1.11-07/-08, JA-5.2.1-07/-08/-09). Both header parameters' own carrier slots on
/// <c>JAdESProtectedHeaders</c> use this one shared type — a parsed message carrying either, both (a
/// pre-cutover signature migrating), or neither is a well-formed, non-conformant local shape (mirroring
/// <c>CBAdESProtectedHeaders</c>'s identical "model permits absence/coexistence, a later rules layer reports
/// the violation" split) — this mandatory/legacy split is a validation-layer concern, not enforced by this
/// model.
/// </para>
/// <para>
/// <strong>Permissive carrier, write-strict minting.</strong> This type
/// represents any RFC 3339-parseable instant, offset and fractional seconds included — a parsed <c>sigT</c>
/// string or a legacy/foreign <c>iat</c> value may carry either, and a validator must be able to hold that fact
/// in memory to report it, the same "well-formed but non-conformant parsed message" posture
/// <c>JAdESProtectedHeaders</c>' own remarks describe for cross-header rules. <see cref="Value"/> therefore
/// carries the supplied <see cref="DateTimeOffset"/> unconditionally; <see cref="IsUtc"/> and
/// <see cref="HasFractionalSeconds"/> expose the two facts JA-5.1.11-05/JA-5.2.1-05/-06 state as SHALLs
/// (UTC-only; no fractional-seconds component) so a later validator can report a violation instead of this
/// constructor silently rejecting the value it needs to represent. Enforcing those SHALLs against a value about
/// to be MINTED — refusing a non-conformant <c>iat</c>/<c>sigT</c> before it reaches the wire — is the
/// creation orchestrator's responsibility (not yet built): the write path stays strict even though this
/// carrier itself no longer throws.
/// </para>
/// </remarks>
public sealed record JAdESClaimedSigningTime
{
    /// <summary>
    /// Initializes a new <see cref="JAdESClaimedSigningTime"/> from any RFC 3339-parseable instant — see the
    /// type remarks for why offset and fractional seconds are preserved rather than rejected here.
    /// </summary>
    /// <param name="value">The claimed signing time, any offset and precision.</param>
    public JAdESClaimedSigningTime(DateTimeOffset value)
    {
        Value = value;
    }


    /// <summary>Gets the claimed signing time, exactly as supplied — any offset, any sub-second precision.</summary>
    public DateTimeOffset Value { get; }

    /// <summary>
    /// Gets whether <see cref="Value"/> carries a zero UTC offset — the fact JA-5.1.11-04/JA-5.2.1-05 state as a
    /// SHALL. <see langword="false"/> marks a non-conformant value this carrier still represents; enforcing the
    /// SHALL is a later stage's concern (see the type remarks).
    /// </summary>
    public bool IsUtc => Value.Offset == TimeSpan.Zero;

    /// <summary>
    /// Gets whether <see cref="Value"/> carries a sub-second component — the negation of the fact
    /// JA-5.1.11-05/JA-5.2.1-06 state as a SHALL ("shall not contain fractions of seconds").
    /// <see langword="true"/> marks a non-conformant value this carrier still represents; enforcing the SHALL is
    /// a later stage's concern (see the type remarks).
    /// </summary>
    public bool HasFractionalSeconds => Value.Ticks % TimeSpan.TicksPerSecond != 0;
}
