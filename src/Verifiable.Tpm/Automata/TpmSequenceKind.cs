namespace Verifiable.Tpm.Automata;

/// <summary>
/// The kind of sequence object a sequence-context handle names — the five kinds TPM 2.0 Library Part 1,
/// clause 29.4.1 enumerates for the sequence-command family.
/// </summary>
/// <remarks>
/// <para>
/// Clause 29.4.1 lists five sequence kinds a <c>TPM2_HashSequenceStart()</c>/<c>TPM2_HMAC_Start()</c>/
/// <c>TPM2_SignSequenceStart()</c>/<c>TPM2_VerifySequenceStart()</c> call may open: an ordinary hash sequence,
/// an event sequence, an HMAC sequence, a signing sequence, and a verification sequence. This type carries all
/// five — <see cref="Hash"/> and <see cref="Event"/> from <c>TPM2_HashSequenceStart()</c> (an implemented
/// <c>hashAlg</c> versus <c>TPM_ALG_NULL</c>, clause 17.4.1), <see cref="Hmac"/> from <c>TPM2_HMAC_Start()</c>
/// against a loaded KEYEDHASH HMAC key, <see cref="Signing"/> from <c>TPM2_SignSequenceStart()</c>, and
/// <see cref="Verification"/> from <c>TPM2_VerifySequenceStart()</c>.
/// </para>
/// <para>
/// Each completing command requires the sequence at its <c>@sequenceHandle</c> to carry the matching kind:
/// <c>TPM2_SequenceComplete()</c> completes <see cref="Hash"/> (a digest and a <c>TPMT_TK_HASHCHECK</c>) and
/// <see cref="Hmac"/> (an HMAC and a NULL ticket, Table 94) — clause 17.8.1: an Event Sequence answers
/// <c>TPM_RC_MODE</c> — <c>TPM2_EventSequenceComplete()</c> only <see cref="Event"/> (clause 17.9.1: a hash or
/// HMAC sequence answers <c>TPM_RC_MODE</c>), <c>TPM2_SignSequenceComplete()</c> only <see cref="Signing"/> and
/// <c>TPM2_VerifySequenceComplete()</c> only <see cref="Verification"/> (clauses 20.6 and 20.3); every mismatch
/// answers <c>TPM_RC_MODE</c>.
/// </para>
/// </remarks>
public enum TpmSequenceKind
{
    /// <summary>
    /// A signing sequence opened by <c>TPM2_SignSequenceStart()</c> and closed by
    /// <c>TPM2_SignSequenceComplete()</c>, which produces a <c>TPMT_SIGNATURE</c> over the accumulated message
    /// (TPM 2.0 Library Part 3, clauses 17.5 and 20.6).
    /// </summary>
    Signing,

    /// <summary>
    /// A verification sequence opened by <c>TPM2_VerifySequenceStart()</c> and closed by
    /// <c>TPM2_VerifySequenceComplete()</c>, which checks a caller-supplied <c>TPMT_SIGNATURE</c> against the
    /// accumulated message and, on success, mints a <c>TPM_ST_MESSAGE_VERIFIED</c> ticket (TPM 2.0 Library
    /// Part 3, clauses 17.6 and 20.3).
    /// </summary>
    Verification,

    /// <summary>
    /// A hash sequence opened by <c>TPM2_HashSequenceStart()</c> with an implemented <c>hashAlg</c> and closed
    /// by <c>TPM2_SequenceComplete()</c>, which returns the digest of the accumulated data and a
    /// <c>TPMT_TK_HASHCHECK</c> ticket saying whether that digest may be signed with a restricted key (TPM 2.0
    /// Library Part 3, clauses 17.4 and 17.8; Part 1, clause 29.4.2). Bound to no key.
    /// </summary>
    Hash,

    /// <summary>
    /// An Event Sequence opened by <c>TPM2_HashSequenceStart()</c> with <c>hashAlg</c> = <c>TPM_ALG_NULL</c>
    /// and closed by <c>TPM2_EventSequenceComplete()</c>, which digests the accumulated data once per
    /// implemented PCR bank and, when a PCR is named, extends each bank with its digest (TPM 2.0 Library Part 3,
    /// clauses 17.4 and 17.9; Part 1, clause 29.4.3). Bound to no key; carries no hash algorithm of its own.
    /// </summary>
    Event,

    /// <summary>
    /// An HMAC sequence opened by <c>TPM2_HMAC_Start()</c> against a loaded KEYEDHASH HMAC key and closed by
    /// <c>TPM2_SequenceComplete()</c>, which returns <c>HMAC_hashAlg(key, message)</c> over the accumulated data
    /// and a NULL <c>TPMT_TK_HASHCHECK</c> (TPM 2.0 Library Part 3, clauses 17.2 and 17.8, Table 94; Part 1,
    /// clause 29.4.4). Bound to the HMAC key's sensitive value, which the sequence copies at
    /// <c>TPM2_HMAC_Start()</c> and owns for its lifetime.
    /// </summary>
    Hmac
}
