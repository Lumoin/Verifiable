namespace Verifiable.Tpm.Automata;

/// <summary>
/// The first-block safety verdict a sequence context settles once, on the first block of data ever presented
/// to it — the rule <c>TPM2_SequenceUpdate()</c> states and a restricted signing key's
/// <c>TPM2_SignSequenceComplete()</c> consults (TPM 2.0 Library Part 3, clauses 17.7 and 17.8).
/// </summary>
/// <remarks>
/// <para>
/// Clause 17.7: "If the sequence is intended to produce a digest that will be signed by a restricted signing
/// key, then the first block of data shall contain at least sizeof(TPM_GENERATED) octets and the first octets
/// shall not be TPM_GENERATED_VALUE." Clause 17.8 adds the short-buffer case: a first block shorter than
/// <c>sizeof(TPM_GENERATED)</c> — four octets — makes the TPM "operate as if digest is not safe to sign".
/// Together the two clauses fix one verdict, taken on the FIRST block only and never revisited by any later
/// block: a restricted key protects against having its signature mistaken for the TPM's own attestation
/// (<c>TPMS_ATTEST.magic</c>, <c>TPM_GENERATED_VALUE</c>), and that protection is meaningless once the
/// message's shape is already fixed by an earlier, safe block.
/// </para>
/// <para>
/// <see cref="Automata.SequenceObjectState"/> settles this from <see cref="NotYetPresented"/> to
/// <see cref="SafeToSign"/> or <see cref="NotSafeToSign"/> the first time a block reaches the sequence — by
/// <c>TPM2_SequenceUpdate()</c> ordinarily, or by <c>TPM2_SignSequenceComplete()</c>'s own trailing
/// <c>buffer</c> when no prior update ever ran. Only a restricted signing key's completion consults the
/// verdict (an unrestricted key and a verification sequence ignore it entirely).
/// </para>
/// </remarks>
public enum TpmSequenceFirstBlock
{
    /// <summary>
    /// No block has reached the sequence yet, so the verdict is unsettled. A sequence closed while still in
    /// this state (a one-buffer completion with no prior <c>TPM2_SequenceUpdate()</c>) settles it from the
    /// completing command's own trailing buffer instead.
    /// </summary>
    NotYetPresented,

    /// <summary>
    /// The first block presented to the sequence was at least four octets long and its first four octets were
    /// not <c>TPM_GENERATED_VALUE</c> — a restricted signing key may complete this sequence.
    /// </summary>
    SafeToSign,

    /// <summary>
    /// The first block presented to the sequence was shorter than four octets, or its first four octets were
    /// <c>TPM_GENERATED_VALUE</c> — a restricted signing key's completion is refused (<c>TPM_RC_ATTRIBUTES</c>);
    /// an unrestricted key is unaffected.
    /// </summary>
    NotSafeToSign
}
