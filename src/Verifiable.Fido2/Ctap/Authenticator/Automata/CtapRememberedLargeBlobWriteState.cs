using System;
using System.Buffers;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The volatile <c>expectedNextOffset</c>/<c>expectedLength</c> pair (CTAP 2.3 §6.10.2, line 7586) plus
/// the not-yet-committed pending serialized large-blob array buffer an in-progress
/// <c>authenticatorLargeBlobs</c> <c>set</c> sequence needs remembered across separate CTAP2 commands —
/// the FIFTH remembered-sequence slot, held on <see cref="CtapAuthenticatorState.RememberedLargeBlobWrite"/>
/// (R7), sibling to <see cref="CtapRememberedGetAssertionState"/>/<see cref="CtapRememberedEnumerateRpsState"/>/
/// <see cref="CtapRememberedEnumerateCredentialsState"/>/<see cref="CtapRememberedBioEnrollmentState"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10.2: Reading and writing serialised data</see>. Installed once <c>set</c>'s
/// <c>offset == 0</c> branch resolves <c>expectedLength</c> (line 7624) and a fragment has been appended
/// into <see cref="PendingBuffer"/>, rented ONCE at <see cref="ExpectedLength"/> bytes up front (seams
/// Q5, rather than growing per fragment); advanced by every accepted continuation fragment (lines
/// 7659-7661); consumed — and <see cref="PendingBuffer"/> either adopted into
/// <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> or discarded — once the pending buffer's
/// length reaches <see cref="ExpectedLength"/> (line 7663), whether the integrity check that follows
/// succeeds or fails. Discarded — with <see cref="PendingBuffer"/> disposed — by every OTHER command (the
/// R7 GLOBAL discipline, CTAP 2.3 section 6 item 2, line 2871's "MAY assume this globally"; see
/// <c>CtapAuthenticatorTransitions.DiscardAllRememberedSequences</c>), by
/// <see cref="CtapAuthenticatorState.PowerCycle"/> (line 2869), by <see cref="CtapAuthenticatorState.FactoryReset"/>,
/// and by the token-expiry discard (line 2873) evaluated against <see cref="AuthenticatingPinUvAuthProtocol"/>
/// when the sequence was gate-armed.
/// </remarks>
/// <param name="ExpectedLength">
/// The total length the completed pending serialized large-blob array must reach (CTAP 2.3 §6.10.2,
/// line 7624, <c>expectedLength</c>) — fixed for the sequence's whole lifetime, resolved once from the
/// initiating fragment's <c>length</c> parameter.
/// </param>
/// <param name="ExpectedNextOffset">
/// The byte offset the NEXT accepted fragment must start at (lines 7586/7661, <c>expectedNextOffset</c>)
/// — equal to the number of bytes already written into <see cref="PendingBuffer"/>.
/// </param>
/// <param name="PendingBuffer">
/// The not-yet-committed pending serialized large-blob array, rented at <see cref="ExpectedLength"/>
/// bytes when the sequence was installed — owned by this record until a commit transfers its bytes into
/// <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> or an integrity failure discards it,
/// leaving the previously stored array unchanged (line 7666). CTAP 2.3, line 7701's single-buffer MAY
/// ("use <c>expectedLength</c> to buffer the final 16 bytes... in volatile storage") is DECLINED: this
/// simulator double-buffers — a fully separate pending buffer, entirely independent of
/// <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> — which is also why line 7703's
/// corruption self-heal MAY ("the authenticator MAY reset the stored value with the initial serialized
/// large-blob array") is UNREACHABLE by construction here: <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/>
/// is only ever replaced by <c>CtapAuthenticatorTransitions.OnLargeBlobArrayCommitAttempted</c> AFTER the
/// commit-time integrity check has already passed, so an invalid stored array can never arise for this
/// simulator to detect or heal.
/// </param>
/// <param name="AuthenticatingPinUvAuthProtocol">
/// The PIN/UV auth protocol whose <c>pinUvAuthToken</c> authenticated the fragment that installed this
/// sequence, or <see langword="null"/> when the sequence was installed TOKENLESS (the R5 gate was
/// unarmed at that time — line 7682's "a serialized large-blob array can be written without user
/// verification if user verification is not configured"). CTAP 2.3, section 6, item 3 (line 2873): "An
/// authenticator MUST discard the state for a stateful command ... if the pinUvAuthToken that
/// authenticated the state initializing command expires" — this field's antecedent is FALSE for a
/// tokenless sequence, since no token exists to expire (R7, documented).
/// </param>
public sealed record CtapRememberedLargeBlobWriteState(
    int ExpectedLength,
    int ExpectedNextOffset,
    IMemoryOwner<byte> PendingBuffer,
    CtapPinUvAuthProtocolId? AuthenticatingPinUvAuthProtocol): IDisposable
{
    /// <summary>
    /// Releases the not-yet-committed <see cref="PendingBuffer"/> this record owns.
    /// </summary>
    public void Dispose()
    {
        PendingBuffer.Dispose();
    }
}
