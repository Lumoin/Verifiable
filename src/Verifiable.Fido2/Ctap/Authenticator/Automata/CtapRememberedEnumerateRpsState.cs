using System;
using System.Collections.Generic;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The <c>enumerateRPsBegin</c> parameters an <c>enumerateRPsGetNextRP</c> command needs remembered
/// across separate CTAP2 commands, persisted as a data field on
/// <see cref="CtapAuthenticatorState.RememberedEnumerateRps"/> — <see cref="CtapRememberedGetAssertionState"/>'s
/// own template, minus the signing-specific fields <c>enumerateRPsGetNextRP</c> has no analogue for.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8.3: Enumerating RPs</see>: <c>enumerateRPsBegin</c> initializes this sequence;
/// <c>enumerateRPsGetNextRP</c> consumes and advances it until it is exhausted, expires, or an
/// intervening command discards it (CTAP 2.3, section 6, item 2, the "stateful commands" preamble).
/// <c>enumerateRPsGetNextRP</c> takes no parameters of its own and signs nothing, so this record carries
/// no <c>ClientDataHash</c>/<c>UserPresent</c>/<c>UserVerified</c> fields. Neither this record nor
/// <see cref="ApplicableRpIds"/> owns any pooled memory (RP identifiers are plain immutable
/// <see cref="string"/>s), so this type is not <see cref="IDisposable"/>.
/// </remarks>
/// <param name="ApplicableRpIds">
/// Every relying party identifier holding at least one discoverable credential, ordered
/// <see cref="CtapCredentialRecord.CreationSequence"/>-ascending by each RP's first-created credential
/// (an implementation choice — CTAP 2.3 states no ordering requirement for RP enumeration). Index 0 was
/// already reported by the <c>enumerateRPsBegin</c> response that created this record;
/// <c>enumerateRPsGetNextRP</c> returns the RP at <see cref="RpCounter"/> on each call.
/// </param>
/// <param name="RpCounter">
/// The index, into <see cref="ApplicableRpIds"/>, of the next RP <c>enumerateRPsGetNextRP</c> will
/// return. Starts at 1 (index 0 was already consumed by the initiating <c>enumerateRPsBegin</c>) and
/// increments by one after every successful <c>enumerateRPsGetNextRP</c>.
/// </param>
/// <param name="LastActivityAt">
/// The time of the last stateful step in this sequence — the originating <c>enumerateRPsBegin</c>, or
/// the most recent <c>enumerateRPsGetNextRP</c> — compared against the 30-second enumeration timer on
/// every subsequent <c>enumerateRPsGetNextRP</c>. Always sourced from the simulator's threaded
/// <see cref="TimeProvider"/>, never <see cref="DateTimeOffset.UtcNow"/>.
/// </param>
/// <param name="AuthenticatingPinUvAuthProtocol">
/// The PIN/UV auth protocol whose <c>pinUvAuthToken</c> authenticated the originating
/// <c>enumerateRPsBegin</c>. CTAP 2.3, section 6, item 3 (line 2873): "An authenticator MUST discard the
/// state for a stateful command command if the pinUvAuthToken that authenticated the state initializing
/// command expires" — every <c>enumerateRPsGetNextRP</c> against this record folds this protocol's own
/// <see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/> before deciding whether to keep serving it.
/// Never <see langword="null"/>: every subcommand that initializes this sequence is one of the five
/// <c>authenticatorCredentialManagement</c> subcommands that require a verified <c>pinUvAuthToken</c>.
/// </param>
public sealed record CtapRememberedEnumerateRpsState(
    IReadOnlyList<string> ApplicableRpIds,
    int RpCounter,
    DateTimeOffset LastActivityAt,
    CtapPinUvAuthProtocolId AuthenticatingPinUvAuthProtocol);
