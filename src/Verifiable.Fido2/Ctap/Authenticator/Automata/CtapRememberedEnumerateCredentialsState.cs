using System;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The <c>enumerateCredentialsBegin</c> parameters an <c>enumerateCredentialsGetNextCredential</c>
/// command needs remembered across separate CTAP2 commands, persisted as a data field on
/// <see cref="CtapAuthenticatorState.RememberedEnumerateCredentials"/> — <see cref="CtapRememberedGetAssertionState"/>'s
/// own template, minus the signing-specific fields <c>enumerateCredentialsGetNextCredential</c> has no
/// analogue for.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8.4: Enumerating Credentials for an RP</see>: <c>enumerateCredentialsBegin</c>
/// initializes this sequence; <c>enumerateCredentialsGetNextCredential</c> consumes and advances it until
/// it is exhausted, expires, or an intervening command discards it. <c>enumerateCredentialsGetNextCredential</c>
/// takes no parameters of its own and signs nothing, so this record carries no
/// <c>ClientDataHash</c>/<c>UserPresent</c>/<c>UserVerified</c> fields. <see cref="ApplicableCredentialIds"/>
/// entries are BORROWED from <see cref="CtapAuthenticatorState.CredentialsByCredentialId"/> — the records
/// themselves stay in the store — so, like <see cref="CtapRememberedGetAssertionState"/>'s own identifier
/// list, this type owns no pooled memory and is not <see cref="IDisposable"/>.
/// </remarks>
/// <param name="ApplicableCredentialIds">
/// Every resident credential this authenticator holds whose relying party identifier's freshly computed
/// SHA-256 hash matched the initiating <c>enumerateCredentialsBegin</c> request's <c>rpIDHash</c>,
/// ordered <see cref="CtapCredentialRecord.CreationSequence"/>-ascending (an implementation choice — CTAP
/// 2.3 states no ordering requirement for credential enumeration). Index 0 was already reported by the
/// <c>enumerateCredentialsBegin</c> response that created this record;
/// <c>enumerateCredentialsGetNextCredential</c> returns the credential at
/// <see cref="CredentialCounter"/> on each call.
/// </param>
/// <param name="CredentialCounter">
/// The index, into <see cref="ApplicableCredentialIds"/>, of the next credential
/// <c>enumerateCredentialsGetNextCredential</c> will return. Starts at 1 (index 0 was already consumed by
/// the initiating <c>enumerateCredentialsBegin</c>) and increments by one after every successful
/// <c>enumerateCredentialsGetNextCredential</c>.
/// </param>
/// <param name="LastActivityAt">
/// The time of the last stateful step in this sequence, compared against the 30-second enumeration timer
/// on every subsequent <c>enumerateCredentialsGetNextCredential</c>. Always sourced from the simulator's
/// threaded <see cref="TimeProvider"/>, never <see cref="DateTimeOffset.UtcNow"/>.
/// </param>
/// <param name="AuthenticatingPinUvAuthProtocol">
/// The PIN/UV auth protocol whose <c>pinUvAuthToken</c> authenticated the originating
/// <c>enumerateCredentialsBegin</c> (CTAP 2.3, section 6, item 3, line 2873) — every
/// <c>enumerateCredentialsGetNextCredential</c> against this record folds this protocol's own
/// <see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/> before deciding whether to keep serving it. Never
/// <see langword="null"/>: every subcommand that initializes this sequence requires a verified
/// <c>pinUvAuthToken</c>.
/// </param>
public sealed record CtapRememberedEnumerateCredentialsState(
    IReadOnlyList<CredentialId> ApplicableCredentialIds,
    int CredentialCounter,
    DateTimeOffset LastActivityAt,
    CtapPinUvAuthProtocolId AuthenticatingPinUvAuthProtocol);
