using System;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The <c>authenticatorGetAssertion</c> parameters an <c>authenticatorGetNextAssertion</c> command needs
/// remembered across separate CTAP2 commands, persisted as a data field on
/// <see cref="CtapAuthenticatorState.RememberedGetAssertion"/> — never a
/// <see cref="CtapAuthenticatorStackSymbol"/>, since this statefulness spans complete, independent
/// commands rather than nesting inside one ceremony.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2</see>, step 12's no-display/silent-authentication branch: "Remember the
/// authenticatorGetAssertion parameters. Create a credential counter... and set it to 1... Select the
/// first credential." This record is that remembered set, minted once when a multi-account
/// <c>authenticatorGetAssertion</c> locates more than one applicable credential, and consulted (and
/// advanced) by every following <c>authenticatorGetNextAssertion</c> until it is exhausted, expires, or an
/// intervening command discards it.
/// </remarks>
/// <param name="ApplicableCredentialIds">
/// The complete applicable-credential list an <c>authenticatorGetAssertion</c> located, ordered
/// most-recently-created first (CTAP 2.3, section 6.2, step 12: "order the credentials... by the time
/// when they were created in reverse order"). Index 0 was already signed and returned by the
/// <c>authenticatorGetAssertion</c> response that created this record; <c>authenticatorGetNextAssertion</c>
/// returns the credential at <see cref="CredentialCounter"/> on each call. Credential identifiers only —
/// the records themselves stay in <see cref="CtapAuthenticatorState.CredentialsByCredentialId"/>.
/// </param>
/// <param name="ClientDataHash">
/// An independently pooled copy of the originating <c>authenticatorGetAssertion</c> request's client
/// data hash, reused unchanged for every subsequent <c>authenticatorGetNextAssertion</c> signature in
/// this sequence — never the request's own carrier, which the transport layer disposes once that single
/// command completes. Owned by this record; disposed when the remembered state is discarded or replaced.
/// </param>
/// <param name="UserPresent">
/// The <c>up</c> option resolution the originating <c>authenticatorGetAssertion</c> request made,
/// reused for every <c>authenticatorGetNextAssertion</c> signature in the sequence — the command takes no
/// parameters of its own.
/// </param>
/// <param name="UserVerified">
/// The <c>uv</c> bit the originating <c>authenticatorGetAssertion</c> resolved, reused unchanged for every
/// <c>authenticatorGetNextAssertion</c> signature in the sequence.
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion">
/// CTAP 2.3, section 6.3</see>: "On success, the authenticator returns the same structure as returned by
/// the authenticatorGetAssertion method" — a series that was user-verified when it was located must report
/// <c>uv=1</c> on every response it produces, including the continuations, not only the first one.
/// </param>
/// <param name="CredentialCounter">
/// The index, into <see cref="ApplicableCredentialIds"/>, of the next credential
/// <c>authenticatorGetNextAssertion</c> will return (CTAP 2.3, section 6.2, step 12: "signifies the next
/// credential to be returned by the authenticator, assuming zero-based indexing"). Starts at 1 (index 0
/// was already consumed by the initiating <c>authenticatorGetAssertion</c>) and increments by one after
/// every successful <c>authenticatorGetNextAssertion</c>.
/// </param>
/// <param name="LastActivityAt">
/// The time of the last stateful step in this sequence — the originating <c>authenticatorGetAssertion</c>,
/// or the most recent <c>authenticatorGetNextAssertion</c> — compared against a 30-second timer on every
/// subsequent <c>authenticatorGetNextAssertion</c> (CTAP 2.3, section 6.3). Always sourced from the
/// simulator's threaded <see cref="TimeProvider"/>, never <see cref="DateTimeOffset.UtcNow"/>.
/// </param>
/// <param name="AuthenticatingPinUvAuthProtocol">
/// The PIN/UV auth protocol whose <c>pinUvAuthToken</c> authenticated the originating
/// <c>authenticatorGetAssertion</c>, or <see langword="null"/> when the series was not token-authenticated.
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticator-api">
/// CTAP 2.3, section 6</see>, item 3 (line 2873): "An authenticator MUST discard the state for a stateful
/// command command if the pinUvAuthToken that authenticated the state initializing command expires" —
/// every <c>authenticatorGetNextAssertion</c> against this record folds that protocol's own
/// <see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/> before deciding whether to keep serving it.
/// </param>
/// <param name="LargeBlobKeyRequested">
/// The originating <c>authenticatorGetAssertion</c> request's <c>largeBlobKey</c> extension resolution
/// (CTAP 2.3 §12.3), reused for every <c>authenticatorGetNextAssertion</c> signature in the sequence —
/// the command takes no parameters of its own, so this is the only way a continuation knows whether the
/// platform wants the extension's output. Each continuation still resolves the emitted value against ITS
/// OWN credential (<see cref="CtapCredentialRecord.LargeBlobKey"/>), never a value borrowed from the
/// first response.
/// </param>
public sealed record CtapRememberedGetAssertionState(
    IReadOnlyList<CredentialId> ApplicableCredentialIds,
    DigestValue ClientDataHash,
    bool UserPresent,
    bool UserVerified,
    int CredentialCounter,
    DateTimeOffset LastActivityAt,
    CtapPinUvAuthProtocolId? AuthenticatingPinUvAuthProtocol,
    bool LargeBlobKeyRequested): IDisposable
{
    /// <summary>
    /// Releases the independently pooled <see cref="ClientDataHash"/> copy this record owns. The
    /// credential identifiers in <see cref="ApplicableCredentialIds"/> are borrowed from the store's own
    /// <see cref="CtapCredentialRecord"/> instances and are not owned or disposed here.
    /// </summary>
    public void Dispose()
    {
        ClientDataHash.Dispose();
    }
}
