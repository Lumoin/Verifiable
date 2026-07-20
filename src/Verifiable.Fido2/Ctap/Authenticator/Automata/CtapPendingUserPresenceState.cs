using System;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The decoded-request context a parked user-presence wait needs to resume the
/// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> it interrupted, once a decision
/// arrives. One subclass per command, mirroring <see cref="CtapPerformBuiltInUvContinuation"/>'s own
/// per-command shape. Owns whatever pooled carriers the parked request holds (CTAP 2.3 R2's custody
/// rule): the carrier that would otherwise be released by <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>'s
/// own <c>DisposeRequestCarriers</c> at the end of a synchronous call is, on a parked command, released
/// here instead — whenever <see cref="CtapPendingUserPresenceState"/> is discarded.
/// </summary>
public abstract record CtapUserPresenceContinuation: IDisposable
{
    /// <summary>
    /// Releases the pooled carriers of the parked request this continuation resumes.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the parked request's pooled carriers when disposing is true.
    /// </summary>
    protected abstract void Dispose(bool disposing);
}

/// <summary>
/// Resumes an interrupted <c>authenticatorMakeCredential</c> once a user-presence decision has been
/// collected for it.
/// </summary>
/// <param name="Requested">
/// The original decoded request and pre-resolved algorithm selection, borrowed unchanged from the input
/// that declared the collect action.
/// </param>
/// <param name="UserVerified">
/// The <c>uv</c> bit already resolved before collection was declared (CTAP 2.3 §6.1.2 step 11) —
/// threaded through unchanged, never recomputed once a decision arrives.
/// </param>
/// <param name="EnterpriseAttestationGranted">
/// The mc Step 9 enterprise-attestation grant decision, computed ONCE in <c>OnMakeCredentialRequested</c>
/// before this collection was declared, and threaded here so it survives the round trip unchanged
/// (mirroring <see cref="CtapMakeCredentialBuiltInUvContinuation.EnterpriseAttestationGranted"/>'s
/// identical carry-through) — never recomputed once a decision arrives.
/// </param>
public sealed record CtapMakeCredentialUserPresenceContinuation(
    MakeCredentialRequested Requested, bool UserVerified, bool EnterpriseAttestationGranted): CtapUserPresenceContinuation
{
    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            CtapMakeCredentialRequest request = Requested.Request;
            request.ClientDataHash.Dispose();
            request.User.Id.Dispose();

            if(request.ExcludeList is not null)
            {
                foreach(PublicKeyCredentialDescriptor descriptor in request.ExcludeList)
                {
                    descriptor.Id.Dispose();
                }
            }
        }
    }
}

/// <summary>
/// Resumes an interrupted <c>authenticatorGetAssertion</c> once a user-presence decision has been
/// collected for it.
/// </summary>
/// <param name="Requested">The original decoded request, borrowed unchanged from the input that declared the collect action.</param>
/// <param name="UserVerified">The <c>uv</c> bit already resolved before collection was declared (CTAP 2.3 §6.2.2 step 6) — threaded through unchanged.</param>
/// <param name="AuthenticatingPinUvAuthProtocol">
/// The protocol whose <c>pinUvAuthToken</c> authenticated this call, or <see langword="null"/> when the
/// call was not token-authenticated — threaded through unchanged for
/// <see cref="CtapRememberGetAssertionRequest.AuthenticatingPinUvAuthProtocol"/>'s identical purpose.
/// </param>
public sealed record CtapGetAssertionUserPresenceContinuation(
    GetAssertionRequested Requested, bool UserVerified, CtapPinUvAuthProtocolId? AuthenticatingPinUvAuthProtocol): CtapUserPresenceContinuation
{
    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            CtapGetAssertionRequest request = Requested.Request;
            request.ClientDataHash.Dispose();

            if(request.AllowList is not null)
            {
                foreach(PublicKeyCredentialDescriptor descriptor in request.AllowList)
                {
                    descriptor.Id.Dispose();
                }
            }
        }
    }
}

/// <summary>
/// A parked <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> user-presence wait (CTAP
/// 2.3 :2840, R2), persisted as a data field on <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/>
/// — never a <see cref="CtapAuthenticatorStackSymbol"/>, mirroring how the five <c>Remembered*</c> slots
/// carry their own cross-call statefulness.
/// </summary>
/// <param name="ArmedAt">
/// The instant this wait was first armed — the ORIGINAL command's own <c>Now</c>, never restamped by a
/// later poll — compared against <see cref="CtapAuthenticatorTransitions.UserActionTimeoutDuration"/> on
/// every <see cref="UserPresencePollRequested"/> (CTAP 2.3 :2840's "at least 10 seconds" timeout,
/// measured from when the authenticator started waiting, not from the most recent poll).
/// </param>
/// <param name="IsDeferralAllowed">
/// Echoed from the parked request's own <c>IsUserPresenceDeferralAllowed</c>
/// (<see cref="MakeCredentialRequested.IsUserPresenceDeferralAllowed"/>/
/// <see cref="GetAssertionRequested.IsUserPresenceDeferralAllowed"/>) — whether a
/// <see cref="CtapUserPresenceDecision.Pending"/> decision keeps this wait parked (deferring transport)
/// or resolves immediately to <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/> (non-deferring).
/// </param>
/// <param name="Continuation">Everything the post-collection <c>Continue*</c> path needs to resume.</param>
public sealed record CtapPendingUserPresenceState(
    DateTimeOffset ArmedAt, bool IsDeferralAllowed, CtapUserPresenceContinuation Continuation): IDisposable
{
    /// <summary>
    /// Releases <see cref="Continuation"/>'s own pooled carriers.
    /// </summary>
    public void Dispose()
    {
        Continuation.Dispose();
    }
}
