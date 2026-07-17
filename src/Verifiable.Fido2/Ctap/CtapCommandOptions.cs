using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>options</c> parameter shared by <c>authenticatorMakeCredential</c> and
/// <c>authenticatorGetAssertion</c> requests: the three boolean-valued option keys either command may
/// carry on the wire.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1</see> and
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// section 6.2</see>. Each member is <see langword="null"/> when the option key is absent from the wire
/// map (the spec's own default then applies) and carries the decoded value when present — including
/// <see cref="ResidentKey"/> on a <c>authenticatorGetAssertion</c> request, where the platform MUST NOT
/// send it at all: this codec layer decodes whatever was sent so the authenticator-side handler can
/// apply the command-specific legality rule (reject unconditionally for
/// <c>authenticatorGetAssertion</c>, gate on <c>authenticatorGetInfo</c>'s advertised <c>rk</c> option ID
/// for <c>authenticatorMakeCredential</c>) rather than the codec silently dropping the distinction.
/// </para>
/// </remarks>
/// <param name="ResidentKey">
/// The <c>rk</c> option: whether the credential is to be discoverable. Legal only on
/// <c>authenticatorMakeCredential</c>.
/// </param>
/// <param name="UserPresence">The <c>up</c> option: whether user presence evidence is required.</param>
/// <param name="UserVerification">The <c>uv</c> option: whether a user-verifying gesture is required.</param>
[DebuggerDisplay("CtapCommandOptions(rk={ResidentKey}, up={UserPresence}, uv={UserVerification})")]
public sealed record CtapCommandOptions(bool? ResidentKey = null, bool? UserPresence = null, bool? UserVerification = null);
