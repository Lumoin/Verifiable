using System;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The subset of the <c>authenticatorGetAssertion</c> response structure this library models: the three
/// Required members plus the members reachable by this headless simulator, reused unchanged for
/// <c>authenticatorGetNextAssertion</c>'s identically shaped response (CTAP 2.3, section 6.3: "the
/// authenticator returns the same structure as returned by the authenticatorGetAssertion method").
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>. <c>numberOfCredentials</c>
/// (<c>0x05</c>) is present only on the first response of a multi-account <c>authenticatorGetAssertion</c>
/// (more than one applicable credential found, <c>allowList</c> absent); every single-credential
/// response and every <c>authenticatorGetNextAssertion</c> response omits it — CTAP 2.3 section 6.3
/// itself: "The numberOfCredentials member is omitted." <c>userSelected</c> (<c>0x06</c>) is never
/// emitted by this headless simulator (no direct-interaction UI exists) but is still decoded if present.
/// <c>unsignedExtensionOutputs</c> (<c>0x08</c>) is not modeled this wave. <see cref="AuthData"/> and
/// <see cref="Signature"/> carry raw wire bytes, mirroring <see cref="CtapMakeCredentialResponse.AuthData"/>'s
/// own rationale.
/// </remarks>
/// <param name="Credential">
/// Required (<c>0x01</c>). The descriptor of the credential whose private key produced the assertion.
/// </param>
/// <param name="AuthData">Required (<c>0x02</c>). The raw signed-over <c>authenticatorData</c> wire bytes.</param>
/// <param name="Signature">Required (<c>0x03</c>). The assertion signature.</param>
/// <param name="User">
/// Optional (<c>0x04</c>). The user account, mandatory-if-present's own field rules described in
/// <see cref="CtapPublicKeyCredentialUserEntity"/>'s remarks. <see langword="null"/> when omitted.
/// </param>
/// <param name="NumberOfCredentials">
/// Optional (<c>0x05</c>). Total applicable-credential count; defaults to one when omitted.
/// </param>
/// <param name="UserSelected">
/// Optional (<c>0x06</c>). Whether the user selected the credential via direct authenticator
/// interaction. Defaults to <see langword="false"/> when omitted. Not modeled as reachable this wave
/// (no direct-interaction UI exists), but decoded if present.
/// </param>
/// <param name="LargeBlobKey">
/// Optional (<c>0x07</c>). The asserted credential's stored <c>largeBlobKey</c> (CTAP 2.3 §12.3, line
/// 12867), present iff the request's <c>largeBlobKey</c> extension resolved to <see langword="true"/>
/// AND the resolved credential carries a key. <see langword="null"/> when the extension was not
/// requested, or was requested against a credential with no stored key — line 12828's MUST NOT: the
/// value is never emitted unsolicited. Travels TOP-LEVEL here, never inside <see cref="AuthData"/>'s
/// extensions map (line 12867: "i.e., not in the extensions field of the authenticator data").
/// </param>
[DebuggerDisplay("CtapGetAssertionResponse(Credential={Credential})")]
public sealed record CtapGetAssertionResponse(
    PublicKeyCredentialDescriptor Credential,
    ReadOnlyMemory<byte> AuthData,
    ReadOnlyMemory<byte> Signature,
    CtapPublicKeyCredentialUserEntity? User = null,
    int? NumberOfCredentials = null,
    bool? UserSelected = null,
    ReadOnlyMemory<byte>? LargeBlobKey = null);
