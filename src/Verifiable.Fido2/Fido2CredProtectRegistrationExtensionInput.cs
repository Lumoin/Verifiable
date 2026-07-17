using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>credProtect</c> extension's registration-side client extension input — one of
/// <see cref="PublicKeyCredentialCreationOptions"/>'s five named extension-input carve-outs (the
/// generic <c>extensions</c> client-input member remains out of scope; see that type's type-level
/// remarks).
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credProtect-extension">
/// CTAP 2.3, section 12.1: Credential Protection (credProtect)</see>, client extension input IDL
/// (snapshot lines 12546-12550): <c>credentialProtectionPolicy</c> and
/// <c>enforceCredentialProtectionPolicy</c> are FLAT top-level members of
/// <c>AuthenticationExtensionsClientInputs</c> — unlike <c>largeBlob</c>'s own nested
/// <c>{"largeBlob": {"support": ...}}</c> shape, neither member is wrapped under a <c>"credProtect"</c>
/// key on the wire (the mapping from this pair to the small integer the CTAP-layer
/// <c>authenticatorMakeCredential</c> <c>extensions</c> map actually carries happens client-side,
/// before the CTAP wire request is built — this record models the WebAuthn client-input pair only).
/// <see cref="EnforceCredentialProtectionPolicy"/> NEVER appears on any CTAP-layer type: the
/// authenticator receives only the mapped <c>credProtect</c> integer, never this platform-side
/// enforcement decision.
/// </remarks>
[DebuggerDisplay("Fido2CredProtectRegistrationExtensionInput(CredentialProtectionPolicy={CredentialProtectionPolicy}, EnforceCredentialProtectionPolicy={EnforceCredentialProtectionPolicy})")]
public sealed record Fido2CredProtectRegistrationExtensionInput
{
    /// <summary>
    /// The relying party's requested credential protection policy — one of the three
    /// <see cref="WellKnownCredProtectPolicies"/> wire values.
    /// </summary>
    public required string CredentialProtectionPolicy { get; init; }

    /// <summary>
    /// Whether the platform MUST refuse to create the credential when it cannot implement
    /// <see cref="CredentialProtectionPolicy"/> (CTAP 2.3 §12.1, line 12592's SHOULD NOT — a
    /// platform-side decision this library exposes for the relying party to request, never enforced
    /// authenticator-side). Defaults to <see langword="false"/>, the WebAuthn IDL's own default.
    /// </summary>
    public bool EnforceCredentialProtectionPolicy { get; init; }
}
