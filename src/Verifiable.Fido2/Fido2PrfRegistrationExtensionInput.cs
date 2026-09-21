using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>prf</c> extension's registration-side client extension input — one of
/// <see cref="PublicKeyCredentialCreationOptions"/>'s named extension-input carve-outs (the generic
/// <c>extensions</c> client-input member remains out of scope; see that type's type-level remarks).
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-prf-extension">W3C Web Authentication Level 3,
/// section 10.1.4: Pseudo-random function extension (prf)</see>, dictionary
/// <c>AuthenticationExtensionsPRFInputs</c>, <c>eval</c> member only: the registration-side client
/// extension processing algorithm's first step returns a client-side <c>NotSupportedError</c> the
/// moment <c>evalByCredential</c> is present at all — this record has no such member, so that
/// rejection is closed by construction rather than by a runtime check (mirroring
/// <see cref="Fido2LargeBlobAssertionExtensionInput"/>'s own Read/Write mutual exclusivity). The
/// section's own prose confirms <c>evalByCredential</c> is assertion-only: "Only applicable during
/// assertions when <c>allowCredentials</c> is not empty" — see
/// <see cref="Fido2PrfAssertionExtensionInput"/> for the assertion-side counterpart that carries it.
/// </remarks>
[DebuggerDisplay("Fido2PrfRegistrationExtensionInput(Eval={Eval})")]
public sealed record Fido2PrfRegistrationExtensionInput
{
    /// <summary>
    /// One or two PRF evaluation inputs, evaluated at credential-creation time when the authenticator
    /// supports it (an assertion is needed to obtain the outputs otherwise).
    /// </summary>
    public required Fido2PrfValues Eval { get; init; }
}
