using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>prf</c> extension's assertion-side client extension input — one of
/// <see cref="PublicKeyCredentialRequestOptions"/>'s named extension-input carve-outs (the generic
/// <c>extensions</c> client-input member remains out of scope; see that type's type-level remarks).
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-prf-extension">W3C Web Authentication Level 3,
/// section 10.1.4: Pseudo-random function extension (prf)</see>, dictionary
/// <c>AuthenticationExtensionsPRFInputs</c>: <c>eval</c> and <c>evalByCredential</c> are NOT mutually
/// exclusive — the client extension processing algorithm tries <see cref="EvalByCredential"/> first
/// (keyed by the credential the authenticator actually asserted) and falls back to <see cref="Eval"/>
/// only when no matching entry exists, so both may be supplied together.
/// </para>
/// <para>
/// <see cref="EvalByCredential"/> is keyed by <see cref="CredentialId"/> rather than a raw base64url
/// string: the section's own authentication-processing algorithm rejects a key "the empty string, or
/// ... not a valid base64url encoding" — a class of failure this library's own <see cref="CredentialId"/>
/// closes by construction at this API surface the same way an invalid base64url <c>id</c> anywhere
/// else in these options types is a wire-format concern for the JSON reader, not a builder-input
/// concern (see <c>Verifiable.Json.PublicKeyCredentialRequestOptionsJsonReader</c>). The remaining
/// clause of that same rule — a key that "does not equal the id of some element of
/// <c>allowCredentials</c>" — and the sibling rule that <c>evalByCredential</c> present with an empty
/// <c>allowCredentials</c> is a client-side <c>NotSupportedError</c>, both need the assembled
/// <c>allowCredentials</c> list to evaluate, so <see cref="Fido2AssertionOptionsBuilder"/> enforces
/// them once <c>allowCredentials</c> is known (see that type's remarks).
/// </para>
/// </remarks>
[DebuggerDisplay("Fido2PrfAssertionExtensionInput(HasEval={Eval is not null}, EvalByCredentialCount={EvalByCredential?.Count})")]
public sealed record Fido2PrfAssertionExtensionInput
{
    /// <summary>
    /// One or two PRF evaluation inputs used when no <see cref="EvalByCredential"/> entry matches the
    /// asserted credential, or <see langword="null"/> when only per-credential evaluation is requested.
    /// </summary>
    public Fido2PrfValues? Eval { get; init; }

    /// <summary>
    /// PRF evaluation inputs keyed by the credential they apply to, evaluated in preference to
    /// <see cref="Eval"/> when the asserted credential has a matching entry, or <see langword="null"/>
    /// when no per-credential evaluation is requested.
    /// </summary>
    public IReadOnlyDictionary<CredentialId, Fido2PrfValues>? EvalByCredential { get; init; }
}
