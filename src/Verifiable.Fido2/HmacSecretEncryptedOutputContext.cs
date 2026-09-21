using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> attached to <see cref="Fido2ClaimIds.Fido2AssertionHmacSecret"/>,
/// recording the decoded <c>hmac-secret</c> or <c>hmac-secret-mc</c> authenticator extension
/// output's encrypted byte string.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension">
/// CTAP 2.3, section 12.7: HMAC Secret Extension (hmac-secret)</see> — the
/// <c>authenticatorGetAssertion</c>-time output, and, per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-make-cred-extension">
/// section 12.8: HMAC Secret MakeCredential Extension (hmac-secret-mc)</see>'s own
/// <c>authenticatorMakeCredential</c>-time output ("Same as the hmac secret extension's
/// getAssertion output"), the one or two 32-byte HMAC-SHA-256 values encrypted under the PIN/UV
/// auth protocol's own <c>encrypt</c> operation. <see cref="EncryptedOutput"/> aliases the caller's
/// own <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> buffer rather than
/// copying it — no existing <see cref="ClaimContext"/> in this library carries a byte payload
/// decoded from that side (the JSON-side <see cref="LargeBlobReadContext"/> owns a
/// <c>System.Text.Json</c>-allocated array instead), so this follows
/// <see cref="ExtensionOutputProcessingRequest"/>'s own non-owning convention directly.
/// </remarks>
public sealed record HmacSecretEncryptedOutputContext: ClaimContext
{
    /// <summary>The decoded, still-encrypted <c>hmac-secret</c>/<c>hmac-secret-mc</c> output bytes.</summary>
    public required ReadOnlyMemory<byte> EncryptedOutput { get; init; }
}
