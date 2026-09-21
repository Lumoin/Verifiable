using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> attached to <see cref="Fido2ClaimIds.Fido2RegistrationHmacSecret"/>,
/// recording whether the authenticator generated and associated the credential's
/// <c>CredRandomWithUV</c>/<c>CredRandomWithoutUV</c> pair.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension">
/// CTAP 2.3, section 12.7: HMAC Secret Extension (hmac-secret)</see> — authenticator extension
/// output, <c>authenticatorMakeCredential</c> only. <see cref="Supported"/> carries no restricted
/// value set: both <see langword="true"/> and <see langword="false"/> are legitimate authenticator
/// states, not protocol violations.
/// </remarks>
public sealed record HmacSecretSupportedContext: ClaimContext
{
    /// <summary>Whether the authenticator generated and associated its CredRandom pair with the credential.</summary>
    public required bool Supported { get; init; }
}
