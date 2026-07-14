using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> attached to <see cref="Fido2ClaimIds.Fido2RegistrationCredProtect"/>,
/// recording the registration ceremony's decoded <c>credProtect</c> authenticator extension output
/// level as evidence for the relying party.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credProtect-extension">
/// CTAP 2.3, section 12.1: Credential Protection (credProtect)</see> — authenticator extension
/// output, registration-only. <see cref="Level"/> is one of the three registered wire values
/// {1, 2, 3}; <see cref="CredProtectExtensionProcessor"/> only attaches this context on a registered
/// level, reporting <see cref="ClaimOutcome.Failure"/> with no context for an out-of-set value.
/// </remarks>
public sealed record CredProtectLevelContext: ClaimContext
{
    /// <summary>The decoded <c>credProtect</c> level the authenticator set for the created credential.</summary>
    public required int Level { get; init; }
}
