using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> attached to <see cref="Fido2ClaimIds.Fido2RegistrationMinPinLength"/>,
/// recording the registration ceremony's decoded <c>minPinLength</c> authenticator extension output
/// value as evidence for the relying party.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension">
/// CTAP 2.3, section 12.5: Minimum PIN Length Extension (minPinLength)</see> — authenticator
/// extension output, registration-only. <see cref="Length"/> carries no restricted value set: any
/// non-negative code-point count is a spec-legal minimum PIN length.
/// </remarks>
public sealed record MinPinLengthContext: ClaimContext
{
    /// <summary>The authenticator's current minimum PIN length, in Unicode code points.</summary>
    public required int Length { get; init; }
}
