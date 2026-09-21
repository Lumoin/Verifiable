using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> attached to <see cref="Fido2ClaimIds.Fido2RegistrationPrfEnabled"/>,
/// recording the registration ceremony's decoded <c>prf</c> <c>enabled</c> boolean as evidence for
/// the relying party.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-prf-extension">W3C Web Authentication Level 3,
/// section 10.1.4: Pseudo-random function extension (prf)</see> — client extension output
/// <c>enabled</c>, registration-only.
/// </remarks>
public sealed record PrfEnabledContext: ClaimContext
{
    /// <summary>Whether the PRF is available for use with the created credential.</summary>
    public required bool Enabled { get; init; }
}
