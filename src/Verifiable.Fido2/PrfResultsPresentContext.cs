using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> attached to
/// <see cref="Fido2ClaimIds.Fido2RegistrationPrfResultsPresent"/> and
/// <see cref="Fido2ClaimIds.Fido2AssertionPrfResultsPresent"/>, recording that the decoded
/// <c>prf</c> client extension output carried a <c>results</c> member — never the secret bytes
/// underneath it.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-prf-extension">W3C Web Authentication Level 3,
/// section 10.1.4: Pseudo-random function extension (prf)</see>. Unlike
/// <see cref="LargeBlobReadContext"/>, which carries the <c>largeBlob</c> extension's non-secret
/// decoded payload, this context carries only the boolean fact that <c>results</c> was present —
/// <see cref="HasResults"/> is predicate-named rather than mirroring the wire member's own spelling,
/// because the wire member's VALUE (the secret PRF output) is exactly what this context refuses to
/// carry. A relying party that needs the secret bytes reads the same wire bytes again through
/// <c>Verifiable.Json.PrfResultsJsonReader</c>, which hands them out in the library's disposable
/// secret-memory carrier rather than through the claim/audit pipeline.
/// </remarks>
public sealed record PrfResultsPresentContext: ClaimContext
{
    /// <summary>Whether the decoded <c>prf</c> client extension output carried a <c>results</c> member.</summary>
    public required bool HasResults { get; init; }
}
