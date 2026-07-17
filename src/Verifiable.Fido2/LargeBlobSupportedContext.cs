using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> attached to <see cref="Fido2ClaimIds.Fido2RegistrationLargeBlobSupported"/>,
/// recording the registration ceremony's decoded <c>largeBlob</c> <c>supported</c> boolean as
/// evidence for the relying party.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
/// Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see> — client extension
/// output <c>supported</c>, registration-only.
/// </remarks>
public sealed record LargeBlobSupportedContext: ClaimContext
{
    /// <summary>Whether the authenticator reported support for large-blob storage.</summary>
    public required bool Supported { get; init; }
}
