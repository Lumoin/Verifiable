using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> attached to <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobWritten"/>,
/// recording the assertion ceremony's decoded <c>largeBlob</c> <c>written</c> boolean as evidence
/// for the relying party.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
/// Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see> — client extension
/// output <c>written</c>, authentication-only.
/// </remarks>
public sealed record LargeBlobWrittenContext: ClaimContext
{
    /// <summary>Whether the large-blob write succeeded.</summary>
    public required bool Written { get; init; }
}
