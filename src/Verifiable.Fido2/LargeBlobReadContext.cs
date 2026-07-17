using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> attached to <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobRead"/>
/// when the assertion ceremony's decoded <c>largeBlob</c> client extension output carried a
/// <c>blob</c> payload, meaning a large-blob read succeeded.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
/// Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see> — client extension
/// output <c>blob</c>, authentication-only, "present only if read succeeded". Carries the decoded
/// bytes as a <see cref="TaggedMemory{T}"/> wrapping the <see cref="System.Text.Json"/>-allocated
/// array rather than copying it into pooled memory — not pooled, per this codebase's
/// <see cref="TaggedMemory{T}"/> convention for short-lived deserialization buffers.
/// </remarks>
public sealed record LargeBlobReadContext: ClaimContext
{
    /// <summary>The decoded <c>blob</c> payload bytes, tagged <see cref="Fido2BufferTags.LargeBlob"/>.</summary>
    public required TaggedMemory<byte> Blob { get; init; }
}
