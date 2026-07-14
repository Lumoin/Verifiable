namespace Verifiable.Fido2;

/// <summary>
/// A relying party's requirement regarding <c>largeBlob</c> extension support at registration time.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
/// Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see>, client extension input
/// <c>support</c>: <c>enum LargeBlobSupport { "required", "preferred" };</c> — deliberately only two
/// values (no <c>discouraged</c>), unlike <see cref="ResidentKeyRequirement"/>/
/// <see cref="UserVerificationRequirement"/>. Registration-only: the <c>largeBlob</c> extension's
/// assertion-side input carries <c>read</c>/<c>write</c> instead, not a <c>support</c> preference.
/// Wire (de)serialization is a JSON-layer concern, via <see cref="WellKnownLargeBlobSupports"/>.
/// </remarks>
public enum LargeBlobSupport
{
    /// <summary>
    /// The authenticator used for registration MUST support the <c>largeBlob</c> extension.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
    /// Level 3, section 10.1.5</see>: the client rejects candidate authenticators that lack
    /// <c>largeBlob</c> support when <c>support</c> is <c>required</c>.
    /// </remarks>
    Required,

    /// <summary>
    /// The client SHOULD select an authenticator that supports the <c>largeBlob</c> extension, but
    /// registration proceeds even if none is available.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
    /// Level 3, section 10.1.5</see>.
    /// </remarks>
    Preferred
}
