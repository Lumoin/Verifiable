using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>largeBlob</c> extension's registration-side client extension input — one of
/// <see cref="PublicKeyCredentialCreationOptions"/>'s five named extension-input carve-outs (the
/// generic <c>extensions</c> client-input member remains out of scope; see that type's type-level
/// remarks).
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
/// Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see>, client extension input
/// <c>support</c> — registration-only (the assertion-side input carries <c>read</c>/<c>write</c>
/// instead, see <see cref="Fido2LargeBlobAssertionExtensionInput"/>).
/// </para>
/// <para>
/// Section 10.1.5's only relying-party-scoped RFC2119 keyword (tally row 7636): "Relying Parties
/// SHOULD use the registration extension when creating the credential if they wish to later use the
/// authentication extension." That SHOULD is unenforceable by a verification-only library — nothing
/// on the wire lets a verifier confirm intent to use the extension later — so it is closed by
/// exposing this input surface for the relying party to opt into, not by any check.
/// </para>
/// </remarks>
[DebuggerDisplay("Fido2LargeBlobRegistrationExtensionInput(Support={Support})")]
public sealed record Fido2LargeBlobRegistrationExtensionInput
{
    /// <summary>
    /// The relying party's requirement regarding <c>largeBlob</c> extension support.
    /// </summary>
    public required LargeBlobSupport Support { get; init; }
}
