using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The options a relying party sends the client to begin an authentication (assertion) ceremony.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-assertion-options">W3C Web Authentication
/// Level 3, section 5.5: Options for Assertion Generation (dictionary
/// <c>PublicKeyCredentialRequestOptions</c>)</see>. Assembled by
/// <see cref="Fido2AssertionOptionsBuilder"/>; written to the CR's own named JSON wire shape
/// (<c>PublicKeyCredentialRequestOptionsJSON</c>, section 5.10.2) by
/// <c>Verifiable.Json.PublicKeyCredentialRequestOptionsJsonWriter</c>.
/// </para>
/// <para>
/// <strong>Mutability.</strong> See <see cref="PublicKeyCredentialCreationOptions"/>'s type-level
/// remarks — the same reasoning applies here.
/// </para>
/// <para>
/// <strong>Extension inputs.</strong> This assertion-side surface carves out exactly two named
/// extension-input members (<see cref="AppId"/>, <see cref="LargeBlob"/>); neither
/// <c>minPinLength</c> nor <c>credProtect</c> gains an assertion-side member (both are
/// registration-only, CTAP 2.3 §12.5/§12.1) — see <see cref="PublicKeyCredentialCreationOptions"/>'s
/// matching remarks for the full, five-member registration-side count.
/// </para>
/// </remarks>
[DebuggerDisplay("PublicKeyCredentialRequestOptions(RpId={RpId}, AllowCredentials={AllowCredentials?.Count})")]
public sealed record PublicKeyCredentialRequestOptions
{
    /// <summary>
    /// The base64url-encoded challenge the authenticator signs over. Required by the CR.
    /// </summary>
    /// <remarks>
    /// Already base64url-encoded — <see cref="Fido2ChallengeGeneration.Generate(System.Buffers.MemoryPool{byte})"/>
    /// returns this exact shape, matching <c>AssertionCeremonyInput.ExpectedChallenge</c>'s own
    /// plain-<see cref="string"/> modeling.
    /// </remarks>
    public string? Challenge { get; set; }

    /// <summary>
    /// A hint, in milliseconds, for how long the relying party is willing to wait for the ceremony to
    /// complete, or <see langword="null"/> for no preference.
    /// </summary>
    /// <remarks>
    /// Neither the CR nor the FIDO Server RD gives a default value or bound for this member — left
    /// unset unless the caller supplies one, mirroring
    /// <see cref="PublicKeyCredentialCreationOptions.Timeout"/>'s own remarks.
    /// </remarks>
    public uint? Timeout { get; set; }

    /// <summary>
    /// The relying party identifier the assertion is scoped to, or <see langword="null"/> to defer to
    /// the client's own effective-domain default.
    /// </summary>
    public string? RpId { get; set; }

    /// <summary>
    /// The credentials acceptable for this assertion, or empty (not <see langword="null"/>) for the
    /// discoverable-credential path where the user account is not yet identified.
    /// </summary>
    /// <remarks>
    /// Row 3902 (SHOULD list allowed credentials when the account is already identified), row 3906
    /// (list items SHOULD specify <c>transports</c> whenever possible) and row 3914 (MAY leave this
    /// empty/unspecified for the discoverable-credential path) — <see cref="Fido2AssertionOptionsBuilder"/>'s
    /// default projects every supplied <see cref="Fido2CredentialRecord"/> the same way
    /// <see cref="PublicKeyCredentialCreationOptions.ExcludeCredentials"/>'s default does (rows
    /// 4270/4277/4285), and returns an empty list rather than <see langword="null"/> when the caller
    /// supplies none.
    /// </remarks>
    public IReadOnlyList<PublicKeyCredentialDescriptor>? AllowCredentials { get; set; }

    /// <summary>
    /// The relying party's requirements regarding user verification for the <c>get()</c> operation.
    /// The CR's own IDL default is <see cref="UserVerificationRequirement.Preferred"/>.
    /// </summary>
    public UserVerificationRequirement? UserVerification { get; set; }

    /// <summary>
    /// Hints guiding the user agent on how this request may best be completed. Empty (not
    /// <see langword="null"/>) when the caller supplies none, per the CR's own <c>[]</c> default.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="PublicKeyCredentialCreationOptions.Hints"/>, request options carry no
    /// <c>authenticatorAttachment</c> member — row 4470's compatibility mapping is
    /// creation-options-only (see the CR's own text: "when this hint is used in
    /// <c>PublicKeyCredentialCreationOptions</c>").
    /// </remarks>
    public IReadOnlyList<PublicKeyCredentialHint>? Hints { get; set; }

    /// <summary>
    /// The <c>appid</c> extension's assertion-side client extension input — the legacy AppID whose
    /// hash the relying party will also accept as the asserted <c>rpIdHash</c>, or
    /// <see langword="null"/> when not requested.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-extension">W3C Web Authentication
    /// Level 3, section 10.1.1: FIDO AppID Extension (appid)</see>. This member only assembles the
    /// options-side request; the response-side verification (matching <c>authData.rpIdHash</c>
    /// against this AppID's hash) is
    /// <c>Fido2AssertionChecks.CheckAssertionRpIdHash</c>'s job, shipped in wave 2 and unchanged
    /// since. One of this type's two named extension-input carve-outs (see the type-level remarks).
    /// </remarks>
    public string? AppId { get; set; }

    /// <summary>
    /// The <c>largeBlob</c> extension's assertion-side client extension input, or
    /// <see langword="null"/> when neither a read nor a write is requested.
    /// </summary>
    /// <remarks>
    /// One of this type's two named extension-input carve-outs (see the type-level remarks and
    /// <see cref="Fido2LargeBlobAssertionExtensionInput"/>).
    /// </remarks>
    public Fido2LargeBlobAssertionExtensionInput? LargeBlob { get; set; }
}
