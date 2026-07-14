using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The options a relying party sends the client to begin a registration ceremony.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-makecredentialoptions">W3C Web
/// Authentication Level 3, section 5.4: Options for Credential Creation (dictionary
/// <c>PublicKeyCredentialCreationOptions</c>)</see>. Assembled by
/// <see cref="Fido2RegistrationOptionsBuilder"/>; written to the CR's own named JSON wire shape
/// (<c>PublicKeyCredentialCreationOptionsJSON</c>, section 5.10.1) by
/// <c>Verifiable.Json.PublicKeyCredentialCreationOptionsJsonWriter</c>.
/// </para>
/// <para>
/// <strong>Mutability.</strong> Every member is a plain settable property, not an <c>init</c>-only
/// one: <see cref="Fido2RegistrationOptionsBuilder"/> extends
/// <c>Verifiable.Foundation.Builder{TResult, TState, TBuilder}</c>, whose fold constructs
/// <c>TResult</c> via a bare <c>new()</c> and then progressively assigns each member across several
/// independently registered transformations — the same shape <c>DcqlQuery</c> and
/// <c>CredentialBuilder</c>'s own <c>VerifiableCredential</c> already use for this exact reason.
/// Nested value types this document is composed from (<see cref="PublicKeyCredentialRpEntity"/>,
/// <see cref="PublicKeyCredentialUserEntity"/>, <see cref="PublicKeyCredentialDescriptor"/>,
/// <see cref="AuthenticatorSelectionCriteria"/>) are constructed directly by the builder's own code
/// (never through the generic fold's bare <c>new()</c>), so they carry ordinary immutable
/// <c>required</c>/<c>init</c> members instead.
/// </para>
/// <para>
/// <strong>Extension inputs.</strong> This registration-options surface carves out five named
/// extension-input members — <see cref="AppIdExclude"/>, <see cref="LargeBlob"/>,
/// <see cref="MinPinLength"/>, and <see cref="CredProtect"/> here, and
/// <c>PublicKeyCredentialRequestOptions.AppId</c>/<c>LargeBlob</c> on the assertion side — mirroring
/// how the shipped <c>appid</c> support (wave 2) bypassed the generic extension-registry entirely.
/// <c>minPinLength</c>/<c>credProtect</c> are registration-only (CTAP 2.3 §12.5's own "only applicable
/// during credential creation"; §12.1's own extension-input section covers only <c>create()</c>) — the
/// assertion-side options gain no corresponding members. The CR's generic <c>extensions</c>
/// client-input member (<c>AuthenticationExtensionsClientInputs</c>, tally rows 3559/3939, tagged
/// <c>WP-Extensions</c>) remains unbuilt beyond these five carve-outs — a future extension needs its
/// own equally-named member here, not a dictionary-typed catch-all.
/// </para>
/// </remarks>
[DebuggerDisplay("PublicKeyCredentialCreationOptions(Rp={Rp}, User={User}, PubKeyCredParams={PubKeyCredParams?.Count})")]
public sealed record PublicKeyCredentialCreationOptions
{
    /// <summary>
    /// The relying party the credential is scoped to. Required by the CR.
    /// </summary>
    public PublicKeyCredentialRpEntity? Rp { get; set; }

    /// <summary>
    /// The user account the credential is being created for. Required by the CR.
    /// </summary>
    public PublicKeyCredentialUserEntity? User { get; set; }

    /// <summary>
    /// The base64url-encoded challenge the authenticator signs over. Required by the CR.
    /// </summary>
    /// <remarks>
    /// Already base64url-encoded — <see cref="Fido2ChallengeGeneration.Generate(System.Buffers.MemoryPool{byte})"/>
    /// returns this exact shape, matching <c>RegistrationCeremonyInput.ExpectedChallenge</c>'s own
    /// plain-<see cref="string"/> modeling. See
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">section 13.4.3:
    /// Cryptographic Challenges</see>.
    /// </remarks>
    public string? Challenge { get; set; }

    /// <summary>
    /// The credential types and signature algorithms the relying party is willing to accept, ordered
    /// most to least preferred. Required by the CR.
    /// </summary>
    /// <remarks>
    /// Row 3497 (SHOULD include EdDSA/ES256/RS256) and row 3506 (SHOULD NOT include the RFC9864
    /// fully-specified identifiers) — <see cref="Fido2RegistrationOptionsBuilder"/>'s default builds
    /// exactly <c>[EdDSA(-8), ES256(-7), RS256(-257)]</c> by explicit inclusion, so row 3506 is
    /// satisfied by construction: the fully-specified identifiers are never added to the default list
    /// in the first place.
    /// </remarks>
    public IReadOnlyList<PublicKeyCredentialParameters>? PubKeyCredParams { get; set; }

    /// <summary>
    /// A hint, in milliseconds, for how long the relying party is willing to wait for the ceremony to
    /// complete, or <see langword="null"/> for no preference.
    /// </summary>
    /// <remarks>
    /// Neither the CR nor the FIDO Server RD gives a default value or bound for this member (verified
    /// against both snapshots) — <see cref="Fido2RegistrationOptionsBuilder"/> deliberately leaves it
    /// unset unless the caller supplies one, rather than manufacturing an unspec'd number.
    /// </remarks>
    public uint? Timeout { get; set; }

    /// <summary>
    /// Existing credentials mapped to this user account, so the client can avoid creating a
    /// duplicate credential on an authenticator that already holds one of them.
    /// </summary>
    /// <remarks>
    /// Row 3527 (SHOULD use this to list existing credentials) and rows 4270/4277/4285 (each
    /// descriptor SHOULD mirror the source credential record's <c>type</c>/<c>id</c>/<c>transports</c>
    /// item) — <see cref="Fido2RegistrationOptionsBuilder"/>'s default projects every supplied
    /// <see cref="Fido2CredentialRecord"/> into a <see cref="PublicKeyCredentialDescriptor"/> this way.
    /// Empty (not <see langword="null"/>) when the caller supplies no existing credentials, per the
    /// CR's own <c>[]</c> default.
    /// </remarks>
    public IReadOnlyList<PublicKeyCredentialDescriptor>? ExcludeCredentials { get; set; }

    /// <summary>
    /// Capabilities and settings the authenticator MUST or SHOULD satisfy to participate in the
    /// ceremony, or <see langword="null"/> for no constraint.
    /// </summary>
    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; set; }

    /// <summary>
    /// Hints guiding the user agent on how this request may best be completed. Empty (not
    /// <see langword="null"/>) when the caller supplies none, per the CR's own <c>[]</c> default.
    /// </summary>
    /// <remarks>
    /// Row 4470: for compatibility with older user agents, a hint used in creation options SHOULD set
    /// <see cref="AuthenticatorSelectionCriteria.AuthenticatorAttachment"/> per its own mapping (see
    /// <see cref="WellKnownPublicKeyCredentialHints.ToCompatibilityAuthenticatorAttachment"/>) —
    /// applied by <see cref="Fido2RegistrationOptionsBuilder"/>'s default whenever hints are supplied
    /// and the caller has not already set an explicit attachment.
    /// </remarks>
    public IReadOnlyList<PublicKeyCredentialHint>? Hints { get; set; }

    /// <summary>
    /// The relying party's preference regarding attestation conveyance. The CR's own IDL default is
    /// <see cref="AttestationConveyancePreference.None"/>.
    /// </summary>
    public AttestationConveyancePreference? Attestation { get; set; }

    /// <summary>
    /// The relying party's preferred attestation statement formats, most to least preferred. Empty
    /// (not <see langword="null"/>) when the caller expresses no preference, per the CR's own
    /// <c>[]</c> default ("no preference").
    /// </summary>
    public IReadOnlyList<string>? AttestationFormats { get; set; }

    /// <summary>
    /// The <c>appidExclude</c> extension's registration-side client extension input — the legacy
    /// AppID this registration should also treat <see cref="ExcludeCredentials"/> as containing U2F
    /// key handles for, or <see langword="null"/> when not requested.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension">W3C Web
    /// Authentication Level 3, section 10.1.2: FIDO AppID Exclusion Extension (appidExclude)</see>.
    /// Section 10.1.2 defines no RFC2119 keyword at all (verified against the CR snapshot) — this
    /// member is feature-completeness, not the closure of a normative clause. One of this type's five
    /// named extension-input carve-outs (see the type-level remarks).
    /// </remarks>
    public string? AppIdExclude { get; set; }

    /// <summary>
    /// The <c>largeBlob</c> extension's registration-side client extension input, or
    /// <see langword="null"/> when not requested.
    /// </summary>
    /// <remarks>
    /// One of this type's five named extension-input carve-outs (see the type-level remarks and
    /// <see cref="Fido2LargeBlobRegistrationExtensionInput"/>).
    /// </remarks>
    public Fido2LargeBlobRegistrationExtensionInput? LargeBlob { get; set; }

    /// <summary>
    /// The <c>minPinLength</c> extension's registration-side client extension input — a request for
    /// the authenticator's current minimum PIN length, or <see langword="null"/> when not requested.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension">
    /// CTAP 2.3, section 12.5: Minimum PIN Length Extension (minPinLength)</see>, client extension
    /// input IDL: a flat <see cref="bool"/>, mirroring <see cref="AppIdExclude"/>'s own flat-scalar
    /// shape. One of this type's five named extension-input carve-outs (see the type-level remarks).
    /// </remarks>
    public bool? MinPinLength { get; set; }

    /// <summary>
    /// The <c>credProtect</c> extension's registration-side client extension input, or
    /// <see langword="null"/> when not requested.
    /// </summary>
    /// <remarks>
    /// One of this type's five named extension-input carve-outs (see the type-level remarks and
    /// <see cref="Fido2CredProtectRegistrationExtensionInput"/>).
    /// </remarks>
    public Fido2CredProtectRegistrationExtensionInput? CredProtect { get; set; }
}
