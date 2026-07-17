using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// Identifies the relying party a registration ceremony's credential is scoped to, per
/// <c>PublicKeyCredentialCreationOptions.rp</c>.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-rp-credential-params">W3C Web
/// Authentication Level 3, section 5.4.2: Relying Party Parameters for Credential Generation
/// (dictionary <c>PublicKeyCredentialRpEntity</c>)</see>, extending
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-pkcredentialentity">section 5.4.1: Public
/// Key Entity Description (dictionary <c>PublicKeyCredentialEntity</c>)</see>.
/// </remarks>
[DebuggerDisplay("PublicKeyCredentialRpEntity(Id={Id}, Name={Name})")]
public sealed record PublicKeyCredentialRpEntity
{
    /// <summary>
    /// The relying party identifier the credential is scoped to.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-rp-credential-params">W3C Web
    /// Authentication Level 3, section 5.4.2</see>: "If absent, its value will be the
    /// CredentialsContainer object's relevant settings object's origin's effective domain" — a
    /// client-side default this library, an RP-side verifier, cannot compute on the RP's behalf, so
    /// it is left <see langword="null"/> rather than guessed at.
    /// </remarks>
    public string? Id { get; init; }

    /// <summary>
    /// [DEPRECATED] A human-palatable identifier for the relying party, intended only for display.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-pkcredentialentity">W3C Web
    /// Authentication Level 3, section 5.4.1</see>: "This member is deprecated because many clients
    /// do not display it, but it remains a required dictionary member for backwards compatibility.
    /// Relying Parties MAY, as a safe default, set this equal to the RP ID." (row 3588).
    /// </para>
    /// <para>
    /// Section 5.4.1 also documents a SHOULD: "Relying Parties SHOULD perform enforcement, as
    /// prescribed in Section 2.3 of [RFC8266] for the Nickname Profile of the PRECIS FreeformClass
    /// [RFC8264], when setting name's value" (row 3590). This library performs no PRECIS profile
    /// enforcement — it is an RP-side text-normalization policy independent of ceremony
    /// verification — so the caller remains responsible for applying it before supplying this value.
    /// </para>
    /// </remarks>
    public required string Name { get; init; }
}
