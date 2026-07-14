using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// Identifies the user account a registration ceremony's credential is being created for, per
/// <c>PublicKeyCredentialCreationOptions.user</c>.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">W3C Web
/// Authentication Level 3, section 5.4.3: User Account Parameters for Credential Generation
/// (dictionary <c>PublicKeyCredentialUserEntity</c>)</see>, extending
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-pkcredentialentity">section 5.4.1: Public
/// Key Entity Description (dictionary <c>PublicKeyCredentialEntity</c>)</see>.
/// </remarks>
[DebuggerDisplay("PublicKeyCredentialUserEntity(Id={Id}, Name={Name}, DisplayName={DisplayName})")]
public sealed record PublicKeyCredentialUserEntity
{
    /// <summary>
    /// The user handle identifying the user account, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#user-handle">section 4: Terminology, "User
    /// Handle"</see>.
    /// </summary>
    /// <remarks>
    /// Borrowed for the lifetime of the enclosing options document; ownership and disposal remain
    /// with whichever caller supplied it (the relying party's own user-account store), mirroring
    /// every other carrier this options surface projects rather than copies — see the type-level
    /// remarks on <see cref="PublicKeyCredentialDescriptor"/>.
    /// </remarks>
    public required UserHandle Id { get; init; }

    /// <summary>
    /// A human-palatable identifier for the user account, the primary value clients display to help
    /// users understand which account a credential is associated with.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-pkcredentialentity">W3C Web
    /// Authentication Level 3, section 5.4.1</see> documents a SHOULD: "The Relying Party SHOULD
    /// perform enforcement, as prescribed in Section 3.4.3 of [RFC8265] for the
    /// UsernameCasePreserved Profile of the PRECIS IdentifierClass [RFC8264], when setting name's
    /// value" (row 3608). This library performs no PRECIS profile enforcement — it is an RP-side
    /// text-normalization policy independent of ceremony verification — so the caller remains
    /// responsible for applying it before supplying this value.
    /// </remarks>
    public required string Name { get; init; }

    /// <summary>
    /// A human-palatable name for the user account, intended only for display.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">W3C Web
    /// Authentication Level 3, section 5.4.3</see>: "If no suitable or human-palatable name is
    /// available, the Relying Party SHOULD set this value to an empty string" (row 3677) — the
    /// default <see cref="Fido2RegistrationOptionsBuilder"/> transformation applies when the caller
    /// supplies no display name. Section 5.4.1's PRECIS Nickname Profile SHOULD (row 3681) applies
    /// here exactly as documented on <see cref="Name"/> — the caller's responsibility, not this
    /// library's.
    /// </remarks>
    public required string DisplayName { get; init; }
}
