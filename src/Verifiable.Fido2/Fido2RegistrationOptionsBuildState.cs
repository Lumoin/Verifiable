using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Core.Model.Common;

namespace Verifiable.Fido2;

/// <summary>
/// The build state for <see cref="Fido2RegistrationOptionsBuilder"/>'s fold/aggregate pipeline —
/// every piece of caller-supplied information a registered <c>With</c> transformation needs to
/// populate one part of the assembled <see cref="PublicKeyCredentialCreationOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// Precomputed once, from <see cref="Fido2RegistrationOptionsBuilder.BuildAsync"/>'s own parameters,
/// before the fold runs — mirroring <c>CredentialBuildState</c>/<c>KeyDidBuildState</c>'s own shape.
/// A member left <see langword="null"/> tells the corresponding default transformation to apply the
/// CR's own spec default instead of an explicit caller value; see each
/// <see cref="PublicKeyCredentialCreationOptions"/> member's own remarks for the specific default.
/// </para>
/// <para>
/// This struct implements value equality semantics where two build states are considered equal if
/// they carry the same relying party, user, and requested option values — list-typed members compare
/// by count only, matching <c>KeyDidBuildState</c>'s own convention, and <see cref="Pool"/> compares
/// by reference, since a memory pool has no meaningful value identity.
/// </para>
/// </remarks>
public readonly struct Fido2RegistrationOptionsBuildState: IEquatable<Fido2RegistrationOptionsBuildState>, IBuilderState
{
    /// <summary>The relying party identifier. See <see cref="PublicKeyCredentialRpEntity.Id"/>.</summary>
    public required string RpId { get; init; }

    /// <summary>The relying party's display name, or <see langword="null"/> to default to <see cref="RpId"/> (row 3588).</summary>
    public string? RpName { get; init; }

    /// <summary>The user handle. See <see cref="PublicKeyCredentialUserEntity.Id"/>. Borrowed, not owned by this state.</summary>
    public required UserHandle UserId { get; init; }

    /// <summary>The user account's name. See <see cref="PublicKeyCredentialUserEntity.Name"/>.</summary>
    public required string UserName { get; init; }

    /// <summary>The user account's display name, or <see langword="null"/> to default to an empty string (row 3677).</summary>
    public string? UserDisplayName { get; init; }

    /// <summary>The memory pool the default challenge transformation rents entropy from.</summary>
    public required MemoryPool<byte> Pool { get; init; }

    /// <summary>
    /// Existing credentials mapped to this user account, projected into <c>excludeCredentials</c>
    /// (rows 3527/4270/4277/4285), or <see langword="null"/>/empty for none.
    /// </summary>
    public IReadOnlyList<Fido2CredentialRecord>? ExistingCredentials { get; init; }

    /// <summary>An explicit challenge overriding the default entropy-provider-generated one, or <see langword="null"/> to use the default.</summary>
    public string? Challenge { get; init; }

    /// <summary>The <c>timeout</c> hint, or <see langword="null"/> to leave it unset (no spec default exists).</summary>
    public uint? Timeout { get; init; }

    /// <summary>The attestation conveyance preference, or <see langword="null"/> to default to <see cref="AttestationConveyancePreference.None"/>.</summary>
    public AttestationConveyancePreference? Attestation { get; init; }

    /// <summary>The preferred attestation statement formats, or <see langword="null"/>/empty for no preference.</summary>
    public IReadOnlyList<string>? AttestationFormats { get; init; }

    /// <summary>An explicit authenticator attachment filter, or <see langword="null"/> for any modality.</summary>
    public string? AuthenticatorAttachment { get; init; }

    /// <summary>The resident-key requirement, or <see langword="null"/> to derive it from <see cref="RequireResidentKey"/>.</summary>
    public ResidentKeyRequirement? ResidentKey { get; init; }

    /// <summary>The Level 1 compatibility flag, or <see langword="null"/> to derive it from <see cref="ResidentKey"/>.</summary>
    public bool? RequireResidentKey { get; init; }

    /// <summary>The user verification requirement for this registration, or <see langword="null"/> to default to <see cref="UserVerificationRequirement.Preferred"/>.</summary>
    public UserVerificationRequirement? UserVerification { get; init; }

    /// <summary>Hints for the user agent, or <see langword="null"/>/empty for none.</summary>
    public IReadOnlyList<PublicKeyCredentialHint>? Hints { get; init; }

    /// <summary>The <c>appidExclude</c> extension's legacy AppID, or <see langword="null"/> when not requested.</summary>
    public string? AppIdExclude { get; init; }

    /// <summary>The <c>largeBlob</c> extension's registration-side support requirement, or <see langword="null"/> when not requested.</summary>
    public LargeBlobSupport? LargeBlobSupport { get; init; }


    /// <summary>
    /// Determines whether the specified <see cref="Fido2RegistrationOptionsBuildState"/> is equal to
    /// the current instance.
    /// </summary>
    /// <param name="other">The build state to compare with the current instance.</param>
    /// <returns><see langword="true"/> if the two build states carry the same values; otherwise <see langword="false"/>.</returns>
    public bool Equals(Fido2RegistrationOptionsBuildState other)
    {
        return RpId == other.RpId
            && RpName == other.RpName
            && UserId.Equals(other.UserId)
            && UserName == other.UserName
            && UserDisplayName == other.UserDisplayName
            && ReferenceEquals(Pool, other.Pool)
            && ExistingCredentials?.Count == other.ExistingCredentials?.Count
            && Challenge == other.Challenge
            && Timeout == other.Timeout
            && Attestation == other.Attestation
            && AttestationFormats?.Count == other.AttestationFormats?.Count
            && AuthenticatorAttachment == other.AuthenticatorAttachment
            && ResidentKey == other.ResidentKey
            && RequireResidentKey == other.RequireResidentKey
            && UserVerification == other.UserVerification
            && Hints?.Count == other.Hints?.Count
            && AppIdExclude == other.AppIdExclude
            && LargeBlobSupport == other.LargeBlobSupport;
    }


    /// <summary>Determines whether the specified object is equal to the current instance.</summary>
    /// <param name="obj">The object to compare with the current instance.</param>
    /// <returns><see langword="true"/> when <paramref name="obj"/> is an equal <see cref="Fido2RegistrationOptionsBuildState"/>.</returns>
    public override bool Equals(object? obj) => obj is Fido2RegistrationOptionsBuildState other && Equals(other);


    /// <summary>Returns the hash code for this instance.</summary>
    /// <returns>A 32-bit signed integer hash code consistent with <see cref="Equals(Fido2RegistrationOptionsBuildState)"/>.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(RpId);
        hash.Add(RpName);
        hash.Add(UserId);
        hash.Add(UserName);
        hash.Add(UserDisplayName);
        hash.Add(ExistingCredentials?.Count ?? 0);
        hash.Add(Challenge);
        hash.Add(Timeout);
        hash.Add(Attestation);
        hash.Add(AttestationFormats?.Count ?? 0);
        hash.Add(AuthenticatorAttachment);
        hash.Add(ResidentKey);
        hash.Add(RequireResidentKey);
        hash.Add(UserVerification);
        hash.Add(Hints?.Count ?? 0);
        hash.Add(AppIdExclude);
        hash.Add(LargeBlobSupport);

        return hash.ToHashCode();
    }


    /// <summary>Determines whether two specified instances are equal.</summary>
    public static bool operator ==(Fido2RegistrationOptionsBuildState left, Fido2RegistrationOptionsBuildState right) => left.Equals(right);


    /// <summary>Determines whether two specified instances are not equal.</summary>
    public static bool operator !=(Fido2RegistrationOptionsBuildState left, Fido2RegistrationOptionsBuildState right) => !left.Equals(right);
}
