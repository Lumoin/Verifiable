using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Core.Model.Common;

namespace Verifiable.Fido2;

/// <summary>
/// The build state for <see cref="Fido2AssertionOptionsBuilder"/>'s fold/aggregate pipeline — every
/// piece of caller-supplied information a registered <c>With</c> transformation needs to populate one
/// part of the assembled <see cref="PublicKeyCredentialRequestOptions"/>.
/// </summary>
/// <remarks>
/// See <see cref="Fido2RegistrationOptionsBuildState"/>'s type-level remarks — the same shape and
/// equality conventions apply here.
/// </remarks>
public readonly struct Fido2AssertionOptionsBuildState: IEquatable<Fido2AssertionOptionsBuildState>, IBuilderState
{
    /// <summary>The relying party identifier this assertion is scoped to. See <see cref="PublicKeyCredentialRequestOptions.RpId"/>.</summary>
    public required string RpId { get; init; }

    /// <summary>The memory pool the default challenge transformation rents entropy from.</summary>
    public required MemoryPool<byte> Pool { get; init; }

    /// <summary>
    /// Credentials acceptable for this assertion, projected into <c>allowCredentials</c> (rows
    /// 3902/3906/4270/4277/4285), or <see langword="null"/>/empty for the discoverable-credential
    /// path (row 3914).
    /// </summary>
    public IReadOnlyList<Fido2CredentialRecord>? AllowedCredentials { get; init; }

    /// <summary>An explicit challenge overriding the default entropy-provider-generated one, or <see langword="null"/> to use the default.</summary>
    public string? Challenge { get; init; }

    /// <summary>The <c>timeout</c> hint, or <see langword="null"/> to leave it unset (no spec default exists).</summary>
    public uint? Timeout { get; init; }

    /// <summary>The user verification requirement for this assertion, or <see langword="null"/> to default to <see cref="UserVerificationRequirement.Preferred"/>.</summary>
    public UserVerificationRequirement? UserVerification { get; init; }

    /// <summary>Hints for the user agent, or <see langword="null"/>/empty for none.</summary>
    public IReadOnlyList<PublicKeyCredentialHint>? Hints { get; init; }

    /// <summary>The <c>appid</c> extension's legacy AppID, or <see langword="null"/> when not requested.</summary>
    public string? AppId { get; init; }

    /// <summary>
    /// The <c>largeBlob</c> extension's assertion-side input (a read or a write request), or
    /// <see langword="null"/> when not requested.
    /// </summary>
    public Fido2LargeBlobAssertionExtensionInput? LargeBlob { get; init; }


    /// <summary>
    /// Determines whether the specified <see cref="Fido2AssertionOptionsBuildState"/> is equal to the
    /// current instance.
    /// </summary>
    /// <param name="other">The build state to compare with the current instance.</param>
    /// <returns><see langword="true"/> if the two build states carry the same values; otherwise <see langword="false"/>.</returns>
    public bool Equals(Fido2AssertionOptionsBuildState other)
    {
        return RpId == other.RpId
            && ReferenceEquals(Pool, other.Pool)
            && AllowedCredentials?.Count == other.AllowedCredentials?.Count
            && Challenge == other.Challenge
            && Timeout == other.Timeout
            && UserVerification == other.UserVerification
            && Hints?.Count == other.Hints?.Count
            && AppId == other.AppId
            && Equals(LargeBlob, other.LargeBlob);
    }


    /// <summary>Determines whether the specified object is equal to the current instance.</summary>
    /// <param name="obj">The object to compare with the current instance.</param>
    /// <returns><see langword="true"/> when <paramref name="obj"/> is an equal <see cref="Fido2AssertionOptionsBuildState"/>.</returns>
    public override bool Equals(object? obj) => obj is Fido2AssertionOptionsBuildState other && Equals(other);


    /// <summary>Returns the hash code for this instance.</summary>
    /// <returns>A 32-bit signed integer hash code consistent with <see cref="Equals(Fido2AssertionOptionsBuildState)"/>.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(RpId);
        hash.Add(AllowedCredentials?.Count ?? 0);
        hash.Add(Challenge);
        hash.Add(Timeout);
        hash.Add(UserVerification);
        hash.Add(Hints?.Count ?? 0);
        hash.Add(AppId);
        hash.Add(LargeBlob);

        return hash.ToHashCode();
    }


    /// <summary>Determines whether two specified instances are equal.</summary>
    public static bool operator ==(Fido2AssertionOptionsBuildState left, Fido2AssertionOptionsBuildState right) => left.Equals(right);


    /// <summary>Determines whether two specified instances are not equal.</summary>
    public static bool operator !=(Fido2AssertionOptionsBuildState left, Fido2AssertionOptionsBuildState right) => !left.Equals(right);
}
