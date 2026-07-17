using System.Linq;
using System.Security.Cryptography;
using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// Validation check functions for the WebAuthn registration ceremony. Each function matches the
/// <see cref="ClaimDelegateAsync{TInput}"/> signature for composition via
/// <see cref="ClaimIssuer{TInput}"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
/// Authentication Level 3, section 7.1: Registering a New Credential</see>.
/// </para>
/// <para>
/// Every check here compares surface fields already carried by <see cref="RegistrationCeremonyInput"/>.
/// Deriving those fields — hashing the RP ID, computing the client data hash, walking an
/// attestation trust path, checking credential-id uniqueness in storage — is ceremony
/// orchestration and lives outside this rule list.
/// </para>
/// </remarks>
public static class Fido2RegistrationChecks
{
    /// <summary>
    /// Checks that the client data <c>type</c> member is <c>webauthn.create</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationClientDataType(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = WellKnownClientDataTypes.IsCreate(input.ClientData.Type)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationClientDataType, outcome)]);
    }


    /// <summary>
    /// Checks that the client data <c>challenge</c> equals the challenge issued for this
    /// ceremony, using ordinal comparison over the base64url-encoded text.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationChallenge(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = string.Equals(input.ClientData.Challenge, input.ExpectedChallenge, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationChallenge, outcome)]);
    }


    /// <summary>
    /// Checks that the client data <c>origin</c> is one of the relying party's expected origins.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationOrigin(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ContainsOrdinal(input.ExpectedOrigins, input.ClientData.Origin)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationOrigin, outcome)]);
    }


    /// <summary>
    /// Checks that a cross-origin ceremony is only accepted when the relying party allows it.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationCrossOrigin(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = input.ClientData.CrossOrigin == true && !input.AllowCrossOrigin
            ? ClaimOutcome.Failure
            : ClaimOutcome.Success;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationCrossOrigin, outcome)]);
    }


    /// <summary>
    /// Checks that a present <c>topOrigin</c> is one of the relying party's expected top-level
    /// origins.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationTopOrigin(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome;
        if(input.ClientData.TopOrigin is null)
        {
            outcome = ClaimOutcome.Success;
        }
        else if(input.ExpectedTopOrigins is null)
        {
            outcome = ClaimOutcome.Failure;
        }
        else
        {
            outcome = ContainsOrdinal(input.ExpectedTopOrigins, input.ClientData.TopOrigin)
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationTopOrigin, outcome)]);
    }


    /// <summary>
    /// Checks that <c>authData.rpIdHash</c> matches the expected relying party ID hash, using a
    /// fixed-time comparison over equal-length buffers.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationRpIdHash(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlySpan<byte> actual = input.AuthenticatorData.RpIdHash.AsReadOnlySpan();
        ReadOnlySpan<byte> expected = input.ExpectedRpIdHash.AsReadOnlySpan();
        ClaimOutcome outcome = actual.Length == expected.Length && CryptographicOperations.FixedTimeEquals(actual, expected)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationRpIdHash, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>UP</c> bit is set, unless the caller opted out via
    /// <see cref="RegistrationCeremonyInput.AllowUserPresenceAbsent"/> for a conditional-create
    /// ceremony.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationUserPresent(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = input.AuthenticatorData.Flags.UserPresent || input.AllowUserPresenceAbsent
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationUserPresent, outcome)]);
    }


    /// <summary>
    /// Checks the <c>UV</c> bit against the relying party's <see cref="UserVerificationRequirement"/>
    /// policy: <see cref="UserVerificationRequirement.Required"/> fails the ceremony on a clear bit;
    /// <see cref="UserVerificationRequirement.Preferred"/>/<see cref="UserVerificationRequirement.Discouraged"/>
    /// always succeed and record the observed bit in the claim's
    /// <see cref="Verifiable.Core.Assessment.Claim.Context"/> via <see cref="UserVerificationClaimContext"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationUserVerified(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        bool userVerified = input.AuthenticatorData.Flags.UserVerified;
        Claim claim = input.UserVerification switch
        {
            UserVerificationRequirement.Required => new Claim(
                Fido2ClaimIds.Fido2RegistrationUserVerified,
                userVerified ? ClaimOutcome.Success : ClaimOutcome.Failure),
            UserVerificationRequirement.Preferred or UserVerificationRequirement.Discouraged => new Claim(
                Fido2ClaimIds.Fido2RegistrationUserVerified,
                ClaimOutcome.Success,
                new UserVerificationClaimContext(userVerified),
                Claim.NoSubClaims),
            _ => throw new System.Diagnostics.UnreachableException($"Unhandled {nameof(UserVerificationRequirement)} value '{input.UserVerification}'; the enum admits only Required, Preferred and Discouraged.")
        };

        return ValueTask.FromResult<List<Claim>>([claim]);
    }


    /// <summary>
    /// Checks that the backup flags are internally consistent: the <c>BS</c> bit must not be set
    /// unless the <c>BE</c> bit is also set.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationBackupFlagsInvariant(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        AuthenticatorDataFlags flags = input.AuthenticatorData.Flags;
        ClaimOutcome outcome = flags.BackupEligible || !flags.BackupState
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationBackupFlagsInvariant, outcome)]);
    }


    /// <summary>
    /// Checks that the attested credential public key's <c>alg</c> is one of the algorithms the
    /// relying party requested.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationCredentialAlgorithm(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        AttestedCredentialData? attestedCredentialData = input.AuthenticatorData.AttestedCredentialData;
        ClaimOutcome outcome = attestedCredentialData is not null
            && attestedCredentialData.CredentialPublicKey.Alg is int algorithm
            && input.AllowedAlgorithms.Contains(algorithm)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationCredentialAlgorithm, outcome)]);
    }


    /// <summary>
    /// Checks that the attested <c>credentialId</c> length falls within the specification's
    /// bound.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRegistrationCredentialIdLength(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        AttestedCredentialData? attestedCredentialData = input.AuthenticatorData.AttestedCredentialData;
        ClaimOutcome outcome = attestedCredentialData is not null
            && attestedCredentialData.CredentialId.Length is >= 1 and <= CredentialId.MaxLength
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationCredentialIdLength, outcome)]);
    }


    /// <summary>
    /// Checks the attestation statement's assessed trustworthiness, an exhaustive switch over the
    /// closed <see cref="AttestationResult"/> sum.
    /// </summary>
    /// <remarks>
    /// A missing result fails outright; <see cref="NoneAttestationResult"/> and
    /// <see cref="SelfAttestationResult"/> succeed only when the relying party's policy accepts
    /// them (see <see cref="RegistrationCeremonyInput.AcceptNoneAttestation"/> and
    /// <see cref="RegistrationCeremonyInput.AcceptSelfAttestation"/>); a
    /// <see cref="CertifiedAttestationResult"/> always succeeds here because its certificate
    /// chain has already validated by the time this check runs; a
    /// <see cref="RejectedAttestationResult"/> always fails.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckRegistrationAttestationTrustworthy(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = input.AttestationResult switch
        {
            null => ClaimOutcome.Failure,
            NoneAttestationResult => input.AcceptNoneAttestation ? ClaimOutcome.Success : ClaimOutcome.Failure,
            SelfAttestationResult => input.AcceptSelfAttestation ? ClaimOutcome.Success : ClaimOutcome.Failure,
            CertifiedAttestationResult => ClaimOutcome.Success,
            RejectedAttestationResult => ClaimOutcome.Failure,
            _ => throw new System.Diagnostics.UnreachableException($"Unhandled {nameof(AttestationResult)} subtype '{input.AttestationResult.GetType().Name}'; the closed sum admits only the four sibling records.")
        };

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy, outcome)]);
    }


    /// <summary>
    /// Determines whether <paramref name="candidates"/> contains <paramref name="value"/> under
    /// ordinal string comparison, independent of whatever equality comparer the caller's set was
    /// constructed with.
    /// </summary>
    /// <param name="candidates">The set of acceptable values.</param>
    /// <param name="value">The value to look for.</param>
    /// <returns><see langword="true"/> if an ordinal match was found; otherwise <see langword="false"/>.</returns>
    private static bool ContainsOrdinal(IReadOnlySet<string> candidates, string value)
    {
        foreach(string candidate in candidates)
        {
            if(string.Equals(candidate, value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
