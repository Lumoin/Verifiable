using System.Security.Cryptography;
using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// Validation check functions for the WebAuthn authentication ceremony. Each function matches
/// the <see cref="ClaimDelegateAsync{TInput}"/> signature for composition via
/// <see cref="ClaimIssuer{TInput}"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication
/// Level 3, section 7.2: Verifying an Authentication Assertion</see>.
/// </para>
/// <para>
/// Every check here compares surface fields already carried by <see cref="AssertionCeremonyInput"/>.
/// Deriving those fields — hashing the RP ID, computing the client data hash, verifying the
/// assertion signature itself, loading the stored credential record — is ceremony orchestration
/// and lives outside this rule list.
/// </para>
/// </remarks>
public static class Fido2AssertionChecks
{
    /// <summary>
    /// Checks that the client data <c>type</c> member is <c>webauthn.get</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckAssertionClientDataType(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = WellKnownClientDataTypes.IsGet(input.ClientData.Type)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionClientDataType, outcome)]);
    }


    /// <summary>
    /// Checks that the client data <c>challenge</c> equals the challenge issued for this
    /// ceremony, using ordinal comparison over the base64url-encoded text.
    /// </summary>
    public static ValueTask<List<Claim>> CheckAssertionChallenge(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = string.Equals(input.ClientData.Challenge, input.ExpectedChallenge, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionChallenge, outcome)]);
    }


    /// <summary>
    /// Checks that the client data <c>origin</c> is one of the relying party's expected origins.
    /// </summary>
    public static ValueTask<List<Claim>> CheckAssertionOrigin(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ContainsOrdinal(input.ExpectedOrigins, input.ClientData.Origin)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionOrigin, outcome)]);
    }


    /// <summary>
    /// Checks that a cross-origin ceremony is only accepted when the relying party allows it.
    /// </summary>
    public static ValueTask<List<Claim>> CheckAssertionCrossOrigin(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = input.ClientData.CrossOrigin == true && !input.AllowCrossOrigin
            ? ClaimOutcome.Failure
            : ClaimOutcome.Success;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionCrossOrigin, outcome)]);
    }


    /// <summary>
    /// Checks that a present <c>topOrigin</c> is one of the relying party's expected top-level
    /// origins.
    /// </summary>
    public static ValueTask<List<Claim>> CheckAssertionTopOrigin(
        AssertionCeremonyInput input,
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
            [new Claim(Fido2ClaimIds.Fido2AssertionTopOrigin, outcome)]);
    }


    /// <summary>
    /// Checks that <c>authData.rpIdHash</c> matches the expected relying party ID hash — or, when
    /// the <c>appid</c> extension was used, the expected AppID hash — using a fixed-time comparison
    /// over equal-length buffers.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#rp-op-verifying-assertion-step-rpid-hash">W3C
    /// Web Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step
    /// 15's note: "If using the appid extension, this step needs some special logic. See
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-extension">section 10.1.1: FIDO
    /// AppID Extension (appid)</see> for details" — whose client extension output sentence reads
    /// "If true, the AppID was used and thus, when verifying the assertion, the Relying Party MUST
    /// expect the rpIdHash to be the hash of the AppID, not the RP ID." This check stays a pure
    /// field comparison: <see cref="AssertionCeremonyInput.AppIdExtensionOutput"/> selects which
    /// already-computed hash to compare against; it derives neither hash itself. An RP that
    /// reports <see cref="AssertionCeremonyInput.AppIdExtensionOutput"/> without configuring
    /// <see cref="AssertionCeremonyInput.ExpectedAppIdHash"/> fails closed rather than falling back
    /// to the RP ID hash.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAssertionRpIdHash(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome;
        if(input.AppIdExtensionOutput && input.ExpectedAppIdHash is null)
        {
            outcome = ClaimOutcome.Failure;
        }
        else
        {
            ReadOnlySpan<byte> actual = input.AuthenticatorData.RpIdHash.AsReadOnlySpan();
            ReadOnlySpan<byte> expected = input.AppIdExtensionOutput
                ? input.ExpectedAppIdHash!.AsReadOnlySpan()
                : input.ExpectedRpIdHash.AsReadOnlySpan();
            outcome = actual.Length == expected.Length && CryptographicOperations.FixedTimeEquals(actual, expected)
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionRpIdHash, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>UP</c> bit is set.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 16
    /// requires this bit unconditionally — unlike registration's step 15, the assertion step
    /// carries no conditional-mediation exception, so there is no opt-out field on
    /// <see cref="AssertionCeremonyInput"/> for this check.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAssertionUserPresent(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = input.AuthenticatorData.Flags.UserPresent
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionUserPresent, outcome)]);
    }


    /// <summary>
    /// Checks the <c>UV</c> bit against the relying party's <see cref="UserVerificationRequirement"/>
    /// policy: <see cref="UserVerificationRequirement.Required"/> fails the ceremony on a clear bit;
    /// <see cref="UserVerificationRequirement.Preferred"/>/<see cref="UserVerificationRequirement.Discouraged"/>
    /// always succeed and record the observed bit in the claim's
    /// <see cref="Verifiable.Core.Assessment.Claim.Context"/> via <see cref="UserVerificationClaimContext"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckAssertionUserVerified(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        bool userVerified = input.AuthenticatorData.Flags.UserVerified;
        Claim claim = input.UserVerification switch
        {
            UserVerificationRequirement.Required => new Claim(
                Fido2ClaimIds.Fido2AssertionUserVerified,
                userVerified ? ClaimOutcome.Success : ClaimOutcome.Failure),
            UserVerificationRequirement.Preferred or UserVerificationRequirement.Discouraged => new Claim(
                Fido2ClaimIds.Fido2AssertionUserVerified,
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
    public static ValueTask<List<Claim>> CheckAssertionBackupFlagsInvariant(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        AuthenticatorDataFlags flags = input.AuthenticatorData.Flags;
        ClaimOutcome outcome = flags.BackupEligible || !flags.BackupState
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionBackupFlagsInvariant, outcome)]);
    }


    /// <summary>
    /// Checks that the asserted credential identifier is one of the relying party's allowed
    /// credentials.
    /// </summary>
    /// <remarks>
    /// <see cref="AssertionCeremonyInput.AllowedCredentialIds"/> being <see langword="null"/>
    /// means the relying party supplied no allowlist — the discoverable-credential path, where
    /// this check does not apply. When an allowlist is present, the asserted credential ID must
    /// be present and byte-for-byte equal (ordinal) to one of its entries.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAssertionAllowedCredentials(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome;
        if(input.AllowedCredentialIds is null)
        {
            outcome = ClaimOutcome.NotApplicable;
        }
        else if(input.CredentialId is not CredentialId credentialId)
        {
            outcome = ClaimOutcome.Failure;
        }
        else
        {
            outcome = ClaimOutcome.Failure;
            foreach(CredentialId allowedCredentialId in input.AllowedCredentialIds)
            {
                if(allowedCredentialId.Equals(credentialId))
                {
                    outcome = ClaimOutcome.Success;
                    break;
                }
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionAllowedCredentials, outcome)]);
    }


    /// <summary>
    /// Checks the assertion's <c>signCount</c> against the stored counter for a possible-clone
    /// signal.
    /// </summary>
    /// <remarks>
    /// Authenticators that do not implement the counter report zero on every assertion, so a
    /// zero-to-zero comparison is a normal outcome, not a regression. A strictly increasing
    /// counter succeeds. Any other relationship — equal nonzero values, or a decrease — is
    /// reported as <see cref="ClaimOutcome.Inconclusive"/> rather than
    /// <see cref="ClaimOutcome.Failure"/>: the specification calls this a signal that the
    /// authenticator may be cloned, not proof of it, and leaves the response (reject, step up,
    /// merely log) to relying party policy. A caller that treats <see cref="ClaimOutcome.Inconclusive"/>
    /// as fatal simply rejects on it.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAssertionSignCountRegression(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        uint signCount = input.AuthenticatorData.SignCount;
        ClaimOutcome outcome = (signCount, input.StoredSignCount) switch
        {
            (0, 0) => ClaimOutcome.Success,
            _ when signCount > input.StoredSignCount => ClaimOutcome.Success,
            _ => ClaimOutcome.Inconclusive
        };

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionSignCountRegression, outcome)]);
    }


    /// <summary>
    /// Checks whether this assertion transitions the stored credential record's
    /// <c>uvInitialized</c> from <see langword="false"/> to <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 24:
    /// "If credentialRecord.uvInitialized is false, update it to the value of the UV bit in the
    /// flags in authData. This change SHOULD require authorization by an additional authentication
    /// factor equivalent to WebAuthn user verification; if not authorized, skip this step." Mirrors
    /// <see cref="CheckAssertionSignCountRegression"/>'s "signal, not proof" framing: the transition
    /// (stored <see langword="false"/>, current <see langword="true"/>) is reported as
    /// <see cref="ClaimOutcome.Inconclusive"/> — the relying party gates the flip behind its own
    /// additional-authentication policy, and this library performs no auth logic and does not mutate
    /// the stored record itself. Every other combination — no transition available (already
    /// <see langword="true"/>), or nothing to upgrade (still <see langword="false"/>) — succeeds.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAssertionUvInitializedUpgrade(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        bool currentUserVerified = input.AuthenticatorData.Flags.UserVerified;
        ClaimOutcome outcome = (input.StoredUvInitialized, currentUserVerified) switch
        {
            (false, true) => ClaimOutcome.Inconclusive,
            _ => ClaimOutcome.Success
        };

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionUvInitializedUpgrade, outcome)]);
    }


    /// <summary>
    /// Checks the assertion's current backup eligibility and backup state against the stored
    /// credential record.
    /// </summary>
    /// <remarks>
    /// <see cref="AssertionCeremonyInput.StoredBackupEligible"/> being <see langword="null"/>
    /// means the relying party does not track backup eligibility, so this check does not apply.
    /// Otherwise the specification requires the current <c>BE</c> bit to match the stored value
    /// exactly — a mismatch fails. Backup <em>state</em> is different: the specification only
    /// requires relying party policy be applied to a change, so a changed <c>BS</c> bit (only
    /// evaluated when <see cref="AssertionCeremonyInput.StoredBackupState"/> is tracked) is
    /// reported as <see cref="ClaimOutcome.Inconclusive"/> — a signal for the relying party's
    /// policy to act on — rather than silently succeeding or failing.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAssertionBackupStateConsistency(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome;
        if(input.StoredBackupEligible is not bool storedBackupEligible)
        {
            outcome = ClaimOutcome.NotApplicable;
        }
        else if(input.AuthenticatorData.Flags.BackupEligible != storedBackupEligible)
        {
            outcome = ClaimOutcome.Failure;
        }
        else if(input.StoredBackupState is bool storedBackupState && input.AuthenticatorData.Flags.BackupState != storedBackupState)
        {
            outcome = ClaimOutcome.Inconclusive;
        }
        else
        {
            outcome = ClaimOutcome.Success;
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionBackupStateConsistency, outcome)]);
    }


    /// <summary>
    /// Checks that the credential's owning user account is confirmed via
    /// <see cref="AssertionCeremonyInput.ResponseUserHandle"/>, per step 6's two-case switch.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A present <see cref="AssertionCeremonyInput.ResponseUserHandle"/> must be 1-64 bytes
    /// (<see href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">section
    /// 5.4.3</see>'s bound on a user handle), must have a
    /// <see cref="AssertionCeremonyInput.StoredUserHandle"/> to compare against — ownership cannot
    /// be confirmed against a record the relying party never looked up — and must equal it
    /// byte-for-byte.
    /// </para>
    /// <para>
    /// An absent <see cref="AssertionCeremonyInput.ResponseUserHandle"/> is only acceptable when
    /// <see cref="AssertionCeremonyInput.AllowedCredentialIds"/> is non-null: the relying party
    /// supplied an allowlist, meaning it had already identified the user before the ceremony, so
    /// step 6's first case applies and a <c>userHandle</c> is optional. When
    /// <see cref="AssertionCeremonyInput.AllowedCredentialIds"/> is <see langword="null"/> — the
    /// discoverable-credential path, step 6's second case — the specification REQUIRES a
    /// <c>userHandle</c>, so its absence fails.
    /// </para>
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAssertionUserHandle(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome;
        if(input.ResponseUserHandle is UserHandle responseUserHandle)
        {
            if(responseUserHandle.Length is < 1 or > UserHandle.MaxLength)
            {
                outcome = ClaimOutcome.Failure;
            }
            else if(input.StoredUserHandle is not UserHandle storedUserHandle)
            {
                outcome = ClaimOutcome.Failure;
            }
            else
            {
                outcome = responseUserHandle.Equals(storedUserHandle) ? ClaimOutcome.Success : ClaimOutcome.Failure;
            }
        }
        else
        {
            outcome = input.AllowedCredentialIds is null ? ClaimOutcome.Failure : ClaimOutcome.NotApplicable;
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionUserHandle, outcome)]);
    }


    /// <summary>
    /// Checks that the assertion <c>authData</c> carries neither the <c>AT</c> flag nor an
    /// attested credential data block.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web
    /// Authentication Level 3, section 6.1: Authenticator Data</see> requires both halves of this
    /// check to hold: the <c>AT</c> flag bit clear AND no attested credential data block present.
    /// Either one alone would let a mismatched authenticator (flag clear, data present, or vice
    /// versa) slip through, so a set flag OR a non-null
    /// <see cref="Fido2.AuthenticatorData.AttestedCredentialData"/> both fail this claim.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAssertionNoAttestedCredentialData(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = input.AuthenticatorData.Flags.AttestedCredentialDataIncluded
            || input.AuthenticatorData.AttestedCredentialData is not null
                ? ClaimOutcome.Failure
                : ClaimOutcome.Success;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(Fido2ClaimIds.Fido2AssertionNoAttestedCredentialData, outcome)]);
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
