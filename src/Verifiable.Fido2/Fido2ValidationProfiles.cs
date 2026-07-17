using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// Pre-built <see cref="ClaimDelegate{TInput}"/> lists for the WebAuthn registration and
/// authentication ceremonies, composable via <see cref="ClaimIssuer{TInput}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each method returns a mutable <see cref="IList{T}"/> the application can extend with custom
/// rules before passing to a <see cref="ClaimIssuer{TInput}"/>. Adding a new WebAuthn-adjacent
/// check means adding methods to <see cref="Fido2RegistrationChecks"/> or
/// <see cref="Fido2AssertionChecks"/> and wiring them in here — not new files.
/// </para>
/// <para>
/// Example: extending registration verification with a relying party's own attestation metadata
/// check.
/// </para>
/// <code>
/// var rules = Fido2ValidationProfiles.RegistrationRules();
/// rules.Add(new ClaimDelegate&lt;RegistrationCeremonyInput&gt;(
///     MyChecks.CheckAttestationMetadata,
///     [MyClaimIds.AttestationMetadataValid]));
///
/// var verifier = new ClaimIssuer&lt;RegistrationCeremonyInput&gt;(
///     "fido2-registration-verifier", rules, timeProvider);
/// </code>
/// </remarks>
public static class Fido2ValidationProfiles
{
    /// <summary>
    /// WebAuthn registration ceremony validation rules, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<RegistrationCeremonyInput>> RegistrationRules() =>
        new List<ClaimDelegate<RegistrationCeremonyInput>>
        {
            new(Fido2RegistrationChecks.CheckRegistrationClientDataType,
                [Fido2ClaimIds.Fido2RegistrationClientDataType]),

            new(Fido2RegistrationChecks.CheckRegistrationChallenge,
                [Fido2ClaimIds.Fido2RegistrationChallenge]),

            new(Fido2RegistrationChecks.CheckRegistrationOrigin,
                [Fido2ClaimIds.Fido2RegistrationOrigin]),

            new(Fido2RegistrationChecks.CheckRegistrationCrossOrigin,
                [Fido2ClaimIds.Fido2RegistrationCrossOrigin]),

            new(Fido2RegistrationChecks.CheckRegistrationTopOrigin,
                [Fido2ClaimIds.Fido2RegistrationTopOrigin]),

            new(Fido2RegistrationChecks.CheckRegistrationRpIdHash,
                [Fido2ClaimIds.Fido2RegistrationRpIdHash]),

            new(Fido2RegistrationChecks.CheckRegistrationUserPresent,
                [Fido2ClaimIds.Fido2RegistrationUserPresent]),

            new(Fido2RegistrationChecks.CheckRegistrationUserVerified,
                [Fido2ClaimIds.Fido2RegistrationUserVerified]),

            new(Fido2RegistrationChecks.CheckRegistrationBackupFlagsInvariant,
                [Fido2ClaimIds.Fido2RegistrationBackupFlagsInvariant]),

            new(Fido2RegistrationChecks.CheckRegistrationCredentialAlgorithm,
                [Fido2ClaimIds.Fido2RegistrationCredentialAlgorithm]),

            new(Fido2RegistrationChecks.CheckRegistrationCredentialIdLength,
                [Fido2ClaimIds.Fido2RegistrationCredentialIdLength]),

            new(Fido2RegistrationChecks.CheckRegistrationAttestationTrustworthy,
                [Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy]),

            new(Fido2ExtensionChecks.CheckRegistrationExtensionOutputs,
                [Fido2ClaimIds.Fido2RegistrationExtensionOutputs]),
        };


    /// <summary>
    /// WebAuthn authentication ceremony validation rules, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<AssertionCeremonyInput>> AssertionRules() =>
        new List<ClaimDelegate<AssertionCeremonyInput>>
        {
            new(Fido2AssertionChecks.CheckAssertionClientDataType,
                [Fido2ClaimIds.Fido2AssertionClientDataType]),

            new(Fido2AssertionChecks.CheckAssertionChallenge,
                [Fido2ClaimIds.Fido2AssertionChallenge]),

            new(Fido2AssertionChecks.CheckAssertionOrigin,
                [Fido2ClaimIds.Fido2AssertionOrigin]),

            new(Fido2AssertionChecks.CheckAssertionCrossOrigin,
                [Fido2ClaimIds.Fido2AssertionCrossOrigin]),

            new(Fido2AssertionChecks.CheckAssertionTopOrigin,
                [Fido2ClaimIds.Fido2AssertionTopOrigin]),

            new(Fido2AssertionChecks.CheckAssertionRpIdHash,
                [Fido2ClaimIds.Fido2AssertionRpIdHash]),

            new(Fido2AssertionChecks.CheckAssertionUserPresent,
                [Fido2ClaimIds.Fido2AssertionUserPresent]),

            new(Fido2AssertionChecks.CheckAssertionUserVerified,
                [Fido2ClaimIds.Fido2AssertionUserVerified]),

            new(Fido2AssertionChecks.CheckAssertionBackupFlagsInvariant,
                [Fido2ClaimIds.Fido2AssertionBackupFlagsInvariant]),

            new(Fido2AssertionChecks.CheckAssertionNoAttestedCredentialData,
                [Fido2ClaimIds.Fido2AssertionNoAttestedCredentialData]),

            new(Fido2AssertionChecks.CheckAssertionAllowedCredentials,
                [Fido2ClaimIds.Fido2AssertionAllowedCredentials]),

            new(Fido2AssertionChecks.CheckAssertionSignCountRegression,
                [Fido2ClaimIds.Fido2AssertionSignCountRegression]),

            new(Fido2AssertionChecks.CheckAssertionUvInitializedUpgrade,
                [Fido2ClaimIds.Fido2AssertionUvInitializedUpgrade]),

            new(Fido2AssertionChecks.CheckAssertionBackupStateConsistency,
                [Fido2ClaimIds.Fido2AssertionBackupStateConsistency]),

            new(Fido2AssertionChecks.CheckAssertionUserHandle,
                [Fido2ClaimIds.Fido2AssertionUserHandle]),

            new(Fido2ExtensionChecks.CheckAssertionExtensionOutputs,
                [Fido2ClaimIds.Fido2AssertionExtensionOutputs]),
        };
}
