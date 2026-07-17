using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// Validation <see cref="ClaimId"/> instances for WebAuthn registration and authentication
/// ceremony checks. Codes 1200–1299.
/// </summary>
/// <remarks>
/// <para>
/// Sub-ranges (mirrors the grouping convention in
/// <see cref="Verifiable.OAuth.Validation.ValidationClaimIds"/>):
/// </para>
/// <list type="bullet">
///   <item><description>1200–1219: Registration ceremony checks, per
///   <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
///   Authentication Level 3, section 7.1: Registering a New Credential</see>.</description></item>
///   <item><description>1220–1239: Assertion ceremony checks, per
///   <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
///   Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>.</description></item>
///   <item><description>1240–1249: Extension output checks (both ceremonies), per
///   <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section 9: WebAuthn
///   Extensions</see>.</description></item>
///   <item><description>1250–1299: Reserved for future WebAuthn ceremony checks.</description></item>
/// </list>
/// </remarks>
public static class Fido2ClaimIds
{
    /// <summary>
    /// The registration client data <c>type</c> member is <c>webauthn.create</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 7.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationClientDataType = ClaimId.Create(1200, "Fido2RegistrationClientDataType");

    /// <summary>
    /// The registration client data <c>challenge</c> matches the expected challenge.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 8.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationChallenge = ClaimId.Create(1201, "Fido2RegistrationChallenge");

    /// <summary>
    /// The registration client data <c>origin</c> is one of the expected origins.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 9.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationOrigin = ClaimId.Create(1202, "Fido2RegistrationOrigin");

    /// <summary>
    /// The registration client data <c>crossOrigin</c> indicator is acceptable under the
    /// relying party's cross-origin policy.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 10.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationCrossOrigin = ClaimId.Create(1203, "Fido2RegistrationCrossOrigin");

    /// <summary>
    /// The registration client data <c>topOrigin</c>, when present, is one of the expected top
    /// origins.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 11.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationTopOrigin = ClaimId.Create(1204, "Fido2RegistrationTopOrigin");

    /// <summary>
    /// The registration <c>authData.rpIdHash</c> matches the expected relying party ID hash.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 14.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationRpIdHash = ClaimId.Create(1205, "Fido2RegistrationRpIdHash");

    /// <summary>
    /// The registration <c>authData</c> <c>UP</c> (user present) bit is set, unless the caller
    /// opted out for a conditional-create ceremony.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 15.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationUserPresent = ClaimId.Create(1206, "Fido2RegistrationUserPresent");

    /// <summary>
    /// The registration <c>authData</c> <c>UV</c> (user verified) bit is set when the relying
    /// party requires user verification.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 16.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationUserVerified = ClaimId.Create(1207, "Fido2RegistrationUserVerified");

    /// <summary>
    /// The registration <c>authData</c> backup flags are internally consistent: the <c>BS</c>
    /// (backup state) bit is not set unless the <c>BE</c> (backup eligible) bit is also set.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 17.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationBackupFlagsInvariant = ClaimId.Create(1208, "Fido2RegistrationBackupFlagsInvariant");

    /// <summary>
    /// The registration attested credential public key's <c>alg</c> is one of the algorithms
    /// the relying party requested.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 20.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationCredentialAlgorithm = ClaimId.Create(1209, "Fido2RegistrationCredentialAlgorithm");

    /// <summary>
    /// The registration attested credential's <c>credentialId</c> length is within the
    /// specification's bound.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 25.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationCredentialIdLength = ClaimId.Create(1210, "Fido2RegistrationCredentialIdLength");

    /// <summary>
    /// The registration attestation statement was assessed as trustworthy under the relying
    /// party's attestation policy.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 24.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationAttestationTrustworthy = ClaimId.Create(1211, "Fido2RegistrationAttestationTrustworthy");

    /// <summary>
    /// The registration <c>credentialId</c> is not yet registered to any other user.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 26. Computed
    /// by <see cref="Fido2RegistrationVerifier"/> via the RP-supplied
    /// <see cref="IsCredentialIdUniqueDelegate"/> rather than by a
    /// <see cref="Fido2RegistrationChecks"/> rule, since only the relying party's own credential
    /// storage can answer it; <see cref="Fido2RegistrationVerifier.VerifyAsync"/> merges this
    /// claim into the <see cref="ClaimIssueResult"/> it returns.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationCredentialIdUnique = ClaimId.Create(1212, "Fido2RegistrationCredentialIdUnique");

    /// <summary>
    /// The registration attestation's trust path did not reach a relying-party-configured anchor,
    /// but the relying party's downgrade policy accepted the credential by treating the
    /// attestation as equivalent to none. Emitted only on the downgrade path; the claim's
    /// <see cref="Claim.Context"/> records the attestation format that was downgraded, for
    /// relying-party audit.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, the ceremony's
    /// final step (step 29): "If the Relying Party does not fail the registration ceremony in this
    /// case, then the Relying Party is accepting that there is no cryptographic proof that the
    /// public key credential has been generated by any particular authenticator model. The Relying
    /// Party MAY consider the credential as equivalent to one with no attestation" (see
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">section 6.5.3:
    /// Attestation Types</see>), MAY. This differs from step 24's own self-attestation NOTE (the
    /// two clauses are adjacent but distinct): step 24's note downgrades an untrustworthy
    /// attestation to self-attestation-equivalent, while this claim's step-29 clause downgrades to
    /// none-equivalent.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationAttestationDowngraded = ClaimId.Create(1213, "Fido2RegistrationAttestationDowngraded");



    /// <summary>
    /// The assertion client data <c>type</c> member is <c>webauthn.get</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 10.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionClientDataType = ClaimId.Create(1220, "Fido2AssertionClientDataType");

    /// <summary>
    /// The assertion client data <c>challenge</c> matches the expected challenge.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 11.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionChallenge = ClaimId.Create(1221, "Fido2AssertionChallenge");

    /// <summary>
    /// The assertion client data <c>origin</c> is one of the expected origins.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 12.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionOrigin = ClaimId.Create(1222, "Fido2AssertionOrigin");

    /// <summary>
    /// The assertion client data <c>crossOrigin</c> indicator is acceptable under the relying
    /// party's cross-origin policy.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 13.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionCrossOrigin = ClaimId.Create(1223, "Fido2AssertionCrossOrigin");

    /// <summary>
    /// The assertion client data <c>topOrigin</c>, when present, is one of the expected top
    /// origins.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 14.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionTopOrigin = ClaimId.Create(1224, "Fido2AssertionTopOrigin");

    /// <summary>
    /// The assertion <c>authData.rpIdHash</c> matches the expected relying party ID hash.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 15.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionRpIdHash = ClaimId.Create(1225, "Fido2AssertionRpIdHash");

    /// <summary>
    /// The assertion <c>authData</c> <c>UP</c> (user present) bit is set.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 16.
    /// Unlike registration's step 15, the assertion step carries no conditional-mediation
    /// exception — the specification text requires this bit unconditionally.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionUserPresent = ClaimId.Create(1226, "Fido2AssertionUserPresent");

    /// <summary>
    /// The assertion <c>authData</c> <c>UV</c> (user verified) bit is set when the relying
    /// party requires user verification.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 17.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionUserVerified = ClaimId.Create(1227, "Fido2AssertionUserVerified");

    /// <summary>
    /// The assertion <c>authData</c> backup flags are internally consistent: the <c>BS</c>
    /// (backup state) bit is not set unless the <c>BE</c> (backup eligible) bit is also set.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 18.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionBackupFlagsInvariant = ClaimId.Create(1228, "Fido2AssertionBackupFlagsInvariant");

    /// <summary>
    /// The asserted credential identifier is one of the relying party's allowed credentials, or
    /// no allowlist was supplied (the discoverable-credential path).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 5.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionAllowedCredentials = ClaimId.Create(1229, "Fido2AssertionAllowedCredentials");

    /// <summary>
    /// The assertion's <c>signCount</c> does not regress against the stored counter — a
    /// possible-clone signal rather than a hard failure.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 22.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionSignCountRegression = ClaimId.Create(1230, "Fido2AssertionSignCountRegression");

    /// <summary>
    /// The assertion's current backup eligibility and backup state are consistent with the
    /// stored credential record.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 19.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionBackupStateConsistency = ClaimId.Create(1231, "Fido2AssertionBackupStateConsistency");

    /// <summary>
    /// The credential's owning user account is confirmed: a present <c>response.userHandle</c>
    /// identifies the owner of the asserted credential, or — on the discoverable-credential path,
    /// where no allowlist was supplied — a <c>userHandle</c> is present at all.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 6:
    /// "Identify the user being authenticated and let credentialRecord be the credential record
    /// for the credential" — a single step (not sub-numbered in the current text) with two cases:
    /// if the user was already identified before the ceremony, a present <c>userHandle</c> must
    /// equal that user account's handle; if the user was not identified beforehand, <c>userHandle</c>
    /// is REQUIRED and identifies the account. <see cref="Fido2AssertionChecks.CheckAssertionUserHandle"/>
    /// treats <see cref="AssertionCeremonyInput.AllowedCredentialIds"/> being <see langword="null"/>
    /// as the "user not identified beforehand" case, mirroring
    /// <see cref="Fido2ClaimIds.Fido2AssertionAllowedCredentials"/>'s own discoverable-credential
    /// reading of that field.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionUserHandle = ClaimId.Create(1232, "Fido2AssertionUserHandle");

    /// <summary>
    /// The assertion <c>authData</c> carries neither the <c>AT</c> flag nor an attested credential
    /// data block.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web
    /// Authentication Level 3, section 6.1: Authenticator Data</see> requires that "For assertion
    /// signatures, the AT flag MUST NOT be set and the attestedCredentialData MUST NOT be
    /// included" — the mirror image of the same list item's registration-side requirement that
    /// attestation signatures MUST set <c>AT</c> and include <c>attestedCredentialData</c>. This
    /// check is ceremony-specific rather than reader behavior: <c>AT</c> and attested credential
    /// data remain legal in registration <c>authData</c>, so
    /// <see cref="AuthenticatorDataReader.Read"/> does not reject them; only the assertion ceremony
    /// rejects their presence, giving the relying party a named cross-check against an
    /// authenticator (or attacker) that replays a <c>makeCredential</c>-shaped <c>authData</c>
    /// structure into a <c>getAssertion</c> response.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionNoAttestedCredentialData = ClaimId.Create(1233, "Fido2AssertionNoAttestedCredentialData");

    /// <summary>
    /// The stored credential record's <c>uvInitialized</c> was <see langword="false"/> and the
    /// assertion's <c>UV</c> flag is <see langword="true"/> — a step-up transition the relying
    /// party gates behind its own additional-authentication policy before persisting the flip.
    /// <see cref="Verifiable.Core.Assessment.ClaimOutcome.Inconclusive"/> for the transition case
    /// (a signal, not proof — mirrors <see cref="Fido2AssertionSignCountRegression"/>'s framing);
    /// <see cref="Verifiable.Core.Assessment.ClaimOutcome.Success"/> when there is no transition to
    /// gate (already <see langword="true"/>, or still <see langword="false"/>).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 24,
    /// the "update credentialRecord" step: "If credentialRecord.uvInitialized is false, update it
    /// to the value of the UV bit in the flags in authData. This change SHOULD require
    /// authorization by an additional authentication factor equivalent to WebAuthn user
    /// verification; if not authorized, skip this step.", SHOULD. The library performs no auth
    /// logic and does not mutate the stored record itself; the relying party's own persistence
    /// code decides.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionUvInitializedUpgrade = ClaimId.Create(1234, "Fido2AssertionUvInitializedUpgrade");



    /// <summary>
    /// The registration ceremony's extension outputs were processed: every present identifier with
    /// a registered processor was honored, and — when the relying party opted in via
    /// <see cref="RegistrationCeremonyInput.RejectUnregisteredExtensionOutputs"/> — no present
    /// identifier lacked one. <see cref="Verifiable.Core.Assessment.ClaimOutcome.NotApplicable"/>
    /// when no extension outputs were present at all.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#reg-ceremony-verify-extension-outputs">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 28, and
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section 9: WebAuthn
    /// Extensions</see>'s "Relying Parties MUST be prepared to handle cases where some or all of
    /// those extensions are ignored".
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationExtensionOutputs = ClaimId.Create(1240, "Fido2RegistrationExtensionOutputs");

    /// <summary>
    /// The assertion ceremony's extension outputs were processed: every present identifier with a
    /// registered processor was honored, and — when the relying party opted in via
    /// <see cref="AssertionCeremonyInput.RejectUnregisteredExtensionOutputs"/> — no present
    /// identifier lacked one. <see cref="Verifiable.Core.Assessment.ClaimOutcome.NotApplicable"/>
    /// when no extension outputs were present at all.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#authn-ceremony-verify-extension-outputs">W3C
    /// Web Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step
    /// 23, and <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section 9: WebAuthn
    /// Extensions</see>'s "Relying Parties MUST be prepared to handle cases where some or all of
    /// those extensions are ignored".
    /// </remarks>
    public static readonly ClaimId Fido2AssertionExtensionOutputs = ClaimId.Create(1241, "Fido2AssertionExtensionOutputs");

    /// <summary>
    /// The registration ceremony's decoded <c>largeBlob</c> client extension output carried a
    /// <c>supported</c> boolean, recorded here as evidence. Always
    /// <see cref="Verifiable.Core.Assessment.ClaimOutcome.Success"/> when the identifier is
    /// present and decodes cleanly — both <see langword="true"/> and <see langword="false"/> are
    /// legitimate authenticator states, not protocol violations; a malformed decode fails closed
    /// via the ceremony-level extension-processing claim instead.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web
    /// Authentication Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see> —
    /// client extension output <c>supported</c>, registration-only.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationLargeBlobSupported = ClaimId.Create(1242, "Fido2RegistrationLargeBlobSupported");

    /// <summary>
    /// The assertion ceremony's decoded <c>largeBlob</c> client extension output carried a
    /// <c>blob</c> payload, meaning a large-blob read succeeded; the decoded bytes are carried in
    /// the claim's <see cref="Claim.Context"/>. A present <c>largeBlob</c> output with no
    /// <c>blob</c> member reflects the specification's own documented "read failed" case, not a
    /// wire defect, and is reported as a distinguishable non-<see
    /// cref="Verifiable.Core.Assessment.ClaimOutcome.Failure"/> outcome — only a genuinely
    /// malformed base64url/JSON shape fails closed.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web
    /// Authentication Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see> —
    /// client extension output <c>blob</c>, authentication-only, "present only if read succeeded".
    /// </remarks>
    public static readonly ClaimId Fido2AssertionLargeBlobRead = ClaimId.Create(1243, "Fido2AssertionLargeBlobRead");

    /// <summary>
    /// The assertion ceremony's decoded <c>largeBlob</c> client extension output carried a
    /// <c>written</c> boolean, recorded here as evidence. Always
    /// <see cref="Verifiable.Core.Assessment.ClaimOutcome.Success"/> when the identifier is
    /// present and decodes cleanly, mirroring <see cref="Fido2RegistrationLargeBlobSupported"/>'s
    /// posture.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web
    /// Authentication Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see> —
    /// client extension output <c>written</c>, authentication-only.
    /// </remarks>
    public static readonly ClaimId Fido2AssertionLargeBlobWritten = ClaimId.Create(1244, "Fido2AssertionLargeBlobWritten");

    /// <summary>
    /// The registration ceremony's <c>appidExclude</c> client extension output acknowledged that
    /// the client acted on the legacy AppID exclusion extension while constructing
    /// <c>excludeCredentials</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension">W3C Web
    /// Authentication Level 3, section 10.1.2: FIDO AppID Exclusion Extension
    /// (appidExclude)</see> — client extension output: "Returns the value TRUE to indicate to the
    /// Relying Party that the extension was acted upon." Section 10.1.2 defines no RFC2119
    /// keyword for this extension (its FacetID-authorization algorithm is client-only processing,
    /// sourced from an external, non-CR document); this claim is a feature-completeness
    /// acknowledgment, not the closure of a normative clause.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationAppIdExclude = ClaimId.Create(1245, "Fido2RegistrationAppIdExclude");

    /// <summary>
    /// The registration ceremony's <c>credProtect</c> authenticator extension output decoded to one of
    /// the three registered wire values {1, 2, 3}; the level is carried in the claim's
    /// <see cref="CredProtectLevelContext"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credProtect-extension">
    /// CTAP 2.3, section 12.1: Credential Protection (credProtect)</see> — authenticator extension
    /// output, registration-only.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationCredProtect = ClaimId.Create(1246, "Fido2RegistrationCredProtect");

    /// <summary>
    /// The registration ceremony's <c>minPinLength</c> authenticator extension output decoded to an
    /// unsigned integer; the length is carried in the claim's <see cref="MinPinLengthContext"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension">
    /// CTAP 2.3, section 12.5: Minimum PIN Length Extension (minPinLength)</see> — authenticator
    /// extension output, registration-only.
    /// </remarks>
    public static readonly ClaimId Fido2RegistrationMinPinLength = ClaimId.Create(1247, "Fido2RegistrationMinPinLength");
}
