using Verifiable.Cbor.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.Fido2;
using Verifiable.Tests.TestDataProviders;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Builds fully-valid <see cref="RegistrationCeremonyInput"/> and <see cref="AssertionCeremonyInput"/>
/// instances for the <see cref="Fido2ValidationProfiles"/> rule tests.
/// </summary>
/// <remarks>
/// Every parameter defaults to a value that keeps the returned ceremony valid against every rule in
/// <see cref="Fido2ValidationProfiles.RegistrationRules"/> / <see cref="Fido2ValidationProfiles.AssertionRules"/>
/// (or, for the two assertion claims whose valid default is "not tracked" —
/// <see cref="Fido2ClaimIds.Fido2AssertionAllowedCredentials"/> and
/// <see cref="Fido2ClaimIds.Fido2AssertionBackupStateConsistency"/> — <see cref="Verifiable.Core.Assessment.ClaimOutcome.NotApplicable"/>).
/// A test overrides exactly the parameter(s) needed to exercise one rule's failure axis, leaving every
/// other rule looking at a valid surface.
/// </remarks>
/// <remarks>
/// Both factory methods return an <see cref="IDisposable"/> ceremony input owning pooled carriers
/// (<c>AuthenticatorData</c>, <c>ExpectedRpIdHash</c>, and, for an assertion, <c>CredentialId</c> /
/// <c>AllowedCredentialIds</c> / <c>ResponseUserHandle</c> / <c>StoredUserHandle</c>) rented from
/// <see cref="BaseMemoryPool.Shared"/>. Callers dispose the returned instance via a
/// <see langword="using"/> declaration.
/// </remarks>
internal static class Fido2CeremonyInputFactory
{
    /// <summary>The base64url-encoded challenge shared by a valid client data payload and its matching expected challenge.</summary>
    internal const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin shared by a valid client data payload and its matching expected origin set.</summary>
    internal const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The top-level browsing context origin used by the topOrigin-present test axis.</summary>
    internal const string ValidTopOrigin = "https://embedder.example";

    /// <summary>The COSE algorithm identifier a valid ceremony's attested credential public key carries.</summary>
    internal const int ValidAlgorithm = WellKnownCoseAlgorithms.Es256;

    /// <summary>The credential identifier a valid ceremony's attested credential data, or asserted credential, carries.</summary>
    internal static byte[] ValidCredentialId { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>
    /// The user handle a valid assertion ceremony's <c>response.userHandle</c> and stored user
    /// account record share by default, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">WebAuthn L3
    /// section 5.4.3</see>'s 1-64 byte bound on a user handle.
    /// </summary>
    internal static byte[] ValidUserHandle { get; } = [0x55, 0x66, 0x77, 0x88];


    /// <summary>
    /// Builds a fully-valid <see cref="RegistrationCeremonyInput"/>: every rule in
    /// <see cref="Fido2ValidationProfiles.RegistrationRules"/> succeeds against the returned instance when
    /// every parameter is left at its default.
    /// </summary>
    /// <param name="clientDataType">The client data <c>type</c> member. Defaults to <see cref="WellKnownClientDataTypes.Create"/>.</param>
    /// <param name="clientDataChallenge">The client-reported challenge. Defaults to <see cref="ValidChallenge"/>.</param>
    /// <param name="clientDataOrigin">The client-reported origin. Defaults to <see cref="ValidOrigin"/>.</param>
    /// <param name="clientDataCrossOrigin">The client-reported <c>crossOrigin</c> indicator. Defaults to absent.</param>
    /// <param name="clientDataTopOrigin">The client-reported <c>topOrigin</c>. Defaults to absent.</param>
    /// <param name="expectedChallenge">The relying party's expected challenge. Defaults to <see cref="ValidChallenge"/>.</param>
    /// <param name="expectedOrigins">The relying party's accepted origins. Defaults to a set containing <see cref="ValidOrigin"/>.</param>
    /// <param name="allowCrossOrigin">Whether the relying party accepts a cross-origin ceremony. Defaults to <see langword="false"/>.</param>
    /// <param name="expectedTopOrigins">The relying party's expected top-level origins. Defaults to <see langword="null"/>.</param>
    /// <param name="authDataRpIdHash">The <c>rpIdHash</c> baked into <c>authData</c>. Defaults to a fresh valid hash.</param>
    /// <param name="expectedRpIdHash">The relying party's expected RP ID hash. Defaults to a fresh valid hash with the same content as <paramref name="authDataRpIdHash"/>'s default.</param>
    /// <param name="userPresent">The <c>UP</c> flag value. Defaults to <see langword="true"/>.</param>
    /// <param name="userVerified">The <c>UV</c> flag value. Defaults to <see langword="true"/>.</param>
    /// <param name="backupEligible">The <c>BE</c> flag value. Defaults to <see langword="false"/>.</param>
    /// <param name="backupState">The <c>BS</c> flag value. Defaults to <see langword="false"/>.</param>
    /// <param name="userVerification">The relying party's user-verification policy. Defaults to <see cref="UserVerificationRequirement.Required"/>.</param>
    /// <param name="allowUserPresenceAbsent">Whether the relying party permits an absent <c>UP</c> bit. Defaults to <see langword="false"/>.</param>
    /// <param name="allowedAlgorithms">The relying party's accepted COSE algorithms. Defaults to a list containing <see cref="ValidAlgorithm"/>.</param>
    /// <param name="credentialAlgorithm">The attested credential public key's <c>alg</c>. Defaults to <see cref="ValidAlgorithm"/>; pass <see langword="null"/> to omit it.</param>
    /// <param name="includeAttestedCredentialData">Whether <c>authData</c> carries attested credential data. Defaults to <see langword="true"/>.</param>
    /// <param name="attestationResult">The attestation verification outcome. Defaults to a <see cref="NoneAttestationResult"/>.</param>
    /// <param name="omitAttestationResult">
    /// Forces <see cref="RegistrationCeremonyInput.AttestationResult"/> to <see langword="null"/> regardless of
    /// <paramref name="attestationResult"/> — the one escape hatch a nullable optional parameter cannot express on
    /// its own, since <see langword="null"/> is also this parameter's own "not specified" default.
    /// </param>
    /// <param name="acceptNoneAttestation">Whether the relying party accepts <see cref="NoneAttestationResult"/>. Defaults to <see langword="true"/>.</param>
    /// <param name="acceptSelfAttestation">Whether the relying party accepts <see cref="SelfAttestationResult"/>. Defaults to <see langword="true"/>.</param>
    /// <param name="clientExtensionOutputs">The ceremony's decoded client extension outputs. Defaults to <see langword="null"/> — no extensions.</param>
    /// <param name="authenticatorExtensionOutputs">The ceremony's decoded authenticator extension outputs. Defaults to <see langword="null"/> — no extensions.</param>
    /// <param name="extensionOutputProcessor">The relying party's extension processor selector. Defaults to <see langword="null"/> — none registered.</param>
    /// <param name="rejectUnregisteredExtensionOutputs">Whether an unregistered extension identifier fails the extension-outputs claim. Defaults to <see langword="false"/>.</param>
    /// <param name="clientDataOverride">
    /// A caller-supplied <see cref="ClientData"/> that replaces the one this factory would otherwise
    /// assemble from <paramref name="clientDataType"/>/<paramref name="clientDataChallenge"/>/
    /// <paramref name="clientDataOrigin"/>/<paramref name="clientDataCrossOrigin"/>/
    /// <paramref name="clientDataTopOrigin"/>. Defaults to <see langword="null"/>. A flow test that
    /// authors its own <c>clientDataJSON</c> through the production writer and reads it back through
    /// <see cref="Verifiable.Json.ClientDataJsonReader"/> passes the result here so the factory only
    /// assembles the ceremony input from already-real wire material.
    /// </param>
    /// <param name="authenticatorDataOverride">
    /// A caller-supplied <see cref="AuthenticatorData"/> that replaces the one this factory would
    /// otherwise assemble from <paramref name="authDataRpIdHash"/> and the flag/credential parameters.
    /// Defaults to <see langword="null"/>, mirroring <paramref name="clientDataOverride"/>.
    /// </param>
    /// <returns>A <see cref="RegistrationCeremonyInput"/> satisfying every rule in <see cref="Fido2ValidationProfiles.RegistrationRules"/> when no parameter is overridden.</returns>
    internal static RegistrationCeremonyInput CreateValidRegistrationInput(
        string? clientDataType = null,
        string? clientDataChallenge = null,
        string? clientDataOrigin = null,
        bool? clientDataCrossOrigin = null,
        string? clientDataTopOrigin = null,
        string? expectedChallenge = null,
        IReadOnlySet<string>? expectedOrigins = null,
        bool allowCrossOrigin = false,
        IReadOnlySet<string>? expectedTopOrigins = null,
        byte[]? authDataRpIdHash = null,
        byte[]? expectedRpIdHash = null,
        bool userPresent = true,
        bool userVerified = true,
        bool backupEligible = false,
        bool backupState = false,
        UserVerificationRequirement userVerification = UserVerificationRequirement.Required,
        bool allowUserPresenceAbsent = false,
        IReadOnlyList<int>? allowedAlgorithms = null,
        int? credentialAlgorithm = ValidAlgorithm,
        bool includeAttestedCredentialData = true,
        AttestationResult? attestationResult = null,
        bool omitAttestationResult = false,
        bool acceptNoneAttestation = true,
        bool acceptSelfAttestation = true,
        IReadOnlyList<Fido2ExtensionOutput>? clientExtensionOutputs = null,
        IReadOnlyList<Fido2ExtensionOutput>? authenticatorExtensionOutputs = null,
        SelectExtensionOutputProcessorDelegate? extensionOutputProcessor = null,
        bool rejectUnregisteredExtensionOutputs = false,
        ClientData? clientDataOverride = null,
        AuthenticatorData? authenticatorDataOverride = null)
    {
        ClientData clientData = clientDataOverride ?? new ClientData(
            clientDataType ?? WellKnownClientDataTypes.Create,
            clientDataChallenge ?? ValidChallenge,
            clientDataOrigin ?? ValidOrigin,
            clientDataCrossOrigin,
            clientDataTopOrigin);

        byte flags = ComposeRegistrationFlags(userPresent, userVerified, backupEligible, backupState, includeAttestedCredentialData);
        byte[]? attestedCredentialDataBytes = includeAttestedCredentialData
            ? BuildAttestedCredentialData(Guid.NewGuid(), ValidCredentialId, EncodeP256CoseKeyWithAlgorithm(credentialAlgorithm))
            : null;

        byte[] authenticatorDataBytes = BuildAuthenticatorData(
            authDataRpIdHash ?? CreateRpIdHash(),
            flags,
            signCount: 0,
            attestedCredentialData: attestedCredentialDataBytes);

        AuthenticatorData authenticatorData = authenticatorDataOverride ?? AuthenticatorDataReader.Read(authenticatorDataBytes, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        AttestationResult? effectiveAttestationResult = omitAttestationResult
            ? null
            : attestationResult ?? new NoneAttestationResult();

        return new RegistrationCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = expectedChallenge ?? ValidChallenge,
            ExpectedOrigins = expectedOrigins ?? new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(expectedRpIdHash ?? CreateRpIdHash(), BaseMemoryPool.Shared),
            AllowCrossOrigin = allowCrossOrigin,
            ExpectedTopOrigins = expectedTopOrigins,
            UserVerification = userVerification,
            AllowUserPresenceAbsent = allowUserPresenceAbsent,
            AllowedAlgorithms = allowedAlgorithms ?? [ValidAlgorithm],
            AttestationResult = effectiveAttestationResult,
            AcceptNoneAttestation = acceptNoneAttestation,
            AcceptSelfAttestation = acceptSelfAttestation,
            ClientExtensionOutputs = clientExtensionOutputs,
            AuthenticatorExtensionOutputs = authenticatorExtensionOutputs,
            ExtensionOutputProcessor = extensionOutputProcessor,
            RejectUnregisteredExtensionOutputs = rejectUnregisteredExtensionOutputs
        };
    }


    /// <summary>
    /// Builds a fully-valid <see cref="AssertionCeremonyInput"/>: every applicable rule in
    /// <see cref="Fido2ValidationProfiles.AssertionRules"/> succeeds — or reports
    /// <see cref="Verifiable.Core.Assessment.ClaimOutcome.NotApplicable"/> for the two claims whose valid
    /// default is "not tracked" (no allowlist, no stored backup record) — when every parameter is left at its
    /// default.
    /// </summary>
    /// <param name="clientDataType">The client data <c>type</c> member. Defaults to <see cref="WellKnownClientDataTypes.Get"/>.</param>
    /// <param name="clientDataChallenge">The client-reported challenge. Defaults to <see cref="ValidChallenge"/>.</param>
    /// <param name="clientDataOrigin">The client-reported origin. Defaults to <see cref="ValidOrigin"/>.</param>
    /// <param name="clientDataCrossOrigin">The client-reported <c>crossOrigin</c> indicator. Defaults to absent.</param>
    /// <param name="clientDataTopOrigin">The client-reported <c>topOrigin</c>. Defaults to absent.</param>
    /// <param name="expectedChallenge">The relying party's expected challenge. Defaults to <see cref="ValidChallenge"/>.</param>
    /// <param name="expectedOrigins">The relying party's accepted origins. Defaults to a set containing <see cref="ValidOrigin"/>.</param>
    /// <param name="allowCrossOrigin">Whether the relying party accepts a cross-origin ceremony. Defaults to <see langword="false"/>.</param>
    /// <param name="expectedTopOrigins">The relying party's expected top-level origins. Defaults to <see langword="null"/>.</param>
    /// <param name="authDataRpIdHash">The <c>rpIdHash</c> baked into <c>authData</c>. Defaults to a fresh valid hash.</param>
    /// <param name="expectedRpIdHash">The relying party's expected RP ID hash. Defaults to a fresh valid hash with the same content as <paramref name="authDataRpIdHash"/>'s default.</param>
    /// <param name="userPresent">The <c>UP</c> flag value. Defaults to <see langword="true"/>.</param>
    /// <param name="userVerified">The <c>UV</c> flag value. Defaults to <see langword="true"/>.</param>
    /// <param name="backupEligible">The <c>BE</c> flag value. Defaults to <see langword="false"/>.</param>
    /// <param name="backupState">The <c>BS</c> flag value. Defaults to <see langword="false"/>.</param>
    /// <param name="userVerification">The relying party's user-verification policy. Defaults to <see cref="UserVerificationRequirement.Required"/>.</param>
    /// <param name="signCount">The asserted <c>authData.signCount</c>. Defaults to <c>1</c>.</param>
    /// <param name="storedSignCount">The stored signature counter. Defaults to <c>0</c>, so the default pairing is strictly increasing.</param>
    /// <param name="storedUvInitialized">The stored credential record's <c>uvInitialized</c> value. Defaults to <see langword="true"/> — no step-up transition to gate by default.</param>
    /// <param name="allowedCredentialIds">The relying party's <c>allowCredentials</c> allowlist. Defaults to <see langword="null"/> — the discoverable-credential path.</param>
    /// <param name="credentialId">The asserted credential identifier. Defaults to <see langword="null"/>.</param>
    /// <param name="storedBackupEligible">The stored credential record's backup eligibility. Defaults to <see langword="null"/> — not tracked.</param>
    /// <param name="storedBackupState">The stored credential record's backup state. Defaults to <see langword="null"/> — not tracked.</param>
    /// <param name="responseUserHandle">
    /// The wire-reported <c>response.userHandle</c> bytes. Defaults to <see cref="ValidUserHandle"/>
    /// — matching <paramref name="storedUserHandle"/>'s default, so
    /// <see cref="Fido2ClaimIds.Fido2AssertionUserHandle"/> succeeds unless overridden.
    /// </param>
    /// <param name="omitResponseUserHandle">
    /// Forces <see cref="AssertionCeremonyInput.ResponseUserHandle"/> to <see langword="null"/>
    /// regardless of <paramref name="responseUserHandle"/> — the one escape hatch a nullable
    /// optional parameter cannot express on its own, mirroring
    /// <see cref="CreateValidRegistrationInput"/>'s <c>omitAttestationResult</c>.
    /// </param>
    /// <param name="storedUserHandle">The relying party's stored user handle for the credential's owner. Defaults to <see cref="ValidUserHandle"/>.</param>
    /// <param name="omitStoredUserHandle">Forces <see cref="AssertionCeremonyInput.StoredUserHandle"/> to <see langword="null"/> regardless of <paramref name="storedUserHandle"/>.</param>
    /// <param name="clientExtensionOutputs">The ceremony's decoded client extension outputs. Defaults to <see langword="null"/> — no extensions.</param>
    /// <param name="authenticatorExtensionOutputs">The ceremony's decoded authenticator extension outputs. Defaults to <see langword="null"/> — no extensions.</param>
    /// <param name="extensionOutputProcessor">The relying party's extension processor selector. Defaults to <see langword="null"/> — none registered.</param>
    /// <param name="rejectUnregisteredExtensionOutputs">Whether an unregistered extension identifier fails the extension-outputs claim. Defaults to <see langword="false"/>.</param>
    /// <param name="appIdExtensionOutput">The decoded <c>appid</c> client extension output boolean. Defaults to <see langword="false"/>.</param>
    /// <param name="expectedAppIdHash">The relying party's expected AppID hash bytes. Defaults to <see langword="null"/> — not configured.</param>
    /// <returns>An <see cref="AssertionCeremonyInput"/> satisfying every applicable rule in <see cref="Fido2ValidationProfiles.AssertionRules"/> when no parameter is overridden.</returns>
    internal static AssertionCeremonyInput CreateValidAssertionInput(
        string? clientDataType = null,
        string? clientDataChallenge = null,
        string? clientDataOrigin = null,
        bool? clientDataCrossOrigin = null,
        string? clientDataTopOrigin = null,
        string? expectedChallenge = null,
        IReadOnlySet<string>? expectedOrigins = null,
        bool allowCrossOrigin = false,
        IReadOnlySet<string>? expectedTopOrigins = null,
        byte[]? authDataRpIdHash = null,
        byte[]? expectedRpIdHash = null,
        bool userPresent = true,
        bool userVerified = true,
        bool backupEligible = false,
        bool backupState = false,
        UserVerificationRequirement userVerification = UserVerificationRequirement.Required,
        uint signCount = 1,
        uint storedSignCount = 0,
        bool storedUvInitialized = true,
        IReadOnlyList<CredentialId>? allowedCredentialIds = null,
        CredentialId? credentialId = null,
        bool? storedBackupEligible = null,
        bool? storedBackupState = null,
        byte[]? responseUserHandle = null,
        bool omitResponseUserHandle = false,
        byte[]? storedUserHandle = null,
        bool omitStoredUserHandle = false,
        IReadOnlyList<Fido2ExtensionOutput>? clientExtensionOutputs = null,
        IReadOnlyList<Fido2ExtensionOutput>? authenticatorExtensionOutputs = null,
        SelectExtensionOutputProcessorDelegate? extensionOutputProcessor = null,
        bool rejectUnregisteredExtensionOutputs = false,
        bool appIdExtensionOutput = false,
        byte[]? expectedAppIdHash = null)
    {
        var clientData = new ClientData(
            clientDataType ?? WellKnownClientDataTypes.Get,
            clientDataChallenge ?? ValidChallenge,
            clientDataOrigin ?? ValidOrigin,
            clientDataCrossOrigin,
            clientDataTopOrigin);

        byte flags = ComposeAssertionFlags(userPresent, userVerified, backupEligible, backupState);
        byte[] authenticatorDataBytes = BuildAuthenticatorData(authDataRpIdHash ?? CreateRpIdHash(), flags, signCount);
        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(authenticatorDataBytes, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        UserHandle? responseUserHandleCarrier = omitResponseUserHandle
            ? null
            : UserHandle.Create(responseUserHandle ?? ValidUserHandle, BaseMemoryPool.Shared);
        UserHandle? storedUserHandleCarrier = omitStoredUserHandle
            ? null
            : UserHandle.Create(storedUserHandle ?? ValidUserHandle, BaseMemoryPool.Shared);
        DigestValue? expectedAppIdHashCarrier = expectedAppIdHash is null
            ? null
            : Fido2TestVectors.WrapRpIdHash(expectedAppIdHash, BaseMemoryPool.Shared);

        return new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = expectedChallenge ?? ValidChallenge,
            ExpectedOrigins = expectedOrigins ?? new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(expectedRpIdHash ?? CreateRpIdHash(), BaseMemoryPool.Shared),
            AllowCrossOrigin = allowCrossOrigin,
            ExpectedTopOrigins = expectedTopOrigins,
            UserVerification = userVerification,
            AllowedCredentialIds = allowedCredentialIds,
            CredentialId = credentialId,
            StoredSignCount = storedSignCount,
            StoredUvInitialized = storedUvInitialized,
            StoredBackupEligible = storedBackupEligible,
            StoredBackupState = storedBackupState,
            ResponseUserHandle = responseUserHandleCarrier,
            StoredUserHandle = storedUserHandleCarrier,
            ClientExtensionOutputs = clientExtensionOutputs,
            AuthenticatorExtensionOutputs = authenticatorExtensionOutputs,
            ExtensionOutputProcessor = extensionOutputProcessor,
            RejectUnregisteredExtensionOutputs = rejectUnregisteredExtensionOutputs,
            AppIdExtensionOutput = appIdExtensionOutput,
            ExpectedAppIdHash = expectedAppIdHashCarrier
        };
    }


    /// <summary>
    /// Composes a registration <c>authData</c> flags byte from its named bits. The extension-data bit is always
    /// clear because no factory-built ceremony carries extensions.
    /// </summary>
    /// <param name="userPresent">The <c>UP</c> bit value.</param>
    /// <param name="userVerified">The <c>UV</c> bit value.</param>
    /// <param name="backupEligible">The <c>BE</c> bit value.</param>
    /// <param name="backupState">The <c>BS</c> bit value.</param>
    /// <param name="attestedCredentialDataIncluded">The <c>AT</c> bit value.</param>
    /// <returns>The composed flags byte.</returns>
    private static byte ComposeRegistrationFlags(bool userPresent, bool userVerified, bool backupEligible, bool backupState, bool attestedCredentialDataIncluded)
    {
        byte flags = AuthenticatorDataFlags.None;
        if(userPresent) { flags |= AuthenticatorDataFlags.UserPresentBit; }
        if(userVerified) { flags |= AuthenticatorDataFlags.UserVerifiedBit; }
        if(backupEligible) { flags |= AuthenticatorDataFlags.BackupEligibleBit; }
        if(backupState) { flags |= AuthenticatorDataFlags.BackupStateBit; }
        if(attestedCredentialDataIncluded) { flags |= AuthenticatorDataFlags.AttestedCredentialDataIncludedBit; }

        return flags;
    }


    /// <summary>
    /// Composes an assertion <c>authData</c> flags byte from its named bits. Assertion ceremonies carry no
    /// attested credential data or extensions, so only the presence/verification/backup bits are set.
    /// </summary>
    /// <param name="userPresent">The <c>UP</c> bit value.</param>
    /// <param name="userVerified">The <c>UV</c> bit value.</param>
    /// <param name="backupEligible">The <c>BE</c> bit value.</param>
    /// <param name="backupState">The <c>BS</c> bit value.</param>
    /// <returns>The composed flags byte.</returns>
    private static byte ComposeAssertionFlags(bool userPresent, bool userVerified, bool backupEligible, bool backupState)
    {
        byte flags = AuthenticatorDataFlags.None;
        if(userPresent) { flags |= AuthenticatorDataFlags.UserPresentBit; }
        if(userVerified) { flags |= AuthenticatorDataFlags.UserVerifiedBit; }
        if(backupEligible) { flags |= AuthenticatorDataFlags.BackupEligibleBit; }
        if(backupState) { flags |= AuthenticatorDataFlags.BackupStateBit; }

        return flags;
    }


    /// <summary>
    /// Builds a P-256 COSE_Key CBOR encoding carrying <paramref name="algorithm"/> as its <c>alg</c> parameter,
    /// reusing <see cref="TestKeyMaterialProvider.CreateP256KeyMaterial"/> and
    /// <see cref="MdocTestFixtures.CoseKeyFromP256Public"/> for the key material and EC2 parameter shape, since
    /// neither helper exposes an <c>alg</c> override.
    /// </summary>
    /// <param name="algorithm">The COSE algorithm identifier to carry, or <see langword="null"/> to omit it.</param>
    /// <returns>The CBOR-encoded COSE_Key bytes.</returns>
    private static byte[] EncodeP256CoseKeyWithAlgorithm(int? algorithm)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CoseKey baseKey = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            var coseKey = new CoseKey(baseKey.Kty, algorithm, baseKey.Curve, baseKey.X, baseKey.Y);

            return MdocCborCoseKeyWriter.Write(coseKey).ToArray();
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }
}
