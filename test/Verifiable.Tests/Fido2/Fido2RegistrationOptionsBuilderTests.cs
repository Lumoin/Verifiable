using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2RegistrationOptionsBuilder"/>: every WP-Options SHOULD/MAY row the
/// registration side owns gets a default-behavior test and an override test, plus the descriptor
/// projection, challenge freshness, and residentKey/requireResidentKey consistency this builder is
/// responsible for.
/// </summary>
[TestClass]
internal sealed class Fido2RegistrationOptionsBuilderTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A fresh user handle for each test. <see cref="PublicKeyCredentialUserEntity.Id"/> borrows this
    /// rather than owning it (per that member's own remarks), so this test class is the owner and
    /// disposes it in <see cref="DisposeUserId"/>.
    /// </summary>
    private UserHandle UserId { get; } = UserHandle.Create([1, 2, 3, 4], BaseMemoryPool.Shared);


    /// <summary>Disposes <see cref="UserId"/> after each test.</summary>
    [TestCleanup]
    public void DisposeUserId()
    {
        UserId.Dispose();
    }


    /// <summary>Row 3588: rp.name defaults to rpId when the caller supplies none.</summary>
    [TestMethod]
    public async Task RpNameDefaultsToRpId()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual("example.com", options.Rp!.Id);
        Assert.AreEqual("example.com", options.Rp.Name);
    }


    /// <summary>Row 3588: an explicit rp.name overrides the rpId default.</summary>
    [TestMethod]
    public async Task RpNameOverrideIsHonored()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: "ACME Corporation", userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual("ACME Corporation", options.Rp!.Name);
    }


    /// <summary>Row 3677: user.displayName defaults to an empty string when the caller supplies none.</summary>
    [TestMethod]
    public async Task UserDisplayNameDefaultsToEmptyString()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(string.Empty, options.User!.DisplayName);
    }


    /// <summary>Row 3677: an explicit displayName overrides the empty-string default.</summary>
    [TestMethod]
    public async Task UserDisplayNameOverrideIsHonored()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: "Alex Müller", pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual("Alex Müller", options.User!.DisplayName);
    }


    /// <summary>
    /// The library performs no PRECIS profile enforcement (rows 3590/3608/3681 are documented SHOULDs
    /// delegated to the caller) — a raw name/displayName passes through unmodified.
    /// </summary>
    [TestMethod]
    public async Task NameAndDisplayNamePassThroughWithoutPrecisEnforcement()
    {
        const string rawName = "  ALEX.mueller@example.com (ОАО Примертех) ";

        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: rawName, userDisplayName: rawName, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(rawName, options.User!.Name);
        Assert.AreEqual(rawName, options.User.DisplayName);
    }


    /// <summary>§13.4.3: the default challenge is generated through the registered entropy provider.</summary>
    [TestMethod]
    public async Task ChallengeDefaultsToGeneratedValue()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsNotNull(options.Challenge);
        Assert.IsNotEmpty(options.Challenge);
    }


    /// <summary>Two builds with no explicit challenge produce distinct challenges — no RNG in the test itself, only the registered entropy provider.</summary>
    [TestMethod]
    public async Task ChallengeIsFreshAcrossBuilds()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions first = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);
        PublicKeyCredentialCreationOptions second = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreNotEqual(first.Challenge, second.Challenge);
    }


    /// <summary>An explicit challenge overrides the default entropy-provider-generated one (e.g. a test fixture needing a fixed value).</summary>
    [TestMethod]
    public async Task ChallengeOverrideIsHonored()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            challenge: "fixed-challenge-value", cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual("fixed-challenge-value", options.Challenge);
    }


    /// <summary>Rows 3497/3506: the default pubKeyCredParams list is exactly EdDSA, ES256, RS256 in that order — never an RFC9864 fully-specified identifier.</summary>
    [TestMethod]
    public async Task PubKeyCredParamsDefaultsToPreferredAlgorithmsInOrder()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.HasCount(3, options.PubKeyCredParams!);
        Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, options.PubKeyCredParams![0].Alg);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, options.PubKeyCredParams[1].Alg);
        Assert.AreEqual(WellKnownCoseAlgorithms.Rs256, options.PubKeyCredParams[2].Alg);
        Assert.DoesNotContain(WellKnownCoseAlgorithms.Esp256, [.. Map(options.PubKeyCredParams)]);
    }


    /// <summary>A caller may append additional algorithms beyond the default list via the inherited <c>With</c>.</summary>
    [TestMethod]
    public async Task PubKeyCredParamsCanBeExtendedViaWith()
    {
        Fido2RegistrationOptionsBuilder builder = new Fido2RegistrationOptionsBuilder()
            .With((options, _, _) =>
            {
                options.PubKeyCredParams =
                [
                    .. options.PubKeyCredParams!,
                    new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256K }
                ];

                return ValueTask.FromResult(options);
            });

        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.HasCount(4, options.PubKeyCredParams!);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256K, options.PubKeyCredParams![3].Alg);
    }


    /// <summary>Rows 3527/4270/4277/4285: excludeCredentials projects a real Fido2CredentialRecord's type/id/transports verbatim.</summary>
    [TestMethod]
    public async Task ExcludeCredentialsProjectsExistingCredentialRecord()
    {
        using Fido2CredentialRecord record = CreateCredentialRecord([9, 8, 7], ["usb", "nfc"]);

        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            existingCredentials: [record], cancellationToken: TestContext.CancellationToken);

        PublicKeyCredentialDescriptor descriptor = Assert.ContainsSingle(options.ExcludeCredentials!);
        Assert.AreEqual(record.Type, descriptor.Type);
        Assert.IsTrue(record.Id.AsReadOnlySpan().SequenceEqual(descriptor.Id.AsReadOnlySpan()));
        Assert.HasCount(2, descriptor.Transports!);
    }


    /// <summary>excludeCredentials is an empty list (not null) when the caller supplies no existing credentials.</summary>
    [TestMethod]
    public async Task ExcludeCredentialsIsEmptyWhenNoneSupplied()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsNotNull(options.ExcludeCredentials);
        Assert.IsEmpty(options.ExcludeCredentials!);
    }


    /// <summary>CR default: neither residentKey nor requireResidentKey supplied resolves to Discouraged/false.</summary>
    [TestMethod]
    public async Task ResidentKeyDefaultsToDiscouraged()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(ResidentKeyRequirement.Discouraged, options.AuthenticatorSelection!.ResidentKey);
        Assert.IsFalse(options.AuthenticatorSelection.RequireResidentKey);
    }


    /// <summary>Row 3731: residentKey=Required forces requireResidentKey=true by construction.</summary>
    [TestMethod]
    public async Task ResidentKeyRequiredForcesRequireResidentKeyTrue()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            residentKey: ResidentKeyRequirement.Required, cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(options.AuthenticatorSelection!.RequireResidentKey);
    }


    /// <summary>CR line 4831: requireResidentKey=true alone (no residentKey given) derives residentKey=Required.</summary>
    [TestMethod]
    public async Task RequireResidentKeyTrueDerivesResidentKeyRequired()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            requireResidentKey: true, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(ResidentKeyRequirement.Required, options.AuthenticatorSelection!.ResidentKey);
    }


    /// <summary>CR's own IDL default: authenticatorSelection.userVerification defaults to Preferred.</summary>
    [TestMethod]
    public async Task UserVerificationDefaultsToPreferred()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(UserVerificationRequirement.Preferred, options.AuthenticatorSelection!.UserVerification);
    }


    /// <summary>An explicit userVerification overrides the Preferred default.</summary>
    [TestMethod]
    public async Task UserVerificationOverrideIsHonored()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            userVerification: UserVerificationRequirement.Required, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(UserVerificationRequirement.Required, options.AuthenticatorSelection!.UserVerification);
    }


    /// <summary>Row 4470: a security-key hint maps to authenticatorAttachment=cross-platform when the caller has not set one explicitly.</summary>
    [TestMethod]
    public async Task SecurityKeyHintMapsToCrossPlatformAttachment()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            hints: [PublicKeyCredentialHint.SecurityKey], cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownAuthenticatorAttachments.CrossPlatform, options.AuthenticatorSelection!.AuthenticatorAttachment);
    }


    /// <summary>Row 4470: a client-device hint maps to authenticatorAttachment=platform.</summary>
    [TestMethod]
    public async Task ClientDeviceHintMapsToPlatformAttachment()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            hints: [PublicKeyCredentialHint.ClientDevice], cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownAuthenticatorAttachments.Platform, options.AuthenticatorSelection!.AuthenticatorAttachment);
    }


    /// <summary>Row 4470: a hybrid hint maps to authenticatorAttachment=cross-platform, completing the section 5.8.6 three-mapping compatibility table.</summary>
    [TestMethod]
    public async Task HybridHintMapsToCrossPlatformAttachment()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            hints: [PublicKeyCredentialHint.Hybrid], cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownAuthenticatorAttachments.CrossPlatform, options.AuthenticatorSelection!.AuthenticatorAttachment);
    }


    /// <summary>Row 4470: the compatibility mapping does not override a caller-supplied explicit attachment.</summary>
    [TestMethod]
    public async Task ExplicitAttachmentIsNotOverriddenByHintMapping()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            authenticatorAttachment: WellKnownAuthenticatorAttachments.Platform,
            hints: [PublicKeyCredentialHint.SecurityKey], cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownAuthenticatorAttachments.Platform, options.AuthenticatorSelection!.AuthenticatorAttachment);
    }


    /// <summary>CR default: attestation defaults to None, attestationFormats defaults to an empty list.</summary>
    [TestMethod]
    public async Task AttestationDefaultsToNoneAndEmptyFormats()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(AttestationConveyancePreference.None, options.Attestation);
        Assert.IsEmpty(options.AttestationFormats!);
    }


    /// <summary>Rows 3543/3550: an explicit attestation preference and format list override the defaults.</summary>
    [TestMethod]
    public async Task AttestationOverrideIsHonored()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            attestation: AttestationConveyancePreference.Direct,
            attestationFormats: [WellKnownWebAuthnAttestationFormats.Packed], cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(AttestationConveyancePreference.Direct, options.Attestation);
        Assert.Contains(WellKnownWebAuthnAttestationFormats.Packed, options.AttestationFormats!);
    }


    /// <summary>No spec-mandated timeout default exists — the member stays unset unless the caller opts in.</summary>
    [TestMethod]
    public async Task TimeoutIsUnsetByDefault()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsNull(options.Timeout);
    }


    /// <summary>An explicit timeout is honored as a pass-through value.</summary>
    [TestMethod]
    public async Task TimeoutOverrideIsHonored()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            timeout: 60000, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual((uint)60000, options.Timeout);
    }


    /// <summary>The appidExclude/largeBlob extension-input carve-outs are null unless the caller opts in.</summary>
    [TestMethod]
    public async Task ExtensionCarveOutsAreNullByDefault()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsNull(options.AppIdExclude);
        Assert.IsNull(options.LargeBlob);
    }


    /// <summary>The appidExclude/largeBlob extension-input carve-outs are populated when the caller opts in.</summary>
    [TestMethod]
    public async Task ExtensionCarveOutsAreHonoredWhenSupplied()
    {
        Fido2RegistrationOptionsBuilder builder = new();
        PublicKeyCredentialCreationOptions options = await builder.BuildAsync(
            rpId: "example.com", rpName: null, userId: UserId, userName: "alexm", userDisplayName: null, pool: BaseMemoryPool.Shared,
            appIdExclude: "https://example.com/appid.json",
            largeBlobSupport: LargeBlobSupport.Preferred, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual("https://example.com/appid.json", options.AppIdExclude);
        Assert.AreEqual(LargeBlobSupport.Preferred, options.LargeBlob!.Support);
    }


    /// <summary>Creates a minimal, valid <see cref="Fido2CredentialRecord"/> for descriptor-projection tests.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId created inline transfers to the Fido2CredentialRecord constructed on the same statement; every call site disposes the returned record via a 'using' declaration.")]
    private static Fido2CredentialRecord CreateCredentialRecord(byte[] idBytes, string[] transports)
    {
        return new Fido2CredentialRecord(
            WellKnownPublicKeyCredentialTypes.PublicKey,
            CredentialId.Create(idBytes, BaseMemoryPool.Shared),
            new CoseKey(CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: new byte[32], y: new byte[32], encodedYCompressionSign: false),
            SignCount: 0,
            UvInitialized: false,
            Transports: transports,
            BackupEligible: false,
            BackupState: false);
    }


    /// <summary>Projects each parameter's <c>alg</c> for a simple membership assertion.</summary>
    private static System.Collections.Generic.IEnumerable<int> Map(System.Collections.Generic.IReadOnlyList<PublicKeyCredentialParameters> parameters)
    {
        foreach(PublicKeyCredentialParameters parameter in parameters)
        {
            yield return parameter.Alg;
        }
    }
}
