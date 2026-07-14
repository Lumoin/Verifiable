using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2AssertionOptionsBuilder"/>: every WP-Options SHOULD/MAY row the
/// assertion side owns gets a default-behavior test and an override test, plus the descriptor
/// projection and challenge freshness this builder is responsible for.
/// </summary>
[TestClass]
internal sealed class Fido2AssertionOptionsBuilderTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The relying party identifier is a direct pass-through.</summary>
    [TestMethod]
    public async Task RpIdIsPassedThrough()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual("example.com", options.RpId);
    }


    /// <summary>§13.4.3: the default challenge is generated through the registered entropy provider.</summary>
    [TestMethod]
    public async Task ChallengeDefaultsToGeneratedValue()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsNotNull(options.Challenge);
        Assert.IsNotEmpty(options.Challenge);
    }


    /// <summary>Two builds with no explicit challenge produce distinct challenges — no RNG in the test itself, only the registered entropy provider.</summary>
    [TestMethod]
    public async Task ChallengeIsFreshAcrossBuilds()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions first = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);
        PublicKeyCredentialRequestOptions second = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.AreNotEqual(first.Challenge, second.Challenge);
    }


    /// <summary>An explicit challenge overrides the default entropy-provider-generated one.</summary>
    [TestMethod]
    public async Task ChallengeOverrideIsHonored()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, challenge: "fixed-challenge-value", cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual("fixed-challenge-value", options.Challenge);
    }


    /// <summary>Rows 3902/3906/4270/4277/4285: allowCredentials projects a real Fido2CredentialRecord's type/id/transports verbatim.</summary>
    [TestMethod]
    public async Task AllowCredentialsProjectsAllowedCredentialRecord()
    {
        using Fido2CredentialRecord record = CreateCredentialRecord([4, 5, 6], ["internal", "hybrid"]);

        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, allowedCredentials: [record], cancellationToken: TestContext.CancellationToken);

        PublicKeyCredentialDescriptor descriptor = Assert.ContainsSingle(options.AllowCredentials!);
        Assert.AreEqual(record.Type, descriptor.Type);
        Assert.IsTrue(record.Id.AsReadOnlySpan().SequenceEqual(descriptor.Id.AsReadOnlySpan()));
        Assert.HasCount(2, descriptor.Transports!);
    }


    /// <summary>Row 3914: allowCredentials is an empty list (not null) for the discoverable-credential path.</summary>
    [TestMethod]
    public async Task AllowCredentialsIsEmptyForDiscoverableCredentialPath()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsNotNull(options.AllowCredentials);
        Assert.IsEmpty(options.AllowCredentials!);
    }


    /// <summary>
    /// Row 7205: "<c>allowCredentials</c> MAY contain a mixture of both WebAuthn credential IDs and
    /// U2F key handles" — the appid extension's entire purpose is letting an RP that migrated from
    /// U2F keep offering its legacy-registered credentials alongside newly registered WebAuthn-native
    /// ones in the same ceremony. <see cref="Fido2OptionsDescriptors.ProjectDescriptors"/> is a
    /// mechanical <see cref="Fido2CredentialRecord"/> → <see cref="PublicKeyCredentialDescriptor"/>
    /// mapper with no branch on credential origin, so a legacy-shaped record (short opaque id,
    /// transports typical of a U2F token) and a WebAuthn-native one both survive into
    /// <c>allowCredentials</c> unchanged and in the order supplied.
    /// </summary>
    [TestMethod]
    public async Task AllowCredentialsProjectsMixedWebAuthnAndLegacyU2fKeyHandlesUnchangedInOrder()
    {
        using Fido2CredentialRecord webAuthnNative = CreateCredentialRecord(
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            ["internal", "hybrid"]);
        using Fido2CredentialRecord legacyU2fKeyHandle = CreateCredentialRecord(
            [0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8],
            ["usb", "nfc"]);

        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(
            rpId: "example.com",
            pool: BaseMemoryPool.Shared,
            allowedCredentials: [webAuthnNative, legacyU2fKeyHandle],
            appId: "https://example.com/appid.json",
            cancellationToken: TestContext.CancellationToken);

        Assert.HasCount(2, options.AllowCredentials!);

        PublicKeyCredentialDescriptor nativeDescriptor = options.AllowCredentials![0];
        Assert.AreEqual(webAuthnNative.Type, nativeDescriptor.Type);
        Assert.IsTrue(webAuthnNative.Id.AsReadOnlySpan().SequenceEqual(nativeDescriptor.Id.AsReadOnlySpan()));
        Assert.HasCount(2, nativeDescriptor.Transports!);

        PublicKeyCredentialDescriptor legacyDescriptor = options.AllowCredentials![1];
        Assert.AreEqual(legacyU2fKeyHandle.Type, legacyDescriptor.Type);
        Assert.IsTrue(legacyU2fKeyHandle.Id.AsReadOnlySpan().SequenceEqual(legacyDescriptor.Id.AsReadOnlySpan()));
        Assert.HasCount(2, legacyDescriptor.Transports!);
    }


    /// <summary>
    /// Adversarial counterpart to <see cref="AllowCredentialsProjectsMixedWebAuthnAndLegacyU2fKeyHandlesUnchangedInOrder"/>:
    /// a legacy key handle at the row-1653 credential-id ceiling (1023 bytes) — the shape furthest
    /// from a typical short WebAuthn-native identifier — is mixed alongside a small native one. If
    /// the projection carried any hidden length- or shape-based discrimination (for example a filter
    /// that treats an oversized or unusually-shaped identifier as suspect and drops or truncates it),
    /// this would surface it; instead the oversized entry survives byte-for-byte, disproving that
    /// hypothesis and confirming the mixture in row 7205 is never rejected regardless of how far a
    /// legacy identifier's shape diverges from a native one.
    /// </summary>
    [TestMethod]
    public async Task AllowCredentialsDoesNotDiscriminateAgainstMaximalLengthLegacyKeyHandleInTheMixture()
    {
        byte[] maximalLegacyKeyHandle = new byte[1023];
        for(int i = 0; i < maximalLegacyKeyHandle.Length; ++i)
        {
            maximalLegacyKeyHandle[i] = (byte)(i % 256);
        }

        using Fido2CredentialRecord webAuthnNative = CreateCredentialRecord([0xAA, 0xBB, 0xCC, 0xDD], ["internal"]);
        using Fido2CredentialRecord maximalLegacyRecord = CreateCredentialRecord(maximalLegacyKeyHandle, ["usb"]);

        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(
            rpId: "example.com",
            pool: BaseMemoryPool.Shared,
            allowedCredentials: [webAuthnNative, maximalLegacyRecord],
            appId: "https://example.com/appid.json",
            cancellationToken: TestContext.CancellationToken);

        Assert.HasCount(2, options.AllowCredentials!);

        PublicKeyCredentialDescriptor maximalDescriptor = options.AllowCredentials![1];
        Assert.AreEqual(1023, maximalDescriptor.Id.Length);
        Assert.IsTrue(maximalLegacyRecord.Id.AsReadOnlySpan().SequenceEqual(maximalDescriptor.Id.AsReadOnlySpan()));
    }


    /// <summary>CR's own IDL default: userVerification defaults to Preferred.</summary>
    [TestMethod]
    public async Task UserVerificationDefaultsToPreferred()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(UserVerificationRequirement.Preferred, options.UserVerification);
    }


    /// <summary>An explicit userVerification overrides the Preferred default.</summary>
    [TestMethod]
    public async Task UserVerificationOverrideIsHonored()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, userVerification: UserVerificationRequirement.Required, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(UserVerificationRequirement.Required, options.UserVerification);
    }


    /// <summary>hints defaults to an empty list.</summary>
    [TestMethod]
    public async Task HintsDefaultsToEmptyList()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsEmpty(options.Hints!);
    }


    /// <summary>An explicit hints list overrides the empty default; request options carry no authenticatorAttachment for row 4470's mapping to touch.</summary>
    [TestMethod]
    public async Task HintsOverrideIsHonored()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, hints: [PublicKeyCredentialHint.Hybrid], cancellationToken: TestContext.CancellationToken);

        Assert.Contains(PublicKeyCredentialHint.Hybrid, options.Hints!);
    }


    /// <summary>No spec-mandated timeout default exists — the member stays unset unless the caller opts in.</summary>
    [TestMethod]
    public async Task TimeoutIsUnsetByDefault()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsNull(options.Timeout);
    }


    /// <summary>An explicit timeout is honored as a pass-through value.</summary>
    [TestMethod]
    public async Task TimeoutOverrideIsHonored()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, timeout: 30000, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual((uint)30000, options.Timeout);
    }


    /// <summary>The appid/largeBlob extension-input carve-outs are null unless the caller opts in.</summary>
    [TestMethod]
    public async Task ExtensionCarveOutsAreNullByDefault()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsNull(options.AppId);
        Assert.IsNull(options.LargeBlob);
    }


    /// <summary>The appid carve-out is populated when the caller opts in.</summary>
    [TestMethod]
    public async Task AppIdCarveOutIsHonoredWhenSupplied()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(rpId: "example.com", pool: BaseMemoryPool.Shared, appId: "https://example.com/appid.json", cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual("https://example.com/appid.json", options.AppId);
    }


    /// <summary>The largeBlob read carve-out sets Read=true and leaves Write absent.</summary>
    [TestMethod]
    public async Task LargeBlobReadCarveOutSetsReadOnly()
    {
        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(
            rpId: "example.com", pool: BaseMemoryPool.Shared, largeBlob: Fido2LargeBlobAssertionExtensionInput.ForRead(),
            cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(options.LargeBlob!.Read);
        Assert.IsNull(options.LargeBlob.Write);
    }


    /// <summary>The largeBlob write carve-out sets Write and leaves Read absent — mutually exclusive by construction.</summary>
    [TestMethod]
    public async Task LargeBlobWriteCarveOutSetsWriteOnly()
    {
        TaggedMemory<byte> payload = new(new byte[] { 1, 2, 3 }, Fido2BufferTags.LargeBlob);

        Fido2AssertionOptionsBuilder builder = new();
        PublicKeyCredentialRequestOptions options = await builder.BuildAsync(
            rpId: "example.com", pool: BaseMemoryPool.Shared, largeBlob: Fido2LargeBlobAssertionExtensionInput.ForWrite(payload),
            cancellationToken: TestContext.CancellationToken);

        Assert.IsNull(options.LargeBlob!.Read);
        Assert.IsTrue(payload.Span.SequenceEqual(options.LargeBlob.Write!.Value.Span));
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
}
