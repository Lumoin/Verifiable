using Lumoin.Veritas.Cbor;
using System.Buffers;
using Verifiable.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="HmacSecretExtensionProcessor"/>: the <c>hmac-secret</c>/<c>hmac-secret-mc</c>
/// extensions' RP-side authenticator-output claim processing (CTAP 2.3 §12.7-12.8).
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension">
/// CTAP 2.3, section 12.7: HMAC Secret Extension (hmac-secret)</see>. Every input is hand-built CBOR,
/// mirroring <see cref="CredProtectExtensionProcessorTests"/>'s own defensive-branch cases: minting
/// real ciphertext through the full PIN/UV auth protocol crypto proves nothing this processor's own
/// length check does not already prove from the decoded byte count alone.
/// </remarks>
[TestClass]
internal sealed class HmacSecretExtensionProcessorTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A registration ceremony's <c>hmac-secret</c> output decoding to CBOR <see langword="true"/>
    /// reports <see cref="Fido2ClaimIds.Fido2RegistrationHmacSecret"/> as
    /// <see cref="ClaimOutcome.Success"/>, with the value recorded in
    /// <see cref="HmacSecretSupportedContext.Supported"/>.
    /// </summary>
    [TestMethod]
    public async Task BooleanTrueReportsSuccessWithSupportedTrue()
    {
        byte[] authenticatorOutputCbor = EncodeCborBoolean(true);
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);
        List<Claim> claims = await HmacSecretExtensionProcessor.ProcessRegistrationOutput(request, TestContext.CancellationToken);

        Claim claim = Assert.ContainsSingle(claims);
        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        Assert.IsTrue(((HmacSecretSupportedContext)claim.Context).Supported);
    }


    /// <summary>
    /// A registration ceremony's <c>hmac-secret</c> output decoding to CBOR <see langword="false"/>
    /// reports <see cref="Fido2ClaimIds.Fido2RegistrationHmacSecret"/> as
    /// <see cref="ClaimOutcome.Success"/> — a failed CredRandom association is a legitimate
    /// authenticator state, not a protocol violation.
    /// </summary>
    [TestMethod]
    public async Task BooleanFalseReportsSuccessWithSupportedFalse()
    {
        byte[] authenticatorOutputCbor = EncodeCborBoolean(false);
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);
        List<Claim> claims = await HmacSecretExtensionProcessor.ProcessRegistrationOutput(request, TestContext.CancellationToken);

        Claim claim = Assert.ContainsSingle(claims);
        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        Assert.IsFalse(((HmacSecretSupportedContext)claim.Context).Supported);
    }


    /// <summary>
    /// A byte string of each length a PIN/UV auth protocol's own <c>encrypt</c> operation produces —
    /// 32/64 (protocol one, one/two salt) and 48/80 (protocol two, one/two salt) — reports
    /// <see cref="Fido2ClaimIds.Fido2AssertionHmacSecret"/> as <see cref="ClaimOutcome.Success"/>,
    /// with the bytes recorded, unmodified, in
    /// <see cref="HmacSecretEncryptedOutputContext.EncryptedOutput"/>.
    /// </summary>
    [TestMethod]
    [DataRow(32, DisplayName = "protocol one, one salt")]
    [DataRow(64, DisplayName = "protocol one, two salt")]
    [DataRow(48, DisplayName = "protocol two, one salt")]
    [DataRow(80, DisplayName = "protocol two, two salt")]
    public async Task AllowedLengthByteStringReportsSuccessWithEncryptedOutput(int length)
    {
        byte[] content = BuildContentBytes(length);
        byte[] authenticatorOutputCbor = EncodeCborByteString(content);

        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);
        List<Claim> claims = await HmacSecretExtensionProcessor.ProcessAssertionOutput(request, TestContext.CancellationToken);

        Claim claim = Assert.ContainsSingle(claims);
        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        Assert.AreSequenceEqual(content, ((HmacSecretEncryptedOutputContext)claim.Context).EncryptedOutput.ToArray());
    }


    /// <summary>
    /// A well-formed byte string of a length no PIN/UV auth protocol's <c>encrypt</c> operation
    /// produces fails <see cref="Fido2ClaimIds.Fido2AssertionHmacSecret"/> with no context — a
    /// defensive check against a non-conformant or adversarial authenticator, not a pass-through of
    /// an untrusted value.
    /// </summary>
    [TestMethod]
    [DataRow(0, DisplayName = "empty")]
    [DataRow(16, DisplayName = "shorter than every allowed shape")]
    [DataRow(40, DisplayName = "between the two one-salt shapes")]
    [DataRow(100, DisplayName = "longer than every allowed shape")]
    public async Task DisallowedLengthByteStringFailsWithNoContext(int length)
    {
        byte[] authenticatorOutputCbor = EncodeCborByteString(BuildContentBytes(length));

        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);
        List<Claim> claims = await HmacSecretExtensionProcessor.ProcessAssertionOutput(request, TestContext.CancellationToken);

        Claim claim = Assert.ContainsSingle(claims);
        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        Assert.AreEqual(ClaimContext.None, claim.Context);
    }


    /// <summary>A <c>hmac-secret</c> output that is not a CBOR boolean at all fails closed via a thrown <see cref="Fido2FormatException"/>.</summary>
    [TestMethod]
    public async Task RegistrationOutputWrongMajorTypeFailsClosed()
    {
        byte[] authenticatorOutputCbor = EncodeCborTextString("not-a-boolean");
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<Fido2FormatException>(() =>
            HmacSecretExtensionProcessor.ProcessRegistrationOutput(request, TestContext.CancellationToken).AsTask());
    }


    /// <summary>A <c>hmac-secret-mc</c> output that is not a CBOR byte string at all fails closed via a thrown <see cref="Fido2FormatException"/>.</summary>
    [TestMethod]
    public async Task AssertionOutputWrongMajorTypeFailsClosed()
    {
        byte[] authenticatorOutputCbor = EncodeCborBoolean(true);
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<Fido2FormatException>(() =>
            HmacSecretExtensionProcessor.ProcessAssertionOutput(request, TestContext.CancellationToken).AsTask());
    }


    /// <summary>Content trailing a well-formed CBOR boolean fails closed via a thrown <see cref="Fido2FormatException"/>.</summary>
    [TestMethod]
    public async Task RegistrationOutputTrailingContentFailsClosed()
    {
        byte[] validBoolean = EncodeCborBoolean(true);
        byte[] authenticatorOutputCbor = [.. validBoolean, 0x00];
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<Fido2FormatException>(() =>
            HmacSecretExtensionProcessor.ProcessRegistrationOutput(request, TestContext.CancellationToken).AsTask());
    }


    /// <summary>Content trailing a well-formed CBOR byte string fails closed via a thrown <see cref="Fido2FormatException"/>.</summary>
    [TestMethod]
    public async Task AssertionOutputTrailingContentFailsClosed()
    {
        byte[] validByteString = EncodeCborByteString(BuildContentBytes(32));
        byte[] authenticatorOutputCbor = [.. validByteString, 0x00];
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<Fido2FormatException>(() =>
            HmacSecretExtensionProcessor.ProcessAssertionOutput(request, TestContext.CancellationToken).AsTask());
    }


    /// <summary>An absent <c>hmac-secret</c> authenticator extension output fails closed via a thrown <see cref="Fido2FormatException"/>.</summary>
    [TestMethod]
    public async Task RegistrationOutputAbsentAuthenticatorOutputFailsClosed()
    {
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor: null, BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<Fido2FormatException>(() =>
            HmacSecretExtensionProcessor.ProcessRegistrationOutput(request, TestContext.CancellationToken).AsTask());
    }


    /// <summary>An absent <c>hmac-secret-mc</c> authenticator extension output fails closed via a thrown <see cref="Fido2FormatException"/>.</summary>
    [TestMethod]
    public async Task AssertionOutputAbsentAuthenticatorOutputFailsClosed()
    {
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc, clientOutputJson: null, authenticatorOutputCbor: null, BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<Fido2FormatException>(() =>
            HmacSecretExtensionProcessor.ProcessAssertionOutput(request, TestContext.CancellationToken).AsTask());
    }


    /// <summary>An already-cancelled token is honored before any decoding, for the boolean decode path.</summary>
    [TestMethod]
    public async Task RegistrationOutputCancellationThrows()
    {
        byte[] authenticatorOutputCbor = EncodeCborBoolean(true);
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() =>
            HmacSecretExtensionProcessor.ProcessRegistrationOutput(request, new CancellationToken(true)).AsTask());
    }


    /// <summary>An already-cancelled token is honored before any decoding, for the byte-string decode path.</summary>
    [TestMethod]
    public async Task AssertionOutputCancellationThrows()
    {
        byte[] authenticatorOutputCbor = EncodeCborByteString(BuildContentBytes(32));
        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() =>
            HmacSecretExtensionProcessor.ProcessAssertionOutput(request, new CancellationToken(true)).AsTask());
    }


    /// <summary>Builds <paramref name="length"/> distinct, deterministic bytes for a byte-string payload.</summary>
    private static byte[] BuildContentBytes(int length)
    {
        var bytes = new byte[length];
        for(int i = 0; i < length; i++)
        {
            bytes[i] = (byte)i;
        }

        return bytes;
    }


    /// <summary>Encodes <paramref name="value"/> as a single CTAP2 canonical CBOR boolean.</summary>
    private static byte[] EncodeCborBoolean(bool value)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Ctap2Canonical);

        writer.WriteBoolean(value);

        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Encodes <paramref name="content"/> as a single CTAP2 canonical CBOR byte string.</summary>
    private static byte[] EncodeCborByteString(byte[] content)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Ctap2Canonical);

        writer.WriteByteString(content);

        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Encodes <paramref name="value"/> as a single CTAP2 canonical CBOR text string.</summary>
    private static byte[] EncodeCborTextString(string value)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Ctap2Canonical);

        writer.WriteTextString(value);

        return writerBuffer.WrittenSpan.ToArray();
    }
}
