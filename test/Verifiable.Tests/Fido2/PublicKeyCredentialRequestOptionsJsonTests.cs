using System;
using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="PublicKeyCredentialRequestOptionsJsonWriter"/>/<see cref="PublicKeyCredentialRequestOptionsJsonReader"/>:
/// round-tripping every member (including both named extension-input carve-outs) and the strict
/// reader's rejections.
/// </summary>
[TestClass]
internal sealed class PublicKeyCredentialRequestOptionsJsonTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Every member of a fully populated document round-trips, including the largeBlob read carve-out.</summary>
    [TestMethod]
    public void FullyPopulatedOptionsWithReadCarveOutRoundTripEveryMember()
    {
        using CredentialId allowedId = CredentialId.Create([4, 5, 6], BaseMemoryPool.Shared);

        PublicKeyCredentialRequestOptions original = new()
        {
            Challenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
            Timeout = 30000,
            RpId = "example.com",
            AllowCredentials = [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = allowedId, Transports = ["internal"] }],
            UserVerification = UserVerificationRequirement.Required,
            Hints = [PublicKeyCredentialHint.Hybrid],
            AppId = "https://example.com/appid.json",
            LargeBlob = Fido2LargeBlobAssertionExtensionInput.ForRead()
        };

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialRequestOptionsJsonWriter.Write(original, buffer);

        PublicKeyCredentialRequestOptions roundTripped = PublicKeyCredentialRequestOptionsJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        Assert.AreEqual(original.Challenge, roundTripped.Challenge);
        Assert.AreEqual(original.Timeout, roundTripped.Timeout);
        Assert.AreEqual(original.RpId, roundTripped.RpId);
        PublicKeyCredentialDescriptor descriptor = Assert.ContainsSingle(roundTripped.AllowCredentials!);
        Assert.IsTrue(allowedId.AsReadOnlySpan().SequenceEqual(descriptor.Id.AsReadOnlySpan()));
        Assert.Contains("internal", descriptor.Transports!);
        Assert.AreEqual(original.UserVerification, roundTripped.UserVerification);
        Assert.Contains(PublicKeyCredentialHint.Hybrid, roundTripped.Hints!);
        Assert.AreEqual(original.AppId, roundTripped.AppId);
        Assert.IsTrue(roundTripped.LargeBlob!.Read);
        Assert.IsNull(roundTripped.LargeBlob.Write);
    }


    /// <summary>The largeBlob write carve-out round-trips its payload bytes exactly.</summary>
    [TestMethod]
    public void LargeBlobWriteCarveOutRoundTripsPayload()
    {
        byte[] payload = [10, 20, 30, 40];
        PublicKeyCredentialRequestOptions original = new()
        {
            Challenge = "AQIDBA",
            LargeBlob = Fido2LargeBlobAssertionExtensionInput.ForWrite(new TaggedMemory<byte>(payload, Fido2BufferTags.LargeBlob))
        };

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialRequestOptionsJsonWriter.Write(original, buffer);

        PublicKeyCredentialRequestOptions roundTripped = PublicKeyCredentialRequestOptionsJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        Assert.IsNull(roundTripped.LargeBlob!.Read);
        Assert.IsTrue(payload.AsSpan().SequenceEqual(roundTripped.LargeBlob.Write!.Value.Span));
    }


    /// <summary>A minimal document (only the CR-required <c>challenge</c>) omits every optional member from the wire.</summary>
    [TestMethod]
    public void MinimalOptionsOmitEveryOptionalMember()
    {
        PublicKeyCredentialRequestOptions original = new() { Challenge = "AQIDBA" };

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialRequestOptionsJsonWriter.Write(original, buffer);
        string json = Encoding.UTF8.GetString(buffer.WrittenSpan);

        Assert.DoesNotContain("timeout", json, StringComparison.Ordinal);
        Assert.DoesNotContain("rpId", json, StringComparison.Ordinal);
        Assert.DoesNotContain("allowCredentials", json, StringComparison.Ordinal);
        Assert.DoesNotContain("userVerification", json, StringComparison.Ordinal);
        Assert.DoesNotContain("hints", json, StringComparison.Ordinal);
        Assert.DoesNotContain("extensions", json, StringComparison.Ordinal);

        PublicKeyCredentialRequestOptions roundTripped = PublicKeyCredentialRequestOptionsJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);
        Assert.IsNull(roundTripped.RpId);
        Assert.IsNull(roundTripped.UserVerification);
        Assert.IsNull(roundTripped.AppId);
        Assert.IsNull(roundTripped.LargeBlob);
    }


    /// <summary>An unrecognised top-level member is rejected rather than silently skipped.</summary>
    [TestMethod]
    public void UnknownTopLevelMemberIsRejected()
    {
        string json = """{"challenge":"AQIDBA","unexpected":1}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A repeated top-level member name is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelMemberIsRejected()
    {
        string json = """{"challenge":"AQIDBA","challenge":"AQIDBA"}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A document missing the required <c>challenge</c> member is rejected.</summary>
    [TestMethod]
    public void MissingRequiredChallengeMemberIsRejected()
    {
        string json = """{"rpId":"example.com"}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A <c>largeBlob</c> extension carrying both <c>read</c> and <c>write</c> is rejected — mutually exclusive per the CR's own client processing step.</summary>
    [TestMethod]
    public void LargeBlobWithBothReadAndWriteIsRejected()
    {
        string json = """{"challenge":"AQIDBA","extensions":{"largeBlob":{"read":true,"write":"AQIDBA"}}}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A malformed base64url value for a descriptor <c>id</c> is rejected.</summary>
    [TestMethod]
    public void MalformedBase64UrlDescriptorIdIsRejected()
    {
        string json = """{"challenge":"AQIDBA","allowCredentials":[{"type":"public-key","id":"not base64url!!"}]}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>
    /// An unregistered <c>userVerification</c> wire value is rejected as <see cref="Fido2FormatException"/>,
    /// not the raw <see cref="ArgumentOutOfRangeException"/> <see cref="WellKnownUserVerificationRequirements.FromWireValue"/>
    /// throws internally — the reader's catch clause must translate it.
    /// </summary>
    [TestMethod]
    public void UnregisteredUserVerificationValueIsRejected()
    {
        string json = """{"challenge":"AQIDBA","userVerification":"unknown-requirement"}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }
}
