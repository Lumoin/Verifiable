using System.Buffers;
using System.Text;
using Verifiable.Fido2;
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
            LargeBlob = Fido2LargeBlobAssertionExtensionInput.ForRead(),
            Prf = new Fido2PrfAssertionExtensionInput
            {
                Eval = new Fido2PrfValues { First = new TaggedMemory<byte>(new byte[] { 1, 2, 3 }, Fido2BufferTags.PrfValue) },
                EvalByCredential = new Dictionary<CredentialId, Fido2PrfValues>
                {
                    [allowedId] = new Fido2PrfValues { First = new TaggedMemory<byte>(new byte[] { 4, 5, 6 }, Fido2BufferTags.PrfValue) }
                }
            }
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
        Assert.IsTrue(original.Prf!.Eval!.First.Span.SequenceEqual(roundTripped.Prf!.Eval!.First.Span));
        KeyValuePair<CredentialId, Fido2PrfValues> roundTrippedEntry = Assert.ContainsSingle(roundTripped.Prf.EvalByCredential!);
        Assert.IsTrue(allowedId.AsReadOnlySpan().SequenceEqual(roundTrippedEntry.Key.AsReadOnlySpan()));
        Assert.IsTrue(original.Prf.EvalByCredential![allowedId].First.Span.SequenceEqual(roundTrippedEntry.Value.First.Span));
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
        Assert.IsNull(roundTripped.Prf);
    }


    /// <summary>The prf extension's two-salt eval input round-trips both values.</summary>
    [TestMethod]
    public void PrfEvalWithTwoSaltsRoundTripsBothValues()
    {
        PublicKeyCredentialRequestOptions original = new()
        {
            Challenge = "AQIDBA",
            Prf = new Fido2PrfAssertionExtensionInput
            {
                Eval = new Fido2PrfValues
                {
                    First = new TaggedMemory<byte>(new byte[] { 1, 2, 3 }, Fido2BufferTags.PrfValue),
                    Second = new TaggedMemory<byte>(new byte[] { 4, 5, 6 }, Fido2BufferTags.PrfValue)
                }
            }
        };

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialRequestOptionsJsonWriter.Write(original, buffer);

        PublicKeyCredentialRequestOptions roundTripped = PublicKeyCredentialRequestOptionsJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        Assert.IsTrue(original.Prf.Eval!.First.Span.SequenceEqual(roundTripped.Prf!.Eval!.First.Span));
        Assert.IsTrue(original.Prf.Eval.Second!.Value.Span.SequenceEqual(roundTripped.Prf.Eval.Second!.Value.Span));
    }


    /// <summary><c>evalByCredential</c> with two credentials round-trips both entries, keyed correctly.</summary>
    [TestMethod]
    public void PrfEvalByCredentialWithTwoCredentialsRoundTripsBothEntries()
    {
        using CredentialId firstId = CredentialId.Create([1, 1, 1], BaseMemoryPool.Shared);
        using CredentialId secondId = CredentialId.Create([2, 2, 2], BaseMemoryPool.Shared);

        PublicKeyCredentialRequestOptions original = new()
        {
            Challenge = "AQIDBA",
            Prf = new Fido2PrfAssertionExtensionInput
            {
                EvalByCredential = new Dictionary<CredentialId, Fido2PrfValues>
                {
                    [firstId] = new Fido2PrfValues { First = new TaggedMemory<byte>(new byte[] { 0xA1 }, Fido2BufferTags.PrfValue) },
                    [secondId] = new Fido2PrfValues { First = new TaggedMemory<byte>(new byte[] { 0xA2 }, Fido2BufferTags.PrfValue) }
                }
            }
        };

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialRequestOptionsJsonWriter.Write(original, buffer);

        PublicKeyCredentialRequestOptions roundTripped = PublicKeyCredentialRequestOptionsJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        IReadOnlyDictionary<CredentialId, Fido2PrfValues> roundTrippedEvalByCredential = roundTripped.Prf!.EvalByCredential!;
        Assert.HasCount(2, roundTrippedEvalByCredential);
        Assert.IsTrue(original.Prf.EvalByCredential![firstId].First.Span.SequenceEqual(roundTrippedEvalByCredential[firstId].First.Span));
        Assert.IsTrue(original.Prf.EvalByCredential[secondId].First.Span.SequenceEqual(roundTrippedEvalByCredential[secondId].First.Span));
    }


    /// <summary>An <c>evalByCredential</c> key that is not valid base64url is rejected — a wire-format concern for this reader.</summary>
    [TestMethod]
    public void PrfEvalByCredentialKeyNotValidBase64UrlIsRejected()
    {
        string json = """{"challenge":"AQIDBA","extensions":{"prf":{"evalByCredential":{"not base64url!!":{"first":"AQIDBA"}}}}}""";

        _ = Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A repeated <c>evalByCredential</c> key is rejected.</summary>
    [TestMethod]
    public void PrfEvalByCredentialRepeatedKeyIsRejected()
    {
        string json = """{"challenge":"AQIDBA","extensions":{"prf":{"evalByCredential":{"AQID":{"first":"AQIDBA"},"AQID":{"first":"AQIDBA"}}}}}""";

        _ = Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>An unrecognised top-level member is rejected rather than silently skipped.</summary>
    [TestMethod]
    public void UnknownTopLevelMemberIsRejected()
    {
        string json = """{"challenge":"AQIDBA","unexpected":1}""";

        _ = Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A repeated top-level member name is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelMemberIsRejected()
    {
        string json = """{"challenge":"AQIDBA","challenge":"AQIDBA"}""";

        _ = Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A document missing the required <c>challenge</c> member is rejected.</summary>
    [TestMethod]
    public void MissingRequiredChallengeMemberIsRejected()
    {
        string json = """{"rpId":"example.com"}""";

        _ = Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A <c>largeBlob</c> extension carrying both <c>read</c> and <c>write</c> is rejected — mutually exclusive per the CR's own client processing step.</summary>
    [TestMethod]
    public void LargeBlobWithBothReadAndWriteIsRejected()
    {
        string json = """{"challenge":"AQIDBA","extensions":{"largeBlob":{"read":true,"write":"AQIDBA"}}}""";

        _ = Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A malformed base64url value for a descriptor <c>id</c> is rejected.</summary>
    [TestMethod]
    public void MalformedBase64UrlDescriptorIdIsRejected()
    {
        string json = """{"challenge":"AQIDBA","allowCredentials":[{"type":"public-key","id":"not base64url!!"}]}""";

        _ = Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
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

        _ = Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialRequestOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }
}
