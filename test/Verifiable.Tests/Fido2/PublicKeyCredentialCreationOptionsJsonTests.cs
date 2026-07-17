using System;
using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="PublicKeyCredentialCreationOptionsJsonWriter"/>/<see cref="PublicKeyCredentialCreationOptionsJsonReader"/>:
/// round-tripping every member (including both named extension-input carve-outs) and the strict
/// reader's rejections, since this is the CR's own named wire shape rather than a private format.
/// </summary>
[TestClass]
internal sealed class PublicKeyCredentialCreationOptionsJsonTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Every member of a fully populated document round-trips, including both extension-input carve-outs.</summary>
    [TestMethod]
    public void FullyPopulatedOptionsRoundTripEveryMember()
    {
        using UserHandle userId = UserHandle.Create([1, 2, 3, 4], BaseMemoryPool.Shared);
        using CredentialId excludeId = CredentialId.Create([9, 8, 7], BaseMemoryPool.Shared);

        PublicKeyCredentialCreationOptions original = new()
        {
            Rp = new PublicKeyCredentialRpEntity { Id = "example.com", Name = "ACME Corporation" },
            User = new PublicKeyCredentialUserEntity { Id = userId, Name = "alexm", DisplayName = "Alex Müller" },
            Challenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
            PubKeyCredParams =
            [
                new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.EdDsa },
                new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }
            ],
            Timeout = 60000,
            ExcludeCredentials = [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = excludeId, Transports = ["usb", "nfc"] }],
            AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = WellKnownAuthenticatorAttachments.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Required,
                RequireResidentKey = true,
                UserVerification = UserVerificationRequirement.Required
            },
            Hints = [PublicKeyCredentialHint.SecurityKey, PublicKeyCredentialHint.Hybrid],
            Attestation = AttestationConveyancePreference.Direct,
            AttestationFormats = [WellKnownWebAuthnAttestationFormats.Packed],
            AppIdExclude = "https://example.com/appid.json",
            LargeBlob = new Fido2LargeBlobRegistrationExtensionInput { Support = LargeBlobSupport.Preferred },
            MinPinLength = true,
            CredProtect = new Fido2CredProtectRegistrationExtensionInput
            {
                CredentialProtectionPolicy = WellKnownCredProtectPolicies.UserVerificationRequired,
                EnforceCredentialProtectionPolicy = true
            }
        };

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialCreationOptionsJsonWriter.Write(original, buffer);

        PublicKeyCredentialCreationOptions roundTripped = PublicKeyCredentialCreationOptionsJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        Assert.AreEqual(original.Rp!.Id, roundTripped.Rp!.Id);
        Assert.AreEqual(original.Rp.Name, roundTripped.Rp.Name);
        Assert.IsTrue(original.User!.Id.AsReadOnlySpan().SequenceEqual(roundTripped.User!.Id.AsReadOnlySpan()));
        Assert.AreEqual(original.User.Name, roundTripped.User.Name);
        Assert.AreEqual(original.User.DisplayName, roundTripped.User.DisplayName);
        Assert.AreEqual(original.Challenge, roundTripped.Challenge);
        Assert.HasCount(2, roundTripped.PubKeyCredParams!);
        Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, roundTripped.PubKeyCredParams![0].Alg);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, roundTripped.PubKeyCredParams[1].Alg);
        Assert.AreEqual(original.Timeout, roundTripped.Timeout);
        PublicKeyCredentialDescriptor descriptor = Assert.ContainsSingle(roundTripped.ExcludeCredentials!);
        Assert.IsTrue(excludeId.AsReadOnlySpan().SequenceEqual(descriptor.Id.AsReadOnlySpan()));
        Assert.HasCount(2, descriptor.Transports!);
        Assert.AreEqual(original.AuthenticatorSelection!.AuthenticatorAttachment, roundTripped.AuthenticatorSelection!.AuthenticatorAttachment);
        Assert.AreEqual(original.AuthenticatorSelection.ResidentKey, roundTripped.AuthenticatorSelection.ResidentKey);
        Assert.AreEqual(original.AuthenticatorSelection.RequireResidentKey, roundTripped.AuthenticatorSelection.RequireResidentKey);
        Assert.AreEqual(original.AuthenticatorSelection.UserVerification, roundTripped.AuthenticatorSelection.UserVerification);
        Assert.HasCount(2, roundTripped.Hints!);
        Assert.Contains(PublicKeyCredentialHint.SecurityKey, roundTripped.Hints!);
        Assert.Contains(PublicKeyCredentialHint.Hybrid, roundTripped.Hints!);
        Assert.AreEqual(original.Attestation, roundTripped.Attestation);
        Assert.Contains(WellKnownWebAuthnAttestationFormats.Packed, roundTripped.AttestationFormats!);
        Assert.AreEqual(original.AppIdExclude, roundTripped.AppIdExclude);
        Assert.AreEqual(original.LargeBlob!.Support, roundTripped.LargeBlob!.Support);
        Assert.AreEqual(original.MinPinLength, roundTripped.MinPinLength);
        Assert.AreEqual(original.CredProtect!.CredentialProtectionPolicy, roundTripped.CredProtect!.CredentialProtectionPolicy);
        Assert.AreEqual(original.CredProtect.EnforceCredentialProtectionPolicy, roundTripped.CredProtect.EnforceCredentialProtectionPolicy);
    }


    /// <summary>A minimal document (only the CR-required members) omits every optional member from the wire.</summary>
    [TestMethod]
    public void MinimalOptionsOmitEveryOptionalMember()
    {
        using UserHandle userId = UserHandle.Create([1], BaseMemoryPool.Shared);

        PublicKeyCredentialCreationOptions original = new()
        {
            Rp = new PublicKeyCredentialRpEntity { Name = "example.com" },
            User = new PublicKeyCredentialUserEntity { Id = userId, Name = "alexm", DisplayName = string.Empty },
            Challenge = "AQIDBA",
            PubKeyCredParams = [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }]
        };

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialCreationOptionsJsonWriter.Write(original, buffer);
        string json = Encoding.UTF8.GetString(buffer.WrittenSpan);

        Assert.DoesNotContain("timeout", json, StringComparison.Ordinal);
        Assert.DoesNotContain("excludeCredentials", json, StringComparison.Ordinal);
        Assert.DoesNotContain("authenticatorSelection", json, StringComparison.Ordinal);
        Assert.DoesNotContain("hints", json, StringComparison.Ordinal);
        Assert.DoesNotContain("attestation", json, StringComparison.Ordinal);
        Assert.DoesNotContain("extensions", json, StringComparison.Ordinal);

        PublicKeyCredentialCreationOptions roundTripped = PublicKeyCredentialCreationOptionsJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);
        Assert.IsNull(roundTripped.Rp!.Id);
        Assert.IsNull(roundTripped.Timeout);
        Assert.IsNull(roundTripped.AuthenticatorSelection);
        Assert.IsNull(roundTripped.Attestation);
        Assert.IsNull(roundTripped.AppIdExclude);
        Assert.IsNull(roundTripped.LargeBlob);
        Assert.IsNull(roundTripped.MinPinLength);
        Assert.IsNull(roundTripped.CredProtect);
    }


    /// <summary>An unrecognised top-level member is rejected rather than silently skipped.</summary>
    [TestMethod]
    public void UnknownTopLevelMemberIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"challenge\":\"AQIDBA\"", "\"challenge\":\"AQIDBA\",\"unexpected\":1", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialCreationOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>An unrecognised extension identifier under <c>extensions</c> is rejected — this writer emits only the two named carve-outs.</summary>
    [TestMethod]
    public void UnknownExtensionIdentifierIsRejected()
    {
        string json = MinimalValidDocument().Replace(
            "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}]",
            "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}],\"extensions\":{\"credProps\":true}",
            StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialCreationOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>An unregistered <c>credentialProtectionPolicy</c> wire value is rejected.</summary>
    [TestMethod]
    public void UnregisteredCredentialProtectionPolicyValueIsRejected()
    {
        string json = MinimalValidDocument().Replace(
            "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}]",
            "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}],\"extensions\":{\"credentialProtectionPolicy\":\"unknownPolicy\"}",
            StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialCreationOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>
    /// An <c>enforceCredentialProtectionPolicy</c> member with no accompanying <c>credentialProtectionPolicy</c>
    /// member is rejected — the enforce flag has no home without the policy it enforces.
    /// </summary>
    [TestMethod]
    public void EnforceCredentialProtectionPolicyWithoutPolicyIsRejected()
    {
        string json = MinimalValidDocument().Replace(
            "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}]",
            "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}],\"extensions\":{\"enforceCredentialProtectionPolicy\":true}",
            StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialCreationOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>
    /// <c>credentialProtectionPolicy</c>/<c>enforceCredentialProtectionPolicy</c> are FLAT top-level
    /// <c>extensions</c> members, not nested under a <c>"credProtect"</c> key — the exact WebAuthn IDL
    /// shape (CTAP 2.3 §12.1's own client-input IDL), distinct from <c>largeBlob</c>'s nested shape.
    /// </summary>
    [TestMethod]
    public void CredProtectExtensionInputRoundTripsAsFlatMembersNotNested()
    {
        PublicKeyCredentialCreationOptions original = new()
        {
            Rp = new PublicKeyCredentialRpEntity { Name = "example.com" },
            User = new PublicKeyCredentialUserEntity { Id = UserHandle.Create([1], BaseMemoryPool.Shared), Name = "alexm", DisplayName = string.Empty },
            Challenge = "AQIDBA",
            PubKeyCredParams = [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }],
            CredProtect = new Fido2CredProtectRegistrationExtensionInput { CredentialProtectionPolicy = WellKnownCredProtectPolicies.UserVerificationOptional }
        };

        ArrayBufferWriter<byte> buffer = new();
        PublicKeyCredentialCreationOptionsJsonWriter.Write(original, buffer);
        string json = Encoding.UTF8.GetString(buffer.WrittenSpan);

        Assert.Contains("\"credentialProtectionPolicy\":\"userVerificationOptional\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"credProtect\"", json, StringComparison.Ordinal);

        PublicKeyCredentialCreationOptions roundTripped = PublicKeyCredentialCreationOptionsJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);
        Assert.AreEqual(WellKnownCredProtectPolicies.UserVerificationOptional, roundTripped.CredProtect!.CredentialProtectionPolicy);
        Assert.IsFalse(roundTripped.CredProtect.EnforceCredentialProtectionPolicy, "enforceCredentialProtectionPolicy's WebAuthn IDL default is false when omitted from the wire.");
    }


    /// <summary>A repeated top-level member name is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelMemberIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"challenge\":\"AQIDBA\",", "\"challenge\":\"AQIDBA\",\"challenge\":\"AQIDBA\",", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialCreationOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A malformed base64url value for <c>user.id</c> is rejected.</summary>
    [TestMethod]
    public void MalformedBase64UrlUserIdIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"id\":\"AQ\"", "\"id\":\"not base64url!!\"", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialCreationOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A document missing the required <c>rp</c> member is rejected.</summary>
    [TestMethod]
    public void MissingRequiredRpMemberIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"rp\":{\"name\":\"example.com\"},", "", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialCreationOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>An unregistered <c>attestation</c> wire value is rejected.</summary>
    [TestMethod]
    public void UnregisteredAttestationValueIsRejected()
    {
        string json = MinimalValidDocument().Replace(
            "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}]",
            "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}],\"attestation\":\"unknown-preference\"",
            StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => PublicKeyCredentialCreationOptionsJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A minimal, structurally valid document — the base every negative test derives its fixture from
    /// via a single targeted string replacement.
    /// </summary>
    private static string MinimalValidDocument() =>
        """{"rp":{"name":"example.com"},"user":{"id":"AQ","name":"alexm","displayName":""},"challenge":"AQIDBA","pubKeyCredParams":[{"type":"public-key","alg":-7}]}""";
}
