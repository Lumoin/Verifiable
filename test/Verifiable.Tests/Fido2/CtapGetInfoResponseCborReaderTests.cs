using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapGetInfoResponseCborReader"/>: round-tripping against the paired writer,
/// the two Required-member negatives, and the section 8 forward-compatibility rule that unknown
/// member keys and option IDs are ignored rather than rejected.
/// </summary>
[TestClass]
internal sealed class CtapGetInfoResponseCborReaderTests
{
    /// <summary>Round-tripping a response with only the Required members recovers them exactly, with the optional members left <see langword="null"/>.</summary>
    [TestMethod]
    public void RoundTripsRequiredMembersOnly()
    {
        Guid aaguid = Guid.NewGuid();
        var written = new CtapGetInfoResponse(Versions: [WellKnownCtapVersions.Fido23], Aaguid: aaguid);

        TaggedMemory<byte> encoded = CtapGetInfoResponseCborWriter.Write(written);
        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(encoded.Memory);

        Assert.HasCount(1, decoded.Versions);
        Assert.AreEqual(WellKnownCtapVersions.Fido23, decoded.Versions[0]);
        Assert.AreEqual(aaguid, decoded.Aaguid);
        Assert.IsNull(decoded.Extensions);
        Assert.IsNull(decoded.Options);
    }


    /// <summary>Round-tripping a response carrying extensions and both options recovers every member.</summary>
    [TestMethod]
    public void RoundTripsExtensionsAndOptions()
    {
        Guid aaguid = Guid.NewGuid();
        var written = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23, WellKnownCtapVersions.Fido21],
            Aaguid: aaguid,
            Extensions: ["hmac-secret", "credProtect"],
            Options: new CtapGetInfoOptions(ResidentKey: true, Platform: false));

        TaggedMemory<byte> encoded = CtapGetInfoResponseCborWriter.Write(written);
        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(encoded.Memory);

        CollectionAssert.AreEqual(new List<string>(written.Versions), new List<string>(decoded.Versions));
        Assert.AreEqual(aaguid, decoded.Aaguid);
        CollectionAssert.AreEqual(new List<string>(written.Extensions!), new List<string>(decoded.Extensions!));
        Assert.IsNotNull(decoded.Options);
        Assert.IsTrue(decoded.Options!.ResidentKey!.Value);
        Assert.IsFalse(decoded.Options!.Platform!.Value);
    }


    /// <summary>A response missing the Required <c>versions</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenVersionsMemberIsMissing()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Aaguid);
        writer.WriteByteString(new byte[16]);
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetInfoResponseCborReader.Read(writer.Encode()));

        Assert.Contains("versions", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A response missing the Required <c>aaguid</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenAaguidMemberIsMissing()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Versions);
        writer.WriteStartArray(1);
        writer.WriteTextString(WellKnownCtapVersions.Fido23);
        writer.WriteEndArray();
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetInfoResponseCborReader.Read(writer.Encode()));

        Assert.Contains("aaguid", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A response carrying an unrecognized top-level member key (here <c>0x05</c>, sorted after
    /// <c>aaguid</c>) is decoded successfully with the unknown member ignored, per CTAP 2.3 section
    /// 8's forward-compatibility rule.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedTopLevelMemberKey()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Versions);
        writer.WriteStartArray(1);
        writer.WriteTextString(WellKnownCtapVersions.Fido23);
        writer.WriteEndArray();
        writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Aaguid);
        writer.WriteByteString(new byte[16]);
        writer.WriteInt32(0x05);
        writer.WriteUInt32(42);
        writer.WriteEndMap();

        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(writer.Encode());

        Assert.AreEqual(WellKnownCtapVersions.Fido23, decoded.Versions[0]);
    }


    /// <summary>Round-tripping a response carrying <c>clientPin</c>, <c>pinUvAuthToken</c>, <c>makeCredUvNotRqd</c>, and <c>pinUvAuthProtocols</c> recovers every value, for both the <c>clientPin: false</c> and <c>clientPin: true</c> variants.</summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void RoundTripsClientPinPinUvAuthTokenMakeCredUvNotRqdAndPinUvAuthProtocols(bool clientPin)
    {
        Guid aaguid = Guid.NewGuid();
        var written = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(ResidentKey: true, ClientPin: clientPin, PinUvAuthToken: true, MakeCredUvNotRqd: true),
            PinUvAuthProtocols: [2, 1]);

        TaggedMemory<byte> encoded = CtapGetInfoResponseCborWriter.Write(written);
        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(encoded.Memory);

        Assert.IsNotNull(decoded.Options);
        Assert.IsTrue(decoded.Options!.ResidentKey!.Value);
        Assert.AreEqual(clientPin, decoded.Options.ClientPin!.Value);
        Assert.IsTrue(decoded.Options.PinUvAuthToken!.Value);
        Assert.IsTrue(decoded.Options.MakeCredUvNotRqd!.Value);
        Assert.IsNotNull(decoded.PinUvAuthProtocols);
        CollectionAssert.AreEqual(new List<int> { 2, 1 }, new List<int>(decoded.PinUvAuthProtocols!));
    }


    /// <summary>
    /// Round-tripping the full <c>authenticatorConfig</c>+<c>authenticatorCredentialManagement</c>
    /// getInfo surface — <c>alwaysUv</c>, <c>credMgmt</c>, <c>authnrCfg</c>, <c>setMinPINLength</c>,
    /// <c>forcePINChange</c>, <c>minPINLength</c>, <c>maxRPIDsForSetMinPINLength</c>,
    /// <c>remainingDiscoverableCredentials</c>, and <c>authenticatorConfigCommands</c> — recovers every
    /// value exactly, for both the <c>alwaysUv</c>-disabled and <c>alwaysUv</c>-enabled config states
    /// (the derived <c>makeCredUvNotRqd</c> negation flips alongside <c>alwaysUv</c>;
    /// <c>credMgmt</c>/<c>remainingDiscoverableCredentials</c> are orthogonal to the config surface and
    /// stay constant across both states).
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void RoundTripsAuthenticatorConfigSurfaceForBothAlwaysUvStates(bool isAlwaysUvEnabled)
    {
        Guid aaguid = Guid.NewGuid();
        var written = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(
                ResidentKey: true,
                AlwaysUv: isAlwaysUvEnabled,
                CredMgmt: true,
                AuthnrCfg: true,
                ClientPin: true,
                PinUvAuthToken: true,
                SetMinPinLength: true,
                MakeCredUvNotRqd: !isAlwaysUvEnabled),
            PinUvAuthProtocols: [2, 1],
            ForcePinChange: isAlwaysUvEnabled,
            MinPinLength: isAlwaysUvEnabled ? 6 : 4,
            MaxRpIdsForSetMinPinLength: 0,
            RemainingDiscoverableCredentials: 8,
            AuthenticatorConfigCommands: [2, 3]);

        TaggedMemory<byte> encoded = CtapGetInfoResponseCborWriter.Write(written);
        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(encoded.Memory);

        Assert.IsNotNull(decoded.Options);
        Assert.AreEqual(isAlwaysUvEnabled, decoded.Options!.AlwaysUv!.Value);
        Assert.IsTrue(decoded.Options.CredMgmt!.Value);
        Assert.IsTrue(decoded.Options.AuthnrCfg!.Value);
        Assert.IsTrue(decoded.Options.SetMinPinLength!.Value);
        Assert.AreEqual(!isAlwaysUvEnabled, decoded.Options.MakeCredUvNotRqd!.Value);
        Assert.AreEqual(isAlwaysUvEnabled, decoded.ForcePinChange!.Value);
        Assert.AreEqual(isAlwaysUvEnabled ? 6 : 4, decoded.MinPinLength!.Value);
        Assert.AreEqual(0, decoded.MaxRpIdsForSetMinPinLength!.Value);
        Assert.AreEqual(8, decoded.RemainingDiscoverableCredentials!.Value);
        CollectionAssert.AreEqual(new List<int> { 2, 3 }, new List<int>(decoded.AuthenticatorConfigCommands!));
    }


    /// <summary>
    /// An <c>options</c> map carrying an unrecognized option ID is decoded successfully with that
    /// entry ignored. <c>uvAcfg</c> is the example here (permanently unmodeled — the UV-path-only
    /// <c>acfg</c> gate this profile never grants through) since <c>uv</c> itself is now a modeled
    /// member (wavebio R2).
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedOptionId()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Versions);
        writer.WriteStartArray(1);
        writer.WriteTextString(WellKnownCtapVersions.Fido23);
        writer.WriteEndArray();
        writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Aaguid);
        writer.WriteByteString(new byte[16]);
        writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Options);
        writer.WriteStartMap(1);
        writer.WriteTextString("uvAcfg");
        writer.WriteBoolean(true);
        writer.WriteEndMap();
        writer.WriteEndMap();

        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(writer.Encode());

        Assert.IsNotNull(decoded.Options);
        Assert.IsNull(decoded.Options!.Ep);
        Assert.IsNull(decoded.Options!.ResidentKey);
        Assert.IsNull(decoded.Options!.Platform);
        Assert.IsNull(decoded.Options!.Uv);
        Assert.IsNull(decoded.Options!.BioEnroll);
        Assert.IsNull(decoded.Options!.UvBioEnroll);
    }


    /// <summary>
    /// Round-tripping a response carrying <c>ep</c> present-true/present-false recovers the value
    /// exactly, alongside a capable-profile <c>authenticatorConfigCommands</c> of <c>[1, 2, 3]</c>
    /// (R2's conditional array). <c>ep</c>'s third tri-state leg — ABSENT for a non-capable
    /// authenticator — is already proven by every other test in this file, none of which ever sets
    /// <c>Ep</c> on the written <see cref="CtapGetInfoOptions"/>.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void RoundTripsEpAndCapableProfileAuthenticatorConfigCommands(bool isEnterpriseAttestationEnabled)
    {
        Guid aaguid = Guid.NewGuid();
        var written = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(Ep: isEnterpriseAttestationEnabled, ResidentKey: true),
            AuthenticatorConfigCommands: [1, 2, 3]);

        TaggedMemory<byte> encoded = CtapGetInfoResponseCborWriter.Write(written);
        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(encoded.Memory);

        Assert.IsNotNull(decoded.Options);
        Assert.AreEqual(isEnterpriseAttestationEnabled, decoded.Options!.Ep!.Value);
        Assert.IsTrue(decoded.Options!.ResidentKey!.Value);
        CollectionAssert.AreEqual(new List<int> { 1, 2, 3 }, new List<int>(decoded.AuthenticatorConfigCommands!));
    }


    /// <summary>
    /// Round-tripping a response carrying <c>uv</c>, <c>bioEnroll</c>, <c>uvBioEnroll</c>,
    /// <c>preferredPlatformUvAttempts</c>, and <c>uvModality</c> recovers every value exactly, for both
    /// the zero-enrollment (<c>uv:false</c>/<c>bioEnroll:false</c>) and at-least-one-enrollment
    /// (<c>uv:true</c>/<c>bioEnroll:true</c>) tri-state values.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void RoundTripsUvBioEnrollUvBioEnrollAndPreferredPlatformUvAttemptsAndUvModality(bool hasProvisionedBioEnrollments)
    {
        Guid aaguid = Guid.NewGuid();
        var written = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(Uv: hasProvisionedBioEnrollments, BioEnroll: hasProvisionedBioEnrollments, UvBioEnroll: true),
            PreferredPlatformUvAttempts: 3,
            UvModality: 0x00000002);

        TaggedMemory<byte> encoded = CtapGetInfoResponseCborWriter.Write(written);
        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(encoded.Memory);

        Assert.IsNotNull(decoded.Options);
        Assert.AreEqual(hasProvisionedBioEnrollments, decoded.Options!.Uv!.Value);
        Assert.AreEqual(hasProvisionedBioEnrollments, decoded.Options!.BioEnroll!.Value);
        Assert.IsTrue(decoded.Options!.UvBioEnroll!.Value);
        Assert.AreEqual(3, decoded.PreferredPlatformUvAttempts!.Value);
        Assert.AreEqual(0x00000002, decoded.UvModality!.Value);
    }
}
