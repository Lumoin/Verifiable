using System;
using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapMakeCredentialRequestCborReader"/>: round-tripping against the paired
/// writer, every Required-member negative, and the section 8 forward-compatibility rule that unknown
/// top-level keys are ignored rather than rejected.
/// </summary>
[TestClass]
internal sealed class CtapMakeCredentialRequestCborReaderTests
{
    /// <summary>A fixed 32-byte clientDataHash pattern.</summary>
    private static byte[] ClientDataHashBytes
    {
        get
        {
            byte[] bytes = new byte[32];
            for(int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)i;
            }

            return bytes;
        }
    }

    /// <summary>A fixed 4-byte user handle pattern.</summary>
    private static byte[] UserHandleBytes => [0x11, 0x22, 0x33, 0x44];

    /// <summary>A fixed 2-byte credential identifier pattern.</summary>
    private static byte[] ShortCredentialIdBytes => [0xAA, 0xBB];


    /// <summary>Round-tripping a request with only the four Required members recovers them exactly, with every optional member left <see langword="null"/>.</summary>
    [TestMethod]
    public void RoundTripsRequiredMembersOnly()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var written = new CtapMakeCredentialRequest(
            clientDataHash,
            new CtapPublicKeyCredentialRpEntity("rp.co"),
            new CtapPublicKeyCredentialUserEntity(userHandle),
            [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }]);

        TaggedMemory<byte> encoded = CtapMakeCredentialRequestCborWriter.Write(written);
        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(encoded.Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsTrue(decoded.ClientDataHash.AsReadOnlySpan().SequenceEqual(ClientDataHashBytes));
            Assert.AreEqual("rp.co", decoded.Rp.Id);
            Assert.IsNull(decoded.Rp.Name);
            Assert.IsTrue(decoded.User.Id.AsReadOnlySpan().SequenceEqual(UserHandleBytes));
            Assert.IsNull(decoded.User.Name);
            Assert.HasCount(1, decoded.PubKeyCredParams);
            Assert.AreEqual(WellKnownCoseAlgorithms.Es256, decoded.PubKeyCredParams[0].Alg);
            Assert.AreEqual(WellKnownPublicKeyCredentialTypes.PublicKey, decoded.PubKeyCredParams[0].Type);
            Assert.IsNull(decoded.ExcludeList);
            Assert.IsNull(decoded.Extensions);
            Assert.IsNull(decoded.Options);
            Assert.IsNull(decoded.PinUvAuthParam);
            Assert.IsNull(decoded.PinUvAuthProtocol);
            Assert.IsNull(decoded.EnterpriseAttestation);
            Assert.IsNull(decoded.AttestationFormatsPreference);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>Round-tripping a request carrying every optional member recovers each one exactly.</summary>
    [TestMethod]
    public void RoundTripsEveryOptionalMember()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);
        using CredentialId excludeCredentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> extensionsOwner = BaseMemoryPool.Shared.Rent(1);
        extensionsOwner.Memory.Span[0] = 0xA0; //the canonical empty map, an opaque but well-formed CBOR item

        using IMemoryOwner<byte> pinUvAuthParamOwner = BaseMemoryPool.Shared.Rent(4);
        Span<byte> pinUvAuthParamSpan = pinUvAuthParamOwner.Memory.Span[..4];
        pinUvAuthParamSpan[0] = 0xDE;
        pinUvAuthParamSpan[1] = 0xAD;
        pinUvAuthParamSpan[2] = 0xBE;
        pinUvAuthParamSpan[3] = 0xEF;

        var written = new CtapMakeCredentialRequest(
            clientDataHash,
            new CtapPublicKeyCredentialRpEntity("rp.co", "Example RP"),
            new CtapPublicKeyCredentialUserEntity(userHandle, "alice", "Alice Example"),
            [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }],
            ExcludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = excludeCredentialId, Transports = ["usb"] }],
            Extensions: extensionsOwner.Memory[..1],
            Options: new CtapCommandOptions(ResidentKey: true, UserPresence: true, UserVerification: false),
            PinUvAuthParam: pinUvAuthParamOwner.Memory[..4],
            PinUvAuthProtocol: 1,
            EnterpriseAttestation: 2,
            AttestationFormatsPreference: ["none"]);

        TaggedMemory<byte> encoded = CtapMakeCredentialRequestCborWriter.Write(written);
        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(encoded.Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.AreEqual("rp.co", decoded.Rp.Id);
            Assert.AreEqual("Example RP", decoded.Rp.Name);
            Assert.AreEqual("alice", decoded.User.Name);
            Assert.AreEqual("Alice Example", decoded.User.DisplayName);
            Assert.HasCount(1, decoded.ExcludeList!);
            Assert.IsTrue(decoded.ExcludeList![0].Id.AsReadOnlySpan().SequenceEqual(ShortCredentialIdBytes));
            Assert.HasCount(1, decoded.ExcludeList![0].Transports!);
            Assert.AreEqual("usb", decoded.ExcludeList![0].Transports![0]);
            Assert.IsTrue(decoded.Extensions!.Value.Span.SequenceEqual(new byte[] { 0xA0 }));
            Assert.IsTrue(decoded.Options!.ResidentKey!.Value);
            Assert.IsTrue(decoded.Options!.UserPresence!.Value);
            Assert.IsFalse(decoded.Options!.UserVerification!.Value);
            Assert.IsTrue(decoded.PinUvAuthParam!.Value.Span.SequenceEqual(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }));
            Assert.AreEqual(1, decoded.PinUvAuthProtocol);
            Assert.AreEqual(2, decoded.EnterpriseAttestation);
            Assert.HasCount(1, decoded.AttestationFormatsPreference!);
            Assert.AreEqual("none", decoded.AttestationFormatsPreference![0]);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();

            foreach(PublicKeyCredentialDescriptor descriptor in decoded.ExcludeList!)
            {
                descriptor.Id.Dispose();
            }
        }
    }


    /// <summary>
    /// A <c>credProtect</c>-only extensions map decodes <see cref="CtapMakeCredentialRequest.CredProtect"/>
    /// while leaving <see cref="CtapMakeCredentialRequest.MinPinLength"/> <see langword="null"/> — R5's
    /// "each key alone" round trip.
    /// </summary>
    [TestMethod]
    public void DecodesCredProtectAloneFromExtensionsMap()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, BuildExtensionsMap(credProtect: 2, minPinLength: null));

        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.AreEqual(2, decoded.CredProtect);
            Assert.IsNull(decoded.MinPinLength);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>
    /// A <c>minPinLength: true</c>-only extensions map decodes
    /// <see cref="CtapMakeCredentialRequest.MinPinLength"/> while leaving
    /// <see cref="CtapMakeCredentialRequest.CredProtect"/> <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void DecodesMinPinLengthTrueAloneFromExtensionsMap()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, BuildExtensionsMap(credProtect: null, minPinLength: true));

        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsNull(decoded.CredProtect);
            Assert.IsTrue(decoded.MinPinLength);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>
    /// A <c>minPinLength: false</c> entry decodes to <see langword="false"/>, not <see langword="null"/>
    /// — R5's rule that the reader faithfully reports what is on the wire, distinct from absence, even
    /// though the transition later treats <see langword="false"/> as semantically "not asking".
    /// </summary>
    [TestMethod]
    public void DecodesMinPinLengthFalseAsFalseNotAsAbsent()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, BuildExtensionsMap(credProtect: null, minPinLength: false));

        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsNotNull(decoded.MinPinLength);
            Assert.IsFalse(decoded.MinPinLength!.Value);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>Both known extension keys present together decode into both convenience members.</summary>
    [TestMethod]
    public void DecodesBothCredProtectAndMinPinLengthFromExtensionsMap()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, BuildExtensionsMap(credProtect: 3, minPinLength: true));

        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.AreEqual(3, decoded.CredProtect);
            Assert.IsTrue(decoded.MinPinLength);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>
    /// A <c>largeBlobKey</c>-only extensions map decodes <see cref="CtapMakeCredentialRequest.LargeBlobKey"/>
    /// while leaving <see cref="CtapMakeCredentialRequest.CredProtect"/>/<see cref="CtapMakeCredentialRequest.MinPinLength"/>
    /// <see langword="null"/> (wavelb R8's third known extension key).
    /// </summary>
    [TestMethod]
    public void DecodesLargeBlobKeyAloneFromExtensionsMap()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var extensionsWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        extensionsWriter.WriteStartMap(1);
        extensionsWriter.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey);
        extensionsWriter.WriteBoolean(true);
        extensionsWriter.WriteEndMap();

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, extensionsWriter.Encode());

        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsNull(decoded.CredProtect);
            Assert.IsNull(decoded.MinPinLength);
            Assert.IsTrue(decoded.LargeBlobKey);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>
    /// An <c>hmac-secret</c>-only extensions map decodes <see cref="CtapMakeCredentialRequest.HmacSecret"/>
    /// while leaving <see cref="CtapMakeCredentialRequest.CredProtect"/>/<see cref="CtapMakeCredentialRequest.MinPinLength"/>
    /// <see langword="null"/> (contract R3's fourth known extension key).
    /// </summary>
    [TestMethod]
    public void DecodesHmacSecretAloneFromExtensionsMap()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var extensionsWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        extensionsWriter.WriteStartMap(1);
        extensionsWriter.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecret);
        extensionsWriter.WriteBoolean(true);
        extensionsWriter.WriteEndMap();

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, extensionsWriter.Encode());

        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsNull(decoded.CredProtect);
            Assert.IsNull(decoded.MinPinLength);
            Assert.IsTrue(decoded.HmacSecret);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>
    /// An <c>hmac-secret: false</c> entry decodes to <see langword="false"/>, not <see langword="null"/>
    /// — the reader faithfully reports what is on the wire, distinct from absence, even though the
    /// transition later treats <see langword="false"/> as semantically "not requested" (contract R3).
    /// </summary>
    [TestMethod]
    public void DecodesHmacSecretFalseAsFalseNotAsAbsent()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var extensionsWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        extensionsWriter.WriteStartMap(1);
        extensionsWriter.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecret);
        extensionsWriter.WriteBoolean(false);
        extensionsWriter.WriteEndMap();

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, extensionsWriter.Encode());

        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsNotNull(decoded.HmacSecret);
            Assert.IsFalse(decoded.HmacSecret!.Value);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>
    /// An <c>hmac-secret</c> entry encoded as an unsigned integer rather than a boolean is a
    /// decode-shape failure, mirroring <see cref="ThrowsWhenCredProtectHasWrongCborType"/> — R7's
    /// classification later maps this to <c>CborUnexpectedType</c> (0x11) at the simulator boundary.
    /// </summary>
    [TestMethod]
    public void ThrowsWhenHmacSecretHasWrongCborType()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var wrongTypeWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        wrongTypeWriter.WriteStartMap(1);
        wrongTypeWriter.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecret);
        wrongTypeWriter.WriteInt32(1);
        wrongTypeWriter.WriteEndMap();

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, wrongTypeWriter.Encode());

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// An extensions map carrying only an unrecognized key decodes successfully, with
    /// <see cref="CtapMakeCredentialRequest.CredProtect"/>/<see cref="CtapMakeCredentialRequest.MinPinLength"/>/
    /// <see cref="CtapMakeCredentialRequest.HmacSecret"/> all left <see langword="null"/> and the raw
    /// <see cref="CtapMakeCredentialRequest.Extensions"/> bytes intact — CTAP 2.3 section 6.1.2 line
    /// 3553's "ignoring any that it does not support" rule. Uses <c>credBlob</c> (CTAP 2.3 §12.2) as the
    /// unrecognized key, since <c>hmac-secret</c> is itself now a recognized key (contract R3) and would
    /// no longer exercise this skip path.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedExtensionsMapKeyAndLeavesKnownMembersNull()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var unknownKeyExtensionsWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        unknownKeyExtensionsWriter.WriteStartMap(1);
        unknownKeyExtensionsWriter.WriteTextString("credBlob");
        unknownKeyExtensionsWriter.WriteBoolean(true);
        unknownKeyExtensionsWriter.WriteEndMap();
        byte[] unknownKeyExtensions = unknownKeyExtensionsWriter.Encode();

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, unknownKeyExtensions);

        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsNull(decoded.CredProtect);
            Assert.IsNull(decoded.MinPinLength);
            Assert.IsNull(decoded.HmacSecret);
            Assert.IsTrue(decoded.Extensions!.Value.Span.SequenceEqual(unknownKeyExtensions));
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>
    /// A <c>credProtect</c> entry encoded as a text string rather than an unsigned integer is a
    /// decode-shape failure, mirroring every other wrong-typed known member this reader already
    /// rejects (<see cref="ThrowsWhenClientDataHashHasWrongCborType"/>) — R5's chosen posture for
    /// wrong-typed known extension-map keys.
    /// </summary>
    [TestMethod]
    public void ThrowsWhenCredProtectHasWrongCborType()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var wrongTypeWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        wrongTypeWriter.WriteStartMap(1);
        wrongTypeWriter.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.CredProtect);
        wrongTypeWriter.WriteTextString("not-an-integer");
        wrongTypeWriter.WriteEndMap();

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, wrongTypeWriter.Encode());

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A <c>minPinLength</c> entry encoded as an unsigned integer rather than a boolean is a
    /// decode-shape failure, mirroring <see cref="ThrowsWhenCredProtectHasWrongCborType"/>.
    /// </summary>
    [TestMethod]
    public void ThrowsWhenMinPinLengthHasWrongCborType()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var wrongTypeWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        wrongTypeWriter.WriteStartMap(1);
        wrongTypeWriter.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.MinPinLength);
        wrongTypeWriter.WriteInt32(1);
        wrongTypeWriter.WriteEndMap();

        var written = BuildRequestWithExtensions(clientDataHash, userHandle, wrongTypeWriter.Encode());

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(CtapMakeCredentialRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared));
    }


    /// <summary>A request missing the Required <c>clientDataHash</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenClientDataHashMemberIsMissing()
    {
        byte[] encoded = BuildMapMissingKey(WellKnownCtapMakeCredentialRequestKeys.ClientDataHash);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(encoded, BaseMemoryPool.Shared));

        Assert.Contains("clientDataHash", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A request missing the Required <c>rp</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenRpMemberIsMissing()
    {
        byte[] encoded = BuildMapMissingKey(WellKnownCtapMakeCredentialRequestKeys.Rp);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(encoded, BaseMemoryPool.Shared));

        Assert.Contains("rp", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A request missing the Required <c>user</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenUserMemberIsMissing()
    {
        byte[] encoded = BuildMapMissingKey(WellKnownCtapMakeCredentialRequestKeys.User);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(encoded, BaseMemoryPool.Shared));

        Assert.Contains("user", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A request missing the Required <c>pubKeyCredParams</c> member is rejected, even though the earlier <c>user</c> member decoded a pooled carrier successfully.</summary>
    [TestMethod]
    public void ThrowsWhenPubKeyCredParamsMemberIsMissing()
    {
        byte[] encoded = BuildMapMissingKey(WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(encoded, BaseMemoryPool.Shared));

        Assert.Contains("pubKeyCredParams", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A <c>clientDataHash</c> encoded as a text string rather than the required byte string is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenClientDataHashHasWrongCborType()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(4);
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.ClientDataHash);
        writer.WriteTextString("not-bytes");
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.Rp);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        writer.WriteTextString("rp.co");
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.User);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        writer.WriteByteString(UserHandleBytes);
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(writer.Encode(), BaseMemoryPool.Shared));
    }


    /// <summary>A parameter map carrying the same top-level key twice is rejected.</summary>
    [TestMethod]
    public void ThrowsOnDuplicateTopLevelKey()
    {
        //Hand-built rather than produced by CborWriter (which enforces canonical key ordering at write
        //time and would refuse to emit this): {1: h'', 1: h''} — a duplicate top-level key, which
        //CtapParameterMapReader's shared first pass must reject regardless of which command reader
        //composes it.
        byte[] duplicateKeyMap = [0xA2, 0x01, 0x40, 0x01, 0x40];

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(duplicateKeyMap, BaseMemoryPool.Shared));
    }


    /// <summary>An indefinite-length top-level map is rejected, per the CTAP2 canonical CBOR encoding form.</summary>
    [TestMethod]
    public void ThrowsOnIndefiniteLengthTopLevelMap()
    {
        //Major type 5 (map) with additional info 31 (indefinite length), one entry, then the break byte.
        byte[] indefiniteLengthMap = [0xBF, 0x01, 0x40, 0xFF];

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialRequestCborReader.Read(indefiniteLengthMap, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A request carrying an unrecognized top-level member key (here <c>0xFF</c>, sorted after
    /// <c>pubKeyCredParams</c>) decodes successfully with the unknown member ignored, per CTAP 2.3
    /// section 8's forward-compatibility rule.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedTopLevelMemberKey()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.ClientDataHash);
        writer.WriteByteString(ClientDataHashBytes);
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.Rp);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        writer.WriteTextString("rp.co");
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.User);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        writer.WriteByteString(UserHandleBytes);
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteInt32(0xFF);
        writer.WriteBoolean(true);
        writer.WriteEndMap();

        CtapMakeCredentialRequest decoded = CtapMakeCredentialRequestCborReader.Read(writer.Encode(), BaseMemoryPool.Shared);

        try
        {
            Assert.AreEqual("rp.co", decoded.Rp.Id);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
            decoded.User.Id.Dispose();
        }
    }


    /// <summary>
    /// Builds a minimal valid <c>authenticatorMakeCredential</c> request carrying
    /// <paramref name="extensionsCbor"/> as its raw <c>extensions</c> member — the shared setup every
    /// extensions-map decode test in this file starts from.
    /// </summary>
    private static CtapMakeCredentialRequest BuildRequestWithExtensions(DigestValue clientDataHash, UserHandle userHandle, byte[] extensionsCbor) =>
        new(
            clientDataHash,
            new CtapPublicKeyCredentialRpEntity("rp.co"),
            new CtapPublicKeyCredentialUserEntity(userHandle),
            [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }],
            Extensions: extensionsCbor);


    /// <summary>
    /// Builds a CTAP2-canonical extensions map carrying whichever of <paramref name="credProtect"/>/
    /// <paramref name="minPinLength"/> is non-<see langword="null"/> — <c>"credProtect"</c> (11
    /// characters) always precedes <c>"minPinLength"</c> (12 characters) when both are present, per the
    /// canonical shorter-key-first sort rule.
    /// </summary>
    private static byte[] BuildExtensionsMap(int? credProtect, bool? minPinLength)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (credProtect is not null ? 1 : 0) + (minPinLength is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(credProtect is int credProtectValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.CredProtect);
            writer.WriteInt32(credProtectValue);
        }

        if(minPinLength is bool minPinLengthValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.MinPinLength);
            writer.WriteBoolean(minPinLengthValue);
        }

        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>Builds a 3-entry request parameter map omitting <paramref name="missingKey"/> from the four Required members.</summary>
    private static byte[] BuildMapMissingKey(int missingKey)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int[] allKeys = [WellKnownCtapMakeCredentialRequestKeys.ClientDataHash, WellKnownCtapMakeCredentialRequestKeys.Rp, WellKnownCtapMakeCredentialRequestKeys.User, WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams];
        int presentCount = 0;
        foreach(int key in allKeys)
        {
            if(key != missingKey)
            {
                presentCount++;
            }
        }

        writer.WriteStartMap(presentCount);

        if(missingKey != WellKnownCtapMakeCredentialRequestKeys.ClientDataHash)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.ClientDataHash);
            writer.WriteByteString(ClientDataHashBytes);
        }

        if(missingKey != WellKnownCtapMakeCredentialRequestKeys.Rp)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.Rp);
            writer.WriteStartMap(1);
            writer.WriteTextString("id");
            writer.WriteTextString("rp.co");
            writer.WriteEndMap();
        }

        if(missingKey != WellKnownCtapMakeCredentialRequestKeys.User)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.User);
            writer.WriteStartMap(1);
            writer.WriteTextString("id");
            writer.WriteByteString(UserHandleBytes);
            writer.WriteEndMap();
        }

        if(missingKey != WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams);
            writer.WriteStartArray(0);
            writer.WriteEndArray();
        }

        writer.WriteEndMap();

        return writer.Encode();
    }
}
