using System;
using System.Buffers;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapMakeCredentialRequestCborWriter"/>, the client-side
/// <c>authenticatorMakeCredential</c> request encoder.
/// </summary>
[TestClass]
internal sealed class CtapMakeCredentialRequestCborWriterTests
{
    /// <summary>A fixed 32-byte clientDataHash pattern, distinguishable byte-by-byte in a failure diff.</summary>
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

    /// <summary>A fixed 2-byte credential identifier pattern, used for excludeList/allowList entries.</summary>
    private static byte[] ShortCredentialIdBytes => [0xAA, 0xBB];


    /// <summary>
    /// A request carrying only the four Required members (<c>clientDataHash</c>, <c>rp</c>,
    /// <c>user</c>, <c>pubKeyCredParams</c>) encodes to a 4-entry map in ascending key order, with the
    /// nested <c>rp</c>/<c>user</c>/<c>PublicKeyCredentialParameters</c> maps each omitting their own
    /// optional members.
    /// </summary>
    [TestMethod]
    public void WriteEncodesRequiredMembersOnlyToExactCanonicalBytes()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var request = new CtapMakeCredentialRequest(
            clientDataHash,
            new CtapPublicKeyCredentialRpEntity("rp.co"),
            new CtapPublicKeyCredentialUserEntity(userHandle),
            [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }]);

        TaggedMemory<byte> result = CtapMakeCredentialRequestCborWriter.Write(request);

        //map(4): clientDataHash(1)=bytes(32), rp(2)={id:"rp.co"}, user(3)={id:bytes(4)},
        //pubKeyCredParams(4)=[{alg:-7,type:"public-key"}].
        byte[] expected = Convert.FromHexString(
            "A4015820000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "02A16269646572702E636F" +
            "03A16269644411223344" +
            "0481A263616C672664747970656A7075626C69632D6B6579");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>excludeList</c> (key <c>0x05</c>) and <c>options</c> (key <c>0x07</c>) write after the four
    /// Required members, in ascending key order, when present.
    /// </summary>
    [TestMethod]
    public void WriteOrdersExcludeListAndOptionsAfterRequiredMembers()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);
        using CredentialId excludeCredentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);

        var request = new CtapMakeCredentialRequest(
            clientDataHash,
            new CtapPublicKeyCredentialRpEntity("rp.co"),
            new CtapPublicKeyCredentialUserEntity(userHandle),
            [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }],
            ExcludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = excludeCredentialId }],
            Options: new CtapCommandOptions(ResidentKey: true));

        TaggedMemory<byte> result = CtapMakeCredentialRequestCborWriter.Write(request);

        byte[] expected = Convert.FromHexString(
            "A6015820000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "02A16269646572702E636F" +
            "03A16269644411223344" +
            "0481A263616C672664747970656A7075626C69632D6B6579" +
            "0581A262696442AABB64747970656A7075626C69632D6B6579" + //key 5 (excludeList): array(1) of descriptor {id:bytes(2), type:"public-key"}
            "07A162726BF5"); //key 7 (options): map(1) {rk: true}

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// Every remaining optional member (<c>extensions</c>, <c>pinUvAuthParam</c>,
    /// <c>pinUvAuthProtocol</c>, <c>enterpriseAttestation</c>, <c>attestationFormatsPreference</c>)
    /// writes at its own ascending key position, producing an 11-entry map.
    /// </summary>
    [TestMethod]
    public void WriteEncodesEveryOptionalMemberInAscendingKeyOrder()
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

        var request = new CtapMakeCredentialRequest(
            clientDataHash,
            new CtapPublicKeyCredentialRpEntity("rp.co"),
            new CtapPublicKeyCredentialUserEntity(userHandle),
            [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }],
            ExcludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = excludeCredentialId }],
            Extensions: extensionsOwner.Memory[..1],
            Options: new CtapCommandOptions(ResidentKey: true),
            PinUvAuthParam: pinUvAuthParamOwner.Memory[..4],
            PinUvAuthProtocol: 1,
            EnterpriseAttestation: 2,
            AttestationFormatsPreference: ["none"]);

        TaggedMemory<byte> result = CtapMakeCredentialRequestCborWriter.Write(request);

        byte[] expected = Convert.FromHexString(
            "AB015820000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "02A16269646572702E636F" +
            "03A16269644411223344" +
            "0481A263616C672664747970656A7075626C69632D6B6579" +
            "0581A262696442AABB64747970656A7075626C69632D6B6579" +
            "06A0" + //key 6 (extensions): the spliced-in canonical empty map, verbatim
            "07A162726BF5" +
            "0844DEADBEEF" + //key 8 (pinUvAuthParam): bytes(4)
            "0901" + //key 9 (pinUvAuthProtocol): 1
            "0A02" + //key 10 (enterpriseAttestation): 2
            "0B81646E6F6E65"); //key 11 (attestationFormatsPreference): array(1) ["none"]

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>A <see langword="null"/> request is rejected before any encoding is attempted.</summary>
    [TestMethod]
    public void ThrowsArgumentNullExceptionForNullRequest()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => CtapMakeCredentialRequestCborWriter.Write(null!));
    }
}
