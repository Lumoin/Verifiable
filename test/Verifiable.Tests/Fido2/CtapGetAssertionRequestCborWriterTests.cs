using System;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapGetAssertionRequestCborWriter"/>, the client-side
/// <c>authenticatorGetAssertion</c> request encoder.
/// </summary>
[TestClass]
internal sealed class CtapGetAssertionRequestCborWriterTests
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

    /// <summary>A fixed 2-byte credential identifier pattern, used for allowList entries.</summary>
    private static byte[] ShortCredentialIdBytes => [0xAA, 0xBB];


    /// <summary>
    /// A request carrying only the two Required members (<c>rpId</c>, <c>clientDataHash</c>) encodes
    /// to a 2-entry map in ascending key order.
    /// </summary>
    [TestMethod]
    public void WriteEncodesRequiredMembersOnlyToExactCanonicalBytes()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);

        var request = new CtapGetAssertionRequest("rp.co", clientDataHash);

        TaggedMemory<byte> result = CtapGetAssertionRequestCborWriter.Write(request);

        //map(2): rpId(1)="rp.co", clientDataHash(2)=bytes(32).
        byte[] expected = Convert.FromHexString(
            "A20165" + "72702E636F" +
            "025820" + "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>allowList</c> (key <c>0x03</c>) and <c>options</c> (key <c>0x05</c>) write after the two
    /// Required members, in ascending key order, when present.
    /// </summary>
    [TestMethod]
    public void WriteOrdersAllowListAndOptionsAfterRequiredMembers()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using CredentialId allowCredentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);

        var request = new CtapGetAssertionRequest(
            "rp.co",
            clientDataHash,
            AllowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = allowCredentialId }],
            Options: new CtapCommandOptions(UserPresence: false));

        TaggedMemory<byte> result = CtapGetAssertionRequestCborWriter.Write(request);

        byte[] expected = Convert.FromHexString(
            "A40165" + "72702E636F" +
            "025820" + "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "0381A262696442AABB64747970656A7075626C69632D6B6579" + //key 3 (allowList): array(1) of descriptor {id:bytes(2), type:"public-key"}
            "05A1627570F4"); //key 5 (options): map(1) {up: false}

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// Every remaining optional member (<c>extensions</c>, <c>pinUvAuthParam</c>,
    /// <c>pinUvAuthProtocol</c>) writes at its own ascending key position, and <see cref="CtapCommandOptions.ResidentKey"/>
    /// is encoded verbatim even though a conformant platform never sends it here — the writer's own
    /// documented rationale is that a capstone-level negative test needs exactly this to construct the
    /// wire vector proving the authenticator rejects it.
    /// </summary>
    [TestMethod]
    public void WriteEncodesEveryOptionalMemberInAscendingKeyOrder()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using CredentialId allowCredentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);

        var request = new CtapGetAssertionRequest(
            "rp.co",
            clientDataHash,
            AllowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = allowCredentialId }],
            Extensions: new byte[] { NoneAttestation.CanonicalEmptyMap }, //the canonical empty map, an opaque but well-formed CBOR item
            Options: new CtapCommandOptions(ResidentKey: true, UserPresence: true, UserVerification: false),
            PinUvAuthParam: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
            PinUvAuthProtocol: 1);

        TaggedMemory<byte> result = CtapGetAssertionRequestCborWriter.Write(request);

        byte[] expected = Convert.FromHexString(
            "A70165" + "72702E636F" +
            "025820" + "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "0381A262696442AABB64747970656A7075626C69632D6B6579" +
            "04A0" + //key 4 (extensions): the spliced-in canonical empty map, verbatim
            "05A362726BF5627570F5627576F4" + //key 5 (options): map(3) {rk: true, up: true, uv: false}
            "0644DEADBEEF" + //key 6 (pinUvAuthParam): bytes(4)
            "0701"); //key 7 (pinUvAuthProtocol): 1

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>A <see langword="null"/> request is rejected before any encoding is attempted.</summary>
    [TestMethod]
    public void ThrowsArgumentNullExceptionForNullRequest()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => CtapGetAssertionRequestCborWriter.Write(null!));
    }
}
