using System;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapGetAssertionResponseCborWriter"/>, the authenticator-side
/// <c>authenticatorGetAssertion</c> response encoder.
/// </summary>
[TestClass]
internal sealed class CtapGetAssertionResponseCborWriterTests
{
    /// <summary>A fixed 2-byte credential identifier pattern.</summary>
    private static byte[] ShortCredentialIdBytes => [0xAA, 0xBB];

    /// <summary>A fixed 3-byte authData pattern.</summary>
    private static byte[] AuthDataBytes => [0x01, 0x02, 0x03];

    /// <summary>A fixed 2-byte signature pattern.</summary>
    private static byte[] SignatureBytes => [0x30, 0x44];

    /// <summary>A fixed 4-byte user handle pattern.</summary>
    private static byte[] UserHandleBytes => [0x11, 0x22, 0x33, 0x44];


    /// <summary>
    /// A response with only the three Required members (<c>credential</c>, <c>authData</c>,
    /// <c>signature</c>) encodes to a 3-entry map in ascending key order.
    /// </summary>
    [TestMethod]
    public void WriteEncodesRequiredMembersOnlyToExactCanonicalBytes()
    {
        using CredentialId credentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);

        var response = new CtapGetAssertionResponse(
            new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId },
            AuthDataBytes,
            SignatureBytes);

        TaggedMemory<byte> result = CtapGetAssertionResponseCborWriter.Write(response);

        //map(3): credential(1)={id:bytes(2), type:"public-key"}, authData(2)=bytes(3), signature(3)=bytes(2).
        byte[] expected = Convert.FromHexString(
            "A3" +
            "01A262696442AABB64747970656A7075626C69632D6B6579" +
            "0243010203" +
            "03423044");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>user</c> (key <c>0x04</c>), <c>numberOfCredentials</c> (key <c>0x05</c>), and
    /// <c>userSelected</c> (key <c>0x06</c>) write after the three Required members, in ascending key
    /// order, when present.
    /// </summary>
    [TestMethod]
    public void WriteOrdersUserNumberOfCredentialsAndUserSelectedAfterRequiredMembers()
    {
        using CredentialId credentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        var response = new CtapGetAssertionResponse(
            new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId },
            AuthDataBytes,
            SignatureBytes,
            User: new CtapPublicKeyCredentialUserEntity(userHandle),
            NumberOfCredentials: 2,
            UserSelected: false);

        TaggedMemory<byte> result = CtapGetAssertionResponseCborWriter.Write(response);

        byte[] expected = Convert.FromHexString(
            "A6" +
            "01A262696442AABB64747970656A7075626C69632D6B6579" +
            "0243010203" +
            "03423044" +
            "04A16269644411223344" + //key 4 (user): map(1) {id: bytes(4)}
            "0502" + //key 5 (numberOfCredentials): 2
            "06F4"); //key 6 (userSelected): false

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A response carrying <c>largeBlobKey</c> (<c>0x07</c>, wavelb R8) writes it, as a byte string,
    /// after the three Required members when no other optional member is present.
    /// </summary>
    [TestMethod]
    public void WriteOrdersLargeBlobKeyAfterRequiredMembersWhenNoOtherOptionalMemberIsPresent()
    {
        using CredentialId credentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);
        byte[] largeBlobKeyBytes = [0x77, 0x88];

        var response = new CtapGetAssertionResponse(
            new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId },
            AuthDataBytes,
            SignatureBytes,
            LargeBlobKey: largeBlobKeyBytes);

        TaggedMemory<byte> result = CtapGetAssertionResponseCborWriter.Write(response);

        //map(4): credential(1)={id:bytes(2), type:"public-key"}, authData(2)=bytes(3), signature(3)=bytes(2), largeBlobKey(7)=bytes(2).
        byte[] expected = Convert.FromHexString(
            "A4" +
            "01A262696442AABB64747970656A7075626C69632D6B6579" +
            "0243010203" +
            "03423044" +
            "07427788");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>A <see langword="null"/> response is rejected before any encoding is attempted.</summary>
    [TestMethod]
    public void ThrowsArgumentNullExceptionForNullResponse()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => CtapGetAssertionResponseCborWriter.Write(null!));
    }
}
