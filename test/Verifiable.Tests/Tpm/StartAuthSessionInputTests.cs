using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire-format tests for <see cref="StartAuthSessionInput"/>, focused on the negotiated symmetric algorithm
/// (TPMT_SYM_DEF) for session-based parameter encryption (TPM 2.0 Library Part 3, Section 11.1).
/// </summary>
[TestClass]
internal sealed class StartAuthSessionInputTests
{
    [TestMethod]
    public void DefaultSymmetricSerializesAsNull()
    {
        StartAuthSessionInput input = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256);

        Assert.IsTrue(input.Symmetric.IsNull, "An HMAC session created without a symmetric algorithm defaults to TPMT_SYM_DEF(NULL).");

        TpmtSymDef parsed = RoundTripSymmetric(input);
        Assert.IsTrue(parsed.IsNull, "The serialized symmetric definition must be a null algorithm.");
    }

    [TestMethod]
    public void XorSymmetricSerializesIntoParameterArea()
    {
        StartAuthSessionInput input = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(
            TpmAlgIdConstants.TPM_ALG_SHA256, TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256));

        Assert.IsTrue(input.Symmetric.IsXor);

        TpmtSymDef parsed = RoundTripSymmetric(input);
        Assert.IsTrue(parsed.IsXor, "The serialized symmetric definition must be XOR.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, parsed.XorHash, "The XOR keyBits field must carry the KDF hash.");
    }

    [TestMethod]
    public void BoundFactoryCarriesXorSymmetric()
    {
        const uint BindHandle = 0x80000001u;
        StartAuthSessionInput input = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(
            BindHandle, TpmAlgIdConstants.TPM_ALG_SHA384, TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA384));

        TpmtSymDef parsed = RoundTripSymmetric(input);
        Assert.IsTrue(parsed.IsXor);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, parsed.XorHash);
    }

    [TestMethod]
    public void AesCfbSymmetricSerializesIntoParameterArea()
    {
        StartAuthSessionInput input = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(
            0x80000001u, TpmAlgIdConstants.TPM_ALG_SHA256, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB));

        TpmtSymDef parsed = RoundTripSymmetric(input);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_AES, parsed.Algorithm);
        Assert.AreEqual((ushort)128, parsed.KeyBits);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_CFB, parsed.Mode, "A block-cipher symmetric definition must carry the CFB mode on the wire.");
    }

    [TestMethod]
    public void SerializedSizeAccountsForXorSymmetric()
    {
        StartAuthSessionInput nullSym = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256);
        StartAuthSessionInput xorSym = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(
            TpmAlgIdConstants.TPM_ALG_SHA256, TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256));

        //XOR is 4 octets (algorithm + keyBits) versus 2 octets for the null definition: a 2-octet difference,
        //given the nonceCaller length is identical (both derive from the same hash).
        Assert.AreEqual(nullSym.GetSerializedSize() + sizeof(ushort), xorSym.GetSerializedSize());
    }

    /// <summary>
    /// Serializes the command parameters and parses out the TPMT_SYM_DEF that sits between sessionType and
    /// authHash, returning it for assertions.
    /// </summary>
    private static TpmtSymDef RoundTripSymmetric(StartAuthSessionInput input)
    {
        //GetSerializedSize covers handles (tpmKey + bind = 8 octets) plus the parameter area.
        int handleSize = sizeof(uint) + sizeof(uint);
        int parameterSize = input.GetSerializedSize() - handleSize;

        byte[] parameters = new byte[parameterSize];
        var writer = new TpmWriter(parameters);
        input.WriteParameters(ref writer);
        Assert.AreEqual(parameterSize, writer.Written, "WriteParameters must fill exactly the budgeted parameter area.");

        var reader = new TpmReader(parameters);
        _ = reader.ReadTpm2b();            //nonceCaller.
        _ = reader.ReadTpm2b();            //encryptedSalt.
        _ = reader.ReadByte();             //sessionType.
        TpmtSymDef symmetric = TpmtSymDef.Parse(ref reader);
        ushort authHash = reader.ReadUInt16();

        Assert.AreEqual((ushort)input.AuthHash, authHash, "authHash must follow the symmetric definition.");
        Assert.AreEqual(0, reader.Remaining, "The parameter area must parse with no trailing bytes.");

        return symmetric;
    }
}
