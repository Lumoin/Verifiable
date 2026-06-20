using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire-format tests for <see cref="TpmtSymDef"/> (TPM 2.0 Library Part 2, Section 11.1.6, Table 159).
/// </summary>
/// <remarks>
/// The union members collapse on the wire, so the encoded length and field set depend on the algorithm:
/// NULL writes only the algorithm; XOR writes algorithm and keyBits (the KDF hash) with no mode; a block cipher
/// writes algorithm, keyBits, and mode. These tests lock that layout and the round-trip.
/// </remarks>
[TestClass]
internal sealed class TpmtSymDefTests
{
    [TestMethod]
    public void NullDefinitionSerializesAlgorithmOnly()
    {
        TpmtSymDef def = TpmtSymDef.Null;

        Assert.IsTrue(def.IsNull);
        Assert.AreEqual(sizeof(ushort), def.SerializedSize, "A null definition is the 2-octet algorithm only.");

        byte[] buffer = new byte[def.SerializedSize];
        var writer = new TpmWriter(buffer);
        def.WriteTo(ref writer);

        Assert.AreEqual(def.SerializedSize, writer.Written);
        Assert.AreEqual((byte)0x00, buffer[0]);
        Assert.AreEqual((byte)TpmAlgIdConstants.TPM_ALG_NULL, buffer[1], "Algorithm must be TPM_ALG_NULL (0x0010).");
    }

    [TestMethod]
    public void XorDefinitionSerializesAlgorithmAndHashWithNoMode()
    {
        TpmtSymDef def = TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256);

        Assert.IsTrue(def.IsXor);
        Assert.IsFalse(def.IsNull);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, def.XorHash, "keyBits.xor overloads the field with the KDF hash.");
        Assert.AreEqual(sizeof(ushort) + sizeof(ushort), def.SerializedSize, "XOR is algorithm + keyBits, with no mode field.");

        byte[] buffer = new byte[def.SerializedSize];
        var writer = new TpmWriter(buffer);
        def.WriteTo(ref writer);

        Assert.AreEqual(def.SerializedSize, writer.Written);
        //algorithm = TPM_ALG_XOR (0x000A), keyBits = TPM_ALG_SHA256 (0x000B). Big-endian.
        byte[] expected = [0x00, (byte)TpmAlgIdConstants.TPM_ALG_XOR, 0x00, (byte)TpmAlgIdConstants.TPM_ALG_SHA256];
        Assert.IsTrue(buffer.AsSpan().SequenceEqual(expected), "XOR wire bytes must be algorithm || hash with no mode.");
    }

    [TestMethod]
    public void AesDefinitionSerializesAlgorithmKeyBitsAndMode()
    {
        TpmtSymDef def = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB);

        Assert.IsFalse(def.IsNull);
        Assert.IsFalse(def.IsXor);
        Assert.AreEqual(sizeof(ushort) + sizeof(ushort) + sizeof(ushort), def.SerializedSize, "A block cipher is algorithm + keyBits + mode.");

        byte[] buffer = new byte[def.SerializedSize];
        var writer = new TpmWriter(buffer);
        def.WriteTo(ref writer);

        Assert.AreEqual(def.SerializedSize, writer.Written);
        //algorithm = TPM_ALG_AES (0x0006), keyBits = 128 (0x0080), mode = TPM_ALG_CFB (0x0043).
        byte[] expected = [0x00, (byte)TpmAlgIdConstants.TPM_ALG_AES, 0x00, 0x80, 0x00, (byte)TpmAlgIdConstants.TPM_ALG_CFB];
        Assert.IsTrue(buffer.AsSpan().SequenceEqual(expected), "AES wire bytes must be algorithm || keyBits || mode.");
    }

    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA1)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA256)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA384)]
    public void XorRoundTrips(TpmAlgIdConstants hash)
    {
        TpmtSymDef def = TpmtSymDef.Xor(hash);

        byte[] buffer = new byte[def.SerializedSize];
        var writer = new TpmWriter(buffer);
        def.WriteTo(ref writer);

        var reader = new TpmReader(buffer);
        TpmtSymDef parsed = TpmtSymDef.Parse(ref reader);

        Assert.AreEqual(0, reader.Remaining, "Parsing must consume exactly the written bytes.");
        Assert.IsTrue(parsed.IsXor);
        Assert.AreEqual(hash, parsed.XorHash);
        Assert.AreEqual(def, parsed, "Round-trip must preserve the definition.");
    }

    [TestMethod]
    public void NullRoundTrips()
    {
        TpmtSymDef def = TpmtSymDef.Null;

        byte[] buffer = new byte[def.SerializedSize];
        var writer = new TpmWriter(buffer);
        def.WriteTo(ref writer);

        var reader = new TpmReader(buffer);
        TpmtSymDef parsed = TpmtSymDef.Parse(ref reader);

        Assert.AreEqual(0, reader.Remaining);
        Assert.IsTrue(parsed.IsNull);
    }

    [TestMethod]
    public void AesRoundTrips()
    {
        TpmtSymDef def = TpmtSymDef.Aes(256, TpmAlgIdConstants.TPM_ALG_CFB);

        byte[] buffer = new byte[def.SerializedSize];
        var writer = new TpmWriter(buffer);
        def.WriteTo(ref writer);

        var reader = new TpmReader(buffer);
        TpmtSymDef parsed = TpmtSymDef.Parse(ref reader);

        Assert.AreEqual(0, reader.Remaining);
        Assert.AreEqual(def, parsed);
        Assert.AreEqual((ushort)256, parsed.KeyBits);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_CFB, parsed.Mode);
    }

    [TestMethod]
    public void DefaultValueIsTreatedAsNullByXorAccessorContract()
    {
        //default(TpmtSymDef) carries TPM_ALG_ERROR (0x0000), not TPM_ALG_NULL (0x0010); IsNull is therefore
        //false for the raw default. Consumers that may see an unset value (such as StartAuthSessionInput) map it
        //to TpmtSymDef.Null. This test documents the raw-default behavior so that contract is deliberate.
        TpmtSymDef raw = default;

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ERROR, raw.Algorithm);
        Assert.IsFalse(raw.IsNull, "The struct default is TPM_ALG_ERROR, not TPM_ALG_NULL.");
    }
}
