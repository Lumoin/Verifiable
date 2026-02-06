using Verifiable.Tpm.Infrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Roundtrip tests verifying TpmReader and TpmWriter interoperability.
/// </summary>
[TestClass]
internal class TpmReaderWriterRoundtripTests
{
    [TestMethod]
    public void UInt16Roundtrips()
    {
        const ushort original = 0xABCD;
        Span<byte> buffer = stackalloc byte[sizeof(ushort)];

        var writer = new TpmWriter(buffer);
        writer.WriteUInt16(original);

        var reader = new TpmReader(buffer);
        ushort parsed = reader.ReadUInt16();

        Assert.AreEqual(original, parsed);
    }

    [TestMethod]
    public void UInt32Roundtrips()
    {
        const uint original = 0x12345678;
        Span<byte> buffer = stackalloc byte[sizeof(uint)];

        var writer = new TpmWriter(buffer);
        writer.WriteUInt32(original);

        var reader = new TpmReader(buffer);
        uint parsed = reader.ReadUInt32();

        Assert.AreEqual(original, parsed);
    }

    [TestMethod]
    public void UInt64Roundtrips()
    {
        const ulong original = 0x123456789ABCDEF0;
        Span<byte> buffer = stackalloc byte[sizeof(ulong)];

        var writer = new TpmWriter(buffer);
        writer.WriteUInt64(original);

        var reader = new TpmReader(buffer);
        ulong parsed = reader.ReadUInt64();

        Assert.AreEqual(original, parsed);
    }

    [TestMethod]
    public void Tpm2bRoundtrips()
    {
        byte[] originalData = [0xDE, 0xAD, 0xBE, 0xEF];
        Span<byte> buffer = stackalloc byte[sizeof(ushort) + originalData.Length];

        var writer = new TpmWriter(buffer);
        writer.WriteTpm2b(originalData);

        var reader = new TpmReader(buffer);
        ReadOnlySpan<byte> parsed = reader.ReadTpm2b();

        Assert.AreEqual(originalData.Length, parsed.Length);
        Assert.IsTrue(originalData.AsSpan().SequenceEqual(parsed));
    }

    [TestMethod]
    public void EmptyTpm2bRoundtrips()
    {
        byte[] originalData = [];
        Span<byte> buffer = stackalloc byte[sizeof(ushort)];

        var writer = new TpmWriter(buffer);
        writer.WriteTpm2b(originalData);

        var reader = new TpmReader(buffer);
        ReadOnlySpan<byte> parsed = reader.ReadTpm2b();

        Assert.AreEqual(0, parsed.Length);
    }

    [TestMethod]
    public void ComplexStructureRoundtrips()
    {
        const ushort field1 = 0x1234;
        const uint field2 = 0xDEADBEEF;
        byte[] field3 = [0xAA, 0xBB, 0xCC];
        const byte field4 = 0xFF;

        int totalSize = sizeof(ushort) + sizeof(uint) + sizeof(ushort) + field3.Length + sizeof(byte);
        Span<byte> buffer = stackalloc byte[totalSize];

        var writer = new TpmWriter(buffer);
        writer.WriteUInt16(field1);
        writer.WriteUInt32(field2);
        writer.WriteTpm2b(field3);
        writer.WriteByte(field4);

        var reader = new TpmReader(buffer);
        ushort parsedField1 = reader.ReadUInt16();
        uint parsedField2 = reader.ReadUInt32();
        ReadOnlySpan<byte> parsedField3 = reader.ReadTpm2b();
        byte parsedField4 = reader.ReadByte();

        Assert.AreEqual(field1, parsedField1);
        Assert.AreEqual(field2, parsedField2);
        Assert.IsTrue(field3.AsSpan().SequenceEqual(parsedField3));
        Assert.AreEqual(field4, parsedField4);
        Assert.IsTrue(reader.IsEmpty);
    }

    [TestMethod]
    public void WrittenEqualsConsumedForSameData()
    {
        Span<byte> buffer = stackalloc byte[32];
        var writer = new TpmWriter(buffer);

        writer.WriteUInt16(0x1234);
        writer.WriteUInt32(0x56789ABC);
        writer.WriteTpm2b([0xDE, 0xAD]);

        var reader = new TpmReader(buffer[..writer.Written]);
        _ = reader.ReadUInt16();
        _ = reader.ReadUInt32();
        _ = reader.ReadTpm2b();

        Assert.AreEqual(writer.Written, reader.Consumed);
    }
}
