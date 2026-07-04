using System.Buffers;
using System.Collections.Generic;
using MessagePack;
using Verifiable.Cryptography;
using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Demonstrates MGPK conformance for KERI key events. The CESR specification requires a conformant parser to
/// support the JSON, CBOR, and MGPK serializations of a field map; the library ships the serialization-agnostic
/// reader and the JSON, CBOR, and CESR-native decode arms, but deliberately does not bundle an MGPK reader. This
/// test stands in for an MGPK deployment: it mints and decodes MGPK event bytes with an independent MessagePack
/// codec, normalizes them to the neutral field-map conventions, and folds the result through the same
/// <see cref="KeriEventReader"/> the other serializations use, showing MGPK plugs into the decode seam unchanged.
/// </summary>
/// <remarks>
/// The MessagePack codec here is the independent oracle, used only in this test; the field-map shape and the
/// reader being exercised are the specification's, not the codec's. The MGPK walker mirrors the library's CBOR
/// arm: a map of text-string keys, scalar values as strings, and homogeneous string arrays normalized to string
/// lists, with any other array left general.
/// </remarks>
[TestClass]
internal sealed class KeriEventMgpkConformanceTests
{
    private const string Aid = "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB";

    private static readonly string[] SigningKeys =
    [
        "DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu",
        "DG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5",
        "DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV"
    ];

    private static readonly string[] NextKeyDigests =
    [
        "ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB",
        "ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YT",
        "EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG"
    ];

    private static readonly string[] Backers = ["BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"];
    private static readonly string[] ConfigurationTraits = ["DID"];


    /// <summary>
    /// MGPK inception bytes, decoded by an independent MessagePack codec and folded through the same reader the
    /// JSON and CBOR arms use, produce a typed inception event carrying every key-state field.
    /// </summary>
    [TestMethod]
    public void DecodesMgpkInceptionThroughTheSameReader()
    {
        using MintedEvent minted = MintInceptionMgpk();
        MessageFieldMap fields = DecodeMgpkFieldMap(minted.Serialization);

        var inception = (KeriInceptionEvent)KeriEventReader.Read(fields);

        Assert.AreEqual(Aid, inception.Said);
        Assert.AreEqual(Aid, inception.Prefix);
        Assert.AreEqual(0, inception.SequenceNumber);
        Assert.AreEqual(KeriThreshold.Unweighted(2), inception.SigningThreshold);
        CollectionAssert.AreEqual(SigningKeys, (System.Collections.ICollection)inception.SigningKeys);
        CollectionAssert.AreEqual(NextKeyDigests, (System.Collections.ICollection)inception.NextKeyDigests);
        CollectionAssert.AreEqual(ConfigurationTraits, (System.Collections.ICollection)inception.ConfigurationTraits);
    }


    /// <summary>
    /// A homogeneous string array decodes to a string list, the neutral-map list convention the reader requires.
    /// </summary>
    [TestMethod]
    public void NormalizesArraysToStringLists()
    {
        using MintedEvent minted = MintInceptionMgpk();
        MessageFieldMap fields = DecodeMgpkFieldMap(minted.Serialization);

        Assert.IsInstanceOfType<IReadOnlyList<string>>(fields[KeriMessageFields.SigningKeys]);
        Assert.IsInstanceOfType<IReadOnlyList<string>>(fields[KeriMessageFields.Backers]);
    }


    //Decodes MGPK bytes into the neutral field map, mirroring the library's CBOR arm: scalars as strings,
    //homogeneous string arrays as string lists, any other array left general, preserving the fields' serialization
    //order as the reader requires. Uses the independent codec's low-level reader.
    private static MessageFieldMap DecodeMgpkFieldMap(ReadOnlyMemory<byte> mgpk)
    {
        var reader = new MessagePackReader(mgpk);
        int count = reader.ReadMapHeader();
        var map = new MessageFieldMap(count, StringComparer.Ordinal);
        for(int i = 0; i < count; i++)
        {
            string key = reader.ReadString()!;
            map[key] = ReadValue(ref reader);
        }

        return map;
    }


    private static object? ReadValue(ref MessagePackReader reader)
    {
        switch(reader.NextMessagePackType)
        {
            case MessagePackType.String:
            {
                return reader.ReadString();
            }
            case MessagePackType.Array:
            {
                return ReadArray(ref reader);
            }
            case MessagePackType.Map:
            {
                return ReadMap(ref reader);
            }
            case MessagePackType.Boolean:
            {
                return reader.ReadBoolean();
            }
            case MessagePackType.Nil:
            {
                reader.ReadNil();

                return null;
            }
            default:
            {
                throw new MessagePackSerializationException($"Unexpected MGPK type '{reader.NextMessagePackType}' in a KERI event.");
            }
        }
    }


    private static object ReadArray(ref MessagePackReader reader)
    {
        int count = reader.ReadArrayHeader();
        var items = new List<object?>(count);
        for(int i = 0; i < count; i++)
        {
            items.Add(ReadValue(ref reader));
        }

        var strings = new List<string>(items.Count);
        foreach(object? item in items)
        {
            if(item is not string text)
            {
                return items;
            }

            strings.Add(text);
        }

        return strings;
    }


    private static Dictionary<string, object?> ReadMap(ref MessagePackReader reader)
    {
        int count = reader.ReadMapHeader();
        var map = new Dictionary<string, object?>(count, StringComparer.Ordinal);
        for(int i = 0; i < count; i++)
        {
            string key = reader.ReadString()!;
            map[key] = ReadValue(ref reader);
        }

        return map;
    }


    //Mints an MGPK inception event body in the specification field order with the independent codec's writer, into
    //a pooled buffer the test owns and disposes.
    private static MintedEvent MintInceptionMgpk()
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new MessagePackWriter(buffer);
        writer.WriteMapHeader(13);

        WriteScalar(ref writer, KeriMessageFields.Version, "KERICAACAAMGPK0001a0.");
        WriteScalar(ref writer, KeriMessageFields.MessageType, KeriMessageTypes.Inception);
        WriteScalar(ref writer, KeriMessageFields.Said, Aid);
        WriteScalar(ref writer, KeriMessageFields.Prefix, Aid);
        WriteScalar(ref writer, KeriMessageFields.SequenceNumber, "0");
        WriteScalar(ref writer, KeriMessageFields.KeysSigningThreshold, "2");
        WriteList(ref writer, KeriMessageFields.SigningKeys, SigningKeys);
        WriteScalar(ref writer, KeriMessageFields.NextKeysSigningThreshold, "2");
        WriteList(ref writer, KeriMessageFields.NextKeyDigests, NextKeyDigests);
        WriteScalar(ref writer, KeriMessageFields.BackerThreshold, "1");
        WriteList(ref writer, KeriMessageFields.Backers, Backers);
        WriteList(ref writer, KeriMessageFields.ConfigurationTraits, ConfigurationTraits);
        WriteList(ref writer, KeriMessageFields.Anchors, []);

        writer.Flush();

        int length = buffer.WrittenCount;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        buffer.WrittenSpan.CopyTo(owner.Memory.Span);

        return new MintedEvent(owner, length);
    }


    private static void WriteScalar(ref MessagePackWriter writer, string label, string value)
    {
        writer.Write(label);
        writer.Write(value);
    }


    private static void WriteList(ref MessagePackWriter writer, string label, string[] values)
    {
        writer.Write(label);
        writer.WriteArrayHeader(values.Length);
        foreach(string value in values)
        {
            writer.Write(value);
        }
    }


    //A minted event's MGPK serialization, carried in a pooled buffer the test owns and disposes.
    private sealed class MintedEvent: IDisposable
    {
        private readonly IMemoryOwner<byte> owner;
        private readonly int length;

        public MintedEvent(IMemoryOwner<byte> owner, int length)
        {
            this.owner = owner;
            this.length = length;
        }

        public ReadOnlyMemory<byte> Serialization => owner.Memory[..length];

        public void Dispose() => owner.Dispose();
    }
}
