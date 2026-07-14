using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Keri;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriEventCbor"/> — the CBOR arm of the bytes-to-field-map decode seam, the sibling of the
/// JSON arm. Each test mints a CBOR KERI message body with a CBOR writer (an independent encoder of the wire
/// bytes), then runs the firewalled path a verifier runs: decode the bytes into the neutral field map and fold
/// that map through <see cref="KeriEventReader"/> into a typed event, with no shared in-memory object between the
/// minter and the reader.
/// </summary>
[TestClass]
internal sealed class KeriEventCborTests
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
    /// CBOR inception bytes decode and fold into a typed inception event carrying every key-state field.
    /// </summary>
    [TestMethod]
    public void DecodesInceptionBytesToTypedEvent()
    {
        using MintedEvent minted = MintInceptionCbor();
        MessageFieldMap fields = KeriEventCbor.DecodeFieldMap(minted.Serialization);

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
    /// A homogeneous text-string array decodes to a string list (the neutral-map list convention).
    /// </summary>
    [TestMethod]
    public void DecodesArraysToStringLists()
    {
        using MintedEvent minted = MintInceptionCbor();
        MessageFieldMap fields = KeriEventCbor.DecodeFieldMap(minted.Serialization);

        Assert.IsInstanceOfType<IReadOnlyList<string>>(fields[KeriMessageFields.SigningKeys]);
        Assert.IsInstanceOfType<IReadOnlyList<string>>(fields[KeriMessageFields.Backers]);
    }


    /// <summary>
    /// Bytes that are not a CBOR map are rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonMapBytes()
    {
        var writer = new CborWriter();
        writer.WriteStartArray(0);
        writer.WriteEndArray();

        int length = writer.BytesWritten;
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        writer.Encode(owner.Memory.Span);
        ReadOnlyMemory<byte> notAMap = owner.Memory[..length];

        Assert.ThrowsExactly<CborContentException>(() => KeriEventCbor.DecodeFieldMap(notAMap));
    }


    //Mints a CBOR inception event body in the specification field order [v, t, d, i, s, kt, k, nt, n, bt, b, c, a],
    //into a pooled buffer the test owns and disposes.
    private static MintedEvent MintInceptionCbor()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(13);

        KeriEventWireFixtures.WriteScalar(writer, KeriMessageFields.Version, "KERICAACAACBOR00012c.");
        KeriEventWireFixtures.WriteScalar(writer, KeriMessageFields.MessageType, KeriMessageTypes.Inception);
        KeriEventWireFixtures.WriteScalar(writer, KeriMessageFields.Said, Aid);
        KeriEventWireFixtures.WriteScalar(writer, KeriMessageFields.Prefix, Aid);
        KeriEventWireFixtures.WriteScalar(writer, KeriMessageFields.SequenceNumber, "0");
        KeriEventWireFixtures.WriteScalar(writer, KeriMessageFields.KeysSigningThreshold, "2");
        KeriEventWireFixtures.WriteList(writer, KeriMessageFields.SigningKeys, SigningKeys);
        KeriEventWireFixtures.WriteScalar(writer, KeriMessageFields.NextKeysSigningThreshold, "2");
        KeriEventWireFixtures.WriteList(writer, KeriMessageFields.NextKeyDigests, NextKeyDigests);
        KeriEventWireFixtures.WriteScalar(writer, KeriMessageFields.BackerThreshold, "1");
        KeriEventWireFixtures.WriteList(writer, KeriMessageFields.Backers, Backers);
        KeriEventWireFixtures.WriteList(writer, KeriMessageFields.ConfigurationTraits, ConfigurationTraits);
        KeriEventWireFixtures.WriteList(writer, KeriMessageFields.Anchors, []);

        writer.WriteEndMap();

        int length = writer.BytesWritten;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        writer.Encode(owner.Memory.Span);

        return new MintedEvent(owner, length);
    }


    //A minted event's CBOR serialization, carried in a pooled buffer the test owns and disposes.
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
