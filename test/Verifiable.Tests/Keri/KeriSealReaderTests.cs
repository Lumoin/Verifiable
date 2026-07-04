using System.Collections.Generic;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriSealReader"/> — reading a decoded, serialization-agnostic seal field map into a typed
/// <see cref="KeriSeal"/>, and an event's anchor list (field <c>a</c>) into typed seals. The seal shapes are the
/// KERI specification's worked seal examples. Because the reader works on a neutral map, the same path serves a
/// seal decoded from JSON, CBOR, MGPK, or CESR-native; one test drives the real JSON decoder end to end to show
/// that the anchor list a decoder produces (a list of string-keyed maps) feeds the reader directly.
/// </summary>
[TestClass]
internal sealed class KeriSealReaderTests
{
    private const string Said = "EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5";
    private const string Aid = "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur";


    /// <summary>
    /// A field map carrying only <c>d</c> reads as a digest seal.
    /// </summary>
    [TestMethod]
    public void ReadsDigestSeal()
    {
        var seal = KeriSealReader.Read(Map((KeriSealFields.Digest, Said)));

        Assert.IsInstanceOfType<KeriDigestSeal>(seal);
        Assert.AreEqual(Said, ((KeriDigestSeal)seal).Digest);
    }


    /// <summary>
    /// A field map carrying only <c>rd</c> reads as a Merkle tree root seal.
    /// </summary>
    [TestMethod]
    public void ReadsMerkleRootSeal()
    {
        var seal = KeriSealReader.Read(Map((KeriSealFields.MerkleRootDigest, Said)));

        Assert.IsInstanceOfType<KeriMerkleRootSeal>(seal);
        Assert.AreEqual(Said, ((KeriMerkleRootSeal)seal).RootDigest);
    }


    /// <summary>
    /// A field map carrying <c>[s, d]</c> reads as a source event seal with the hexadecimal sequence number decoded.
    /// </summary>
    [TestMethod]
    public void ReadsSourceEventSeal()
    {
        var seal = KeriSealReader.Read(Map((KeriSealFields.SequenceNumber, "e"), (KeriSealFields.Digest, Said)));

        Assert.IsInstanceOfType<KeriSourceEventSeal>(seal);
        var sourceEvent = (KeriSourceEventSeal)seal;
        Assert.AreEqual(14, sourceEvent.SequenceNumber, "Sequence number 'e' is hexadecimal 14.");
        Assert.AreEqual(Said, sourceEvent.Said);
    }


    /// <summary>
    /// A field map carrying <c>[i, s, d]</c> reads as a key event seal.
    /// </summary>
    [TestMethod]
    public void ReadsKeyEventSeal()
    {
        var seal = KeriSealReader.Read(Map((KeriSealFields.Prefix, Aid), (KeriSealFields.SequenceNumber, "1"), (KeriSealFields.Digest, Said)));

        Assert.IsInstanceOfType<KeriKeyEventSeal>(seal);
        var keyEvent = (KeriKeyEventSeal)seal;
        Assert.AreEqual(Aid, keyEvent.Prefix);
        Assert.AreEqual(1, keyEvent.SequenceNumber);
        Assert.AreEqual(Said, keyEvent.Said);
    }


    /// <summary>
    /// A field map carrying only <c>i</c> reads as a latest establishment event seal.
    /// </summary>
    [TestMethod]
    public void ReadsLatestEstablishmentEventSeal()
    {
        var seal = KeriSealReader.Read(Map((KeriSealFields.Prefix, Aid)));

        Assert.IsInstanceOfType<KeriLatestEstablishmentEventSeal>(seal);
        Assert.AreEqual(Aid, ((KeriLatestEstablishmentEventSeal)seal).Prefix);
    }


    /// <summary>
    /// A field map carrying <c>[bi, d]</c> reads as a registrar backer seal.
    /// </summary>
    [TestMethod]
    public void ReadsRegistrarBackerSeal()
    {
        var seal = KeriSealReader.Read(Map((KeriSealFields.BackerIdentifier, Aid), (KeriSealFields.Digest, Said)));

        Assert.IsInstanceOfType<KeriRegistrarBackerSeal>(seal);
        var backer = (KeriRegistrarBackerSeal)seal;
        Assert.AreEqual(Aid, backer.BackerIdentifier);
        Assert.AreEqual(Said, backer.Said);
    }


    /// <summary>
    /// A field map carrying <c>[t, d]</c> reads as a typed seal.
    /// </summary>
    [TestMethod]
    public void ReadsTypedSeal()
    {
        var seal = KeriSealReader.Read(Map((KeriSealFields.SealType, "YCSMTCAA"), (KeriSealFields.Digest, Said)));

        Assert.IsInstanceOfType<KeriTypedSeal>(seal);
        var typed = (KeriTypedSeal)seal;
        Assert.AreEqual("YCSMTCAA", typed.SealType);
        Assert.AreEqual(Said, typed.Digest);
    }


    /// <summary>
    /// A field map whose set of labels matches no seal type is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsUnknownSealShape()
    {
        //An identifier together with a digest but no sequence number matches no seal type.
        Assert.ThrowsExactly<KeriException>(() => KeriSealReader.Read(Map((KeriSealFields.Prefix, Aid), (KeriSealFields.Digest, Said))));
    }


    /// <summary>
    /// An empty field map is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsEmptySeal()
    {
        Assert.ThrowsExactly<KeriException>(() => KeriSealReader.Read(new Dictionary<string, object?>(StringComparer.Ordinal)));
    }


    /// <summary>
    /// A source event seal whose sequence number is not hexadecimal is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonHexadecimalSequenceNumber()
    {
        Assert.ThrowsExactly<KeriException>(() => KeriSealReader.Read(Map((KeriSealFields.SequenceNumber, "xyz"), (KeriSealFields.Digest, Said))));
    }


    /// <summary>
    /// An anchor list value that is not a list is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonListAnchors()
    {
        Assert.ThrowsExactly<KeriException>(() => KeriSealReader.ReadList("not a list"));
    }


    /// <summary>
    /// An anchor list decoded from real JSON — a heterogeneous mix of seal types — reads into the matching typed
    /// seals, proving the maps a JSON decoder produces for the seal objects feed the reader directly.
    /// </summary>
    [TestMethod]
    public void ReadsAnchorListDecodedFromJson()
    {
        string json = $$"""
        {"a":[
          {"d":"{{Said}}"},
          {"i":"{{Aid}}","s":"2","d":"{{Said}}"},
          {"t":"YCSMTCAA","d":"{{Said}}"},
          {"i":"{{Aid}}"}
        ]}
        """;

        MessageFieldMap fields = KeriEventJson.DecodeFieldMap(Encoding.UTF8.GetBytes(json));
        IReadOnlyList<KeriSeal> seals = KeriSealReader.ReadList(fields[KeriMessageFields.Anchors]);

        Assert.HasCount(4, seals);
        Assert.IsInstanceOfType<KeriDigestSeal>(seals[0]);
        Assert.IsInstanceOfType<KeriKeyEventSeal>(seals[1]);
        Assert.AreEqual(2, ((KeriKeyEventSeal)seals[1]).SequenceNumber);
        Assert.IsInstanceOfType<KeriTypedSeal>(seals[2]);
        Assert.IsInstanceOfType<KeriLatestEstablishmentEventSeal>(seals[3]);
    }


    //Builds a seal field map from label/value pairs, preserving the neutral-map convention (string-keyed,
    //object-valued) the reader consumes.
    private static Dictionary<string, object?> Map(params (string Label, string Value)[] fields)
    {
        var map = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach((string label, string value) in fields)
        {
            map[label] = value;
        }

        return map;
    }
}
