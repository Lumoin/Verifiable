using System;
using System.Buffers;
using System.Text;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Cesr;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Conformance tests for the CESR-native ACDC serialization (<see cref="AcdcCesr"/>): the field-map message body
/// (<c>-G</c>) and the aggregate-list serialization. The message-body cases build the specification's worked compact
/// <c>acm</c> field map (CESR variant), encode it, and check the byte count and the top-level SAID the reference
/// publishes — the SAID cryptographically anchors the exact native bytes — then decode and fold through the
/// serialization-agnostic reader. The aggregate cases check the count-coded group against the worked aggregate
/// example (<see cref="AcdcExampleVectors"/>), whose block SAIDs aggregate into the published AGID <c>EEL7…</c>.
/// </summary>
[TestClass]
internal sealed class AcdcCesrTests
{
    /// <summary>The three CESR-native block SAIDs in order, the list the AGID is taken over.</summary>
    private static readonly string[] BlockSaids =
        [AcdcExampleVectors.CesrAggregateIssueeBlockSaid, AcdcExampleVectors.CesrAggregateScoreBlockSaid, AcdcExampleVectors.CesrAggregateNameBlockSaid];

    /// <summary>The reconstructed in-memory version string of the compact CESR acm (kind CESR, length from the framing).</summary>
    private const string CompactAcmVersion = "ACDCCAACAACESRAADc.";

    /// <summary>The message type of the compact acm.</summary>
    private const string CompactAcmMessageType = "acm";

    /// <summary>The top-level SAID of the compact CESR acm, taken over its native serialization.</summary>
    private const string CompactAcmSaid = "EFqQkKmWt_q2yF05izCOSYm9cXN_awDyncVpT9ji-aKg";

    /// <summary>The issuer AID of the compact acm.</summary>
    private const string CompactAcmIssuer = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ";

    /// <summary>The compacted schema section SAID of the compact CESR acm.</summary>
    private const string CompactAcmSchemaSaid = "EF0XwXr-uBOdJ0jEIfK2R0qjDr3nSAz23ipY0t066lMa";

    /// <summary>The compacted attribute section SAID of the compact CESR acm.</summary>
    private const string CompactAcmAttributeSaid = "EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-";

    /// <summary>The total byte count of the compact CESR acm native serialization.</summary>
    private const int CompactAcmSize = 220;


    /// <summary>
    /// Builds the compact CESR acm field map in canonical order, the neutral map the native encode consumes.
    /// </summary>
    /// <returns>The compact acm field map.</returns>
    private static MessageFieldMap CompactAcm() => new(StringComparer.Ordinal)
    {
        ["v"] = CompactAcmVersion,
        ["t"] = CompactAcmMessageType,
        ["d"] = CompactAcmSaid,
        ["i"] = CompactAcmIssuer,
        ["s"] = CompactAcmSchemaSaid,
        ["a"] = CompactAcmAttributeSaid
    };


    /// <summary>
    /// The compact acm encodes to its native serialization: the byte count matches the specification's, and the
    /// top-level SAID recomputes over the native bytes to the published value, so the exact bytes are anchored by
    /// the SAID rather than by a stored string.
    /// </summary>
    [TestMethod]
    public async Task EncodesCompactAcmToNativeMessage()
    {
        var buffer = new ArrayBufferWriter<byte>();
        AcdcCesr.EncodeFieldMap(CompactAcm(), BaseMemoryPool.Shared, buffer);

        Assert.AreEqual(CompactAcmSize, buffer.WrittenCount);
        Assert.IsTrue(await AcdcSaid.VerifyAsync(buffer.WrittenMemory, CompactAcmSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The native compact acm decodes back to its field map — the version reconstructed as the in-memory
    /// placeholder, every other field verbatim — and re-encoding the decoded map reproduces the original bytes.
    /// </summary>
    [TestMethod]
    public void RoundTripsNativeCompactAcm()
    {
        var buffer = new ArrayBufferWriter<byte>();
        AcdcCesr.EncodeFieldMap(CompactAcm(), BaseMemoryPool.Shared, buffer);

        MessageFieldMap decoded = AcdcCesr.DecodeFieldMap(buffer.WrittenMemory, BaseMemoryPool.Shared);
        Assert.AreEqual(CompactAcmVersion, decoded["v"]);
        Assert.AreEqual(CompactAcmMessageType, decoded["t"]);
        Assert.AreEqual(CompactAcmSaid, decoded["d"]);
        Assert.AreEqual(CompactAcmIssuer, decoded["i"]);
        Assert.AreEqual(CompactAcmSchemaSaid, decoded["s"]);
        Assert.AreEqual(CompactAcmAttributeSaid, decoded["a"]);

        var reBuffer = new ArrayBufferWriter<byte>();
        AcdcCesr.EncodeFieldMap(decoded, BaseMemoryPool.Shared, reBuffer);
        Assert.IsTrue(reBuffer.WrittenSpan.SequenceEqual(buffer.WrittenSpan));
    }


    /// <summary>
    /// The native compact acm folds through the serialization-agnostic reader into a typed ACDC carrying the
    /// reconstructed version, message type, SAID, issuer, and compacted section SAIDs — the same reader the JSON,
    /// CBOR, and MGPK arms feed.
    /// </summary>
    [TestMethod]
    public void FoldsNativeCompactAcmToTypedMessage()
    {
        var buffer = new ArrayBufferWriter<byte>();
        AcdcCesr.EncodeFieldMap(CompactAcm(), BaseMemoryPool.Shared, buffer);
        MessageFieldMap decoded = AcdcCesr.DecodeFieldMap(buffer.WrittenMemory, BaseMemoryPool.Shared);

        AcdcMessage acdc = AcdcReader.Read(decoded);
        Assert.AreEqual(CompactAcmVersion, acdc.VersionString);
        Assert.AreEqual(CompactAcmMessageType, acdc.MessageType);
        Assert.AreEqual(CompactAcmSaid, acdc.Said);
        Assert.AreEqual(CompactAcmIssuer, acdc.Issuer);
        Assert.AreEqual(CompactAcmSchemaSaid, ((CompactAcdcSection)acdc.Schema).Said);
        Assert.AreEqual(CompactAcmAttributeSaid, ((CompactAcdcSection)acdc.Attribute!).Said);
    }


    /// <summary>
    /// A serialization framed as a generic field map rather than a message body group is not a native ACDC message.
    /// </summary>
    [TestMethod]
    public void RejectsNonMessageFrame()
    {
        var buffer = new ArrayBufferWriter<byte>();
        CesrFieldMapCodec.EncodeFieldMap(new MessageFieldMap(StringComparer.Ordinal), BaseMemoryPool.Shared, buffer);

        Assert.ThrowsExactly<AcdcException>(() => AcdcCesr.DecodeFieldMap(buffer.WrittenMemory, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// The dummied aggregate list serializes to the specification's raw CESR value: the count code framing the group
    /// of quadlets followed by the dummied AGID placeholder and the block SAIDs concatenated with no separators.
    /// </summary>
    [TestMethod]
    public void SerializesDummiedAggregateListToSpecRawValue()
    {
        string placeholder = CesrSaid.Placeholder(CesrDigestCodes.Blake3Bits256);
        string[] dummied = [placeholder, .. BlockSaids];

        var buffer = new ArrayBufferWriter<byte>();
        AcdcCesr.EncodeAggregateList(dummied, buffer);

        Assert.AreEqual(AcdcExampleVectors.CesrAggregateDummiedRaw, Encoding.ASCII.GetString(buffer.WrittenSpan));
    }


    /// <summary>
    /// The CESR-native AGID derives from the ordered block SAIDs to the published value: the count-coded group with
    /// the AGID slot dummied is digested with BLAKE3 and CESR-encoded.
    /// </summary>
    [TestMethod]
    public async Task DerivesCesrAggregateAgid()
    {
        string agid = await AcdcAggregate.DeriveAgidAsync(BlockSaids, CesrDigestCodes.Blake3Bits256, AcdcCesr.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(AcdcExampleVectors.CesrAggregateAgid, agid);
    }


    /// <summary>
    /// The published CESR-native AGID verifies over the ordered block SAIDs, and a different AGID does not.
    /// </summary>
    [TestMethod]
    public async Task VerifiesCesrAggregateAgid()
    {
        Assert.IsTrue(await AcdcAggregate.VerifyAgidAsync(AcdcExampleVectors.CesrAggregateAgid, BlockSaids, AcdcCesr.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));

        string wrong = AcdcExampleVectors.CesrAggregateAgid[..^1] + (AcdcExampleVectors.CesrAggregateAgid[^1] == 'A' ? 'B' : 'A');
        Assert.IsFalse(await AcdcAggregate.VerifyAgidAsync(wrong, BlockSaids, AcdcCesr.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>The stable top-level SAID of the worked expanded/compact acm (the same in either form).</summary>
    private const string StableAcmSaid = "ED8yz6pQ0jBIp3vDGcxiC0J5pz5BbKJNYMD40ueu7b7P";


    /// <summary>
    /// Builds the worked expanded acm field map: the top-level fields plus fully expanded attribute, edge, and rule
    /// section blocks, each a nested field map with its own sub-blocks, from the specification's acm example (CESR).
    /// </summary>
    /// <returns>The expanded acm field map.</returns>
    private static MessageFieldMap ExpandedAcm() => new(StringComparer.Ordinal)
    {
        ["v"] = "ACDCCAACAACESRAAYw.",
        ["t"] = "acm",
        ["d"] = StableAcmSaid,
        ["u"] = "0ABhYmNkZWZnaGlqa2xtbW9w",
        ["i"] = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ",
        ["rd"] = "EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq",
        ["s"] = "EF0XwXr-uBOdJ0jEIfK2R0qjDr3nSAz23ipY0t066lMa",
        ["a"] = new MessageFieldMap(StringComparer.Ordinal)
        {
            ["d"] = "EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-",
            ["u"] = "0ABhYmNkZWZnaGlqa2xtbW9w",
            ["i"] = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C",
            ["role"] = "leader",
            ["contact"] = new MessageFieldMap(StringComparer.Ordinal)
            {
                ["d"] = "EKkFu2dX274cXnfaXh0OWZj1LnaUrjmDKAS_ozGBZ9Pz",
                ["u"] = "0ABhYmNkZWZnaGlqa2xtbW9w",
                ["first"] = "Cloe",
                ["last"] = "Cleveridge"
            }
        },
        ["e"] = new MessageFieldMap(StringComparer.Ordinal)
        {
            ["d"] = "EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw",
            ["u"] = "0AwjaDAE0qHcgNghkDaG7OY1",
            ["work"] = new MessageFieldMap(StringComparer.Ordinal)
            {
                ["d"] = "EFYkMnj7wgn4Vn02F6iniWoCJFf-kCzvkM2wZ7RFzWPC",
                ["u"] = "0ANghkDaG7OY1wjaDAE0qHcg",
                ["n"] = "ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX",
                ["s"] = "ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw"
            },
            ["play"] = new MessageFieldMap(StringComparer.Ordinal)
            {
                ["d"] = "ENCGxUkFQndU5bKtD6o3PRXvl2ZbgmSF-aQU1sVkGudj",
                ["u"] = "0ADAE0qHcgNghkDaG7OY1wja",
                ["n"] = "EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5",
                ["s"] = "EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N",
                ["o"] = "NI2I"
            }
        },
        ["r"] = new MessageFieldMap(StringComparer.Ordinal)
        {
            ["d"] = "EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-",
            ["u"] = "0ADaG7OaDAE0qHcgY1Nghkwj",
            ["disclaimers"] = new MessageFieldMap(StringComparer.Ordinal)
            {
                ["d"] = "EGMp181uEcUmi5FXs0ebqEhOyVi27-IDiYdoqe453BRD",
                ["u"] = "0AHcgY1NghkwjDaG7OaDAE0q",
                ["l"] = "Issuer disclaimers:",
                ["warrantyDisclaimer"] = new MessageFieldMap(StringComparer.Ordinal)
                {
                    ["d"] = "EO6ekaJYyWfl0Civ2bApVLgCmge43io1KvFCqSPt8Qc5",
                    ["u"] = "0AG7OY1wjaDAE0qHcgNghkDa",
                    ["l"] = "AS IS"
                },
                ["liabilityDisclaimer"] = new MessageFieldMap(StringComparer.Ordinal)
                {
                    ["d"] = "EDzyrYOaVI3TwLvN-w-pfGyoZfyvV0rslCieRCgXgEF7",
                    ["u"] = "0AHcgNghkDaG7OY1wjaDAE0q",
                    ["l"] = "No Liability"
                }
            },
            ["permittedUse"] = new MessageFieldMap(StringComparer.Ordinal)
            {
                ["d"] = "EBdHlf04DK2w4So61ebgUydOr85YGjP_xkLO-CnEXcsj",
                ["u"] = "0ADaG7OY1wjaDAE0qHcgNghk",
                ["l"] = "Non-commercial"
            }
        }
    };


    /// <summary>
    /// The expanded acm — nested attribute, edge, and rule blocks — encodes to its native serialization at the
    /// specification's byte count, decodes back with every nested value recovered (including the long-Base64 rule
    /// text carried as a string primitive), re-encodes to the identical bytes, and folds into a typed ACDC whose
    /// sections are expanded.
    /// </summary>
    [TestMethod]
    public void RoundTripsExpandedAcm()
    {
        var buffer = new ArrayBufferWriter<byte>();
        AcdcCesr.EncodeFieldMap(ExpandedAcm(), BaseMemoryPool.Shared, buffer);

        Assert.AreEqual(1584, buffer.WrittenCount);

        MessageFieldMap decoded = AcdcCesr.DecodeFieldMap(buffer.WrittenMemory, BaseMemoryPool.Shared);
        var attribute = (MessageFieldMap)decoded["a"]!;
        Assert.AreEqual("leader", attribute["role"]);
        var contact = (MessageFieldMap)attribute["contact"]!;
        Assert.AreEqual("Cloe", contact["first"]);
        Assert.AreEqual("Cleveridge", contact["last"]);
        var edge = (MessageFieldMap)decoded["e"]!;
        Assert.AreEqual("NI2I", ((MessageFieldMap)edge["play"]!)["o"]);
        var rule = (MessageFieldMap)decoded["r"]!;
        Assert.AreEqual("Issuer disclaimers:", ((MessageFieldMap)rule["disclaimers"]!)["l"]);
        Assert.AreEqual("Non-commercial", ((MessageFieldMap)rule["permittedUse"]!)["l"]);

        var reBuffer = new ArrayBufferWriter<byte>();
        AcdcCesr.EncodeFieldMap(decoded, BaseMemoryPool.Shared, reBuffer);
        Assert.IsTrue(reBuffer.WrittenSpan.SequenceEqual(buffer.WrittenSpan));

        AcdcMessage acdc = AcdcReader.Read(decoded);
        Assert.AreEqual(StableAcmSaid, acdc.Said);
        Assert.IsInstanceOfType<ExpandedAcdcSection>(acdc.Attribute);
        Assert.IsInstanceOfType<ExpandedAcdcSection>(acdc.Edge);
        Assert.IsInstanceOfType<ExpandedAcdcSection>(acdc.Rule);
    }


    /// <summary>
    /// The compact form of the same acm — the section blocks replaced by their SAIDs, plus the UUID and registry
    /// fields — encodes at the specification's byte count, and its top-level SAID (stable across the compact and
    /// expanded forms) recomputes over the native bytes, cryptographically anchoring the encoding.
    /// </summary>
    [TestMethod]
    public async Task EncodesCompactAcmWithSectionSaids()
    {
        var map = new MessageFieldMap(StringComparer.Ordinal)
        {
            ["v"] = "ACDCCAACAACESRAAGI.",
            ["t"] = "acm",
            ["d"] = StableAcmSaid,
            ["u"] = "0ABhYmNkZWZnaGlqa2xtbW9w",
            ["i"] = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ",
            ["rd"] = "EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq",
            ["s"] = "EF0XwXr-uBOdJ0jEIfK2R0qjDr3nSAz23ipY0t066lMa",
            ["a"] = "EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-",
            ["e"] = "EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw",
            ["r"] = "EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-"
        };

        var buffer = new ArrayBufferWriter<byte>();
        AcdcCesr.EncodeFieldMap(map, BaseMemoryPool.Shared, buffer);

        Assert.AreEqual(392, buffer.WrittenCount);
        Assert.IsTrue(await AcdcSaid.VerifyAsync(buffer.WrittenMemory, StableAcmSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }
}
