using System.Linq;
using System.Text;
using Verifiable.Acdc;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Tests for <see cref="AcdcReader"/> over the JSON decode arm (<see cref="AcdcJson"/>) — the firewalled path a
/// consumer runs: decode the received bytes into a neutral field map, then fold that map into a typed
/// <see cref="AcdcMessage"/>. The positive cases use the specification's worked Accreditation ACDC
/// (<see cref="AcdcExampleVectors"/>) in both its most-compact form and its expanded form; the negative cases drive
/// the structural rules the reader enforces.
/// </summary>
[TestClass]
internal sealed class AcdcReaderTests
{
    /// <summary>The field order of the expanded attribute block, used to check the decode preserves it.</summary>
    private static readonly string[] AttributeBlockFieldOrder = ["d", "u", "i", "name", "level"];


    /// <summary>
    /// The most-compact Accreditation ACDC folds into a typed ACDC whose scalar fields carry their values and whose
    /// schema, attribute, and rule sections are each the compact SAID; the absent edge section is null.
    /// </summary>
    [TestMethod]
    public void ReadsCompactAccreditationAcdc()
    {
        AcdcMessage acdc = AcdcReader.Read(Decode(AcdcExampleVectors.CompactAcdc));

        Assert.AreEqual(AcdcExampleVectors.CompactVersionString, acdc.VersionString);
        Assert.AreEqual(AcdcMessageTypes.Acdc, acdc.MessageType);
        Assert.AreEqual(AcdcExampleVectors.AccreditationSaid, acdc.Said);
        Assert.AreEqual(AcdcExampleVectors.Uuid, acdc.Uuid);
        Assert.AreEqual(AcdcExampleVectors.IssuerAid, acdc.Issuer);
        Assert.AreEqual(AcdcExampleVectors.RegistrySaid, acdc.RegistryDigest);
        AssertCompactSection(acdc.Schema, AcdcExampleVectors.SchemaSaid);
        AssertCompactSection(acdc.Attribute, AcdcExampleVectors.AttributeSectionSaid);
        AssertCompactSection(acdc.Rule, AcdcExampleVectors.RuleSectionSaid);
        Assert.IsNull(acdc.Edge, "The Accreditation ACDC has no edge section.");
    }


    /// <summary>
    /// The expanded Accreditation ACDC folds into a typed ACDC whose schema stays a compact SAID while the attribute
    /// and rule sections are expanded blocks; each block's SAID and a representative field are read, and the block
    /// preserves field order.
    /// </summary>
    [TestMethod]
    public void ReadsExpandedAccreditationAcdc()
    {
        AcdcMessage acdc = AcdcReader.Read(Decode(AcdcExampleVectors.ExpandedAcdc));

        AssertCompactSection(acdc.Schema, AcdcExampleVectors.SchemaSaid);

        var attribute = acdc.Attribute as ExpandedAcdcSection;
        Assert.IsNotNull(attribute, "The expanded attribute section is a block.");
        Assert.IsTrue(attribute.Detail.TryGetString(AcdcMessageFields.Said, out string? attributeSaid));
        Assert.AreEqual(AcdcExampleVectors.AttributeSectionSaid, attributeSaid);
        Assert.IsTrue(attribute.Detail.TryGetString("name", out string? name));
        Assert.AreEqual("Sunspot College", name);
        CollectionAssert.AreEqual(AttributeBlockFieldOrder, attribute.Detail.Keys.ToArray(), "The expanded block preserves field order.");

        var rule = acdc.Rule as ExpandedAcdcSection;
        Assert.IsNotNull(rule, "The expanded rule section is a block.");
        Assert.IsTrue(rule.Detail.TryGetString(AcdcMessageFields.Said, out string? ruleSaid));
        Assert.AreEqual(AcdcExampleVectors.RuleSectionSaid, ruleSaid);
    }


    /// <summary>
    /// A field-map ACDC with no message type is read as the implied default type, <c>acm</c>.
    /// </summary>
    [TestMethod]
    public void ImpliesAcmWhenMessageTypeAbsent()
    {
        AcdcMessage acdc = AcdcReader.Read(Decode(
            """{"v":"ACDCCAACAAJSONAAF3.","d":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi","i":"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT","s":"EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG"}"""));

        Assert.AreEqual(AcdcMessageTypes.Acdc, acdc.MessageType);
    }


    /// <summary>
    /// An unexpected top-level field is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsUnexpectedTopLevelField()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcReader.Read(Decode(
            """{"v":"v","t":"acm","d":"d","i":"i","s":"s","zz":"y"}""")));
    }


    /// <summary>
    /// Top-level fields out of the canonical order are rejected: here the message type follows the SAID.
    /// </summary>
    [TestMethod]
    public void RejectsFieldsOutOfCanonicalOrder()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcReader.Read(Decode(
            """{"v":"v","d":"d","t":"acm","i":"i","s":"s"}""")));
    }


    /// <summary>
    /// A missing required field (here the schema) is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsMissingRequiredField()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcReader.Read(Decode(
            """{"v":"v","t":"acm","d":"d","i":"i"}""")));
    }


    /// <summary>
    /// The attribute and aggregate sections are mutually exclusive.
    /// </summary>
    [TestMethod]
    public void RejectsBothAttributeAndAggregate()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcReader.Read(Decode(
            """{"v":"v","t":"acm","d":"d","i":"i","s":"s","a":"a","A":"A"}""")));
    }


    /// <summary>
    /// An ACDC carrying the aggregate section <c>A</c> as its compact AGID is read: the attribute section is null and
    /// the aggregate section carries the AGID with no disclosed blocks.
    /// </summary>
    [TestMethod]
    public void ReadsCompactAggregateSection()
    {
        AcdcMessage acdc = AcdcReader.Read(Decode(
            """{"v":"v","t":"acm","d":"d","i":"i","s":"s","A":"EAggregateIdentifierCompactPlaceholderValueXXXXXXXXX"}"""));

        Assert.IsNull(acdc.Attribute, "An aggregate ACDC carries no attribute section.");
        Assert.IsNotNull(acdc.Aggregate, "The aggregate section is read into the typed message.");
        Assert.AreEqual("EAggregateIdentifierCompactPlaceholderValueXXXXXXXXX", acdc.Aggregate.Agid);
        Assert.HasCount(0, acdc.Aggregate.Blocks);
    }


    /// <summary>
    /// An ACDC whose aggregate section <c>A</c> is a blinded attribute list is read: the aggregate carries the AGID
    /// and its blocks in order, each a blinded SAID or a revealed detail block.
    /// </summary>
    [TestMethod]
    public void ReadsExpandedAggregateSection()
    {
        AcdcMessage acdc = AcdcReader.Read(Decode(
            """{"v":"v","t":"acm","d":"d","i":"i","s":"s","A":["EAggregateIdentifier","EBlindedBlockSaid",{"d":"ERevealedBlockSaid","u":"0AwRUUID","score":"42"}]}"""));

        Assert.IsNull(acdc.Attribute, "An aggregate ACDC carries no attribute section.");
        Assert.IsNotNull(acdc.Aggregate, "The aggregate section is read into the typed message.");
        Assert.AreEqual("EAggregateIdentifier", acdc.Aggregate.Agid);
        Assert.HasCount(2, acdc.Aggregate.Blocks);
        Assert.IsInstanceOfType<CompactAggregateBlock>(acdc.Aggregate.Blocks[0], "The first block is blinded to its SAID.");
        Assert.IsInstanceOfType<ExpandedAggregateBlock>(acdc.Aggregate.Blocks[1], "The second block is revealed as its detail.");
    }


    /// <summary>
    /// A field-map ACDC whose message type is a fixed-field native type is rejected by the field-map reader.
    /// </summary>
    [TestMethod]
    public void RejectsFixedFieldMessageType()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcReader.Read(Decode(
            """{"v":"v","t":"act","d":"d","i":"i","s":"s"}""")));
    }


    private static MessageFieldMap Decode(string json) => AcdcJson.DecodeFieldMap(Encoding.UTF8.GetBytes(json));


    private static void AssertCompactSection(AcdcSection? section, string expectedSaid)
    {
        var compact = section as CompactAcdcSection;
        Assert.IsNotNull(compact, "Expected a compact (SAID) section.");
        Assert.AreEqual(expectedSaid, compact.Said);
    }
}
