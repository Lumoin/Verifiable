using System.Collections.Generic;
using System.Linq;
using Verifiable.Acdc;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Tests for <see cref="AcdcMessageFields"/> and <see cref="AcdcMessageTypes"/> — the ACDC wire vocabulary. The
/// field labels and message type values are pinned to their specification wire forms, the canonical top-level order
/// and required-field set are checked against the specification's top-level fields table, and the message-type
/// classification (ACDC body, section message, registry message) is checked against the specification's message
/// type table.
/// </summary>
[TestClass]
internal sealed class AcdcMessageVocabularyTests
{
    /// <summary>
    /// The reserved field labels carry their compact specification wire forms.
    /// </summary>
    [TestMethod]
    public void FieldLabelsAreTheSpecificationWireForms()
    {
        Assert.AreEqual("v", AcdcMessageFields.Version);
        Assert.AreEqual("t", AcdcMessageFields.MessageType);
        Assert.AreEqual("d", AcdcMessageFields.Said);
        Assert.AreEqual("u", AcdcMessageFields.Uuid);
        Assert.AreEqual("i", AcdcMessageFields.Issuer);
        Assert.AreEqual("rd", AcdcMessageFields.RegistryDigest);
        Assert.AreEqual("s", AcdcMessageFields.Schema);
        Assert.AreEqual("a", AcdcMessageFields.Attribute);
        Assert.AreEqual("A", AcdcMessageFields.AttributeAggregate);
        Assert.AreEqual("e", AcdcMessageFields.Edge);
        Assert.AreEqual("r", AcdcMessageFields.Rule);
        Assert.AreEqual("dt", AcdcMessageFields.Datetime);
        Assert.AreEqual("n", AcdcMessageFields.Node);
        Assert.AreEqual("o", AcdcMessageFields.Operator);
        Assert.AreEqual("w", AcdcMessageFields.Weight);
        Assert.AreEqual("l", AcdcMessageFields.LegalLanguage);
    }


    /// <summary>
    /// The top-level fields appear in the canonical order the specification fixes: <c>[v, t, d, u, i, rd, s, a, A, e, r]</c>.
    /// The wire form of each label is pinned in <see cref="FieldLabelsAreTheSpecificationWireForms"/>; this verifies
    /// the order against those well-known labels.
    /// </summary>
    [TestMethod]
    public void TopLevelFieldOrderIsCanonical()
    {
        IReadOnlyList<string> order = AcdcMessageFields.TopLevelFieldOrder;
        Assert.HasCount(11, order);
        Assert.AreEqual(AcdcMessageFields.Version, order[0]);
        Assert.AreEqual(AcdcMessageFields.MessageType, order[1]);
        Assert.AreEqual(AcdcMessageFields.Said, order[2]);
        Assert.AreEqual(AcdcMessageFields.Uuid, order[3]);
        Assert.AreEqual(AcdcMessageFields.Issuer, order[4]);
        Assert.AreEqual(AcdcMessageFields.RegistryDigest, order[5]);
        Assert.AreEqual(AcdcMessageFields.Schema, order[6]);
        Assert.AreEqual(AcdcMessageFields.Attribute, order[7]);
        Assert.AreEqual(AcdcMessageFields.AttributeAggregate, order[8]);
        Assert.AreEqual(AcdcMessageFields.Edge, order[9]);
        Assert.AreEqual(AcdcMessageFields.Rule, order[10]);
    }


    /// <summary>
    /// The required top-level fields are <c>[v, d, i, s]</c>, and each is part of the canonical order.
    /// </summary>
    [TestMethod]
    public void RequiredFieldsAreTheSpecificationRequiredSet()
    {
        IReadOnlyList<string> required = AcdcMessageFields.RequiredFields;
        Assert.HasCount(4, required);
        Assert.AreEqual(AcdcMessageFields.Version, required[0]);
        Assert.AreEqual(AcdcMessageFields.Said, required[1]);
        Assert.AreEqual(AcdcMessageFields.Issuer, required[2]);
        Assert.AreEqual(AcdcMessageFields.Schema, required[3]);
        Assert.IsTrue(required.All(AcdcMessageFields.TopLevelFieldOrder.Contains), "Every required field is a top-level field.");
    }


    /// <summary>
    /// The section fields are <c>[s, a, A, e, r]</c>, and the SAID-compactable subset excludes the aggregate <c>A</c>,
    /// whose compact form is its aggregate value rather than a SAID.
    /// </summary>
    [TestMethod]
    public void SectionFieldsAndSaidableSubset()
    {
        IReadOnlyList<string> sections = AcdcMessageFields.SectionFields;
        Assert.HasCount(5, sections);
        Assert.AreEqual(AcdcMessageFields.Schema, sections[0]);
        Assert.AreEqual(AcdcMessageFields.Attribute, sections[1]);
        Assert.AreEqual(AcdcMessageFields.AttributeAggregate, sections[2]);
        Assert.AreEqual(AcdcMessageFields.Edge, sections[3]);
        Assert.AreEqual(AcdcMessageFields.Rule, sections[4]);

        IReadOnlyList<string> saidable = AcdcMessageFields.SaidableSectionFields;
        Assert.HasCount(4, saidable);
        Assert.AreEqual(AcdcMessageFields.Schema, saidable[0]);
        Assert.AreEqual(AcdcMessageFields.Attribute, saidable[1]);
        Assert.AreEqual(AcdcMessageFields.Edge, saidable[2]);
        Assert.AreEqual(AcdcMessageFields.Rule, saidable[3]);

        Assert.IsTrue(AcdcMessageFields.IsSection(AcdcMessageFields.Attribute));
        Assert.IsTrue(AcdcMessageFields.IsSection(AcdcMessageFields.AttributeAggregate));
        Assert.IsFalse(AcdcMessageFields.IsSection(AcdcMessageFields.Issuer), "The issuer field is not a section field.");
    }


    /// <summary>
    /// Reserved labels are recognized as reserved and an unknown label is not.
    /// </summary>
    [TestMethod]
    public void RecognizesReservedFieldLabels()
    {
        Assert.IsTrue(AcdcMessageFields.IsReserved(AcdcMessageFields.RegistryDigest));
        Assert.IsTrue(AcdcMessageFields.IsReserved(AcdcMessageFields.LegalLanguage));
        Assert.IsFalse(AcdcMessageFields.IsReserved("zz"), "An unknown label is not reserved.");
    }


    /// <summary>
    /// The message type values carry their three-character specification ilk forms.
    /// </summary>
    [TestMethod]
    public void MessageTypesAreTheSpecificationIlkValues()
    {
        Assert.AreEqual("acm", AcdcMessageTypes.Acdc);
        Assert.AreEqual("act", AcdcMessageTypes.AcdcFixedAttribute);
        Assert.AreEqual("acg", AcdcMessageTypes.AcdcFixedAggregate);
        Assert.AreEqual("sch", AcdcMessageTypes.SchemaSection);
        Assert.AreEqual("att", AcdcMessageTypes.AttributeSection);
        Assert.AreEqual("agg", AcdcMessageTypes.AggregateSection);
        Assert.AreEqual("edg", AcdcMessageTypes.EdgeSection);
        Assert.AreEqual("rul", AcdcMessageTypes.RuleSection);
        Assert.AreEqual("rip", AcdcMessageTypes.RegistryInception);
        Assert.AreEqual("upd", AcdcMessageTypes.RegistryUpdate);
    }


    /// <summary>
    /// The three ACDC body types classify as ACDCs; a section message and a registry message do not.
    /// </summary>
    [TestMethod]
    public void ClassifiesAcdcBodies()
    {
        Assert.IsTrue(AcdcMessageTypes.IsAcdc(AcdcMessageTypes.Acdc));
        Assert.IsTrue(AcdcMessageTypes.IsAcdc(AcdcMessageTypes.AcdcFixedAttribute));
        Assert.IsTrue(AcdcMessageTypes.IsAcdc(AcdcMessageTypes.AcdcFixedAggregate));
        Assert.IsFalse(AcdcMessageTypes.IsAcdc(AcdcMessageTypes.SchemaSection), "A schema section message is not an ACDC body.");
        Assert.IsFalse(AcdcMessageTypes.IsAcdc(AcdcMessageTypes.RegistryInception), "A registry inception message is not an ACDC body.");
    }


    /// <summary>
    /// The five section message types classify as section messages; an ACDC body does not.
    /// </summary>
    [TestMethod]
    public void ClassifiesSectionMessages()
    {
        Assert.IsTrue(AcdcMessageTypes.IsSectionMessage(AcdcMessageTypes.SchemaSection));
        Assert.IsTrue(AcdcMessageTypes.IsSectionMessage(AcdcMessageTypes.AttributeSection));
        Assert.IsTrue(AcdcMessageTypes.IsSectionMessage(AcdcMessageTypes.AggregateSection));
        Assert.IsTrue(AcdcMessageTypes.IsSectionMessage(AcdcMessageTypes.EdgeSection));
        Assert.IsTrue(AcdcMessageTypes.IsSectionMessage(AcdcMessageTypes.RuleSection));
        Assert.IsFalse(AcdcMessageTypes.IsSectionMessage(AcdcMessageTypes.Acdc), "An ACDC body is not a section message.");
    }


    /// <summary>
    /// The registry inception and update types classify as registry messages; a section message does not.
    /// </summary>
    [TestMethod]
    public void ClassifiesRegistryMessages()
    {
        Assert.IsTrue(AcdcMessageTypes.IsRegistryMessage(AcdcMessageTypes.RegistryInception));
        Assert.IsTrue(AcdcMessageTypes.IsRegistryMessage(AcdcMessageTypes.RegistryUpdate));
        Assert.IsFalse(AcdcMessageTypes.IsRegistryMessage(AcdcMessageTypes.EdgeSection), "An edge section message is not a registry message.");
    }
}
