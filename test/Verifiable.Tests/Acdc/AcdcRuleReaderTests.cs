using System.Text;
using Verifiable.Acdc;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Tests for <see cref="AcdcRuleReader"/> over the JSON decode arm (<see cref="AcdcJson"/>): decode a rule section's
/// expanded block into a neutral field map, then fold that map into a typed <see cref="AcdcRuleGroup"/> tree. The
/// positive cases use the specification's worked rule sections (<see cref="AcdcExampleVectors"/>) — the
/// Accreditation's single-clause rule section and the richer partially-disclosable nested rule section, in both its
/// fully disclosed and its partially disclosed forms — and the negative cases drive the structural rules the reader
/// enforces for rules and rule-groups.
/// </summary>
[TestClass]
internal sealed class AcdcRuleReaderTests
{
    /// <summary>
    /// The Accreditation rule section — a top-level rule-group that is a single Ricardian clause with only a SAID
    /// and legal language — folds into a rule-group carrying that SAID and legal language with no nested members.
    /// </summary>
    [TestMethod]
    public void ReadsAccreditationRuleSection()
    {
        AcdcRuleGroup group = AcdcRuleReader.Read(Decode(AcdcExampleVectors.RuleSection));

        Assert.AreEqual(AcdcExampleVectors.RuleSectionSaid, group.Said);
        Assert.IsNull(group.Uuid);
        Assert.AreEqual("Issuer provides this ACDC on an AS IS basis. This ACDC in whole or in part MUST NOT be shared with any other entity besides the intended recipient.", group.Legal);
        Assert.IsEmpty(group.Members, "The Accreditation rule section has no nested members.");
    }


    /// <summary>
    /// The fully disclosed nested rule section folds into the full tree: a top-level rule-group whose members, in
    /// order, are the <c>disclaimers</c> rule-group (itself holding the <c>warrantyDisclaimer</c> and
    /// <c>liabilityDisclaimer</c> rules) and the <c>permittedUse</c> rule. Each block's SAID, UUID, and legal
    /// language are read, and the member order is preserved.
    /// </summary>
    [TestMethod]
    public void ReadsNestedExpandedRuleSection()
    {
        AcdcRuleGroup top = AcdcRuleReader.Read(Decode(AcdcExampleVectors.NestedRuleSectionExpanded));

        Assert.AreEqual(AcdcExampleVectors.NestedRuleSectionSaid, top.Said);
        Assert.AreEqual("0ABhY2Rjc3BlY3dvcmtyYXcw", top.Uuid);
        Assert.IsNull(top.Legal, "The top-level rule-group has no legal language of its own.");
        Assert.HasCount(2, top.Members);
        Assert.AreEqual("disclaimers", top.Members[0].Label);
        Assert.AreEqual("permittedUse", top.Members[1].Label);

        var disclaimers = top.Members[0].Node as AcdcRuleGroup;
        Assert.IsNotNull(disclaimers, "The disclaimers member is a rule-group: it nests further rules.");
        Assert.AreEqual(AcdcExampleVectors.DisclaimersGroupSaid, disclaimers.Said);
        Assert.AreEqual("0ABhY2Rjc3BlY3dvcmtyYXcx", disclaimers.Uuid);
        Assert.AreEqual("The person or legal entity identified by this ACDC's Issuer AID (Issuer) makes the following disclaimers:", disclaimers.Legal);
        Assert.HasCount(2, disclaimers.Members);
        Assert.AreEqual("warrantyDisclaimer", disclaimers.Members[0].Label);
        Assert.AreEqual("liabilityDisclaimer", disclaimers.Members[1].Label);

        var warranty = disclaimers.Members[0].Node as AcdcRule;
        Assert.IsNotNull(warranty, "The warrantyDisclaimer member is a rule: a terminal clause.");
        Assert.AreEqual(AcdcExampleVectors.WarrantyDisclaimerSaid, warranty.Said);
        Assert.AreEqual("0ABhY2Rjc3BlY3dvcmtyYXcy", warranty.Uuid);
        Assert.AreEqual("Issuer provides this ACDC on an AS IS basis.", warranty.Legal);

        var liability = disclaimers.Members[1].Node as AcdcRule;
        Assert.IsNotNull(liability, "The liabilityDisclaimer member is a rule.");
        Assert.AreEqual(AcdcExampleVectors.LiabilityDisclaimerSaid, liability.Said);
        Assert.AreEqual("The Issuer SHALL NOT be liable for ANY damages arising as a result of this credential.", liability.Legal);

        var permittedUse = top.Members[1].Node as AcdcRule;
        Assert.IsNotNull(permittedUse, "The permittedUse member is a rule.");
        Assert.AreEqual(AcdcExampleVectors.PermittedUseSaid, permittedUse.Said);
        Assert.AreEqual("0ABhY2Rjc3BlY3dvcmtyYXc0", permittedUse.Uuid);
        Assert.AreEqual("The Issuee (controller of the Issuee AID) MAY only use this ACDC for non-commercial purposes.", permittedUse.Legal);
    }


    /// <summary>
    /// The partially disclosed nested rule section — where the nested rule-group and rule are hidden behind their
    /// SAIDs — folds into a top-level rule-group whose two members are each a compact node carrying the hidden
    /// block's SAID, with the classification of the string left to a schema-aware step.
    /// </summary>
    [TestMethod]
    public void ReadsPartiallyDisclosedRuleSection()
    {
        AcdcRuleGroup top = AcdcRuleReader.Read(Decode(AcdcExampleVectors.NestedRuleSectionPartiallyDisclosed));

        Assert.AreEqual(AcdcExampleVectors.NestedRuleSectionSaid, top.Said);
        Assert.HasCount(2, top.Members);

        var disclaimers = top.Members[0].Node as AcdcCompactRuleNode;
        Assert.IsNotNull(disclaimers, "A hidden rule-group is disclosed as a compact node.");
        Assert.AreEqual(AcdcExampleVectors.DisclaimersGroupSaid, disclaimers.Value);

        var permittedUse = top.Members[1].Node as AcdcCompactRuleNode;
        Assert.IsNotNull(permittedUse, "A hidden rule is disclosed as a compact node.");
        Assert.AreEqual(AcdcExampleVectors.PermittedUseSaid, permittedUse.Value);
    }


    /// <summary>
    /// A simple-compact rule — a nested rule whose value is a string — is read as a compact node, the same neutral
    /// form a compact SAID takes, because a string at a non-reserved label is the legal language or the SAID as the
    /// section's schema determines.
    /// </summary>
    [TestMethod]
    public void ReadsSimpleCompactRuleAsCompactNode()
    {
        AcdcRuleGroup group = AcdcRuleReader.Read(Decode(
            """{"l":"The following disclaimers apply:","warrantyDisclaimer":"Issuer provides this ACDC on an AS IS basis."}"""));

        Assert.AreEqual("The following disclaimers apply:", group.Legal);
        Assert.HasCount(1, group.Members);
        var rule = group.Members[0].Node as AcdcCompactRuleNode;
        Assert.IsNotNull(rule);
        Assert.AreEqual("Issuer provides this ACDC on an AS IS basis.", rule.Value);
    }


    /// <summary>
    /// A nested rule with no legal language is rejected: a rule MUST have a legal, <c>l</c>, field.
    /// </summary>
    [TestMethod]
    public void RejectsRuleWithoutLegal()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcRuleReader.Read(Decode(
            """{"permittedUse":{"d":"Edddddddddddddddddddddddddddddddddddddddddddd","u":"0ABhY2Rjc3BlY3dvcmtyYXc0"}}""")));
    }


    /// <summary>
    /// Reserved fields out of the order <c>[d, u, l]</c> are rejected: here the UUID precedes the SAID.
    /// </summary>
    [TestMethod]
    public void RejectsReservedFieldsOutOfOrder()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcRuleReader.Read(Decode(
            """{"u":"0ABhY2Rjc3BlY3dvcmtyYXcw","d":"Edddddddddddddddddddddddddddddddddddddddddddd"}""")));
    }


    /// <summary>
    /// A reserved field after a nested member is rejected: the reserved fields MUST appear before any nested rule
    /// or rule-group.
    /// </summary>
    [TestMethod]
    public void RejectsReservedFieldAfterMember()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcRuleReader.Read(Decode(
            """{"warrantyDisclaimer":"Issuer provides this ACDC on an AS IS basis.","l":"Trailing legal language."}""")));
    }


    /// <summary>
    /// A reserved label other than <c>[d, u, l]</c> in a rule block is rejected: only those three are reserved for
    /// a rule or rule-group.
    /// </summary>
    [TestMethod]
    public void RejectsNonRuleReservedField()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcRuleReader.Read(Decode(
            """{"i":"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT","l":"Legal language."}""")));
    }


    /// <summary>
    /// A UUID without a SAID is rejected: the UUID appears only as the second field following the SAID.
    /// </summary>
    [TestMethod]
    public void RejectsUuidWithoutSaid()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcRuleReader.Read(Decode(
            """{"u":"0ABhY2Rjc3BlY3dvcmtyYXcw","l":"Legal language."}""")));
    }


    /// <summary>
    /// A member value that is neither a block nor a string is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonBlockNonStringMember()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcRuleReader.Read(Decode(
            """{"warrantyDisclaimer":[1,2,3]}""")));
    }


    private static MessageFieldMap Decode(string json) => AcdcJson.DecodeFieldMap(Encoding.UTF8.GetBytes(json));
}
