using System.Text;
using Verifiable.Acdc;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Tests for <see cref="AcdcEdgeReader"/> over the JSON decode arm (<see cref="AcdcJson"/>): decode an edge
/// section's expanded block into a neutral field map, then fold that map into a typed <see cref="AcdcEdgeGroup"/>
/// tree. The positive cases use the specification's worked Transcript ACDC edge section
/// (<see cref="AcdcExampleVectors"/>) — a targeted edge alongside a nested <c>OR</c> edge-group of two untargeted
/// edges — in both its fully disclosed and its partially disclosed forms, and the negative cases drive the
/// structural rules the reader enforces for edges and edge-groups.
/// </summary>
[TestClass]
internal sealed class AcdcEdgeReaderTests
{
    /// <summary>
    /// The fully disclosed Transcript edge section folds into the full tree: a top-level edge-group whose members,
    /// in order, are the <c>accreditation</c> edge (with a far node and a far-node schema constraint) and the
    /// <c>reports</c> edge-group (an <c>OR</c> of the <c>research</c> and <c>project</c> edges). Each block's
    /// reserved fields are read and the member order is preserved.
    /// </summary>
    [TestMethod]
    public void ReadsNestedExpandedEdgeSection()
    {
        AcdcEdgeGroup top = AcdcEdgeReader.Read(Decode(AcdcExampleVectors.EdgeSectionExpanded));

        Assert.AreEqual(AcdcExampleVectors.EdgeSectionSaid, top.Said);
        Assert.AreEqual("0ABhY2Rjc3BlY3dvcmtyYXcy", top.Uuid);
        Assert.IsNull(top.Operator, "The top-level edge-group has no explicit operator; the AND default is implied.");
        Assert.IsNull(top.Weight, "The top-level edge-group has no weight.");
        Assert.HasCount(2, top.Members);
        Assert.AreEqual("accreditation", top.Members[0].Label);
        Assert.AreEqual("reports", top.Members[1].Label);

        var accreditation = top.Members[0].Node as AcdcEdge;
        Assert.IsNotNull(accreditation, "The accreditation member is an edge: it has a node 'n' field.");
        Assert.AreEqual(AcdcExampleVectors.AccreditationEdgeSaid, accreditation.Said);
        Assert.AreEqual("0ABhY2Rjc3BlY3dvcmtyYXcz", accreditation.Uuid);
        Assert.AreEqual(AcdcExampleVectors.AccreditationFarNode, accreditation.Node);
        Assert.AreEqual(AcdcExampleVectors.SchemaSaid, accreditation.Schema);
        Assert.IsNull(accreditation.Operators, "The accreditation edge has no explicit operator; the I2I default is implied.");
        Assert.IsNull(accreditation.Properties, "The accreditation edge has no non-reserved property fields.");

        var reports = top.Members[1].Node as AcdcEdgeGroup;
        Assert.IsNotNull(reports, "The reports member is an edge-group: it has no node and nests further edges.");
        Assert.AreEqual(AcdcExampleVectors.ReportsGroupSaid, reports.Said);
        Assert.AreEqual("OR", reports.Operator);
        Assert.HasCount(2, reports.Members);
        Assert.AreEqual("research", reports.Members[0].Label);
        Assert.AreEqual("project", reports.Members[1].Label);

        var research = reports.Members[0].Node as AcdcEdge;
        Assert.IsNotNull(research, "The research member is an edge.");
        Assert.AreEqual(AcdcExampleVectors.ResearchEdgeSaid, research.Said);
        Assert.AreEqual("EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5", research.Node);
        Assert.IsNotNull(research.Operators);
        Assert.HasCount(1, research.Operators);
        Assert.AreEqual("NI2I", research.Operators[0]);

        var project = reports.Members[1].Node as AcdcEdge;
        Assert.IsNotNull(project, "The project member is an edge.");
        Assert.AreEqual(AcdcExampleVectors.ProjectEdgeSaid, project.Said);
        Assert.AreEqual("EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M", project.Node);
    }


    /// <summary>
    /// The partially disclosed edge section — where the nested edge and edge-group are hidden behind their SAIDs —
    /// folds into a top-level edge-group whose two members are each a compact node carrying the hidden block's SAID,
    /// with the classification of the string left to a schema-aware step.
    /// </summary>
    [TestMethod]
    public void ReadsPartiallyDisclosedEdgeSection()
    {
        AcdcEdgeGroup top = AcdcEdgeReader.Read(Decode(AcdcExampleVectors.EdgeSectionPartiallyDisclosed));

        Assert.AreEqual(AcdcExampleVectors.EdgeSectionSaid, top.Said);
        Assert.HasCount(2, top.Members);

        var accreditation = top.Members[0].Node as AcdcCompactEdgeNode;
        Assert.IsNotNull(accreditation, "A hidden edge is disclosed as a compact node.");
        Assert.AreEqual(AcdcExampleVectors.AccreditationEdgeSaid, accreditation.Value);

        var reports = top.Members[1].Node as AcdcCompactEdgeNode;
        Assert.IsNotNull(reports, "A hidden edge-group is disclosed as a compact node.");
        Assert.AreEqual(AcdcExampleVectors.ReportsGroupSaid, reports.Value);
    }


    /// <summary>
    /// A simple-compact edge — a nested edge whose value is the far node's SAID directly — is read as a compact
    /// node, the same neutral form a compact edge's block SAID takes, because the section's schema determines which
    /// a string is.
    /// </summary>
    [TestMethod]
    public void ReadsSimpleCompactEdgeAsCompactNode()
    {
        AcdcEdgeGroup top = AcdcEdgeReader.Read(Decode(
            """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","qvi":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi"}"""));

        Assert.HasCount(1, top.Members);
        var edge = top.Members[0].Node as AcdcCompactEdgeNode;
        Assert.IsNotNull(edge);
        Assert.AreEqual(AcdcExampleVectors.AccreditationFarNode, edge.Value);
    }


    /// <summary>
    /// An edge with multiple unary operators carries them as a list in order.
    /// </summary>
    [TestMethod]
    public void ReadsEdgeOperatorList()
    {
        AcdcEdgeGroup top = AcdcEdgeReader.Read(Decode(
            """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","link":{"n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi","o":["NOT","NI2I"]}}"""));

        var edge = top.Members[0].Node as AcdcEdge;
        Assert.IsNotNull(edge);
        Assert.IsNotNull(edge.Operators);
        Assert.HasCount(2, edge.Operators);
        Assert.AreEqual("NOT", edge.Operators[0]);
        Assert.AreEqual("NI2I", edge.Operators[1]);
    }


    /// <summary>
    /// An edge's non-reserved property fields are preserved in order after its reserved fields.
    /// </summary>
    [TestMethod]
    public void PreservesEdgeProperties()
    {
        AcdcEdgeGroup top = AcdcEdgeReader.Read(Decode(
            """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","link":{"n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi","role":"endorser"}}"""));

        var edge = top.Members[0].Node as AcdcEdge;
        Assert.IsNotNull(edge);
        Assert.IsNotNull(edge.Properties);
        Assert.IsTrue(edge.Properties.TryGetString("role", out string? role));
        Assert.AreEqual("endorser", role);
    }


    /// <summary>
    /// A nested edge-group MAY carry a weight; only the top-level edge-group MUST NOT.
    /// </summary>
    [TestMethod]
    public void ReadsNestedEdgeGroupWeight()
    {
        AcdcEdgeGroup top = AcdcEdgeReader.Read(Decode(
            """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","branch":{"o":"WAVG","w":"0.5","link":{"n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi"}}}"""));

        var branch = top.Members[0].Node as AcdcEdgeGroup;
        Assert.IsNotNull(branch);
        Assert.AreEqual("WAVG", branch.Operator);
        Assert.AreEqual("0.5", branch.Weight);
    }


    /// <summary>
    /// A top-level edge section that is an edge — it carries a node, <c>n</c>, field — is rejected: the top-level
    /// block MUST be an edge-group.
    /// </summary>
    [TestMethod]
    public void RejectsTopLevelEdge()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeReader.Read(Decode(
            """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi"}""")));
    }


    /// <summary>
    /// The top-level edge-group with a weight, <c>w</c>, field is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsTopLevelWeight()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeReader.Read(Decode(
            """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","w":"0.5","link":{"n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi"}}""")));
    }


    /// <summary>
    /// An edge-group with a schema, <c>s</c>, field is rejected: the schema field is an edge-only reserved field.
    /// </summary>
    [TestMethod]
    public void RejectsEdgeGroupWithSchema()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeReader.Read(Decode(
            """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","s":"EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG","link":{"n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi"}}""")));
    }


    /// <summary>
    /// Reserved fields out of the order <c>[d, u, n, s, o, w]</c> are rejected: here the node precedes the SAID.
    /// </summary>
    [TestMethod]
    public void RejectsReservedFieldsOutOfOrder()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeReader.Read(Decode(
            """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","link":{"n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi","d":"EAFj8JaNEC3mdFNJKrXW8E03_k9qqb_xM9NjAPVHw-xJ"}}""")));
    }


    /// <summary>
    /// A UUID without a SAID in an edge block is rejected: the UUID appears only as the second field following the
    /// SAID.
    /// </summary>
    [TestMethod]
    public void RejectsUuidWithoutSaid()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeReader.Read(Decode(
            """{"d":"ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0","link":{"u":"0ABhY2Rjc3BlY3dvcmtyYXcz","n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi"}}""")));
    }


    /// <summary>
    /// A reserved label after a nested member is rejected: the reserved fields MUST appear before any member.
    /// </summary>
    [TestMethod]
    public void RejectsReservedFieldAfterMember()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeReader.Read(Decode(
            """{"link":{"n":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi"},"u":"0ABhY2Rjc3BlY3dvcmtyYXcy"}""")));
    }


    /// <summary>
    /// A member value that is neither a block nor a string is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonBlockNonStringMember()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeReader.Read(Decode(
            """{"link":[1,2,3]}""")));
    }


    /// <summary>
    /// A non-string node, <c>n</c>, field is rejected: a node is the far ACDC's SAID string.
    /// </summary>
    [TestMethod]
    public void RejectsNonStringNode()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeReader.Read(Decode(
            """{"link":{"n":{"d":"EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi"}}}""")));
    }


    private static MessageFieldMap Decode(string json) => AcdcJson.DecodeFieldMap(Encoding.UTF8.GetBytes(json));
}
