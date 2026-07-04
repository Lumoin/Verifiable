using System.Collections.Generic;
using System.Text;
using Verifiable.Acdc;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Tests for <see cref="AcdcEdgeEvaluation"/>: applying the edge operators that turn a chain of ACDCs into a
/// verifiable chain-of-authority. The conformance case uses the specification's worked Transcript and Accreditation
/// ACDCs — the Transcript's <c>accreditation</c> edge points to the Accreditation ACDC, and the Transcript's Issuer
/// is the Accreditation's Issuee, so the default <c>I2I</c> operator authorizes the Transcript's issuance. The
/// remaining cases drive the unary operators, the m-ary aggregation, and the rejections with constructed edge
/// sub-graphs.
/// </summary>
[TestClass]
internal sealed class AcdcEdgeEvaluationTests
{
    /// <summary>
    /// The Transcript's edge section validates as a chain-of-authority: the Issuer of the Transcript is the Issuee
    /// of the Accreditation ACDC its <c>accreditation</c> edge points to (the default <c>I2I</c> holds), and the
    /// untargeted report edges hold under their <c>NI2I</c> operators, so the whole section is valid. The
    /// authorizing identity is read from the real ACDCs, not asserted by hand.
    /// </summary>
    [TestMethod]
    public void ValidatesI2IChainOfAuthority()
    {
        AcdcMessage transcript = AcdcReader.Read(Decode(AcdcExampleVectors.TranscriptExpanded));
        AcdcEdgeGroup edgeSection = AcdcEdgeReader.Read(Expanded(transcript.Edge));
        AcdcFarNode accreditation = FarNodeFromAcdc(AcdcExampleVectors.ExpandedAcdc);

        //The chain link: the Transcript's Issuer is the Accreditation's Issuee.
        Assert.AreEqual(transcript.Issuer, accreditation.IssueeAid, "The Transcript Issuer must be the Accreditation Issuee for the I2I chain to hold.");

        AcdcFarNodeResolver resolve = nodeSaid => nodeSaid == accreditation.Said
            ? accreditation
            : new AcdcFarNode(nodeSaid, IssueeAid: null, IsValid: true);

        Assert.IsTrue(AcdcEdgeEvaluation.Evaluate(edgeSection, transcript.Issuer, resolve), "The Transcript edge section is a valid chain-of-authority.");
    }


    /// <summary>
    /// The same edge section fails when the near node's Issuer is not the Accreditation's Issuee: the
    /// <c>accreditation</c> edge's <c>I2I</c> operator is not satisfied, so the top-level <c>AND</c> is invalid.
    /// </summary>
    [TestMethod]
    public void RejectsBrokenI2IChain()
    {
        AcdcMessage transcript = AcdcReader.Read(Decode(AcdcExampleVectors.TranscriptExpanded));
        AcdcEdgeGroup edgeSection = AcdcEdgeReader.Read(Expanded(transcript.Edge));
        AcdcFarNode accreditation = FarNodeFromAcdc(AcdcExampleVectors.ExpandedAcdc);

        AcdcFarNodeResolver resolve = nodeSaid => nodeSaid == accreditation.Said
            ? accreditation
            : new AcdcFarNode(nodeSaid, IssueeAid: null, IsValid: true);

        Assert.IsFalse(AcdcEdgeEvaluation.Evaluate(edgeSection, "ENotTheAccreditedIssueeAAAAAAAAAAAAAAAAAAAAAA", resolve), "An Issuer that is not the Accreditation Issuee breaks the I2I chain.");
    }


    /// <summary>
    /// An edge to an untargeted far node holds under the default <c>NI2I</c> operator regardless of the near node's
    /// Issuer, because <c>NI2I</c> imposes no issuer constraint.
    /// </summary>
    [TestMethod]
    public void EvaluatesUntargetedEdgeUnderNi2iDefault()
    {
        AcdcEdgeGroup section = SingleEdge("EFarNodeUntargetedAAAAAAAAAAAAAAAAAAAAAAAAAA", operators: null);
        AcdcFarNodeResolver resolve = nodeSaid => new AcdcFarNode(nodeSaid, IssueeAid: null, IsValid: true);

        Assert.IsTrue(AcdcEdgeEvaluation.Evaluate(section, "EAnyIssuerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", resolve));
    }


    /// <summary>
    /// The <c>NOT</c> operator inverts the far node's validity contribution: a valid far node makes the edge
    /// invalid, and an invalid far node makes it valid.
    /// </summary>
    [TestMethod]
    public void NotOperatorInvertsValidity()
    {
        AcdcEdgeGroup section = SingleEdge("EFarNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", operators: ["NOT", "NI2I"]);

        Assert.IsFalse(AcdcEdgeEvaluation.Evaluate(section, "EIssuerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", _ => new AcdcFarNode("EFarNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", null, IsValid: true)), "NOT over a valid far node is invalid.");
        Assert.IsTrue(AcdcEdgeEvaluation.Evaluate(section, "EIssuerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", _ => new AcdcFarNode("EFarNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", null, IsValid: false)), "NOT over an invalid far node is valid.");
    }


    /// <summary>
    /// The m-ary operators aggregate member validity: <c>AND</c> needs all valid, <c>OR</c> needs one, <c>NAND</c>
    /// is the negation of <c>AND</c>, and <c>NOR</c> the negation of <c>OR</c>.
    /// </summary>
    [TestMethod]
    public void AggregatesMaryOperators()
    {
        //One valid edge (to the valid node) and one invalid edge (to a node the resolver marks invalid), both NI2I.
        const string validNode = "EmemberValidAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        AcdcFarNodeResolver resolve = nodeSaid => new AcdcFarNode(nodeSaid, IssueeAid: null, IsValid: string.Equals(nodeSaid, validNode, System.StringComparison.Ordinal));

        Assert.IsFalse(AcdcEdgeEvaluation.Evaluate(Group("AND"), "EI", resolve), "AND with one invalid member is invalid.");
        Assert.IsTrue(AcdcEdgeEvaluation.Evaluate(Group("OR"), "EI", resolve), "OR with one valid member is valid.");
        Assert.IsTrue(AcdcEdgeEvaluation.Evaluate(Group("NAND"), "EI", resolve), "NAND with one invalid member is valid.");
        Assert.IsFalse(AcdcEdgeEvaluation.Evaluate(Group("NOR"), "EI", resolve), "NOR with one valid member is invalid.");

        static AcdcEdgeGroup Group(string maryOperator) => new(
            null, null, maryOperator, null,
            [
                new AcdcEdgeMember("a", new AcdcEdge(null, null, validNode, null, ["NI2I"], null, null)),
                new AcdcEdgeMember("b", new AcdcEdge(null, null, "EmemberInvalidBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", null, ["NI2I"], null, null))
            ]);
    }


    /// <summary>
    /// An edge whose far node resolves to a different SAID than the edge's node value is invalid: the far node does
    /// not match what the edge points to.
    /// </summary>
    [TestMethod]
    public void RejectsNodeSaidMismatch()
    {
        AcdcEdgeGroup section = SingleEdge("EExpectedNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", operators: ["NI2I"]);
        AcdcFarNodeResolver resolve = _ => new AcdcFarNode("EDifferentNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", IssueeAid: null, IsValid: true);

        Assert.IsFalse(AcdcEdgeEvaluation.Evaluate(section, "EI", resolve));
    }


    /// <summary>
    /// An edge whose far node cannot be resolved is invalid.
    /// </summary>
    [TestMethod]
    public void RejectsUnresolvableFarNode()
    {
        AcdcEdgeGroup section = SingleEdge("EUnresolvableAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", operators: ["NI2I"]);

        Assert.IsFalse(AcdcEdgeEvaluation.Evaluate(section, "EI", _ => null));
    }


    /// <summary>
    /// An edge disclosed only as its compact SAID cannot be evaluated and is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsCompactEdge()
    {
        AcdcEdgeGroup section = new(null, null, null, null, [new AcdcEdgeMember("link", new AcdcCompactEdgeNode("ECompactEdgeSaidAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))]);

        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeEvaluation.Evaluate(section, "EI", _ => new AcdcFarNode("x", null, true)));
    }


    /// <summary>
    /// A DI2I edge that needs a delegation lookup — the near Issuer is not the far node's Issuee — is rejected when
    /// no delegation resolver is supplied, rather than silently narrowed to I2I.
    /// </summary>
    [TestMethod]
    public void RejectsDi2iWithoutDelegationResolver()
    {
        AcdcFarNodeResolver resolve = nodeSaid => new AcdcFarNode(nodeSaid, IssueeAid: "EIssueeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", IsValid: true);

        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeEvaluation.Evaluate(SingleEdge("EFarAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ["DI2I"]), "EI", resolve));
    }


    /// <summary>
    /// The averaging operators, which aggregate a numeric property, are rejected rather than approximated.
    /// </summary>
    [TestMethod]
    public void RejectsAveragingOperators()
    {
        AcdcFarNodeResolver resolve = nodeSaid => new AcdcFarNode(nodeSaid, IssueeAid: "EIssueeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", IsValid: true);

        AcdcEdgeGroup averaging = new(null, null, "AVG", null, [new AcdcEdgeMember("a", new AcdcEdge(null, null, "EFarAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", null, ["NI2I"], null, null))]);
        Assert.ThrowsExactly<AcdcException>(() => AcdcEdgeEvaluation.Evaluate(averaging, "EI", resolve));
    }


    /// <summary>
    /// A DI2I edge is satisfied when the near node's Issuer is the far node's Issuee itself, needing no delegation
    /// lookup (so even the overload without a delegation resolver accepts it).
    /// </summary>
    [TestMethod]
    public void ValidatesDi2iForDirectIssuee()
    {
        const string issueeAid = "EDi2iIssueeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        AcdcEdgeGroup section = SingleEdge("EDi2iFarNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ["DI2I"]);
        AcdcFarNodeResolver resolve = nodeSaid => new AcdcFarNode(nodeSaid, IssueeAid: issueeAid, IsValid: true);

        Assert.IsTrue(AcdcEdgeEvaluation.Evaluate(section, issueeAid, resolve, _ => null), "The far node's Issuee itself satisfies DI2I.");
    }


    /// <summary>
    /// A DI2I edge is satisfied when the near node's Issuer is an AID the far node's Issuee delegated, across one or
    /// more delegation steps: the evaluation walks up the near Issuer's delegation chain to the Issuee.
    /// </summary>
    [TestMethod]
    public void ValidatesDi2iForDelegatedIssuer()
    {
        const string issueeAid = "EDi2iIssueeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const string middleAid = "EDi2iMiddleAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const string leafAid = "EDi2iLeafAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        AcdcEdgeGroup section = SingleEdge("EDi2iFarNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ["DI2I"]);
        AcdcFarNodeResolver resolve = nodeSaid => new AcdcFarNode(nodeSaid, IssueeAid: issueeAid, IsValid: true);

        AcdcDelegationResolver oneStep = aid => aid switch
        {
            leafAid => issueeAid,
            _ => null
        };
        Assert.IsTrue(AcdcEdgeEvaluation.Evaluate(section, leafAid, resolve, oneStep), "An AID directly delegated by the Issuee satisfies DI2I.");

        AcdcDelegationResolver twoStep = aid => aid switch
        {
            leafAid => middleAid,
            middleAid => issueeAid,
            _ => null
        };
        Assert.IsTrue(AcdcEdgeEvaluation.Evaluate(section, leafAid, resolve, twoStep), "An AID delegated transitively through the Issuee satisfies DI2I.");
    }


    /// <summary>
    /// A DI2I edge is rejected when the near node's Issuer is neither the far node's Issuee nor an AID that Issuee
    /// delegated.
    /// </summary>
    [TestMethod]
    public void RejectsDi2iForUnrelatedIssuer()
    {
        const string issueeAid = "EDi2iIssueeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const string strangerAid = "EDi2iStrangerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        AcdcEdgeGroup section = SingleEdge("EDi2iFarNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ["DI2I"]);
        AcdcFarNodeResolver resolve = nodeSaid => new AcdcFarNode(nodeSaid, IssueeAid: issueeAid, IsValid: true);

        //The near Issuer is delegated, but by an unrelated AID, not the far node's Issuee.
        AcdcDelegationResolver unrelated = aid => aid switch
        {
            strangerAid => "EDi2iOtherDelegatorAAAAAAAAAAAAAAAAAAAAAAAAAA",
            _ => null
        };

        Assert.IsFalse(AcdcEdgeEvaluation.Evaluate(section, strangerAid, resolve, unrelated), "An Issuer the far node's Issuee did not delegate does not satisfy DI2I.");
    }


    /// <summary>
    /// A DI2I edge is rejected when its far node is untargeted: the operator requires a targeted far node with an
    /// Issuee to delegate from.
    /// </summary>
    [TestMethod]
    public void RejectsDi2iForUntargetedFarNode()
    {
        AcdcEdgeGroup section = SingleEdge("EDi2iFarNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ["DI2I"]);
        AcdcFarNodeResolver resolve = nodeSaid => new AcdcFarNode(nodeSaid, IssueeAid: null, IsValid: true);

        Assert.IsFalse(AcdcEdgeEvaluation.Evaluate(section, "EAnyIssuerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", resolve, _ => null), "DI2I requires a targeted far node.");
    }


    private static AcdcEdgeGroup SingleEdge(string node, IReadOnlyList<string>? operators) =>
        new(null, null, null, null, [new AcdcEdgeMember("link", new AcdcEdge(null, null, node, null, operators, null, null))]);


    private static AcdcFarNode FarNodeFromAcdc(string expandedAcdcJson)
    {
        AcdcMessage acdc = AcdcReader.Read(Decode(expandedAcdcJson));
        string? issuee = acdc.Attribute is ExpandedAcdcSection attribute && attribute.Detail.TryGetString(AcdcMessageFields.Issuer, out string? aid) ? aid : null;

        return new AcdcFarNode(acdc.Said, issuee, IsValid: true);
    }


    private static MessageFieldMap Expanded(AcdcSection? section) => ((ExpandedAcdcSection)section!).Detail;


    private static MessageFieldMap Decode(string json) => AcdcJson.DecodeFieldMap(Encoding.UTF8.GetBytes(json));
}
