using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using Lumoin.Base;
using Verifiable.Cesr;
using Verifiable.Cesr.Streaming;
using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriCountCodeSemantics"/> — the genus-specific meaning of the KERI / ACDC count codes.
/// The classification picks which <see cref="CesrGroupReader"/> walk a consumer runs over a group body the codec
/// framed; the end-to-end tests prove the bridge by classifying a code and then walking a real group body with
/// the walk the classification selects.
/// </summary>
[TestClass]
internal sealed class KeriCountCodeSemanticsTests
{
    private static readonly byte[] DigestRaw = Convert.FromHexString("0ff9dafee5024209554babba1e341af32c637fcaec9e3e65d568ecda03db1ce6");
    private static readonly byte[] SignatureRaw = [.. Enumerable.Range(0, 64).Select(i => (byte)i)];


    /// <summary>
    /// The indexed controller and witness signature groups (<c>-K</c>, <c>-L</c>), in both small and large forms,
    /// are classified as controller and witness signatures respectively; both are indexed signature groups.
    /// </summary>
    [TestMethod]
    public void ClassifiesIndexedSignatureGroups()
    {
        Assert.AreEqual(KeriGroupContent.ControllerSignatures, KeriCountCodeSemantics.Classify("-K"));
        Assert.AreEqual(KeriGroupContent.ControllerSignatures, KeriCountCodeSemantics.Classify("--K"), "The large form classifies the same as the small form.");
        Assert.AreEqual(KeriGroupContent.WitnessSignatures, KeriCountCodeSemantics.Classify("-L"));
        Assert.IsTrue(KeriCountCodeSemantics.IsIndexedSignatureGroup("-K"));
        Assert.IsTrue(KeriCountCodeSemantics.IsIndexedSignatureGroup("-L"));
    }


    /// <summary>
    /// The well-known count codes name the canonical wire strings, and their <c>Is…</c> helpers classify a code —
    /// controller (<c>-K</c>) apart from witness (<c>-L</c>) — recognizing both the small and large forms while
    /// telling controller and witness signature groups apart.
    /// </summary>
    [TestMethod]
    public void WellKnownControllerAndWitnessCodesClassifyByGroup()
    {
        Assert.AreEqual("-K", WellKnownKeriCountCodes.ControllerSignatureGroup);
        Assert.AreEqual("-L", WellKnownKeriCountCodes.WitnessSignatureGroup);

        Assert.IsTrue(WellKnownKeriCountCodes.IsControllerSignatureGroup("-K"));
        Assert.IsTrue(WellKnownKeriCountCodes.IsControllerSignatureGroup("--K"), "The large form is recognized as a controller signature group.");
        Assert.IsFalse(WellKnownKeriCountCodes.IsControllerSignatureGroup("-L"), "A witness signature group is not a controller signature group.");

        Assert.IsTrue(WellKnownKeriCountCodes.IsWitnessSignatureGroup("-L"));
        Assert.IsFalse(WellKnownKeriCountCodes.IsWitnessSignatureGroup("-K"), "A controller signature group is not a witness signature group.");
    }


    /// <summary>
    /// The seal, receipt, and blinded-state groups frame flat primitive tuples.
    /// </summary>
    [TestMethod]
    public void ClassifiesSealAndReceiptGroupsAsPrimitives()
    {
        Assert.AreEqual(KeriGroupContent.Primitives, KeriCountCodeSemantics.Classify("-M"), "Nontransferable receipt couples.");
        Assert.AreEqual(KeriGroupContent.Primitives, KeriCountCodeSemantics.Classify("-Q"), "Digest seal singles.");
        Assert.AreEqual(KeriGroupContent.Primitives, KeriCountCodeSemantics.Classify("--T"), "Anchoring seal triples (large form).");
        Assert.AreEqual(KeriGroupContent.Primitives, KeriCountCodeSemantics.Classify("-a"), "Blinded state quadruples.");
        Assert.IsTrue(KeriCountCodeSemantics.IsPrimitiveGroup("-Q"));
    }


    /// <summary>
    /// The container, message, and mixed/composite groups are classified as nested groups.
    /// </summary>
    [TestMethod]
    public void ClassifiesContainerGroupsAsNested()
    {
        Assert.AreEqual(KeriGroupContent.NestedGroups, KeriCountCodeSemantics.Classify("-A"), "Generic pipeline group.");
        Assert.AreEqual(KeriGroupContent.NestedGroups, KeriCountCodeSemantics.Classify("-B"), "Message + attachments group.");
        Assert.AreEqual(KeriGroupContent.NestedGroups, KeriCountCodeSemantics.Classify("-C"), "Attachments-only group.");
        Assert.AreEqual(KeriGroupContent.NestedGroups, KeriCountCodeSemantics.Classify("-X"), "Transferable indexed-signature group.");
    }


    /// <summary>
    /// A genus/version code frames no group body and is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsGenusVersionCode()
    {
        Assert.ThrowsExactly<CesrFormatException>(() => KeriCountCodeSemantics.Classify(KeriGenus.GenusCode));
    }


    /// <summary>
    /// A code that is not a count code (a bare primitive code) is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonCountCode()
    {
        Assert.ThrowsExactly<CesrFormatException>(() => KeriCountCodeSemantics.Classify("D"));
    }


    /// <summary>
    /// End to end: a body of indexed signatures, classified from its group code, is walked with the indexed
    /// signature walk the classification selects, recovering every signature.
    /// </summary>
    [TestMethod]
    public void WalksIndexedSignatureGroupSelectedBySemantics()
    {
        byte[] first = IndexedBytes("A", SignatureRaw, index: 0);
        byte[] second = IndexedBytes("A", SignatureRaw, index: 2);
        byte[] body = [.. first, .. second];

        Assert.AreEqual(KeriGroupContent.ControllerSignatures, KeriCountCodeSemantics.Classify("-K"));

        var decoded = new List<(string Code, int Index)>();
        foreach(CesrParsedIndexedSignature signature in CesrGroupReader.ReadIndexedSignatures(body, BaseMemoryPool.Shared))
        {
            decoded.Add((signature.Code, signature.Index));
            signature.Dispose();
        }

        Assert.HasCount(2, decoded);
        Assert.AreEqual(("A", 0), decoded[0]);
        Assert.AreEqual(("A", 2), decoded[1]);
    }


    /// <summary>
    /// End to end: a body of digest seal primitives, classified from its group code, is walked with the primitive
    /// walk the classification selects, recovering every primitive.
    /// </summary>
    [TestMethod]
    public void WalksPrimitiveSealGroupSelectedBySemantics()
    {
        byte[] first = PrimitiveBytes("E", DigestRaw);
        byte[] second = PrimitiveBytes("E", DigestRaw);
        byte[] body = [.. first, .. second];

        Assert.AreEqual(KeriGroupContent.Primitives, KeriCountCodeSemantics.Classify("-Q"));

        var decoded = new List<string>();
        foreach(CesrParsedPrimitive primitive in CesrGroupReader.ReadPrimitives(body, BaseMemoryPool.Shared))
        {
            decoded.Add(primitive.Code);
            primitive.Dispose();
        }

        Assert.HasCount(2, decoded);
        Assert.AreEqual("E", decoded[0]);
        Assert.AreEqual("E", decoded[1]);
    }


    private static byte[] PrimitiveBytes(string code, byte[] raw)
    {
        int byteLength = CesrPrimitiveCodec.EncodeText(code, raw).Length * 3 / 4;
        using IMemoryOwner<byte> owner = CesrPrimitiveCodec.EncodeBinary(code, raw, BaseMemoryPool.Shared);

        return owner.Memory.Span[..byteLength].ToArray();
    }


    private static byte[] IndexedBytes(string code, byte[] raw, int index)
    {
        int byteLength = CesrIndexedSignatureCodec.EncodeText(code, raw, index).Length * 3 / 4;
        using IMemoryOwner<byte> owner = CesrIndexedSignatureCodec.EncodeBinary(code, raw, index, BaseMemoryPool.Shared);

        return owner.Memory.Span[..byteLength].ToArray();
    }
}
