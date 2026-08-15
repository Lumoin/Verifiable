using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESTimeStampValidationDataPlacement.TryDetermineBinding"/> against clause 5.5.1.2's
/// "Use of <c>URI</c> attribute" placement protocol of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the adjacent/non-adjacent × <c>URI</c> match/mismatch/absent matrix, and
/// Case B's cross-container binding.
/// </summary>
[TestClass]
internal sealed class XAdESTimeStampValidationDataPlacementTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";


    /// <summary>
    /// <c>UnsignedSignatureProperties</c> carrying, in order: <c>SignatureTimeStamp</c> ("stamp1"), a
    /// <c>TimeStampValidationData</c> IMMEDIATELY AFTER it with a non-matching <c>URI</c> ("adjacentMismatch"),
    /// an unrecognized filler element ("filler1"), a <c>TimeStampValidationData</c> further along with a
    /// matching <c>URI</c> ("nonAdjacentMatch"), one with no <c>URI</c> at all ("nonAdjacentAbsent"), one with
    /// a non-matching <c>URI</c> ("nonAdjacentMismatch"), and one whose <c>URI</c> matches a Case B property
    /// declared OUTSIDE this container entirely ("caseBMatch"). A sibling <c>SignedDataObjectProperties</c>
    /// carries the Case B <c>IndividualDataObjectsTimeStamp</c> ("idots1").
    /// </summary>
    private static string Document() => $$"""
        <root>
          <UnsignedSignatureProperties xmlns="{{V132}}" Id="usp1">
            <SignatureTimeStamp Id="stamp1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></SignatureTimeStamp>
            <TimeStampValidationData xmlns="{{V141}}" Id="adjacentMismatch" URI="#doesNotExist"/>
            <Filler xmlns="{{V141}}" Id="filler1"/>
            <TimeStampValidationData xmlns="{{V141}}" Id="nonAdjacentMatch" URI="#stamp1"/>
            <TimeStampValidationData xmlns="{{V141}}" Id="nonAdjacentAbsent"/>
            <TimeStampValidationData xmlns="{{V141}}" Id="nonAdjacentMismatch" URI="#filler1"/>
            <TimeStampValidationData xmlns="{{V141}}" Id="caseBMatch" URI="#idots1"/>
          </UnsignedSignatureProperties>
          <SignedDataObjectProperties xmlns="{{V132}}">
            <IndividualDataObjectsTimeStamp Id="idots1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></IndividualDataObjectsTimeStamp>
          </SignedDataObjectProperties>
        </root>
        """;


    private static (XmlNodeTable Table, XAdESUnsignedSignatureProperties Container) ReadFixture(BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(Document()), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        bool isFound = table!.TryFindElementById("usp1"u8, out int containerIndex, out _);
        Assert.IsTrue(isFound, "The fixture UnsignedSignatureProperties must resolve by Id.");
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, containerIndex, out XAdESUnsignedSignatureProperties container, out XAdESReadError containerError);
        Assert.IsTrue(isRead, $"The fixture UnsignedSignatureProperties must read but was refused with {containerError.Failure}.");

        return (table, container);
    }


    private static int OrdinalOf(XAdESUnsignedSignatureProperties container, XmlNodeTable table, string id)
    {
        bool isFound = table.TryFindElementById(Encoding.UTF8.GetBytes(id), out int elementIndex, out _);
        Assert.IsTrue(isFound, $"'{id}' must resolve by Id.");
        for(int i = 0; i < container.Properties.Count; ++i)
        {
            if(container.Properties[i].ElementIndex == elementIndex)
            {
                return i;
            }
        }

        Assert.Fail($"'{id}' must be a direct child of the fixture UnsignedSignatureProperties.");

        return -1;
    }


    private static XAdESValidationData ReadTimeStampValidationData(XmlNodeTable table, string id, BaseMemoryPool pool)
    {
        bool isFound = table.TryFindElementById(Encoding.UTF8.GetBytes(id), out int elementIndex, out _);
        Assert.IsTrue(isFound, $"'{id}' must resolve by Id.");
        bool isRead = XAdESValidationData.TryReadTimeStampValidationData(table, elementIndex, pool, out XAdESValidationData? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"'{id}' must read but was refused with {error.Failure}.");

        return value!;
    }


    /// <summary>
    /// Proves clause 5.5.1.2's Case A adjacency rule: immediately-after placement binds even
    /// when the present <c>URI</c> value does not match the target — adjacency wins, the <c>URI</c> is ignored.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.2.
    /// </summary>
    [TestMethod]
    public void AdjacentWithMismatchedUriIsBoundByAdjacency()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(pool);
        using(table)
        {
            bool isFound = table.TryFindElementById("stamp1"u8, out int stampIndex, out _);
            Assert.IsTrue(isFound);
            using XAdESValidationData tsvd = ReadTimeStampValidationData(table, "adjacentMismatch", pool);
            int ordinal = OrdinalOf(container, table, "adjacentMismatch");

            bool isDetermined = XAdESTimeStampValidationDataPlacement.TryDetermineBinding(table, container, ordinal, tsvd, stampIndex, out XAdESTimeStampValidationDataBindingDisposition disposition, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESTimeStampValidationDataBindingDisposition.BoundByAdjacency, disposition);
        }
    }


    /// <summary>
    /// Proves clause 5.5.1.2's non-adjacent rule: a matching <c>URI</c> binds when
    /// adjacency does not already establish the link.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.2.
    /// </summary>
    [TestMethod]
    public void NonAdjacentWithMatchingUriIsBoundByUri()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(pool);
        using(table)
        {
            bool isFound = table.TryFindElementById("stamp1"u8, out int stampIndex, out _);
            Assert.IsTrue(isFound);
            using XAdESValidationData tsvd = ReadTimeStampValidationData(table, "nonAdjacentMatch", pool);
            int ordinal = OrdinalOf(container, table, "nonAdjacentMatch");

            bool isDetermined = XAdESTimeStampValidationDataPlacement.TryDetermineBinding(table, container, ordinal, tsvd, stampIndex, out XAdESTimeStampValidationDataBindingDisposition disposition, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESTimeStampValidationDataBindingDisposition.BoundByUri, disposition);
        }
    }


    /// <summary>
    /// Proves clause 5.5.1.2's validation-time rule: non-adjacent with an ABSENT <c>URI</c>
    /// yields <see cref="XAdESTimeStampValidationDataBindingDisposition.NotBound"/> — a fact, not a refusal
    /// (<c>isDetermined</c> stays <see langword="true"/>).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.2.
    /// </summary>
    [TestMethod]
    public void NonAdjacentWithAbsentUriIsNotBound()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(pool);
        using(table)
        {
            bool isFound = table.TryFindElementById("stamp1"u8, out int stampIndex, out _);
            Assert.IsTrue(isFound);
            using XAdESValidationData tsvd = ReadTimeStampValidationData(table, "nonAdjacentAbsent", pool);
            int ordinal = OrdinalOf(container, table, "nonAdjacentAbsent");

            bool isDetermined = XAdESTimeStampValidationDataPlacement.TryDetermineBinding(table, container, ordinal, tsvd, stampIndex, out XAdESTimeStampValidationDataBindingDisposition disposition, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESTimeStampValidationDataBindingDisposition.NotBound, disposition);
        }
    }


    /// <summary>
    /// Proves clause 5.5.1.2's validation-time rule for a non-matching (rather than absent)
    /// <c>URI</c> when non-adjacent: also <see cref="XAdESTimeStampValidationDataBindingDisposition.NotBound"/>,
    /// not a refusal.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.2.
    /// </summary>
    [TestMethod]
    public void NonAdjacentWithMismatchedUriIsNotBound()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(pool);
        using(table)
        {
            bool isFound = table.TryFindElementById("stamp1"u8, out int stampIndex, out _);
            Assert.IsTrue(isFound);
            using XAdESValidationData tsvd = ReadTimeStampValidationData(table, "nonAdjacentMismatch", pool);
            int ordinal = OrdinalOf(container, table, "nonAdjacentMismatch");

            bool isDetermined = XAdESTimeStampValidationDataPlacement.TryDetermineBinding(table, container, ordinal, tsvd, stampIndex, out XAdESTimeStampValidationDataBindingDisposition disposition, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESTimeStampValidationDataBindingDisposition.NotBound, disposition);
        }
    }


    /// <summary>
    /// Proves Case B: a <c>TimeStampValidationData</c> bound, via <c>URI</c> only (Case B's target,
    /// <c>IndividualDataObjectsTimeStamp</c>, never lives inside <c>UnsignedSignatureProperties</c>, so
    /// adjacency can never establish the link — clause 5.5.1.2's NOTE 2 rationale), to a signed time-stamp
    /// container declared under a SIBLING <c>SignedDataObjectProperties</c> container entirely.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.2.
    /// </summary>
    [TestMethod]
    public void CaseBBindsAcrossContainersByUri()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(pool);
        using(table)
        {
            bool isFound = table.TryFindElementById("idots1"u8, out int idotsIndex, out _);
            Assert.IsTrue(isFound);
            using XAdESValidationData tsvd = ReadTimeStampValidationData(table, "caseBMatch", pool);
            int ordinal = OrdinalOf(container, table, "caseBMatch");

            bool isDetermined = XAdESTimeStampValidationDataPlacement.TryDetermineBinding(table, container, ordinal, tsvd, idotsIndex, out XAdESTimeStampValidationDataBindingDisposition disposition, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESTimeStampValidationDataBindingDisposition.BoundByUri, disposition);
        }
    }


    /// <summary>
    /// Proves the table-identity guard: a foreign table refuses rather than computing against the wrong document. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.2.
    /// </summary>
    [TestMethod]
    public void TableMismatchIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(pool);
        (XmlNodeTable foreignTable, XAdESUnsignedSignatureProperties foreignContainer) = ReadFixture(pool);
        using(table)
        using(foreignTable)
        {
            bool isFound = table.TryFindElementById("stamp1"u8, out int stampIndex, out _);
            Assert.IsTrue(isFound);
            using XAdESValidationData tsvd = ReadTimeStampValidationData(table, "nonAdjacentMatch", pool);
            int ordinal = OrdinalOf(container, table, "nonAdjacentMatch");
            _ = foreignContainer;

            bool isDetermined = XAdESTimeStampValidationDataPlacement.TryDetermineBinding(foreignTable, container, ordinal, tsvd, stampIndex, out _, out XAdESProcessingError error);
            Assert.IsFalse(isDetermined, "A foreign table must refuse rather than computing against the wrong document.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves the table-identity guard extends to <c>unsignedSignatureProperties</c> itself, not only <c>timeStampValidationData</c>: a <c>container</c> read from a SEPARATE
    /// parse of the IDENTICAL document text is refused rather than accepted, even though its own <c>ElementIndex</c> ordinals are numerically identical to <paramref
    /// name="table"/>'s own (deterministic parsing assigns the same integer offsets to structurally identical documents) — the "adjacentMismatch" entry, whose adjacency
    /// check would otherwise spuriously succeed against <paramref name="table"/>'s own <c>stamp1</c> index by sheer numeric coincidence, is the fixture chosen specifically
    /// to exercise the adjacency branch this guard protects. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.2.
    /// </summary>
    [TestMethod]
    public void UnsignedSignaturePropertiesFromForeignTableIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, _) = ReadFixture(pool);
        (XmlNodeTable foreignTable, XAdESUnsignedSignatureProperties foreignContainer) = ReadFixture(pool);
        using(table)
        using(foreignTable)
        {
            bool isFound = table.TryFindElementById("stamp1"u8, out int stampIndex, out _);
            Assert.IsTrue(isFound);
            using XAdESValidationData tsvd = ReadTimeStampValidationData(table, "adjacentMismatch", pool);
            int ordinal = OrdinalOf(foreignContainer, foreignTable, "adjacentMismatch");

            bool isDetermined = XAdESTimeStampValidationDataPlacement.TryDetermineBinding(table, foreignContainer, ordinal, tsvd, stampIndex, out _, out XAdESProcessingError error);
            Assert.IsFalse(isDetermined, "A foreign-table unsignedSignatureProperties must refuse rather than computing against the wrong document.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves the "layer on, no engine change needed" shape: <see cref="XAdESSigAndRefsTimeStampV2"/> joins
    /// Case A's adjacency rule exactly like <c>SignatureTimeStamp</c>/<c>ArchiveTimeStamp</c> without any
    /// change to <see cref="XAdESTimeStampValidationDataPlacement"/> itself, which takes a candidate element
    /// index generically and already covers this property by name.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.2.
    /// </summary>
    [TestMethod]
    public void SigAndRefsTimeStampV2CandidateBindsByAdjacency()
    {
        string document = $$"""
            <root>
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="usp2">
                <SigAndRefsTimeStampV2 xmlns="{{V141}}" Id="sarts1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></SigAndRefsTimeStampV2>
                <TimeStampValidationData xmlns="{{V141}}" Id="tsvd1" URI="#doesNotExist"/>
              </UnsignedSignatureProperties>
            </root>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            bool isContainerFound = table!.TryFindElementById("usp2"u8, out int containerIndex, out _);
            Assert.IsTrue(isContainerFound);
            bool isContainerRead = XAdESUnsignedSignatureProperties.TryRead(table, containerIndex, out XAdESUnsignedSignatureProperties container, out XAdESReadError containerError);
            Assert.IsTrue(isContainerRead, $"The fixture UnsignedSignatureProperties must read but was refused with {containerError.Failure}.");

            bool isCandidateFound = table.TryFindElementById("sarts1"u8, out int candidateIndex, out _);
            Assert.IsTrue(isCandidateFound);
            using XAdESValidationData tsvd = ReadTimeStampValidationData(table, "tsvd1", pool);
            int ordinal = OrdinalOf(container, table, "tsvd1");

            bool isDetermined = XAdESTimeStampValidationDataPlacement.TryDetermineBinding(table, container, ordinal, tsvd, candidateIndex, out XAdESTimeStampValidationDataBindingDisposition disposition, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESTimeStampValidationDataBindingDisposition.BoundByAdjacency, disposition);
        }
    }


    /// <summary>
    /// Proves the same "layer on, no engine change needed" shape for <see cref="XAdESRefsOnlyTimeStampV2"/> via
    /// the non-adjacent <c>URI</c>-match branch, complementing the adjacency proof
    /// <see cref="SigAndRefsTimeStampV2CandidateBindsByAdjacency"/> gives its sibling property.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.2.
    /// </summary>
    [TestMethod]
    public void RefsOnlyTimeStampV2CandidateBindsByUri()
    {
        string document = $$"""
            <root>
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="usp3">
                <RefsOnlyTimeStampV2 xmlns="{{V141}}" Id="rots1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></RefsOnlyTimeStampV2>
                <Filler xmlns="{{V141}}" Id="filler2"/>
                <TimeStampValidationData xmlns="{{V141}}" Id="tsvd2" URI="#rots1"/>
              </UnsignedSignatureProperties>
            </root>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            bool isContainerFound = table!.TryFindElementById("usp3"u8, out int containerIndex, out _);
            Assert.IsTrue(isContainerFound);
            bool isContainerRead = XAdESUnsignedSignatureProperties.TryRead(table, containerIndex, out XAdESUnsignedSignatureProperties container, out XAdESReadError containerError);
            Assert.IsTrue(isContainerRead, $"The fixture UnsignedSignatureProperties must read but was refused with {containerError.Failure}.");

            bool isCandidateFound = table.TryFindElementById("rots1"u8, out int candidateIndex, out _);
            Assert.IsTrue(isCandidateFound);
            using XAdESValidationData tsvd = ReadTimeStampValidationData(table, "tsvd2", pool);
            int ordinal = OrdinalOf(container, table, "tsvd2");

            bool isDetermined = XAdESTimeStampValidationDataPlacement.TryDetermineBinding(table, container, ordinal, tsvd, candidateIndex, out XAdESTimeStampValidationDataBindingDisposition disposition, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESTimeStampValidationDataBindingDisposition.BoundByUri, disposition);
        }
    }
}
