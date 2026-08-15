using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESRefsOnlyTimeStampV2Imprint"/> against clause A.1.5.2.2 (not-distributed) and clause
/// A.1.5.2.3 (distributed) message-imprint computation of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the narrower four-property covered set (no <c>ds:SignatureValue</c>/
/// <c>SignatureTimeStamp</c> coverage, unlike <see cref="XAdESSigAndRefsTimeStampV2Imprint"/>), the
/// preceding-boundary filter, and the distributed case's <c>Include</c>-order/comment-deletion rules.
/// </summary>
[TestClass]
internal sealed class XAdESRefsOnlyTimeStampV2ImprintTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private const string ExclusiveC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";


    private static string Document(string usspBody) => $$"""
        <root xmlns:ds="{{DsNamespace}}" xmlns:xadesv2="{{V141}}">
          <UnsignedSignatureProperties xmlns="{{V132}}" Id="usp1">
            {{usspBody}}
          </UnsignedSignatureProperties>
        </root>
        """;


    private static (XmlNodeTable Table, XAdESUnsignedSignatureProperties Container, XAdESRefsOnlyTimeStampV2 Stamp) ReadFixture(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        bool isContainerFound = table!.TryFindElementById("usp1"u8, out int containerIndex, out _);
        Assert.IsTrue(isContainerFound, "The fixture UnsignedSignatureProperties must resolve by Id.");
        bool isContainerRead = XAdESUnsignedSignatureProperties.TryRead(table, containerIndex, out XAdESUnsignedSignatureProperties container, out XAdESReadError containerError);
        Assert.IsTrue(isContainerRead, $"The fixture UnsignedSignatureProperties must read but was refused with {containerError.Failure}.");

        bool isStampFound = table.TryFindElementById("rots1"u8, out int stampIndex, out _);
        Assert.IsTrue(isStampFound, "The fixture RefsOnlyTimeStampV2 must resolve by Id.");
        bool isStampRead = XAdESRefsOnlyTimeStampV2.TryRead(table, stampIndex, pool, out XAdESRefsOnlyTimeStampV2? stamp, out XAdESReadError stampError);
        Assert.IsTrue(isStampRead, $"The fixture RefsOnlyTimeStampV2 must read but was refused with {stampError.Failure}.");

        return (table!, container, stamp!);
    }


    private static byte[] CanonicalizeById(XmlNodeTable table, string id, BaseMemoryPool pool, XmlCanonicalizationAlgorithm algorithm, bool withoutComments = false)
    {
        bool isFound = table.TryFindElementById(Encoding.UTF8.GetBytes(id), out int elementIndex, out _);
        Assert.IsTrue(isFound, $"'{id}' must resolve by Id.");
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, elementIndex);
        if(withoutComments)
        {
            nodeSet = nodeSet.WithoutComments();
        }

        bool isCanonicalized = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(table, nodeSet, algorithm, ReadOnlySpan<byte>.Empty, pool, out PooledMemory? canonical, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"'{id}' must canonicalize but was refused with {error.Failure}.");
        using(canonical)
        {
            return canonical!.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// Proves the not-distributed algorithm end to end: the imprint equals every one of the four covered
    /// property TYPES — the v1.4.1-namespace <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c>
    /// and the v1.3.2-namespace <c>CompleteRevocationRefs</c>/<c>AttributeRevocationRefs</c> — that PRECEDE
    /// <c>RefsOnlyTimeStampV2</c>, in document order, with NO <c>ds:SignatureValue</c> contribution (contrast
    /// <see cref="XAdESSigAndRefsTimeStampV2Imprint"/>): a preceding <c>SignatureTimeStamp</c> is excluded because
    /// it is not one of A.1.5.2.1's four covered types, and a second <c>CompleteRevocationRefs</c> placed AFTER
    /// the candidate is excluded by the preceding-boundary.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.2.2.
    /// </summary>
    [TestMethod]
    public void NotDistributedImprintCoversOnlyPrecedingFourRefsPropertiesNoSignatureValue()
    {
        string usspBody = $$"""
            <SignatureTimeStamp Id="st1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></SignatureTimeStamp>
            <xadesv2:CompleteCertificateRefsV2 Id="ccr1"/>
            <CompleteRevocationRefs Id="crr1"/>
            <xadesv2:AttributeCertificateRefsV2 Id="acr1"/>
            <AttributeRevocationRefs Id="arr1"/>
            <xadesv2:RefsOnlyTimeStampV2 Id="rots1"><ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:RefsOnlyTimeStampV2>
            <CompleteRevocationRefs Id="crr2"/>
            """;
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container, XAdESRefsOnlyTimeStampV2 stamp) = ReadFixture(document, pool);
        using(table)
        using(stamp)
        {
            XmlCanonicalizationAlgorithm algorithm = XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10;
            byte[] expected =
            [
                .. CanonicalizeById(table, "ccr1", pool, algorithm),
                .. CanonicalizeById(table, "crr1", pool, algorithm),
                .. CanonicalizeById(table, "acr1", pool, algorithm),
                .. CanonicalizeById(table, "arr1", pool, algorithm),
            ];

            bool isComputed = XAdESRefsOnlyTimeStampV2Imprint.TryComputeNotDistributedImprintInput(table, stamp, container, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves the not-distributed engine's own empty-selection floor: zero covered properties preceding the
    /// candidate yields empty (never null) octets, mirroring the shared reference-list engine's own
    /// "initialize the final octet stream as empty" vacuous-satisfaction posture.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.2.2.
    /// </summary>
    [TestMethod]
    public void NotDistributedImprintWithNoPrecedingCoveredPropertiesIsEmpty()
    {
        string usspBody = """<xadesv2:RefsOnlyTimeStampV2 Id="rots1"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:RefsOnlyTimeStampV2>""";
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container, XAdESRefsOnlyTimeStampV2 stamp) = ReadFixture(document, pool);
        using(table)
        using(stamp)
        {
            bool isComputed = XAdESRefsOnlyTimeStampV2Imprint.TryComputeNotDistributedImprintInput(table, stamp, container, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.HasCount(0, imprintInput!.AsReadOnlySpan());
            }
        }
    }


    /// <summary>
    /// Proves the distributed variant's own ordering rule: the <c>Include</c> elements' OWN document order — here
    /// deliberately reversed relative to BOTH the covered properties' own document order (<c>ccr1</c> appears
    /// before <c>arr1</c>) AND A.1.5.2.1's "listed order" of covered types (<c>CompleteCertificateRefsV2</c>
    /// before <c>AttributeRevocationRefs</c>) — governs concatenation order, not either of those, and with NO
    /// implicit <c>ds:SignatureValue</c> step. Comment nodes are deleted; a <c>WithComments</c> algorithm makes a
    /// surviving comment visible if deletion did not happen.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.2.3.
    /// </summary>
    [TestMethod]
    public void DistributedImprintUsesIncludeOrderNotListedOrderAndDeletesComments()
    {
        string usspBody = $$"""
            <xadesv2:CompleteCertificateRefsV2 Id="ccr1"><!--comment-ccr--><Data>CCR</Data></xadesv2:CompleteCertificateRefsV2>
            <AttributeRevocationRefs Id="arr1"><!--comment-arr--><Data>ARR</Data></AttributeRevocationRefs>
            <xadesv2:RefsOnlyTimeStampV2 Id="rots1">
              <Include URI="#arr1"/>
              <Include URI="#ccr1"/>
              <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14NWithComments}}"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </xadesv2:RefsOnlyTimeStampV2>
            """;
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container, XAdESRefsOnlyTimeStampV2 stamp) = ReadFixture(document, pool);
        using(table)
        using(stamp)
        {
            Assert.HasCount(2, stamp.TimeStamp.Includes);
            XmlCanonicalizationAlgorithm algorithm = XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments;
            byte[] expected =
            [
                .. CanonicalizeById(table, "arr1", pool, algorithm, withoutComments: true),
                .. CanonicalizeById(table, "ccr1", pool, algorithm, withoutComments: true),
            ];

            bool isComputed = XAdESRefsOnlyTimeStampV2Imprint.TryComputeDistributedImprintInput(table, stamp, container, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                byte[] actual = imprintInput!.AsReadOnlySpan().ToArray();
                Assert.AreSequenceEqual(expected, actual);

                byte[] arrWithComments = CanonicalizeById(table, "arr1", pool, algorithm, withoutComments: false);
                byte[] arrWithoutComments = CanonicalizeById(table, "arr1", pool, algorithm, withoutComments: true);
                Assert.IsGreaterThan(arrWithoutComments.Length, arrWithComments.Length);
            }
        }
    }


    /// <summary>
    /// Proves clause A.1.5.2.3's "each listed property" membership restriction: a relocated-decoy attack — the genuine <c>Include</c> target (<c>AttributeRevocationRefs</c>,
    /// one of the four covered types) moved OUT of <c>UnsignedSignatureProperties</c> (same <c>Id</c>, same content, so no duplicate-<c>Id</c> refusal fires) to a
    /// document-level sibling, with a forged replacement inserted in its place — refuses with <see cref="XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty"/>
    /// rather than silently canonicalizing the relocated original. The honest sibling document, where the same property legitimately sits inside
    /// <c>UnsignedSignatureProperties</c>, computes successfully. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.2.3.
    /// </summary>
    [TestMethod]
    public void DistributedIncludeTargetRelocatedOutsideContainerIsRefused()
    {
        string honestDocument = $$"""
            <root xmlns:ds="{{DsNamespace}}" xmlns:xadesv2="{{V141}}">
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="usp1">
                <AttributeRevocationRefs Id="arr1"><Data>ORIGINAL</Data></AttributeRevocationRefs>
                <xadesv2:RefsOnlyTimeStampV2 Id="rots1">
                  <Include URI="#arr1"/>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
                </xadesv2:RefsOnlyTimeStampV2>
              </UnsignedSignatureProperties>
            </root>
            """;
        string attackedDocument = $$"""
            <root xmlns:ds="{{DsNamespace}}" xmlns:xadesv2="{{V141}}">
              <AttributeRevocationRefs xmlns="{{V132}}" Id="arr1"><Data>ORIGINAL</Data></AttributeRevocationRefs>
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="usp1">
                <AttributeRevocationRefs Id="arr1-forged"><Data>FORGED</Data></AttributeRevocationRefs>
                <xadesv2:RefsOnlyTimeStampV2 Id="rots1">
                  <Include URI="#arr1"/>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
                </xadesv2:RefsOnlyTimeStampV2>
              </UnsignedSignatureProperties>
            </root>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable honestTable, XAdESUnsignedSignatureProperties honestContainer, XAdESRefsOnlyTimeStampV2 honestStamp) = ReadFixture(honestDocument, pool);
        using(honestTable)
        using(honestStamp)
        {
            bool isHonestComputed = XAdESRefsOnlyTimeStampV2Imprint.TryComputeDistributedImprintInput(
                honestTable, honestStamp, honestContainer, pool, out PooledMemory? honestImprintInput, out XAdESProcessingError honestError);
            Assert.IsTrue(isHonestComputed, $"The honest document must compute but was refused with {honestError.Failure}.");
            honestImprintInput!.Dispose();
        }

        (XmlNodeTable attackedTable, XAdESUnsignedSignatureProperties attackedContainer, XAdESRefsOnlyTimeStampV2 attackedStamp) = ReadFixture(attackedDocument, pool);
        using(attackedTable)
        using(attackedStamp)
        {
            bool isAttackedComputed = XAdESRefsOnlyTimeStampV2Imprint.TryComputeDistributedImprintInput(
                attackedTable, attackedStamp, attackedContainer, pool, out PooledMemory? attackedImprintInput, out XAdESProcessingError attackedError);
            Assert.IsFalse(isAttackedComputed, "The relocated-decoy attack must be refused rather than producing an imprint.");
            Assert.IsNull(attackedImprintInput);
            Assert.AreEqual(XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty, attackedError.Failure);
        }
    }


    /// <summary>
    /// Proves an absent <c>ds:CanonicalizationMethod</c> on the <c>RefsOnlyTimeStampV2</c> itself refuses rather than assuming a default algorithm. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.2.
    /// </summary>
    [TestMethod]
    public void AbsentCanonicalizationMethodIsRefused()
    {
        string usspBody = """<xadesv2:RefsOnlyTimeStampV2 Id="rots1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:RefsOnlyTimeStampV2>""";
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container, XAdESRefsOnlyTimeStampV2 stamp) = ReadFixture(document, pool);
        using(table)
        using(stamp)
        {
            bool isComputed = XAdESRefsOnlyTimeStampV2Imprint.TryComputeNotDistributedImprintInput(table, stamp, container, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An absent CanonicalizationMethod must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.AbsentCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves the not-distributed engine refuses when the given <c>RefsOnlyTimeStampV2</c> is not itself a member
    /// of the given <c>UnsignedSignatureProperties</c> entry list.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.2.2.
    /// </summary>
    [TestMethod]
    public void NotDistributedNotFoundInContainerIsRefused()
    {
        string document = $$"""
            <root xmlns:ds="{{DsNamespace}}" xmlns:xadesv2="{{V141}}">
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="uspA">
                <xadesv2:RefsOnlyTimeStampV2 Id="rotsA"><ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:RefsOnlyTimeStampV2>
              </UnsignedSignatureProperties>
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="uspB">
                <xadesv2:RefsOnlyTimeStampV2 Id="rotsB"><ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:RefsOnlyTimeStampV2>
              </UnsignedSignatureProperties>
            </root>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            bool isFoundB = table!.TryFindElementById("uspB"u8, out int containerBIndex, out _);
            bool isFoundStampA = table.TryFindElementById("rotsA"u8, out int stampAIndex, out _);
            Assert.IsTrue(isFoundB && isFoundStampA);

            bool isContainerBRead = XAdESUnsignedSignatureProperties.TryRead(table, containerBIndex, out XAdESUnsignedSignatureProperties containerB, out XAdESReadError containerBError);
            Assert.IsTrue(isContainerBRead, $"uspB must read but was refused with {containerBError.Failure}.");
            bool isStampARead = XAdESRefsOnlyTimeStampV2.TryRead(table, stampAIndex, pool, out XAdESRefsOnlyTimeStampV2? stampA, out XAdESReadError stampAError);
            Assert.IsTrue(isStampARead, $"rotsA must read but was refused with {stampAError.Failure}.");
            using(stampA)
            {
                bool isComputed = XAdESRefsOnlyTimeStampV2Imprint.TryComputeNotDistributedImprintInput(
                    table, stampA!, containerB, pool, out _, out XAdESProcessingError error);
                Assert.IsFalse(isComputed, "rotsA is not a member of uspB and must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.RefsOnlyTimeStampV2NotFoundInUnsignedSignatureProperties, error.Failure);
            }
        }
    }


    /// <summary>
    /// Proves the table-identity guard on the not-distributed engine. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.2.2.
    /// </summary>
    [TestMethod]
    public void TableMismatchIsRefused()
    {
        string usspBody = """<xadesv2:RefsOnlyTimeStampV2 Id="rots1"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:RefsOnlyTimeStampV2>""";
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container, XAdESRefsOnlyTimeStampV2 stamp) = ReadFixture(document, pool);
        (XmlNodeTable foreignTable, XAdESUnsignedSignatureProperties foreignContainer, XAdESRefsOnlyTimeStampV2 foreignStamp) = ReadFixture(document, pool);
        using(table)
        using(stamp)
        using(foreignTable)
        using(foreignStamp)
        {
            _ = foreignContainer;
            bool isComputed = XAdESRefsOnlyTimeStampV2Imprint.TryComputeNotDistributedImprintInput(foreignTable, stamp, container, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "A foreign table must refuse rather than computing against the wrong document.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves custody is balanced on the success path via <see cref="MeteredHousePool"/> for the not-distributed
    /// engine: every intermediate buffer rented while canonicalizing is released internally, and only the final
    /// result is handed to the caller.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.2.2.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnSuccessAfterDisposingTheResult()
    {
        string usspBody = """<xadesv2:RefsOnlyTimeStampV2 Id="rots1"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:RefsOnlyTimeStampV2>""";
        string document = Document(usspBody);
        using(var metered = new MeteredHousePool())
        {
            (XmlNodeTable table, XAdESUnsignedSignatureProperties container, XAdESRefsOnlyTimeStampV2 stamp) = ReadFixture(document, metered.Pool);
            using(table)
            using(stamp)
            {
                bool isComputed = XAdESRefsOnlyTimeStampV2Imprint.TryComputeNotDistributedImprintInput(table, stamp, container, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
                imprintInput!.Dispose();
            }
        }
    }
}
