using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSigAndRefsTimeStampV2Imprint"/> against clause A.1.5.1.2 (not-distributed) and
/// clause A.1.5.1.3 (distributed) message-imprint computation of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the implicit <c>ds:SignatureValue</c> contribution both cases share, the
/// preceding-boundary/covered-type filter, and the distributed case's <c>Include</c>-order/comment-deletion
/// rules.
/// </summary>
[TestClass]
internal sealed class XAdESSigAndRefsTimeStampV2ImprintTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private const string ExclusiveC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";


    private static string Document(string usspBody) => $$"""
        <root xmlns:ds="{{DsNamespace}}" xmlns:xadesv2="{{V141}}">
          <ds:Signature Id="sig1">
            <ds:SignedInfo>
              <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
              <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              <ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>QQ==</ds:SignatureValue>
          </ds:Signature>
          <UnsignedSignatureProperties xmlns="{{V132}}" Id="usp1">
            {{usspBody}}
          </UnsignedSignatureProperties>
        </root>
        """;


    private static (XmlNodeTable Table, XmlSignature Signature, XAdESUnsignedSignatureProperties Container, XAdESSigAndRefsTimeStampV2 Stamp) ReadFixture(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices);
        bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");

        bool isContainerFound = table!.TryFindElementById("usp1"u8, out int containerIndex, out _);
        Assert.IsTrue(isContainerFound, "The fixture UnsignedSignatureProperties must resolve by Id.");
        bool isContainerRead = XAdESUnsignedSignatureProperties.TryRead(table, containerIndex, out XAdESUnsignedSignatureProperties container, out XAdESReadError containerError);
        Assert.IsTrue(isContainerRead, $"The fixture UnsignedSignatureProperties must read but was refused with {containerError.Failure}.");

        bool isStampFound = table.TryFindElementById("sarts1"u8, out int stampIndex, out _);
        Assert.IsTrue(isStampFound, "The fixture SigAndRefsTimeStampV2 must resolve by Id.");
        bool isStampRead = XAdESSigAndRefsTimeStampV2.TryRead(table, stampIndex, pool, out XAdESSigAndRefsTimeStampV2? stamp, out XAdESReadError stampError);
        Assert.IsTrue(isStampRead, $"The fixture SigAndRefsTimeStampV2 must read but was refused with {stampError.Failure}.");

        return (table!, signature!, container, stamp!);
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


    private static byte[] Canonicalize(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, XmlCanonicalizationAlgorithm algorithm)
    {
        bool isCanonicalized = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(table, XmlNodeSet.ElementSubtree(table, elementIndex), algorithm, ReadOnlySpan<byte>.Empty, pool, out PooledMemory? canonical, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"Element must canonicalize but was refused with {error.Failure}.");
        using(canonical)
        {
            return canonical!.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// Proves the not-distributed algorithm end to end: the imprint equals <c>ds:SignatureValue</c>
    /// (implicit, always first) followed by every one of the five covered property TYPES —
    /// <c>SignatureTimeStamp</c>, the v1.4.1-namespace <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c>,
    /// and the v1.3.2-namespace <c>CompleteRevocationRefs</c>/<c>AttributeRevocationRefs</c> — that PRECEDE
    /// <c>SigAndRefsTimeStampV2</c>, in document order; a SECOND <c>SignatureTimeStamp</c> placed AFTER the
    /// candidate is excluded, proving the preceding-boundary (the property this test proves, mirroring
    /// <c>XAdESArchiveTimeStampImprint</c>'s own step-5 boundary proof).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.2.
    /// </summary>
    [TestMethod]
    public void NotDistributedImprintCoversSignatureValueThenPrecedingCoveredPropertiesOnly()
    {
        string usspBody = $$"""
            <SignatureTimeStamp Id="st1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></SignatureTimeStamp>
            <xadesv2:CompleteCertificateRefsV2 Id="ccr1"/>
            <CompleteRevocationRefs Id="crr1"/>
            <xadesv2:AttributeCertificateRefsV2 Id="acr1"/>
            <AttributeRevocationRefs Id="arr1"/>
            <xadesv2:SigAndRefsTimeStampV2 Id="sarts1"><ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:SigAndRefsTimeStampV2>
            <SignatureTimeStamp Id="st2"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></SignatureTimeStamp>
            """;
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESSigAndRefsTimeStampV2 stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            XmlCanonicalizationAlgorithm algorithm = XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10;
            byte[] expected =
            [
                .. Canonicalize(table, signature.SignatureValueElementIndex, pool, algorithm),
                .. CanonicalizeById(table, "st1", pool, algorithm),
                .. CanonicalizeById(table, "ccr1", pool, algorithm),
                .. CanonicalizeById(table, "crr1", pool, algorithm),
                .. CanonicalizeById(table, "acr1", pool, algorithm),
                .. CanonicalizeById(table, "arr1", pool, algorithm),
            ];

            bool isComputed = XAdESSigAndRefsTimeStampV2Imprint.TryComputeNotDistributedImprintInput(table, signature, stamp, container, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves the covered-type filter's negative case: a preceding <c>CounterSignature</c> — a legitimate
    /// <c>UnsignedSignatureProperties</c> child, but not one of A.1.5.1.1's five covered types — contributes
    /// nothing, even though it precedes the candidate.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.2.
    /// </summary>
    [TestMethod]
    public void NotDistributedImprintIgnoresUncoveredPrecedingProperty()
    {
        string usspBody = $$"""
            <CounterSignature Id="cs1"><Filler/></CounterSignature>
            <xadesv2:SigAndRefsTimeStampV2 Id="sarts1"><ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:SigAndRefsTimeStampV2>
            """;
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESSigAndRefsTimeStampV2 stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            XmlCanonicalizationAlgorithm algorithm = XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10;
            byte[] expected = Canonicalize(table, signature.SignatureValueElementIndex, pool, algorithm);

            bool isComputed = XAdESSigAndRefsTimeStampV2Imprint.TryComputeNotDistributedImprintInput(table, signature, stamp, container, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves the distributed variant's own ordering rule: the <c>Include</c> elements' OWN document order — here
    /// deliberately reversed relative to BOTH the covered properties' own document order (<c>ccr1</c> appears
    /// before <c>arr1</c> in <c>UnsignedSignatureProperties</c>) AND A.1.5.1.1's "listed order" of covered types
    /// (<c>CompleteCertificateRefsV2</c> before <c>AttributeRevocationRefs</c>) — governs concatenation order, not
    /// either of those. Comment nodes are deleted (the <see cref="XAdESIncludeUriProcessing"/> machinery every
    /// <c>Include</c> mechanism shares); a <c>WithComments</c> algorithm makes a surviving comment visible if
    /// deletion did not happen.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.3.
    /// </summary>
    [TestMethod]
    public void DistributedImprintUsesIncludeOrderNotListedOrderAndDeletesComments()
    {
        string usspBody = $$"""
            <xadesv2:CompleteCertificateRefsV2 Id="ccr1"><!--comment-ccr--><Data>CCR</Data></xadesv2:CompleteCertificateRefsV2>
            <AttributeRevocationRefs Id="arr1"><!--comment-arr--><Data>ARR</Data></AttributeRevocationRefs>
            <xadesv2:SigAndRefsTimeStampV2 Id="sarts1">
              <Include URI="#arr1"/>
              <Include URI="#ccr1"/>
              <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14NWithComments}}"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </xadesv2:SigAndRefsTimeStampV2>
            """;
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESSigAndRefsTimeStampV2 stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            Assert.HasCount(2, stamp.TimeStamp.Includes);
            XmlCanonicalizationAlgorithm algorithm = XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments;
            byte[] expected =
            [
                .. Canonicalize(table, signature.SignatureValueElementIndex, pool, algorithm),
                .. CanonicalizeById(table, "arr1", pool, algorithm, withoutComments: true),
                .. CanonicalizeById(table, "ccr1", pool, algorithm, withoutComments: true),
            ];

            bool isComputed = XAdESSigAndRefsTimeStampV2Imprint.TryComputeDistributedImprintInput(table, signature, stamp, container, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
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
    /// Proves clause A.1.5.1.3 step 3's "each listed unsigned qualifying property" membership restriction: a relocated-decoy attack — the genuine <c>Include</c> target
    /// (<c>AttributeRevocationRefs</c>, one of the five covered types) moved OUT of <c>UnsignedSignatureProperties</c> (same <c>Id</c>, same content, so no duplicate-<c>Id</c>
    /// refusal fires) to a sibling of the signature, with a forged replacement inserted in its place — refuses with <see
    /// cref="XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty"/> rather than silently canonicalizing the relocated original. The honest sibling document,
    /// where the same property legitimately sits inside <c>UnsignedSignatureProperties</c>, computes successfully. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.3.
    /// </summary>
    [TestMethod]
    public void DistributedIncludeTargetRelocatedOutsideContainerIsRefused()
    {
        string honestDocument = $$"""
            <root xmlns:ds="{{DsNamespace}}" xmlns:xadesv2="{{V141}}">
              <ds:Signature Id="sig1">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>QQ==</ds:SignatureValue>
              </ds:Signature>
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="usp1">
                <AttributeRevocationRefs Id="arr1"><Data>ORIGINAL</Data></AttributeRevocationRefs>
                <xadesv2:SigAndRefsTimeStampV2 Id="sarts1">
                  <Include URI="#arr1"/>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
                </xadesv2:SigAndRefsTimeStampV2>
              </UnsignedSignatureProperties>
            </root>
            """;
        string attackedDocument = $$"""
            <root xmlns:ds="{{DsNamespace}}" xmlns:xadesv2="{{V141}}">
              <ds:Signature Id="sig1">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>QQ==</ds:SignatureValue>
              </ds:Signature>
              <AttributeRevocationRefs xmlns="{{V132}}" Id="arr1"><Data>ORIGINAL</Data></AttributeRevocationRefs>
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="usp1">
                <AttributeRevocationRefs Id="arr1-forged"><Data>FORGED</Data></AttributeRevocationRefs>
                <xadesv2:SigAndRefsTimeStampV2 Id="sarts1">
                  <Include URI="#arr1"/>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
                </xadesv2:SigAndRefsTimeStampV2>
              </UnsignedSignatureProperties>
            </root>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable honestTable, XmlSignature honestSignature, XAdESUnsignedSignatureProperties honestContainer, XAdESSigAndRefsTimeStampV2 honestStamp) = ReadFixture(honestDocument, pool);
        using(honestTable)
        using(honestSignature)
        using(honestStamp)
        {
            bool isHonestComputed = XAdESSigAndRefsTimeStampV2Imprint.TryComputeDistributedImprintInput(
                honestTable, honestSignature, honestStamp, honestContainer, pool, out PooledMemory? honestImprintInput, out XAdESProcessingError honestError);
            Assert.IsTrue(isHonestComputed, $"The honest document must compute but was refused with {honestError.Failure}.");
            honestImprintInput!.Dispose();
        }

        (XmlNodeTable attackedTable, XmlSignature attackedSignature, XAdESUnsignedSignatureProperties attackedContainer, XAdESSigAndRefsTimeStampV2 attackedStamp) = ReadFixture(attackedDocument, pool);
        using(attackedTable)
        using(attackedSignature)
        using(attackedStamp)
        {
            bool isAttackedComputed = XAdESSigAndRefsTimeStampV2Imprint.TryComputeDistributedImprintInput(
                attackedTable, attackedSignature, attackedStamp, attackedContainer, pool, out PooledMemory? attackedImprintInput, out XAdESProcessingError attackedError);
            Assert.IsFalse(isAttackedComputed, "The relocated-decoy attack must be refused rather than producing an imprint.");
            Assert.IsNull(attackedImprintInput);
            Assert.AreEqual(XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty, attackedError.Failure);
        }
    }


    /// <summary>
    /// Proves an absent <c>ds:CanonicalizationMethod</c> on the <c>SigAndRefsTimeStampV2</c> itself refuses rather than assuming a default algorithm. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.
    /// </summary>
    [TestMethod]
    public void AbsentCanonicalizationMethodIsRefused()
    {
        string usspBody = """<xadesv2:SigAndRefsTimeStampV2 Id="sarts1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:SigAndRefsTimeStampV2>""";
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESSigAndRefsTimeStampV2 stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESSigAndRefsTimeStampV2Imprint.TryComputeNotDistributedImprintInput(table, signature, stamp, container, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An absent CanonicalizationMethod must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.AbsentCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves the not-distributed engine refuses when the given <c>SigAndRefsTimeStampV2</c> is not itself a
    /// member of the given <c>UnsignedSignatureProperties</c> entry list.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.2.
    /// </summary>
    [TestMethod]
    public void NotDistributedNotFoundInContainerIsRefused()
    {
        string document = $$"""
            <root xmlns:ds="{{DsNamespace}}" xmlns:xadesv2="{{V141}}">
              <ds:Signature Id="sig1">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>QQ==</ds:SignatureValue>
              </ds:Signature>
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="uspA">
                <xadesv2:SigAndRefsTimeStampV2 Id="sartsA"><ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:SigAndRefsTimeStampV2>
              </UnsignedSignatureProperties>
              <UnsignedSignatureProperties xmlns="{{V132}}" Id="uspB">
                <xadesv2:SigAndRefsTimeStampV2 Id="sartsB"><ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:SigAndRefsTimeStampV2>
              </UnsignedSignatureProperties>
            </root>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            Assert.HasCount(1, signatureIndices);
            bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
            Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");
            using(signature)
            {
                bool isFoundB = table!.TryFindElementById("uspB"u8, out int containerBIndex, out _);
                bool isFoundStampA = table.TryFindElementById("sartsA"u8, out int stampAIndex, out _);
                Assert.IsTrue(isFoundB && isFoundStampA);

                bool isContainerBRead = XAdESUnsignedSignatureProperties.TryRead(table, containerBIndex, out XAdESUnsignedSignatureProperties containerB, out XAdESReadError containerBError);
                Assert.IsTrue(isContainerBRead, $"uspB must read but was refused with {containerBError.Failure}.");
                bool isStampARead = XAdESSigAndRefsTimeStampV2.TryRead(table, stampAIndex, pool, out XAdESSigAndRefsTimeStampV2? stampA, out XAdESReadError stampAError);
                Assert.IsTrue(isStampARead, $"sartsA must read but was refused with {stampAError.Failure}.");
                using(stampA)
                {
                    bool isComputed = XAdESSigAndRefsTimeStampV2Imprint.TryComputeNotDistributedImprintInput(
                        table, signature!, stampA!, containerB, pool, out _, out XAdESProcessingError error);
                    Assert.IsFalse(isComputed, "sartsA is not a member of uspB and must be refused.");
                    Assert.AreEqual(XAdESProcessingFailure.SigAndRefsTimeStampV2NotFoundInUnsignedSignatureProperties, error.Failure);
                }
            }
        }
    }


    /// <summary>
    /// Proves the table-identity guard on the not-distributed engine. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.2.
    /// </summary>
    [TestMethod]
    public void TableMismatchIsRefused()
    {
        string usspBody = """<xadesv2:SigAndRefsTimeStampV2 Id="sarts1"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:SigAndRefsTimeStampV2>""";
        string document = Document(usspBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESSigAndRefsTimeStampV2 stamp) = ReadFixture(document, pool);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature, XAdESUnsignedSignatureProperties foreignContainer, XAdESSigAndRefsTimeStampV2 foreignStamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        using(foreignTable)
        using(foreignSignature)
        using(foreignStamp)
        {
            _ = foreignContainer;
            bool isComputed = XAdESSigAndRefsTimeStampV2Imprint.TryComputeNotDistributedImprintInput(foreignTable, signature, stamp, container, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "A foreign table must refuse rather than computing against the wrong document.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves custody is balanced on the success path via <see cref="MeteredHousePool"/> for the not-distributed
    /// engine: every intermediate buffer rented while canonicalizing is released internally, and only the final
    /// result is handed to the caller.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.2.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnSuccessAfterDisposingTheResult()
    {
        string usspBody = """<xadesv2:SigAndRefsTimeStampV2 Id="sarts1"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:SigAndRefsTimeStampV2>""";
        string document = Document(usspBody);
        using(var metered = new MeteredHousePool())
        {
            (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESSigAndRefsTimeStampV2 stamp) = ReadFixture(document, metered.Pool);
            using(table)
            using(signature)
            using(stamp)
            {
                bool isComputed = XAdESSigAndRefsTimeStampV2Imprint.TryComputeNotDistributedImprintInput(table, signature, stamp, container, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
                imprintInput!.Dispose();
            }
        }
    }
}
