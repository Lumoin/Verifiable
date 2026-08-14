using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESIncludeProcessing.TryComputeImprintInput"/> against the generic
/// <c>Include</c>-processing frame of clause 5.1.4.4.2.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: retrieval, the <c>referencedData="true"</c> routing rule, canonicalization
/// of the kept node-set, document-order concatenation, the absent-<c>ds:CanonicalizationMethod</c> refusal
/// this library requires, and the <c>referencedData</c> presence rule XA-5.1.4.4.2.1-5 states.
/// </summary>
[TestClass]
internal sealed class XAdESIncludeProcessingTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";


    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static (XmlNodeTable Table, XmlCanonicalizationMethodInfo Method) ReadCanonicalizationMethod(string algorithmUri, BaseMemoryPool pool)
    {
        string document = $"""<ds:CanonicalizationMethod xmlns:ds="{DsNamespace}" Algorithm="{algorithmUri}"/>""";
        XmlNodeTable table = Parse(document, pool);
        bool isRead = XmlCanonicalizationMethodInfo.TryRead(table, table.DocumentElementIndex, out XmlCanonicalizationMethodInfo method, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"The CanonicalizationMethod fixture must read but was refused with {error.Failure}.");

        return (table, method);
    }


    private static XAdESInclude ReadInclude(XmlNodeTable table, int elementIndex)
    {
        bool isRead = XAdESInclude.TryRead(table, elementIndex, out XAdESInclude include, out XAdESReadError error);
        Assert.IsTrue(isRead, $"The Include fixture must read but was refused with {error.Failure}.");

        return include;
    }


    /// <summary>
    /// Proves an absent <c>ds:CanonicalizationMethod</c> refuses rather than assuming a default algorithm — <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1
    /// V1.3.1</see> clause 4.5 makes the element generator-mandatory, and legacy material is out of this reader's scope.
    /// </summary>
    [TestMethod]
    public void AbsentCanonicalizationMethodIsRefused()
    {
        using XmlNodeTable table = Parse("""<root/>""", BaseMemoryPool.Shared);
        bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
            table, [], hasCanonicalizationMethod: false, default, resolver: null, BaseMemoryPool.Shared, out _, out XAdESProcessingError error);
        Assert.IsFalse(isComputed, "An absent CanonicalizationMethod must be refused.");
        Assert.AreEqual(XAdESProcessingFailure.AbsentCanonicalizationMethod, error.Failure);
    }


    /// <summary>
    /// Proves an <c>Algorithm</c> outside the six <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3(d) canonicalization identifiers is refused.
    /// </summary>
    [TestMethod]
    public void UnsupportedCanonicalizationMethodIsRefused()
    {
        using XmlNodeTable table = Parse("""<root/>""", BaseMemoryPool.Shared);
        (XmlNodeTable canonTable, XmlCanonicalizationMethodInfo method) = ReadCanonicalizationMethod("http://example.com/not-a-real-c14n", BaseMemoryPool.Shared);
        using(canonTable)
        {
            bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
                table, [], hasCanonicalizationMethod: true, method, resolver: null, BaseMemoryPool.Shared, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An unrecognized canonicalization algorithm must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.UnsupportedCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves an empty <c>Include</c> list produces empty octets rather than a refusal — "concatenate ... in
    /// Include order" (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.3's XA-5.1.4.4.2.3-1 step 4) is vacuously satisfied by nothing to concatenate; selecting
    /// between the explicit mechanism and a property's own implicit rule (XA-5.1.4.4.1-3/-4) is the caller's
    /// concern, not this frame's.
    /// </summary>
    [TestMethod]
    public void EmptyIncludeListProducesEmptyOctets()
    {
        using XmlNodeTable table = Parse("""<root/>""", BaseMemoryPool.Shared);
        (XmlNodeTable canonTable, XmlCanonicalizationMethodInfo method) = ReadCanonicalizationMethod(ExclusiveC14N, BaseMemoryPool.Shared);
        using(canonTable)
        {
            bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
                table, [], hasCanonicalizationMethod: true, method, resolver: null, BaseMemoryPool.Shared, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.HasCount(0, imprintInput!.AsReadOnlySpan());
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1's XA-5.1.4.4.2.1-2/XA-5.1.4.4.2.3-4: the <c>Include</c> DOCUMENT order — not the targets' own
    /// document order — determines the concatenation order, by comparing the frame's output against an
    /// independently ordered concatenation of the same two node-sets canonicalized directly through the
    /// shipped <see cref="XmlReferenceProcessing"/> dispatch.
    /// </summary>
    [TestMethod]
    public void IncludeOrderDeterminesConcatenationOrderNotTargetDocumentOrder()
    {
        //Targets appear in the order b, a; the Includes reference them in the order a, b — the opposite.
        string document = $"""
            <root>
              <Data Id="b">second</Data>
              <Data Id="a">first</Data>
              <Include URI="#a"/>
              <Include URI="#b"/>
            </root>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        (XmlNodeTable canonTable, XmlCanonicalizationMethodInfo method) = ReadCanonicalizationMethod(ExclusiveC14N, BaseMemoryPool.Shared);
        using(canonTable)
        {
            bool isFoundA = table.TryFindElementById("a"u8, out int aIndex, out _);
            bool isFoundB = table.TryFindElementById("b"u8, out int bIndex, out _);
            Assert.IsTrue(isFoundA && isFoundB, "Both fixture targets must resolve by Id.");

            bool isCanonicalizedA = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(
                table, XmlNodeSet.ElementSubtree(table, aIndex).WithoutComments(), XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10, method.PrefixList, BaseMemoryPool.Shared, out PooledMemory? canonicalA, out XmlCanonicalizationError canonAError);
            Assert.IsTrue(isCanonicalizedA, $"Target 'a' must canonicalize but was refused with {canonAError.Failure}.");
            bool isCanonicalizedB = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(
                table, XmlNodeSet.ElementSubtree(table, bIndex).WithoutComments(), XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10, method.PrefixList, BaseMemoryPool.Shared, out PooledMemory? canonicalB, out XmlCanonicalizationError canonBError);
            Assert.IsTrue(isCanonicalizedB, $"Target 'b' must canonicalize but was refused with {canonBError.Failure}.");

            byte[] expected;
            using(canonicalA)
            using(canonicalB)
            {
                expected = [.. canonicalA!.AsReadOnlySpan(), .. canonicalB!.AsReadOnlySpan()];
            }

            //Locate the two Include elements in their own document order (a then b).
            var includes = new List<XAdESInclude>();
            for(int child = table.FirstChildOf(table.DocumentElementIndex); child >= 0; child = table.NextSiblingOf(child))
            {
                if(table.KindOf(child) == XmlNodeKind.Element && table.LocalNameOf(child).SequenceEqual("Include"u8) && table.NamespaceUriOf(child).IsEmpty)
                {
                    includes.Add(ReadInclude(table, child));
                }
            }

            Assert.HasCount(2, includes);

            bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
                table, includes, hasCanonicalizationMethod: true, method, resolver: null, BaseMemoryPool.Shared, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.3's XA-5.1.4.4.2.3-1 step 2: an <c>Include</c> whose target is a <c>ds:Reference</c> element with
    /// <c>referencedData="true"</c> is routed through the XMLDSIG reference-processing engine — proven by
    /// equality against calling <see cref="XmlReferenceProcessing.TryComputeDigestInputForReference"/>
    /// directly on the same reference.
    /// </summary>
    [TestMethod]
    public void ReferencedDataTrueOnAReferenceTargetRoutesThroughTheReferenceProcessingEngine()
    {
        string document = $"""
            <root xmlns:ds="{DsNamespace}">
              <Data Id="payload">hello</Data>
              <ds:Reference Id="ref1" URI="#payload">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>QQ==</ds:DigestValue>
              </ds:Reference>
              <Include URI="#ref1" referencedData="true"/>
            </root>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        (XmlNodeTable canonTable, XmlCanonicalizationMethodInfo method) = ReadCanonicalizationMethod(ExclusiveC14N, BaseMemoryPool.Shared);
        using(canonTable)
        {
            bool isFoundReference = table.TryFindElementById("ref1"u8, out int referenceElementIndex, out _);
            Assert.IsTrue(isFoundReference, "The fixture ds:Reference must resolve by Id.");

            var owned = new List<PooledMemory>();
            bool isReferenceRead = XmlReference.TryRead(table, referenceElementIndex, BaseMemoryPool.Shared, owned, out XmlReference reference, out XmlSignatureReadError readError);
            Assert.IsTrue(isReferenceRead, $"The fixture ds:Reference must read but was refused with {readError.Failure}.");
            bool isExpectedComputed = XmlReferenceProcessing.TryComputeDigestInputForReference(table, reference, resolver: null, BaseMemoryPool.Shared, out PooledMemory? expectedDigestInput, out XmlSignatureProcessingError expectedError);
            Assert.IsTrue(isExpectedComputed, $"The direct reference-processing call must compute but was refused with {expectedError.Failure}.");

            byte[] expected;
            using(expectedDigestInput)
            {
                expected = expectedDigestInput!.AsReadOnlySpan().ToArray();
            }

            foreach(PooledMemory buffer in owned)
            {
                buffer.Dispose();
            }

            List<XAdESInclude> includes = [ReadInclude(table, FindIncludeElement(table))];
            bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
                table, includes, hasCanonicalizationMethod: true, method, resolver: null, BaseMemoryPool.Shared, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves the OTHER half of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.3's XA-5.1.4.4.2.3-1 step 2: when <c>referencedData</c> is ABSENT on a
    /// <c>ds:Reference</c> target, the retrieved node-set is kept and canonicalized directly — the reference
    /// is NOT itself processed through the XMLDSIG reference-processing engine, since only
    /// <c>referencedData="true"</c> triggers that route (presence of the attribute alone does not).
    /// </summary>
    [TestMethod]
    public void ReferencedDataAbsentOnAReferenceTargetKeepsTheRetrievedNodeSet()
    {
        string document = $"""
            <root xmlns:ds="{DsNamespace}">
              <Data Id="payload">hello</Data>
              <ds:Reference Id="ref1" URI="#payload">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>QQ==</ds:DigestValue>
              </ds:Reference>
              <Include URI="#ref1"/>
            </root>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        (XmlNodeTable canonTable, XmlCanonicalizationMethodInfo method) = ReadCanonicalizationMethod(ExclusiveC14N, BaseMemoryPool.Shared);
        using(canonTable)
        {
            bool isFoundReference = table.TryFindElementById("ref1"u8, out int referenceElementIndex, out _);
            Assert.IsTrue(isFoundReference, "The fixture ds:Reference must resolve by Id.");

            bool isCanonicalized = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(
                table, XmlNodeSet.ElementSubtree(table, referenceElementIndex).WithoutComments(), XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10, method.PrefixList, BaseMemoryPool.Shared, out PooledMemory? expectedCanonical, out XmlCanonicalizationError canonError);
            Assert.IsTrue(isCanonicalized, $"Direct canonicalization must succeed but was refused with {canonError.Failure}.");

            byte[] expected;
            using(expectedCanonical)
            {
                expected = expectedCanonical!.AsReadOnlySpan().ToArray();
            }

            List<XAdESInclude> includes = [ReadInclude(table, FindIncludeElement(table))];
            bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
                table, includes, hasCanonicalizationMethod: true, method, resolver: null, BaseMemoryPool.Shared, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1's "If the object referenced by the URI attribute is not a ds:Reference
    /// element, the referencedData attribute shall not be present" — enforced fail-closed at processing
    /// time, since the structural <see cref="XAdESInclude"/> reader alone cannot know what the URI resolves
    /// to.
    /// </summary>
    [TestMethod]
    public void ReferencedDataPresentOnANonReferenceTargetIsRefused()
    {
        string document = $"""
            <root>
              <Data Id="payload">hello</Data>
              <Include URI="#payload" referencedData="true"/>
            </root>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        (XmlNodeTable canonTable, XmlCanonicalizationMethodInfo method) = ReadCanonicalizationMethod(ExclusiveC14N, BaseMemoryPool.Shared);
        using(canonTable)
        {
            List<XAdESInclude> includes = [ReadInclude(table, FindIncludeElement(table))];
            bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
                table, includes, hasCanonicalizationMethod: true, method, resolver: null, BaseMemoryPool.Shared, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "referencedData on a non-ds:Reference target must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.ReferencedDataNotPermittedOnNonReferenceTarget, error.Failure);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.3, a non-same-document <c>Include</c> refusal from <see cref="XAdESIncludeUriProcessing"/>
    /// propagates unchanged through the frame.
    /// </summary>
    [TestMethod]
    public void NonSameDocumentIncludeRefusalPropagatesThroughTheFrame()
    {
        string document = """<root><Include URI="external.xml#frag"/></root>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        (XmlNodeTable canonTable, XmlCanonicalizationMethodInfo method) = ReadCanonicalizationMethod(ExclusiveC14N, BaseMemoryPool.Shared);
        using(canonTable)
        {
            List<XAdESInclude> includes = [ReadInclude(table, FindIncludeElement(table))];
            bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
                table, includes, hasCanonicalizationMethod: true, method, resolver: null, BaseMemoryPool.Shared, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "A non-same-document Include must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.NonSameDocumentIncludeUnresolved, error.Failure);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.3, custody balances on the success path (two Includes, one via each retrieval route) via
    /// <see cref="MeteredHousePool"/>: every intermediate buffer the frame rents while retrieving,
    /// reference-processing and canonicalizing is released internally, and only the final concatenated
    /// result is handed to the caller for disposal.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnSuccessAfterDisposingTheResult()
    {
        string document = $"""
            <root xmlns:ds="{DsNamespace}">
              <Data Id="payload">hello</Data>
              <ds:Reference Id="ref1" URI="#payload">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>QQ==</ds:DigestValue>
              </ds:Reference>
              <Include URI="#payload"/>
              <Include URI="#ref1" referencedData="true"/>
            </root>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, metered.Pool);
            (XmlNodeTable canonTable, XmlCanonicalizationMethodInfo method) = ReadCanonicalizationMethod(ExclusiveC14N, metered.Pool);
            using(canonTable)
            {
                List<XAdESInclude> includes = [];
                for(int child = table.FirstChildOf(table.DocumentElementIndex); child >= 0; child = table.NextSiblingOf(child))
                {
                    if(table.KindOf(child) == XmlNodeKind.Element && table.LocalNameOf(child).SequenceEqual("Include"u8) && table.NamespaceUriOf(child).IsEmpty)
                    {
                        includes.Add(ReadInclude(table, child));
                    }
                }

                Assert.HasCount(2, includes);

                bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
                    table, includes, hasCanonicalizationMethod: true, method, resolver: null, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
                imprintInput!.Dispose();
            }
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.3, custody balances on a mid-list refusal too: the first <c>Include</c> succeeds and contributes
    /// bytes before the second fails, and every buffer accumulated so far is still released by the frame's
    /// own <c>try</c>/<c>finally</c>, with nothing left for the caller to release since no result was ever
    /// produced.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnAMidListRefusalWithNoCallerDisposalNeeded()
    {
        string document = """
            <root>
              <Data Id="present">hello</Data>
              <Include URI="#present"/>
              <Include URI="#missing"/>
            </root>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, metered.Pool);
            (XmlNodeTable canonTable, XmlCanonicalizationMethodInfo method) = ReadCanonicalizationMethod(ExclusiveC14N, metered.Pool);
            using(canonTable)
            {
                List<XAdESInclude> includes = [];
                for(int child = table.FirstChildOf(table.DocumentElementIndex); child >= 0; child = table.NextSiblingOf(child))
                {
                    if(table.KindOf(child) == XmlNodeKind.Element && table.LocalNameOf(child).SequenceEqual("Include"u8) && table.NamespaceUriOf(child).IsEmpty)
                    {
                        includes.Add(ReadInclude(table, child));
                    }
                }

                Assert.HasCount(2, includes);

                bool isComputed = XAdESIncludeProcessing.TryComputeImprintInput(
                    table, includes, hasCanonicalizationMethod: true, method, resolver: null, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsFalse(isComputed, "The second Include must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.IncludeTargetIdNotFound, error.Failure);
                Assert.IsNull(imprintInput);
            }
        }

        //No caller-side disposal call is made above: the frame's own outer try/finally must have already
        //released the first Include's canonicalized bytes and the output accumulator.
    }


    private static int FindIncludeElement(XmlNodeTable table)
    {
        for(int child = table.FirstChildOf(table.DocumentElementIndex); child >= 0; child = table.NextSiblingOf(child))
        {
            if(table.KindOf(child) == XmlNodeKind.Element && table.LocalNameOf(child).SequenceEqual("Include"u8) && table.NamespaceUriOf(child).IsEmpty)
            {
                return child;
            }
        }

        Assert.Fail("The fixture document must carry an Include element.");

        return -1;
    }
}
