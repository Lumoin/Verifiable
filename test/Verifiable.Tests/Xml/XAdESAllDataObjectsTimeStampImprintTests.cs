using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput"/> against clause 5.2.8.1's
/// message-imprint computation input procedure of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: all <c>ds:SignedInfo</c> references except the one referencing
/// <c>SignedProperties</c>, in <c>ds:SignedInfo</c> document order, each processed per steps a)-d) and
/// concatenated.
/// </summary>
[TestClass]
internal sealed class XAdESAllDataObjectsTimeStampImprintTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";


    private static string DefaultCanonicalizationMethodElement { get; } = $"""<ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>""";


    private static string Document(string referencesXml, string? canonicalizationMethodElement = null) => $$"""
        <root xmlns:ds="{{DsNamespace}}">
          <ds:Signature Id="sig1">
            <ds:SignedInfo>
              <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
              <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              {{referencesXml}}
            </ds:SignedInfo>
            <ds:SignatureValue>QQ==</ds:SignatureValue>
            <ds:Object>
              <Data Id="data1">first</Data>
              <Data Id="data2">second</Data>
              <SignedProperties Id="sp1">ignored</SignedProperties>
            </ds:Object>
          </ds:Signature>
          <AllDataObjectsTimeStamp xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}" Id="adots1">
            {{canonicalizationMethodElement ?? DefaultCanonicalizationMethodElement}}
            <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
          </AllDataObjectsTimeStamp>
        </root>
        """;


    private static string Reference(string id, string uri, string? type = null) =>
        $"""<ds:Reference Id="{id}" URI="{uri}"{(type is null ? "" : $""" Type="{type}" """)}><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>QQ==</ds:DigestValue></ds:Reference>""";


    private static (XmlNodeTable Table, XmlSignature Signature, XAdESAllDataObjectsTimeStamp Stamp) ReadFixture(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices);
        bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");

        bool isFound = table!.TryFindElementById("adots1"u8, out int stampIndex, out _);
        Assert.IsTrue(isFound, "The fixture AllDataObjectsTimeStamp must resolve by Id.");
        bool isStampRead = XAdESAllDataObjectsTimeStamp.TryRead(table, stampIndex, pool, out XAdESAllDataObjectsTimeStamp? stamp, out XAdESReadError stampError);
        Assert.IsTrue(isStampRead, $"The fixture AllDataObjectsTimeStamp must read but was refused with {stampError.Failure}.");

        return (table, signature!, stamp!);
    }


    private static byte[] CanonicalizeById(XmlNodeTable table, string id, BaseMemoryPool pool)
    {
        bool isFound = table.TryFindElementById(Encoding.UTF8.GetBytes(id), out int elementIndex, out _);
        Assert.IsTrue(isFound, $"'{id}' must resolve by Id.");
        bool isCanonicalized = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(
            table, XmlNodeSet.ElementSubtree(table, elementIndex), XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10, ReadOnlySpan<byte>.Empty, pool, out PooledMemory? canonical, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"'{id}' must canonicalize but was refused with {error.Failure}.");
        using(canonical)
        {
            return canonical!.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// Proves the except-<c>SignedProperties</c> exclusion (clause 5.2.8.1: "all the <c>ds:Reference</c>
    /// elements within the <c>ds:SignedInfo</c> except the one referencing the <c>SignedProperties</c>
    /// element") by Type-URI, not position: the <c>SignedProperties</c> reference is placed FIRST, yet the
    /// imprint input equals the plain concatenation of ONLY the two remaining references' canonical octets —
    /// proving both the exclusion and, since nothing but the two canonical byte runs appears, the plain
    /// concatenation with no separator (the concatenation-boundary evidence this test proves).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.1.
    /// </summary>
    [TestMethod]
    public void ExcludesTheSignedPropertiesReferenceByTypeRegardlessOfPosition()
    {
        string references = Reference("ref-sp", "#sp1", SignedPropertiesType) + Reference("ref1", "#data1") + Reference("ref2", "#data2");
        string document = Document(references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            byte[] expected = [.. CanonicalizeById(table, "data1", pool), .. CanonicalizeById(table, "data2", pool)];

            bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves the order pin (clause 5.2.8.1 step 2: "in their order of appearance"): <c>ds:SignedInfo</c>
    /// document order governs concatenation order, verified by reversing the two data references' textual
    /// order in the fixture and observing the imprint input follows suit.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.1.
    /// </summary>
    [TestMethod]
    public void SignedInfoDocumentOrderDeterminesConcatenationOrder()
    {
        string references = Reference("ref2", "#data2") + Reference("ref1", "#data1") + Reference("ref-sp", "#sp1", SignedPropertiesType);
        string document = Document(references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            byte[] expected = [.. CanonicalizeById(table, "data2", pool), .. CanonicalizeById(table, "data1", pool)];

            bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves clause 4.4.2's assumed uniqueness: zero <c>Type</c>-matching references among
    /// <c>ds:SignedInfo</c>'s own reference list is refused rather than silently processing everything.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.1.
    /// </summary>
    [TestMethod]
    public void ZeroSignedPropertiesReferencesIsRefused()
    {
        string references = Reference("ref1", "#data1") + Reference("ref2", "#data2");
        string document = Document(references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "Zero SignedProperties-typed references must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.SignedPropertiesReferenceNotFound, error.Failure);
        }
    }


    /// <summary>
    /// Proves the ambiguous-target counterpart: more than one <c>Type</c>-matching reference is refused rather
    /// than excluding the first match and silently including the rest.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.1.
    /// </summary>
    [TestMethod]
    public void MultipleSignedPropertiesReferencesIsRefused()
    {
        string references = Reference("ref-sp1", "#sp1", SignedPropertiesType) + Reference("ref-sp2", "#data2", SignedPropertiesType) + Reference("ref1", "#data1");
        string document = Document(references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "More than one SignedProperties-typed reference must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.MultipleSignedPropertiesReferences, error.Failure);
        }
    }


    /// <summary>
    /// Proves an absent <c>ds:CanonicalizationMethod</c> on the <c>AllDataObjectsTimeStamp</c> itself refuses rather than assuming a default algorithm. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.1.
    /// </summary>
    [TestMethod]
    public void AbsentCanonicalizationMethodIsRefused()
    {
        string references = Reference("ref1", "#data1") + Reference("ref-sp", "#sp1", SignedPropertiesType);
        string document = Document(references, canonicalizationMethodElement: string.Empty);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An absent CanonicalizationMethod must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.AbsentCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves the table-identity guard: a <c>signature</c>/<c>allDataObjectsTimeStamp</c> pair read against a foreign table refuses rather than computing against the wrong
    /// document. Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>
    /// clause 5.2.8.1.
    /// </summary>
    [TestMethod]
    public void TableMismatchIsRefused()
    {
        string references = Reference("ref1", "#data1") + Reference("ref-sp", "#sp1", SignedPropertiesType);
        string document = Document(references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature, XAdESAllDataObjectsTimeStamp foreignStamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        using(foreignTable)
        using(foreignSignature)
        using(foreignStamp)
        {
            bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(foreignTable, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "A foreign table must refuse rather than computing against the wrong document.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves custody is balanced on the success path via <see cref="MeteredHousePool"/>: every intermediate
    /// buffer the engine rents while dereferencing and canonicalizing each selected reference is released
    /// internally, and only the final concatenated result is handed to the caller for disposal.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.1.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnSuccessAfterDisposingTheResult()
    {
        string references = Reference("ref1", "#data1") + Reference("ref2", "#data2") + Reference("ref-sp", "#sp1", SignedPropertiesType);
        string document = Document(references);
        using(var metered = new MeteredHousePool())
        {
            (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(document, metered.Pool);
            using(table)
            using(signature)
            using(stamp)
            {
                bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
                imprintInput!.Dispose();
            }
        }
    }


    /// <summary>
    /// Proves custody is balanced on a mid-list refusal too: the first selected reference succeeds and
    /// contributes bytes before the second's dangling <c>URI</c> fails to dereference, and every buffer
    /// accumulated so far is released by the engine's own <c>try</c>/<c>finally</c>, with nothing left for
    /// the caller to release since no result was ever produced.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.1.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnAMidListRefusalWithNoCallerDisposalNeeded()
    {
        string references = Reference("ref1", "#data1") + Reference("ref2", "#missing") + Reference("ref-sp", "#sp1", SignedPropertiesType);
        string document = Document(references);
        using(var metered = new MeteredHousePool())
        {
            (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(document, metered.Pool);
            using(table)
            using(signature)
            using(stamp)
            {
                bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsFalse(isComputed, "The second selected reference's dangling URI must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.MessageImprintReferenceProcessingFailed, error.Failure);
                Assert.IsNull(imprintInput);
            }
        }
    }
}
