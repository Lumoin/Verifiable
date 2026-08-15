using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput"/> against clause
/// 5.2.8.2's message-imprint computation input procedure of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the <c>Include</c>-selected subset of <c>ds:Reference</c> elements,
/// processed in <c>Include</c> document order (not their own <c>ds:SignedInfo</c> order) per steps a)-d) and
/// concatenated.
/// </summary>
[TestClass]
internal sealed class XAdESIndividualDataObjectsTimeStampImprintTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

    private static string DefaultCanonicalizationMethodElement { get; } = $"""<ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>""";


    private static string Document(string includesXml, string referencesXml, string? canonicalizationMethodElement = null) => $$"""
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
          <IndividualDataObjectsTimeStamp xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}" Id="idots1">
            {{includesXml}}
            {{canonicalizationMethodElement ?? DefaultCanonicalizationMethodElement}}
            <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
          </IndividualDataObjectsTimeStamp>
        </root>
        """;


    private static string Reference(string id, string uri, string? type = null) =>
        $"""<ds:Reference Id="{id}" URI="{uri}"{(type is null ? "" : $""" Type="{type}" """)}><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>QQ==</ds:DigestValue></ds:Reference>""";


    private static string Include(string uri) => $"""<Include URI="{uri}" referencedData="true"/>""";


    private static (XmlNodeTable Table, XmlSignature Signature, XAdESIndividualDataObjectsTimeStamp Stamp) ReadFixture(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices);
        bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");

        bool isFound = table!.TryFindElementById("idots1"u8, out int stampIndex, out _);
        Assert.IsTrue(isFound, "The fixture IndividualDataObjectsTimeStamp must resolve by Id.");
        bool isStampRead = XAdESIndividualDataObjectsTimeStamp.TryRead(table, stampIndex, pool, out XAdESIndividualDataObjectsTimeStamp? stamp, out XAdESReadError stampError);
        Assert.IsTrue(isStampRead, $"The fixture IndividualDataObjectsTimeStamp must read but was refused with {stampError.Failure}.");

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
    /// Proves the clause 5.2.8.2 step 2 ordering key: "Process each one in their order of appearance WITHIN
    /// THE <c>Include</c> ELEMENT" — the <c>Include</c> list names <c>ref2</c> before <c>ref1</c>, the
    /// opposite of their own <c>ds:SignedInfo</c> declaration order, and the imprint input follows the
    /// <c>Include</c> order. The two distinguishable canonical byte runs, concatenated with nothing in
    /// between, is the concatenation-boundary evidence this test proves.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void IncludeOrderDeterminesConcatenationOrderNotSignedInfoOrder()
    {
        string references = Reference("ref1", "#data1") + Reference("ref2", "#data2") + Reference("ref-sp", "#sp1", SignedPropertiesType);
        string includes = Include("#ref2") + Include("#ref1");
        string document = Document(includes, references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            byte[] expected = [.. CanonicalizeById(table, "data2", pool), .. CanonicalizeById(table, "data1", pool)];

            bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves clause 5.2.8.2's "The set of <c>ds:Reference</c> elements processed shall not include the one
    /// referencing the <c>SignedProperties</c> element": an <c>Include</c> resolving to the
    /// <c>SignedProperties</c>-typed reference is refused rather than silently time-stamping it.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void IncludeTargetingTheSignedPropertiesReferenceIsRefused()
    {
        string references = Reference("ref1", "#data1") + Reference("ref-sp", "#sp1", SignedPropertiesType);
        string includes = Include("#ref1") + Include("#ref-sp");
        string document = Document(includes, references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An Include targeting the SignedProperties reference must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.IndividualDataObjectsTimeStampIncludeTargetsSignedPropertiesReference, error.Failure);
        }
    }


    /// <summary>
    /// Proves clause 5.1.4.4.2.1's target-shape rule, enforced at processing time since the structural reader
    /// alone cannot know what a bare-name fragment resolves to: an <c>Include</c> whose <c>URI</c> resolves to
    /// a non-<c>ds:Reference</c> element is refused, even though <see cref="XAdESIndividualDataObjectsTimeStamp.TryRead"/>
    /// already accepted <c>referencedData="true"</c> at read time.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void IncludeTargetNotAReferenceIsRefused()
    {
        string references = Reference("ref1", "#data1");
        string includes = Include("#data1");
        string document = Document(includes, references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An Include whose target is not a ds:Reference must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.ReferencedDataNotPermittedOnNonReferenceTarget, error.Failure);
        }
    }


    /// <summary>
    /// Proves clause 5.2.8.2 step 2's own scope restriction: "Take all the <c>ds:Reference</c> elements WITHIN <c>ds:SignedInfo</c> OR WITHIN A SIGNED <c>ds:Manifest</c>" —
    /// a structurally well-formed <c>ds:Reference</c> sitting inside an UNSIGNED <c>ds:Manifest</c> (one no <c>ds:SignedInfo</c> reference points at) satisfies neither arm,
    /// so an <c>Include</c> resolving to it is refused rather than silently time-stamping data no core signature validation ever covered. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void IncludeTargetInUnsignedManifestIsRefused()
    {
        string document = $$"""
            <root xmlns:ds="{{DsNamespace}}">
              <ds:Signature Id="sig1">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  {{Reference("ref1", "#data1")}}
                </ds:SignedInfo>
                <ds:SignatureValue>QQ==</ds:SignatureValue>
                <ds:Object>
                  <Data Id="data1">first</Data>
                  <SignedProperties Id="sp1">ignored</SignedProperties>
                </ds:Object>
              </ds:Signature>
              <ds:Manifest Id="unsignedManifest">
                {{Reference("ref-in-manifest", "#data1")}}
              </ds:Manifest>
              <IndividualDataObjectsTimeStamp xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}" Id="idots1">
                {{Include("#ref-in-manifest")}}
                {{DefaultCanonicalizationMethodElement}}
                <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              </IndividualDataObjectsTimeStamp>
            </root>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An Include targeting a ds:Reference inside an unsigned ds:Manifest must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.IndividualDataObjectsTimeStampIncludeTargetNotWithinSignedInfoOrSignedManifest, error.Failure);
        }
    }


    /// <summary>
    /// Proves a structurally-named but malformed <c>ds:Reference</c> target (missing its mandatory
    /// <c>ds:DigestValue</c>) surfaces as <see cref="XAdESProcessingFailure.MalformedReferenceTarget"/>, the
    /// inner read refusal carried via <see cref="XAdESProcessingError.InnerReadError"/>. The malformed reference
    /// sits inside a SIGNED <c>ds:Manifest</c> (rather than as a direct <c>ds:SignedInfo</c> child) so the
    /// clause 5.2.8.2 step 2 scope check (<see cref="XAdESProcessingFailure.IndividualDataObjectsTimeStampIncludeTargetNotWithinSignedInfoOrSignedManifest"/>)
    /// passes and this refusal, not that one, is what the engine reaches — <c>ds:Manifest</c> content is opaque
    /// <c>ds:Object</c> content the core signature read never structurally validates, unlike a malformed
    /// reference directly under <c>ds:SignedInfo</c>, which <see cref="XmlSignature.TryRead"/> itself would
    /// already refuse.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void MalformedReferenceTargetIsRefused()
    {
        string document = $$"""
            <root xmlns:ds="{{DsNamespace}}">
              <ds:Signature Id="sig1">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  {{Reference("ref-to-manifest", "#manifest1")}}
                </ds:SignedInfo>
                <ds:SignatureValue>QQ==</ds:SignatureValue>
                <ds:Object>
                  <ds:Manifest Id="manifest1">
                    <ds:Reference Id="ref1" URI="#data1"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference>
                  </ds:Manifest>
                  <Data Id="data1">first</Data>
                  <SignedProperties Id="sp1">ignored</SignedProperties>
                </ds:Object>
              </ds:Signature>
              <IndividualDataObjectsTimeStamp xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}" Id="idots1">
                {{Include("#ref1")}}
                {{DefaultCanonicalizationMethodElement}}
                <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              </IndividualDataObjectsTimeStamp>
            </root>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "A malformed ds:Reference target must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.MalformedReferenceTarget, error.Failure);
        }
    }


    /// <summary>
    /// Proves the table-identity guard: a foreign table refuses rather than computing against the wrong document. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void TableMismatchIsRefused()
    {
        string references = Reference("ref1", "#data1");
        string includes = Include("#ref1");
        string document = Document(includes, references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature, XAdESIndividualDataObjectsTimeStamp foreignStamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        using(foreignTable)
        using(foreignSignature)
        using(foreignStamp)
        {
            bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(foreignTable, foreignSignature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "A foreign table must refuse rather than computing against the wrong document.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves the zero-<c>Include</c> acceptance stays total at this layer: a zero-<c>Include</c> instance —
    /// accepted, not refused, at read (<see cref="XAdESIndividualDataObjectsTimeStampTests.ZeroIncludesIsNotRefused"/>)
    /// — produces empty (but non-null) imprint-input octets here, since step 1's "initialize the final octet
    /// stream as an empty octet stream" is vacuously satisfied by nothing to concatenate.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void ZeroIncludesProducesEmptyImprintInput()
    {
        string references = Reference("ref1", "#data1");
        string document = Document(string.Empty, references);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            Assert.HasCount(0, stamp.TimeStamp.Includes);

            bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.HasCount(0, imprintInput!.AsReadOnlySpan());
            }
        }
    }


    /// <summary>
    /// Proves an absent <c>ds:CanonicalizationMethod</c> on the <c>IndividualDataObjectsTimeStamp</c> itself refuses rather than assuming a default algorithm. Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void AbsentCanonicalizationMethodIsRefused()
    {
        string references = Reference("ref1", "#data1");
        string includes = Include("#ref1");
        string document = Document(includes, references, canonicalizationMethodElement: string.Empty);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An absent CanonicalizationMethod must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.AbsentCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves custody is balanced on the success path via <see cref="MeteredHousePool"/>: every intermediate
    /// buffer the engine rents while resolving, re-reading and canonicalizing each <c>Include</c>-selected
    /// reference is released internally, and only the final concatenated result is handed to the caller for
    /// disposal.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnSuccessAfterDisposingTheResult()
    {
        string references = Reference("ref1", "#data1") + Reference("ref2", "#data2");
        string includes = Include("#ref1") + Include("#ref2");
        string document = Document(includes, references);
        using(var metered = new MeteredHousePool())
        {
            (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, metered.Pool);
            using(table)
            using(signature)
            using(stamp)
            {
                bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
                imprintInput!.Dispose();
            }
        }
    }


    /// <summary>
    /// Proves custody is balanced on a mid-list refusal too: the first <c>Include</c> resolves and
    /// contributes bytes before the second's target is not found, and every buffer accumulated so far —
    /// including the first <c>XmlReference</c>'s own decoded content — is released by the engine's own
    /// <c>try</c>/<c>finally</c>, with nothing left for the caller to release since no result was produced.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnAMidListRefusalWithNoCallerDisposalNeeded()
    {
        string references = Reference("ref1", "#data1");
        string includes = Include("#ref1") + Include("#missing");
        string document = Document(includes, references);
        using(var metered = new MeteredHousePool())
        {
            (XmlNodeTable table, XmlSignature signature, XAdESIndividualDataObjectsTimeStamp stamp) = ReadFixture(document, metered.Pool);
            using(table)
            using(signature)
            using(stamp)
            {
                bool isComputed = XAdESIndividualDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsFalse(isComputed, "The second Include must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.IncludeTargetIdNotFound, error.Failure);
                Assert.IsNull(imprintInput);
            }
        }
    }
}
