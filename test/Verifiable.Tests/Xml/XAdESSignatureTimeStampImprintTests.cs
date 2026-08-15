using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignatureTimeStampImprint.TryComputeImprintInput"/> against clause 5.3's
/// message-imprint computation input procedure of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: "1) take the <c>ds:SignatureValue</c> element and its contents; and 2)
/// canonicalize it as specified in clause 4.5."
/// </summary>
[TestClass]
internal sealed class XAdESSignatureTimeStampImprintTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";


    private static string Document(string canonicalizationMethodElement) => $$"""
        <root xmlns:ds="{{DsNamespace}}">
          <ds:Signature Id="sig1">
            <ds:SignedInfo>
              <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
              <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              <ds:Reference URI="">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>AQ==</ds:DigestValue>
              </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>QQ==</ds:SignatureValue>
          </ds:Signature>
          <SignatureTimeStamp xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}" Id="stamp1">
            {{canonicalizationMethodElement}}
            <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
          </SignatureTimeStamp>
        </root>
        """;


    private static (XmlNodeTable Table, XmlSignature Signature, XAdESSignatureTimeStamp Stamp) ReadFixture(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices);
        bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");

        bool isFound = table!.TryFindElementById("stamp1"u8, out int stampIndex, out _);
        Assert.IsTrue(isFound, "The fixture SignatureTimeStamp must resolve by Id.");
        bool isStampRead = XAdESSignatureTimeStamp.TryRead(table, stampIndex, pool, out XAdESSignatureTimeStamp? stamp, out XAdESReadError stampError);
        Assert.IsTrue(isStampRead, $"The fixture SignatureTimeStamp must read but was refused with {stampError.Failure}.");

        return (table, signature!, stamp!);
    }


    /// <summary>
    /// Proves the two-step clause 5.3 procedure exactly: the imprint input equals the <c>ds:SignatureValue</c>
    /// element subtree canonicalized with the property's own <c>ds:CanonicalizationMethod</c>, computed here a
    /// SECOND, independent way (direct canonicalization of the same node-set) and compared byte-for-byte.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.3.
    /// </summary>
    [TestMethod]
    public void ImprintInputEqualsCanonicalizedSignatureValueElement()
    {
        string document = Document($"""<ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>""");
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESSignatureTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isCanonicalizedDirectly = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(
                table, XmlNodeSet.ElementSubtree(table, signature.SignatureValueElementIndex), XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10, ReadOnlySpan<byte>.Empty, pool, out PooledMemory? expectedMemory, out XmlCanonicalizationError canonError);
            Assert.IsTrue(isCanonicalizedDirectly, $"Direct canonicalization must succeed but was refused with {canonError.Failure}.");

            byte[] expected;
            using(expectedMemory)
            {
                expected = expectedMemory!.AsReadOnlySpan().ToArray();
            }

            bool isComputed = XAdESSignatureTimeStampImprint.TryComputeImprintInput(table, signature, stamp, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves an absent <c>ds:CanonicalizationMethod</c> on the <c>SignatureTimeStamp</c> itself refuses rather than assuming a default algorithm. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.3.
    /// </summary>
    [TestMethod]
    public void AbsentCanonicalizationMethodIsRefused()
    {
        string document = Document(string.Empty);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESSignatureTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESSignatureTimeStampImprint.TryComputeImprintInput(table, signature, stamp, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An absent CanonicalizationMethod must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.AbsentCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves an <c>Algorithm</c> outside the six clause 6.3(d) canonicalization identifiers is refused.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.3.
    /// </summary>
    [TestMethod]
    public void UnsupportedCanonicalizationMethodIsRefused()
    {
        string document = Document("""<ds:CanonicalizationMethod Algorithm="http://example.com/not-a-real-c14n"/>""");
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESSignatureTimeStamp stamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESSignatureTimeStampImprint.TryComputeImprintInput(table, signature, stamp, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An unrecognized canonicalization algorithm must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.UnsupportedCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves the table-identity guard: a <c>signature</c>/<c>signatureTimeStamp</c> pair read against a foreign table refuses rather than computing against the wrong
    /// document. Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>
    /// clause 5.3.
    /// </summary>
    [TestMethod]
    public void TableMismatchIsRefused()
    {
        string document = Document($"""<ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>""");
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESSignatureTimeStamp stamp) = ReadFixture(document, pool);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature, XAdESSignatureTimeStamp foreignStamp) = ReadFixture(document, pool);
        using(table)
        using(signature)
        using(stamp)
        using(foreignTable)
        using(foreignSignature)
        using(foreignStamp)
        {
            bool isComputed = XAdESSignatureTimeStampImprint.TryComputeImprintInput(foreignTable, signature, stamp, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "A foreign table must refuse rather than computing against the wrong document.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves custody is balanced on the success path via <see cref="MeteredHousePool"/>: every intermediate
    /// buffer the engine rents while canonicalizing is released internally, and only the final result is
    /// handed to the caller for disposal.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.3.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnSuccessAfterDisposingTheResult()
    {
        string document = Document($"""<ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>""");
        using(var metered = new MeteredHousePool())
        {
            (XmlNodeTable table, XmlSignature signature, XAdESSignatureTimeStamp stamp) = ReadFixture(document, metered.Pool);
            using(table)
            using(signature)
            using(stamp)
            {
                bool isComputed = XAdESSignatureTimeStampImprint.TryComputeImprintInput(table, signature, stamp, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
                imprintInput!.Dispose();
            }
        }
    }
}
