using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESCanonicalizationManagement.TryResolve"/> against clause 4.5 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the shared resolution point every optional-<c>ds:CanonicalizationMethod</c>
/// qualifying property uses.
/// </summary>
[TestClass]
internal sealed class XAdESCanonicalizationManagementTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Parses and reads a standalone <c>ds:CanonicalizationMethod</c> fixture, returning both the value and
    /// the table its spans read from — the table must outlive every use of the returned value, mirroring
    /// <c>XAdESIncludeProcessingTests.ReadCanonicalizationMethod</c>'s own tuple-return idiom in this leaf.
    /// </summary>
    private static (XmlNodeTable Table, XmlCanonicalizationMethodInfo Method) ReadMethod(string algorithmUri, BaseMemoryPool pool)
    {
        string document = $"""<ds:CanonicalizationMethod xmlns:ds="{DsNamespace}" Algorithm="{algorithmUri}"/>""";
        XmlNodeTable table = Parse(document, pool);
        bool isRead = XmlCanonicalizationMethodInfo.TryRead(table, table.DocumentElementIndex, out XmlCanonicalizationMethodInfo method, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"The CanonicalizationMethod fixture must read but was refused with {error.Failure}.");

        return (table, method);
    }


    /// <summary>
    /// Proves XA-4.5-1/XA-4.5-2's absence-is-a-refusal enforcement point: an absent
    /// <c>ds:CanonicalizationMethod</c> refuses with <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/>
    /// rather than assuming a default algorithm — <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.5 makes the element generator-mandatory for both
    /// new-signature generation (XA-4.5-1) and legacy-signature augmentation (XA-4.5-2), and this ONE
    /// resolution point enforces the shared consequence both statements impose at use time.
    /// </summary>
    [TestMethod]
    public void AbsentMethodIsRefused()
    {
        bool isResolved = XAdESCanonicalizationManagement.TryResolve(false, default, out _, out XAdESProcessingError error);

        Assert.IsFalse(isResolved, "An absent CanonicalizationMethod must be refused.");
        Assert.AreEqual(XAdESProcessingFailure.AbsentCanonicalizationMethod, error.Failure);
    }


    /// <summary>
    /// Proves an <c>Algorithm</c> outside the six <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3(d) canonicalization identifiers is refused.
    /// </summary>
    [TestMethod]
    public void UnsupportedAlgorithmIsRefused()
    {
        (XmlNodeTable table, XmlCanonicalizationMethodInfo method) = ReadMethod("http://example.com/not-a-real-c14n", BaseMemoryPool.Shared);
        using(table)
        {
            bool isResolved = XAdESCanonicalizationManagement.TryResolve(true, method, out _, out XAdESProcessingError error);

            Assert.IsFalse(isResolved, "An unrecognized algorithm must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.UnsupportedCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves NOTE 1/NOTE 2 of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.5 (informative, but functionally binding through 6.3(d)): all six
    /// shipped canonicalization algorithms — Canonical XML 1.0/1.1 and Exclusive XML Canonicalization, each
    /// with and without comments — resolve successfully.
    /// </summary>
    [TestMethod]
    [DataRow("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", XmlCanonicalizationAlgorithm.CanonicalXml10)]
    [DataRow("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", XmlCanonicalizationAlgorithm.CanonicalXml10WithComments)]
    [DataRow("http://www.w3.org/2006/12/xml-c14n11", XmlCanonicalizationAlgorithm.CanonicalXml11)]
    [DataRow("http://www.w3.org/2006/12/xml-c14n11#WithComments", XmlCanonicalizationAlgorithm.CanonicalXml11WithComments)]
    [DataRow("http://www.w3.org/2001/10/xml-exc-c14n#", XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10)]
    [DataRow("http://www.w3.org/2001/10/xml-exc-c14n#WithComments", XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments)]
    public void EachOfTheSixShippedAlgorithmsResolves(string algorithmUri, XmlCanonicalizationAlgorithm expected)
    {
        //Literal URIs (XmlSignatureIdentifiers's own members are properties, not compile-time constants, so
        //they cannot appear directly as DataRow arguments) — copied exact-character from that type's own
        //source, the six clause 6.3(d) identifiers this shipped substrate already supports.
        (XmlNodeTable table, XmlCanonicalizationMethodInfo method) = ReadMethod(algorithmUri, BaseMemoryPool.Shared);
        using(table)
        {
            bool isResolved = XAdESCanonicalizationManagement.TryResolve(true, method, out XmlCanonicalizationAlgorithm algorithm, out XAdESProcessingError error);

            Assert.IsTrue(isResolved, $"{algorithmUri} must resolve but was refused with {error.Failure}.");
            Assert.AreEqual(expected, algorithm);
        }
    }


    /// <summary>
    /// Proves clause 6.3 letter d)'s own six-value enumeration ("the <c>Algorithm</c> attribute of
    /// <c>ds:SignedInfo</c>'s <c>ds:CanonicalizationMethod</c> child element shall have one of the following
    /// values") is exactly the shipped surface this one resolution point already recognizes — the SAME six URIs
    /// <see cref="EachOfTheSixShippedAlgorithmsResolves"/> proves resolve, restated here with letter d)'s own
    /// clause anchor rather than clause 4.5's NOTE 1/NOTE 2, since Table 2's row t02 cites letter d) as the
    /// requirement governing <c>ds:CanonicalizationMethod</c>, and row t04 cites it for
    /// <c>ds:Reference/ds:Transforms</c> via letter f).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter d).
    /// </summary>
    [TestMethod]
    [DataRow("http://www.w3.org/2006/12/xml-c14n11")]
    [DataRow("http://www.w3.org/2001/10/xml-exc-c14n#")]
    [DataRow("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")]
    [DataRow("http://www.w3.org/2006/12/xml-c14n11#WithComments")]
    [DataRow("http://www.w3.org/2001/10/xml-exc-c14n#WithComments")]
    [DataRow("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments")]
    public void LetterDsSixUriEnumerationResolves(string algorithmUri)
    {
        (XmlNodeTable table, XmlCanonicalizationMethodInfo method) = ReadMethod(algorithmUri, BaseMemoryPool.Shared);
        using(table)
        {
            bool isResolved = XAdESCanonicalizationManagement.TryResolve(true, method, out _, out XAdESProcessingError error);

            Assert.IsTrue(isResolved, $"Letter d)'s own URI {algorithmUri} must resolve but was refused with {error.Failure}.");
        }
    }


    /// <summary>
    /// Proves clause 6.3 letter e) ("The signer/signature generator SHOULD NOT use a canonicalization algorithm
    /// that provides comments") is verifier-observable on the resolved algorithm through
    /// <see cref="XAdESCanonicalizationManagement.IsWithCommentsAlgorithm"/>: the three "with comments" variants
    /// flag <see langword="true"/>, their three comment-omitting counterparts flag <see langword="false"/> — a
    /// SHOULD-NOT advisory, never a read-time refusal (letter d)'s own six-URI set stays fully accepted).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter e).
    /// </summary>
    [TestMethod]
    [DataRow(XmlCanonicalizationAlgorithm.CanonicalXml10, false)]
    [DataRow(XmlCanonicalizationAlgorithm.CanonicalXml10WithComments, true)]
    [DataRow(XmlCanonicalizationAlgorithm.CanonicalXml11, false)]
    [DataRow(XmlCanonicalizationAlgorithm.CanonicalXml11WithComments, true)]
    [DataRow(XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10, false)]
    [DataRow(XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments, true)]
    public void LetterEsWithCommentsObservationMatchesTheAlgorithmsOwnName(XmlCanonicalizationAlgorithm algorithm, bool expected)
    {
        Assert.AreEqual(expected, XAdESCanonicalizationManagement.IsWithCommentsAlgorithm(algorithm));
    }
}
