using System.Globalization;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESCounterSignature.TryRead"/> against clause 5.2.7.2's enveloped-countersignature
/// <c>CounterSignature</c> qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESCounterSignatureTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private const string CountersignedSignatureType = "http://uri.etsi.org/01903#CountersignedSignature";


    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string MinimalCounterSignature(string? idAttribute = null, string innerSignatureContent = """
        <ds:Signature xmlns:ds="{0}" Id="counterSig">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{1}"/>
            <ds:SignatureMethod Algorithm="{2}"/>
            <ds:Reference URI="#data1">
              <ds:DigestMethod Algorithm="{3}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue>AQ==</ds:SignatureValue>
          <ds:Object Id="data1">payload</ds:Object>
        </ds:Signature>
        """)
    {
        string idPart = idAttribute is null ? string.Empty : $" Id=\"{idAttribute}\"";
        string signature = string.Format(CultureInfo.InvariantCulture, innerSignatureContent, DsNamespace, XmlSignatureIdentifiers.CanonicalXml11Uri, SignatureMethodAlgorithm, DigestMethodAlgorithm);

        return $"""<CounterSignature xmlns="{V132}"{idPart}>{signature}</CounterSignature>""";
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2, the minimal shape — one
    /// <c>ds:Signature</c> child, no <c>Id</c> — reads, exposing the fully-parsed embedded signature and its
    /// own <c>ds:Reference</c> children, and custody balances to zero once the caller disposes the returned
    /// value.
    /// </summary>
    [TestMethod]
    public void MinimalShapeReadsAndExposesEmbeddedSignatureAndReferences()
    {
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(MinimalCounterSignature(), BaseMemoryPool.Shared);
            bool isRead = XAdESCounterSignature.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESCounterSignature? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsFalse(value!.HasId);
            Assert.AreEqual("counterSig", Encoding.UTF8.GetString(value.Signature.Id));
            Assert.HasCount(1, value.Signature.SignedInfo.References);
            Assert.AreEqual("#data1", Encoding.UTF8.GetString(value.Signature.SignedInfo.References[0].Uri));

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer the embedded signature rented must be released once the caller disposes the value.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2's own NOTE 1 rationale, the
    /// optional <c>Id</c> attribute — which lets this unsigned property be referenced by URI when indirect
    /// incorporation is used — reads exact-character when present.
    /// </summary>
    [TestMethod]
    public void IdAttributeSurfacesWhenPresent()
    {
        using XmlNodeTable table = Parse(MinimalCounterSignature(idAttribute: "cs1"), BaseMemoryPool.Shared);
        bool isRead = XAdESCounterSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCounterSignature? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasId);
            Assert.AreEqual("cs1", Encoding.UTF8.GetString(value.Id));
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2's acquired v132
    /// <c>CounterSignatureType</c> schema, an entirely empty <c>CounterSignature</c> — no <c>ds:Signature</c>
    /// child at all — is refused.
    /// </summary>
    [TestMethod]
    public void MissingDsSignatureChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""<CounterSignature xmlns="{V132}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESCounterSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A CounterSignature with no ds:Signature child must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2's schema, a single child
    /// that is not a <c>ds:Signature</c> element is refused.
    /// </summary>
    [TestMethod]
    public void NonDsSignatureChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""<CounterSignature xmlns="{V132}"><NotASignature/></CounterSignature>""", BaseMemoryPool.Shared);
        bool isRead = XAdESCounterSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A non-ds:Signature single child must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2's schema — a single
    /// <c>ds:Signature</c> child — trailing content after the embedded signature is refused.
    /// </summary>
    [TestMethod]
    public void TrailingContentAfterSignatureIsRefused()
    {
        string document = MinimalCounterSignature().Replace("</CounterSignature>", "<Extra/></CounterSignature>", StringComparison.Ordinal);
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCounterSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Trailing content after ds:Signature must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2's single-child schema, a
    /// second <c>ds:Signature</c> element is refused as a duplicate, distinct from a generic unknown-element
    /// refusal.
    /// </summary>
    [TestMethod]
    public void DuplicateDsSignatureIsRefused()
    {
        string innerSignature = $"""
            <ds:Signature xmlns:ds="{DsNamespace}">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="#data1">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object Id="data1">payload</ds:Object>
            </ds:Signature>
            """;
        string document = $"""<CounterSignature xmlns="{V132}">{innerSignature}{innerSignature}</CounterSignature>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCounterSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A duplicate ds:Signature child must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2, an unrecognized attribute
    /// beyond the optional <c>Id</c> is refused fail-closed.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        string document = MinimalCounterSignature().Replace($"""xmlns="{V132}">""", $"""xmlns="{V132}" unexpected="value">""", StringComparison.Ordinal);
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCounterSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2, a <c>ds:Signature</c> child
    /// that does not itself read as a well-formed XMLDSIG signature — here, missing the mandatory
    /// <c>ds:SignedInfo</c> — is refused with <see cref="XAdESReadFailure.MalformedEmbeddedSignature"/>, the
    /// bridge <see cref="XAdESCounterSignature.TryRead"/> applies over <see cref="XmlSignature.TryRead"/>'s
    /// own refusal.
    /// </summary>
    [TestMethod]
    public void MalformedEmbeddedSignatureIsRefused()
    {
        string document = $"""<CounterSignature xmlns="{V132}"><ds:Signature xmlns:ds="{DsNamespace}"><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></CounterSignature>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCounterSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A ds:Signature missing its mandatory SignedInfo must be refused.");
        Assert.AreEqual(XAdESReadFailure.MalformedEmbeddedSignature, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2 and the pooling
    /// discipline, custody is balanced even on a refusal path: when the embedded signature's <c>SignedInfo</c> and <c>SignatureValue</c> already decoded successfully before a malformed
    /// <c>ds:X509Certificate</c> (invalid base64) inside <c>KeyInfo</c> causes the whole embedded read to refuse, nothing is left outstanding.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnARefusalDuringPartialEmbeddedDecoding()
    {
        string document = $"""
            <CounterSignature xmlns="{V132}">
              <ds:Signature xmlns:ds="{DsNamespace}">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                  <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                  <ds:Reference URI="#data1">
                    <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                    <ds:DigestValue>AQ==</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
                <ds:KeyInfo><ds:X509Data><ds:X509Certificate>not-valid-base64!!!</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                <ds:Object Id="data1">payload</ds:Object>
              </ds:Signature>
            </CounterSignature>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESCounterSignature.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESCounterSignature? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "A malformed embedded KeyInfo must refuse the whole read.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.MalformedEmbeddedSignature, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer the embedded signature rented before the refusal must already be released.");
            }
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clauses 5.2.7.1 and 5.2.7.2 together, a
    /// real countersigned shape: an outer <c>ds:Signature</c> carrying a <c>CounterSignature</c> qualifying
    /// property whose embedded <c>ds:Signature</c> carries a <c>ds:Reference</c> naming the clause 5.2.7.1
    /// countersignature marker and pointing at the outer signature's own <c>ds:SignatureValue</c> — reading
    /// the embedded signature through <see cref="XAdESCounterSignature.TryRead"/>, recognizing it as a
    /// countersignature through <see cref="XAdESCountersignatureIdentification.IsCountersignature"/>, and
    /// resolving the marking reference's own bare-name <c>URI</c> to the outer signature's
    /// <c>ds:SignatureValue</c> element — all structural surface, with no digest computed or compared (clause
    /// 5.2.7.2's digest rule is verification-side — <see cref="XAdESCounterSignatureDigestRule"/> locates the
    /// reference structurally; <c>Verifiable.Cryptography.Pki.XAdESLevelRules.CheckCounterSignatureDigestAsync</c>
    /// performs the actual digest check above the leaf).
    /// </summary>
    [TestMethod]
    public void RealCountersignedShapeReadsAndIdentifiesTheEmbeddedCountersignature()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="outerSig">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="#outerData">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue Id="outerSigValue">AQ==</ds:SignatureValue>
              <ds:Object Id="outerData">payload</ds:Object>
              <ds:Object>
                <CounterSignature xmlns="{V132}">
                  <ds:Signature Id="counterSig">
                    <ds:SignedInfo>
                      <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                      <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                      <ds:Reference URI="#outerSigValue" Type="{CountersignedSignatureType}">
                        <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                        <ds:DigestValue>AQ==</ds:DigestValue>
                      </ds:Reference>
                    </ds:SignedInfo>
                    <ds:SignatureValue>AQ==</ds:SignatureValue>
                  </ds:Signature>
                </CounterSignature>
              </ds:Object>
            </ds:Signature>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table);
        Assert.HasCount(2, signatureIndices, "The fixture carries the outer signature and the nested countersignature.");
        bool isOuterRead = XmlSignature.TryRead(table, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? outerSignature, out XmlSignatureReadError outerError);
        Assert.IsTrue(isOuterRead, $"The outer signature must read but was refused with {outerError.Failure}.");
        using(outerSignature)
        {
            int counterSignatureElementIndex = -1;
            foreach(XmlSignatureObject signatureObject in outerSignature!.Objects)
            {
                foreach(int contentIndex in signatureObject.ContentNodeIndices)
                {
                    if(table.KindOf(contentIndex) == XmlNodeKind.Element && XmlSignatureModelGrammar.IsElement(table, contentIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CounterSignature"u8))
                    {
                        counterSignatureElementIndex = contentIndex;
                    }
                }
            }

            Assert.IsGreaterThanOrEqualTo(0, counterSignatureElementIndex, "The fixture's second ds:Object must carry a CounterSignature child.");
            bool isCounterSignatureRead = XAdESCounterSignature.TryRead(table, counterSignatureElementIndex, BaseMemoryPool.Shared, out XAdESCounterSignature? counterSignature, out XAdESReadError counterSignatureError);
            Assert.IsTrue(isCounterSignatureRead, $"The CounterSignature must read but was refused with {counterSignatureError.Failure}.");
            using(counterSignature)
            {
                Assert.IsTrue(XAdESCountersignatureIdentification.IsCountersignature(counterSignature!.Signature), "The embedded signature must be recognized as a countersignature via its Type-marked ds:Reference.");

                XmlReference markerReference = default;
                foreach(XmlReference reference in counterSignature.Signature.SignedInfo.References)
                {
                    if(XAdESCountersignatureIdentification.IsCountersignatureReference(reference))
                    {
                        markerReference = reference;
                    }
                }

                Assert.IsTrue(markerReference.HasUri);
                ReadOnlySpan<byte> uri = markerReference.Uri;
                Assert.IsTrue(uri.Length > 0 && uri[0] == (byte)'#', "The marker reference's URI must be a same-document fragment.");
                bool isTargetFound = table.TryFindElementById(uri[1..], out int targetElementIndex, out _);
                Assert.IsTrue(isTargetFound, "The marker reference's URI must resolve within the document.");
                Assert.AreEqual(outerSignature.SignatureValueElementIndex, targetElementIndex, "The marker reference must resolve to the OUTER signature's own ds:SignatureValue element.");
            }
        }
    }
}
