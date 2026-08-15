using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference"/> against clause
/// 5.2.7.2's digest-rule shape requirement of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: "shall contain one <c>ds:Reference</c> element referencing the
/// <c>ds:SignatureValue</c> element of the embedding and countersigned XAdES signature." Adversarial shapes
/// wrong target, self-referencing, dangling, and ambiguous (two correct matches).
/// </summary>
[TestClass]
internal sealed class XAdESCounterSignatureDigestRuleTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Builds a document with an outer signature (<c>Id="outerSig"</c>, <c>ds:SignatureValue Id="outerSigValue"</c>)
    /// carrying a second <c>ds:Object</c> whose <c>CounterSignature</c> embeds a signature with exactly one
    /// <c>ds:Reference</c> pointing at <paramref name="referenceTargetFragment"/> (already including the
    /// leading <c>#</c>, or <see langword="null"/> to omit the <c>URI</c> attribute entirely) plus, when
    /// <paramref name="secondReferenceTargetFragment"/> is supplied, a SECOND reference at that target too (the
    /// ambiguous-match shape).
    /// </summary>
    private static string BuildDocument(string? referenceTargetFragment, string? secondReferenceTargetFragment = null)
    {
        string uriAttribute = referenceTargetFragment is null ? string.Empty : $" URI=\"{referenceTargetFragment}\"";
        string secondReference = secondReferenceTargetFragment is null ? string.Empty : $"""
            <ds:Reference URI="{secondReferenceTargetFragment}">
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
            """;

        return $"""
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
                      <ds:Reference{uriAttribute}>
                        <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                        <ds:DigestValue>AQ==</ds:DigestValue>
                      </ds:Reference>
                      {secondReference}
                    </ds:SignedInfo>
                    <ds:SignatureValue Id="counterSigValue">AQ==</ds:SignatureValue>
                  </ds:Signature>
                </CounterSignature>
              </ds:Object>
              <ds:Object>
                <Decoy xmlns="{V132}"><ds:SignatureValue xmlns:ds="{DsNamespace}" Id="decoySigValue">AQ==</ds:SignatureValue></Decoy>
              </ds:Object>
            </ds:Signature>
            """;
    }


    private static (XmlSignature Outer, XAdESCounterSignature CounterSignature, XmlNodeTable Table) ReadFixture(string document)
    {
        XmlNodeTable table = Parse(document);
        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table);
        Assert.IsGreaterThanOrEqualTo(1, signatureIndices.Length, "The fixture must carry at least the outer signature.");
        bool isOuterRead = XmlSignature.TryRead(table, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? outer, out XmlSignatureReadError outerError);
        Assert.IsTrue(isOuterRead, $"The outer signature must read but was refused with {outerError.Failure}.");

        int counterSignatureElementIndex = -1;
        foreach(XmlSignatureObject signatureObject in outer!.Objects)
        {
            foreach(int contentIndex in signatureObject.ContentNodeIndices)
            {
                if(table.KindOf(contentIndex) == XmlNodeKind.Element && XmlSignatureModelGrammar.IsElement(table, contentIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CounterSignature"u8))
                {
                    counterSignatureElementIndex = contentIndex;
                }
            }
        }

        Assert.IsGreaterThanOrEqualTo(0, counterSignatureElementIndex, "The fixture must carry a CounterSignature.");
        bool isCounterSignatureRead = XAdESCounterSignature.TryRead(table, counterSignatureElementIndex, BaseMemoryPool.Shared, out XAdESCounterSignature? counterSignature, out XAdESReadError counterSignatureError);
        Assert.IsTrue(isCounterSignatureRead, $"The CounterSignature must read but was refused with {counterSignatureError.Failure}.");

        return (outer, counterSignature!, table);
    }


    /// <summary>
    /// Proves the happy path: the countersignature's sole <c>ds:Reference</c>, targeting the outer signature's
    /// own <c>ds:SignatureValue</c>, is located per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2's "shall contain one ds:Reference" rule.
    /// </summary>
    [TestMethod]
    public void CorrectSelfReferenceIsLocated()
    {
        (XmlSignature outer, XAdESCounterSignature counterSignature, XmlNodeTable table) = ReadFixture(BuildDocument("#outerSigValue"));
        using(table)
        using(outer)
        using(counterSignature)
        {
            bool isLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(table, outer, counterSignature, out XmlReference reference, out int ordinal, out XAdESProcessingError error);
            Assert.IsTrue(isLocated, $"Must locate but was refused with {error.Failure}.");
            Assert.AreEqual(0, ordinal);
            Assert.AreEqual("#outerSigValue", Encoding.UTF8.GetString(reference.Uri));
        }
    }


    /// <summary>
    /// Proves the wrong-target adversarial shape: a reference resolving to a DIFFERENT element entirely (a
    /// decoy, non-<c>ds:SignatureValue</c> element sharing no relation to the countersigned signature) is
    /// refused with <see cref="XAdESProcessingFailure.CounterSignatureSignatureValueReferenceNotFound"/> per
    /// clause 5.2.7.2 of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>,
    /// since it never resolves to the required target.
    /// </summary>
    [TestMethod]
    public void ReferenceToAWrongTargetIsRefused()
    {
        (XmlSignature outer, XAdESCounterSignature counterSignature, XmlNodeTable table) = ReadFixture(BuildDocument("#decoySigValue"));
        using(table)
        using(outer)
        using(counterSignature)
        {
            bool isLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(table, outer, counterSignature, out _, out _, out XAdESProcessingError error);
            Assert.IsFalse(isLocated, "A reference to the wrong target must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.CounterSignatureSignatureValueReferenceNotFound, error.Failure);
        }
    }


    /// <summary>
    /// Proves the self-referencing adversarial shape: a reference resolving to the COUNTERSIGNATURE's OWN
    /// <c>ds:SignatureValue</c> — never the countersigned outer signature's — is refused with
    /// <see cref="XAdESProcessingFailure.CounterSignatureSignatureValueReferenceNotFound"/>, the same
    /// "no reference points at the right target" disposition as every other non-match, per clause 5.2.7.2 of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void SelfReferencingReferenceIsRefused()
    {
        (XmlSignature outer, XAdESCounterSignature counterSignature, XmlNodeTable table) = ReadFixture(BuildDocument("#counterSigValue"));
        using(table)
        using(outer)
        using(counterSignature)
        {
            bool isLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(table, outer, counterSignature, out _, out _, out XAdESProcessingError error);
            Assert.IsFalse(isLocated, "A self-referencing reference must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.CounterSignatureSignatureValueReferenceNotFound, error.Failure);
        }
    }


    /// <summary>
    /// Proves the dangling adversarial shape: a reference whose fragment names no <c>Id</c> present anywhere
    /// in the document is refused identically to the wrong-target and self-referencing shapes — a dangling
    /// URI can never resolve to the required target either, per clause 5.2.7.2 of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void DanglingReferenceIsRefused()
    {
        (XmlSignature outer, XAdESCounterSignature counterSignature, XmlNodeTable table) = ReadFixture(BuildDocument("#doesNotExist"));
        using(table)
        using(outer)
        using(counterSignature)
        {
            bool isLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(table, outer, counterSignature, out _, out _, out XAdESProcessingError error);
            Assert.IsFalse(isLocated, "A dangling reference must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.CounterSignatureSignatureValueReferenceNotFound, error.Failure);
        }
    }


    /// <summary>
    /// Proves a reference with no <c>URI</c> attribute at all is likewise never a candidate — the located-zero
    /// disposition, since an application-context (no-URI) reference cannot be the required same-document
    /// bare-name-XPointer self-reference clause 5.2.7.2 of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> requires.
    /// </summary>
    [TestMethod]
    public void MissingUriReferenceIsRefused()
    {
        (XmlSignature outer, XAdESCounterSignature counterSignature, XmlNodeTable table) = ReadFixture(BuildDocument(referenceTargetFragment: null));
        using(table)
        using(outer)
        using(counterSignature)
        {
            bool isLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(table, outer, counterSignature, out _, out _, out XAdESProcessingError error);
            Assert.IsFalse(isLocated, "A reference with no URI at all must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.CounterSignatureSignatureValueReferenceNotFound, error.Failure);
        }
    }


    /// <summary>
    /// Proves clause 5.2.7.2's "shall contain ONE" read as an exact cardinality: two DISTINCT references both
    /// resolving to the outer signature's own <c>ds:SignatureValue</c> refuse as ambiguous rather than the
    /// first match being silently accepted. Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2.
    /// </summary>
    [TestMethod]
    public void TwoMatchingReferencesAreRefusedAsAmbiguous()
    {
        (XmlSignature outer, XAdESCounterSignature counterSignature, XmlNodeTable table) = ReadFixture(BuildDocument("#outerSigValue", "#outerSigValue"));
        using(table)
        using(outer)
        using(counterSignature)
        {
            bool isLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(table, outer, counterSignature, out _, out _, out XAdESProcessingError error);
            Assert.IsFalse(isLocated, "Two references to the correct target must be refused as ambiguous.");
            Assert.AreEqual(XAdESProcessingFailure.CounterSignatureSignatureValueReferenceAmbiguous, error.Failure);
        }
    }


    /// <summary>
    /// Proves clause 5.2.7.2's "other <c>ds:Reference</c> elements referencing other data objects may be
    /// added": a correct self-reference alongside an unrelated second reference (to the outer signed data
    /// object, not to any <c>ds:SignatureValue</c>) still locates cleanly — the extra reference is silently
    /// skipped, never treated as ambiguity. Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2.
    /// </summary>
    [TestMethod]
    public void CorrectSelfReferenceAlongsideAnUnrelatedReferenceStillLocates()
    {
        (XmlSignature outer, XAdESCounterSignature counterSignature, XmlNodeTable table) = ReadFixture(BuildDocument("#outerSigValue", "#outerData"));
        using(table)
        using(outer)
        using(counterSignature)
        {
            bool isLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(table, outer, counterSignature, out XmlReference reference, out int ordinal, out XAdESProcessingError error);
            Assert.IsTrue(isLocated, $"Must locate but was refused with {error.Failure}.");
            Assert.AreEqual(0, ordinal);
            Assert.AreEqual("#outerSigValue", Encoding.UTF8.GetString(reference.Uri));
        }
    }
}
