using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Adversarial proofs that signature-wrapping shapes — a document-order-independent cloned <c>Id</c>, and an
/// attacker's own <c>Object</c> carrying a decoy element sharing the honest reference's target <c>Id</c> —
/// never let <see cref="XmlReferenceProcessing.TryComputeDigestInput"/> resolve to either the honest or the
/// attacker's element, per the fail-closed <see cref="XmlSignatureProcessingFailure.DuplicateId"/> posture:
/// signature wrapping via duplicate/retargeted Ids must die on it. Every refusal path is
/// observed through <see cref="MeteredHousePool"/> accounting.
/// </summary>
[TestClass]
internal sealed class XmlSignatureWrappingAttackTests
{
    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private const string XAdESNamespaceV132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string SignedPropertiesTypeUri = "http://uri.etsi.org/01903#SignedProperties";


    private static (XmlNodeTable Table, XmlSignature[] Signatures) ReadAllSignaturesInDocumentOrder(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        var signatures = new XmlSignature[signatureIndices.Length];
        for(int i = 0; i < signatureIndices.Length; ++i)
        {
            bool isRead = XmlSignature.TryRead(table!, signatureIndices[i], pool, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
            Assert.IsTrue(isRead, $"Signature #{i} must read but was refused with {readSignatureError.Failure}.");
            signatures[i] = signature!;
        }

        return (table!, signatures);
    }


    /// <summary>
    /// Proves the "ambiguous targets are how signature-wrapping works — fail closed, never first-match",
    /// grounded in the null-URI/shortname-XPointer support <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.2 requires every conformant application to implement: a
    /// wrapping-style clone of the honest target — same recognized <c>Id</c>, hostile content, placed BEFORE
    /// the honest element in document order (the position a naive first-match resolver would pick) — refuses
    /// as <see cref="XmlSignatureProcessingFailure.DuplicateId"/> through the full engine entry point rather
    /// than silently digesting the attacker's element.
    /// </summary>
    [TestMethod]
    public void AttackerClonePrecedingTheHonestTargetRefusesRatherThanResolvingToEither()
    {
        string document = $$"""
            <Document>
              <Target Id="target">ATTACKER-CONTENT</Target>
              <Target Id="target">honest-content</Target>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature[] signatures) = ReadAllSignaturesInDocumentOrder(document, BaseMemoryPool.Shared);
        using(table)
        using(signatures[0])
        {
            using var metered = new MeteredHousePool();
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signatures[0], 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed, "A cloned Id preceding the honest target must never resolve.");
            Assert.IsNull(digestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.DuplicateId, error.Failure);
            Assert.AreEqual(0L, metered.OutstandingCount, "The refusal must not leave any rented buffer outstanding.");
        }
    }


    /// <summary>
    /// Proves the fail-closed posture, over the same <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.2 null-URI/shortname-XPointer support the preceding test grounds
    /// against, holds regardless of document order — the order-independence mirror of that test: the
    /// attacker's clone now FOLLOWS the honest element instead of preceding it. The refusal is identical
    /// either way, proving the fail-closed disposition does not depend on document order — a first-match
    /// resolver would have picked a different element in each of the two tests, but this reader picks
    /// neither.
    /// </summary>
    [TestMethod]
    public void AttackerCloneFollowingTheHonestTargetRefusesRatherThanResolvingToEither()
    {
        string document = $$"""
            <Document>
              <Target Id="target">honest-content</Target>
              <Target Id="target">ATTACKER-CONTENT</Target>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature[] signatures) = ReadAllSignaturesInDocumentOrder(document, BaseMemoryPool.Shared);
        using(table)
        using(signatures[0])
        {
            using var metered = new MeteredHousePool();
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signatures[0], 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed, "A cloned Id following the honest target must never resolve.");
            Assert.IsNull(digestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.DuplicateId, error.Failure);
            Assert.AreEqual(0L, metered.OutstandingCount, "The refusal must not leave any rented buffer outstanding.");
        }
    }


    /// <summary>
    /// Proves signature wrapping via duplicate/retargeted Ids dies on the same fail-closed posture even over a decoy
    /// element the attacker relocates inside their OWN wrapped <c>ds:Signature</c> — itself nested inside an
    /// <c>Object</c> of the honest signature, the shape <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 9's "Recorded misc. facts" notes the schema permits: it still triggers
    /// <see cref="XmlSignatureProcessingFailure.DuplicateId"/> for the HONEST signature's own reference —
    /// <c>Id</c> recognition is document-wide (<see cref="XmlNodeTable.TryFindElementById"/> scans every
    /// element in the table), so hiding a decoy deep inside an attacker-controlled subtree does not exempt
    /// it from the ambiguity check. The engine never resolves an attacker-relocated target.
    /// </summary>
    [TestMethod]
    public void DecoyInsideAttackerWrappedObjectStillTriggersDuplicateIdForTheHonestReference()
    {
        string document = $$"""
            <Document>
              <Target Id="target">honest-content</Target>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}" Id="honest">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
                <Object>
                  <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}" Id="attacker-wrapped">
                    <SignedInfo>
                      <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                      <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                      <Reference URI="#dummy">
                        <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                        <DigestValue>Ag==</DigestValue>
                      </Reference>
                    </SignedInfo>
                    <SignatureValue>Ag==</SignatureValue>
                    <Object>
                      <Target Id="target">ATTACKER-CONTENT</Target>
                    </Object>
                  </Signature>
                </Object>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature[] signatures) = ReadAllSignaturesInDocumentOrder(document, BaseMemoryPool.Shared);
        Assert.HasCount(2, signatures, "Both the honest outer signature and the attacker's nested wrapped signature must be located.");
        using(table)
        using(signatures[0])
        using(signatures[1])
        {
            using var metered = new MeteredHousePool();
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signatures[0], 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed, "A decoy relocated inside the attacker's own wrapped Object must still make 'target' ambiguous document-wide.");
            Assert.IsNull(digestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.DuplicateId, error.Failure);
            Assert.AreEqual(0L, metered.OutstandingCount, "The refusal must not leave any rented buffer outstanding.");
        }
    }


    /// <summary>
    /// Proves the table/node-identity pin for <see cref="XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding"/>,
    /// extending this suite's own wrapping discipline into the XAdES layer: an attacker's decoy element OUTSIDE the honest <c>ds:Signature</c>
    /// carries the SAME <c>Id</c> as the genuine <c>SignedProperties</c> the honest <c>Type="http://uri.etsi.org/01903#SignedProperties"</c>
    /// reference targets. Since <c>Id</c> recognition is document-wide (<see cref="XmlNodeTable.TryFindElementById"/> scans every element in the
    /// table, exactly as <see cref="DecoyInsideAttackerWrappedObjectStillTriggersDuplicateIdForTheHonestReference"/> proves for the XMLDSIG core),
    /// the ambiguity refuses the binding rather than resolving to either element. Anchored to clause 4.4.2 of <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void DecoySharingTheHonestSignedPropertiesIdRefusesTheSignedPropertiesBinding()
    {
        string document = $$"""
            <Document>
              <Decoy Id="spid">ATTACKER-CONTENT</Decoy>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}" Id="honest">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#spid" Type="{{SignedPropertiesTypeUri}}">
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
                <Object>
                  <QualifyingProperties xmlns="{{XAdESNamespaceV132}}" Target="#honest">
                    <SignedProperties Id="spid">
                      <SignedSignatureProperties><SigningTime/></SignedSignatureProperties>
                    </SignedProperties>
                  </QualifyingProperties>
                </Object>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature[] signatures) = ReadAllSignaturesInDocumentOrder(document, BaseMemoryPool.Shared);
        using(table)
        using(signatures[0])
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signatures[0], out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");
            Assert.IsTrue(result.QualifyingProperties.HasSignedProperties);

            bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding(
                table, signatures[0], result.QualifyingProperties.SignedProperties, resolver: null, BaseMemoryPool.Shared, out _, out XAdESProcessingError error);

            Assert.IsFalse(isBound, "A decoy sharing the honest SignedProperties' own Id must make the reference ambiguous.");
            Assert.AreEqual(XAdESProcessingFailure.SignedPropertiesReferenceDereferenceFailed, error.Failure);
            Assert.IsNotNull(error.InnerProcessingError);
            Assert.AreEqual(XmlSignatureProcessingFailure.DuplicateId, error.InnerProcessingError!.Value.Failure);
        }
    }
}
