using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESCommitmentTypeIndication.TryRead"/> and
/// <see cref="XAdESCommitmentTypeIndication.TryVerifyObjectReferences"/> against clause 5.2.3's
/// <c>CommitmentTypeIndication</c> qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESCommitmentTypeIndicationTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static (XmlNodeTable Table, XmlSignature Signature) ReadSoleSignature(string document)
    {
        XmlNodeTable table = Parse(document);
        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table);
        Assert.HasCount(1, signatureIndices, "The fixture must carry exactly one ds:Signature.");
        bool isRead = XmlSignature.TryRead(table, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isRead, $"The signature must read but was refused with {signatureError.Failure}.");

        return (table, signature!);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3's minimal shape: <c>CommitmentTypeId</c> followed by one
    /// <c>ObjectReference</c> reads, with the choice recognized as
    /// <see cref="XAdESCommitmentTypeIndicationChoice.ObjectReferences"/>.
    /// </summary>
    [TestMethod]
    public void MinimalObjectReferenceShapeReads()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-origin</Identifier></CommitmentTypeId>
              <ObjectReference>#ref1</ObjectReference>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out XAdESCommitmentTypeIndication value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreEqual(XAdESCommitmentTypeIndicationChoice.ObjectReferences, value.Choice);
        Assert.AreEqual(1, value.ObjectReferenceCount);
        Assert.AreEqual("#ref1", Encoding.UTF8.GetString(value.ObjectReferenceAt(0)));
        Assert.IsFalse(value.HasCommitmentTypeQualifiers);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, the second choice arm: a single,
    /// empty <c>AllSignedDataObjects</c> marker reads, with zero <c>ObjectReference</c> entries.
    /// </summary>
    [TestMethod]
    public void AllSignedDataObjectsShapeReads()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-approval</Identifier></CommitmentTypeId>
              <AllSignedDataObjects/>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out XAdESCommitmentTypeIndication value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreEqual(XAdESCommitmentTypeIndicationChoice.AllSignedDataObjects, value.Choice);
        Assert.AreEqual(0, value.ObjectReferenceCount);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, "shall incorporate one
    /// <c>ObjectReference</c> element for each one of signed data objects" for a multi-object commitment
    /// subset: more than one <c>ObjectReference</c> reads, in document order.
    /// </summary>
    [TestMethod]
    public void MultipleObjectReferencesReadInOrder()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-origin</Identifier></CommitmentTypeId>
              <ObjectReference>#ref1</ObjectReference>
              <ObjectReference>#ref2</ObjectReference>
              <ObjectReference>#ref3</ObjectReference>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out XAdESCommitmentTypeIndication value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreEqual(3, value.ObjectReferenceCount);
        Assert.AreEqual("#ref1", Encoding.UTF8.GetString(value.ObjectReferenceAt(0)));
        Assert.AreEqual("#ref2", Encoding.UTF8.GetString(value.ObjectReferenceAt(1)));
        Assert.AreEqual("#ref3", Encoding.UTF8.GetString(value.ObjectReferenceAt(2)));
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, the optional
    /// <c>CommitmentTypeQualifiers</c> reads its <c>CommitmentTypeQualifier</c> children as unmodeled
    /// <c>AnyType</c> content.
    /// </summary>
    [TestMethod]
    public void CommitmentTypeQualifiersRead()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-origin</Identifier></CommitmentTypeId>
              <AllSignedDataObjects/>
              <CommitmentTypeQualifiers>
                <CommitmentTypeQualifier><Note xmlns="http://example.com/ns">extra info</Note></CommitmentTypeQualifier>
              </CommitmentTypeQualifiers>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out XAdESCommitmentTypeIndication value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasCommitmentTypeQualifiers);
        Assert.HasCount(1, value.CommitmentTypeQualifiers);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3's acquired v132 schema, an
    /// empty <c>CommitmentTypeQualifiers</c> (zero <c>CommitmentTypeQualifier</c> children) reads — the
    /// schema's <c>CommitmentTypeQualifier</c> declares <c>minOccurs="0"</c>, unlike <c>SigPolicyQualifier</c>
    /// (clause 5.2.9.1), which the survey confirms has no such floor.
    /// </summary>
    [TestMethod]
    public void EmptyCommitmentTypeQualifiersReads()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-origin</Identifier></CommitmentTypeId>
              <AllSignedDataObjects/>
              <CommitmentTypeQualifiers/>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out XAdESCommitmentTypeIndication value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasCommitmentTypeQualifiers);
        Assert.HasCount(0, value.CommitmentTypeQualifiers);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, "its <c>Identifier</c> child
    /// shall not have a <c>Qualifier</c> attribute (i.e. the aforementioned URI shall not represent an OID
    /// value)" — a <c>CommitmentTypeId</c> whose <c>Identifier</c> carries <c>Qualifier="OIDAsURI"</c> is
    /// refused, even though <c>ObjectIdentifierType</c>'s own general schema permits it.
    /// </summary>
    [TestMethod]
    public void CommitmentTypeIdWithQualifierIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier Qualifier="OIDAsURI">urn:oid:1.2.3.4</Identifier></CommitmentTypeId>
              <AllSignedDataObjects/>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A CommitmentTypeId with a Qualifier attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.CommitmentTypeIdQualifierNotPermitted, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3's fixed
    /// <c>CommitmentTypeIndicationType</c> sequence, a missing <c>CommitmentTypeId</c> is refused — it is the
    /// mandatory first child.
    /// </summary>
    [TestMethod]
    public void MissingCommitmentTypeIdIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <AllSignedDataObjects/>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A missing CommitmentTypeId must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3's <c>xsd:choice</c>, the
    /// choice itself is mandatory: neither an <c>ObjectReference</c> nor an <c>AllSignedDataObjects</c>
    /// present is refused.
    /// </summary>
    [TestMethod]
    public void MissingChoiceIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-origin</Identifier></CommitmentTypeId>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A missing choice must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, an <c>AllSignedDataObjects</c>
    /// element carrying a stray element child is refused — the marker must be genuinely empty of meaningful
    /// content.
    /// </summary>
    [TestMethod]
    public void AllSignedDataObjectsWithElementChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-origin</Identifier></CommitmentTypeId>
              <AllSignedDataObjects><Unexpected/></AllSignedDataObjects>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "AllSignedDataObjects with an element child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnexpectedElementContent, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, an <c>AllSignedDataObjects</c>
    /// element containing only insignificant whitespace still reads — pretty-printing whitespace is tolerated
    /// everywhere else in this leaf's grammar, and this marker is no exception.
    /// </summary>
    [TestMethod]
    public void AllSignedDataObjectsWithOnlyWhitespaceReads()
    {
        using XmlNodeTable table = Parse($"""
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-origin</Identifier></CommitmentTypeId>
              <AllSignedDataObjects>
              </AllSignedDataObjects>
            </CommitmentTypeIndication>
            """);
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, table.DocumentElementIndex, out XAdESCommitmentTypeIndication value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Whitespace-only AllSignedDataObjects content must read but was refused with {error.Failure}.");
        Assert.AreEqual(XAdESCommitmentTypeIndicationChoice.AllSignedDataObjects, value.Choice);
    }


    // --- TryVerifyObjectReferences: clause 5.2.3's cross-artifact rule ---

    private static string SignatureWithCommitment(string commitmentBody) => $"""
        <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
            <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
            <ds:Reference Id="ref1" URI="#data1">
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
            <ds:Reference Id="manifestRef" URI="#manifest1">
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue>AQ==</ds:SignatureValue>
          <ds:Object Id="data1">payload</ds:Object>
          <ds:Object>
            <ds:Manifest Id="manifest1">
              <ds:Reference Id="manRef1" URI="#data2">
                <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                <ds:DigestValue>AQ==</ds:DigestValue>
              </ds:Reference>
            </ds:Manifest>
          </ds:Object>
          <ds:Object Id="data2">payload2</ds:Object>
          <ds:Object>
            <ds:Manifest Id="unsignedManifest1">
              <ds:Reference Id="unsignedManRef1" URI="#data2">
                <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                <ds:DigestValue>AQ==</ds:DigestValue>
              </ds:Reference>
            </ds:Manifest>
          </ds:Object>
          <ds:Object>
            <CommitmentTypeIndication xmlns="{V132}">
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-origin</Identifier></CommitmentTypeId>
              {commitmentBody}
            </CommitmentTypeIndication>
          </ds:Object>
        </ds:Signature>
        """;


    private static XAdESCommitmentTypeIndication ReadCommitment(XmlNodeTable table)
    {
        // The CommitmentTypeIndication is the document's last ds:Object's sole child element.
        int documentElement = table.DocumentElementIndex;
        int lastObject = -1;
        for(int child = table.FirstChildOf(documentElement); child >= 0; child = table.NextSiblingOf(child))
        {
            if(table.KindOf(child) == XmlNodeKind.Element && XmlSignatureModelGrammar.IsDsElement(table, child, "Object"u8))
            {
                lastObject = child;
            }
        }

        Assert.IsGreaterThanOrEqualTo(0, lastObject, "The fixture must carry at least one ds:Object.");
        int commitmentElement = -1;
        for(int child = table.FirstChildOf(lastObject); child >= 0; child = table.NextSiblingOf(child))
        {
            if(table.KindOf(child) == XmlNodeKind.Element)
            {
                commitmentElement = child;
            }
        }

        Assert.IsGreaterThanOrEqualTo(0, commitmentElement, "The fixture's last ds:Object must carry a CommitmentTypeIndication child.");
        bool isRead = XAdESCommitmentTypeIndication.TryRead(table, commitmentElement, out XAdESCommitmentTypeIndication value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"The fixture's CommitmentTypeIndication must read but was refused with {error.Failure}.");

        return value;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, "Each <c>ObjectReference</c>
    /// shall reference one <c>ds:Reference</c> element within the <c>ds:SignedInfo</c> element" arm: an
    /// <c>ObjectReference</c> naming a <c>ds:SignedInfo</c>-level reference resolves.
    /// </summary>
    [TestMethod]
    public void ObjectReferenceWithinSignedInfoResolves()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithCommitment("<ObjectReference>#ref1</ObjectReference>"));
        using(table)
        using(signature)
        {
            XAdESCommitmentTypeIndication commitment = ReadCommitment(table);
            bool isVerified = XAdESCommitmentTypeIndication.TryVerifyObjectReferences(table, signature, commitment, out XAdESProcessingError error);
            Assert.IsTrue(isVerified, $"Must resolve but was refused with {error.Failure}.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, "or within a signed
    /// <c>ds:Manifest</c> element" arm: an <c>ObjectReference</c> naming a reference inside a <c>ds:Manifest</c>
    /// that is itself referenced from <c>ds:SignedInfo</c> resolves.
    /// </summary>
    [TestMethod]
    public void ObjectReferenceWithinSignedManifestResolves()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithCommitment("<ObjectReference>#manRef1</ObjectReference>"));
        using(table)
        using(signature)
        {
            XAdESCommitmentTypeIndication commitment = ReadCommitment(table);
            bool isVerified = XAdESCommitmentTypeIndication.TryVerifyObjectReferences(table, signature, commitment, out XAdESProcessingError error);
            Assert.IsTrue(isVerified, $"Must resolve but was refused with {error.Failure}.");
        }
    }


    /// <summary>
    /// Proves an <c>ObjectReference</c> naming a reference inside a <c>ds:Manifest</c> that is NOT itself
    /// signed (no <c>ds:SignedInfo</c>-level reference names it) is refused — <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3's allowlist is exactly "within <c>ds:SignedInfo</c> or
    /// within a SIGNED <c>ds:Manifest</c>," not any manifest anywhere in the document.
    /// </summary>
    [TestMethod]
    public void ObjectReferenceWithinUnsignedManifestIsRefused()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithCommitment("<ObjectReference>#unsignedManRef1</ObjectReference>"));
        using(table)
        using(signature)
        {
            XAdESCommitmentTypeIndication commitment = ReadCommitment(table);
            bool isVerified = XAdESCommitmentTypeIndication.TryVerifyObjectReferences(table, signature, commitment, out XAdESProcessingError error);
            Assert.IsFalse(isVerified, "A reference inside an unsigned manifest must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.ObjectReferenceNotWithinSignedInfoOrSignedManifest, error.Failure);
        }
    }


    /// <summary>
    /// Proves an <c>ObjectReference</c> resolving to an element that is not a <c>ds:Reference</c> at all —
    /// here, a <c>ds:Object</c> sharing the fragment's <c>Id</c> — is refused:
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3 names the target's element identity, not merely its <c>Id</c>.
    /// </summary>
    [TestMethod]
    public void ObjectReferenceTargetingNonReferenceElementIsRefused()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithCommitment("<ObjectReference>#data1</ObjectReference>"));
        using(table)
        using(signature)
        {
            XAdESCommitmentTypeIndication commitment = ReadCommitment(table);
            bool isVerified = XAdESCommitmentTypeIndication.TryVerifyObjectReferences(table, signature, commitment, out XAdESProcessingError error);
            Assert.IsFalse(isVerified, "A target that is not a ds:Reference must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.ObjectReferenceTargetNotReference, error.Failure);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, an <c>ObjectReference</c> that
    /// is not shaped as a bare-name XPointer — here, an absolute URI with no leading <c>#</c> — is refused.
    /// </summary>
    [TestMethod]
    public void NonBareNameObjectReferenceIsRefused()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithCommitment("<ObjectReference>http://example.com/ref1</ObjectReference>"));
        using(table)
        using(signature)
        {
            XAdESCommitmentTypeIndication commitment = ReadCommitment(table);
            bool isVerified = XAdESCommitmentTypeIndication.TryVerifyObjectReferences(table, signature, commitment, out XAdESProcessingError error);
            Assert.IsFalse(isVerified, "A non-bare-name ObjectReference must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.UnsupportedObjectReferenceUriForm, error.Failure);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, an <c>ObjectReference</c>
    /// naming an <c>Id</c> present nowhere in the document is refused.
    /// </summary>
    [TestMethod]
    public void ObjectReferenceTargetIdNotFoundIsRefused()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithCommitment("<ObjectReference>#doesNotExist</ObjectReference>"));
        using(table)
        using(signature)
        {
            XAdESCommitmentTypeIndication commitment = ReadCommitment(table);
            bool isVerified = XAdESCommitmentTypeIndication.TryVerifyObjectReferences(table, signature, commitment, out XAdESProcessingError error);
            Assert.IsFalse(isVerified, "A nonexistent target Id must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.ObjectReferenceTargetIdNotFound, error.Failure);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, an
    /// <see cref="XAdESCommitmentTypeIndicationChoice.AllSignedDataObjects"/> commitment has no
    /// <c>ObjectReference</c> to verify and trivially succeeds.
    /// </summary>
    [TestMethod]
    public void AllSignedDataObjectsChoiceHasNothingToVerify()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithCommitment("<AllSignedDataObjects/>"));
        using(table)
        using(signature)
        {
            XAdESCommitmentTypeIndication commitment = ReadCommitment(table);
            bool isVerified = XAdESCommitmentTypeIndication.TryVerifyObjectReferences(table, signature, commitment, out XAdESProcessingError error);
            Assert.IsTrue(isVerified, $"AllSignedDataObjects must have nothing to verify but was refused with {error.Failure}.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3, the
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> guard on <see cref="XAdESCommitmentTypeIndication.TryVerifyObjectReferences"/> — the anti-wrapping discipline: a
    /// table argument that is not the identical instance the signature and the property were read from refuses rather than being processed.
    /// </summary>
    [TestMethod]
    public void TryVerifyObjectReferencesRefusesWhenTableIsMismatched()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithCommitment("<ObjectReference>#ref1</ObjectReference>"));
        using(table)
        using(signature)
        using(XmlNodeTable otherTable = Parse("""<root/>"""))
        {
            XAdESCommitmentTypeIndication commitment = ReadCommitment(table);
            bool isVerified = XAdESCommitmentTypeIndication.TryVerifyObjectReferences(otherTable, signature, commitment, out XAdESProcessingError error);
            Assert.IsFalse(isVerified, "A mismatched table must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }
}
