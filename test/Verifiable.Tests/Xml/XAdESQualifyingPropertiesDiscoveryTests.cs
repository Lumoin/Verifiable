using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESQualifyingPropertiesDiscovery"/> against clauses 4.4.1 (incorporation
/// discovery), 4.4.2 (the <c>SignedProperties</c> reference binding) and 4.3.1's <c>Target</c> binding of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESQualifyingPropertiesDiscoveryTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private const string SignedPropertiesTypeUri = "http://uri.etsi.org/01903#SignedProperties";


    private static (XmlNodeTable Table, XmlSignature Signature) ReadSoleSignature(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices, "The fixture must carry exactly one ds:Signature.");
        bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isRead, $"The signature must read but was refused with {signatureError.Failure}.");

        return (table!, signature!);
    }


    /// <summary>
    /// A minimal, well-formed direct-incorporation XAdES-shaped signature: one <c>ds:Reference</c> whose
    /// <c>Type</c> is the clause 4.4.2 <c>SignedProperties</c> URI and whose <c>URI</c> targets
    /// <c>SignedProperties</c>'s own <c>Id</c>, one <c>ds:Object</c> carrying a <c>QualifyingProperties</c>
    /// whose <c>Target</c> binds to the signature's own <c>Id</c>.
    /// </summary>
    private static string WellFormedDocument(string signatureId = "sig1", string signedPropertiesId = "spid") => $"""
        <ds:Signature xmlns:ds="{DsNamespace}" Id="{signatureId}">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
            <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
            <ds:Reference URI="#{signedPropertiesId}" Type="{SignedPropertiesTypeUri}">
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue>AQ==</ds:SignatureValue>
          <ds:Object>
            <QualifyingProperties xmlns="{V132}" Target="#{signatureId}">
              <SignedProperties Id="{signedPropertiesId}">
                <SignedSignatureProperties><SigningTime/></SignedSignatureProperties>
              </SignedProperties>
            </QualifyingProperties>
          </ds:Object>
        </ds:Signature>
        """;


    // --- Discovery: clause 4.4.1 ---

    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1's XA-4.4.1-2: a direct-incorporation <c>QualifyingProperties</c> as a <c>ds:Object</c> child is
    /// discovered.
    /// </summary>
    [TestMethod]
    public void DirectlyIncorporatedQualifyingPropertiesIsDiscovered()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(WellFormedDocument(), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError error);

            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {error.Failure}.");
            Assert.IsTrue(result.HasQualifyingProperties);
            Assert.AreEqual(0, result.ObjectOrdinal);
            Assert.HasCount(0, result.QualifyingPropertiesReferences);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1, a signature carrying no XAdES content at all is not a refusal — discovery completes with
    /// <see cref="XAdESQualifyingPropertiesDiscoveryResult.HasQualifyingProperties"/> <see langword="false"/>
    /// and an empty reference list.
    /// </summary>
    [TestMethod]
    public void SignatureWithNoXadesContentDiscoversNothing()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError error);

            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {error.Failure}.");
            Assert.IsFalse(result.HasQualifyingProperties);
            Assert.AreEqual(-1, result.ObjectOrdinal);
            Assert.HasCount(0, result.QualifyingPropertiesReferences);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1's XA-4.4.1-3: zero or more <c>QualifyingPropertiesReference</c> instances (indirect incorporation)
    /// are discovered, each modeled structurally.
    /// </summary>
    [TestMethod]
    public void QualifyingPropertiesReferencesAreDiscovered()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingPropertiesReference xmlns="{V132}" URI="external1.xml#qp"/>
                <QualifyingPropertiesReference xmlns="{V132}" URI="external2.xml#qp"/>
              </ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError error);

            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {error.Failure}.");
            Assert.IsFalse(result.HasQualifyingProperties);
            Assert.HasCount(2, result.QualifyingPropertiesReferences);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1's XA-4.4.1-4's "at most one instance of the <c>QualifyingProperties</c> element may occur"
    /// cardinality bound: a second direct <c>QualifyingProperties</c> child refuses.
    /// </summary>
    [TestMethod]
    public void SecondQualifyingPropertiesInTheSameObjectIsRefused()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="#sig1">
                  <SignedProperties><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                </QualifyingProperties>
                <QualifyingProperties xmlns="{V132}" Target="#sig1">
                  <SignedProperties><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                </QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out _, out XAdESProcessingError error);

            Assert.IsFalse(isDiscovered, "A second QualifyingProperties must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.MultipleQualifyingProperties, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1's "all instances ... shall occur within a single <c>ds:Object</c> element" rule:
    /// a <c>QualifyingProperties</c> in one <c>ds:Object</c> and a <c>QualifyingPropertiesReference</c> in a
    /// DIFFERENT <c>ds:Object</c> of the same signature refuses.
    /// </summary>
    [TestMethod]
    public void ContentScatteredAcrossTwoObjectsIsRefused()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="#sig1">
                  <SignedProperties><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                </QualifyingProperties>
              </ds:Object>
              <ds:Object>
                <QualifyingPropertiesReference xmlns="{V132}" URI="external.xml#qp"/>
              </ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out _, out XAdESProcessingError error);

            Assert.IsFalse(isDiscovered, "Content scattered across two ds:Object elements must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.QualifyingContentScatteredAcrossMultipleObjects, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1's XA-4.4.1-5/-6: unrelated <c>ds:Object</c> elements coexist without disturbing discovery, AND
    /// the XAdES-carrying <c>ds:Object</c> need not be first among siblings — "No restrictions apply to the
    /// relative position."
    /// </summary>
    [TestMethod]
    public void UnrelatedObjectsAndNonFirstPositionDoNotDisturbDiscovery()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="#spid" Type="{SignedPropertiesTypeUri}">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object><Unrelated xmlns="urn:example:whatever"/></ds:Object>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="#sig1">
                  <SignedProperties Id="spid"><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                </QualifyingProperties>
              </ds:Object>
              <ds:Object><AlsoUnrelated xmlns="urn:example:whatever"/></ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError error);

            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {error.Failure}.");
            Assert.IsTrue(result.HasQualifyingProperties);
            Assert.AreEqual(1, result.ObjectOrdinal, "The XAdES content sits in the middle ds:Object, not the first.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1, the <see cref="XAdESProcessingFailure.TableMismatch"/> guard: a table argument that is not the
    /// identical instance <see cref="XmlSignature.Table"/> was read from refuses rather than being processed.
    /// </summary>
    [TestMethod]
    public void TryDiscoverRefusesWhenTableIsNotTheSignaturesOwnTable()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(WellFormedDocument(), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        using(XmlNodeTable otherTable = ParseStandalone("""<root/>""", BaseMemoryPool.Shared))
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(otherTable, signature, out _, out XAdESProcessingError error);

            Assert.IsFalse(isDiscovered, "A mismatched table must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves a discovered <c>QualifyingProperties</c> that fails its own structural read (here: empty,
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1's XA-4.3.1-9) propagates as <see cref="XAdESProcessingFailure.MalformedQualifyingProperties"/>, carrying
    /// the container's own <see cref="XAdESReadFailure"/> in <see cref="XAdESProcessingError.InnerQualifyingPropertiesReadError"/>.
    /// </summary>
    [TestMethod]
    public void MalformedQualifyingPropertiesPropagatesTheStructuralReadFailure()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="#sig1"/>
              </ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out _, out XAdESProcessingError error);

            Assert.IsFalse(isDiscovered, "An empty QualifyingProperties must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.MalformedQualifyingProperties, error.Failure);
            Assert.IsNotNull(error.InnerQualifyingPropertiesReadError);
            Assert.AreEqual(XAdESReadFailure.EmptyQualifyingPropertiesContainer, error.InnerQualifyingPropertiesReadError!.Value.Failure);
        }
    }


    /// <summary>
    /// Proves a discovered <c>QualifyingPropertiesReference</c> that fails its own structural read (here:
    /// missing the mandatory <c>URI</c>, <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.3's XA-4.4.3-2) propagates as
    /// <see cref="XAdESProcessingFailure.MalformedQualifyingPropertiesReference"/>.
    /// </summary>
    [TestMethod]
    public void MalformedQualifyingPropertiesReferencePropagatesTheStructuralReadFailure()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingPropertiesReference xmlns="{V132}"/>
              </ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out _, out XAdESProcessingError error);

            Assert.IsFalse(isDiscovered, "A QualifyingPropertiesReference missing its mandatory URI must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.MalformedQualifyingPropertiesReference, error.Failure);
            Assert.IsNotNull(error.InnerQualifyingPropertiesReadError);
            Assert.AreEqual(XAdESReadFailure.MissingRequiredAttribute, error.InnerQualifyingPropertiesReadError!.Value.Failure);
        }
    }


    // --- Target binding: clause 4.3.1 ---

    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1's XA-4.3.1-4/-5/-6: a <c>Target</c> whose non-fragment part is empty and whose bare-name fragment
    /// resolves to the signature's own <c>Id</c> binds successfully.
    /// </summary>
    [TestMethod]
    public void WellFormedTargetBindsToItsOwnSignature()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(WellFormedDocument(), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");

            bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifyTargetBinding(table, result.QualifyingProperties, signature, out XAdESProcessingError error);

            Assert.IsTrue(isBound, $"Target must bind but was refused with {error.Failure}.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1's XA-4.3.1-5: a <c>Target</c> with no <c>#</c> at all is not shaped as a URI with a bare-name
    /// XPointer fragment.
    /// </summary>
    [TestMethod]
    public void TargetWithNoFragmentIsRefused()
    {
        AssertTargetBindingWithRawTarget("sig1", error => Assert.AreEqual(XAdESProcessingFailure.UnsupportedTargetUriForm, error.Failure));
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1's XA-4.3.1-6: "If the XAdES signature envelops the <c>QualifyingProperties</c> element, its
    /// not-fragment part shall be empty" — direct incorporation is always enveloping, so a non-empty
    /// non-fragment part refuses.
    /// </summary>
    [TestMethod]
    public void TargetWithNonEmptyNonFragmentPartIsRefused()
    {
        AssertTargetBindingWithRawTarget("doc.xml#sig1", error => Assert.AreEqual(XAdESProcessingFailure.TargetNonFragmentPartNotEmpty, error.Failure));
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1, a fragment naming no <c>Id</c> anywhere in the document refuses as
    /// <see cref="XAdESProcessingFailure.TargetIdNotFound"/>, bridged from
    /// <see cref="XmlSignatureProcessingFailure.IdNotFound"/>.
    /// </summary>
    [TestMethod]
    public void TargetFragmentNotFoundIsRefused()
    {
        AssertTargetBindingWithRawTarget("#does-not-exist", error => Assert.AreEqual(XAdESProcessingFailure.TargetIdNotFound, error.Failure));
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1, the mismatch shape this check names: a <c>QualifyingProperties</c> whose
    /// <c>Target</c> fragment names a DIFFERENT signature's <c>Id</c> refuses when checked against the signature it was actually discovered within.
    /// </summary>
    [TestMethod]
    public void TargetPointingAtADifferentSignatureViaWrongFragmentIsRefused()
    {
        string document = $"""
            <Wrapper>
              <ds:Signature xmlns:ds="{DsNamespace}" Id="decoy-target">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                  <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                  <ds:Reference URI="">
                    <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                    <ds:DigestValue>AQ==</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
              </ds:Signature>
              <ds:Signature xmlns:ds="{DsNamespace}" Id="actual-signature">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                  <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                  <ds:Reference URI="#spid" Type="{SignedPropertiesTypeUri}">
                    <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                    <ds:DigestValue>AQ==</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
                <ds:Object>
                  <QualifyingProperties xmlns="{V132}" Target="#decoy-target">
                    <SignedProperties Id="spid"><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                  </QualifyingProperties>
                </ds:Object>
              </ds:Signature>
            </Wrapper>
            """;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            Assert.HasCount(2, signatureIndices);
            bool isRead = XmlSignature.TryRead(table!, signatureIndices[1], BaseMemoryPool.Shared, out XmlSignature? actualSignature, out XmlSignatureReadError signatureError);
            Assert.IsTrue(isRead, $"The actual signature must read but was refused with {signatureError.Failure}.");
            using(actualSignature)
            {
                bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table!, actualSignature!, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
                Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");

                bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifyTargetBinding(table!, result.QualifyingProperties, actualSignature!, out XAdESProcessingError error);

                Assert.IsFalse(isBound, "A Target naming a different signature's Id must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.TargetSignatureMismatch, error.Failure);
            }
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1, the <see cref="XAdESProcessingFailure.TableMismatch"/> guard on
    /// <see cref="XAdESQualifyingPropertiesDiscovery.TryVerifyTargetBinding"/>.
    /// </summary>
    [TestMethod]
    public void TryVerifyTargetBindingRefusesWhenTableIsMismatched()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(WellFormedDocument(), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        using(XmlNodeTable otherTable = ParseStandalone("""<root/>""", BaseMemoryPool.Shared))
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");

            bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifyTargetBinding(otherTable, result.QualifyingProperties, signature, out XAdESProcessingError error);

            Assert.IsFalse(isBound, "A mismatched table must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    // --- SignedProperties reference binding: clause 4.4.2 ---

    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.2's XA-4.4.2-2/-3/-4: the <c>Type="http://uri.etsi.org/01903#SignedProperties"</c> reference is
    /// located and dereferences to the EXACT <c>SignedProperties</c> node of the discovered <c>QualifyingProperties</c> container — exactly what the table/node-identity pin requires.
    /// </summary>
    [TestMethod]
    public void WellFormedSignedPropertiesReferenceBindsToTheExactNode()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(WellFormedDocument(), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");
            Assert.IsTrue(result.QualifyingProperties.HasSignedProperties);

            bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding(
                table, signature, result.QualifyingProperties.SignedProperties, resolver: null, BaseMemoryPool.Shared, out XmlReference matchedReference, out XAdESProcessingError error);

            Assert.IsTrue(isBound, $"Must bind but was refused with {error.Failure}.");
            Assert.IsTrue(matchedReference.HasType);
            Assert.AreSequenceEqual(XAdESIdentifiers.SignedPropertiesTypeUriUtf8.ToArray(), matchedReference.Type.ToArray(), "The matched reference must carry the exact clause 4.4.2 Type URI.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.2's XA-4.4.2-4: no <c>ds:Reference</c> carrying the exact <c>Type</c> URI refuses as
    /// <see cref="XAdESProcessingFailure.SignedPropertiesReferenceNotFound"/> — a near-miss <c>Type</c> value
    /// does not match.
    /// </summary>
    [TestMethod]
    public void NoMatchingTypeReferenceIsRefused()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="#spid" Type="{SignedPropertiesTypeUri}NOT-QUITE">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="#sig1">
                  <SignedProperties Id="spid"><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                </QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");

            bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding(
                table, signature, result.QualifyingProperties.SignedProperties, resolver: null, BaseMemoryPool.Shared, out _, out XAdESProcessingError error);

            Assert.IsFalse(isBound, "No matching Type must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.SignedPropertiesReferenceNotFound, error.Failure);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1, ambiguity is refused rather than resolved to the first match: two references sharing the
    /// <c>Type</c> URI refuse as <see cref="XAdESProcessingFailure.MultipleSignedPropertiesReferences"/>.
    /// </summary>
    [TestMethod]
    public void TwoReferencesWithTheSameTypeAreRefused()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="#spid" Type="{SignedPropertiesTypeUri}">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
                <ds:Reference URI="#spid" Type="{SignedPropertiesTypeUri}">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>Ag==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="#sig1">
                  <SignedProperties Id="spid"><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                </QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");

            bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding(
                table, signature, result.QualifyingProperties.SignedProperties, resolver: null, BaseMemoryPool.Shared, out _, out XAdESProcessingError error);

            Assert.IsFalse(isBound, "Two Type-matching references must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.MultipleSignedPropertiesReferences, error.Failure);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1, the table/node-identity pin (this library's central hardening requirement, extended here to the wrapping-suite decoy shape):
    /// a <c>Type</c>-matching reference whose <c>URI</c> dereferences to a DECOY element — sharing the shape of a <c>SignedProperties</c>-typed element elsewhere in the document, with its own distinct <c>Id</c> — rather than the genuinely discovered
    /// <c>SignedProperties</c>, refuses as <see cref="XAdESProcessingFailure.SignedPropertiesReferenceTargetMismatch"/> rather than being accepted as the signed qualifying properties.
    /// </summary>
    [TestMethod]
    public void ReferenceDereferencingToADecoyElementIsRefused()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="#decoy" Type="{SignedPropertiesTypeUri}">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="#sig1">
                  <SignedProperties Id="spid"><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                </QualifyingProperties>
                <Decoy xmlns="urn:example:decoy" Id="decoy">ATTACKER-CONTENT</Decoy>
              </ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");

            bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding(
                table, signature, result.QualifyingProperties.SignedProperties, resolver: null, BaseMemoryPool.Shared, out _, out XAdESProcessingError error);

            Assert.IsFalse(isBound, "A reference dereferencing to a decoy element must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.SignedPropertiesReferenceTargetMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves a <c>Type</c>-matching reference whose <c>URI</c> targets a non-same-document (external)
    /// resource refuses as <see cref="XAdESProcessingFailure.SignedPropertiesReferenceTargetsExternalDocument"/>
    /// — <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.2 always ties this reference to the <c>SignedProperties</c> of the SAME
    /// <c>QualifyingProperties</c> the discovered <c>ds:Object</c> carries — and the resolver's own rented
    /// octets are disposed rather than leaked, proven via <see cref="MeteredHousePool"/>.
    /// </summary>
    [TestMethod]
    public void ReferenceTargetingExternalDocumentIsRefusedAndDisposesTheResolvedOctets()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="external.xml#spid" Type="{SignedPropertiesTypeUri}">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="#sig1">
                  <SignedProperties Id="spid"><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                </QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        using(var metered = new MeteredHousePool())
        {
            (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, metered.Pool);
            using(table)
            using(signature)
            {
                bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
                Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");

                XmlReferenceResolver resolver = (ReadOnlySpan<byte> uri, BaseMemoryPool pool, out PooledMemory? octets) =>
                {
                    octets = PooledMemory.FromBytes([1, 2, 3], pool, BufferTags.XmlDecodedContent);

                    return true;
                };

                bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding(
                    table, signature, result.QualifyingProperties.SignedProperties, resolver, metered.Pool, out _, out XAdESProcessingError error);

                Assert.IsFalse(isBound, "An external target must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.SignedPropertiesReferenceTargetsExternalDocument, error.Failure);
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "The resolver's own rented octets must be disposed on the refusal path.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1, the <see cref="XAdESProcessingFailure.TableMismatch"/> guard on
    /// <see cref="XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding"/>.
    /// </summary>
    [TestMethod]
    public void TryVerifySignedPropertiesReferenceBindingRefusesWhenTableIsMismatched()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(WellFormedDocument(), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        using(XmlNodeTable otherTable = ParseStandalone("""<root/>""", BaseMemoryPool.Shared))
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");

            bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding(
                otherTable, signature, result.QualifyingProperties.SignedProperties, resolver: null, BaseMemoryPool.Shared, out _, out XAdESProcessingError error);

            Assert.IsFalse(isBound, "A mismatched table must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    private static XmlNodeTable ParseStandalone(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static void AssertTargetBindingWithRawTarget(string target, Action<XAdESProcessingError> assertion)
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="{target}">
                  <SignedProperties><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>
                </QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError discoveryError);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {discoveryError.Failure}.");

            bool isBound = XAdESQualifyingPropertiesDiscovery.TryVerifyTargetBinding(table, result.QualifyingProperties, signature, out XAdESProcessingError error);

            Assert.IsFalse(isBound, $"Target '{target}' must be refused.");
            assertion(error);
        }
    }


}
