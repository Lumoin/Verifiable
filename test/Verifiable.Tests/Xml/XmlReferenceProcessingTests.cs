using System.Globalization;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XmlReferenceProcessing"/> — the transform-chain engine and its two entry points,
/// <see cref="XmlReferenceProcessing.TryComputeDigestInput"/> and <see
/// cref="XmlReferenceProcessing.TryComputeSignedInfoOctets"/> — covering section
/// 4.3.3.2 type-flow in both MUST directions, the implicit Canonical XML 1.0 final default, base64 over
/// octets and over a node-set, enveloped-signature nearest-ancestor semantics over sibling and nested
/// signatures, canonicalization transforms mid-chain with <c>InclusiveNamespaces PrefixList</c>, canonical
/// <c>SignedInfo</c> octets for all six clause 6.3(d) algorithms, every refusal disposition of, and the
/// hardening limits.
/// </summary>
[TestClass]
internal sealed class XmlReferenceProcessingTests
{
    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";


    private static (XmlNodeTable Table, XmlSignature Signature) ReadFirstSignature(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.IsGreaterThan(0, signatureIndices.Length, "The fixture document must carry at least one Signature element.");

        bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
        Assert.IsTrue(isRead, $"The fixture Signature must read but was refused with {readSignatureError.Failure}.");

        return (table!, signature!);
    }


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


    private static string ComputeDigestInputText(XmlNodeTable table, XmlSignature signature, int referenceOrdinal = 0, XmlReferenceResolver? resolver = null, BaseMemoryPool? pool = null)
    {
        BaseMemoryPool usedPool = pool ?? BaseMemoryPool.Shared;
        bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, referenceOrdinal, resolver, usedPool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
        Assert.IsTrue(isComputed, $"Digest input must compute but was refused with {error.Failure}.");
        using(digestInput)
        {
            return Encoding.UTF8.GetString(digestInput!.AsReadOnlySpan());
        }
    }


    private static XmlReferenceResolver CreateFixedResolver(byte[] octets)
    {
        return (ReadOnlySpan<byte> uri, BaseMemoryPool pool, out PooledMemory? result) =>
        {
            result = PooledMemory.FromBytes(octets, pool, BufferTags.XmlDigestInput);

            return true;
        };
    }


    /// <summary>
    /// Proves, against the reference-processing model of <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing (Second Edition)</see> section
    /// 4.3.3.2 (whose Id resolution and enveloped-signature exclusion are defined relative to "the document that contains the <c>URI</c> attribute"), for <see
    /// cref="XmlReferenceProcessing.TryComputeDigestInput(XmlNodeTable, XmlSignature, int, XmlReferenceResolver?, BaseMemoryPool, out PooledMemory?, out XmlSignatureProcessingError)"/>: <see
    /// cref="XmlSignatureProcessingFailure.TableMismatch"/> for a <c>table</c> argument that is not the identical instance <see cref="XmlSignature.Table"/> refuses rather than being
    /// processed — the guard the security lens found missing, since a caller holding two tables (a re-parse, a normalized copy) could otherwise retarget Id resolution and the
    /// enveloped-signature exclusion to the wrong document.
    /// </summary>
    [TestMethod]
    public void DigestInputRefusesWhenTableIsNotTheSignaturesOwnTable()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="">
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        using(foreignTable)
        using(foreignSignature)
        {
            Assert.IsFalse(signature.IsOver(foreignTable), "The two byte-identical documents must still be distinct table instances.");

            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(foreignTable, signature, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed, "A foreign table must refuse rather than compute against the wrong document.");
            Assert.IsNull(digestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves, against the reference-processing model of <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.2, for <see
    /// cref="XmlReferenceProcessing.TryComputeSignedInfoOctets"/>: <see
    /// cref="XmlSignatureProcessingFailure.TableMismatch"/> for a foreign <c>table</c> argument — before the
    /// fix this shape reached <see cref="XmlNodeSet.ElementSubtree"/> with an element index from a foreign
    /// table and could canonicalize the wrong element or crash rather than refuse — the security lens's
    /// concrete break.
    /// </summary>
    [TestMethod]
    public void SignedInfoOctetsRefuseWhenTableIsNotTheSignaturesOwnTable()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="">
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        using(foreignTable)
        using(foreignSignature)
        {
            bool isComputed = XmlReferenceProcessing.TryComputeSignedInfoOctets(foreignTable, signature, BaseMemoryPool.Shared, out PooledMemory? signedInfoOctets, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed, "A foreign table must refuse rather than canonicalize against the wrong document.");
            Assert.IsNull(signedInfoOctets);
            Assert.AreEqual(XmlSignatureProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves, against the reference-processing model of <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing (Second Edition)</see> section
    /// 4.3.3.2, for the <see cref="XmlManifest"/> overload of <see cref="XmlReferenceProcessing.TryComputeDigestInput(XmlNodeTable, XmlManifest, int, XmlReferenceResolver?, BaseMemoryPool, out
    /// PooledMemory?, out XmlSignatureProcessingError)"/>: <see cref="XmlSignatureProcessingFailure.TableMismatch"/> for a <c>table</c> argument that is not the identical instance the <see
    /// cref="XmlManifest"/> was read from — the third public entry point the table-identity guard covers, mechanically the same shape as the two signature-side pins above but through the
    /// manifest overload, against a second byte-identical but distinct table instance.
    /// </summary>
    [TestMethod]
    public void ManifestDigestInputRefusesWhenTableIsNotTheManifestsOwnTable()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="#manifestRef">
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <Object Id="manifestRef">
                <Manifest>
                  <Reference URI="#manifestTarget">
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>Ag==</DigestValue>
                  </Reference>
                </Manifest>
              </Object>
              <Object><Target Id="manifestTarget">hello</Target></Object>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        using(foreignTable)
        using(foreignSignature)
        {
            int manifestElementIndex = signature.Objects[0].ContentNodeIndices
                .First(i => table.KindOf(i) == XmlNodeKind.Element && table.LocalNameOf(i).SequenceEqual("Manifest"u8));
            bool isManifestRead = XmlManifest.TryRead(table, manifestElementIndex, BaseMemoryPool.Shared, out XmlManifest? manifest, out XmlSignatureReadError manifestReadError);
            Assert.IsTrue(isManifestRead, $"The Manifest must read but was refused with {manifestReadError.Failure}.");
            using(manifest)
            {
                Assert.IsFalse(manifest!.IsOver(foreignTable), "The two byte-identical documents must still be distinct table instances.");

                bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(foreignTable, manifest, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

                Assert.IsFalse(isComputed, "A foreign table must refuse rather than compute against the wrong document.");
                Assert.IsNull(digestInput);
                Assert.AreEqual(XmlSignatureProcessingFailure.TableMismatch, error.Failure);
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's octets-to-node-set default: "If the data object is
    /// an octet stream and the next transform requires a node-set, the signature application MUST attempt to
    /// parse the octets yielding the required node-set via [XML] well-formed processing." An external
    /// reference's octets meet a canonicalization transform, which needs a node-set, forcing exactly this
    /// parse; the canonicalized result of an already-canonical fragment is itself, byte-exact.
    /// </summary>
    [TestMethod]
    public void OctetsArrivingAtCanonicalizationTransformReparseIntoNodeSet()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="http://example.com/frag.xml">
                  <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.CanonicalXml10Uri}}"/></Transforms>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            string text = ComputeDigestInputText(table, signature, resolver: CreateFixedResolver("<a>text</a>"u8.ToArray()));

            Assert.AreEqual("<a>text</a>", text, "An already-canonical fragment must canonicalize to itself.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's octets-to-node-set default applies MID-CHAIN, not
    /// only at chain entry: the base64 transform decodes to well-formed XML octets, which the following
    /// canonicalization transform — needing a node-set — must parse afresh (a second re-parse distinct from
    /// any at chain entry). Canonical XML never uses the empty-element shorthand, so the self-closing source
    /// expands to an explicit end tag.
    /// </summary>
    [TestMethod]
    public void MidChainReparseAfterBase64DecodingIntoWellFormedXml()
    {
        string document = $$"""
            <Document>
              <Target Id="target">PGIvPg==</Target>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <Transforms>
                      <Transform Algorithm="{{XmlSignatureIdentifiers.Base64TransformUri}}"/>
                      <Transform Algorithm="{{XmlSignatureIdentifiers.CanonicalXml10Uri}}"/>
                    </Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            string text = ComputeDigestInputText(table, signature);

            Assert.AreEqual("<b></b>", text, "'PGIvPg==' base64-decodes to '<b/>', which re-parses and canonicalizes to an explicit end tag.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.2's own node-set-to-octets rule for base64 — "applying an XPath transform with
    /// expression <c>self::text()</c>, then taking the string-value of the node-set" — is used instead of
    /// canonicalization: the identified element's start/end tags and its descendant element's tags, a
    /// comment and a processing instruction all vanish from the concatenated text, while text nested inside
    /// a descendant element still contributes, in document order, exactly reproducing the spec's own
    /// worked description "automatically strips away the start and end tags of the identified element and
    /// any of its descendant elements as well as any descendant comments and processing instructions."
    /// </summary>
    [TestMethod]
    public void NodeSetArrivingAtBase64TransformSelectsTextNotCanonicalForm()
    {
        string document = $$"""
            <Data Id="target">AQ<?pi data?><!--ignored--><Sub>==</Sub></Data>
            """;
        string signatureDocument = $$"""
            <Document>
              {{document}}
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.Base64TransformUri}}"/></Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(signatureDocument, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(digestInput)
            {
                Assert.AreSequenceEqual(new byte[] { 0x01 }, digestInput!.AsReadOnlySpan().ToArray(), "'AQ' + '==' (comment/PI/tags stripped, Sub's own text kept) concatenates to 'AQ==', decoding to one octet 0x01.");
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.2's "requires an octet stream for input" default path:
    /// the base64 transform decodes octets directly when octets — not a node-set — arrive (the node-set
    /// conversion rule is the exceptional case for when a node-set is given instead).
    /// </summary>
    [TestMethod]
    public void OctetsArrivingAtBase64TransformDecodeDirectly()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="http://example.com/raw.b64">
                  <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.Base64TransformUri}}"/></Transforms>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, CreateFixedResolver("AQ=="u8.ToArray()), BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(digestInput)
            {
                Assert.AreSequenceEqual(new byte[] { 0x01 }, digestInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.4's defining rule, as adjudicated by, over two SIBLING
    /// signatures: each signature's own transform removes only ITS OWN nearest ancestor <c>Signature</c>,
    /// leaving the sibling untouched — "necessary to exclude the second signature element from the digest
    /// calculations of the first signature so that adding the second signature does not break the first
    /// signature" is the mirror image of what this proves: the OTHER signature's markup survives in each
    /// one's own digest input.
    /// </summary>
    [TestMethod]
    public void EnvelopedTransformExcludesOnlyItsOwnSignatureAmongSiblings()
    {
        string document = $$"""
            <Root>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="">
                    <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.EnvelopedSignatureTransformUri}}"/></Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>QQ==</SignatureValue>
              </Signature>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="">
                    <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.EnvelopedSignatureTransformUri}}"/></Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>Ag==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>Qg==</SignatureValue>
              </Signature>
            </Root>
            """;
        (XmlNodeTable table, XmlSignature[] signatures) = ReadAllSignaturesInDocumentOrder(document, BaseMemoryPool.Shared);
        using(table)
        using(signatures[0])
        using(signatures[1])
        {
            string firstText = ComputeDigestInputText(table, signatures[0]);
            string secondText = ComputeDigestInputText(table, signatures[1]);

            Assert.DoesNotContain("QQ==", firstText, "The first signature's own SignatureValue must be excluded from its own digest input.");
            Assert.Contains("Qg==", firstText, "The sibling signature must survive in the first signature's digest input.");
            Assert.DoesNotContain("Qg==", secondText, "The second signature's own SignatureValue must be excluded from its own digest input.");
            Assert.Contains("QQ==", secondText, "The sibling signature must survive in the second signature's digest input.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.4's nearest-ancestor rule over a NESTED signature (a
    /// <c>ds:Signature</c> inside another's <c>Object</c>, the shape section 9's "Recorded misc. facts"
    /// notes the schema permits): the OUTER signature's own transform excludes its whole subtree, dropping
    /// the inner signature nested inside it along the way, while the INNER signature's own transform
    /// excludes only itself — "nearest," not "outermost" — leaving the outer signature's own markup around
    /// it intact.
    /// </summary>
    [TestMethod]
    public void EnvelopedTransformExcludesTheNearestNotTheOutermostSignature()
    {
        string document = $$"""
            <Root>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}" Id="outer">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="">
                    <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.EnvelopedSignatureTransformUri}}"/></Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>Qw==</SignatureValue>
                <Object>
                  <Signature Id="inner">
                    <SignedInfo>
                      <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                      <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                      <Reference URI="">
                        <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.EnvelopedSignatureTransformUri}}"/></Transforms>
                        <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                        <DigestValue>Ag==</DigestValue>
                      </Reference>
                    </SignedInfo>
                    <SignatureValue>RA==</SignatureValue>
                  </Signature>
                </Object>
              </Signature>
            </Root>
            """;
        (XmlNodeTable table, XmlSignature[] signatures) = ReadAllSignaturesInDocumentOrder(document, BaseMemoryPool.Shared);
        Assert.HasCount(2, signatures, "The document-order scan must find both the outer and the nested inner Signature.");
        using(table)
        using(signatures[0])
        using(signatures[1])
        {
            string outerText = ComputeDigestInputText(table, signatures[0]);
            string innerText = ComputeDigestInputText(table, signatures[1]);

            Assert.DoesNotContain("Qw==", outerText, "Excluding the outer signature's own subtree removes its own SignatureValue.");
            Assert.DoesNotContain("RA==", outerText, "Excluding the outer signature's whole subtree also removes the nested inner signature.");
            Assert.Contains("Qw==", innerText, "The inner signature's transform excludes only ITS nearest ancestor, so the outer signature's own markup survives.");
            Assert.DoesNotContain("RA==", innerText, "The inner signature's own SignatureValue is excluded from its own digest input.");
        }
    }


    /// <summary>
    /// Proves <see cref="XmlSignatureProcessingFailure.EnvelopedSignatureSourceMismatch"/> for
    /// <c>Transforms=[c14n-1.0, enveloped-signature]</c> over <c>URI=""</c> — the first transform
    /// converts the node-set to octets, forcing the enveloped-signature transform to re-parse into a FRESH
    /// table before it can apply its exclusion. Section 6.6.4 (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">
    /// XML Signature Syntax and Processing (Second Edition)</see>) line 3794 permits this transform to be
    /// "applied to a node-set from its parent XML document" only, and its defining <c>here()</c> function
    /// (section 6.6.3) "results in an error if the containing XPath expression does not appear in the same
    /// XML document against which the XPath expression is being evaluated" — the <c>Transform</c> element
    /// lives in the ORIGINAL document, the current node-set is now over the RE-PARSED one, so this refuses
    /// rather than silently leaving the signature un-excluded in the digest input.
    /// </summary>
    [TestMethod]
    public void EnvelopedTransformAfterAMidChainCanonicalizationReparseRefusesAsSourceMismatch()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="">
                  <Transforms>
                    <Transform Algorithm="{{XmlSignatureIdentifiers.CanonicalXml10Uri}}"/>
                    <Transform Algorithm="{{XmlSignatureIdentifiers.EnvelopedSignatureTransformUri}}"/>
                  </Transforms>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using var metered = new MeteredHousePool();
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed, "The chain must refuse rather than return a digest input with the signature un-excluded.");
            Assert.IsNull(digestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.EnvelopedSignatureSourceMismatch, error.Failure);
            Assert.AreEqual(0L, metered.OutstandingCount, "The refusal must not leave the mid-chain re-parsed table or any octets buffer outstanding.");
        }
    }


    /// <summary>
    /// Proves a canonicalization transform mid-chain honors its own <c>InclusiveNamespaces PrefixList</c>,
    /// per section 4.2 of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>: a namespace prefix in scope at the identified subtree but not visibly utilized by anything
    /// in it renders only when the transform's own <c>PrefixList</c> names it.
    /// </summary>
    [TestMethod]
    public void CanonicalizationTransformMidChainHonorsItsOwnPrefixList()
    {
        string document = $$"""
            <Document xmlns:q="urn:example:q">
              <Target Id="target"><Elem/></Target>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <Transforms>
                      <Transform Algorithm="{{XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri}}">
                        <ec:InclusiveNamespaces xmlns:ec="{{XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri}}" PrefixList="q"/>
                      </Transform>
                    </Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                  <Reference URI="#target">
                    <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri}}"/></Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>Ag==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            string withPrefixList = ComputeDigestInputText(table, signature, referenceOrdinal: 0);
            string withoutPrefixList = ComputeDigestInputText(table, signature, referenceOrdinal: 1);

            Assert.Contains("xmlns:q=\"urn:example:q\"", withPrefixList, "PrefixList=\"q\" must force the in-scope 'q' declaration to render even though nothing in the subtree visibly utilizes it.");
            Assert.DoesNotContain("xmlns:q", withoutPrefixList, "Without PrefixList, 'q' is not visibly utilized anywhere in the subtree and must not render.");
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax
    /// and Processing (Second Edition)</see> section 8.3's "even there perverse parameters might cause
    /// unacceptable processing or memory demand", the tokenwise parse: a <c>PrefixList</c> naming MULTIPLE
    /// whitespace-separated tokens still honors every one of them — two in-scope namespace prefixes neither
    /// is visibly utilized in the identified subtree both render because both are named on the list.
    /// </summary>
    [TestMethod]
    public void PrefixListWithMultipleTokensHonorsEveryToken()
    {
        string document = $$"""
            <Document xmlns:q="urn:example:q" xmlns:r="urn:example:r">
              <Target Id="target"><Elem/></Target>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <Transforms>
                      <Transform Algorithm="{{XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri}}">
                        <ec:InclusiveNamespaces xmlns:ec="{{XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri}}" PrefixList="q r"/>
                      </Transform>
                    </Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            string text = ComputeDigestInputText(table, signature);

            Assert.Contains("xmlns:q=\"urn:example:q\"", text, "The first token of a multi-token PrefixList must render.");
            Assert.Contains("xmlns:r=\"urn:example:r\"", text, "The second token of a multi-token PrefixList must render.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 8.3's "even there perverse parameters might cause
    /// unacceptable processing or memory demand" through the documented hardening bound: <see
    /// cref="XmlSignatureProcessingFailure.InvalidCanonicalizationParameter"/> for a <c>PrefixList</c>
    /// exceeding <see cref="XmlReferenceProcessing.MaximumPrefixListByteLength"/> — Exclusive XML
    /// Canonicalization 1.0 sets no such bound, and the attribute value is otherwise fully
    /// attacker-controlled.
    /// </summary>
    [TestMethod]
    public void PrefixListExceedingTheDocumentedCapRefuses()
    {
        string overLongPrefixList = new string('a', XmlReferenceProcessing.MaximumPrefixListByteLength + 1);
        string document = $$"""
            <Document>
              <Target Id="target"><Elem/></Target>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <Transforms>
                      <Transform Algorithm="{{XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri}}">
                        <ec:InclusiveNamespaces xmlns:ec="{{XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri}}" PrefixList="{{overLongPrefixList}}"/>
                      </Transform>
                    </Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using var metered = new MeteredHousePool();
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed, "A PrefixList exceeding the documented cap must refuse rather than be tokenized.");
            Assert.IsNull(digestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.InvalidCanonicalizationParameter, error.Failure);
            Assert.AreEqual(0L, metered.OutstandingCount, "The cap refusal must not rent anything left outstanding.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's default's other (node-set-to-octets) direction end
    /// to end: a <c>Reference</c> with no <c>Transforms</c> at all leaves the chain's
    /// dereferenced node-set to convert by the implicit default — Canonical XML 1.0 — rendering a set the
    /// bare-name dereference already marked <see cref="XmlNodeSet.WithoutComments"/> — exactly, byte for
    /// byte, against a hand-derived expectation, and carrying <see cref="BufferTags.XmlDigestInput"/>
    /// directly rather than a copy-to-retag (house finding on the tag-parameterized <see
    /// cref="XmlCanonicalization.TryCanonicalize"/> overload).
    /// </summary>
    [TestMethod]
    public void NodeSetWithNoTransformsConvertsByTheImplicitCanonicalXml10Default()
    {
        string document = $$"""
            <Document>
              <Target Id="target">hello</Target>
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
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            Assert.HasCount(0, signature.SignedInfo.References[0].Transforms, "This fixture proves the no-Transforms path.");

            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
            Assert.IsTrue(isComputed, $"Digest input must compute but was refused with {error.Failure}.");
            using(digestInput)
            {
                Assert.AreEqual("<Target Id=\"target\">hello</Target>", Encoding.UTF8.GetString(digestInput!.AsReadOnlySpan()));
                Assert.AreEqual(BufferTags.XmlDigestInput, digestInput.Tag, "The implicit final conversion must produce XmlDigestInput-tagged octets directly.");
            }
        }
    }


    /// <summary>
    /// Proves for the <see cref="XmlManifest"/> overload of <c>TryComputeDigestInput</c>, which exists to
    /// make good on <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax
    /// and Processing (Second Edition)</see> section 5.1's "digests within such a Manifest are checked at
    /// the application's discretion" — a real, callable way to compute one, which the two-method public
    /// surface (only <see cref="XmlSignedInfo.References"/>-indexed previously) could not reach: a
    /// <c>ds:Manifest</c> reference runs through the identical engine a <c>SignedInfo</c> reference does,
    /// byte-exact against the same public <see cref="XmlCanonicalization"/> oracle the sibling <see
    /// cref="NodeSetWithNoTransformsConvertsByTheImplicitCanonicalXml10Default"/> test uses.
    /// </summary>
    [TestMethod]
    public void ManifestReferenceDigestInputComputesThroughTheSameEngine()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="#manifestRef">
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <Object Id="manifestRef">
                <Manifest>
                  <Reference URI="#manifestTarget">
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>Ag==</DigestValue>
                  </Reference>
                </Manifest>
              </Object>
              <Object><Target Id="manifestTarget">hello</Target></Object>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            int manifestElementIndex = signature.Objects[0].ContentNodeIndices
                .First(i => table.KindOf(i) == XmlNodeKind.Element && table.LocalNameOf(i).SequenceEqual("Manifest"u8));
            bool isManifestRead = XmlManifest.TryRead(table, manifestElementIndex, BaseMemoryPool.Shared, out XmlManifest? manifest, out XmlSignatureReadError manifestReadError);
            Assert.IsTrue(isManifestRead, $"The Manifest must read but was refused with {manifestReadError.Failure}.");
            using(manifest)
            {
                bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, manifest!, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
                Assert.IsTrue(isComputed, $"The manifest reference's digest input must compute but was refused with {error.Failure}.");
                using(digestInput)
                {
                    Assert.AreEqual(
                        $"<Target xmlns=\"{XmlSignatureIdentifiers.XmlSignatureNamespace}\" Id=\"manifestTarget\">hello</Target>",
                        Encoding.UTF8.GetString(digestInput!.AsReadOnlySpan()),
                        "Canonicalization must render the ds namespace Target inherits from its ancestor Signature.");
                }
            }
        }
    }


    /// <summary>
    /// Proves the clause 6.3(d) of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> canonicalization-identifier set for <see
    /// cref="XmlReferenceProcessing.TryComputeSignedInfoOctets"/>: all six identifiers compute, each
    /// cross-checked against directly canonicalizing the same <c>SignedInfo</c> element subtree — the same
    /// oracle <see cref="XmlCanonicalization"/> is proven byte-exact against the raw specification fixtures
    /// elsewhere in this leaf's suite.
    /// </summary>
    [TestMethod]
    public void SignedInfoOctetsComputeForAllSixCanonicalizationAlgorithms()
    {
        string[] algorithmUris =
        [
            XmlSignatureIdentifiers.CanonicalXml10Uri,
            XmlSignatureIdentifiers.CanonicalXml10WithCommentsUri,
            XmlSignatureIdentifiers.CanonicalXml11Uri,
            XmlSignatureIdentifiers.CanonicalXml11WithCommentsUri,
            XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri,
            XmlSignatureIdentifiers.ExclusiveCanonicalXml10WithCommentsUri
        ];
        foreach(string algorithmUri in algorithmUris)
        {
            string document = $$"""
                <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                  <SignedInfo>
                    <CanonicalizationMethod Algorithm="{{algorithmUri}}"/>
                    <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                    <Reference URI="">
                      <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                      <DigestValue>AQ==</DigestValue>
                    </Reference>
                  </SignedInfo>
                  <SignatureValue>AQ==</SignatureValue>
                </Signature>
                """;
            (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
            using(table)
            using(signature)
            {
                bool isComputed = XmlReferenceProcessing.TryComputeSignedInfoOctets(table, signature, BaseMemoryPool.Shared, out PooledMemory? signedInfoOctets, out XmlSignatureProcessingError error);
                Assert.IsTrue(isComputed, $"'{algorithmUri}' must compute but was refused with {error.Failure}.");
                using(signedInfoOctets)
                {
                    string actual = Encoding.UTF8.GetString(signedInfoOctets!.AsReadOnlySpan());
                    XmlNodeSet expectedNodeSet = XmlNodeSet.ElementSubtree(table, signature.SignedInfo.ElementIndex);
                    bool isExclusive = algorithmUri == XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri || algorithmUri == XmlSignatureIdentifiers.ExclusiveCanonicalXml10WithCommentsUri;
                    bool isOracleCanonicalized = isExclusive
                        ? XmlCanonicalization.TryCanonicalizeExclusive(table, expectedNodeSet, algorithmUri.EndsWith("WithComments", StringComparison.Ordinal), [], BaseMemoryPool.Shared, out PooledMemory? expectedOctets, out _)
                        : XmlCanonicalization.TryCanonicalize(table, expectedNodeSet, MapAlgorithm(algorithmUri), BaseMemoryPool.Shared, out expectedOctets, out _);
                    Assert.IsTrue(isOracleCanonicalized);
                    using(expectedOctets)
                    {
                        Assert.AreEqual(Encoding.UTF8.GetString(expectedOctets!.AsReadOnlySpan()), actual, $"'{algorithmUri}' must dispatch to the matching canonicalization algorithm.");
                    }
                }
            }
        }
    }


    private static XmlCanonicalizationAlgorithm MapAlgorithm(string algorithmUri) => algorithmUri switch
    {
        _ when algorithmUri == XmlSignatureIdentifiers.CanonicalXml10Uri => XmlCanonicalizationAlgorithm.CanonicalXml10,
        _ when algorithmUri == XmlSignatureIdentifiers.CanonicalXml10WithCommentsUri => XmlCanonicalizationAlgorithm.CanonicalXml10WithComments,
        _ when algorithmUri == XmlSignatureIdentifiers.CanonicalXml11Uri => XmlCanonicalizationAlgorithm.CanonicalXml11,
        _ => XmlCanonicalizationAlgorithm.CanonicalXml11WithComments
    };


    /// <summary>
    /// Proves the "anything else is <c>UnsupportedCanonicalizationMethod</c>" boundary on clause 6.3(d)
    /// of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see>: a <c>CanonicalizationMethod Algorithm</c> outside the six named URIs
    /// refuses as <see cref="XmlSignatureProcessingFailure.UnsupportedCanonicalizationMethod"/> rather than
    /// being silently accepted.
    /// </summary>
    [TestMethod]
    public void SignedInfoOctetsRefuseAnUnsupportedCanonicalizationMethod()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="">
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isComputed = XmlReferenceProcessing.TryComputeSignedInfoOctets(table, signature, BaseMemoryPool.Shared, out PooledMemory? signedInfoOctets, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed);
            Assert.IsNull(signedInfoOctets);
            Assert.AreEqual(XmlSignatureProcessingFailure.UnsupportedCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax
    /// and Processing (Second Edition)</see> section 4.3.1's "This element uses the general structure for
    /// algorithms described in ... section 6.1" (parameter elements attach to the algorithm role element),
    /// the "a <c>PrefixList</c> on the method honored for the exclusive family": the
    /// <c>CanonicalizationMethod</c>'s own <c>InclusiveNamespaces PrefixList</c> is honored when
    /// canonicalizing <c>SignedInfo</c> itself — a namespace prefix in scope at <c>SignedInfo</c> but not
    /// visibly utilized inside it renders only when the method's own <c>PrefixList</c> names it.
    /// </summary>
    [TestMethod]
    public void SignedInfoOctetsHonorThePrefixListOnTheCanonicalizationMethod()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}" xmlns:q="urn:example:q">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri}}">
                  <ec:InclusiveNamespaces xmlns:ec="{{XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri}}" PrefixList="q"/>
                </CanonicalizationMethod>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="">
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isComputed = XmlReferenceProcessing.TryComputeSignedInfoOctets(table, signature, BaseMemoryPool.Shared, out PooledMemory? signedInfoOctets, out XmlSignatureProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(signedInfoOctets)
            {
                string text = Encoding.UTF8.GetString(signedInfoOctets!.AsReadOnlySpan());
                Assert.Contains("xmlns:q=\"urn:example:q\"", text);
            }
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature
    /// Syntax and Processing (Second Edition)</see> section 4.3.3.3 (whose comment-deletion rule governs
    /// same-document REFERENCE dereferencing, not <c>SignedInfo</c> canonicalization), the "comments inside
    /// <c>SignedInfo</c> follow the algorithm variant, section 4.3.3.3 does not apply to
    /// <c>SignedInfo</c>": the same comment renders under a with-comments algorithm and is absent under the
    /// comment-omitting one.
    /// </summary>
    [TestMethod]
    public void SignedInfoOctetsRenderCommentsPerTheAlgorithmVariant()
    {
        string BuildDocument(string algorithmUri) => $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{algorithmUri}}"/>
                <!--signedinfo-comment-->
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="">
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;

        (XmlNodeTable withCommentsTable, XmlSignature withCommentsSignature) = ReadFirstSignature(BuildDocument(XmlSignatureIdentifiers.CanonicalXml10WithCommentsUri), BaseMemoryPool.Shared);
        (XmlNodeTable omitCommentsTable, XmlSignature omitCommentsSignature) = ReadFirstSignature(BuildDocument(XmlSignatureIdentifiers.CanonicalXml10Uri), BaseMemoryPool.Shared);
        using(withCommentsTable)
        using(withCommentsSignature)
        using(omitCommentsTable)
        using(omitCommentsSignature)
        {
            bool isWithComputed = XmlReferenceProcessing.TryComputeSignedInfoOctets(withCommentsTable, withCommentsSignature, BaseMemoryPool.Shared, out PooledMemory? withCommentsOctets, out XmlSignatureProcessingError withError);
            bool isOmitComputed = XmlReferenceProcessing.TryComputeSignedInfoOctets(omitCommentsTable, omitCommentsSignature, BaseMemoryPool.Shared, out PooledMemory? omitCommentsOctets, out XmlSignatureProcessingError omitError);
            Assert.IsTrue(isWithComputed, $"Must compute but was refused with {withError.Failure}.");
            Assert.IsTrue(isOmitComputed, $"Must compute but was refused with {omitError.Failure}.");
            using(withCommentsOctets)
            using(omitCommentsOctets)
            {
                Assert.Contains("<!--signedinfo-comment-->", Encoding.UTF8.GetString(withCommentsOctets!.AsReadOnlySpan()));
                Assert.DoesNotContain("<!--", Encoding.UTF8.GetString(omitCommentsOctets!.AsReadOnlySpan()));
            }
        }
    }


    private static XmlSignatureProcessingError ComputeDigestInputRefusalForTransform(string transformAlgorithmUri)
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="">
                  <Transforms><Transform Algorithm="{{transformAlgorithmUri}}"/></Transforms>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using(var metered = new MeteredHousePool())
            {
                bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
                Assert.IsFalse(isComputed, $"Transform '{transformAlgorithmUri}' must refuse.");
                Assert.IsNull(digestInput);
                Assert.AreEqual(0L, metered.OutstandingCount, $"Transform '{transformAlgorithmUri}' must refuse without leaving the dereferenced node-set outstanding.");

                return error;
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6 chapeau's "Algorithm Identifiers and Implementation
    /// Requirements": <see cref="XmlSignatureProcessingFailure.UnsupportedTransform"/> for a <c>Transform
    /// Algorithm</c> URI this leaf does not recognize at all, refusing rather than being silently skipped or
    /// executed.
    /// </summary>
    [TestMethod]
    public void UnrecognizedTransformUriRefusesAsUnsupportedTransform()
    {
        XmlSignatureProcessingError error = ComputeDigestInputRefusalForTransform("urn:example:unknown-transform");

        Assert.AreEqual(XmlSignatureProcessingFailure.UnsupportedTransform, error.Failure);
    }


    /// <summary>
    /// Proves the staging disposition for the XPath transform of <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 6.6.3 ("Recommended"): <see
    /// cref="XmlSignatureProcessingFailure.TransformNotYetSupported"/>, STAGED and owned by (needs the
    /// hand-rolled XPath 1.0 evaluator; the JSONata precedent sizes it as feasible) — this is a staging
    /// split, not a deviation; leg-end conformance requires to land.
    /// </summary>
    [TestMethod]
    public void XPathTransformRefusesAsTransformNotYetSupported()
    {
        XmlSignatureProcessingError error = ComputeDigestInputRefusalForTransform(XmlSignatureIdentifiers.XPathTransformUri);

        Assert.AreEqual(XmlSignatureProcessingFailure.TransformNotYetSupported, error.Failure);
    }


    /// <summary>
    /// Proves <see cref="XmlSignatureProcessingFailure.TransformNotYetSupported"/> for the XML-Signature
    /// XPath Filter 2.0 transform clause 6.3(g) of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> requires "shall be supported": STAGED, owned by (needs the
    /// hand-rolled XPath 1.0 evaluator; the JSONata precedent sizes it as feasible) — this is a staging
    /// split, not a deviation; leg-end conformance requires to land.
    /// </summary>
    [TestMethod]
    public void XPathFilter2TransformRefusesAsTransformNotYetSupported()
    {
        XmlSignatureProcessingError error = ComputeDigestInputRefusalForTransform(XmlSignatureIdentifiers.XPathFilter2TransformUri);

        Assert.AreEqual(XmlSignatureProcessingFailure.TransformNotYetSupported, error.Failure);
    }


    /// <summary>
    /// Proves the DEVIATION disposition for XSLT (<see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 6.6.5, XMLDSIG "Optional"; ETSI 6.3(g) "shall be supported"): <see
    /// cref="XmlSignatureProcessingFailure.TransformRefused"/>, adjudicated — executing attacker-supplied
    /// stylesheets is the section 8.3 "unacceptable processing or memory demand" class and this surface's
    /// DOCTYPE precedent refuses such classes at the door; XMLDSIG core itself ranks XSLT Optional.
    /// Flagged for owner ratification at the XAdES leg reconciliation, beside the matching ETSI
    /// requirement letter.
    /// </summary>
    [TestMethod]
    public void XsltTransformRefusesAsTransformRefused()
    {
        XmlSignatureProcessingError error = ComputeDigestInputRefusalForTransform(XmlSignatureIdentifiers.XsltTransformUri);

        Assert.AreEqual(XmlSignatureProcessingFailure.TransformRefused, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax
    /// and Processing (Second Edition)</see> section 8.3's "even there perverse parameters might cause
    /// unacceptable processing or memory demand" (the same DEVIATION class as XSLT), the DEVIATION
    /// disposition for the OOXML Relationships transform (ECMA-376; ETSI 6.3(g) "shall be supported"): <see
    /// cref="XmlSignatureProcessingFailure.TransformRefused"/>, same treatment as XSLT — OPC package signing
    /// is outside the document classes this library models.
    /// </summary>
    [TestMethod]
    public void RelationshipTransformRefusesAsTransformRefused()
    {
        XmlSignatureProcessingError error = ComputeDigestInputRefusalForTransform(XmlSignatureIdentifiers.RelationshipTransformUri);

        Assert.AreEqual(XmlSignatureProcessingFailure.TransformRefused, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 8.3's "even there perverse parameters might cause
    /// unacceptable processing or memory demand" through the documented hardening bound "maximum transforms
    /// per reference (32, named constant ... — DoS posture; XMLDSIG sets no bound": <see
    /// cref="XmlSignatureProcessingFailure.TransformCountExceeded"/> for a chain of <see
    /// cref="XmlReferenceProcessing.MaximumTransformCount"/> plus one <c>Transform</c> elements. The refusal
    /// is immediate (no dereference, no transform execution), so it neither hangs nor leaves any buffer
    /// outstanding in the metered pool.
    /// </summary>
    [TestMethod]
    public void TransformCountExceededRefusesImmediatelyWithBalancedPool()
    {
        var transforms = new StringBuilder();
        for(int i = 0; i <= XmlReferenceProcessing.MaximumTransformCount; ++i)
        {
            transforms.Append(CultureInfo.InvariantCulture, $"<Transform Algorithm=\"{XmlSignatureIdentifiers.EnvelopedSignatureTransformUri}\"/>");
        }

        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="">
                  <Transforms>{{transforms}}</Transforms>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            Assert.HasCount(XmlReferenceProcessing.MaximumTransformCount + 1, signature.SignedInfo.References[0].Transforms);

            using(var metered = new MeteredHousePool())
            {
                bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

                Assert.IsFalse(isComputed);
                Assert.IsNull(digestInput);
                Assert.AreEqual(XmlSignatureProcessingFailure.TransformCountExceeded, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "The refusal must not rent anything left outstanding.");
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 8.3's "even there perverse parameters might cause
    /// unacceptable processing or memory demand" through the documented hardening bound "maximum re-parse
    /// depth through a chain (4 — octets→node-set parses per reference)": <see
    /// cref="XmlSignatureProcessingFailure.ReparseDepthExceeded"/> for a chain of <see
    /// cref="XmlReferenceProcessing.MaximumReparseDepth"/> plus one canonicalization transforms in a row,
    /// each converting the previous one's octets output back to octets and so forcing a fresh
    /// octets-to-node-set parse for the next — the refusal fires on the parse that would exceed the bound,
    /// rather than looping. Every octets buffer and every re-parsed table the engine rented along the way is
    /// returned, observed through <see cref="MeteredHousePool"/>.
    /// </summary>
    [TestMethod]
    public void ReparseDepthExceededRefusesWithoutHangingAndWithBalancedPool()
    {
        var transforms = new StringBuilder();
        for(int i = 0; i <= XmlReferenceProcessing.MaximumReparseDepth; ++i)
        {
            transforms.Append(CultureInfo.InvariantCulture, $"<Transform Algorithm=\"{XmlSignatureIdentifiers.CanonicalXml10Uri}\"/>");
        }

        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="http://example.com/frag.xml">
                  <Transforms>{{transforms}}</Transforms>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using(var metered = new MeteredHousePool())
            {
                bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, CreateFixedResolver("<a/>"u8.ToArray()), metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

                Assert.IsFalse(isComputed);
                Assert.IsNull(digestInput);
                Assert.AreEqual(XmlSignatureProcessingFailure.ReparseDepthExceeded, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every re-parsed table and every intermediate octets buffer must be returned on refusal.");
            }
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature
    /// Syntax and Processing (Second Edition)</see> section 4.3.3.2's octets-to-node-set MUST (the re-parse
    /// this failure occurs during), the "a mid-chain parse failure surfaces the inner <c>XmlReadError</c>
    /// offset": a mid-chain re-parse failure surfaces <see
    /// cref="XmlSignatureProcessingFailure.ReferenceParseFailed"/> with the inner <see
    /// cref="XmlReadError"/> the failed parse itself reported — a canonicalization transform needs a
    /// node-set, but the octets a resolver supplies are not well-formed XML.
    /// </summary>
    [TestMethod]
    public void MidChainReparseFailurePropagatesTheInnerReadError()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="http://example.com/malformed.xml">
                  <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.CanonicalXml10Uri}}"/></Transforms>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using(var metered = new MeteredHousePool())
            {
                bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, CreateFixedResolver("<a>"u8.ToArray()), metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

                Assert.IsFalse(isComputed);
                Assert.IsNull(digestInput);
                Assert.AreEqual(XmlSignatureProcessingFailure.ReferenceParseFailed, error.Failure);
                Assert.IsNotNull(error.InnerReadError, "The failed re-parse's own XmlReadError must be carried.");
                Assert.AreEqual(0L, metered.OutstandingCount, "The staged octets and the failed re-parse's own resources must not leak on refusal.");
            }
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature
    /// Syntax and Processing (Second Edition)</see> section 4.3.3.2's reference-processing model, the "a
    /// <c>Reference</c> with no <c>URI</c> attribute is <c>UriOmitted</c>" propagates through the engine,
    /// not only the dereferencer directly: a dereferencing refusal (<see cref="XmlReferenceDereferencer"/>'s
    /// own <see cref="XmlSignatureProcessingFailure.UriOmitted"/>) propagates unchanged through <see
    /// cref="XmlReferenceProcessing.TryComputeDigestInput"/> rather than being absorbed or remapped.
    /// </summary>
    [TestMethod]
    public void DereferencingRefusalPropagatesThroughDigestInputComputation()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using(var metered = new MeteredHousePool())
            {
                bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

                Assert.IsFalse(isComputed);
                Assert.IsNull(digestInput);
                Assert.AreEqual(XmlSignatureProcessingFailure.UriOmitted, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "A refusal at dereference time, before any transform runs, must leave nothing outstanding.");
            }
        }
    }
}
