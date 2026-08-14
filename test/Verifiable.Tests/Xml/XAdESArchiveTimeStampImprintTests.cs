using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESArchiveTimeStampImprint"/> against clause 5.5.2.3 (not-distributed) and clause
/// 5.5.2.4 (distributed) message-imprint computation of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the shared steps 2)-4)/6), the variant-specific step 5), and both cases'
/// exclusion of the <c>ds:Object</c> carrying <c>QualifyingProperties</c> at step 6).
/// </summary>
[TestClass]
internal sealed class XAdESArchiveTimeStampImprintTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private const string ExclusiveC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

    private const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";


    private static string Reference(string id, string uri, string? type = null) =>
        $"""<ds:Reference Id="{id}" URI="{uri}"{(type is null ? "" : $""" Type="{type}" """)}><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>QQ==</ds:DigestValue></ds:Reference>""";


    /// <summary>
    /// A signature with two <c>ds:SignedInfo</c> references (a plain data reference and the SignedProperties
    /// one), a two-member <c>UnsignedSignatureProperties</c> straddling the <c>ArchiveTimeStamp</c> under test
    /// (one property before it, one after), and two <c>ds:Object</c> elements — the second carrying
    /// <c>QualifyingProperties</c>, excluded from step 6. The default namespace stays v1.3.2 throughout (so
    /// <c>XAdESTimeStampType</c>'s own children — <c>EncapsulatedTimeStamp</c>, <c>Include</c> — resolve
    /// correctly regardless of which XAdES element wraps them); <paramref name="archiveTimeStampBody"/> supplies
    /// its own v1.4.1-namespace <c>ArchiveTimeStamp</c> wrapper via the <c>ats:</c> prefix declared here.
    /// </summary>
    private static string Document(string archiveTimeStampBody, bool includeKeyInfo = false) => $$"""
        <ds:Signature xmlns:ds="{{DsNamespace}}" xmlns:ats="{{V141}}" Id="sig1">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            {{Reference("ref-data", "#data1")}}
            {{Reference("ref-sp", "#sp1", SignedPropertiesType)}}
          </ds:SignedInfo>
          <ds:SignatureValue>QQ==</ds:SignatureValue>
          {{(includeKeyInfo ? "<ds:KeyInfo Id=\"ki1\"><ds:KeyName>k</ds:KeyName></ds:KeyInfo>" : "")}}
          <ds:Object Id="obj-data">
            <Data Id="data1">hello</Data>
          </ds:Object>
          <ds:Object Id="obj-qp">
            <QualifyingProperties xmlns="{{V132}}" Target="#sig1">
              <SignedProperties Id="sp1">
                <SignedSignatureProperties><SigningTime>2024-01-01T00:00:00Z</SigningTime></SignedSignatureProperties>
              </SignedProperties>
              <UnsignedProperties>
                <UnsignedSignatureProperties Id="usp1">
                  <SignatureTimeStamp Id="earlier1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></SignatureTimeStamp>
                  {{archiveTimeStampBody}}
                  <SignatureTimeStamp Id="later1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></SignatureTimeStamp>
                </UnsignedSignatureProperties>
              </UnsignedProperties>
            </QualifyingProperties>
          </ds:Object>
        </ds:Signature>
        """;


    private static string ArchiveTimeStampBody(string extraChildren = "") =>
        $"""<ats:ArchiveTimeStamp Id="ats1">{extraChildren}<ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></ats:ArchiveTimeStamp>""";


    private static (XmlNodeTable Table, XmlSignature Signature, XAdESUnsignedSignatureProperties UnsignedSignatureProperties, XAdESArchiveTimeStamp ArchiveTimeStamp) ReadFixture(string document, BaseMemoryPool parsePool, BaseMemoryPool readPool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), parsePool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices);
        bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], readPool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");

        bool isContainerFound = table!.TryFindElementById("usp1"u8, out int containerIndex, out _);
        Assert.IsTrue(isContainerFound, "The fixture UnsignedSignatureProperties must resolve by Id.");
        bool isContainerRead = XAdESUnsignedSignatureProperties.TryRead(table, containerIndex, out XAdESUnsignedSignatureProperties container, out XAdESReadError containerError);
        Assert.IsTrue(isContainerRead, $"The fixture UnsignedSignatureProperties must read but was refused with {containerError.Failure}.");

        bool isStampFound = table.TryFindElementById("ats1"u8, out int stampIndex, out _);
        Assert.IsTrue(isStampFound, "The fixture ArchiveTimeStamp must resolve by Id.");
        bool isStampRead = XAdESArchiveTimeStamp.TryRead(table, stampIndex, readPool, out XAdESArchiveTimeStamp? stamp, out XAdESReadError stampError);
        Assert.IsTrue(isStampRead, $"The fixture ArchiveTimeStamp must read but was refused with {stampError.Failure}.");

        return (table!, signature!, container, stamp!);
    }


    private static byte[] CanonicalizeById(XmlNodeTable table, string id, BaseMemoryPool pool, XmlCanonicalizationAlgorithm algorithm, bool withoutComments = false)
    {
        bool isFound = table.TryFindElementById(Encoding.UTF8.GetBytes(id), out int elementIndex, out _);
        Assert.IsTrue(isFound, $"'{id}' must resolve by Id.");
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, elementIndex);
        if(withoutComments)
        {
            nodeSet = nodeSet.WithoutComments();
        }

        bool isCanonicalized = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(table, nodeSet, algorithm, ReadOnlySpan<byte>.Empty, pool, out PooledMemory? canonical, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"'{id}' must canonicalize but was refused with {error.Failure}.");
        using(canonical)
        {
            return canonical!.AsReadOnlySpan().ToArray();
        }
    }


    private static byte[] Canonicalize(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, XmlCanonicalizationAlgorithm algorithm)
    {
        bool isCanonicalized = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(table, XmlNodeSet.ElementSubtree(table, elementIndex), algorithm, ReadOnlySpan<byte>.Empty, pool, out PooledMemory? canonical, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"Element must canonicalize but was refused with {error.Failure}.");
        using(canonical)
        {
            return canonical!.AsReadOnlySpan().ToArray();
        }
    }


    private static byte[] StepThreeBytes(XmlNodeTable table, XmlSignature signature, XmlCanonicalizationAlgorithm algorithm, BaseMemoryPool pool)
    {
        bool isComputed = XmlReferenceProcessing.TryComputeMessageImprintInputForReferences(table, signature.SignedInfo.References, algorithm, ReadOnlySpan<byte>.Empty, resolver: null, pool, out PooledMemory? step3, out XmlSignatureProcessingError error);
        Assert.IsTrue(isComputed, $"Step 3 reference computation must succeed but was refused with {error.Failure}.");
        using(step3)
        {
            return step3!.AsReadOnlySpan().ToArray();
        }
    }


    private static bool Contains(byte[] haystack, byte[] needle)
    {
        if(needle.Length == 0)
        {
            return true;
        }

        for(int i = 0; i <= haystack.Length - needle.Length; ++i)
        {
            if(haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Proves the not-distributed algorithm end to end: step 3) includes BOTH <c>ds:SignedInfo</c> references
    /// (INCLUDING the <c>SignedProperties</c> one — contrast clause 5.2.8.1's exclusion), step 4) canonicalizes
    /// <c>ds:SignedInfo</c> then <c>ds:SignatureValue</c> (no <c>ds:KeyInfo</c>), step 5) canonicalizes only the
    /// unsigned property PRECEDING the <c>ArchiveTimeStamp</c> ("earlier1"), never the one AFTER it
    /// ("later1" — the boundary this test proves), and step 6) canonicalizes only the <c>ds:Object</c>
    /// NOT carrying <c>QualifyingProperties</c>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.3.
    /// </summary>
    [TestMethod]
    public void NotDistributedImprintMatchesStepwiseComputationAndExcludesFollowingProperty()
    {
        string document = Document(ArchiveTimeStampBody());
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESArchiveTimeStamp stamp) = ReadFixture(document, pool, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            XmlCanonicalizationAlgorithm algorithm = XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10;
            byte[] expected =
            [
                .. StepThreeBytes(table, signature, algorithm, pool),
                .. Canonicalize(table, signature.SignedInfo.ElementIndex, pool, algorithm),
                .. Canonicalize(table, signature.SignatureValueElementIndex, pool, algorithm),
                .. CanonicalizeById(table, "earlier1", pool, algorithm),
                .. CanonicalizeById(table, "obj-data", pool, algorithm),
            ];

            bool isFound = table.TryFindElementById("obj-qp"u8, out int qpObjectElementIndex, out _);
            Assert.IsTrue(isFound);
            int qualifyingPropertiesObjectOrdinal = -1;
            for(int i = 0; i < signature.Objects.Count; ++i)
            {
                if(signature.Objects[i].ElementIndex == qpObjectElementIndex)
                {
                    qualifyingPropertiesObjectOrdinal = i;
                }
            }

            Assert.IsGreaterThanOrEqualTo(0, qualifyingPropertiesObjectOrdinal);

            bool isComputed = XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput(
                table, signature, stamp, container, qualifyingPropertiesObjectOrdinal, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                Assert.AreSequenceEqual(expected, imprintInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves step 4) canonicalizes <c>ds:KeyInfo</c> too, when present, after <c>ds:SignatureValue</c>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.3.
    /// </summary>
    [TestMethod]
    public void NotDistributedImprintIncludesKeyInfoWhenPresent()
    {
        string document = Document(ArchiveTimeStampBody(), includeKeyInfo: true);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESArchiveTimeStamp stamp) = ReadFixture(document, pool, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            Assert.IsTrue(signature.KeyInfo.HasValue, "The fixture must carry ds:KeyInfo.");
            bool isFound = table.TryFindElementById("obj-qp"u8, out int qpObjectElementIndex, out _);
            Assert.IsTrue(isFound);
            int qualifyingPropertiesObjectOrdinal = signature.Objects.Count - 1;
            Assert.AreEqual(qpObjectElementIndex, signature.Objects[qualifyingPropertiesObjectOrdinal].ElementIndex);

            bool isComputed = XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput(
                table, signature, stamp, container, qualifyingPropertiesObjectOrdinal, resolver: null, pool, out PooledMemory? withKeyInfo, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(withKeyInfo)
            {
                byte[] keyInfoCanonical = Canonicalize(table, signature.KeyInfo!.Value.ElementIndex, pool, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10);
                byte[] actual = withKeyInfo!.AsReadOnlySpan().ToArray();
                Assert.IsTrue(Contains(actual, keyInfoCanonical), "The canonicalized ds:KeyInfo octets must appear in the imprint input.");
            }
        }
    }


    /// <summary>
    /// Proves the distributed variant's step 5): the <c>ArchiveTimeStamp</c>'s <c>Include</c> elements, in
    /// their OWN document order (not the order the referenced properties themselves appear in), each retrieved
    /// with COMMENT NODES DELETED — the <see cref="XAdESIncludeUriProcessing"/> machinery every <c>Include</c>
    /// mechanism shares. A <c>WithComments</c> canonicalization algorithm is used specifically so that a
    /// surviving comment would be visible if deletion did not happen.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.4.
    /// </summary>
    [TestMethod]
    public void DistributedImprintUsesIncludeOrderAndDeletesComments()
    {
        string archiveTimeStampBody = $"""
            <ats:ArchiveTimeStamp Id="ats1">
              <Include URI="#propB"/>
              <Include URI="#propA"/>
              <ds:CanonicalizationMethod Algorithm="{ExclusiveC14NWithComments}"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </ats:ArchiveTimeStamp>
            """;
        string document = $$"""
            <ds:Signature xmlns:ds="{{DsNamespace}}" xmlns:ats="{{V141}}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                {{Reference("ref-data", "#data1")}}
                {{Reference("ref-sp", "#sp1", SignedPropertiesType)}}
              </ds:SignedInfo>
              <ds:SignatureValue>QQ==</ds:SignatureValue>
              <ds:Object Id="obj-data">
                <Data Id="data1">hello</Data>
              </ds:Object>
              <ds:Object Id="obj-qp">
                <QualifyingProperties xmlns="{{V132}}" Target="#sig1">
                  <SignedProperties Id="sp1">
                    <SignedSignatureProperties><SigningTime>2024-01-01T00:00:00Z</SigningTime></SignedSignatureProperties>
                  </SignedProperties>
                  <UnsignedProperties>
                    <UnsignedSignatureProperties Id="usp1">
                      <PropA Id="propA"><!--comment-a--><Data>A</Data></PropA>
                      <PropB Id="propB"><!--comment-b--><Data>B</Data></PropB>
                      {{archiveTimeStampBody}}
                    </UnsignedSignatureProperties>
                  </UnsignedProperties>
                </QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESArchiveTimeStamp stamp) = ReadFixture(document, pool, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            Assert.HasCount(2, stamp.TimeStamp.Includes);
            XmlCanonicalizationAlgorithm algorithm = XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments;

            byte[] expected =
            [
                .. StepThreeBytes(table, signature, algorithm, pool),
                .. Canonicalize(table, signature.SignedInfo.ElementIndex, pool, algorithm),
                .. Canonicalize(table, signature.SignatureValueElementIndex, pool, algorithm),
                .. CanonicalizeById(table, "propB", pool, algorithm, withoutComments: true),
                .. CanonicalizeById(table, "propA", pool, algorithm, withoutComments: true),
                .. CanonicalizeById(table, "obj-data", pool, algorithm),
            ];

            int qualifyingPropertiesObjectOrdinal = signature.Objects.Count - 1;

            bool isComputed = XAdESArchiveTimeStampImprint.TryComputeDistributedImprintInput(
                table, signature, stamp, container, qualifyingPropertiesObjectOrdinal, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(imprintInput)
            {
                byte[] actual = imprintInput!.AsReadOnlySpan().ToArray();
                Assert.AreSequenceEqual(expected, actual);

                //Sanity: had comments NOT been deleted, propA's WithComments canonical form would carry more
                //bytes than the WithoutComments form used to build `expected` — proving this fixture actually
                //exercises comment deletion, not vacuously passing because there was nothing to delete.
                byte[] propAWithComments = CanonicalizeById(table, "propA", pool, algorithm, withoutComments: false);
                byte[] propAWithoutComments = CanonicalizeById(table, "propA", pool, algorithm, withoutComments: true);
                Assert.IsGreaterThan(propAWithoutComments.Length, propAWithComments.Length);
            }
        }
    }


    /// <summary>
    /// Proves clause 5.5.2.4 step 5's "present in the XAdES signature" membership restriction: a relocated-decoy attack — the genuine <c>Include</c> target moved OUT of
    /// <c>UnsignedSignatureProperties</c> (same <c>Id</c>, same content, same namespace, so no duplicate-<c>Id</c> refusal fires) into a plain <c>ds:Object</c>, with a
    /// forged replacement inserted in its place inside <c>UnsignedSignatureProperties</c> — refuses with <see
    /// cref="XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty"/> rather than silently canonicalizing the relocated original (which, before this fix,
    /// produced byte-identical imprint octets to the honest document while the in-signature property was forged). The honest sibling document, where the same property
    /// legitimately sits inside <c>UnsignedSignatureProperties</c>, computes successfully. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.4.
    /// </summary>
    [TestMethod]
    public void DistributedIncludeTargetRelocatedOutsideContainerIsRefused()
    {
        string honestDocument = $$"""
            <ds:Signature xmlns:ds="{{DsNamespace}}" xmlns:ats="{{V141}}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                {{Reference("ref-data", "#data1")}}
                {{Reference("ref-sp", "#sp1", SignedPropertiesType)}}
              </ds:SignedInfo>
              <ds:SignatureValue>QQ==</ds:SignatureValue>
              <ds:Object Id="obj-data">
                <Data Id="data1">hello</Data>
              </ds:Object>
              <ds:Object Id="obj-qp">
                <QualifyingProperties xmlns="{{V132}}" Target="#sig1">
                  <SignedProperties Id="sp1">
                    <SignedSignatureProperties><SigningTime>2024-01-01T00:00:00Z</SigningTime></SignedSignatureProperties>
                  </SignedProperties>
                  <UnsignedProperties>
                    <UnsignedSignatureProperties Id="usp1">
                      <PropA Id="propA"><Data>ORIGINAL</Data></PropA>
                      <ats:ArchiveTimeStamp Id="ats1">
                        <Include URI="#propA"/>
                        <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                        <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
                      </ats:ArchiveTimeStamp>
                    </UnsignedSignatureProperties>
                  </UnsignedProperties>
                </QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        string attackedDocument = $$"""
            <ds:Signature xmlns:ds="{{DsNamespace}}" xmlns:ats="{{V141}}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                {{Reference("ref-data", "#data1")}}
                {{Reference("ref-sp", "#sp1", SignedPropertiesType)}}
              </ds:SignedInfo>
              <ds:SignatureValue>QQ==</ds:SignatureValue>
              <ds:Object Id="obj-data">
                <Data Id="data1">hello</Data>
                <PropA Id="propA"><Data>ORIGINAL</Data></PropA>
              </ds:Object>
              <ds:Object Id="obj-qp">
                <QualifyingProperties xmlns="{{V132}}" Target="#sig1">
                  <SignedProperties Id="sp1">
                    <SignedSignatureProperties><SigningTime>2024-01-01T00:00:00Z</SigningTime></SignedSignatureProperties>
                  </SignedProperties>
                  <UnsignedProperties>
                    <UnsignedSignatureProperties Id="usp1">
                      <PropA Id="propA-forged"><Data>FORGED</Data></PropA>
                      <ats:ArchiveTimeStamp Id="ats1">
                        <Include URI="#propA"/>
                        <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                        <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
                      </ats:ArchiveTimeStamp>
                    </UnsignedSignatureProperties>
                  </UnsignedProperties>
                </QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable honestTable, XmlSignature honestSignature, XAdESUnsignedSignatureProperties honestContainer, XAdESArchiveTimeStamp honestStamp) = ReadFixture(honestDocument, pool, pool);
        using(honestTable)
        using(honestSignature)
        using(honestStamp)
        {
            bool isHonestComputed = XAdESArchiveTimeStampImprint.TryComputeDistributedImprintInput(
                honestTable, honestSignature, honestStamp, honestContainer, qualifyingPropertiesObjectOrdinal: 1, resolver: null, pool, out PooledMemory? honestImprintInput, out XAdESProcessingError honestError);
            Assert.IsTrue(isHonestComputed, $"The honest document must compute but was refused with {honestError.Failure}.");
            honestImprintInput!.Dispose();
        }

        (XmlNodeTable attackedTable, XmlSignature attackedSignature, XAdESUnsignedSignatureProperties attackedContainer, XAdESArchiveTimeStamp attackedStamp) = ReadFixture(attackedDocument, pool, pool);
        using(attackedTable)
        using(attackedSignature)
        using(attackedStamp)
        {
            bool isAttackedComputed = XAdESArchiveTimeStampImprint.TryComputeDistributedImprintInput(
                attackedTable, attackedSignature, attackedStamp, attackedContainer, qualifyingPropertiesObjectOrdinal: 1, resolver: null, pool, out PooledMemory? attackedImprintInput, out XAdESProcessingError attackedError);
            Assert.IsFalse(isAttackedComputed, "The relocated-decoy attack must be refused rather than producing an imprint.");
            Assert.IsNull(attackedImprintInput);
            Assert.AreEqual(XAdESProcessingFailure.IncludeTargetNotAnUnsignedQualifyingProperty, attackedError.Failure);
        }
    }


    /// <summary>
    /// Proves step 6's <c>qualifyingPropertiesObjectOrdinal</c> — the
    /// ordinal that decides which <c>ds:Object</c> is EXCLUDED from the imprint — is refused when it names a
    /// <c>ds:Object</c> that does NOT itself carry a <c>QualifyingProperties</c> direct child (here, ordinal 0,
    /// which names <c>obj-data</c> rather than the genuine <c>obj-qp</c> at ordinal 1), rather than silently
    /// computing the imprint over the wrong object set.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.3.
    /// </summary>
    [TestMethod]
    public void OrdinalNamingANonQualifyingPropertiesObjectIsRefused()
    {
        string document = Document(ArchiveTimeStampBody());
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESArchiveTimeStamp stamp) = ReadFixture(document, pool, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isFound = table.TryFindElementById("obj-data"u8, out int dataObjectElementIndex, out _);
            Assert.IsTrue(isFound);
            int nonQualifyingPropertiesOrdinal = -1;
            for(int i = 0; i < signature.Objects.Count; ++i)
            {
                if(signature.Objects[i].ElementIndex == dataObjectElementIndex)
                {
                    nonQualifyingPropertiesOrdinal = i;
                }
            }

            Assert.IsGreaterThanOrEqualTo(0, nonQualifyingPropertiesOrdinal);

            bool isComputed = XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput(
                table, signature, stamp, container, nonQualifyingPropertiesOrdinal, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An ordinal naming a non-QualifyingProperties ds:Object must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.QualifyingPropertiesObjectOrdinalDoesNotCarryQualifyingProperties, error.Failure);
        }
    }


    /// <summary>
    /// Proves an absent <c>ds:CanonicalizationMethod</c> on the <c>ArchiveTimeStamp</c> itself refuses rather than assuming a default algorithm — the not-distributed engine.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.1.
    /// </summary>
    [TestMethod]
    public void AbsentCanonicalizationMethodIsRefused()
    {
        string archiveTimeStampBody = """<ats:ArchiveTimeStamp Id="ats1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></ats:ArchiveTimeStamp>""";
        string document = Document(archiveTimeStampBody);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESArchiveTimeStamp stamp) = ReadFixture(document, pool, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput(table, signature, stamp, container, signature.Objects.Count - 1, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "An absent CanonicalizationMethod must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.AbsentCanonicalizationMethod, error.Failure);
        }
    }


    /// <summary>
    /// Proves custody is balanced on the success path via <see cref="MeteredHousePool"/> for the not-distributed
    /// engine: every intermediate buffer rented while processing references and canonicalizing is released
    /// internally, and only the final result is handed to the caller. The document itself parses over
    /// <see cref="BaseMemoryPool.Shared"/> — the table's own buffers are excluded from the metered count.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.3.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnSuccessAfterDisposingTheResult()
    {
        string document = Document(ArchiveTimeStampBody());
        using(var metered = new MeteredHousePool())
        {
            (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESArchiveTimeStamp stamp) = ReadFixture(document, BaseMemoryPool.Shared, metered.Pool);
            using(table)
            using(signature)
            using(stamp)
            {
                bool isComputed = XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput(
                    table, signature, stamp, container, signature.Objects.Count - 1, resolver: null, metered.Pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
                imprintInput!.Dispose();
            }
        }
    }


    /// <summary>
    /// Proves the table-identity guard on the not-distributed engine. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.3.
    /// </summary>
    [TestMethod]
    public void TableMismatchIsRefused()
    {
        string document = Document(ArchiveTimeStampBody());
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESUnsignedSignatureProperties container, XAdESArchiveTimeStamp stamp) = ReadFixture(document, pool, pool);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature, XAdESUnsignedSignatureProperties foreignContainer, XAdESArchiveTimeStamp foreignStamp) = ReadFixture(document, pool, pool);
        using(table)
        using(signature)
        using(stamp)
        using(foreignTable)
        using(foreignSignature)
        using(foreignStamp)
        {
            _ = foreignContainer;
            bool isComputed = XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput(foreignTable, signature, stamp, container, signature.Objects.Count - 1, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, "A foreign table must refuse rather than computing against the wrong document.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves the not-distributed engine refuses when the given <c>ArchiveTimeStamp</c> is not itself a member
    /// of the given <c>UnsignedSignatureProperties</c> entry list — two independent, same-table containers,
    /// each with its own <c>ArchiveTimeStamp</c>, cross-paired.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.3.
    /// </summary>
    [TestMethod]
    public void ArchiveTimeStampNotInContainerIsRefused()
    {
        string document = $"""
            <root xmlns:ds="{DsNamespace}" xmlns:ats="{V141}">
              <ds:Signature Id="sig1">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  {Reference("ref-sp", "#sp1", SignedPropertiesType)}
                </ds:SignedInfo>
                <ds:SignatureValue>QQ==</ds:SignatureValue>
                <ds:Object Id="obj-qp">
                  <QualifyingProperties xmlns="{V132}" Target="#sig1">
                    <SignedProperties Id="sp1">
                      <SignedSignatureProperties><SigningTime>2024-01-01T00:00:00Z</SigningTime></SignedSignatureProperties>
                    </SignedProperties>
                  </QualifyingProperties>
                </ds:Object>
              </ds:Signature>
              <UnsignedSignatureProperties xmlns="{V132}" Id="uspA">
                <ats:ArchiveTimeStamp Id="atsA"><ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></ats:ArchiveTimeStamp>
              </UnsignedSignatureProperties>
              <UnsignedSignatureProperties xmlns="{V132}" Id="uspB">
                <ats:ArchiveTimeStamp Id="atsB"><ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></ats:ArchiveTimeStamp>
              </UnsignedSignatureProperties>
            </root>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            Assert.HasCount(1, signatureIndices);
            bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
            Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");
            using(signature)
            {
                bool isFoundA = table!.TryFindElementById("uspA"u8, out int containerAIndex, out _);
                bool isFoundB = table.TryFindElementById("uspB"u8, out int containerBIndex, out _);
                bool isFoundAts = table.TryFindElementById("atsA"u8, out int stampAIndex, out _);
                Assert.IsTrue(isFoundA && isFoundB && isFoundAts);

                bool isContainerBRead = XAdESUnsignedSignatureProperties.TryRead(table, containerBIndex, out XAdESUnsignedSignatureProperties containerB, out XAdESReadError containerBError);
                Assert.IsTrue(isContainerBRead, $"uspB must read but was refused with {containerBError.Failure}.");
                bool isStampARead = XAdESArchiveTimeStamp.TryRead(table, stampAIndex, pool, out XAdESArchiveTimeStamp? stampA, out XAdESReadError stampAError);
                Assert.IsTrue(isStampARead, $"atsA must read but was refused with {stampAError.Failure}.");
                using(stampA)
                {
                    _ = containerAIndex;
                    bool isComputed = XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput(
                        table, signature!, stampA!, containerB, qualifyingPropertiesObjectOrdinal: 0, resolver: null, pool, out _, out XAdESProcessingError error);
                    Assert.IsFalse(isComputed, "atsA is not a member of uspB and must be refused.");
                    Assert.AreEqual(XAdESProcessingFailure.ArchiveTimeStampNotFoundInUnsignedSignatureProperties, error.Failure);
                }
            }
        }
    }
}
