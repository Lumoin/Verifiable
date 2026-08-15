using System.Collections.Generic;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESRenewedDigestsV2Processing"/> against clause 5.5.3's XA-5.5.3-3 "shall not be
/// used" precondition and the XA-5.5.3-13 validation procedure's input-construction/comparison scaffolding of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESRenewedDigestsV2ProcessingTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";


    private static (XmlNodeTable Table, XmlSignature Signature) ReadSoleSignature(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices);
        bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isRead, $"The signature must read but was refused with {signatureError.Failure}.");

        return (table!, signature!);
    }


    private static XmlManifest ReadManifest(XmlNodeTable table, string id, BaseMemoryPool pool)
    {
        bool isFound = table.TryFindElementById(Encoding.UTF8.GetBytes(id), out int elementIndex, out _);
        Assert.IsTrue(isFound, $"'{id}' must resolve by Id.");
        bool isRead = XmlManifest.TryRead(table, elementIndex, pool, out XmlManifest? manifest, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"'{id}' must read but was refused with {error.Failure}.");

        return manifest!;
    }


    // --- XA-5.5.3-3 precondition ---

    /// <summary>
    /// Proves the permitted shape: a manifest that is BOTH signed (referenced by a same-document
    /// <c>ds:SignedInfo</c> reference) AND carries a detached (non-same-document) <c>ds:Reference</c>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void SignedManifestWithDetachedReferenceIsPermitted()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#manifest1"><ds:DigestMethod Algorithm="{Sha256}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>QQ==</ds:SignatureValue>
              <ds:Object>
                <ds:Manifest Id="manifest1">
                  <ds:Reference URI="http://example.com/detached.bin"><ds:DigestMethod Algorithm="{Sha256}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
                </ds:Manifest>
              </ds:Object>
            </ds:Signature>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, pool);
        using(table)
        using(signature)
        {
            XmlManifest manifest = ReadManifest(table, "manifest1", pool);
            using(manifest)
            {
                bool isDetermined = XAdESRenewedDigestsV2Processing.TryDetermineIsUsePermitted(table, signature, [manifest], out bool isPermitted, out XAdESProcessingError error);
                Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
                Assert.IsTrue(isPermitted);
            }
        }
    }


    /// <summary>
    /// Proves an UNSIGNED manifest (no <c>ds:SignedInfo</c> reference names it) — even carrying a detached
    /// reference — does not permit use.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void UnsignedManifestIsNotPermitted()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI=""><ds:DigestMethod Algorithm="{Sha256}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>QQ==</ds:SignatureValue>
              <ds:Object>
                <ds:Manifest Id="manifest1">
                  <ds:Reference URI="http://example.com/detached.bin"><ds:DigestMethod Algorithm="{Sha256}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
                </ds:Manifest>
              </ds:Object>
            </ds:Signature>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, pool);
        using(table)
        using(signature)
        {
            XmlManifest manifest = ReadManifest(table, "manifest1", pool);
            using(manifest)
            {
                bool isDetermined = XAdESRenewedDigestsV2Processing.TryDetermineIsUsePermitted(table, signature, [manifest], out bool isPermitted, out XAdESProcessingError error);
                Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
                Assert.IsFalse(isPermitted);
            }
        }
    }


    /// <summary>
    /// Proves a SIGNED manifest whose own references are all same-document (nothing detached) does not permit
    /// use.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void SignedManifestWithNoDetachedReferenceIsNotPermitted()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#manifest1"><ds:DigestMethod Algorithm="{Sha256}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>QQ==</ds:SignatureValue>
              <ds:Object>
                <Data Id="data1">hello</Data>
                <ds:Manifest Id="manifest1">
                  <ds:Reference URI="#data1"><ds:DigestMethod Algorithm="{Sha256}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
                </ds:Manifest>
              </ds:Object>
            </ds:Signature>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, pool);
        using(table)
        using(signature)
        {
            XmlManifest manifest = ReadManifest(table, "manifest1", pool);
            using(manifest)
            {
                bool isDetermined = XAdESRenewedDigestsV2Processing.TryDetermineIsUsePermitted(table, signature, [manifest], out bool isPermitted, out XAdESProcessingError error);
                Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
                Assert.IsFalse(isPermitted);
            }
        }
    }


    /// <summary>
    /// Proves an empty manifest list is not permitted, trivially.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void EmptyManifestListIsNotPermitted()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI=""><ds:DigestMethod Algorithm="{Sha256}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>QQ==</ds:SignatureValue>
            </ds:Signature>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, pool);
        using(table)
        using(signature)
        {
            bool isDetermined = XAdESRenewedDigestsV2Processing.TryDetermineIsUsePermitted(table, signature, [], out bool isPermitted, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.IsFalse(isPermitted);
        }
    }


    /// <summary>
    /// Proves the table-identity guard fires for a foreign manifest. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void ForeignManifestTableIsRefused()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#manifest1"><ds:DigestMethod Algorithm="{Sha256}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>QQ==</ds:SignatureValue>
              <ds:Object>
                <ds:Manifest Id="manifest1">
                  <ds:Reference URI="http://example.com/detached.bin"><ds:DigestMethod Algorithm="{Sha256}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
                </ds:Manifest>
              </ds:Object>
            </ds:Signature>
            """;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document, pool);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature) = ReadSoleSignature(document, pool);
        using(table)
        using(signature)
        using(foreignTable)
        using(foreignSignature)
        {
            XmlManifest manifest = ReadManifest(table, "manifest1", pool);
            using(manifest)
            {
                bool isDetermined = XAdESRenewedDigestsV2Processing.TryDetermineIsUsePermitted(foreignTable, signature, [manifest], out _, out XAdESProcessingError error);
                Assert.IsFalse(isDetermined, "A foreign table must refuse.");
                Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
            }
        }
    }


    // --- Input-construction/comparison scaffolding ---

    private static string InputConstructionDocument() => $$"""
        <root xmlns:ds="{{DsNamespace}}">
          <Data Id="data1">hello</Data>
          <ds:Reference Id="candidateRef" URI="#data1"><ds:DigestMethod Algorithm="{{Sha256}}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>
          <RenewedDigestsV2 xmlns="{{V141}}" Id="rdv1">
            <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
            <ds:DigestMethod Algorithm="{{Sha256}}"/>
            <RecomputedDigestValue><NewSDODigestValue>AQ==</NewSDODigestValue><OriginalRefDigest>Ag==</OriginalRefDigest></RecomputedDigestValue>
          </RenewedDigestsV2>
        </root>
        """;


    private static (XmlNodeTable Table, XAdESRenewedDigestsV2 RenewedDigestsV2, XmlReference CandidateReference) ReadInputConstructionFixture(BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(InputConstructionDocument()), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        bool isRdvFound = table!.TryFindElementById("rdv1"u8, out int rdvIndex, out _);
        Assert.IsTrue(isRdvFound, "The fixture RenewedDigestsV2 must resolve by Id.");
        bool isRdvRead = XAdESRenewedDigestsV2.TryRead(table, rdvIndex, pool, out XAdESRenewedDigestsV2? renewedDigestsV2, out XAdESReadError rdvError);
        Assert.IsTrue(isRdvRead, $"The fixture RenewedDigestsV2 must read but was refused with {rdvError.Failure}.");

        bool isRefFound = table.TryFindElementById("candidateRef"u8, out int refIndex, out _);
        Assert.IsTrue(isRefFound, "The fixture candidate ds:Reference must resolve by Id.");
        var owned = new List<PooledMemory>();
        bool isRefRead = XmlReference.TryRead(table, refIndex, pool, owned, out XmlReference candidateReference, out XmlSignatureReadError refError);
        Assert.IsTrue(isRefRead, $"The fixture candidate ds:Reference must read but was refused with {refError.Failure}.");

        return (table!, renewedDigestsV2!, candidateReference);
    }


    /// <summary>
    /// Proves <see cref="XAdESRenewedDigestsV2Processing.TryComputeOriginalRefDigestInput"/> equals the
    /// candidate <c>ds:Reference</c> element subtree canonicalized directly with the same algorithm — computed
    /// a second, independent way.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void OriginalRefDigestInputEqualsCanonicalizedReferenceElement()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESRenewedDigestsV2 renewedDigestsV2, XmlReference candidateReference) = ReadInputConstructionFixture(pool);
        using(table)
        using(renewedDigestsV2)
        {
            bool isCanonicalizedDirectly = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(
                table, XmlNodeSet.ElementSubtree(table, candidateReference.ElementIndex), XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10, ReadOnlySpan<byte>.Empty, pool, out PooledMemory? expectedMemory, out XmlCanonicalizationError canonError);
            Assert.IsTrue(isCanonicalizedDirectly, $"Direct canonicalization must succeed but was refused with {canonError.Failure}.");
            byte[] expected;
            using(expectedMemory)
            {
                expected = expectedMemory!.AsReadOnlySpan().ToArray();
            }

            bool isComputed = XAdESRenewedDigestsV2Processing.TryComputeOriginalRefDigestInput(table, renewedDigestsV2, candidateReference, pool, out PooledMemory? input, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(input)
            {
                Assert.AreSequenceEqual(expected, input!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves <see cref="XAdESRenewedDigestsV2Processing.TryComputeNewSDODigestValueInput"/> is exactly
    /// <see cref="XmlReferenceProcessing.TryComputeDigestInputForReference"/>'s own result — the digest-INPUT-
    /// not-digest split XA-5.5.3-13's NOTE 2 requires (retrieval and transform processing WITHOUT the final
    /// digest step), computed a second, independent way through the same shipped engine.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void NewSDODigestValueInputEqualsDigestInputForReference()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XAdESRenewedDigestsV2 renewedDigestsV2, XmlReference candidateReference) = ReadInputConstructionFixture(pool);
        using(table)
        using(renewedDigestsV2)
        {
            bool isComputedDirectly = XmlReferenceProcessing.TryComputeDigestInputForReference(table, candidateReference, resolver: null, pool, out PooledMemory? expectedMemory, out XmlSignatureProcessingError directError);
            Assert.IsTrue(isComputedDirectly, $"Direct computation must succeed but was refused with {directError.Failure}.");
            byte[] expected;
            using(expectedMemory)
            {
                expected = expectedMemory!.AsReadOnlySpan().ToArray();
            }

            bool isComputed = XAdESRenewedDigestsV2Processing.TryComputeNewSDODigestValueInput(table, candidateReference, resolver: null, pool, out PooledMemory? input, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
            using(input)
            {
                Assert.AreSequenceEqual(expected, input!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves <see cref="XAdESRenewedDigestsV2Processing.CompareDigest"/>'s equality/inequality both ways —
    /// this leaf's comparison scaffolding for XA-5.5.3-13 steps 4)-5), which never digests itself.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void CompareDigestMatchesAndMismatches()
    {
        byte[] a = [1, 2, 3];
        byte[] b = [1, 2, 3];
        byte[] c = [1, 2, 4];
        Assert.IsTrue(XAdESRenewedDigestsV2Processing.CompareDigest(a, b));
        Assert.IsFalse(XAdESRenewedDigestsV2Processing.CompareDigest(a, c));
    }
}
