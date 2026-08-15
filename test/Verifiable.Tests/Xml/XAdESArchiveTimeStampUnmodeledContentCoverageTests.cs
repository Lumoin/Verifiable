using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proves the unmodeled-content-smuggling item: a genuinely UNKNOWN unsigned-signature- property occurrence
/// (foreign namespace, not one of clause 4.3.6's named choice members, tolerated as an unmodeled entry)
/// preceding an <c>ArchiveTimeStamp</c> is COVERED by its clause 5.5.2.3 step 5) message-imprint computation —
/// canonicalized into the imprint input like any other preceding property — rather than silently skipped
/// because this leaf does not interpret it. Skipping unmodeled content would let an attacker inject or alter
/// unknown-shaped material after archival without invalidating the archive time-stamp, defeating its whole
/// purpose.
/// </summary>
[TestClass]
internal sealed class XAdESArchiveTimeStampUnmodeledContentCoverageTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";


    private static string Reference(string id, string uri, string? type = null) =>
        $"""<ds:Reference Id="{id}" URI="{uri}"{(type is null ? "" : $""" Type="{type}" """)}><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>QQ==</ds:DigestValue></ds:Reference>""";


    /// <summary>
    /// The same document shape as <c>XAdESArchiveTimeStampImprintTests</c>'s own fixture, except the property
    /// preceding the <c>ArchiveTimeStamp</c> is a genuinely UNKNOWN, foreign-namespace element
    /// (<c>Id="unknown1"</c>) rather than a recognized <c>SignatureTimeStamp</c>.
    /// </summary>
    private static string Document() => $$"""
        <ds:Signature xmlns:ds="{{DsNamespace}}" xmlns:ats="{{V141}}" xmlns:x="urn:unknown-property" Id="sig1">
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
                  <x:UnknownProperty Id="unknown1">smuggled-content-must-be-covered</x:UnknownProperty>
                  <ats:ArchiveTimeStamp Id="ats1"><ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></ats:ArchiveTimeStamp>
                </UnsignedSignatureProperties>
              </UnsignedProperties>
            </QualifyingProperties>
          </ds:Object>
        </ds:Signature>
        """;


    private static byte[] CanonicalizeById(XmlNodeTable table, string id, BaseMemoryPool pool, XmlCanonicalizationAlgorithm algorithm)
    {
        bool isFound = table.TryFindElementById(Encoding.UTF8.GetBytes(id), out int elementIndex, out _);
        Assert.IsTrue(isFound, $"'{id}' must resolve by Id.");
        bool isCanonicalized = XmlReferenceProcessing.TryCanonicalizeForAlgorithm(
            table, XmlNodeSet.ElementSubtree(table, elementIndex), algorithm, ReadOnlySpan<byte>.Empty, pool, out PooledMemory? canonical, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"'{id}' must canonicalize but was refused with {error.Failure}.");
        using(canonical)
        {
            return canonical!.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// Proves clause 5.5.2.3 step 5) of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> canonicalizes an unrecognized preceding <c>UnsignedSignatureProperties</c>
    /// child into the <c>ArchiveTimeStamp</c> message-imprint input — see the type remarks.
    /// </summary>
    [TestMethod]
    public void UnknownPrecedingPropertyIsCanonicalizedIntoTheImprintInputNotSkipped()
    {
        string document = Document();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            Assert.HasCount(1, signatureIndices);
            bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
            Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");
            using(signature)
            {
                bool isContainerFound = table!.TryFindElementById("usp1"u8, out int containerIndex, out _);
                Assert.IsTrue(isContainerFound);
                bool isContainerRead = XAdESUnsignedSignatureProperties.TryRead(table, containerIndex, out XAdESUnsignedSignatureProperties container, out XAdESReadError containerError);
                Assert.IsTrue(isContainerRead, $"The fixture UnsignedSignatureProperties must read but was refused with {containerError.Failure}.");

                //Proves the leaf's own classification never refuses this content and marks it Unrecognized --
                //the precondition for the imprint-coverage claim below: an unmodeled entry, not a read refusal.
                Assert.AreEqual(XAdESUnsignedSignaturePropertyName.Unrecognized, container.Properties[0].Name);

                bool isStampFound = table.TryFindElementById("ats1"u8, out int stampIndex, out _);
                Assert.IsTrue(isStampFound);
                bool isStampRead = XAdESArchiveTimeStamp.TryRead(table, stampIndex, pool, out XAdESArchiveTimeStamp? stamp, out XAdESReadError stampError);
                Assert.IsTrue(isStampRead, $"The fixture ArchiveTimeStamp must read but was refused with {stampError.Failure}.");
                using(stamp)
                {
                    bool isFound = table.TryFindElementById("obj-qp"u8, out int qpObjectElementIndex, out _);
                    Assert.IsTrue(isFound);
                    int qualifyingPropertiesObjectOrdinal = -1;
                    for(int i = 0; i < signature!.Objects.Count; ++i)
                    {
                        if(signature.Objects[i].ElementIndex == qpObjectElementIndex)
                        {
                            qualifyingPropertiesObjectOrdinal = i;
                        }
                    }

                    Assert.IsGreaterThanOrEqualTo(0, qualifyingPropertiesObjectOrdinal);

                    bool isComputed = XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput(
                        table, signature, stamp!, container, qualifyingPropertiesObjectOrdinal, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                    Assert.IsTrue(isComputed, $"Must compute but was refused with {error.Failure}.");
                    using(imprintInput)
                    {
                        byte[] actual = imprintInput!.AsReadOnlySpan().ToArray();
                        byte[] unknownPropertyCanonical = CanonicalizeById(table, "unknown1", pool, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10);

                        bool isSubsequence = Contains(actual, unknownPropertyCanonical);
                        Assert.IsTrue(isSubsequence, "The unknown preceding property's own canonicalized octets must appear verbatim in the imprint input -- unmodeled content must be COVERED, never skipped.");

                        //A stronger, content-level proof: the smuggled text itself must reach the imprint input.
                        bool isTextPresent = Contains(actual, Encoding.UTF8.GetBytes("smuggled-content-must-be-covered"));
                        Assert.IsTrue(isTextPresent, "The smuggled text content must reach the imprint input.");
                    }
                }
            }
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
}
