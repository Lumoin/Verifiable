using System.Globalization;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESCounterSignatureChain.TryWalk"/> against clause 5.2.7.2 NOTE 2/NOTE 3's own
/// "arbitrarily long chains of explicit countersignatures" of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>, and the hardening bound <see cref="XAdESCounterSignatureChain.MaximumChainNodeCount"/>
/// closes over that unbounded construction.
/// </summary>
[TestClass]
internal sealed class XAdESCounterSignatureChainTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";


    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Builds a LINEAR chain of <paramref name="depth"/> nested <c>CounterSignature</c> occurrences: the outer
    /// signature's own <c>UnsignedSignatureProperties</c> carries one <c>CounterSignature</c>, whose embedded
    /// signature carries its OWN <c>UnsignedSignatureProperties/CounterSignature</c>, and so on — exactly the
    /// construction clause 5.2.7.2 NOTE 3 describes ("each one signing the ds:SignatureValue element of the one
    /// where it is directly embedded"), though this fixture does not itself populate genuine self-reference
    /// digests — <see cref="XAdESCounterSignatureChain.TryWalk"/> is a structural existence/count walk only.
    /// </summary>
    private static string BuildLinearChain(int depth)
    {
        string Signature(int remaining, string id)
        {
            string inner = remaining <= 0
                ? string.Empty
                : $"""
                    <ds:Object>
                      <QualifyingProperties xmlns="{V132}" Target="#{id}">
                        <UnsignedProperties>
                          <UnsignedSignatureProperties>
                            <CounterSignature>{Signature(remaining - 1, $"{id}n")}</CounterSignature>
                          </UnsignedSignatureProperties>
                        </UnsignedProperties>
                      </QualifyingProperties>
                    </ds:Object>
                    """;

            return $"""
                <ds:Signature xmlns:ds="{DsNamespace}" Id="{id}">
                  <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                    <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                    <ds:Reference URI="#{id}data">
                      <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                      <ds:DigestValue>AQ==</ds:DigestValue>
                    </ds:Reference>
                  </ds:SignedInfo>
                  <ds:SignatureValue>AQ==</ds:SignatureValue>
                  <ds:Object Id="{id}data">payload</ds:Object>
                  {inner}
                </ds:Signature>
                """;
        }

        return Signature(depth, "root");
    }


    private static XmlSignature ReadRootSignature(XmlNodeTable table)
    {
        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table);
        Assert.IsGreaterThanOrEqualTo(1, signatureIndices.Length, "At least the root signature must be found.");
        bool isRead = XmlSignature.TryRead(table, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"The root signature must read but was refused with {error.Failure}.");

        return signature!;
    }


    /// <summary>
    /// Proves a signature with no <c>CounterSignature</c> at all walks trivially: zero visited, no refusal.
    /// Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2.
    /// </summary>
    [TestMethod]
    public void SignatureWithNoCounterSignatureWalksToZero()
    {
        using XmlNodeTable table = Parse(BuildLinearChain(0), BaseMemoryPool.Shared);
        using XmlSignature root = ReadRootSignature(table);
        bool isWalked = XAdESCounterSignatureChain.TryWalk(table, root, BaseMemoryPool.Shared, out int visitedCount, out XAdESProcessingError error);
        Assert.IsTrue(isWalked, $"Must walk but was refused with {error.Failure}.");
        Assert.AreEqual(0, visitedCount);
    }


    /// <summary>
    /// Proves a chain within the bound walks successfully and reports the exact node count visited — clause
    /// 5.2.7.2 NOTE 2/NOTE 3's own "arbitrarily long chains" construction, well inside
    /// <see cref="XAdESCounterSignatureChain.MaximumChainNodeCount"/>. Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2.
    /// </summary>
    [TestMethod]
    public void ChainWithinBoundWalksToExactCount()
    {
        const int Depth = 5;
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(BuildLinearChain(Depth), metered.Pool);
            using XmlSignature root = ReadRootSignature(table);
            bool isWalked = XAdESCounterSignatureChain.TryWalk(table, root, metered.Pool, out int visitedCount, out XAdESProcessingError error);
            Assert.IsTrue(isWalked, $"Must walk but was refused with {error.Failure}.");
            Assert.AreEqual(Depth, visitedCount);
        }
    }


    /// <summary>
    /// Proves the hardening bound <see cref="XAdESCounterSignatureChain.MaximumChainNodeCount"/> engages fail-closed: a chain one hop deeper than
    /// the bound refuses with <see cref="XAdESProcessingFailure.CounterSignatureChainLimitExceeded"/> rather than exhausting the call stack or
    /// running unbounded work, per the countersignature-chain depth/count bound over clause 5.2.7.2 NOTE 2/NOTE 3's unbounded "arbitrarily long
    /// chains" construction of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN
    /// 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void ChainExceedingBoundIsRefused()
    {
        int depth = XAdESCounterSignatureChain.MaximumChainNodeCount + 1;
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(BuildLinearChain(depth), metered.Pool);
            using XmlSignature root = ReadRootSignature(table);
            bool isWalked = XAdESCounterSignatureChain.TryWalk(table, root, metered.Pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isWalked, "A chain deeper than the bound must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.CounterSignatureChainLimitExceeded, error.Failure);
        }
    }


    /// <summary>
    /// Proves the cost side, counted: a hostile chain many times deeper than the bound refuses with the walk's OWN work bounded by <see
    /// cref="XAdESCounterSignatureChain.MaximumChainNodeCount"/> rather than by the attacker's chosen depth. The walk opens exactly <c>MaximumChainNodeCount</c>
    /// nested <c>ds:Signature</c> occurrences (<see cref="XAdESCounterSignature.TryRead"/>) before refusing the next one; each occurrence decodes exactly two
    /// base64 fields — its one <c>Reference</c>'s <c>DigestValue</c> and its own <c>SignatureValue</c>, both <c>"AQ=="</c> — and each such decode costs exactly
    /// three pool rents (<see cref="XmlBase64Content.TryDecode"/>'s two <c>PooledStructList</c> scratch buffers plus <see cref="PooledMemory.FromBytes"/>'s own
    /// copy), for <c>MaximumChainNodeCount &#215; 6</c> rents attributable to the walk. Measured as the delta across the call, so parsing the 150-hop fixture —
    /// which the walk itself never touches — cannot dilute the signal the way a wall-clock ceiling would when parsing dominates the measured time. Every rented
    /// buffer is returned once every disposable in the fixture is disposed. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2.
    /// </summary>
    [TestMethod]
    public void DeepHostileChainRefusesAfterOpeningExactlyMaximumChainNodeCountSignatures()
    {
        //Far beyond the bound: the underlying XmlSpanReader.MaximumElementDepth (1024) already caps how deep
        //raw XML nesting can go, so this uses the deepest chain that still parses (each hop costs several
        //XML element levels) to prove the walk's OWN cost stays bounded well before that outer limit matters.
        const int Depth = 150;
        const long RentsPerOpenedCounterSignature = 6L;
        using var metered = new MeteredHousePool();
        long rentedBeforeWalk;
        long rentedAfterWalk;
        using(XmlNodeTable table = Parse(BuildLinearChain(Depth), metered.Pool))
        {
            using XmlSignature root = ReadRootSignature(table);
            rentedBeforeWalk = metered.RentedCount;
            bool isWalked = XAdESCounterSignatureChain.TryWalk(table, root, metered.Pool, out _, out XAdESProcessingError error);

            Assert.IsFalse(isWalked, "A hostile chain far beyond the bound must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.CounterSignatureChainLimitExceeded, error.Failure);
            rentedAfterWalk = metered.RentedCount;
        }

        Assert.AreEqual(
            XAdESCounterSignatureChain.MaximumChainNodeCount * RentsPerOpenedCounterSignature, rentedAfterWalk - rentedBeforeWalk,
            "The walk opens exactly MaximumChainNodeCount nested signatures before refusing the next one; the unbounded shape this bound fixes would open all 150.");
        Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer is returned once every disposable in the fixture is disposed.");
    }
}
