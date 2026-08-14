using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// A real-wire, whole-chain proof of clause 5.2.7.2's digest rule of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the leaf's structural locator (<see cref="XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference"/>) plus its canonicalized- digest-input construction (<see
/// cref="XmlReferenceProcessing.TryComputeDigestInput(XmlNodeTable, XmlSignature, int, XmlReferenceResolver?, BaseMemoryPool, out PooledMemory?, out XmlSignatureProcessingError)"/>) compose with the Pki-side house
/// digest (<see cref="XAdESLevelRules.CheckCounterSignatureDigestAsync"/>) to confirm a genuinely correct countersignature and to DETECT a tampered one — exercising the whole composition-root seam this library's
/// layering rule requires, not merely its structural half.
/// </summary>
[TestClass]
internal sealed class XAdESCounterSignatureDigestEndToEndTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    public TestContext TestContext { get; set; } = null!;


    private static string BuildDocument(string outerSignatureValueText, string selfReferenceDigestBase64) => $"""
        <ds:Signature xmlns:ds="{DsNamespace}" Id="outerSig">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
            <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
            <ds:Reference URI="#outerData">
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue Id="outerSigValue">{outerSignatureValueText}</ds:SignatureValue>
          <ds:Object Id="outerData">payload</ds:Object>
          <ds:Object>
            <CounterSignature xmlns="{V132}">
              <ds:Signature Id="counterSig">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                  <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                  <ds:Reference URI="#outerSigValue">
                    <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                    <ds:DigestValue>{selfReferenceDigestBase64}</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
              </ds:Signature>
            </CounterSignature>
          </ds:Object>
        </ds:Signature>
        """;


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static (XmlSignature Outer, XAdESCounterSignature CounterSignature) ReadFixture(XmlNodeTable table)
    {
        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table);
        Assert.HasCount(2, signatureIndices, "The fixture carries the outer signature and the nested countersignature.");
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

        return (outer, counterSignature!);
    }


    private static async Task<byte[]> ComputeDigestOverCandidateAsync(XmlNodeTable table, XmlSignature outer, XAdESCounterSignature counterSignature, CancellationToken cancellationToken)
    {
        bool isLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(table, outer, counterSignature, out XmlReference reference, out int ordinal, out XAdESProcessingError locateError);
        Assert.IsTrue(isLocated, $"Must locate the self-reference but was refused with {locateError.Failure}.");

        bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, counterSignature.Signature, ordinal, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError digestInputError);
        Assert.IsTrue(isComputed, $"The digest input must compute but was refused with {digestInputError.Failure}.");
        using(digestInput)
        {
            string digestAlgorithmUri = Encoding.UTF8.GetString(reference.DigestMethodAlgorithm);
            PkiDigestAlgorithm? resolvedAlgorithm = XmlSignatureWellKnown.DigestAlgorithmFromUri(digestAlgorithmUri);
            Assert.IsNotNull(resolvedAlgorithm, $"'{digestAlgorithmUri}' must resolve onto this library's digest vocabulary.");

            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                digestInput!.AsReadOnlySpan().ToArray(), 32, resolvedAlgorithm!.Value.DigestTag, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

            return digest.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// Proves the whole chain end to end: a genuinely correct countersignature — whose self-reference
    /// <c>ds:DigestValue</c> is the ACTUAL house-computed SHA-256 digest of the canonicalized outer
    /// <c>ds:SignatureValue</c> element — produces zero violations, and mutating the outer
    /// <c>ds:SignatureValue</c>'s own text content afterward (so its canonical octets change while the stored
    /// digest stays the original, now-stale value) is DETECTED as a
    /// <see cref="XAdESCounterSignatureDigestViolation"/>, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2's digest rule.
    /// </summary>
    [TestMethod]
    public async Task RealDigestComputationConfirmsMatchAndDetectsTampering()
    {
        const string OuterSignatureValueText = "MTIzNDU2Nzg5MA==";

        using XmlNodeTable placeholderTable = Parse(BuildDocument(OuterSignatureValueText, "AAAA"));
        (XmlSignature placeholderOuter, XAdESCounterSignature placeholderCounterSignature) = ReadFixture(placeholderTable);
        byte[] actualDigest;
        using(placeholderOuter)
        using(placeholderCounterSignature)
        {
            actualDigest = await ComputeDigestOverCandidateAsync(placeholderTable, placeholderOuter, placeholderCounterSignature, TestContext.CancellationToken).ConfigureAwait(false);
        }

        string actualDigestBase64 = Convert.ToBase64String(actualDigest);
        using XmlNodeTable correctTable = Parse(BuildDocument(OuterSignatureValueText, actualDigestBase64));
        (XmlSignature correctOuter, XAdESCounterSignature correctCounterSignature) = ReadFixture(correctTable);
        using(correctOuter)
        using(correctCounterSignature)
        {
            bool isLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(correctTable, correctOuter, correctCounterSignature, out XmlReference reference, out int ordinal, out XAdESProcessingError locateError);
            Assert.IsTrue(isLocated, $"Must locate but was refused with {locateError.Failure}.");

            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(correctTable, correctCounterSignature.Signature, ordinal, resolver: null, BaseMemoryPool.Shared, out PooledMemory? candidateOctets, out XmlSignatureProcessingError candidateError);
            Assert.IsTrue(isComputed, $"Must compute but was refused with {candidateError.Failure}.");
            using(candidateOctets)
            {
                IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(reference.DigestValueOctets.Length);
                reference.DigestValueOctets.AsReadOnlySpan().CopyTo(expectedOwner.Memory.Span);
                using var expectedDigest = new DigestValue(expectedOwner, CryptoTags.Sha256Digest);

                IReadOnlyList<XAdESRuleViolation> matched = await XAdESLevelRules.CheckCounterSignatureDigestAsync(
                    AlgorithmIdentifier.Sha256, expectedDigest, candidateOctets!.AsReadOnlySpan().ToArray(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsEmpty(matched, "A genuinely correct countersignature digest must produce zero violations.");

                //Tamper: a DIFFERENT outer ds:SignatureValue text changes the canonical octets the reference
                //covers while the stored digest (computed over the ORIGINAL text) stays unchanged -- the
                //classic substitution attack clause 5.2.7.2's digest rule exists to catch.
                using XmlNodeTable tamperedTable = Parse(BuildDocument("MDk4NzY1NDMyMQ==", actualDigestBase64));
                (XmlSignature tamperedOuter, XAdESCounterSignature tamperedCounterSignature) = ReadFixture(tamperedTable);
                using(tamperedOuter)
                using(tamperedCounterSignature)
                {
                    bool isTamperedLocated = XAdESCounterSignatureDigestRule.TryLocateSignatureValueReference(tamperedTable, tamperedOuter, tamperedCounterSignature, out _, out int tamperedOrdinal, out XAdESProcessingError tamperedLocateError);
                    Assert.IsTrue(isTamperedLocated, $"Must locate but was refused with {tamperedLocateError.Failure}.");

                    bool isTamperedComputed = XmlReferenceProcessing.TryComputeDigestInput(tamperedTable, tamperedCounterSignature.Signature, tamperedOrdinal, resolver: null, BaseMemoryPool.Shared, out PooledMemory? tamperedCandidateOctets, out XmlSignatureProcessingError tamperedComputeError);
                    Assert.IsTrue(isTamperedComputed, $"Must compute but was refused with {tamperedComputeError.Failure}.");
                    using(tamperedCandidateOctets)
                    {
                        IReadOnlyList<XAdESRuleViolation> mismatched = await XAdESLevelRules.CheckCounterSignatureDigestAsync(
                            AlgorithmIdentifier.Sha256, expectedDigest, tamperedCandidateOctets!.AsReadOnlySpan().ToArray(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
                        Assert.ContainsSingle(v => v is XAdESCounterSignatureDigestViolation, mismatched);
                    }
                }
            }
        }
    }
}
