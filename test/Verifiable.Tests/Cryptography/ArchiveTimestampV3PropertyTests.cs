using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading.Tasks;
using CsCheck;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Property-based tests (CsCheck) for the archive time-stamp message imprint input of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.5.3</see>: that building it is a function of its four stated parts and of
/// nothing else, and that appending unsigned attributes — which is what every later augmentation does — leaves
/// it identical, which is why an archive time-stamp survives augmentation at all.
/// </summary>
/// <remarks>
/// <para>
/// The signature and the index are minted once and reused across every sample; what varies is how many
/// attributes are appended and how large their values are, chosen wide enough that the enclosing containers'
/// length octets grow. A failing sample is a defect, not noise: CsCheck shrinks it and prints the seed that
/// reproduces it.
/// </para>
/// <para>
/// CsCheck's <c>Sample</c> callback is synchronous; the asynchronous calls inside it are blocked on with
/// <c>AsTask().GetAwaiter().GetResult()</c>, the idiom this suite already uses in
/// <see cref="SignatureValidationDeterminismPropertyTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ArchiveTimestampV3PropertyTests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time the minted signatures carry.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The generation time the minted signature time-stamp carries.</summary>
    private static DateTimeOffset SignatureTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The attribute types the appended attributes carry, drawn from the CAdES unsigned attributes.</summary>
    private static string[] AppendedAttributeTypes { get; } =
    [
        CAdESSignatureFacts.CertificateValuesAttributeOid,
        CAdESSignatureFacts.RevocationValuesAttributeOid,
        CAdESSignatureFacts.EscTimestampAttributeOid,
        CAdESSignatureFacts.CertificateAndCrlTimestampAttributeOid
    ];


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Building the message imprint input from the same signature and the same index yields the same octets
    /// every time, and those octets are the ones the independent oracle assembles from the clause text.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until the build fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    public async Task TheMessageImprintInputIsTheSameOnEveryBuildFromTheSameInputs()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData signature = CmsSignedDataTestFactory.SignAsCAdEST(
            "the archive time-stamp property content"u8, signerCertificate, SigningTime, timestampCertificate, SignatureTimestampTime);
        using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            signature, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] octets = signature.AsReadOnlySpan().ToArray();
        using SignedContentMemory oracleInput = AtsHashIndexV3Oracle.BuildMessageImprintInput(
            octets, signerIndex: 0, hashIndex.AsReadOnlySpan(), PkiDigestAlgorithm.Sha256);
        byte[] expected = oracleInput.AsReadOnlySpan().ToArray();

        Gen.Int[2, 6].Sample(repeatCount =>
        {
            for(int i = 0; i < repeatCount; ++i)
            {
                using SignedContentMemory built = ArchiveTimestampV3.BuildMessageImprintInputAsync(
                    new ArchiveTimestampImprintContext
                    {
                        SignedData = signature,
                        HashIndex = hashIndex,
                        MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256
                    },
                    BaseMemoryPool.Shared,
                    TestContext.CancellationToken).AsTask().GetAwaiter().GetResult();

                if(!built.AsReadOnlySpan().SequenceEqual(expected))
                {
                    return false;
                }
            }

            return true;
        });
    }


    /// <summary>
    /// Appending unsigned attributes to a signature leaves the message imprint input of an archive time-stamp
    /// already computed over it identical, whatever is appended and however large it is. This is the property
    /// that makes clause 5.5.3's design work: the imprint input names the <c>SignerInfo</c> fields other than
    /// <c>unsignedAttrs</c>, so the unsigned attributes are reached only through the index of step 4), and an
    /// augmentation that adds new ones cannot disturb an earlier archive time-stamp.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until the build fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    public async Task AppendingUnsignedAttributesLeavesTheMessageImprintInputUnchanged()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData signature = CmsSignedDataTestFactory.SignAsCAdEST(
            "the archive time-stamp property content"u8, signerCertificate, SigningTime, timestampCertificate, SignatureTimestampTime);
        using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            signature, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using SignedContentMemory before = await ArchiveTimestampV3.BuildMessageImprintInputAsync(
            new ArchiveTimestampImprintContext { SignedData = signature, HashIndex = hashIndex, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256 },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        byte[] expected = before.AsReadOnlySpan().ToArray();

        (from attributeCount in Gen.Int[1, 4]
         from valueLength in Gen.Int[0, 300]
         select (attributeCount, valueLength))
        .Sample(sample => TheImprintInputSurvivesTheAugmentation(signature, hashIndex, sample.attributeCount, sample.valueLength, expected, TestContext.CancellationToken));
    }


    /// <summary>
    /// Runs one sample: appends the attributes, rebuilds the imprint input over the augmented signature with the
    /// same index, and decides whether it is octet for octet what it was. Every input the sample needs is an
    /// explicit parameter, so the check keeps no state.
    /// </summary>
    /// <param name="signature">The signature to augment.</param>
    /// <param name="hashIndex">The index the imprint input is built with.</param>
    /// <param name="attributeCount">The number of attributes to append.</param>
    /// <param name="valueLength">The base size of each appended attribute's value.</param>
    /// <param name="expected">The imprint input built before the augmentation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "GetAwaiter().GetResult() blocks until the build fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    private static bool TheImprintInputSurvivesTheAugmentation(
        CmsSignedData signature,
        AtsHashIndexV3 hashIndex,
        int attributeCount,
        int valueLength,
        byte[] expected,
        System.Threading.CancellationToken cancellationToken)
    {
        var attributes = new List<CmsAttribute>(attributeCount);
        try
        {
            for(int i = 0; i < attributeCount; ++i)
            {
                attributes.Add(CmsAttribute.Create(AppendedAttributeTypes[i], WriteOctetString(valueLength + i), BaseMemoryPool.Shared));
            }

            using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(signature, signerIndex: 0, attributes, BaseMemoryPool.Shared);
            using SignedContentMemory rebuilt = ArchiveTimestampV3.BuildMessageImprintInputAsync(
                new ArchiveTimestampImprintContext { SignedData = augmented, HashIndex = hashIndex, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256 },
                BaseMemoryPool.Shared,
                cancellationToken).AsTask().GetAwaiter().GetResult();

            return rebuilt.AsReadOnlySpan().SequenceEqual(expected);
        }
        finally
        {
            foreach(CmsAttribute attribute in attributes)
            {
                attribute.Dispose();
            }
        }
    }


    /// <summary>
    /// Writes a DER OCTET STRING value of the given content size, filled with a size-derived pattern so the
    /// sample's material is deterministic and distinguishable without drawing any entropy.
    /// </summary>
    /// <param name="contentLength">The number of octets the string carries.</param>
    /// <returns>The encoded value.</returns>
    private static byte[] WriteOctetString(int contentLength)
    {
        var content = new byte[contentLength];
        for(int i = 0; i < content.Length; ++i)
        {
            content[i] = (byte)(contentLength + i);
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(content);

        return writer.Encode();
    }
}
