using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using CsCheck;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Property-based tests (CsCheck) for the preservation rule of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.5.3</see>: "The augmentation shall preserve the binary encoding of already
/// present unsigned attributes and any component contributing to the archive time-stamp's message imprint
/// computation input." The property states it as an octet-level invariant — appending unsigned attributes to a
/// real signature changes nothing except the length octets of the containers that enclose the insertion point —
/// and holds it over signatures with and without existing unsigned attributes, with one signer and with two,
/// for attribute counts and value sizes that make the enclosing containers' length octets grow.
/// </summary>
/// <remarks>
/// <para>
/// Three signatures are minted once by the framework's own CMS signer and reused across every sample: what
/// varies is which signature is augmented, which signer of it, how many attributes are appended, and how large
/// their values are. Each sample is judged by two readers that share no code with the operation under test —
/// <see cref="CmsStructureOracle"/> for the octet-level invariant, and the platform's own CMS reader, which
/// decodes the result and rechecks the signature.
/// </para>
/// <para>
/// A failing sample is a defect, not noise: CsCheck shrinks it and prints the seed that reproduces it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CmsSignedDataAugmentationPropertyTests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The signing time the minted signatures carry.</summary>
    private static DateTimeOffset SigningTime { get; } = new(2025, 3, 14, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The time-stamp time the minted CAdES-B-T signature carries.</summary>
    private static DateTimeOffset TimestampTime { get; } = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The attribute types the appended attributes carry, drawn from the CAdES unsigned attributes so the
    /// samples are shaped like real augmentation material rather than arbitrary object identifiers.
    /// </summary>
    private static string[] AppendedAttributeTypes { get; } =
    [
        CAdESSignatureFacts.CertificateValuesAttributeOid,
        CAdESSignatureFacts.RevocationValuesAttributeOid,
        CAdESSignatureFacts.ArchiveTimestampV3AttributeOid,
        CAdESSignatureFacts.SignatureTimestampAttributeOid
    ];


    /// <summary>
    /// Appending unsigned attributes preserves every octet of the input except the length octets of the
    /// containers enclosing the insertion point, leaves the signature verifiable under the platform's own CMS
    /// reader, and adds exactly the attributes that were supplied.
    /// </summary>
    [TestMethod]
    public void AppendingUnsignedAttributesPreservesEveryOctetOutsideTheLengthChain()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using ECDsa secondSignerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var secondSignerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(secondSignerKey, NotBefore, NotAfter);

        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdES("the property content"u8, signerCertificate, SigningTime);
        using CmsSignedData timestamped = CmsSignedDataTestFactory.SignAsCAdEST("the property content"u8, signerCertificate, SigningTime, timestampCertificate, TimestampTime);
        using CmsSignedData twoSigners = CmsSignedDataTestFactory.SignAsCmsWithTwoSigners("the property content"u8, signerCertificate, secondSignerCertificate);

        CmsSignedData[] worlds = [baseline, timestamped, twoSigners];
        int[] signerCounts = [1, 1, 2];

        (from worldIndex in Gen.Int[0, 2]
         from signerSelector in Gen.Int[0, 1]
         from attributeCount in Gen.Int[1, 4]
         from valueLength in Gen.Int[0, 300]
         select (worldIndex, signerSelector, attributeCount, valueLength))
        .Sample(sample => AugmentationPreservesTheInput(
            worlds[sample.worldIndex],
            sample.signerSelector % signerCounts[sample.worldIndex],
            sample.attributeCount,
            sample.valueLength));
    }


    /// <summary>
    /// Runs one sample: appends the attributes, then decides whether the octet-level invariant held, the
    /// attribute count grew by exactly what was appended, and the platform's own reader still accepts the
    /// signature. Every input the sample needs is an explicit parameter, so the check keeps no state.
    /// </summary>
    /// <param name="original">The signature to augment.</param>
    /// <param name="signerIndex">The zero-based index of the signer to augment.</param>
    /// <param name="attributeCount">The number of attributes to append.</param>
    /// <param name="valueLength">The base size of each appended attribute's value.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    private static bool AugmentationPreservesTheInput(CmsSignedData original, int signerIndex, int attributeCount, int valueLength)
    {
        byte[] originalOctets = original.AsReadOnlySpan().ToArray();
        int originalAttributeCount = CmsStructureOracle.UnsignedAttributes(originalOctets, signerIndex).Count;

        var attributes = new List<CmsAttribute>(attributeCount);
        try
        {
            for(int i = 0; i < attributeCount; ++i)
            {
                attributes.Add(CmsAttribute.Create(AppendedAttributeTypes[i], WriteOctetString(valueLength + i), BaseMemoryPool.Shared));
            }

            using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex, attributes, BaseMemoryPool.Shared);
            byte[] augmentedOctets = augmented.AsReadOnlySpan().ToArray();

            if(!CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(originalOctets, augmentedOctets, signerIndex))
            {
                return false;
            }

            if(CmsStructureOracle.UnsignedAttributes(augmentedOctets, signerIndex).Count != originalAttributeCount + attributeCount)
            {
                return false;
            }

            var decoded = new SignedCms();
            decoded.Decode(augmentedOctets);
            decoded.SignerInfos[signerIndex].CheckSignature(verifySignatureOnly: true);

            return true;
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
