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
/// Property-based tests (CsCheck) for the reconstruction rule of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">IETF RFC 4998 Appendix A</see>: "The length of
/// fields containing tags has to be adapted. Apart from that, the existing coding must not be modified." The
/// properties state it at the octet level over structures the framework's own CMS signer produced — every region
/// the removal did not address comes through untouched, an appended attribute removed again leaves the structure
/// it was, and the splice agrees octet for octet with an independent rebuild that shares no code with it.
/// </summary>
/// <remarks>
/// <para>
/// Three signatures are minted once and reused across every sample; what varies is which signature is reduced,
/// which signer of it, how many attributes are appended first, how large their values are, and which of them are
/// then removed. The sizes reach past the short-form and one-octet length boundaries in both directions, so the
/// enclosing containers' length octets grow on the way out and shrink on the way back in.
/// </para>
/// <para>
/// A failing sample is a defect, not noise: CsCheck shrinks it and prints the seed that reproduces it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CmsSignedDataReductionPropertyTests
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
    /// samples are shaped like real material rather than arbitrary object identifiers.
    /// </summary>
    private static string[] AppendedAttributeTypes { get; } =
    [
        CAdESSignatureFacts.CertificateValuesAttributeOid,
        CAdESSignatureFacts.RevocationValuesAttributeOid,
        CAdESSignatureFacts.ArchiveTimestampV3AttributeOid,
        CAdESSignatureFacts.SignatureTimestampAttributeOid
    ];


    /// <summary>
    /// Removing exactly the attributes that were appended restores the structure that stood before them, octet
    /// for octet — the statement that the removal is the inverse of the append and therefore reconstructs a
    /// coding rather than producing a new one.
    /// </summary>
    [TestMethod]
    public void RemovingWhatWasAppendedRestoresTheOriginalOctets()
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
         from valueLength in Gen.Int[0, 400]
         select (worldIndex, signerSelector, attributeCount, valueLength))
        .Sample(sample => AppendingThenRemovingIsIdentity(
            worlds[sample.worldIndex],
            sample.signerSelector % signerCounts[sample.worldIndex],
            sample.attributeCount,
            sample.valueLength));
    }


    /// <summary>
    /// Removing an arbitrary subset of the attributes a signer carries leaves every octet the removal did not
    /// address untouched: every surviving attribute is found in the result with the octets it had, the splice
    /// agrees with the independent rebuild, and the platform's own reader still accepts the signature.
    /// </summary>
    [TestMethod]
    public void RemovingASubsetLeavesEveryUntouchedRegionIdentical()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);

        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdES("the property content"u8, signerCertificate, SigningTime);
        using CmsSignedData timestamped = CmsSignedDataTestFactory.SignAsCAdEST("the property content"u8, signerCertificate, SigningTime, timestampCertificate, TimestampTime);

        CmsSignedData[] worlds = [baseline, timestamped];

        (from worldIndex in Gen.Int[0, 1]
         from attributeCount in Gen.Int[1, 4]
         from valueLength in Gen.Int[0, 400]
         from removalMask in Gen.Int[1, 15]
         select (worldIndex, attributeCount, valueLength, removalMask))
        .Sample(sample => RemovingASubsetPreservesTheRest(
            worlds[sample.worldIndex],
            sample.attributeCount,
            sample.valueLength,
            sample.removalMask));
    }


    /// <summary>
    /// Runs one sample of the inverse property: appends the attributes, removes exactly them again, and decides
    /// whether the result is the input's own octets. Every input the sample needs is an explicit parameter, so
    /// the check keeps no state.
    /// </summary>
    /// <param name="original">The signature to augment and then reduce.</param>
    /// <param name="signerIndex">The zero-based index of the signer to work on.</param>
    /// <param name="attributeCount">The number of attributes to append.</param>
    /// <param name="valueLength">The base size of each appended attribute's value.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    private static bool AppendingThenRemovingIsIdentity(CmsSignedData original, int signerIndex, int attributeCount, int valueLength)
    {
        byte[] originalOctets = original.AsReadOnlySpan().ToArray();
        int originalValueCount = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(original, signerIndex).Count;

        var attributes = new List<CmsAttribute>(attributeCount);
        try
        {
            for(int i = 0; i < attributeCount; ++i)
            {
                attributes.Add(CmsAttribute.Create(AppendedAttributeTypes[i], WriteOctetString(valueLength + i), BaseMemoryPool.Shared));
            }

            using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex, attributes, BaseMemoryPool.Shared);
            IReadOnlyList<CmsUnsignedAttributeValueLocation> locations = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(augmented, signerIndex);
            var appended = new List<CmsUnsignedAttributeValueLocation>(attributeCount);
            for(int i = originalValueCount; i < locations.Count; ++i)
            {
                appended.Add(locations[i]);
            }

            using CmsSignedData reduced = CmsSignedDataReduction.RemoveUnsignedAttributeValues(augmented, signerIndex, appended, BaseMemoryPool.Shared);

            return reduced.AsReadOnlySpan().SequenceEqual(originalOctets);
        }
        finally
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                attributes[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Runs one sample of the untouched-region property: appends the attributes, removes the subset the mask
    /// names, and decides whether every surviving attribute came through verbatim, the independent rebuild
    /// agrees, and the platform's reader still accepts the signature.
    /// </summary>
    /// <param name="original">The signature to augment and then reduce.</param>
    /// <param name="attributeCount">The number of attributes to append.</param>
    /// <param name="valueLength">The base size of each appended attribute's value.</param>
    /// <param name="removalMask">A bit per appended attribute, set for the ones removed.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    private static bool RemovingASubsetPreservesTheRest(CmsSignedData original, int attributeCount, int valueLength, int removalMask)
    {
        var attributes = new List<CmsAttribute>(attributeCount);
        try
        {
            for(int i = 0; i < attributeCount; ++i)
            {
                attributes.Add(CmsAttribute.Create(AppendedAttributeTypes[i], WriteOctetString(valueLength + i), BaseMemoryPool.Shared));
            }

            using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, attributes, BaseMemoryPool.Shared);
            byte[] augmentedOctets = augmented.AsReadOnlySpan().ToArray();
            int originalValueCount = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(original, signerIndex: 0).Count;
            IReadOnlyList<CmsUnsignedAttributeValueLocation> locations = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(augmented, signerIndex: 0);

            var removed = new List<CmsUnsignedAttributeValueLocation>();
            var removedOrdinals = new List<int>();
            var survivingOctets = new List<byte[]>();
            for(int i = 0; i < locations.Count; ++i)
            {
                bool isRemoved = i >= originalValueCount && (removalMask & (1 << (i - originalValueCount))) != 0;
                if(isRemoved)
                {
                    removed.Add(locations[i]);
                    removedOrdinals.Add(i);

                    continue;
                }

                survivingOctets.Add(CmsSignedDataAugmentation.ReadUnsignedAttributeValue(augmented, 0, locations[i].AttributeIndex, locations[i].ValueIndex).ToArray());
            }

            if(removed.Count == 0)
            {
                return true;
            }

            using CmsSignedData reduced = CmsSignedDataReduction.RemoveUnsignedAttributeValues(augmented, signerIndex: 0, removed, BaseMemoryPool.Shared);
            byte[] reducedOctets = reduced.AsReadOnlySpan().ToArray();

            if(!reducedOctets.AsSpan().SequenceEqual(CmsStructureOracle.RemoveUnsignedAttributeValues(augmentedOctets, signerIndex: 0, removedOrdinals)))
            {
                return false;
            }

            IReadOnlyList<CmsUnsignedAttributeValueLocation> remaining = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(reduced, signerIndex: 0);
            if(remaining.Count != survivingOctets.Count)
            {
                return false;
            }

            for(int i = 0; i < remaining.Count; ++i)
            {
                if(!CmsSignedDataAugmentation.ReadUnsignedAttributeValue(reduced, 0, remaining[i].AttributeIndex, remaining[i].ValueIndex).Span.SequenceEqual(survivingOctets[i]))
                {
                    return false;
                }
            }

            var reader = new SignedCms();
            reader.Decode(reducedOctets);
            reader.CheckSignature(verifySignatureOnly: true);

            return true;
        }
        finally
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                attributes[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Writes a DER OCTET STRING of the requested content length, the shape an attribute value takes here.
    /// </summary>
    /// <param name="contentLength">The number of content octets.</param>
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
