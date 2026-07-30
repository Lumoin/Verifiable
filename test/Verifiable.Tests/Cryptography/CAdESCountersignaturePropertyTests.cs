using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;
using CsCheck;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Scenario = Verifiable.Tests.Cryptography.CAdESCountersignatureTests.CountersignatureScenario;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Property-based tests (CsCheck) for the two directions of NOTE 6 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.5.3</see>: adding a countersignature beside one an
/// <c>archive-time-stamp-v3</c> protects leaves that archive time-stamp valid, while adding an unsigned attribute
/// <em>inside</em> the protected countersignature breaks it. The clause states both in one sentence, and the two
/// outcomes are opposite, so each is worth holding over a range of inputs rather than one.
/// </summary>
/// <remarks>
/// <para>
/// The world — the signer, the counter signer, the countersigned CAdES-B-B signature and the archive time-stamp
/// over it — is minted once through the shipped surfaces and reused across every sample; what varies is how many
/// sibling countersignatures are appended and how (one splice or one per attribute) in the first property, and
/// what unsigned attribute of what size is placed inside the protected countersignature in the second. The
/// coverage is always stated by the shipped component both directions of this wave compute the clause 5.5.2 index
/// and the clause 5.5.3 imprint input with.
/// </para>
/// <para>
/// CsCheck's <c>Sample</c> callback is synchronous; the asynchronous calls inside it are blocked on with
/// <c>AsTask().GetAwaiter().GetResult()</c>, the idiom <see cref="ArchiveTimestampV3PropertyTests"/> already uses.
/// A failing sample is a defect, not noise: CsCheck shrinks it and prints the seed that reproduces it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CAdESCountersignaturePropertyTests
{
    /// <summary>
    /// The attribute types the inner-attribute samples draw from: all four are legitimately unsigned attributes,
    /// which the first draft of the sibling test learned matters — the independent CMS reader rejects an attribute
    /// like <c>signing-time</c> that RFC 5652 §11.3 requires to be signed.
    /// </summary>
    private static string[] InnerAttributeTypes { get; } =
    [
        CAdESSignatureFacts.CertificateValuesAttributeOid,
        CAdESSignatureFacts.RevocationValuesAttributeOid,
        CAdESSignatureFacts.EscTimestampAttributeOid,
        CAdESSignatureFacts.CertificateAndCrlTimestampAttributeOid
    ];


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// However many countersignatures are added beside one an <c>archive-time-stamp-v3</c> already protects, and
    /// whether they arrive in one splice or one at a time, the archive time-stamp stays valid and its message
    /// imprint still verifies against the recomputed clause 5.5.3 input — clause 5.5.2's membership check running
    /// from the index toward the material, never the other way.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until each call fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    public async Task SiblingCountersignaturesNeverInvalidateAnEarlierArchiveTimestamp()
    {
        using Scenario scenario = Scenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData countersigned = await scenario.CountersignAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData archived = await scenario.AddArchiveTimestampAsync(
            countersigned, scenario.SignerCertificate, TestContext.CancellationToken).ConfigureAwait(false);

        //Three further countersignatures of the same countersigned signer, minted once: each signing draws its own
        //randomness, so the three attribute values are distinct however many a sample appends.
        var siblings = new List<CmsAttribute>(3);
        try
        {
            for(int i = 0; i < 3; ++i)
            {
                using PooledMemory countersignature = await scenario.BuildCountersignatureAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);
                siblings.Add(CmsAttribute.Create(
                    CAdESSignatureFacts.CountersignatureAttributeOid, countersignature.AsReadOnlySpan(), BaseMemoryPool.Shared));
            }

            (from siblingCount in Gen.Int[1, 3]
             from oneAtATime in Gen.Bool
             select (siblingCount, oneAtATime))
            .Sample(sample => TheArchiveTimestampSurvivesTheSiblings(
                archived, siblings, sample.siblingCount, sample.oneAtATime, TestContext.CancellationToken));
        }
        finally
        {
            foreach(CmsAttribute sibling in siblings)
            {
                sibling.Dispose();
            }
        }
    }


    /// <summary>
    /// Whatever unsigned attribute of whatever size is placed inside a countersignature an
    /// <c>archive-time-stamp-v3</c> protects, that archive time-stamp becomes invalid: the attribute value's octets
    /// change, so the index entry naming the original matches no current material and clause 5.5.2's validity
    /// condition fails. The countersignature's own signed attributes and signature value are identical across every
    /// sample, so nothing but the inner unsigned attribute can be the cause.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until each call fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    public async Task AnyUnsignedAttributeAddedInsideAProtectedCountersignatureInvalidatesTheArchiveTimestamp()
    {
        using Scenario scenario = Scenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareCountersignatureAsync(
            baseline, countersignedSignerIndex: 0, scenario.CountersignerCertificate, PkiDigestAlgorithm.Sha256,
            TestClock.CanonicalEpoch.AddMinutes(30), algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        (IMemoryOwner<byte> signatureBuffer, int signatureLength) = await scenario.SignPreparationAsync(
            preparation, TestContext.CancellationToken).ConfigureAwait(false);

        using(signatureBuffer)
        {
            ReadOnlyMemory<byte> signatureValue = signatureBuffer.Memory[..signatureLength];
            using PooledMemory original = CAdESSignatureCreation.CompleteCountersignature(
                preparation, scenario.CountersignerCertificate, CryptoAlgorithm.P256, signatureValue, unsignedAttributes: null, BaseMemoryPool.Shared);
            using CmsAttribute originalAttribute = CmsAttribute.Create(
                CAdESSignatureFacts.CountersignatureAttributeOid, original.AsReadOnlySpan(), BaseMemoryPool.Shared);
            using CmsSignedData countersigned = CmsSignedDataAugmentation.AppendUnsignedAttributes(
                baseline, signerIndex: 0, [originalAttribute], BaseMemoryPool.Shared);
            using CmsSignedData archived = await scenario.AddArchiveTimestampAsync(
                countersigned, scenario.SignerCertificate, TestContext.CancellationToken).ConfigureAwait(false);

            using ArchiveTimestampCoverage before = await CAdESCountersignatureTests.StateArchiveCoverageAsync(
                archived, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, before.Status, "The world every sample mutates starts from a valid archive time-stamp.");
            Assert.IsTrue(CAdESCountersignatureTests.CountersignatureValuesAreCovered(before), "And from a countersignature the index actually names.");

            (from typeIndex in Gen.Int[0, InnerAttributeTypes.Length - 1]
             from valueLength in Gen.Int[0, 300]
             select (typeIndex, valueLength))
            .Sample(sample => TheArchiveTimestampBreaksOnTheInnerAttribute(
                archived, preparation, scenario, signatureValue, sample.typeIndex, sample.valueLength, TestContext.CancellationToken));
        }
    }


    /// <summary>
    /// Runs one sample of the sibling property: appends the first <paramref name="siblingCount"/> of the pre-minted
    /// countersignature attributes and decides whether the archive time-stamp is still valid and still verifies.
    /// Every input the sample needs is an explicit parameter, so the check keeps no state.
    /// </summary>
    /// <param name="archived">The archive-time-stamped, already countersigned signature.</param>
    /// <param name="siblings">The pre-minted countersignature attributes to draw from.</param>
    /// <param name="siblingCount">How many of them to append.</param>
    /// <param name="oneAtATime">Whether to append them in separate splices rather than one.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "GetAwaiter().GetResult() blocks until each call fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    private static bool TheArchiveTimestampSurvivesTheSiblings(
        CmsSignedData archived,
        List<CmsAttribute> siblings,
        int siblingCount,
        bool oneAtATime,
        CancellationToken cancellationToken)
    {
        var appended = new List<CmsSignedData>(siblingCount);
        try
        {
            CmsSignedData current = archived;
            if(oneAtATime)
            {
                for(int i = 0; i < siblingCount; ++i)
                {
                    current = CmsSignedDataAugmentation.AppendUnsignedAttributes(current, signerIndex: 0, [siblings[i]], BaseMemoryPool.Shared);
                    appended.Add(current);
                }
            }
            else
            {
                var batch = new List<CmsAttribute>(siblingCount);
                for(int i = 0; i < siblingCount; ++i)
                {
                    batch.Add(siblings[i]);
                }

                current = CmsSignedDataAugmentation.AppendUnsignedAttributes(current, signerIndex: 0, batch, BaseMemoryPool.Shared);
                appended.Add(current);
            }

            using ArchiveTimestampCoverage coverage = CAdESCountersignatureTests.StateArchiveCoverageAsync(current, cancellationToken)
                .AsTask().GetAwaiter().GetResult();
            if(coverage.Status != ArchiveTimestampCoverageStatus.Stated || !coverage.ProtectedObjects!.EveryIndexEntryMatched)
            {
                return false;
            }

            //The earlier countersignature keeps its coverage and the later ones are simply uncovered, which is
            //NOTE 5's design rather than an error.
            int covered = 0;
            int uncovered = 0;
            foreach(CoveredAttributeValue value in coverage.ProtectedObjects!.UnsignedAttributeValues)
            {
                if(!string.Equals(value.AttributeType, CAdESSignatureFacts.CountersignatureAttributeOid, StringComparison.Ordinal))
                {
                    continue;
                }

                if(value.IsCovered)
                {
                    ++covered;
                }
                else
                {
                    ++uncovered;
                }
            }

            if(covered != 1 || uncovered != siblingCount)
            {
                return false;
            }

            return CAdESCountersignatureTests.ArchiveTimestampImprintStillVerifiesAsync(current, coverage, cancellationToken)
                .AsTask().GetAwaiter().GetResult();
        }
        finally
        {
            foreach(CmsSignedData signature in appended)
            {
                signature.Dispose();
            }
        }
    }


    /// <summary>
    /// Runs one sample of the mutation property: rebuilds the countersignature with one unsigned attribute inside
    /// it, replaces the protected attribute value with it, and decides whether the archive time-stamp's index is
    /// reported invalid.
    /// </summary>
    /// <param name="archived">The archive-time-stamped, already countersigned signature.</param>
    /// <param name="preparation">The countersignature's prepared signed attributes, identical for every sample.</param>
    /// <param name="scenario">The world, for the counter signer's certificate.</param>
    /// <param name="signatureValue">The countersignature's signature value, identical for every sample.</param>
    /// <param name="typeIndex">Which of <see cref="InnerAttributeTypes"/> the inner attribute is.</param>
    /// <param name="valueLength">The size of the inner attribute's value.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "GetAwaiter().GetResult() blocks until each call fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    private static bool TheArchiveTimestampBreaksOnTheInnerAttribute(
        CmsSignedData archived,
        CAdESSignaturePreparation preparation,
        Scenario scenario,
        ReadOnlyMemory<byte> signatureValue,
        int typeIndex,
        int valueLength,
        CancellationToken cancellationToken)
    {
        using CmsAttribute innerAttribute = CmsAttribute.Create(
            InnerAttributeTypes[typeIndex], WriteOctetString(valueLength), BaseMemoryPool.Shared);
        using PooledMemory mutated = CAdESSignatureCreation.CompleteCountersignature(
            preparation, scenario.CountersignerCertificate, CryptoAlgorithm.P256, signatureValue, [innerAttribute], BaseMemoryPool.Shared);
        using CmsSignedData tampered = CAdESCountersignatureTests.ReplaceCountersignatureValue(archived, mutated.AsReadOnlySpan());
        using ArchiveTimestampCoverage coverage = CAdESCountersignatureTests.StateArchiveCoverageAsync(tampered, cancellationToken)
            .AsTask().GetAwaiter().GetResult();

        return coverage.Status == ArchiveTimestampCoverageStatus.HashIndexInvalid
            && !coverage.ProtectedObjects!.EveryIndexEntryMatched
            && coverage.MessageImprintInput is null;
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
