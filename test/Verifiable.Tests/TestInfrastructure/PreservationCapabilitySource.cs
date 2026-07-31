using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The material the capability layer of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> is exercised over: cryptographic constraints tables, preservation profiles built
/// item by item, hash-only submissions whose values come from the registered digest seam, and evidence-artifact
/// facts carrying a self-description.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The digests are computed, not invented.</strong> A submitted hash value comes from
/// <see cref="CryptographicKeyEvents.ComputeDigestAsync"/> over real octets, so a length check that passes has
/// been shown something a real submitter could have sent. The one builder that produces a value of the wrong
/// length says so in its name and exists for the refusal that check owes.
/// </para>
/// <para>
/// <strong>Every instant is stated.</strong> Constraint rows and profile validity periods are offsets from
/// <see cref="TestClock.CanonicalEpoch"/>, so a run tomorrow reads exactly as a run today and nothing here reads
/// a clock.
/// </para>
/// </remarks>
internal static class PreservationCapabilitySource
{
    /// <summary>The instant every decision of these tests is taken at.</summary>
    internal static DateTimeOffset DecisionInstant { get; } = TestClock.CanonicalEpoch;

    /// <summary>The lead a service of these tests augments ahead of an expiry with — thirty days, stated by the caller as the requirement obliges.</summary>
    internal static TimeSpan LeadTime { get; } = TimeSpan.FromDays(30);

    /// <summary>The identifier the profiles of these tests are named by.</summary>
    internal static string ProfileIdentifier { get; } = "https://preservation.example.test/profile/capability/1";

    /// <summary>Where the profiles of these tests say their preservation evidence policy is to be found.</summary>
    internal static string EvidencePolicyLocation { get; } = "https://preservation.example.test/policy/evidence/1";

    /// <summary>The identifier the profiles of these tests name their preservation service by.</summary>
    internal static string ServiceIdentifier { get; } = "https://preservation.example.test/service";


    /// <summary>Builds a constraints table from algorithm-and-expiry pairs, stating no key-size floor.</summary>
    /// <param name="rows">Each row's algorithm and the instant it is asserted reliable until, or <see langword="null"/> for no asserted expiry.</param>
    /// <returns>The table.</returns>
    internal static CryptographicConstraints Constraints(params (AlgorithmIdentifier Algorithm, DateTimeOffset? TrustedUntil)[] rows)
    {
        ArgumentNullException.ThrowIfNull(rows);

        var entries = new List<AlgorithmReliabilityEntry>(rows.Length);
        for(int i = 0; i < rows.Length; ++i)
        {
            entries.Add(new AlgorithmReliabilityEntry(rows[i].Algorithm, MinimumKeySizeBits: null, rows[i].TrustedUntil));
        }

        return new CryptographicConstraints { Entries = entries };
    }


    /// <summary>Builds a constraints table with one row that states a key-size floor.</summary>
    /// <param name="algorithm">The algorithm the row is about.</param>
    /// <param name="minimumKeySizeBits">The floor the row states.</param>
    /// <param name="trustedUntil">The instant the row asserts reliability until, or <see langword="null"/>.</param>
    /// <returns>The table.</returns>
    internal static CryptographicConstraints ConstraintsWithKeySizeFloor(
        AlgorithmIdentifier algorithm,
        int minimumKeySizeBits,
        DateTimeOffset? trustedUntil) =>
        new() { Entries = [new AlgorithmReliabilityEntry(algorithm, minimumKeySizeBits, trustedUntil)] };


    /// <summary>Builds one algorithm use of a hash function, which takes no key.</summary>
    /// <param name="algorithm">The algorithm the material used.</param>
    /// <param name="materialIdentifier">What used it, in terms a report can present.</param>
    /// <returns>The use.</returns>
    internal static AlgorithmUse HashUse(AlgorithmIdentifier algorithm, string materialIdentifier) =>
        new(algorithm, KeySizeBits: null, materialIdentifier);


    /// <summary>Builds one algorithm use of a signature algorithm, which takes a key.</summary>
    /// <param name="algorithm">The algorithm the material used.</param>
    /// <param name="keySizeBits">The key size the material used it with.</param>
    /// <param name="materialIdentifier">What used it, in terms a report can present.</param>
    /// <returns>The use.</returns>
    internal static AlgorithmUse KeyedUse(AlgorithmIdentifier algorithm, int keySizeBits, string materialIdentifier) =>
        new(algorithm, keySizeBits, materialIdentifier);


    /// <summary>Builds the context one augmentation decision is taken from.</summary>
    /// <param name="constraints">The table.</param>
    /// <param name="uses">The uses being monitored.</param>
    /// <param name="instant">The instant the question is asked at, or <see langword="null"/> for <see cref="DecisionInstant"/>.</param>
    /// <param name="leadTime">The lead the answering service augments with, or <see langword="null"/> for <see cref="LeadTime"/>.</param>
    /// <returns>The context.</returns>
    internal static PreservationAugmentationContext DecisionContext(
        CryptographicConstraints constraints,
        IReadOnlyList<AlgorithmUse> uses,
        DateTimeOffset? instant = null,
        TimeSpan? leadTime = null) =>
        new()
        {
            Constraints = constraints,
            AlgorithmUses = uses,
            Instant = instant ?? DecisionInstant,
            LeadTime = leadTime ?? LeadTime
        };


    /// <summary>
    /// Builds a profile that states every item clause 6.4 requires of it, which each test then takes one item
    /// away from rather than building a whole profile of its own.
    /// </summary>
    /// <param name="storageModel">The storage model the profile announces.</param>
    /// <param name="goals">The preservation goals it announces.</param>
    /// <param name="acceptedHashFunctions">The hash functions its submission operation accepts as input formats.</param>
    /// <param name="retentionPeriod">The evidence retention period, which a temporary-storage profile owes.</param>
    /// <param name="expectedEvidenceDuration">The expected evidence duration, which a temporary-storage or no-storage profile is recommended to state.</param>
    /// <param name="policies">The policy references, or <see langword="null"/> for the evidence policy alone.</param>
    /// <param name="descriptions">The descriptions, or <see langword="null"/> for one in one language.</param>
    /// <param name="validUntil">When the profile ceases to be active, or <see langword="null"/> for a profile still in force.</param>
    /// <returns>The profile. The caller disposes it.</returns>
    internal static PreservationProfile Profile(
        string? storageModel = null,
        IReadOnlyList<string>? goals = null,
        IReadOnlyList<PkiDigestAlgorithm>? acceptedHashFunctions = null,
        string? retentionPeriod = null,
        string? expectedEvidenceDuration = null,
        IReadOnlyList<PreservationPolicyReference>? policies = null,
        IReadOnlyList<PreservationLocalizedText>? descriptions = null,
        DateTimeOffset? validUntil = null)
    {
        var inputFormats = new List<PreservationFormatDescriptor>
        {
            new() { FormatId = PreservationFormatWellKnown.CadesSignatureFormat }
        };

        if(acceptedHashFunctions is not null)
        {
            for(int i = 0; i < acceptedHashFunctions.Count; ++i)
            {
                inputFormats.Add(new PreservationFormatDescriptor { FormatId = PreservationDigestMethod.ToUrn(acceptedHashFunctions[i]) });
            }
        }

        return new PreservationProfile
        {
            ProfileIdentifier = ProfileIdentifier,
            Operations =
            [
                new PreservationOperationDescriptor { Name = PreservationWellKnown.RetrieveInfoOperation },
                new PreservationOperationDescriptor
                {
                    Name = PreservationWellKnown.PreservePreservationObjectOperation,
                    InputFormats = inputFormats,
                    OutputFormats = [new PreservationFormatDescriptor { FormatId = PreservationFormatWellKnown.EvidenceRecordContainerFormat }]
                }
            ],
            Policies = policies ??
            [
                new PreservationPolicyReference
                {
                    PolicyType = PreservationWellKnown.PreservationEvidencePolicyType,
                    PolicyLocation = EvidencePolicyLocation
                },
                new PreservationPolicyReference
                {
                    PolicyType = PreservationWellKnown.SignatureValidationPolicyType,
                    PolicyLocation = "https://preservation.example.test/policy/validation/1"
                }
            ],
            ValidityPeriod = new PreservationValidityPeriod
            {
                ValidFrom = TestClock.CanonicalEpoch.AddYears(-1),
                ValidUntil = validUntil
            },
            StorageModel = storageModel ?? PreservationWellKnown.WithStorageModel,
            PreservationGoals = goals ?? [PreservationWellKnown.DigitalSignatureGoal],
            EvidenceFormats = [new PreservationFormatDescriptor { FormatId = PreservationFormatWellKnown.EvidenceRecordEvidenceFormat }],
            SchemeIdentifier = PreservationWellKnown.StorageWithEvidenceRecordsScheme,
            Specifications = ["https://preservation.example.test/profile/capability/1.html"],
            Descriptions = descriptions ?? [new PreservationLocalizedText { Text = "A capability-layer profile.", Language = "en" }],
            PreservationEvidenceRetentionPeriod = retentionPeriod,
            ExpectedEvidenceDuration = expectedEvidenceDuration
        };
    }


    /// <summary>
    /// Builds a hash-only submission: a detached signature payload and one hash value per signed data object,
    /// computed through the registered digest seam.
    /// </summary>
    /// <param name="algorithm">The hash function the values are computed with.</param>
    /// <param name="signedDataObjects">The content of each signed data object the submitter withholds.</param>
    /// <param name="hashFunctionIdentifier">The identifier stated on the wire, or <see langword="null"/> for the algorithm's own.</param>
    /// <param name="pool">The pool every carrier is rented from.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The submission. The caller disposes it, which disposes every carrier it owns.</returns>
    internal static async ValueTask<PreservationHashOnlySubmission> SubmissionAsync(
        PkiDigestAlgorithm algorithm,
        IReadOnlyList<string> signedDataObjects,
        string? hashFunctionIdentifier,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signedDataObjects);

        var hashes = new List<DigestValue>(signedDataObjects.Count);
        PreservationObject? signature = null;
        try
        {
            for(int i = 0; i < signedDataObjects.Count; ++i)
            {
                hashes.Add(await CryptographicKeyEvents.ComputeDigestAsync(
                    Encoding.UTF8.GetBytes(signedDataObjects[i]),
                    algorithm.OutputByteLength,
                    algorithm.DigestTag,
                    pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false));
            }

            signature = new PreservationObject
            {
                Content = PooledMemory.FromBytes(Encoding.UTF8.GetBytes("a detached signature"), pool, PreservationTags.PreservationObject),
                ContentForm = PreservationContentForm.BinaryData,
                FormatId = PreservationFormatWellKnown.CadesSignatureFormat
            };

            return new PreservationHashOnlySubmission
            {
                HashFunctionIdentifier = hashFunctionIdentifier ?? PreservationDigestMethod.ToUrn(algorithm),
                SignedDataHashes = hashes,
                DetachedSignature = signature
            };
        }
        catch
        {
            signature?.Dispose();
            for(int i = 0; i < hashes.Count; ++i)
            {
                hashes[i].Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Builds a submission whose one hash value is deliberately of the wrong length for the identifier it states —
    /// the shape the second check of <c>OVR-9.3-08</c> exists to refuse.
    /// </summary>
    /// <param name="statedAlgorithm">The algorithm the submission names.</param>
    /// <param name="valueLength">How many octets the one value really occupies.</param>
    /// <param name="pool">The pool every carrier is rented from.</param>
    /// <returns>The submission. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the digest value and of the detached signature transfers to the returned submission, which the caller disposes; the catch disposes whatever was built on a partial failure.")]
    internal static PreservationHashOnlySubmission SubmissionWithValueOfLength(
        PkiDigestAlgorithm statedAlgorithm,
        int valueLength,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(valueLength);
        PreservationObject? signature = null;
        DigestValue? value = null;
        try
        {
            owner.Memory.Span.Fill(0x2A);
            value = new DigestValue(owner, statedAlgorithm.DigestTag);
            signature = new PreservationObject
            {
                Content = PooledMemory.FromBytes(Encoding.UTF8.GetBytes("a detached signature"), pool, PreservationTags.PreservationObject),
                ContentForm = PreservationContentForm.BinaryData,
                FormatId = PreservationFormatWellKnown.CadesSignatureFormat
            };

            return new PreservationHashOnlySubmission
            {
                HashFunctionIdentifier = PreservationDigestMethod.ToUrn(statedAlgorithm),
                SignedDataHashes = [value],
                DetachedSignature = signature
            };
        }
        catch
        {
            signature?.Dispose();
            if(value is null)
            {
                owner.Dispose();
            }
            else
            {
                value.Dispose();
            }

            throw;
        }
    }


    /// <summary>Builds evidence-artifact facts carrying a self-description, as the placement surface produces them.</summary>
    /// <param name="serviceIdentifier">What the evidence says its preservation service is, or <see langword="null"/> to state none.</param>
    /// <param name="policyIdentifier">What it says its preservation evidence policy is, or <see langword="null"/>.</param>
    /// <param name="profileIdentifier">What it says its preservation profile is, or <see langword="null"/>.</param>
    /// <param name="isProtected">Whether a time assertion of the evidence covers what it says about itself.</param>
    /// <returns>The facts.</returns>
    internal static EArkEvidenceArtifactFacts ArtifactWithSelfDescription(
        string? serviceIdentifier,
        string? policyIdentifier,
        string? profileIdentifier,
        bool isProtected) =>
        new()
        {
            Kind = EArkEvidenceKind.EvidenceRecord,
            EntryName = "metadata/other/evidence.ers",
            SelfDescription = new EArkEvidenceSelfDescription
            {
                PreservationServiceIdentifier = serviceIdentifier,
                EvidencePolicyIdentifier = policyIdentifier,
                PreservationProfileIdentifier = profileIdentifier
            },
            SelfDescriptionCarrier = EArkEvidenceSelfDescriptionCarrier.ArchiveTimeStampAttributes,
            SelfDescriptionIsProtected = isProtected
        };


    /// <summary>Builds evidence-artifact facts carrying no self-description at all.</summary>
    /// <returns>The facts.</returns>
    internal static EArkEvidenceArtifactFacts ArtifactWithoutSelfDescription() =>
        new()
        {
            Kind = EArkEvidenceKind.EvidenceRecord,
            EntryName = "metadata/other/evidence.ers"
        };
}
