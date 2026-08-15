using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A Time-Stamping Authority minted for one call, together with the address a shipped surface is given for it.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> An instance owns the two certificate-ring nodes; disposing it disposes them. The
/// responder holds them and must not outlive it.
/// </remarks>
internal sealed record PreservationTimestampAuthority: IDisposable
{
    /// <summary>Gets the root certification authority of the ring. Owned by this instance.</summary>
    public required X509ChainTestRingNode Root { get; init; }

    /// <summary>Gets the time-stamping authority. Owned by this instance.</summary>
    public required X509ChainTestRingNode Authority { get; init; }

    /// <summary>Gets the responder that mints a genuine token over whatever imprint a request states.</summary>
    public required MintingTimestampResponder Responder { get; init; }

    /// <summary>
    /// Gets the address handed to the time-stamp transport delegate. No socket is opened for it: the delegate
    /// answers from the in-process authority, and the value exists because the shipped surface makes a caller
    /// name the authority it is talking to.
    /// </summary>
    public required string Address { get; init; }


    /// <summary>Disposes the ring nodes.</summary>
    public void Dispose()
    {
        Authority.Dispose();
        Root.Dispose();
    }
}


/// <summary>
/// The material the container profile of Annex A.3.1 and the <c>DigestList</c> component of clause 5.6.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> are exercised over: containers minted through the shipped surfaces, digest lists
/// built through the registered digest seam, and the authority that time-stamps them.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Everything under test is minted, not invented.</strong> A container comes from
/// <see cref="AsicContainerCreation.CreateEvidenceRecordAsync"/> and carries a real Evidence Record over a real
/// hash tree, time-stamped by an authority that signs what it is asked to sign; a digest value is computed
/// through <see cref="CryptographicKeyEvents.ComputeDigestAsync"/>. A profile evaluation that only ever saw
/// hand-written octets would not have been told anything.
/// </para>
/// <para>
/// <strong>The clock is stated.</strong> Every certificate and every token comes from
/// <see cref="TestClock.CanonicalEpoch"/> and its offsets, so a run tomorrow reads exactly as a run today.
/// </para>
/// </remarks>
internal static class PreservationProfileSource
{
    /// <summary>The address handed to the time-stamp transport delegate.</summary>
    internal static string TimestampAuthorityAddress { get; } = "https://preservation-authority.example.test/tsa";

    /// <summary>The <c>genTime</c> the initial archive time-stamp of a minted record states.</summary>
    internal static DateTimeOffset InitialArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The <c>genTime</c> a renewal's archive time-stamp states.</summary>
    internal static DateTimeOffset RenewalArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);


    /// <summary>
    /// Mints a Time-Stamping Authority that answers with a genuine token asserting a stated instant.
    /// </summary>
    /// <param name="generationTime">The instant every token it mints asserts.</param>
    /// <returns>The authority. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both ring nodes transfers to the returned record, which the caller disposes.")]
    internal static PreservationTimestampAuthority MintAuthority(DateTimeOffset generationTime)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        try
        {
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

            return new PreservationTimestampAuthority
            {
                Root = root,
                Authority = authority,
                Responder = new MintingTimestampResponder(authority, [authority, root], generationTime),
                Address = TimestampAuthorityAddress
            };
        }
        catch
        {
            root.Dispose();

            throw;
        }
    }


    /// <summary>
    /// States the data objects a container of this source carries, as the shipped creation surface takes them.
    /// </summary>
    /// <param name="contents">The content of each data object, in order.</param>
    /// <returns>The data objects.</returns>
    internal static List<AsicDataObject> DataObjects(params string[] contents)
    {
        ArgumentNullException.ThrowIfNull(contents);

        var dataObjects = new List<AsicDataObject>(contents.Length);
        for(int i = 0; i < contents.Length; ++i)
        {
            dataObjects.Add(new AsicDataObject
            {
                Name = string.Concat("data-", (i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), ".txt"),
                Content = Encoding.UTF8.GetBytes(contents[i]),
                MediaType = "text/plain"
            });
        }

        return dataObjects;
    }


    /// <summary>
    /// States the creation context a container of this source is built from.
    /// </summary>
    /// <param name="dataObjects">The data objects the container carries and its Evidence Record proves.</param>
    /// <param name="authority">The authority the record's time-stamp is taken from.</param>
    /// <param name="evidenceRecordReferenceMediaType">
    /// The media type to state on the manifest's <c>SigReference</c>, which the profile forbids — stated only by
    /// the test that shows the refusal.
    /// </param>
    /// <param name="shape">Which container shape to build; the extended one unless a test states otherwise.</param>
    /// <returns>The context.</returns>
    internal static AsicContainerEvidenceRecordContext CreationContext(
        IReadOnlyList<AsicDataObject> dataObjects,
        PreservationTimestampAuthority authority,
        string? evidenceRecordReferenceMediaType = null,
        AsicContainerShape shape = AsicContainerShape.Extended)
    {
        ArgumentNullException.ThrowIfNull(authority);

        return new AsicContainerEvidenceRecordContext
        {
            Shape = shape,
            DataObjects = dataObjects,
            LastModified = TestClock.CanonicalEpoch,
            TsaUri = authority.Address,
            FetchTimestampResponse = authority.Responder.FetchAsync,
            DigestAlgorithm = PkiDigestAlgorithm.Sha256,
            EncodeManifest = Verifiable.Cryptography.Pki.Xml.AsicManifestXmlBinding.EncodeAsync,
            EvidenceRecordReferenceMediaType = evidenceRecordReferenceMediaType
        };
    }


    /// <summary>
    /// Reads a container's facts and parses every evidence-record manifest it carries, as the profile evaluation
    /// takes them.
    /// </summary>
    /// <param name="containerOctets">The container's octets.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The facts and the parsed manifests. The caller owns and disposes both.</returns>
    /// <remarks>
    /// The manifest parse goes through the worked binding staged beside the container tests, because the shipped
    /// surface ships no serialisation of its own — which is the same division of labour the profile evaluation
    /// itself assumes.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the read result and of every parsed manifest transfers to the returned tuple, which the caller disposes; the catch disposes whatever is held on a partial failure.")]
    internal static async ValueTask<(AsicContainerReadResult Read, List<AsicManifestParseResult> Manifests)> ReadContainerAsync(
        ReadOnlyMemory<byte> containerOctets,
        CancellationToken cancellationToken)
    {
        AsicContainerReadResult read = AsicContainerReading.Read(containerOctets, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        var manifests = new List<AsicManifestParseResult>();
        try
        {
            AsicContainerFacts facts = read.Facts!;
            for(int i = 0; i < facts.Manifests.Count; ++i)
            {
                AsicManifestFile manifestFile = facts.Manifests[i];
                if(manifestFile.Role != AsicManifestRole.EvidenceRecord)
                {
                    continue;
                }

                using PooledMemory document = PooledMemory.FromBytes(
                    manifestFile.Entry.Content.AsReadOnlySpan(), BaseMemoryPool.Shared, AsicTags.Manifest);

                manifests.Add(await Verifiable.Cryptography.Pki.Xml.AsicManifestXmlBinding.ParseAsync(
                    new AsicManifestParseContext { Document = document },
                    BaseMemoryPool.Shared,
                    cancellationToken).ConfigureAwait(false));
            }

            return (read, manifests);
        }
        catch
        {
            for(int i = 0; i < manifests.Count; ++i)
            {
                manifests[i].Dispose();
            }

            read.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Builds a digest list over data objects: one digest value per object, computed through the registered
    /// digest seam under the stated algorithm.
    /// </summary>
    /// <param name="dataObjects">The data objects the digest values are computed over.</param>
    /// <param name="algorithm">The algorithm the digest method names.</param>
    /// <param name="evidence">The evidence the submission carries, or <see langword="null"/> to carry none. Ownership transfers to the digest list.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The digest list. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every computed digest and of the supplied evidence transfers to the returned digest list, which the caller disposes; the catch disposes what has been computed on a partial failure.")]
    internal static async ValueTask<PreservationDigestList> DigestListAsync(
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjects,
        PkiDigestAlgorithm algorithm,
        PreservationEvidence? evidence,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dataObjects);

        var digestValues = new List<DigestValue>(dataObjects.Count);
        try
        {
            for(int i = 0; i < dataObjects.Count; ++i)
            {
                digestValues.Add(await CryptographicKeyEvents.ComputeDigestAsync(
                    dataObjects[i],
                    algorithm.OutputByteLength,
                    algorithm.DigestTag,
                    BaseMemoryPool.Shared,
                    cancellationToken: cancellationToken).ConfigureAwait(false));
            }

            return new PreservationDigestList
            {
                DigestMethod = PreservationDigestMethod.ToUrn(algorithm),
                DigestValues = digestValues,
                Evidence = evidence
            };
        }
        catch
        {
            for(int i = 0; i < digestValues.Count; ++i)
            {
                digestValues[i].Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// States an Evidence Record as the <c>Evidence</c> component clause 5.4.4 defines, ready to ride in a digest
    /// list.
    /// </summary>
    /// <param name="evidenceRecord">The record to carry.</param>
    /// <param name="formatId">The evidence format identifier to state, or <see langword="null"/> for the ASN.1 evidence record of clause A.2.2.</param>
    /// <returns>The evidence. The caller owns and disposes it, usually by disposing the digest list holding it.</returns>
    internal static PreservationEvidence Evidence(EvidenceRecord evidenceRecord, string? formatId = null)
    {
        ArgumentNullException.ThrowIfNull(evidenceRecord);

        return new PreservationEvidence
        {
            Content = PooledMemory.FromBytes(evidenceRecord.AsReadOnlySpan(), BaseMemoryPool.Shared, PreservationTags.PreservationEvidence),
            ContentForm = PreservationContentForm.BinaryData,
            FormatId = formatId ?? PreservationFormatWellKnown.EvidenceRecordEvidenceFormat
        };
    }
}
