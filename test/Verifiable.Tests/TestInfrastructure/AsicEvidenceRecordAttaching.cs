using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// What attaching an <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> Evidence Record to
/// an existing Associated Signature Container produced: the rewritten container, the record itself, and the two
/// entry names the attachment chose.
/// </summary>
/// <remarks><strong>Ownership.</strong> The caller owns and disposes both <see cref="Container"/> and <see cref="EvidenceRecord"/>.</remarks>
internal sealed record AsicAttachedEvidenceRecord
{
    /// <summary>The container carrying the record and the <c>ASiCEvidenceRecordManifest</c> naming it.</summary>
    public required PooledMemory Container { get; init; }

    /// <summary>The record, as the carrier a renewal takes.</summary>
    public required EvidenceRecord EvidenceRecord { get; init; }

    /// <summary>The entry name the record is stored under.</summary>
    public required string EvidenceRecordEntryName { get; init; }

    /// <summary>The entry name the <c>ASiCEvidenceRecordManifest</c> is stored under.</summary>
    public required string ManifestEntryName { get; init; }

    /// <summary>The instant the record's initial Archive Timestamp asserts.</summary>
    public required DateTimeOffset ArchiveTime { get; init; }
}


/// <summary>
/// Everything <see cref="AsicEvidenceRecordAttaching.AttachAsync"/> needs: the container to attach to, the
/// entries the record is to protect, the algorithm, and how to reach the Time-Stamping Authority.
/// </summary>
/// <remarks>A configured object rather than loose parameters, so nothing reaches the call through a closure.</remarks>
internal sealed record AsicEvidenceRecordAttachmentContext
{
    /// <summary>Gets the container's octets.</summary>
    public required ReadOnlyMemory<byte> Container { get; init; }

    /// <summary>Gets the entry names the Evidence Record is to protect, which become both its data object group and the manifest's <c>DataObjectReference</c> targets.</summary>
    public required IReadOnlyList<string> ProtectedEntryNames { get; init; }

    /// <summary>Gets the instant the two added entries record.</summary>
    public required DateTimeOffset LastModified { get; init; }

    /// <summary>Gets the Time-Stamping Authority address, in whatever form the transport delegate understands.</summary>
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the record's time-stamp is acquired over.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>Gets the seam the <c>ASiCEvidenceRecordManifest</c> is written through.</summary>
    public required EncodeAsicManifestDelegate EncodeManifest { get; init; }

    /// <summary>Gets the algorithm the record's hash tree and the manifest's <c>ds:DigestMethod</c> both state (clause 4.4.3.2 item 4's "shall match").</summary>
    public PkiDigestAlgorithm DigestAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;
}


/// <summary>
/// Attaches and replaces the Evidence Record of a container that ALREADY carries its signatures, its manifests
/// and possibly an Annex A.7 chain — the composition the flow legs of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> clause 4.4.4.2 item 4 a) need and that no single shipped surface performs.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this exists in the test project.</strong> <c>AsicContainerCreation.CreateEvidenceRecordAsync</c>
/// builds a container FROM data objects and cannot be handed one that already carries <c>META-INF</c> entries,
/// and the augmentation surface ships no Evidence Record attachment. Every step here is nevertheless a shipped
/// surface — <see cref="AsicZipReading"/>, <see cref="EvidenceRecords"/>, <see cref="AsicManifestNaming"/>, the
/// manifest encoding seam and <see cref="AsicZipAuthoring"/> — composed in the order the specification states,
/// with the entry names taken from the naming surface rather than from literals so that a collision is
/// impossible by construction.
/// </para>
/// <para>
/// <strong>What it preserves.</strong> Every entry the container already carried is written back with its own
/// octets, compression method and instant unchanged, which is what keeps every digest an existing manifest
/// states — and every time-stamp token committed to those digests — true across the attachment.
/// </para>
/// <para>
/// The record covers the entries as the container stores them, so clause 4.4.4.2 item d)'s digest comparison
/// and RFC 4998 clause 4.3's tree-path proof are statements about the same octets.
/// </para>
/// </remarks>
internal static class AsicEvidenceRecordAttaching
{
    /// <summary>
    /// Creates an Evidence Record over the named entries as ONE data object group, writes the
    /// <c>ASiCEvidenceRecordManifest</c> naming it and them, and rewrites the container with both files added.
    /// </summary>
    /// <param name="context">The container, the targets, the algorithm and the transport.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The rewritten container, the record and the two names. The caller disposes the container and the record.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When the container cannot be read, an entry the record is to protect is missing, or the manifest seam refuses to write.</exception>
    public static async ValueTask<AsicAttachedEvidenceRecord> AttachAsync(
        AsicEvidenceRecordAttachmentContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        using AsicZipReadResult read = AsicZipReading.Read(context.Container, AsicZipReadLimits.Conformant, pool);
        if(!read.IsRead)
        {
            throw new InvalidOperationException($"The container has to read before an Evidence Record can be attached to it ({read.Status}).");
        }

        var existingNames = new List<string>(read.Container!.Entries.Count);
        List<AsicZipEntrySource> entries = CopyEntries(read.Container, existingNames);

        var dataObjects = new List<ReadOnlyMemory<byte>>(context.ProtectedEntryNames.Count);
        for(int i = 0; i < context.ProtectedEntryNames.Count; ++i)
        {
            AsicZipEntry target = read.Container.FindEntry(context.ProtectedEntryNames[i])
                ?? throw new InvalidOperationException($"The container carries no entry named '{context.ProtectedEntryNames[i]}'.");
            dataObjects.Add(target.Content.AsReadOnlyMemory());
        }

        using EvidenceRecordCreation creation = await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = dataObjects }],
                DigestAlgorithm = context.DigestAlgorithm,
                TsaUri = context.TsaUri,
                FetchTimestampResponse = context.FetchTimestampResponse
            },
            pool,
            cancellationToken).ConfigureAwait(false);

        string recordEntryName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.BinaryEvidenceRecord, existingNames);
        string manifestEntryName = AsicManifestNaming.CreateEntryName(
            AsicContainerFileKind.EvidenceRecordManifest, existingNames.Append(recordEntryName));

        using AsicManifest manifest = await BuildManifestAsync(context, dataObjects, recordEntryName, pool, cancellationToken).ConfigureAwait(false);
        using AsicManifestEncodeResult encoded = await context.EncodeManifest(
            new AsicManifestEncodeContext { Manifest = manifest }, pool, cancellationToken).ConfigureAwait(false);
        if(!encoded.IsEncoded || encoded.Document is not PooledMemory document)
        {
            throw new InvalidOperationException($"The ASiCEvidenceRecordManifest could not be written ({encoded.Status}: {encoded.FailureReason}).");
        }

        byte[] recordOctets = creation.EvidenceRecords[0].AsReadOnlySpan().ToArray();
        entries.Add(new AsicZipEntrySource { Name = manifestEntryName, Content = document.AsReadOnlySpan().ToArray(), LastModified = context.LastModified });
        entries.Add(new AsicZipEntrySource { Name = recordEntryName, Content = recordOctets, LastModified = context.LastModified });

        PooledMemory rewritten = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = read.Container.MediaType,
                Entries = entries,
                LastModified = context.LastModified,
                ArchiveComment = read.Container.ArchiveComment
            },
            pool);

        try
        {
            return new AsicAttachedEvidenceRecord
            {
                Container = rewritten,
                EvidenceRecord = EvidenceRecord.Read(recordOctets, pool),
                EvidenceRecordEntryName = recordEntryName,
                ManifestEntryName = manifestEntryName,
                ArchiveTime = creation.ArchiveTime
            };
        }
        catch
        {
            rewritten.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Rewrites a container with one entry's octets replaced and every other entry's payload, method and instant
    /// carried forward unchanged — how a renewed Evidence Record takes the place of the record it renews.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="entryName">The entry to replace.</param>
    /// <param name="content">The octets it is to carry.</param>
    /// <param name="lastModified">The instant the replaced entry records.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <returns>The rewritten container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="entryName"/>, <paramref name="content"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When the container cannot be read or carries no such entry.</exception>
    public static PooledMemory ReplaceEntry(
        ReadOnlyMemory<byte> container,
        string entryName,
        ReadOnlyMemory<byte> content,
        DateTimeOffset lastModified,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(entryName);
        ArgumentNullException.ThrowIfNull(pool);

        using AsicZipReadResult read = AsicZipReading.Read(container, AsicZipReadLimits.Conformant, pool);
        if(!read.IsRead)
        {
            throw new InvalidOperationException($"The container has to read before an entry of it can be replaced ({read.Status}).");
        }

        var entries = new List<AsicZipEntrySource>(read.Container!.Entries.Count);
        int replaced = 0;
        foreach(AsicZipEntry entry in read.Container.Entries)
        {
            if(AsicWellKnown.IsMimetypeEntryName(entry.Name))
            {
                continue;
            }

            bool isTarget = string.Equals(entry.Name, entryName, StringComparison.Ordinal);
            replaced += isTarget ? 1 : 0;
            entries.Add(new AsicZipEntrySource
            {
                Name = entry.Name,
                Content = isTarget ? content.ToArray() : entry.Content.AsReadOnlySpan().ToArray(),
                CompressionMethod = entry.CompressionMethod,
                LastModified = isTarget ? lastModified : entry.LastModified
            });
        }

        if(replaced != 1)
        {
            throw new InvalidOperationException($"'{entryName}' occurs {replaced} times in the container; exactly one entry can be replaced.");
        }

        return AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = read.Container.MediaType,
                Entries = entries,
                LastModified = lastModified,
                ArchiveComment = read.Container.ArchiveComment
            },
            pool);
    }


    /// <summary>
    /// Copies every entry of a read container into the sources a rewrite is written from, leaving out the
    /// <c>mimetype</c> entry, whose content, position and encoding Annex A.1 makes the archive author's own.
    /// </summary>
    /// <param name="container">The read container.</param>
    /// <param name="existingNames">Receives every entry name, the <c>mimetype</c> entry included, for collision-free naming.</param>
    /// <returns>The sources, in the order the container carries them.</returns>
    private static List<AsicZipEntrySource> CopyEntries(AsicZipContainer container, List<string> existingNames)
    {
        var entries = new List<AsicZipEntrySource>(container.Entries.Count + 2);
        foreach(AsicZipEntry entry in container.Entries)
        {
            existingNames.Add(entry.Name);
            if(AsicWellKnown.IsMimetypeEntryName(entry.Name))
            {
                continue;
            }

            entries.Add(new AsicZipEntrySource
            {
                Name = entry.Name,
                Content = entry.Content.AsReadOnlySpan().ToArray(),
                CompressionMethod = entry.CompressionMethod,
                LastModified = entry.LastModified
            });
        }

        return entries;
    }


    /// <summary>
    /// Builds the <c>ASiCEvidenceRecordManifest</c> model: a <c>SigReference</c> naming the record and one
    /// <c>DataObjectReference</c> per protected entry, each stating the digest of that entry as the container
    /// stores it (Annex A.4.1, clause 4.4.3.2 item 4).
    /// </summary>
    /// <param name="context">The attachment context.</param>
    /// <param name="dataObjects">The protected entries' octets, in the order their names are stated.</param>
    /// <param name="recordEntryName">The entry name the record is stored under.</param>
    /// <param name="pool">The memory pool every digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The manifest. The caller disposes it, which disposes the references and their digests.</returns>
    private static async ValueTask<AsicManifest> BuildManifestAsync(
        AsicEvidenceRecordAttachmentContext context,
        List<ReadOnlyMemory<byte>> dataObjects,
        string recordEntryName,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        var references = new List<AsicDataObjectReference>(dataObjects.Count);
        try
        {
            for(int i = 0; i < dataObjects.Count; ++i)
            {
                DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    dataObjects[i],
                    context.DigestAlgorithm.OutputByteLength,
                    context.DigestAlgorithm.DigestTag,
                    pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                references.Add(new AsicDataObjectReference
                {
                    Uri = AsicContainerUri.ToReference(context.ProtectedEntryNames[i]),
                    DigestAlgorithm = context.DigestAlgorithm,
                    Digest = digest
                });
            }

            return new AsicManifest
            {
                SignatureReference = new AsicSignatureReference { Uri = AsicContainerUri.ToReference(recordEntryName) },
                DataObjectReferences = references
            };
        }
        catch
        {
            for(int i = 0; i < references.Count; ++i)
            {
                references[i].Dispose();
            }

            throw;
        }
    }
}
