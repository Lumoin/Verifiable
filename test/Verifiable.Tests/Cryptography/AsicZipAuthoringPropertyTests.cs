using System;
using System.Collections.Generic;
using CsCheck;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Property-based tests (CsCheck) for the two claims the container layer rests on that no example can establish:
/// that a container is a function of the context it was written from, and that a container this library wrote
/// is one it reads back unchanged.
/// </summary>
/// <remarks>
/// <para>
/// Both fail silently when they are wrong. A container that recorded an ambient instant, or a length field that
/// was right for the entries the examples happened to use, produces a well-formed archive that no structural
/// check refuses — it simply differs from the one the same context produced a moment earlier, or loses an octet
/// of an entry nobody looked at. A failing sample is a defect, not noise: CsCheck shrinks it and prints the seed
/// that reproduces it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicZipAuthoringPropertyTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The instant every container in this class records.</summary>
    private static DateTimeOffset Instant { get; } = TestClock.CanonicalEpoch;


    /// <summary>
    /// Writing the same context twice produces the same octets, whatever the entries are and however they are
    /// stored. Nothing in a container records when or where it was written.
    /// </summary>
    [TestMethod]
    public void WritingOneContextTwiceProducesTheSameOctets()
    {
        ContentSamples.Sample(sample =>
        {
            AsicZipAuthoringContext context = BuildContext(sample.Contents, sample.MethodSelector);
            using PooledMemory first = AsicZipAuthoring.Write(context, BaseMemoryPool.Shared);
            using PooledMemory second = AsicZipAuthoring.Write(context, BaseMemoryPool.Shared);

            return first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan());
        });
    }


    /// <summary>
    /// Every container this library writes reads back with the same entries in the same order, each holding
    /// exactly the octets it was written from.
    /// </summary>
    [TestMethod]
    public void EveryContainerWrittenReadsBackWithItsEntriesUnchanged()
    {
        ContentSamples.Sample(sample =>
        {
            AsicZipAuthoringContext context = BuildContext(sample.Contents, sample.MethodSelector);
            using PooledMemory written = AsicZipAuthoring.Write(context, BaseMemoryPool.Shared);
            using AsicZipReadResult result = AsicZipReading.Read(written.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);

            if(!result.IsRead || result.Container!.Entries.Count != context.Entries.Count + 1)
            {
                return false;
            }

            for(int i = 0; i < context.Entries.Count; ++i)
            {
                AsicZipEntry? read = result.Container.FindEntry(context.Entries[i].Name);
                if(read is null || !read.Content.AsReadOnlySpan().SequenceEqual(context.Entries[i].Content.Span))
                {
                    return false;
                }

                if(read.CompressionMethod != context.Entries[i].CompressionMethod || read.LastModified != Instant)
                {
                    return false;
                }
            }

            return true;
        });
    }


    /// <summary>
    /// However many entries a container holds and however they are stored, its media type is readable at
    /// offset 38 by the algorithm the Annex A.1 NOTE of ETSI EN 319 162-1 V1.1.1 describes — the recognition
    /// feature the whole container format hangs on.
    /// </summary>
    [TestMethod]
    public void TheMediaTypeIsAlwaysReadableAtOffset38()
    {
        ContentSamples.Sample(sample =>
        {
            AsicZipAuthoringContext context = BuildContext(sample.Contents, sample.MethodSelector);
            using PooledMemory written = AsicZipAuthoring.Write(context, BaseMemoryPool.Shared);

            return string.Equals(
                AsicZipStructureOracle.MediaTypeAtOffset38(written.AsReadOnlySpan()),
                context.MediaType,
                StringComparison.Ordinal);
        });
    }


    /// <summary>
    /// The samples every property in this class runs over: between one and six entries of up to 64 octets each,
    /// with a selector deciding which of them are deflated.
    /// </summary>
    private static Gen<(byte[][] Contents, int MethodSelector)> ContentSamples { get; } =
        from contents in Gen.Byte.Array[0, 64].Array[1, 6]
        from methodSelector in Gen.Int[0, 63]
        select (contents, methodSelector);


    /// <summary>
    /// Builds a context from generated content, naming the entries so that no two of them collide.
    /// </summary>
    /// <param name="contents">The octets each entry carries.</param>
    /// <param name="methodSelector">A bit per entry deciding whether it is deflated.</param>
    /// <returns>The context to write.</returns>
    private static AsicZipAuthoringContext BuildContext(byte[][] contents, int methodSelector)
    {
        var entries = new List<AsicZipEntrySource>(contents.Length);
        for(int i = 0; i < contents.Length; ++i)
        {
            entries.Add(new AsicZipEntrySource
            {
                Name = $"data/object{i}.bin",
                Content = contents[i],
                CompressionMethod = ((methodSelector >> i) & 1) == 1 ? AsicZipCompressionMethod.Deflated : AsicZipCompressionMethod.Stored
            });
        }

        return new AsicZipAuthoringContext
        {
            MediaType = AsicWellKnown.AsicExtendedMediaType,
            Entries = entries,
            LastModified = Instant
        };
    }
}
