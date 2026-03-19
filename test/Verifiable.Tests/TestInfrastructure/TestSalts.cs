using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Test helpers for constructing <see cref="Salt"/> instances from raw bytes and
/// for producing <see cref="GenerateDisclosureSaltDelegate"/> implementations
/// suitable for issuance-side tests.
/// </summary>
/// <remarks>
/// <para>
/// Production code allocates salt through the entropy backend (e.g.,
/// <see cref="Verifiable.Microsoft.MicrosoftEntropyFunctions.GenerateSalt"/>) which
/// stamps full provenance — <see cref="Purpose.Salt"/>, <see cref="ProviderLibrary"/>,
/// <see cref="CryptoLibrary"/>, <see cref="ProviderClass"/>,
/// <see cref="ProviderOperation"/> — on the resulting <see cref="Salt.Tag"/>. Tests
/// need a parallel path:
/// </para>
/// <list type="bullet">
/// <item><description>For tests that have hand-coded salt bytes (deterministic test
/// vectors, RFC 9901 examples, and so on),
/// <see cref="FromBytes(ReadOnlySpan{byte}, MemoryPool{byte}?)"/> wraps the bytes in
/// a <see cref="Salt"/> with a test-only tag.</description></item>
/// <item><description>For tests that need a fresh salt on every disclosure
/// (issuance pipelines), <see cref="DefaultGenerator"/> returns a
/// <see cref="GenerateDisclosureSaltDelegate"/> bound to <see cref="Salt.Generate"/>.</description></item>
/// <item><description>For tests that need deterministic salts in a sequence,
/// <see cref="FromQueue"/> returns a delegate that pops bytes from a queue.</description></item>
/// </list>
/// <para>
/// <see cref="TestSaltTag"/> carries <see cref="Purpose.Salt"/> plus a
/// <see cref="ProviderLibrary"/> and <see cref="ProviderClass"/> identifying the
/// test assembly. Salts produced by this helper are forensically distinguishable
/// from production salts in any diagnostic dump while sharing the same purpose
/// semantics, so consumers that branch on <see cref="Purpose"/> behave identically
/// for test-originated and production salts.
/// </para>
/// </remarks>
[SuppressMessage(
    "Reliability", "CA2000",
    Justification =
        "Salt instances returned by FromBytes are intended to transfer ownership to " +
        "downstream factories (SdDisclosure.CreateProperty/CreateArrayElement). The " +
        "analyzer cannot see ownership transfer through factory methods.")]
internal static class TestSalts
{
    /// <summary>
    /// The tag stamped on every test-constructed salt. Carries
    /// <see cref="Purpose.Salt"/> plus test-assembly provenance.
    /// </summary>
    public static readonly Tag TestSaltTag = CreateTestSaltTag();


    private static Tag CreateTestSaltTag()
    {
        string assemblyName = typeof(TestSalts).Assembly.GetName().Name
            ?? "Verifiable.Tests";
        string assemblyVersion = typeof(TestSalts).Assembly.GetName().Version?.ToString()
            ?? "Unknown";

        return new Tag(new Dictionary<Type, object>
        {
            [typeof(Purpose)] = Purpose.Salt,
            [typeof(ProviderLibrary)] = new ProviderLibrary(assemblyName, assemblyVersion),
            [typeof(ProviderClass)] = new ProviderClass(nameof(TestSalts))
        });
    }


    /// <summary>
    /// Wraps the supplied <paramref name="bytes"/> in a fresh <see cref="Salt"/>
    /// allocated from <paramref name="pool"/>. Ownership of the returned
    /// <see cref="Salt"/> transfers to the caller.
    /// </summary>
    /// <param name="bytes">The salt bytes to wrap. Copied into a pool-rented buffer.</param>
    /// <param name="pool">
    /// The memory pool to allocate from. Defaults to
    /// <see cref="SensitiveMemoryPool{T}.Shared"/> when omitted.
    /// </param>
    /// <returns>A new <see cref="Salt"/> owning a copy of <paramref name="bytes"/>.</returns>
    public static Salt FromBytes(ReadOnlySpan<byte> bytes, MemoryPool<byte>? pool = null)
    {
        MemoryPool<byte> resolvedPool = pool ?? SensitiveMemoryPool<byte>.Shared;
        IMemoryOwner<byte> owner = resolvedPool.Rent(bytes.Length);

        try
        {
            bytes.CopyTo(owner.Memory.Span[..bytes.Length]);
            return new Salt(owner, TestSaltTag, lifetime: null);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Convenience overload for tests holding salt as a <see cref="byte"/> array.
    /// </summary>
    public static Salt FromBytes(byte[] bytes, MemoryPool<byte>? pool = null) =>
        FromBytes(bytes.AsSpan(), pool);


    /// <summary>
    /// Returns a <see cref="GenerateDisclosureSaltDelegate"/> that produces a fresh
    /// random salt of <paramref name="byteLength"/> bytes on each call, allocated
    /// from <paramref name="pool"/>.
    /// </summary>
    /// <param name="byteLength">
    /// Salt length in bytes. RFC 9901 §4.2.2 mandates at least 16 (128 bits).
    /// </param>
    /// <param name="pool">
    /// The memory pool to allocate from. Defaults to
    /// <see cref="SensitiveMemoryPool{T}.Shared"/> when omitted.
    /// </param>
    public static GenerateDisclosureSaltDelegate DefaultGenerator(
        int byteLength = 16,
        MemoryPool<byte>? pool = null)
    {
        MemoryPool<byte> resolvedPool = pool ?? SensitiveMemoryPool<byte>.Shared;
        return () => Salt.Generate(byteLength, TestSaltTag, resolvedPool);
    }


    /// <summary>
    /// Returns a <see cref="GenerateDisclosureSaltDelegate"/> that yields salts in
    /// the order supplied by <paramref name="bytesSequence"/>, throwing once the
    /// sequence is exhausted. Used for deterministic test vectors where every
    /// disclosure's salt is fixed in advance.
    /// </summary>
    /// <param name="bytesSequence">The sequence of salts, returned in order.</param>
    /// <param name="pool">
    /// The memory pool to allocate from. Defaults to
    /// <see cref="SensitiveMemoryPool{T}.Shared"/> when omitted.
    /// </param>
    public static GenerateDisclosureSaltDelegate FromQueue(
        IEnumerable<byte[]> bytesSequence,
        MemoryPool<byte>? pool = null)
    {
        ArgumentNullException.ThrowIfNull(bytesSequence);
        Queue<byte[]> queue = new(bytesSequence);
        return () =>
        {
            if(queue.Count == 0)
            {
                throw new InvalidOperationException(
                    "Test salt queue exhausted — provide more salt vectors.");
            }
            return FromBytes(queue.Dequeue(), pool);
        };
    }
}
