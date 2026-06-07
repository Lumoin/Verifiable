using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for <see cref="CommitmentReuseDetection"/> — the stateless reuse-detection engine driven by the
/// application-owned <see cref="IsCommitmentSeenDelegate"/> / <see cref="RecordCommitmentDelegate"/>
/// seam. The store is wired as method groups on an app object, exactly as a real consumer would: the
/// per-call commitment is threaded in by the library, the store is the app's own infrastructure.
/// </summary>
[TestClass]
internal sealed class CommitmentReuseDetectionTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static readonly Tag DigestTag = new(new Dictionary<Type, object>
    {
        [typeof(HashAlgorithmName)] = HashAlgorithmName.SHA256
    });


    [TestMethod]
    public async Task FirstPresentationOfDistinctSaltsReportsNoReuse()
    {
        var store = new InMemoryCommitmentStore();
        using Salt first = TestSalts.Generate(TestSalts.TestSaltTag, Pool);
        using Salt second = TestSalts.Generate(TestSalts.TestSaltTag, Pool);
        using DigestValue firstCommitment = Commit(first);
        using DigestValue secondCommitment = Commit(second);

        IReadOnlyList<DigestValue> reused = await CommitmentReuseDetection.DetectAsync(
            [firstCommitment, secondCommitment], store.IsSeen, store.Record, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(reused, "Distinct salts seen for the first time are not reuse.");
    }


    [TestMethod]
    public async Task SameSaltPresentedInALaterCallIsReuse()
    {
        var store = new InMemoryCommitmentStore();
        using Salt salt = TestSalts.Generate(TestSalts.TestSaltTag, Pool);

        using DigestValue firstSeen = Commit(salt);
        await CommitmentReuseDetection.DetectAsync([firstSeen], store.IsSeen, store.Record, TestContext.CancellationToken).ConfigureAwait(false);

        //A later presentation of the same salt yields the same (deterministic) commitment bytes.
        using DigestValue presentedAgain = Commit(salt);
        IReadOnlyList<DigestValue> reused = await CommitmentReuseDetection.DetectAsync(
            [presentedAgain], store.IsSeen, store.Record, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, reused, "Re-presenting a salt recorded in an earlier call must be detected as reuse.");
        Assert.AreSame(presentedAgain, reused[0]);
    }


    [TestMethod]
    public async Task DuplicateSaltWithinOneBatchIsReuse()
    {
        var store = new InMemoryCommitmentStore();
        using Salt salt = TestSalts.Generate(TestSalts.TestSaltTag, Pool);
        using DigestValue commitment = Commit(salt);
        using DigestValue duplicate = Commit(salt);

        //The first occurrence is recorded as it is checked, so the second occurrence in the same batch
        //is already "seen".
        IReadOnlyList<DigestValue> reused = await CommitmentReuseDetection.DetectAsync(
            [commitment, duplicate], store.IsSeen, store.Record, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, reused, "A salt repeated within one presentation must be detected.");
        Assert.AreSame(duplicate, reused[0], "The second occurrence is the reuse.");
    }


    [TestMethod]
    public async Task NullLookupDelegateDisablesDetection()
    {
        using Salt salt = TestSalts.Generate(TestSalts.TestSaltTag, Pool);
        using DigestValue commitment = Commit(salt);
        using DigestValue duplicate = Commit(salt);

        //No lookup delegate => detection off, even for an obvious within-batch duplicate.
        IReadOnlyList<DigestValue> reused = await CommitmentReuseDetection.DetectAsync(
            [commitment, duplicate], isSeen: null, record: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(reused, "A null lookup delegate disables reuse detection entirely.");
    }


    private static DigestValue Commit(Salt salt) =>
        salt.ComputeCommitment(SHA256.HashData, outputByteLength: 32, DigestTag, Pool);


    /// <summary>
    /// An application-side commitment store: a process-local set keyed by the commitment bytes. A real
    /// deployment would back this with its own persistence and keying; the engine neither knows nor cares.
    /// </summary>
    private sealed class InMemoryCommitmentStore
    {
        private readonly HashSet<string> seen = new(StringComparer.Ordinal);

        public ValueTask<bool> IsSeen(DigestValue commitment, CancellationToken cancellationToken) =>
            ValueTask.FromResult(seen.Contains(Key(commitment)));

        public ValueTask Record(DigestValue commitment, CancellationToken cancellationToken)
        {
            seen.Add(Key(commitment));

            return ValueTask.CompletedTask;
        }

        private static string Key(DigestValue commitment) => Convert.ToHexString(commitment.AsReadOnlySpan());
    }
}
