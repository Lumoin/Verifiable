using System;
using Verifiable.DidComm.Transport;
using Verifiable.Foundation;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Disposal semantics for <see cref="DidCommExchangeResult"/>: it owns <see cref="DidCommExchangeResult.ReplyBody"/>
/// and delegates <see cref="DidCommExchangeResult.Dispose"/> to it, so the carrier's own dispose-safety
/// properties (post-dispose access throws, double dispose is safe, the shared <see cref="PooledMemory.Empty"/>
/// stays usable across every reply-less result) are exactly what this type's own disposal behavior depends on.
/// </summary>
[TestClass]
internal sealed class DidCommExchangeResultTests
{
    private static readonly BaseMemoryPool Pool = BaseMemoryPool.Shared;

    /// <summary>A dedicated tag distinct from any production tag, so assertions never coincide with a real buffer role by accident.</summary>
    private static Tag TestTag { get; } = Tag.Create("test-reply");

    /// <summary>Reading <see cref="DidCommExchangeResult.ReplyBody"/>'s bytes after disposing the result throws, via the underlying <see cref="PooledMemory"/> carrier.</summary>
    [TestMethod]
    public void PostDisposeReplyBodyAccessThrowsViaTheCarrier()
    {
        PooledMemory replyBody = PooledMemory.FromBytes([0x01, 0x02, 0x03], Pool, TestTag);
        DidCommExchangeResult result = DidCommExchangeResult.Accepted(200, replyBody, null);

        result.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => result.ReplyBody.AsReadOnlySpan());
    }


    /// <summary>Disposing a result carrying a rented reply is safe to call more than once.</summary>
    [TestMethod]
    public void DoubleDisposeIsSafeForARentedReply()
    {
        PooledMemory replyBody = PooledMemory.FromBytes([0x01], Pool, TestTag);
        DidCommExchangeResult result = DidCommExchangeResult.Accepted(200, replyBody, null);

        result.Dispose();
        result.Dispose();
    }


    /// <summary>
    /// Every reply-less factory (<see cref="DidCommExchangeResult.Accepted(int?)"/>,
    /// <see cref="DidCommExchangeResult.Rejected"/>, <see cref="DidCommExchangeResult.DeniedByPolicy"/>,
    /// <see cref="DidCommExchangeResult.TransportFailed"/>) mints <see cref="PooledMemory.Empty"/>, so
    /// disposing any of them — repeatedly, across many independently minted results — is always a no-op and
    /// never poisons the shared instance for another result.
    /// </summary>
    [TestMethod]
    public void ReplyLessResultsDisposeAsNoOpsOnTheSharedEmpty()
    {
        DidCommExchangeResult accepted = DidCommExchangeResult.Accepted(202);
        DidCommExchangeResult rejected = DidCommExchangeResult.Rejected(400);
        DidCommExchangeResult deniedByPolicy = DidCommExchangeResult.DeniedByPolicy();
        DidCommExchangeResult transportFailed = DidCommExchangeResult.TransportFailed();

        accepted.Dispose();
        rejected.Dispose();
        deniedByPolicy.Dispose();
        transportFailed.Dispose();
        accepted.Dispose();

        Assert.IsTrue(PooledMemory.Empty.IsEmpty, "The shared Empty instance stays usable after every reply-less result disposed it.");
        Assert.IsTrue(PooledMemory.Empty.AsReadOnlySpan().IsEmpty);
    }


    /// <summary>Ownership transfer is null-guarded: <see cref="DidCommExchangeResult.Accepted(int?, PooledMemory, string?)"/> rejects a null reply body.</summary>
    [TestMethod]
    public void AcceptedWithReplyRejectsNullReplyBody()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => DidCommExchangeResult.Accepted(200, null!, null));
    }
}
