using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core.EventLogs;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebDidResolver"/> covering URL computation from W3C CCG test vectors,
/// the <see cref="DidMethodResolverDelegate"/>-compatible <c>ResolveAsync</c> method,
/// and the application developer pattern of feeding resolution results into the
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> pipeline to build
/// a verifiable audit log of resolution history.
/// </summary>
/// <remarks>
/// For DID methods whose specifications mandate log-driven resolution — such as
/// did:webvh and did:cel — the <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>
/// is the resolution algorithm itself. The same infrastructure serves both cases.
/// </remarks>
[TestClass]
internal sealed class WebDidResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void ResolveDomainOnly()
    {
        string result = WebDidResolver.Resolve("did:web:w3c-ccg.github.io");
        Assert.AreEqual("https://w3c-ccg.github.io/.well-known/did.json", result);
    }

    [TestMethod]
    public void ResolveDomainAndPath()
    {
        string result = WebDidResolver.Resolve("did:web:w3c-ccg.github.io:user:alice");
        Assert.AreEqual("https://w3c-ccg.github.io/user/alice/did.json", result);
    }

    [TestMethod]
    public void ResolveDomainPortAndPath()
    {
        string result = WebDidResolver.Resolve("did:web:example.com%3A3000:user:alice");
        Assert.AreEqual("https://example.com:3000/user/alice/did.json", result);
    }

    [TestMethod]
    public void ResolveDomainWithPortOnly()
    {
        string result = WebDidResolver.Resolve("did:web:example.com%3A8443");
        Assert.AreEqual("https://example.com:8443/.well-known/did.json", result);
    }

    [TestMethod]
    public void ResolveThrowsForNonDidWebIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebDidResolver.Resolve("did:key:z6Mk..."));
    }

    [TestMethod]
    public void ResolveThrowsForEmptyString()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebDidResolver.Resolve(""));
    }

    [TestMethod]
    public void ResolveThrowsForNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            WebDidResolver.Resolve(null!));
    }

    [TestMethod]
    public async Task ResolveAsyncReturnsDocumentUrlKind()
    {
        var result = await WebDidResolver.ResolveAsync(
            "did:web:example.com",
            DidResolutionOptions.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.DocumentUrl, result.Kind);
        Assert.IsNull(result.Document);
        Assert.AreEqual("https://example.com/.well-known/did.json", result.DocumentUrl);
    }

    [TestMethod]
    public async Task ResolveAsyncReturnsCorrectUrlForPathDid()
    {
        var result = await WebDidResolver.ResolveAsync(
            "did:web:example.com:users:alice",
            DidResolutionOptions.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.DocumentUrl, result.Kind);
        Assert.AreEqual("https://example.com/users/alice/did.json", result.DocumentUrl);
    }

    [TestMethod]
    public async Task SingleResolutionProducesGenesisEntry()
    {
        var (resolver, log) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();
        var context = BuildContext(log);

        const string did = "did:web:example.com";
        var resolution = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await foreach(var result in replayer.ReplayAsync(BuildEntries([(did, resolution)]), context, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsNull(result.Error);
        }

        Assert.HasCount(1, log);
        Assert.AreEqual(LogEntryClassification.Genesis, log[0].Classification);
    }

    [TestMethod]
    public async Task GenesisEntryProofCarriesDidAndDocumentUrl()
    {
        var (resolver, log) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();
        var context = BuildContext(log);

        const string did = "did:web:example.com";
        var resolution = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await foreach(var _ in replayer.ReplayAsync(BuildEntries([(did, resolution)]), context, TestContext.CancellationToken).ConfigureAwait(false)) { }

        var proof = log[0].Entry.Proofs[0];
        Assert.AreEqual("did:web:example.com", proof.Did);
        Assert.AreEqual("https://example.com/.well-known/did.json", proof.DocumentUrl);
    }

    [TestMethod]
    public async Task GenesisEntryOperationCarriesDidAndKind()
    {
        var (resolver, log) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();
        var context = BuildContext(log);

        const string did = "did:web:example.com";
        var resolution = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await foreach(var _ in replayer.ReplayAsync(BuildEntries([(did, resolution)]), context, TestContext.CancellationToken).ConfigureAwait(false)) { }

        var operation = log[0].Entry.Operation;
        Assert.IsNotNull(operation);
        Assert.AreEqual("did:web:example.com", operation.Did);
        Assert.AreEqual(DidResolutionKind.DocumentUrl, operation.Kind);
    }

    [TestMethod]
    public async Task SubsequentResolutionProducesUpdateEntry()
    {
        var (resolver, log) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();
        var context = BuildContext(log);

        const string did = "did:web:example.com";
        var first = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var second = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await foreach(var _ in replayer.ReplayAsync(BuildEntries([(did, first), (did, second)]), context, TestContext.CancellationToken).ConfigureAwait(false)) { }

        Assert.HasCount(2, log);
        Assert.AreEqual(LogEntryClassification.Genesis, log[0].Classification);
        Assert.AreEqual(LogEntryClassification.Update, log[1].Classification);
    }

    [TestMethod]
    public async Task EachUpdateEntryChainLinksToThePreviousDigest()
    {
        var (resolver, log) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();
        var context = BuildContext(log);

        const string did = "did:web:example.com";
        var resolutions = new List<(string, DidResolutionResult)>();
        for(var i = 0; i < 3; i++)
        {
            resolutions.Add((did, await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)));
        }

        await foreach(var _ in replayer.ReplayAsync(BuildEntries(resolutions), context, TestContext.CancellationToken).ConfigureAwait(false)) { }

        Assert.HasCount(3, log);
        Assert.IsNull(log[0].Entry.PreviousDigest);
        Assert.IsTrue(log[1].Entry.PreviousDigest.HasValue);
        Assert.IsTrue(log[0].Entry.Digest.Span.SequenceEqual(log[1].Entry.PreviousDigest!.Value.Span));
        Assert.IsTrue(log[2].Entry.PreviousDigest.HasValue);
        Assert.IsTrue(log[1].Entry.Digest.Span.SequenceEqual(log[2].Entry.PreviousDigest!.Value.Span));
    }

    [TestMethod]
    public async Task MultipleDifferentDidsProduceIndependentLogStreams()
    {
        var (resolver, logAlice) = BuildResolverAndLog();
        var (_, logBob) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();

        const string aliceDid = "did:web:alice.example.com";
        const string bobDid = "did:web:bob.example.com";
        var alice = await resolver.ResolveAsync(aliceDid, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var bob = await resolver.ResolveAsync(bobDid, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await foreach(var _ in replayer.ReplayAsync(BuildEntries([(aliceDid, alice)]), BuildContext(logAlice), TestContext.CancellationToken).ConfigureAwait(false)) { }
        await foreach(var _ in replayer.ReplayAsync(BuildEntries([(bobDid, bob)]), BuildContext(logBob), TestContext.CancellationToken).ConfigureAwait(false)) { }

        Assert.AreEqual("did:web:alice.example.com", logAlice[0].Entry.Proofs[0].Did);
        Assert.AreEqual("did:web:bob.example.com", logBob[0].Entry.Proofs[0].Did);
    }

    [TestMethod]
    public async Task FailedResolutionProducesEntryWithErrorKind()
    {
        var (resolver, log) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();
        var context = BuildContext(log);

        const string did = "not-a-did";
        var failure = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(failure.IsSuccessful);

        await foreach(var _ in replayer.ReplayAsync(BuildEntries([(did, failure)]), context, TestContext.CancellationToken).ConfigureAwait(false)) { }

        Assert.HasCount(1, log);
        var operation = log[0].Entry.Operation;
        Assert.IsNotNull(operation);
        Assert.AreEqual("not-a-did", operation.Did);
        Assert.AreEqual(DidResolutionKind.Error, operation.Kind);
    }

    [TestMethod]
    public async Task OnEntryProcessedReceivesActiveStateAfterGenesis()
    {
        var (resolver, log) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();
        var context = BuildContext(log);

        const string did = "did:web:example.com";
        var resolution = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await foreach(var _ in replayer.ReplayAsync(BuildEntries([(did, resolution)]), context, TestContext.CancellationToken).ConfigureAwait(false)) { }

        Assert.IsInstanceOfType<ActiveLogState<DidResolutionResult>>(log[0].State);
    }

    [TestMethod]
    public async Task StateValueCarriesTheResolutionResult()
    {
        var (resolver, log) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();
        var context = BuildContext(log);

        const string did = "did:web:example.com";
        var resolution = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await foreach(var _ in replayer.ReplayAsync(BuildEntries([(did, resolution)]), context, TestContext.CancellationToken).ConfigureAwait(false)) { }

        var active = (ActiveLogState<DidResolutionResult>)log[0].State;
        Assert.AreEqual("https://example.com/.well-known/did.json", active.Value.DocumentUrl);
    }

    [TestMethod]
    public async Task TamperedEntryDigestCausesChainIntegrityError()
    {
        var (resolver, log) = BuildResolverAndLog();
        var replayer = new LogReplayer<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>();
        var context = BuildContext(log);

        const string did = "did:web:example.com";
        var first = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var second = await resolver.ResolveAsync(did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var entries = new List<LogEntry<WebResolutionOperation, WebResolutionProof>>();
        await foreach(var e in BuildEntries([(did, first), (did, second)]).WithCancellation(TestContext.CancellationToken).ConfigureAwait(false))
        {
            entries.Add(e);
        }

        //Tamper: replace the second entry's PreviousDigest with wrong bytes.
        var tampered = new LogEntry<WebResolutionOperation, WebResolutionProof>
        {
            Index = entries[1].Index,
            PreviousDigest = new byte[32],
            Digest = entries[1].Digest,
            CanonicalBytes = entries[1].CanonicalBytes,
            Operation = entries[1].Operation,
            Proofs = entries[1].Proofs
        };
        entries[1] = tampered;

        LogReplayResult<DidResolutionResult, WebResolutionOperation, WebResolutionProof>? errorResult = null;
        await foreach(var result in replayer.ReplayAsync(ToAsync(entries, TestContext.CancellationToken), context, TestContext.CancellationToken).ConfigureAwait(false))
        {
            if(!result.IsSuccess)
            {
                errorResult = result;
            }
        }

        Assert.IsNotNull(errorResult);
        Assert.IsNotNull(errorResult.Error);
    }


    //Proof type defined by the application developer — not part of the library.
    //Carries the inputs used to produce this entry so the caller can verify
    //that the proof was constructed from the correct resolution result.
    private sealed record WebResolutionProof(string Did, string DocumentUrl, bool IsSuccessful);

    //Operation type defined by the application developer — not part of the library.
    //Records what was resolved and what the outcome kind was.
    private sealed record WebResolutionOperation(string Did, DidResolutionKind Kind);

    //Proof validation context — no trust anchors are needed for this demonstration.
    private sealed record NoValidationContext;


    private static (DidResolver Resolver, List<LogReplayResult<DidResolutionResult, WebResolutionOperation, WebResolutionProof>> Log) BuildResolverAndLog()
    {
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.WebDidMethodPrefix, WebDidResolver.ResolveAsync)));

        var log = new List<LogReplayResult<DidResolutionResult, WebResolutionOperation, WebResolutionProof>>();

        return (resolver, log);
    }

    private static LogReplayContext<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext> BuildContext(
        List<LogReplayResult<DidResolutionResult, WebResolutionOperation, WebResolutionProof>> log)
    {
        return new LogReplayContext<DidResolutionResult, WebResolutionOperation, WebResolutionProof, NoValidationContext>
        {
            Classify = OperationClassifiers.ByIndex<WebResolutionOperation, WebResolutionProof>(),
            VerifyChainIntegrity = VerifyChainIntegrity,
            ValidateProof = static (_, _, _, _) => ValueTask.FromResult<string?>(null),
            ValidationContext = new NoValidationContext(),
            Apply = LogReplayDefaults.CreateApplyDelegate<DidResolutionResult, WebResolutionOperation, WebResolutionProof>(
                genesis: static (_, entry, _) => ValueTask.FromResult<(ActiveLogState<DidResolutionResult>, string?)>(
                    (new ActiveLogState<DidResolutionResult>(entry.Operation is not null
                        ? new DidResolutionResult
                        {
                            Kind = entry.Operation.Kind,
                            ResolutionMetadata = new DidResolutionMetadata(),
                            DocumentUrl = entry.Proofs[0].DocumentUrl
                        }
                        : DidResolutionResult.Failure(DidResolutionErrors.InternalError)), null)),
                update: static (_, entry, _) => ValueTask.FromResult<(ActiveLogState<DidResolutionResult>, string?)>(
                    (new ActiveLogState<DidResolutionResult>(entry.Operation is not null
                        ? new DidResolutionResult
                        {
                            Kind = entry.Operation.Kind,
                            ResolutionMetadata = new DidResolutionMetadata(),
                            DocumentUrl = entry.Proofs[0].DocumentUrl
                        }
                        : DidResolutionResult.Failure(DidResolutionErrors.InternalError)), null)),
                deactivate: static (active, _, _) => ValueTask.FromResult<(DeactivatedLogState<DidResolutionResult>, string?)>(
                    (new DeactivatedLogState<DidResolutionResult>(active.Value), null))),
            OnEntryProcessed = (result, _) =>
            {
                log.Add(result);
                return ValueTask.CompletedTask;
            },
            TimeProvider = TimeProvider.System
        };
    }


    /// <summary>
    /// Builds a stream of log entries from (did, resolutionResult) pairs.
    /// Each entry's CanonicalBytes are the UTF-8 encoding of the DocumentUrl or error string.
    /// The Digest is SHA-256 of those bytes. PreviousDigest chains each entry to its predecessor.
    /// </summary>
    /// <param name="resolutions">The resolutions to build log entries from.</param>
    /// <returns>An asynchronous enumerable of log entries.</returns>
    private static IAsyncEnumerable<LogEntry<WebResolutionOperation, WebResolutionProof>> BuildEntries(IEnumerable<(string Did, DidResolutionResult Resolution)> resolutions)
    {
        var entries = new List<LogEntry<WebResolutionOperation, WebResolutionProof>>();
        ReadOnlyMemory<byte>? previousDigest = null;

        foreach(var ((did, resolution), index) in resolutions.Select((r, i) => (r, (ulong)i)))
        {
            var documentUrl = resolution.DocumentUrl ?? resolution.ResolutionMetadata.Error?.Detail ?? string.Empty;
            var canonical = Encoding.UTF8.GetBytes(documentUrl);
            var digest = (ReadOnlyMemory<byte>)SHA256.HashData(canonical);

            var entry = new LogEntry<WebResolutionOperation, WebResolutionProof>
            {
                Index = index,
                PreviousDigest = previousDigest,
                Digest = digest,
                CanonicalBytes = canonical,
                Operation = new WebResolutionOperation(did, resolution.Kind),
                Proofs = [new WebResolutionProof(did, documentUrl, resolution.IsSuccessful)]
            };

            entries.Add(entry);
            previousDigest = digest;
        }

        return ToAsync(entries);
    }


    /// <summary>
    /// Converts an <see cref="IEnumerable{T}"/> to an <see cref="IAsyncEnumerable{T}"/> by yielding each item 
    /// </summary>
    /// <param name="source">The source enumerable.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>An asynchronous enumerable that yields each item from the source.</returns>
    private static async IAsyncEnumerable<T> ToAsync<T>(IEnumerable<T> source, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach(var item in source)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return item;
            await Task.CompletedTask.ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Verifies that each entry's PreviousDigest matches the digest the replayer
    /// recorded from the preceding entry.
    /// </summary>
    /// <param name="entry">The current log entry.</param>
    /// <param name="previousEntryDigest">The digest of the previous log entry.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains an error message if the chain integrity is broken, or null if the chain is intact.</returns>
    private static ValueTask<string?> VerifyChainIntegrity(
        LogEntry<WebResolutionOperation, WebResolutionProof> entry,
        ReadOnlyMemory<byte>? previousEntryDigest,
        CancellationToken cancellationToken)
    {
        if(entry.Index == 0)
        {
            return ValueTask.FromResult<string?>(null);
        }

        if(previousEntryDigest is null || entry.PreviousDigest is null)
        {
            return ValueTask.FromResult<string?>("Chain integrity broken: missing digest.");
        }

        if(!entry.PreviousDigest.Value.Span.SequenceEqual(previousEntryDigest.Value.Span))
        {
            return ValueTask.FromResult<string?>("Chain integrity broken: previous digest mismatch.");
        }

        return ValueTask.FromResult<string?>(null);
    }
}