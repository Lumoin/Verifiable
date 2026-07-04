using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Foundation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// End-to-end tests for <see cref="WebPlusDidResolver.Build"/> — the full did:webplus resolver that fetches the
/// <c>did-documents.jsonl</c> through the guarded <see cref="OutboundFetch"/> chokepoint, replays and verifies
/// every document through the <see cref="Verifiable.Cryptography.EventLogs.LogReplayer{TState,TOperation,TProof,TContext}"/>,
/// selects the requested version, and returns the resolved <see cref="Verifiable.Core.Model.Did.DidDocument"/>.
/// Anchored on the specification's "Creating and Updating a DID" worked examples (minted by the independent Rust
/// reference implementation), served by a faked transport; BLAKE3 is supplied from BouncyCastle as an independent
/// oracle (firewall). The resolver wiring lives in <see cref="WebPlusTestResolver"/>.
/// </summary>
[TestClass]
internal sealed class WebPlusDidResolverResolvingTests
{
    /// <summary>The cancellation-token source for the test.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The specification's latest (versionId-1) document of example 1 resolves through the full replay.</summary>
    [TestMethod]
    public async Task ResolvesLatestVersion()
    {
        string microledger = WebPlusWorkedExamples.ToMicroledger(WebPlusWorkedExamples.Example1Root, WebPlusWorkedExamples.Example1NonRoot);

        DidResolutionResult result = await ResolveAsync(WebPlusWorkedExamples.Example1Did, microledger).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A two-document did:webplus microledger MUST resolve. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.AreEqual(WebPlusWorkedExamples.Example1Did, result.Document!.Id?.ToString());
        Assert.AreEqual("1", result.DocumentMetadata.VersionId);
        Assert.IsFalse(result.DocumentMetadata.Deactivated);
    }


    /// <summary>A single root document resolves as a valid one-document history (versionId 0).</summary>
    [TestMethod]
    public async Task ResolvesRootOnly()
    {
        string microledger = WebPlusWorkedExamples.ToMicroledger(WebPlusWorkedExamples.Example1Root);

        DidResolutionResult result = await ResolveAsync(WebPlusWorkedExamples.Example1Did, microledger).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A root-only microledger MUST resolve. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.AreEqual("0", result.DocumentMetadata.VersionId);
    }


    /// <summary>Resolving by an explicit numeric <c>versionId</c> returns that specific document (WP-RES-2).</summary>
    [TestMethod]
    public async Task ResolvesByVersionId()
    {
        string microledger = WebPlusWorkedExamples.ToMicroledger(WebPlusWorkedExamples.Example1Root, WebPlusWorkedExamples.Example1NonRoot);

        DidResolutionResult result = await ResolveAsync(
            WebPlusWorkedExamples.Example1Did, microledger, new DidResolutionOptions { VersionId = "0" }).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A versionId query MUST resolve. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.AreEqual("0", result.DocumentMetadata.VersionId);
    }


    /// <summary>Resolving by an explicit <c>selfHash</c> MBHash returns that specific document (WP-RES-2).</summary>
    [TestMethod]
    public async Task ResolvesBySelfHash()
    {
        string microledger = WebPlusWorkedExamples.ToMicroledger(WebPlusWorkedExamples.Example1Root, WebPlusWorkedExamples.Example1NonRoot);

        DidResolutionResult result = await ResolveAsync(
            WebPlusWorkedExamples.Example1Did, microledger, new DidResolutionOptions { VersionId = WebPlusWorkedExamples.Example1RootSelfHash }).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A selfHash query MUST resolve. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.AreEqual("0", result.DocumentMetadata.VersionId, "The selfHash query MUST select the root (versionId-0) document.");
    }


    /// <summary>
    /// Resolving the latest version of a deactivated DID succeeds with a null document and <c>deactivated:true</c>
    /// metadata: a resolver MUST NOT return the DIDDoc of a deactivated DID (WP-CTL-3, WP-MD-7).
    /// </summary>
    [TestMethod]
    public async Task DeactivatedLatestReturnsNoDocument()
    {
        string microledger = WebPlusWorkedExamples.ToMicroledger(
            WebPlusWorkedExamples.Example2Root, WebPlusWorkedExamples.Example2V1, WebPlusWorkedExamples.Example2V2Deactivation);

        DidResolutionResult result = await ResolveAsync(WebPlusWorkedExamples.Example2Did, microledger).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A deactivated did:webplus DID MUST resolve with deactivated metadata. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.IsNull(result.Document, "A resolver MUST NOT return the DIDDoc for a deactivated DID.");
        Assert.IsTrue(result.DocumentMetadata.Deactivated, "A deactivated DID MUST carry deactivated:true.");
        Assert.AreEqual("2", result.DocumentMetadata.VersionId, "The resolved version MUST be the deactivation document.");
    }


    /// <summary>
    /// Resolving a prior version of a deactivated DID returns that earlier DIDDoc but MUST still carry
    /// <c>deactivated:true</c> in the metadata (a verified later deactivation marks the DID deactivated; WP-MD-7).
    /// </summary>
    [TestMethod]
    public async Task PriorVersionOfDeactivatedDidCarriesDeactivatedMetadata()
    {
        string microledger = WebPlusWorkedExamples.ToMicroledger(
            WebPlusWorkedExamples.Example2Root, WebPlusWorkedExamples.Example2V1, WebPlusWorkedExamples.Example2V2Deactivation);

        DidResolutionResult result = await ResolveAsync(
            WebPlusWorkedExamples.Example2Did, microledger, new DidResolutionOptions { VersionId = "1" }).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A prior version of a deactivated DID MUST resolve. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.IsNotNull(result.Document, "A prior version of a deactivated DID returns that version's DIDDoc.");
        Assert.AreEqual("1", result.DocumentMetadata.VersionId);
        Assert.IsTrue(result.DocumentMetadata.Deactivated, "A prior version of a deactivated DID MUST still carry deactivated:true.");
    }


    /// <summary>A document tampered after signing fails resolution: its self-hash no longer verifies (WP-VAL-0).</summary>
    [TestMethod]
    public async Task TamperedDocumentFailsResolution()
    {
        //Change a verification-method public key in the versionId-1 document; the selfHash no longer commits to it.
        string tampered = WebPlusWorkedExamples.Example1NonRoot.Replace(
            "g2AYHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg",
            "AAAAHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg",
            StringComparison.Ordinal);
        string microledger = WebPlusWorkedExamples.ToMicroledger(WebPlusWorkedExamples.Example1Root, tampered);

        DidResolutionResult result = await ResolveAsync(WebPlusWorkedExamples.Example1Did, microledger).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A tampered did:webplus microledger MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsNotNull(result.ResolutionMetadata.Error?.Detail);
    }


    /// <summary>
    /// A DID whose trailing root-self-hash does not match the served root document's <c>selfHash</c> MUST NOT
    /// resolve (WP-ID-1: the DID commits to its root document).
    /// </summary>
    [TestMethod]
    public async Task RootSelfHashMismatchIsInvalid()
    {
        //A DID carrying a different (well-formed) trailing self-hash than the served root document's selfHash.
        const string wrongDid = "did:webplus:example.com:hey:uHiCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        string microledger = WebPlusWorkedExamples.ToMicroledger(WebPlusWorkedExamples.Example1Root, WebPlusWorkedExamples.Example1NonRoot);

        DidResolutionResult result = await ResolveAsync(wrongDid, microledger).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A DID whose root-self-hash does not match the root document MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>A missing microledger (a 404 at the resolution URL) is reported as NotFound.</summary>
    [TestMethod]
    public async Task ReportsNotFoundForMissingLog()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebPlusDidResolver.Resolve(WebPlusWorkedExamples.Example1Did)] = (404, null)
        });

        DidResolutionResult result = await WebPlusTestResolver.ResolveAsync(WebPlusWorkedExamples.Example1Did, transport, options: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }


    /// <summary>An unknown requested <c>versionId</c> is reported as NotFound.</summary>
    [TestMethod]
    public async Task UnknownVersionIdIsNotFound()
    {
        string microledger = WebPlusWorkedExamples.ToMicroledger(WebPlusWorkedExamples.Example1Root, WebPlusWorkedExamples.Example1NonRoot);

        DidResolutionResult result = await ResolveAsync(
            WebPlusWorkedExamples.Example1Did, microledger, new DidResolutionOptions { VersionId = "9" }).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }


    /// <summary>An oversized microledger MUST be rejected before it is parsed (resource-exhaustion guard).</summary>
    [TestMethod]
    public async Task OversizedMicroledgerIsRejected()
    {
        string oversized = WebPlusWorkedExamples.ToMicroledger(WebPlusWorkedExamples.Example1Root) + "\n" + new string(' ', 9 * 1024 * 1024);

        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebPlusDidResolver.Resolve(WebPlusWorkedExamples.Example1Did)] = (200, oversized)
        });

        DidResolutionResult result = await WebPlusTestResolver.ResolveAsync(WebPlusWorkedExamples.Example1Did, transport, options: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "An oversized did:webplus microledger MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>did:webplus dispatches through the multi-method resolver composition (WP-RES wiring).</summary>
    [TestMethod]
    public async Task DispatchesDidWebPlusThroughComposition()
    {
        string microledger = WebPlusWorkedExamples.ToMicroledger(WebPlusWorkedExamples.Example1Root, WebPlusWorkedExamples.Example1NonRoot);

        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebPlusDidResolver.Resolve(WebPlusWorkedExamples.Example1Did)] = (200, microledger)
        });

        DidMethodResolverDelegate webPlus = WebPlusTestResolver.Build(transport.Delegate);

        DidResolver composed = DidResolverComposition.Build(
            BaseMemoryPool.Shared,
            static (request, context, cancellationToken) => ValueTask.FromResult(new OutboundResponse { StatusCode = 404, Body = TaggedMemory<byte>.Empty }),
            static jsonUtf8 => null,
            static jsonUtf8 => null,
            additionalMethods: [(WellKnownDidMethodPrefixes.WebPlusDidMethodPrefix, webPlus)]);

        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        DidResolutionResult result = await composed.ResolveAsync(WebPlusWorkedExamples.Example1Did, context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:webplus MUST dispatch through the composition. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.AreEqual(WebPlusWorkedExamples.Example1Did, result.Document!.Id?.ToString());
    }


    /// <summary>Resolves a DID over a transport serving the given microledger at the DID's resolution URL.</summary>
    /// <param name="did">The DID to resolve.</param>
    /// <param name="microledger">The <c>did-documents.jsonl</c> body to serve.</param>
    /// <param name="options">The resolution options, or <see langword="null"/> for the latest version.</param>
    /// <returns>The resolution result.</returns>
    private Task<DidResolutionResult> ResolveAsync(string did, string microledger, DidResolutionOptions? options = null)
    {
        return WebPlusTestResolver.ResolveAsync(did, microledger, options, TestContext.CancellationToken);
    }
}
