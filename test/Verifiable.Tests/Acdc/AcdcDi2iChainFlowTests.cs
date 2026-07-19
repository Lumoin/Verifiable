using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Json;
using Verifiable.Keri;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// A multi-server, over-the-wire end-to-end flow for the ACDC delegated chain-of-authority (the <c>DI2I</c> edge
/// operator): a delegator (X) and its delegate (B) each run their own in-process Kestrel listener on a distinct
/// loopback socket. X self-issues a targeted far credential whose Issuee is X, and its KEL anchors both that
/// credential and the delegating seal for B's delegated inception. B is a delegated AID whose <c>dip</c> names X; B
/// issues a near credential with a <c>DI2I</c> edge to X's far credential. A firewalled Disclosee verifies the far
/// credential first (capturing the delegator's KEL anchors), then verifies the near credential by replaying B's
/// delegated inception against those anchors — so the near credential's Proof of Issuance is itself the
/// cooperative-delegation check — and evaluates the edge: <c>DI2I</c> holds because B is an AID X (the far
/// credential's Issuee) delegated, though plain <c>I2I</c> would not, since B is not X itself. Every credential and
/// KEL crosses its own socket; nothing is shared in memory across the parties.
/// </summary>
[TestClass]
internal sealed class AcdcDi2iChainFlowTests
{
    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The delegated chain-of-authority validates across the delegator and delegate sockets: the Disclosee verifies
    /// the far node over the delegator's socket, verifies the near credential by replaying its delegated inception
    /// against the delegator's anchors, and evaluates the <c>DI2I</c> edge as valid because B is an AID delegated by
    /// the far credential's Issuee.
    /// </summary>
    [TestMethod]
    public async Task Di2iChainOfAuthorityVerifiesAcrossDelegatorAndDelegateSockets()
    {
        bool valid = await RunDi2iChainAsync(brokenDelegation: false).ConfigureAwait(false);

        Assert.IsTrue(valid, "The DI2I edge holds when the near Issuer is an AID the far credential's Issuee delegated.");
    }


    /// <summary>
    /// An unverifiable delegation is rejected across the sockets: when the delegator's KEL does not anchor the
    /// delegate's delegating seal, the delegate's delegated inception fails closed on replay, so the near credential
    /// does not verify and the chain does not hold.
    /// </summary>
    [TestMethod]
    public async Task UnverifiableDelegationIsRejectedAcrossSockets()
    {
        bool valid = await RunDi2iChainAsync(brokenDelegation: true).ConfigureAwait(false);

        Assert.IsFalse(valid, "A delegation the delegator's KEL does not anchor cannot satisfy DI2I.");
    }


    /// <summary>
    /// Mints a delegator/delegate chain, publishes each party's credential and KEL on its own socket, and runs the
    /// Disclosee's verification: verify the far node over the delegator's socket, verify the near credential by
    /// replaying its delegated inception against the delegator's anchors, and evaluate the DI2I edge.
    /// </summary>
    /// <param name="brokenDelegation">Whether the delegator's KEL omits the delegate's delegating seal.</param>
    /// <returns>Whether the near credential verifies and its DI2I edge evaluates as valid.</returns>
    private async Task<bool> RunDi2iChainAsync(bool brokenDelegation)
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (AcdcFlowKit.EdgeChainParty delegated, AcdcFlowKit.EdgeChainParty delegator) =
                await AcdcFlowKit.MintDi2iChainAsync(brokenDelegation, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost delegateHost = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            await using StaticContentHost delegatorHost = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(delegateHost.BaseAddress, delegatorHost.BaseAddress, "The delegate and delegator MUST serve from independent sockets.");

            delegateHost.Publish("/acdc", delegated.Acdc.Serialization, "application/json");
            delegateHost.Publish("/kel", AcdcFlowKit.SerializeKel(delegated.Kel), "application/json");
            delegatorHost.Publish("/acdc", delegator.Acdc.Serialization, "application/json");
            delegatorHost.Publish("/kel", AcdcFlowKit.SerializeKel(delegator.Kel), "application/json");

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient([delegateHost.Certificate, delegatorHost.Certificate]);

            //Verify the far credential (the delegator's) and capture the delegator's verified KEL anchors. The
            //delegator self-issues, so its KEL carries no delegated event and needs no delegating-seal resolver.
            (AcdcMessage? farMessage, IReadOnlyList<KeriSeal>? delegatorAnchors) =
                await VerifyAcdcAsync(httpClient, BaseOf(delegatorHost, "/acdc"), BaseOf(delegatorHost, "/kel"), resolveDelegationSeal: null, disposables, cancellationToken).ConfigureAwait(false);
            if(farMessage is null || delegatorAnchors is null)
            {
                return false;
            }

            string? farIssuee = farMessage.Attribute is ExpandedAcdcSection attribute && attribute.Detail.TryGetString(AcdcMessageFields.Issuer, out string? issuee) ? issuee : null;
            var resolved = new AcdcFarNode(farMessage.Said, farIssuee, IsValid: true);

            //Verify the near credential (the delegate's) by replaying its delegated inception against the delegator's
            //anchors: the delegate's KEL verifies only when the delegator anchors the delegating seal, so this fetch
            //is the cooperative-delegation check. A broken delegation makes the near credential unverifiable.
            DelegationSealResolver resolveSeal = delegatedEvent => KeriDelegation.FindDelegationSeal(delegatorAnchors, delegatedEvent);
            (AcdcMessage? nearMessage, _) =
                await VerifyAcdcAsync(httpClient, BaseOf(delegateHost, "/acdc"), BaseOf(delegateHost, "/kel"), resolveSeal, disposables, cancellationToken).ConfigureAwait(false);
            if(nearMessage is null)
            {
                return false;
            }

            Assert.IsInstanceOfType<ExpandedAcdcSection>(nearMessage.Edge, "The near credential discloses its edge section.");
            AcdcEdgeGroup edgeSection = AcdcEdgeReader.Read(((ExpandedAcdcSection)nearMessage.Edge!).Detail);

            //The delegate's verified KEL confirms its delegator; map the near Issuer to that delegator for DI2I.
            string? confirmedDelegator = await ReadConfirmedDelegatorAsync(httpClient, BaseOf(delegateHost, "/kel"), nearMessage.Issuer, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            AcdcDelegationResolver resolveDelegation = aid => string.Equals(aid, nearMessage.Issuer, StringComparison.Ordinal) ? confirmedDelegator : null;

            Assert.IsTrue(delegateHost.WasRequested("/acdc") && delegateHost.WasRequested("/kel"), "The near credential and KEL MUST be fetched over the delegate socket.");
            Assert.IsTrue(delegatorHost.WasRequested("/acdc") && delegatorHost.WasRequested("/kel"), "The far credential and KEL MUST be fetched over the delegator socket.");

            //Evaluate the DI2I edge across the wire: the far-node resolver returns the far node verified over its
            //socket, and the delegation resolver returns the near Issuer's wire-confirmed delegator.
            return AcdcEdgeEvaluation.Evaluate(
                edgeSection,
                nearMessage.Issuer,
                nodeSaid => string.Equals(nodeSaid, resolved.Said, StringComparison.Ordinal) ? resolved : null,
                resolveDelegation);
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Reads the delegator a delegate's verified KEL confirms: reconstructs the delegate's KEL and takes the
    /// delegator named by its delegated inception. The delegate's KEL has already verified against the delegator's
    /// anchors, so the delegator this returns is the cooperatively-confirmed one.
    /// </summary>
    /// <param name="httpClient">The Disclosee's HTTP client.</param>
    /// <param name="delegateKelUri">The delegate's KEL URI.</param>
    /// <param name="delegateAid">The delegate AID whose delegator is read.</param>
    /// <param name="disposables">The list reconstructed buffers are tracked on for disposal.</param>
    /// <param name="pool">The pool the reconstructed buffers are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the fetch.</param>
    /// <returns>The confirmed delegator AID, or <see langword="null"/> when the KEL's first event is not the delegate's delegated inception.</returns>
    private static async Task<string?> ReadConfirmedDelegatorAsync(HttpClient httpClient, Uri delegateKelUri, string delegateAid, List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        string delegateKelJson = await httpClient.GetStringAsync(delegateKelUri, cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization delegateKelBytes = AcdcTestSupport.Encode(delegateKelJson);
        List<LogEntry<KeriKeyEvent, CryptoProof>> delegateLog = AcdcFlowKit.ReconstructKel(delegateKelBytes.Memory, disposables, pool);

        return delegateLog.Count > 0 && delegateLog[0].Operation is KeriDelegatedInceptionEvent dip && string.Equals(dip.Prefix, delegateAid, StringComparison.Ordinal)
            ? dip.DelegatorPrefix
            : null;
    }


    /// <summary>
    /// Fetches an ACDC and verifies Proof of Disclosure (the disclosed expanded form compacts to its claimed SAID)
    /// and Proof of Issuance (the Issuer's KEL anchors a seal committing to that SAID under the AID the credential
    /// names as Issuer, replaying any delegated event against the given delegating-seal resolver), returning the
    /// typed message and the Issuer's anchors, or nulls when either proof fails.
    /// </summary>
    /// <param name="httpClient">The Disclosee's HTTP client.</param>
    /// <param name="acdcUri">The credential's URI.</param>
    /// <param name="kelUri">The Issuer KEL's URI.</param>
    /// <param name="resolveDelegationSeal">The resolver for a delegated event's delegating seal, or <see langword="null"/> when the Issuer KEL carries no delegated events.</param>
    /// <param name="disposables">The list reconstructed buffers are tracked on for disposal.</param>
    /// <param name="cancellationToken">A token to cancel the verification.</param>
    /// <returns>The verified message and the Issuer's anchors, or nulls when a proof fails.</returns>
    private static async Task<(AcdcMessage? Message, IReadOnlyList<KeriSeal>? Anchors)> VerifyAcdcAsync(HttpClient httpClient, Uri acdcUri, Uri kelUri, DelegationSealResolver? resolveDelegationSeal, List<IDisposable> disposables, CancellationToken cancellationToken)
    {
        string acdcJson = await httpClient.GetStringAsync(acdcUri, cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization credential = AcdcTestSupport.Encode(acdcJson);
        MessageFieldMap map = AcdcJson.DecodeFieldMap(credential.Memory);
        AcdcMessage message = AcdcReader.Read(map);

        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(map, AcdcJson.Encode, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        if(!string.Equals((string)compact[AcdcMessageFields.Said]!, message.Said, StringComparison.Ordinal))
        {
            return (null, null);
        }

        string kelJson = await httpClient.GetStringAsync(kelUri, cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization kelBytes = AcdcTestSupport.Encode(kelJson);
        IReadOnlyList<KeriSeal>? anchors = await AcdcFlowKit.VerifyKelAndReadAnchorsAsync(kelBytes.Memory, message.Issuer, resolveDelegationSeal, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        if(anchors is null || AcdcKeriBinding.FindDirectIssuanceSeal(anchors, message.Said) is null)
        {
            return (null, null);
        }

        return (message, anchors);
    }


    /// <summary>Builds a URI for a path on a host's base address.</summary>
    /// <param name="host">The host.</param>
    /// <param name="path">The path.</param>
    /// <returns>The absolute URI.</returns>
    private static Uri BaseOf(StaticContentHost host, string path) => new(host.BaseAddress, path);


    /// <summary>Disposes every tracked resource.</summary>
    /// <param name="disposables">The tracked resources.</param>
    private static void Dispose(List<IDisposable> disposables)
    {
        foreach(IDisposable disposable in disposables)
        {
            disposable.Dispose();
        }
    }
}
