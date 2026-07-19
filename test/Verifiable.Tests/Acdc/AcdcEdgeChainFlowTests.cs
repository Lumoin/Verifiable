using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Keri;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// A multi-server, over-the-wire end-to-end flow for the ACDC chain-of-authority: a far Issuer (A) and a near
/// Issuer (B) each run their own in-process Kestrel listener on a distinct loopback socket. A is the accreditor: it
/// issues a targeted credential whose Issuee is B. B issues a credential with an edge pointing to A's credential. A
/// firewalled Disclosee fetches B's credential, verifies it, reads its edge, then resolves the far node by fetching
/// A's credential over A's socket and verifying it, and evaluates the edge — the default <c>I2I</c> operator holds
/// only because B (the near Issuer) is the Issuee of the far credential, so the chain authorizes B's issuance. Every
/// credential and KEL crosses its own socket; nothing is shared in memory across the parties.
/// </summary>
[TestClass]
internal sealed class AcdcEdgeChainFlowTests
{
    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The chain-of-authority validates across two Issuer sockets: the Disclosee verifies the near credential
    /// (Proof of Disclosure and Proof of Issuance), resolves the far node over the far Issuer's socket (verifying
    /// it the same way), and confirms the edge holds because the near Issuer is the far credential's Issuee.
    /// </summary>
    [TestMethod]
    public async Task EdgeChainOfAuthorityVerifiesAcrossTwoIssuerSockets()
    {
        bool valid = await RunEdgeChainAsync(brokenChain: false).ConfigureAwait(false);

        Assert.IsTrue(valid, "The edge section is a valid chain-of-authority when the near Issuer is the far credential's Issuee.");
    }


    /// <summary>
    /// A broken chain is rejected across the sockets: when the far credential's Issuee is some other AID — not the
    /// near Issuer — the default <c>I2I</c> operator is not satisfied even though both credentials and both KELs
    /// verify on their own, so the edge section is invalid.
    /// </summary>
    [TestMethod]
    public async Task BrokenChainOfAuthorityIsRejectedAcrossSockets()
    {
        bool valid = await RunEdgeChainAsync(brokenChain: true).ConfigureAwait(false);

        Assert.IsFalse(valid, "A far credential whose Issuee is not the near Issuer breaks the I2I chain.");
    }


    /// <summary>
    /// Mints a two-Issuer chain, publishes each Issuer's credential and KEL on its own socket, and runs the
    /// Disclosee's verification: verify the near credential, resolve and verify the far node over its socket, and
    /// evaluate the edge.
    /// </summary>
    /// <param name="brokenChain">Whether the far credential's Issuee is not the near Issuer.</param>
    /// <returns>Whether the near credential's edge section evaluates as valid.</returns>
    private async Task<bool> RunEdgeChainAsync(bool brokenChain)
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (AcdcFlowKit.EdgeChainParty near, AcdcFlowKit.EdgeChainParty far) =
                await AcdcFlowKit.MintEdgeChainAsync(brokenChain, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost nearIssuer = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            await using StaticContentHost farIssuer = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);

            nearIssuer.Publish("/acdc", near.Acdc.Serialization, "application/json");
            nearIssuer.Publish("/kel", AcdcFlowKit.SerializeKel(near.Kel), "application/json");
            farIssuer.Publish("/acdc", far.Acdc.Serialization, "application/json");
            farIssuer.Publish("/kel", AcdcFlowKit.SerializeKel(far.Kel), "application/json");

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient([nearIssuer.Certificate, farIssuer.Certificate]);

            //Verify the near credential and read its edge section.
            AcdcMessage? nearMessage = await VerifyAcdcAsync(httpClient, BaseOf(nearIssuer, "/acdc"), BaseOf(nearIssuer, "/kel"), disposables, cancellationToken).ConfigureAwait(false);
            Assert.IsNotNull(nearMessage, "The near credential MUST verify (Proof of Disclosure and Proof of Issuance).");
            Assert.IsInstanceOfType<ExpandedAcdcSection>(nearMessage.Edge, "The near credential discloses its edge section.");
            AcdcEdgeGroup edgeSection = AcdcEdgeReader.Read(((ExpandedAcdcSection)nearMessage.Edge!).Detail);

            //Resolve the far node over the far Issuer's socket and verify it the same way.
            AcdcMessage? farMessage = await VerifyAcdcAsync(httpClient, BaseOf(farIssuer, "/acdc"), BaseOf(farIssuer, "/kel"), disposables, cancellationToken).ConfigureAwait(false);
            Assert.IsNotNull(farMessage, "The far credential MUST verify when fetched over its socket.");

            string? farIssuee = farMessage.Attribute is ExpandedAcdcSection attribute && attribute.Detail.TryGetString(AcdcMessageFields.Issuer, out string? issuee) ? issuee : null;
            var resolved = new AcdcFarNode(farMessage.Said, farIssuee, IsValid: true);

            //Both fetches crossed their respective sockets.
            Assert.IsTrue(nearIssuer.WasRequested("/acdc") && nearIssuer.WasRequested("/kel"), "The near credential and KEL MUST be fetched over the near socket.");
            Assert.IsTrue(farIssuer.WasRequested("/acdc") && farIssuer.WasRequested("/kel"), "The far credential and KEL MUST be fetched over the far socket.");

            //Evaluate the edge: the resolver returns the far node verified over its socket.
            return AcdcEdgeEvaluation.Evaluate(edgeSection, nearMessage.Issuer, nodeSaid => string.Equals(nodeSaid, resolved.Said, StringComparison.Ordinal) ? resolved : null);
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Fetches an ACDC and verifies Proof of Disclosure (the disclosed expanded form compacts to its claimed SAID)
    /// and Proof of Issuance (the Issuer's KEL anchors a seal committing to that SAID under the AID the credential
    /// names as Issuer), returning the typed message or <see langword="null"/> when either proof fails.
    /// </summary>
    /// <param name="httpClient">The Disclosee's HTTP client.</param>
    /// <param name="acdcUri">The credential's URI.</param>
    /// <param name="kelUri">The Issuer KEL's URI.</param>
    /// <param name="disposables">The list reconstructed buffers are tracked on for disposal.</param>
    /// <param name="cancellationToken">A token to cancel the verification.</param>
    /// <returns>The verified message, or <see langword="null"/> when a proof fails.</returns>
    private static async Task<AcdcMessage?> VerifyAcdcAsync(HttpClient httpClient, Uri acdcUri, Uri kelUri, List<IDisposable> disposables, CancellationToken cancellationToken)
    {
        string acdcJson = await httpClient.GetStringAsync(acdcUri, cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization credential = AcdcTestSupport.Encode(acdcJson);
        MessageFieldMap map = AcdcJson.DecodeFieldMap(credential.Memory);
        AcdcMessage message = AcdcReader.Read(map);

        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(map, AcdcJson.Encode, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        if(!string.Equals((string)compact[AcdcMessageFields.Said]!, message.Said, StringComparison.Ordinal))
        {
            return null;
        }

        string kelJson = await httpClient.GetStringAsync(kelUri, cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization kelBytes = AcdcTestSupport.Encode(kelJson);
        IReadOnlyList<KeriSeal>? anchors = await AcdcFlowKit.VerifyKelAndReadAnchorsAsync(kelBytes.Memory, message.Issuer, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return anchors is not null && AcdcKeriBinding.FindDirectIssuanceSeal(anchors, message.Said) is not null ? message : null;
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
