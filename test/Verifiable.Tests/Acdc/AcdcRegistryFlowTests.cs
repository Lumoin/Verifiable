using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Json;
using Verifiable.Keri;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// A multi-server, over-the-wire end-to-end flow for the registry-bound (indirect) ACDC binding: an Issuer party
/// publishes its KEL and its transaction-event-log registry on its socket, a Discloser publishes the credential on
/// another socket, and a firewalled Disclosee verifies the credential's issuance and revocation state from the
/// bytes it fetches. The credential references the registry by its SAID; the Disclosee fetches the registry,
/// verifies each event's SAID over its bytes, validates the chain, reads the credential's latest transaction state,
/// and confirms the registry inception is anchored in the Issuer's verified KEL — the hierarchical binding that
/// makes the credential's state a verifiable commitment by the Issuer that survives Issuer key rotation.
/// </summary>
[TestClass]
internal sealed class AcdcRegistryFlowTests
{
    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An issued credential verifies across the sockets: the Disclosee confirms Proof of Disclosure, validates the
    /// registry chain and reads the credential's state as <c>issued</c>, confirms the credential references that
    /// registry, and confirms the registry inception is anchored in the Issuer's verified KEL.
    /// </summary>
    [TestMethod]
    public async Task IssuedCredentialVerifiesWithRegistryStateAcrossWire()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (string _, AcdcFlowKit.MintedAcdc acdc, IReadOnlyList<AcdcFlowKit.RegistryEvent> registry, IReadOnlyList<AcdcFlowKit.SignedEvent> kel) =
                await AcdcFlowKit.MintRegistryIssuerAsync(includeRevocation: false, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost issuer = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            await using StaticContentHost discloser = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);

            issuer.Publish("/kel", AcdcFlowKit.SerializeKel(kel), "application/json");
            issuer.Publish("/registry", AcdcFlowKit.SerializeRegistry(registry), "application/json");
            discloser.Publish("/acdc", acdc.Serialization, "application/json");

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient([issuer.Certificate, discloser.Certificate]);

            //Proof of Disclosure, and the credential's registry reference.
            string credentialJson = await httpClient.GetStringAsync(new Uri(discloser.BaseAddress, "/acdc"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization credential = AcdcTestSupport.Encode(credentialJson);
            AcdcMessage message = AcdcReader.Read(AcdcJson.DecodeFieldMap(credential.Memory));
            Assert.IsTrue(await AcdcSaid.VerifyAsync(credential.Memory, message.Said, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "Proof of Disclosure: the credential's SAID MUST verify over its received bytes.");

            //The registry state: fetch, validate the chain, and read the credential's latest state.
            (string registrySaid, string? state) = await VerifyRegistryStateAsync(httpClient, issuer.BaseAddress, message, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(message.RegistryDigest, registrySaid, "The credential MUST reference the registry whose chain validated.");
            Assert.AreEqual("issued", state, "The credential's latest registry state MUST be issued.");

            //The indirect binding: the registry inception's SAID is anchored in the Issuer's verified KEL.
            string kelJson = await httpClient.GetStringAsync(new Uri(issuer.BaseAddress, "/kel"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization kelBytes = AcdcTestSupport.Encode(kelJson);
            IReadOnlyList<KeriSeal>? anchors = await AcdcFlowKit.VerifyKelAndReadAnchorsAsync(kelBytes.Memory, message.Issuer, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            Assert.IsNotNull(anchors, "The Issuer KEL MUST verify and be the credential Issuer's.");
            Assert.IsNotNull(AcdcKeriBinding.FindDirectIssuanceSeal(anchors, registrySaid), "The registry inception MUST be anchored in the Issuer's KEL.");

            Assert.IsTrue(issuer.WasRequested("/registry"), "The registry MUST have been fetched over the socket.");
            Assert.IsTrue(issuer.WasRequested("/kel"), "The Issuer KEL MUST have been fetched over the socket.");
            Assert.IsTrue(discloser.WasRequested("/acdc"), "The credential MUST have been fetched over the socket.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A revoked credential is rejected by its registry state across the wire: the registry's latest update for the
    /// credential sets it <c>revoked</c>, so the Disclosee reads that state and rejects the disclosure even though
    /// the credential and the chain are otherwise valid.
    /// </summary>
    [TestMethod]
    public async Task RevokedCredentialIsRejectedByRegistryStateAcrossWire()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (string _, AcdcFlowKit.MintedAcdc acdc, IReadOnlyList<AcdcFlowKit.RegistryEvent> registry, IReadOnlyList<AcdcFlowKit.SignedEvent> _) =
                await AcdcFlowKit.MintRegistryIssuerAsync(includeRevocation: true, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost issuer = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            issuer.Publish("/registry", AcdcFlowKit.SerializeRegistry(registry), "application/json");

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(issuer.Certificate);
            AcdcMessage message = AcdcReader.Read(AcdcJson.DecodeFieldMap(acdc.Serialization));

            (string registrySaid, string? state) = await VerifyRegistryStateAsync(httpClient, issuer.BaseAddress, message, cancellationToken).ConfigureAwait(false);

            Assert.AreEqual(message.RegistryDigest, registrySaid, "The chain validates and matches the credential's registry.");
            Assert.AreEqual("revoked", state, "The credential's latest registry state MUST be revoked, so a Disclosee rejects it.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Fetches the registry over the wire, verifies each event's SAID over its bytes, validates the chain, and reads
    /// the credential's latest transaction state.
    /// </summary>
    /// <param name="httpClient">The Disclosee's HTTP client.</param>
    /// <param name="issuerBase">The Issuer's base address.</param>
    /// <param name="credential">The disclosed credential.</param>
    /// <param name="cancellationToken">A token to cancel the verification.</param>
    /// <returns>The registry SAID and the credential's latest state (or <see langword="null"/> when the registry holds no state for it).</returns>
    private static async Task<(string RegistrySaid, string? State)> VerifyRegistryStateAsync(HttpClient httpClient, Uri issuerBase, AcdcMessage credential, CancellationToken cancellationToken)
    {
        string registryJson = await httpClient.GetStringAsync(new Uri(issuerBase, "/registry"), cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization registryBytes = AcdcTestSupport.Encode(registryJson);

        List<string>? eventTexts = JsonSerializer.Deserialize<List<string>>(registryBytes.Bytes);
        if(eventTexts is null)
        {
            throw new InvalidOperationException("The published registry did not deserialize to events.");
        }

        var events = new List<AcdcRegistryEvent>(eventTexts.Count);
        string? state = null;
        foreach(string eventText in eventTexts)
        {
            using AcdcTestSupport.EncodedSerialization eventBytes = AcdcTestSupport.Encode(eventText);
            AcdcRegistryEvent registryEvent = AcdcRegistryReader.Read(AcdcJson.DecodeFieldMap(eventBytes.Memory));

            Assert.IsTrue(await AcdcSaid.VerifyAsync(eventBytes.Memory, registryEvent.Said, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "Each registry event's SAID MUST verify over its received bytes.");
            events.Add(registryEvent);

            if(registryEvent is RegistryUpdateEvent update && string.Equals(update.TransactionAcdcSaid, credential.Said, StringComparison.Ordinal))
            {
                state = update.TransactionState;
            }
        }

        string registrySaid = AcdcRegistry.ValidateChain(events);

        return (registrySaid, state);
    }


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
