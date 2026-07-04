using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
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
/// A multi-server, over-the-wire end-to-end flow for an IPEX disclosure exchange: a Discloser publishes a grant
/// exchange message (and its KEL) on its socket, a firewalled Disclosee fetches and verifies the grant, and the
/// Disclosee publishes the admit it returns on its own socket, which the Discloser then fetches. IPEX is the routed
/// envelope on top of the credential proofs (the specification's
/// <see href="https://trustoverip.github.io/kswg-acdc-specification/#issuance-and-presentation-exchange-ipex">
/// Issuance and Presentation Exchange</see>, a non-normative protocol), so this exercises the routed grant-then-admit
/// exchange and the two proofs it carries — Proof of Disclosure of the embedded credential and Proof of Issuance via
/// the Issuer's KEL — rather than the exchange-envelope signature. The grant embeds the credential and routes it; the
/// admit chains to the grant by its SAID; each envelope is verified over its received bytes by its own SAID.
/// </summary>
[TestClass]
internal sealed class AcdcIpexExchangeFlowTests
{
    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The grant-then-admit exchange completes across the two sockets: the Disclosee verifies the grant envelope,
    /// extracts the embedded credential and proves it (Proof of Disclosure and Proof of Issuance), then returns an
    /// admit that chains to the grant by its SAID, which the Discloser fetches and confirms is the admit of the grant
    /// it sent. Every envelope and the KEL crosses its socket; nothing is shared in memory across the parties.
    /// </summary>
    [TestMethod]
    public async Task IpexGrantAdmitExchangeVerifiesAcrossDiscloserAndDdiscloseeSockets()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (string issuerAid, AcdcFlowKit.ExchangeMessage grant, string credentialSaid, IReadOnlyList<AcdcFlowKit.SignedEvent> kel) =
                await AcdcFlowKit.MintIpexGrantAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost discloser = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            await using StaticContentHost disclosee = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(discloser.BaseAddress, disclosee.BaseAddress, "The Discloser and Disclosee MUST serve from independent sockets.");

            //The Discloser publishes the grant (embedding the credential) and the Issuer KEL.
            discloser.Publish("/ipex/grant", grant.Serialization, "application/json");
            discloser.Publish("/kel", AcdcFlowKit.SerializeKel(kel), "application/json");

            using HttpClient httpClient = new();

            //The Disclosee fetches and verifies the grant envelope, then proves the credential it embeds.
            string grantSaid = await VerifyGrantAndProveCredentialAsync(httpClient, discloser.BaseAddress, credentialSaid, issuerAid, disposables, cancellationToken).ConfigureAwait(false);

            //The Disclosee returns an admit chaining to the grant by its SAID, and publishes it on its own socket.
            AcdcFlowKit.ExchangeMessage admit = await AcdcFlowKit.BuildIpexAdmit(AcdcFlowWellKnown.DiscloseeAid, grantSaid, disposables, BaseMemoryPool.Shared).ConfigureAwait(false);
            disclosee.Publish("/ipex/admit", admit.Serialization, "application/json");

            //The Discloser fetches the admit and confirms it is the admit of the grant it sent.
            string admitJson = await httpClient.GetStringAsync(new Uri(disclosee.BaseAddress, "/ipex/admit"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization admitBytes = AcdcTestSupport.Encode(admitJson);
            MessageFieldMap admitMap = AcdcJson.DecodeFieldMap(admitBytes.Memory);

            Assert.IsTrue(await AcdcSaid.VerifyAsync(admitBytes.Memory, ReadString(admitMap, ExchangeFields.Said), AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "The admit envelope MUST verify over its received bytes by its own SAID.");
            Assert.AreEqual(AcdcFlowWellKnown.IpexAdmitRoute, ReadString(admitMap, ExchangeFields.Route), "The returned message MUST be routed to admit.");
            Assert.AreEqual(grantSaid, ReadString(admitMap, ExchangeFields.Prior), "The admit MUST chain to the grant it accepts by the grant's SAID.");
            Assert.AreEqual(AcdcFlowWellKnown.DiscloseeAid, ReadString(admitMap, ExchangeFields.Sender), "The admit MUST name the Disclosee as its sender.");

            //Each envelope and the KEL crossed its respective socket.
            Assert.IsTrue(discloser.WasRequested("/ipex/grant"), "The grant MUST have been fetched from the Discloser over the socket.");
            Assert.IsTrue(discloser.WasRequested("/kel"), "The Issuer KEL MUST have been fetched from the Discloser over the socket.");
            Assert.IsTrue(disclosee.WasRequested("/ipex/admit"), "The admit MUST have been fetched from the Disclosee over the socket.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A tampered grant envelope is rejected across the wire: altering the credential the grant embeds (or any other
    /// byte of the envelope) leaves the grant's claimed SAID in place but makes the envelope no longer verify over its
    /// received bytes, so the Disclosee rejects the grant before trusting its routing or the credential it carries —
    /// the envelope's SAID binds everything it transports.
    /// </summary>
    [TestMethod]
    public async Task TamperedGrantEnvelopeIsRejectedAcrossWire()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (string issuerAid, AcdcFlowKit.ExchangeMessage grant, string _, IReadOnlyList<AcdcFlowKit.SignedEvent> _) =
                await AcdcFlowKit.MintIpexGrantAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            //Alter the Issuer AID the grant carries (in both the sender field and the embedded credential): the grant's
            //claimed SAID is untouched, but the envelope no longer hashes to it.
            string grantJson = Encoding.UTF8.GetString(grant.Serialization.Span);
            string tampered = grantJson.Replace(issuerAid, AcdcFlowWellKnown.UnrelatedIssueeAid, StringComparison.Ordinal);
            Assert.AreNotEqual(grantJson, tampered, "The tamper must alter the grant envelope.");

            await using StaticContentHost discloser = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            discloser.Publish("/ipex/grant", Encoding.UTF8.GetBytes(tampered), "application/json");

            using HttpClient httpClient = new();
            string fetched = await httpClient.GetStringAsync(new Uri(discloser.BaseAddress, "/ipex/grant"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization grantBytes = AcdcTestSupport.Encode(fetched);

            Assert.IsFalse(await AcdcSaid.VerifyAsync(grantBytes.Memory, grant.Said, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "A tampered grant envelope MUST fail its SAID verification over the received bytes.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Fetches the grant, verifies its envelope by its own SAID and its route, extracts the embedded credential, and
    /// proves it: Proof of Disclosure (the embedded credential's SAID over its canonical bytes) and Proof of Issuance
    /// (the Issuer's fetched KEL anchors a seal committing to that SAID under the credential's named Issuer).
    /// </summary>
    /// <param name="httpClient">The Disclosee's HTTP client.</param>
    /// <param name="discloserBase">The Discloser's base address.</param>
    /// <param name="expectedCredentialSaid">The credential SAID the grant is expected to carry.</param>
    /// <param name="expectedIssuer">The Issuer AID the credential and its KEL are expected to name.</param>
    /// <param name="disposables">The list reconstructed buffers are tracked on for disposal.</param>
    /// <param name="cancellationToken">A token to cancel the verification.</param>
    /// <returns>The grant message's SAID, the value the admit chains to.</returns>
    private static async Task<string> VerifyGrantAndProveCredentialAsync(HttpClient httpClient, Uri discloserBase, string expectedCredentialSaid, string expectedIssuer, List<IDisposable> disposables, CancellationToken cancellationToken)
    {
        string grantJson = await httpClient.GetStringAsync(new Uri(discloserBase, "/ipex/grant"), cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization grantBytes = AcdcTestSupport.Encode(grantJson);
        MessageFieldMap grantMap = AcdcJson.DecodeFieldMap(grantBytes.Memory);

        string grantSaid = ReadString(grantMap, ExchangeFields.Said);
        Assert.IsTrue(await AcdcSaid.VerifyAsync(grantBytes.Memory, grantSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "The grant envelope MUST verify over its received bytes by its own SAID.");
        Assert.AreEqual(AcdcFlowWellKnown.IpexGrantRoute, ReadString(grantMap, ExchangeFields.Route), "The fetched message MUST be routed to grant.");

        //Extract the embedded credential and re-serialize it to its canonical bytes.
        MessageFieldMap credentialMap = ReadMap(ReadMap(grantMap, ExchangeFields.Embeds), ExchangeFields.EmbeddedCredential);
        var canonical = new ArrayBufferWriter<byte>();
        AcdcJson.Encode(credentialMap, canonical);

        string credentialSaid = ReadString(credentialMap, AcdcMessageFields.Said);
        Assert.AreEqual(expectedCredentialSaid, credentialSaid, "The grant embeds the credential the Discloser granted.");
        Assert.IsTrue(await AcdcSaid.VerifyAsync(canonical.WrittenMemory, credentialSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "Proof of Disclosure: the embedded credential's SAID MUST verify over its canonical bytes.");

        string credentialIssuer = ReadString(credentialMap, AcdcMessageFields.Issuer);
        Assert.AreEqual(expectedIssuer, credentialIssuer, "The embedded credential names the granting Issuer.");

        //Proof of Issuance: the Issuer's KEL anchors a seal committing to the credential's SAID.
        string kelJson = await httpClient.GetStringAsync(new Uri(discloserBase, "/kel"), cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization kelBytes = AcdcTestSupport.Encode(kelJson);
        IReadOnlyList<KeriSeal>? anchors = await AcdcFlowKit.VerifyKelAndReadAnchorsAsync(kelBytes.Memory, credentialIssuer, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        Assert.IsNotNull(anchors, "The Issuer KEL MUST verify and be the credential Issuer's.");
        Assert.IsNotNull(AcdcKeriBinding.FindDirectIssuanceSeal(anchors, credentialSaid), "Proof of Issuance: the Issuer KEL MUST anchor a seal committing to the credential's SAID.");

        return grantSaid;
    }


    /// <summary>Reads a nested field map from a decoded message.</summary>
    /// <param name="map">The decoded message field map.</param>
    /// <param name="label">The field label.</param>
    /// <returns>The nested field map.</returns>
    private static MessageFieldMap ReadMap(MessageFieldMap map, string label)
    {
        if(!map.TryGetValue(label, out object? value) || value is not MessageFieldMap nested)
        {
            throw new InvalidOperationException($"The message is missing the nested field '{label}'.");
        }

        return nested;
    }


    /// <summary>Reads a required string field from a decoded message.</summary>
    /// <param name="map">The decoded message field map.</param>
    /// <param name="label">The field label.</param>
    /// <returns>The field value.</returns>
    private static string ReadString(MessageFieldMap map, string label)
    {
        if(!map.TryGetString(label, out string? value))
        {
            throw new InvalidOperationException($"The message is missing the required field '{label}'.");
        }

        return value;
    }


    /// <summary>
    /// The exchange-message (<c>exn</c>) field labels this flow reads. They are named here rather than reused from
    /// <see cref="AcdcMessageFields"/> because two of the wire characters mean something different in an exchange
    /// message than in an ACDC body: <c>e</c> is the embeds block (not the edge section) and <c>r</c> is the route
    /// (not the rule section).
    /// </summary>
    private static class ExchangeFields
    {
        /// <summary>The SAID label <c>d</c>: the exchange message's own self-addressing digest.</summary>
        public static string Said { get; } = "d";

        /// <summary>The sender label <c>i</c>: the AID of the party that sent the exchange message.</summary>
        public static string Sender { get; } = "i";

        /// <summary>The prior-message label <c>p</c>: the SAID of the message this one chains to.</summary>
        public static string Prior { get; } = "p";

        /// <summary>The route label <c>r</c>: the exchange step the message performs.</summary>
        public static string Route { get; } = "r";

        /// <summary>The embeds label <c>e</c>: the block of artifacts the exchange message carries.</summary>
        public static string Embeds { get; } = "e";

        /// <summary>The embedded credential label <c>acdc</c>: the disclosed credential within the embeds block.</summary>
        public static string EmbeddedCredential { get; } = "acdc";
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
