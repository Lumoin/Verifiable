using System;
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
/// A multi-server, over-the-wire end-to-end flow for ACDC selective disclosure of an aggregate section: an Issuer
/// publishes its KEL on its socket, and a Discloser publishes a selective disclosure of an aggregate-section
/// credential on another socket — one blinded attribute block revealed as its detail, another blinded to its SAID. A
/// firewalled Disclosee fetches the disclosure and proves it from the bytes alone: every revealed block is authentic
/// and the blocks aggregate to the section's AGID (selective-disclosure Proof of Disclosure), the AGID is bound into
/// the credential's top-level SAID through its most-compact form, and the Issuer's KEL anchors that top-level SAID
/// (Proof of Issuance). The Disclosee learns the revealed block without learning the blinded one, yet proves both
/// are members of the one set the Issuer committed to.
/// </summary>
[TestClass]
internal sealed class AcdcAggregateDisclosureFlowTests
{
    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A selective disclosure validates across the sockets: the Disclosee confirms the section reveals the Issuee
    /// block and blinds the score block, verifies the disclosure aggregates to the committed AGID, confirms the AGID
    /// is bound into the credential's top-level SAID, and confirms the Issuer's KEL anchors that SAID.
    /// </summary>
    [TestMethod]
    public async Task SelectiveAggregateDisclosureVerifiesAcrossIssuerAndDiscloserSockets()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (string issuerAid, AcdcFlowKit.AggregateAcdc acdc, IReadOnlyList<AcdcFlowKit.SignedEvent> kel) =
                await AcdcFlowKit.MintAggregateIssuerAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost issuer = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            await using StaticContentHost discloser = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(issuer.BaseAddress, discloser.BaseAddress, "The Issuer and Discloser MUST serve from independent sockets.");

            issuer.Publish("/kel", AcdcFlowKit.SerializeKel(kel), "application/json");
            discloser.Publish("/acdc", acdc.Disclosed.Serialization, "application/json");

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient([issuer.Certificate, discloser.Certificate]);

            //Fetch the selective disclosure and fold it into a typed ACDC: the top-level reader now reads the
            //aggregate section 'A' as a first-class section into AcdcMessage.Aggregate.
            string json = await httpClient.GetStringAsync(new Uri(discloser.BaseAddress, "/acdc"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization credential = AcdcTestSupport.Encode(json);
            MessageFieldMap map = AcdcJson.DecodeFieldMap(credential.Memory);
            AcdcMessage credentialMessage = AcdcReader.Read(map);

            string topSaid = credentialMessage.Said;
            string credentialIssuer = credentialMessage.Issuer;
            Assert.IsNotNull(credentialMessage.Aggregate, "The disclosed credential carries a first-class aggregate section.");
            AcdcAggregateSection section = credentialMessage.Aggregate;

            //Selective disclosure: the Issuee block is revealed, the score block is blinded to its SAID.
            Assert.AreEqual(acdc.Agid, section.Agid, "The disclosed section carries the committed AGID.");
            Assert.HasCount(2, section.Blocks);
            var revealed = section.Blocks[0] as ExpandedAggregateBlock;
            Assert.IsNotNull(revealed, "The Issuee block is revealed as its detail.");
            Assert.IsTrue(revealed.Detail.TryGetString(AcdcMessageFields.Issuer, out string? subject) && subject == AcdcFlowWellKnown.AggregateSubjectAid, "The revealed block discloses the Issuee AID.");
            Assert.IsInstanceOfType<CompactAggregateBlock>(section.Blocks[1], "The score block is blinded to its SAID, disclosing no value.");

            //Proof of Disclosure: every revealed block is authentic and the blocks aggregate to the AGID.
            Assert.IsTrue(await AcdcAggregate.VerifyDisclosureAsync(section, AcdcJson.Encode, AcdcJson.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "The selective disclosure MUST verify: each revealed block is authentic and the AGID matches over the reconstructed list.");

            //Proof of Disclosure binding: the AGID is committed by the credential's top-level SAID.
            Assert.AreEqual(topSaid, await RecomputeCompactTopSaid(map, section.Agid), "The credential's top-level SAID MUST bind the AGID through its most-compact form.");

            //Proof of Issuance: the Issuer's KEL anchors the committed top-level SAID.
            string kelJson = await httpClient.GetStringAsync(new Uri(issuer.BaseAddress, "/kel"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization kelBytes = AcdcTestSupport.Encode(kelJson);
            IReadOnlyList<KeriSeal>? anchors = await AcdcFlowKit.VerifyKelAndReadAnchorsAsync(kelBytes.Memory, credentialIssuer, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            Assert.IsNotNull(anchors, "The Issuer KEL MUST verify and be the credential Issuer's.");
            Assert.IsNotNull(AcdcKeriBinding.FindDirectIssuanceSeal(anchors, topSaid), "Proof of Issuance: the Issuer KEL MUST anchor the committed top-level SAID.");

            Assert.IsTrue(discloser.WasRequested("/acdc"), "The selective disclosure MUST have been fetched over the socket.");
            Assert.IsTrue(issuer.WasRequested("/kel"), "The Issuer KEL MUST have been fetched over the socket.");
            Assert.AreEqual(issuerAid, credentialIssuer, "The credential names the Issuer AID the KEL establishes.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A disclosure whose revealed block was altered after issuance is rejected across the wire: changing the
    /// revealed Issuee AID makes the block no longer hash to its claimed SAID, so the reconstructed list no longer
    /// aggregates to the committed AGID and the selective disclosure fails to verify.
    /// </summary>
    [TestMethod]
    public async Task TamperedRevealedBlockFailsSelectiveDisclosureAcrossWire()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (string _, AcdcFlowKit.AggregateAcdc acdc, IReadOnlyList<AcdcFlowKit.SignedEvent> _) =
                await AcdcFlowKit.MintAggregateIssuerAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            //Alter the revealed block's Issuee AID: the block no longer hashes to its claimed SAID.
            string disclosedJson = Encoding.UTF8.GetString(acdc.Disclosed.Serialization.Span);
            string tampered = disclosedJson.Replace(AcdcFlowWellKnown.AggregateSubjectAid, AcdcFlowWellKnown.UnrelatedIssueeAid, StringComparison.Ordinal);
            Assert.AreNotEqual(disclosedJson, tampered, "The tamper must alter the revealed block.");

            await using StaticContentHost discloser = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            discloser.Publish("/acdc", Encoding.UTF8.GetBytes(tampered), "application/json");

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(discloser.Certificate);
            string json = await httpClient.GetStringAsync(new Uri(discloser.BaseAddress, "/acdc"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization credential = AcdcTestSupport.Encode(json);
            MessageFieldMap map = AcdcJson.DecodeFieldMap(credential.Memory);
            AcdcMessage credentialMessage = AcdcReader.Read(map);
            Assert.IsNotNull(credentialMessage.Aggregate, "The disclosed credential carries a first-class aggregate section.");
            AcdcAggregateSection section = credentialMessage.Aggregate;

            Assert.IsFalse(await AcdcAggregate.VerifyDisclosureAsync(section, AcdcJson.Encode, AcdcJson.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "A tampered revealed block MUST fail selective-disclosure verification.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Recomputes the top-level SAID over the credential's most-compact form, the aggregate section reduced to its
    /// AGID alone: copies the disclosed top-level fields, replaces the aggregate list with the AGID, and compacts.
    /// This is the binding a Disclosee checks to tie the AGID to the SAID the Issuer anchors.
    /// </summary>
    /// <param name="disclosed">The disclosed credential's top-level field map.</param>
    /// <param name="agid">The aggregate section's AGID, the most-compact form of the aggregate section.</param>
    /// <returns>The top-level SAID over the most-compact form.</returns>
    private static async Task<string> RecomputeCompactTopSaid(MessageFieldMap disclosed, string agid)
    {
        var compactTop = new MessageFieldMap(StringComparer.Ordinal);
        foreach((string label, object? value) in disclosed)
        {
            compactTop[label] = string.Equals(label, AcdcMessageFields.AttributeAggregate, StringComparison.Ordinal) ? agid : value;
        }

        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(compactTop, AcdcJson.Encode, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared).ConfigureAwait(false);

        return (string)compact[AcdcMessageFields.Said]!;
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
