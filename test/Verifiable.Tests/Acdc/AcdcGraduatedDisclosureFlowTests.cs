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
/// A multi-server, over-the-wire end-to-end flow for ACDC graduated disclosure: an Issuer publishes its KEL on its
/// socket, and a Discloser publishes the SAME credential at two graduation levels on another socket — its
/// most-compact form (every section reduced to its SAID) and its expanded form (the attribute block disclosed). A
/// firewalled Disclosee fetches both variants and proves each: the received form compacts to the top-level SAID it
/// claims (Proof of Disclosure), both variants compact to the one SAID, and the one Issuer KEL anchor that commits
/// to that SAID covers both variants (Proof of Issuance). This is the specification's most-compact-form SAID
/// property exercised across real sockets: a single Issuer commitment to the compact-form SAID authenticates every
/// graduation level a Discloser may present, so the Discloser chooses how much to reveal without a new Issuer
/// signature, yet cannot alter what is revealed.
/// </summary>
[TestClass]
internal sealed class AcdcGraduatedDisclosureFlowTests
{
    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Both graduation levels validate across the sockets to the one committed SAID: the Disclosee proves each
    /// variant compacts to its claimed SAID, confirms the compact variant blinds the attribute values while the
    /// expanded variant discloses them, confirms both variants are the one credential, and confirms one Issuer KEL
    /// anchor commits to that SAID — so the single commitment covers both graduation levels.
    /// </summary>
    [TestMethod]
    public async Task GraduatedDisclosureVerifiesBothVariantsToOneCommittedSaidAcrossWire()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (string issuerAid, AcdcFlowKit.GraduatedAcdc graduated, IReadOnlyList<AcdcFlowKit.SignedEvent> kel) =
                await AcdcFlowKit.MintGraduatedIssuerAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost issuer = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            await using StaticContentHost discloser = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(issuer.BaseAddress, discloser.BaseAddress, "The Issuer and Discloser MUST serve from independent sockets.");

            //The Issuer publishes its KEL; the Discloser publishes the one credential at two graduation levels.
            issuer.Publish("/kel", AcdcFlowKit.SerializeKel(kel), "application/json");
            discloser.Publish("/acdc/compact", graduated.Compact.Serialization, "application/json");
            discloser.Publish("/acdc/expanded", graduated.Expanded.Serialization, "application/json");

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient([issuer.Certificate, discloser.Certificate]);

            //Proof of Disclosure for each variant: the received form compacts to the top-level SAID it claims.
            (AcdcMessage compactMessage, string compactCompactedSaid) = await FetchAndCompactAsync(httpClient, new Uri(discloser.BaseAddress, "/acdc/compact"), cancellationToken).ConfigureAwait(false);
            (AcdcMessage expandedMessage, string expandedCompactedSaid) = await FetchAndCompactAsync(httpClient, new Uri(discloser.BaseAddress, "/acdc/expanded"), cancellationToken).ConfigureAwait(false);

            Assert.AreEqual(compactMessage.Said, compactCompactedSaid, "Proof of Disclosure: the compact variant MUST compact to the SAID it claims.");
            Assert.AreEqual(expandedMessage.Said, expandedCompactedSaid, "Proof of Disclosure: the expanded variant MUST compact to the SAID it claims.");

            //Both graduation levels are the one credential, identified by the one committed SAID.
            Assert.AreEqual(compactMessage.Said, expandedMessage.Said, "Both variants MUST be the one credential, sharing the one top-level SAID.");
            Assert.AreEqual(graduated.Said, compactMessage.Said, "The committed SAID the Issuer anchors MUST be the SAID both variants carry.");

            //Graduated disclosure: the compact variant blinds the attribute values behind the section SAID; the
            //expanded variant discloses them, yet both prove to the one SAID.
            Assert.IsInstanceOfType<CompactAcdcSection>(compactMessage.Attribute, "The compact variant carries the attribute section as its SAID, disclosing no values.");
            var disclosed = expandedMessage.Attribute as ExpandedAcdcSection;
            Assert.IsNotNull(disclosed, "The expanded variant discloses the attribute block.");
            Assert.IsTrue(disclosed.Detail.TryGetString(AcdcMessageFields.Issuer, out string? subject) && subject == AcdcFlowWellKnown.GraduatedSubjectAid, "The expanded variant reveals the attribute block's Issuee.");
            Assert.IsTrue(disclosed.Detail.TryGetString(AcdcFlowWellKnown.GraduatedNameLabel, out string? name) && name == AcdcFlowWellKnown.GraduatedSubjectName, "The expanded variant reveals the attribute block's disclosed field.");

            //Proof of Issuance: one Issuer KEL anchor commits to the one SAID, covering both graduation levels.
            string kelJson = await httpClient.GetStringAsync(new Uri(issuer.BaseAddress, "/kel"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization kelBytes = AcdcTestSupport.Encode(kelJson);
            IReadOnlyList<KeriSeal>? anchors = await AcdcFlowKit.VerifyKelAndReadAnchorsAsync(kelBytes.Memory, expandedMessage.Issuer, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            Assert.IsNotNull(anchors, "The Issuer KEL MUST verify and be the credential Issuer's.");
            Assert.IsNotNull(AcdcKeriBinding.FindDirectIssuanceSeal(anchors, graduated.Said), "Proof of Issuance: one Issuer KEL anchor MUST commit to the committed SAID, covering both graduation levels.");

            //Both graduation levels crossed the Discloser socket and the KEL crossed the Issuer socket.
            Assert.IsTrue(discloser.WasRequested("/acdc/compact"), "The compact variant MUST have been fetched over the socket.");
            Assert.IsTrue(discloser.WasRequested("/acdc/expanded"), "The expanded variant MUST have been fetched over the socket.");
            Assert.IsTrue(issuer.WasRequested("/kel"), "The Issuer KEL MUST have been fetched over the socket.");
            Assert.AreEqual(issuerAid, expandedMessage.Issuer, "The credential names the Issuer AID the KEL establishes.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A tampered expanded disclosure fails Proof of Disclosure across the wire: altering a disclosed attribute value
    /// while leaving the claimed top-level SAID untouched makes the expanded form compact to a different SAID, so it
    /// no longer proves disclosure of the committed credential. The discloser may choose how much to reveal, but the
    /// SAID binds what is revealed.
    /// </summary>
    [TestMethod]
    public async Task TamperedExpandedDisclosureFailsProofOfDisclosureAcrossWire()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (string _, AcdcFlowKit.GraduatedAcdc graduated, IReadOnlyList<AcdcFlowKit.SignedEvent> _) =
                await AcdcFlowKit.MintGraduatedIssuerAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            //Alter the disclosed attribute value, leaving the claimed top-level SAID in place: only what the expanded
            //form reveals changed, so it compacts to a SAID other than the one it still claims.
            string expandedJson = Encoding.UTF8.GetString(graduated.Expanded.Serialization.Span);
            string tampered = expandedJson.Replace(AcdcFlowWellKnown.GraduatedSubjectName, "Charles Dodgson", StringComparison.Ordinal);
            Assert.AreNotEqual(expandedJson, tampered, "The tamper must alter the disclosed attribute value.");

            await using StaticContentHost discloser = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            discloser.Publish("/acdc/expanded", Encoding.UTF8.GetBytes(tampered), "application/json");

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(discloser.Certificate);
            (AcdcMessage message, string compactedSaid) = await FetchAndCompactAsync(httpClient, new Uri(discloser.BaseAddress, "/acdc/expanded"), cancellationToken).ConfigureAwait(false);

            Assert.AreEqual(graduated.Said, message.Said, "The tamper leaves the claimed SAID in place; only the disclosed value changed.");
            Assert.AreNotEqual(message.Said, compactedSaid, "A tampered expanded disclosure MUST fail Proof of Disclosure: it compacts to a different SAID than it claims.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Fetches an ACDC variant and compacts it: parses the received form and computes the top-level SAID over its
    /// most-compact form, the value a caller checks against the variant's claimed SAID (Proof of Disclosure).
    /// </summary>
    /// <param name="httpClient">The Disclosee's HTTP client.</param>
    /// <param name="variantUri">The variant's URI.</param>
    /// <param name="cancellationToken">A token to cancel the fetch.</param>
    /// <returns>The parsed message and the top-level SAID its most-compact form yields.</returns>
    private static async Task<(AcdcMessage Message, string CompactedSaid)> FetchAndCompactAsync(HttpClient httpClient, Uri variantUri, CancellationToken cancellationToken)
    {
        string json = await httpClient.GetStringAsync(variantUri, cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization variant = AcdcTestSupport.Encode(json);
        MessageFieldMap map = AcdcJson.DecodeFieldMap(variant.Memory);
        AcdcMessage message = AcdcReader.Read(map);

        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(map, AcdcJson.Encode, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return (message, (string)compact[AcdcMessageFields.Said]!);
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
