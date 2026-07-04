using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
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
/// A multi-server, over-the-wire end-to-end disclosure flow for an ACDC: an Issuer party and a Discloser (Holder)
/// party each run their own in-process Kestrel listener on a distinct loopback socket, and a firewalled Disclosee
/// reconstructs the credential and its proofs from the bytes it fetches over those sockets — nothing is shared
/// in-memory across the parties. The Disclosee verifies both proofs the specification requires of a disclosed ACDC:
/// Proof of Disclosure (the credential's SAID over its received serialization) and Proof of Issuance (the Issuer's
/// KEL, fetched and replayed, anchors a seal committing to that SAID, under the AID the credential names as its
/// Issuer). This is the issuance-and-presentation exchange reduced to its verifiable core, run across real sockets.
/// </summary>
[TestClass]
internal sealed class AcdcDisclosureFlowTests
{
    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The full disclosure flow validates across two sockets: the Disclosee fetches the credential from the
    /// Discloser and the Issuer's KEL from the Issuer, verifies the credential's SAID over its received bytes
    /// (Proof of Disclosure), replays the Issuer's KEL, and confirms it anchors the credential's SAID under the
    /// AID the credential names as Issuer (Proof of Issuance). Both fetches are proven to have crossed their socket.
    /// </summary>
    [TestMethod]
    public async Task DisclosedAcdcVerifiesAcrossIssuerAndDiscloserSockets()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            //The Issuer mints its KEL and a credential issued under its AID, anchoring the credential's SAID.
            (string issuerAid, AcdcFlowKit.MintedAcdc acdc, IReadOnlyList<AcdcFlowKit.SignedEvent> kel) =
                await AcdcFlowKit.MintIssuerAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost issuer = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            await using StaticContentHost discloser = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(issuer.BaseAddress, discloser.BaseAddress, "The Issuer and Discloser MUST serve from independent sockets.");

            //The Issuer publishes its KEL; the Discloser (Holder) publishes the credential it received at issuance.
            issuer.Publish("/kel", AcdcFlowKit.SerializeKel(kel), "application/json");
            discloser.Publish("/acdc", acdc.Serialization, "application/json");

            using HttpClient httpClient = new();

            //Proof of Disclosure: fetch the credential from the Discloser and verify its SAID over the received bytes.
            string credentialJson = await httpClient.GetStringAsync(new Uri(discloser.BaseAddress, "/acdc"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization credential = AcdcTestSupport.Encode(credentialJson);
            AcdcMessage message = AcdcReader.Read(AcdcJson.DecodeFieldMap(credential.Memory));

            Assert.AreEqual(acdc.Said, message.Said, "The disclosed credential is the issued one.");
            Assert.IsTrue(await AcdcSaid.VerifyAsync(credential.Memory, message.Said, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "Proof of Disclosure: the credential's SAID MUST verify over its received bytes.");

            //Proof of Issuance: fetch and replay the Issuer's KEL, then confirm it anchors the credential's SAID.
            KeriDigestSeal? issuanceSeal = await VerifyIssuanceAsync(httpClient, issuer.BaseAddress, message, disposables, cancellationToken).ConfigureAwait(false);
            Assert.IsNotNull(issuanceSeal, "Proof of Issuance: the Issuer's KEL MUST anchor a seal committing to the credential's SAID.");

            //Both fetches crossed their respective sockets.
            Assert.IsTrue(discloser.WasRequested("/acdc"), "The credential MUST have been fetched from the Discloser over the socket.");
            Assert.IsTrue(issuer.WasRequested("/kel"), "The Issuer KEL MUST have been fetched over the socket.");
            Assert.AreEqual(issuerAid, message.Issuer, "The credential names the Issuer AID the KEL establishes.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A credential tampered after issuance fails Proof of Disclosure across the wire: altering any byte of the
    /// served credential makes its SAID no longer verify over the received bytes.
    /// </summary>
    [TestMethod]
    public async Task TamperedCredentialFailsProofOfDisclosure()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            (string _, AcdcFlowKit.MintedAcdc acdc, IReadOnlyList<AcdcFlowKit.SignedEvent> _) =
                await AcdcFlowKit.MintIssuerAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost discloser = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);

            //Flip a character of the served bytes: the serialization still parses but no longer matches the SAID
            //computed over the original bytes.
            string original = Encoding.UTF8.GetString(acdc.Serialization.Span);
            string tampered = original[..^2] + (original[^2] == 'A' ? 'B' : 'A') + original[^1];
            Assert.AreNotEqual(original, tampered, "The tamper must alter the served bytes.");
            discloser.Publish("/acdc", Encoding.UTF8.GetBytes(tampered), "application/json");

            using HttpClient httpClient = new();
            string credentialJson = await httpClient.GetStringAsync(new Uri(discloser.BaseAddress, "/acdc"), cancellationToken).ConfigureAwait(false);
            using AcdcTestSupport.EncodedSerialization credential = AcdcTestSupport.Encode(credentialJson);

            Assert.IsFalse(await AcdcSaid.VerifyAsync(credential.Memory, acdc.Said, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, cancellationToken), "A tampered credential MUST fail Proof of Disclosure.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A credential whose Issuer KEL anchors nothing for it fails Proof of Issuance: the Disclosee replays the
    /// fetched KEL but finds no issuance seal for the credential's SAID.
    /// </summary>
    [TestMethod]
    public async Task UnanchoredCredentialFailsProofOfIssuance()
    {
        var disposables = new List<IDisposable>();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            //Two independently minted Issuers: the credential from one, the KEL from the other, so the KEL anchors a
            //different credential's SAID and not this one.
            (string _, AcdcFlowKit.MintedAcdc acdc, IReadOnlyList<AcdcFlowKit.SignedEvent> _) =
                await AcdcFlowKit.MintIssuerAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            (string _, AcdcFlowKit.MintedAcdc _, IReadOnlyList<AcdcFlowKit.SignedEvent> otherKel) =
                await AcdcFlowKit.MintIssuerAsync(disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            await using StaticContentHost issuer = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            issuer.Publish("/kel", AcdcFlowKit.SerializeKel(otherKel), "application/json");

            using HttpClient httpClient = new();
            AcdcMessage message = AcdcReader.Read(AcdcJson.DecodeFieldMap(acdc.Serialization));

            KeriDigestSeal? issuanceSeal = await VerifyIssuanceAsync(httpClient, issuer.BaseAddress, message, disposables, cancellationToken).ConfigureAwait(false);

            Assert.IsNull(issuanceSeal, "A KEL that anchors no seal for the credential's SAID MUST fail Proof of Issuance.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Proof of Issuance over the wire: fetch the Issuer KEL, reconstruct and replay it from the fetched bytes,
    /// require every event to verify and the inception to establish the AID the credential names as Issuer, then
    /// return the issuance seal that commits to the credential's SAID (or <see langword="null"/> when none does).
    /// </summary>
    /// <param name="httpClient">The Disclosee's HTTP client.</param>
    /// <param name="issuerBase">The Issuer's base address.</param>
    /// <param name="credential">The disclosed credential.</param>
    /// <param name="disposables">The list reconstructed buffers are tracked on for disposal.</param>
    /// <param name="cancellationToken">A token to cancel the verification.</param>
    /// <returns>The issuance seal, or <see langword="null"/> when the KEL does not anchor the credential.</returns>
    private static async Task<KeriDigestSeal?> VerifyIssuanceAsync(HttpClient httpClient, Uri issuerBase, AcdcMessage credential, List<IDisposable> disposables, CancellationToken cancellationToken)
    {
        string kelJson = await httpClient.GetStringAsync(new Uri(issuerBase, "/kel"), cancellationToken).ConfigureAwait(false);
        using AcdcTestSupport.EncodedSerialization kelBytes = AcdcTestSupport.Encode(kelJson);

        IReadOnlyList<KeriSeal>? anchors = await AcdcFlowKit.VerifyKelAndReadAnchorsAsync(kelBytes.Memory, credential.Issuer, disposables, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return anchors is null ? null : AcdcKeriBinding.FindDirectIssuanceSeal(anchors, credential.Said);
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
