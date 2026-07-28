using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="OcspRevocationChecker"/>: the <see cref="CheckCertificateRevocationStatusAsyncDelegate"/>
/// implementation that reads a certificate's Authority Information Access OCSP responder URIs
/// (<see cref="RevocationSourceFactsExtractor"/>), builds a request per configured responder
/// (<see cref="OcspRequests"/>), and verifies the response (<see cref="OcspResponseVerification"/>)
/// fail-closed. The transport is a configured, no-closure-capture <see cref="MapBackedOcspResponder"/> test
/// double answering from a fixed responder-URI-to-response map — never a live network call. The capstone
/// tests drive the checker through the real shipped <see cref="MicrosoftX509Functions.ValidateChainAsync"/>
/// composition over a minted three-tier chain, mirroring <c>CrlRevocationCheckerTests</c>' capstone shape for
/// the offline CRL source.
/// </summary>
[TestClass]
internal sealed class OcspRevocationCheckerTests
{
    /// <summary>The default minted certificate validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The default minted certificate validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The <c>thisUpdate</c> instant a fresh, in-window minted response uses.</summary>
    private static DateTimeOffset ThisUpdate { get; } = new(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The <c>nextUpdate</c> instant a fresh, in-window minted response uses.</summary>
    private static DateTimeOffset NextUpdate { get; } = new(2025, 6, 8, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The instant every check in this class evaluates a response against; inside <see cref="ThisUpdate"/>/<see cref="NextUpdate"/>'s window.</summary>
    private static DateTimeOffset ValidationTime { get; } = new(2025, 6, 2, 0, 0, 0, TimeSpan.Zero);

    /// <summary>A <c>thisUpdate</c> instant whose window has already elapsed by <see cref="ValidationTime"/>, for the stale-response fixture.</summary>
    private static DateTimeOffset StaleThisUpdate { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>A <c>nextUpdate</c> instant before <see cref="ValidationTime"/>, for the stale-response fixture.</summary>
    private static DateTimeOffset StaleNextUpdate { get; } = new(2024, 1, 8, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The revocation time a minted <c>Revoked</c> response carries.</summary>
    private static DateTimeOffset RevocationTime { get; } = new(2025, 5, 15, 12, 0, 0, TimeSpan.Zero);


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>A verified <c>Good</c> response from the configured responder reports <see cref="CertificateRevocationStatus.Good"/>.</summary>
    [TestMethod]
    public async Task ReportsGoodWhenTheResponderConfirmsGoodStatus()
    {
        const string responderUri = "http://ocsp.checker.example.test/good";
        using OcspCheckerScenario scenario = BuildScenario(responderUri);
        PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: null);
        using var responder = new MapBackedOcspResponder(new Dictionary<string, PkiCertificateMemory?> { [responderUri] = response });
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.Certificate, [scenario.Issuer], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Good, status, "A verified Good response reports Good.");
    }


    /// <summary>A verified <c>Revoked</c> response reports <see cref="CertificateRevocationStatus.Revoked"/>.</summary>
    [TestMethod]
    public async Task ReportsRevokedWhenTheResponderConfirmsRevokedStatus()
    {
        const string responderUri = "http://ocsp.checker.example.test/revoked";
        using OcspCheckerScenario scenario = BuildScenario(responderUri);
        PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Revoked, ThisUpdate, NextUpdate, RevocationTime, revocationReason: 1, echoNonce: null);
        using var responder = new MapBackedOcspResponder(new Dictionary<string, PkiCertificateMemory?> { [responderUri] = response });
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.Certificate, [scenario.Issuer], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Revoked, status, "A verified Revoked response reports Revoked.");
    }


    /// <summary>An unreachable responder (the transport delegate returns <see langword="null"/>) reports <see cref="CertificateRevocationStatus.Unknown"/>.</summary>
    [TestMethod]
    public async Task ReportsUnknownWhenTheResponderIsUnreachable()
    {
        const string responderUri = "http://ocsp.checker.example.test/unreachable";
        using OcspCheckerScenario scenario = BuildScenario(responderUri);
        using var responder = new MapBackedOcspResponder(new Dictionary<string, PkiCertificateMemory?> { [responderUri] = null });
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.Certificate, [scenario.Issuer], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "An unreachable responder cannot determine a status, so the fail-closed result is Unknown.");
    }


    /// <summary>
    /// The certificate carries two OCSP responder URIs; the first answers with unparseable garbage, the
    /// second with a verified <c>Good</c> response. The checker tries the next configured URI rather than
    /// failing the whole check on one bad responder.
    /// </summary>
    [TestMethod]
    public async Task TriesTheNextResponderUriWhenTheFirstReturnsGarbage()
    {
        const string firstUri = "http://ocsp.checker.example.test/garbage";
        const string secondUri = "http://ocsp.checker.example.test/valid";
        using OcspCheckerScenario scenario = BuildScenario(firstUri, secondUri);
        PkiCertificateMemory garbage = BuildGarbageResponse();
        PkiCertificateMemory good = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: null);
        using var responder = new MapBackedOcspResponder(new Dictionary<string, PkiCertificateMemory?> { [firstUri] = garbage, [secondUri] = good });
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.Certificate, [scenario.Issuer], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Good, status, "A garbage response from the first URI is skipped in favour of the valid answer from the second.");
    }


    /// <summary>A certificate with no Authority Information Access extension carries no OCSP responder URI, so the check reports <see cref="CertificateRevocationStatus.Unknown"/> without attempting a fetch.</summary>
    [TestMethod]
    public async Task ReportsUnknownWhenTheCertificateCarriesNoAiaExtension()
    {
        using OcspCheckerScenario scenario = BuildScenario();
        using var responder = new MapBackedOcspResponder(new Dictionary<string, PkiCertificateMemory?>());
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.Certificate, [scenario.Issuer], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "A certificate without an AIA extension carries no responder URI to check against.");
    }


    /// <summary>When no supplied issuer candidate matches the target's issuer Name, the check reports <see cref="CertificateRevocationStatus.Unknown"/> without attempting a fetch.</summary>
    [TestMethod]
    public async Task ReportsUnknownWhenNoIssuerCandidateMatches()
    {
        const string responderUri = "http://ocsp.checker.example.test/no-issuer";
        using OcspCheckerScenario scenario = BuildScenario(responderUri);
        using var responder = new MapBackedOcspResponder(new Dictionary<string, PkiCertificateMemory?>());
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.Certificate, [], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "With no issuer candidate to build a CertID against, the status cannot be determined.");
    }


    /// <summary>A response that fails the RFC 6960 §3.2 verification checks — here, stale relative to the validation time — reports <see cref="CertificateRevocationStatus.Unknown"/>, never the response's own claimed status.</summary>
    [TestMethod]
    public async Task ReportsUnknownWhenTheResponseIsStale()
    {
        const string responderUri = "http://ocsp.checker.example.test/stale";
        using OcspCheckerScenario scenario = BuildScenario(responderUri);
        PkiCertificateMemory staleResponse = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, StaleThisUpdate, StaleNextUpdate, echoNonce: null);
        using var responder = new MapBackedOcspResponder(new Dictionary<string, PkiCertificateMemory?> { [responderUri] = staleResponse });
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.Certificate, [scenario.Issuer], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "A stale response never verifies, so the checker cannot use its claimed Good status.");
    }


    /// <summary>
    /// Fail-closed pin: a response whose envelope claims <c>Good</c> but whose signature is corrupted never
    /// verifies, so the checker must never report <see cref="CertificateRevocationStatus.Good"/> from it —
    /// the result is <see cref="CertificateRevocationStatus.Unknown"/>.
    /// </summary>
    [TestMethod]
    public async Task NeverReportsGoodWithoutAVerifiedResponse()
    {
        const string responderUri = "http://ocsp.checker.example.test/corrupted";
        using OcspCheckerScenario scenario = BuildScenario(responderUri);
        PkiCertificateMemory goodResponse = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: null);
        PkiCertificateMemory corrupted = OcspTestFixtures.FlipLastByte(goodResponse);
        using var responder = new MapBackedOcspResponder(new Dictionary<string, PkiCertificateMemory?> { [responderUri] = corrupted });
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.Certificate, [scenario.Issuer], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "A response claiming Good but failing signature verification must never be reported as Good.");
        Assert.AreNotEqual(CertificateRevocationStatus.Good, status, "Restated: an unverified response is never Good, regardless of its claimed CertStatus.");
    }


    /// <summary>
    /// The capstone: a real minted three-tier chain (Root CA, Intermediate CA, Leaf — each carrying an AIA
    /// extension and an Authority Key Identifier) is validated through the shipped
    /// <see cref="MicrosoftX509Functions.ValidateChainAsync"/> composition with <see cref="OcspRevocationChecker"/>
    /// as the revocation source; a <c>Good</c> OCSP status from the configured responder for both the leaf
    /// and the intermediate lets validation complete and return the leaf's public key. The verifier side
    /// reconstructs everything from the wire DER carriers produced by minting; no parsed object crosses from
    /// mint to verify.
    /// </summary>
    [TestMethod]
    public async Task ChainValidationReturnsTheLeafKeyWhenOcspReportsGood()
    {
        using CapstoneScenario scenario = BuildCapstoneScenario();
        using MapBackedOcspResponder responder = BuildCapstoneResponder(scenario, OcspCertificateStatus.Good);
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);
        PkiCertificateMemory[] chain = [scenario.LeafCarrier, scenario.IntermediateCarrier];
        PkiCertificateMemory[] anchors = [scenario.RootCarrier];

        using PublicKeyMemory leafKey = await MicrosoftX509Functions.ValidateChainAsync(
            chain, anchors, ValidationTime, BaseMemoryPool.Shared, checker.CheckAsync, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(leafKey, "A Good OCSP status for both the leaf and the intermediate lets chain validation complete and return the leaf key.");
    }


    /// <summary>The capstone's negative twin: a leaf the configured responder reports <c>Revoked</c> for is rejected by chain validation with a <see cref="SecurityException"/>.</summary>
    [TestMethod]
    public async Task ChainValidationRejectsARevokedLeaf()
    {
        using CapstoneScenario scenario = BuildCapstoneScenario();
        using MapBackedOcspResponder responder = BuildCapstoneResponder(scenario, OcspCertificateStatus.Revoked);
        var checker = new OcspRevocationChecker(responder.FetchAsync, includeNonce: false);
        PkiCertificateMemory[] chain = [scenario.LeafCarrier, scenario.IntermediateCarrier];
        PkiCertificateMemory[] anchors = [scenario.RootCarrier];

        await Assert.ThrowsExactlyAsync<SecurityException>(async () =>
            await MicrosoftX509Functions.ValidateChainAsync(
                chain, anchors, ValidationTime, BaseMemoryPool.Shared, checker.CheckAsync, TestContext.CancellationToken)
            .ConfigureAwait(false), "A leaf the OCSP responder reports Revoked for must be rejected by chain validation.").ConfigureAwait(false);
    }


    /// <summary>Builds a 3-byte payload that is not a well-formed DER structure, tagged as an OCSP response — the "responder returned garbage" fixture.</summary>
    /// <returns>The pooled response carrier; ownership transfers to whichever <see cref="MapBackedOcspResponder"/> map it is placed in.</returns>
    private static PkiCertificateMemory BuildGarbageResponse()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(3);
        ReadOnlySpan<byte> garbageBytes = [0x01, 0x02, 0x03];
        garbageBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);
    }


    /// <summary>
    /// Mints a Root CA and a leaf issued by it, the leaf carrying an <c>id-ad-ocsp</c> Authority Information
    /// Access entry for each given URI (none when called with no URIs), plus the leaf and issuer DER carriers.
    /// </summary>
    /// <param name="ocspResponderUris">The OCSP responder URIs the leaf's AIA extension carries, in order; empty for no AIA extension at all.</param>
    /// <returns>The scenario; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every minted certificate and carrier transfers to the returned OcspCheckerScenario, which the caller disposes; the nested try/catch disposes already-minted parts if a later step throws.")]
    private static OcspCheckerScenario BuildScenario(params string[] ocspResponderUris)
    {
        MintedCertificate root = OcspTestFixtures.MintRootCa("OCSP Checker Root", NotBefore, NotAfter);
        try
        {
            List<X509Extension> extensions = [];
            if(ocspResponderUris.Length > 0)
            {
                var aiaEntries = new (string AccessMethod, Asn1Tag NameTag, string NameValue)[ocspResponderUris.Length];
                for(int i = 0; i < ocspResponderUris.Length; i++)
                {
                    aiaEntries[i] = OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, ocspResponderUris[i]);
                }

                extensions.Add(OcspTestFixtures.CreateAuthorityInfoAccessExtension(aiaEntries));
            }

            MintedCertificate leaf = OcspTestFixtures.MintCertificate(root.Certificate, root.Key, "OCSP Checker Leaf", NotBefore, NotAfter, extensions);
            try
            {
                PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
                try
                {
                    PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

                    return new OcspCheckerScenario(root, leaf, certificate, issuer);
                }
                catch
                {
                    certificate.Dispose();
                    throw;
                }
            }
            catch
            {
                leaf.Dispose();
                throw;
            }
        }
        catch
        {
            root.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Mints the capstone's three-tier chain: a Root CA, an Intermediate CA carrying an AIA extension for
    /// <see cref="CapstoneScenario.IntermediateResponderUri"/>, and a Leaf carrying an AIA extension for
    /// <see cref="CapstoneScenario.LeafResponderUri"/> — every non-root certificate chained with an Authority
    /// Key Identifier per <see cref="OcspTestFixtures.MintCertificate"/>, so chain building never sees an
    /// ambiguous same-subject issuer.
    /// </summary>
    /// <returns>The scenario; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every minted certificate and carrier transfers to the returned CapstoneScenario, which the caller disposes; the nested try/catch disposes already-minted parts if a later step throws.")]
    private static CapstoneScenario BuildCapstoneScenario()
    {
        const string intermediateResponderUri = "http://ocsp.capstone.example.test/intermediate";
        const string leafResponderUri = "http://ocsp.capstone.example.test/leaf";

        MintedCertificate root = OcspTestFixtures.MintRootCa("OCSP Capstone Root", NotBefore, NotAfter);
        try
        {
            X509Extension intermediateAia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
                OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, intermediateResponderUri));
            MintedCertificate intermediate = OcspTestFixtures.MintCertificate(
                root.Certificate, root.Key, "OCSP Capstone Intermediate", NotBefore, NotAfter, [intermediateAia], isCa: true);
            try
            {
                X509Extension leafAia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
                    OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, leafResponderUri));
                MintedCertificate leaf = OcspTestFixtures.MintCertificate(
                    intermediate.Certificate, intermediate.Key, "OCSP Capstone Leaf", NotBefore, NotAfter, [leafAia]);
                try
                {
                    PkiCertificateMemory leafCarrier = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
                    try
                    {
                        PkiCertificateMemory intermediateCarrier = OcspTestFixtures.ToCertificateCarrier(intermediate.Certificate);
                        try
                        {
                            PkiCertificateMemory rootCarrier = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

                            return new CapstoneScenario(root, intermediate, leaf, leafCarrier, intermediateCarrier, rootCarrier, intermediateResponderUri, leafResponderUri);
                        }
                        catch
                        {
                            intermediateCarrier.Dispose();
                            throw;
                        }
                    }
                    catch
                    {
                        leafCarrier.Dispose();
                        throw;
                    }
                }
                catch
                {
                    leaf.Dispose();
                    throw;
                }
            }
            catch
            {
                intermediate.Dispose();
                throw;
            }
        }
        catch
        {
            root.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Builds the capstone responder map: the Intermediate's OCSP URI always answers <c>Good</c> (signed by
    /// the Root), so a capstone test isolates the LEAF's OCSP outcome; the Leaf's OCSP URI answers with
    /// <paramref name="leafStatus"/> (signed by the Intermediate, its direct issuer).
    /// </summary>
    /// <param name="scenario">The capstone scenario to answer for.</param>
    /// <param name="leafStatus">The <c>CertStatus</c> the leaf's configured responder reports.</param>
    /// <returns>The responder; the caller disposes it.</returns>
    private static MapBackedOcspResponder BuildCapstoneResponder(CapstoneScenario scenario, OcspCertificateStatus leafStatus)
    {
        PkiCertificateMemory intermediateResponse = OcspTestFixtures.MintOcspResponse(
            scenario.Intermediate.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: null);

        DateTimeOffset? revocationTime = leafStatus == OcspCertificateStatus.Revoked ? RevocationTime : null;
        int? revocationReason = leafStatus == OcspCertificateStatus.Revoked ? 1 : null;
        PkiCertificateMemory leafResponse = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Intermediate.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Intermediate.Certificate, scenario.Intermediate.Key, responderIdByKey: false, embeddedCertificates: null,
            leafStatus, ThisUpdate, NextUpdate, revocationTime, revocationReason, echoNonce: null);

        return new MapBackedOcspResponder(new Dictionary<string, PkiCertificateMemory?>
        {
            [scenario.IntermediateResponderUri] = intermediateResponse,
            [scenario.LeafResponderUri] = leafResponse
        });
    }


    /// <summary>A minted Root CA and leaf, the leaf's certificate carrier, and its issuer carrier — disposed together.</summary>
    /// <param name="Root">The Root CA.</param>
    /// <param name="Leaf">The target leaf certificate.</param>
    /// <param name="Certificate">The leaf's DER carrier.</param>
    /// <param name="Issuer">The Root CA's DER carrier.</param>
    private sealed record OcspCheckerScenario(
        MintedCertificate Root,
        MintedCertificate Leaf,
        PkiCertificateMemory Certificate,
        PkiCertificateMemory Issuer): IDisposable
    {
        /// <inheritdoc/>
        public void Dispose()
        {
            Issuer.Dispose();
            Certificate.Dispose();
            Leaf.Dispose();
            Root.Dispose();
        }
    }


    /// <summary>The capstone's minted Root CA, Intermediate CA, and Leaf, their DER carriers, and the OCSP responder URI each non-root certificate's AIA extension carries — disposed together.</summary>
    /// <param name="Root">The Root CA.</param>
    /// <param name="Intermediate">The Intermediate CA, issued by <paramref name="Root"/>.</param>
    /// <param name="Leaf">The Leaf, issued by <paramref name="Intermediate"/>.</param>
    /// <param name="LeafCarrier">The Leaf's DER carrier, chain index 0 for <see cref="MicrosoftX509Functions.ValidateChainAsync"/>.</param>
    /// <param name="IntermediateCarrier">The Intermediate's DER carrier, chain index 1.</param>
    /// <param name="RootCarrier">The Root's DER carrier, the sole trust anchor.</param>
    /// <param name="IntermediateResponderUri">The URI the Intermediate's AIA extension names.</param>
    /// <param name="LeafResponderUri">The URI the Leaf's AIA extension names.</param>
    private sealed record CapstoneScenario(
        MintedCertificate Root,
        MintedCertificate Intermediate,
        MintedCertificate Leaf,
        PkiCertificateMemory LeafCarrier,
        PkiCertificateMemory IntermediateCarrier,
        PkiCertificateMemory RootCarrier,
        string IntermediateResponderUri,
        string LeafResponderUri): IDisposable
    {
        /// <inheritdoc/>
        public void Dispose()
        {
            RootCarrier.Dispose();
            IntermediateCarrier.Dispose();
            LeafCarrier.Dispose();
            Leaf.Dispose();
            Intermediate.Dispose();
            Root.Dispose();
        }
    }
}


/// <summary>
/// A <see cref="FetchOcspResponseAsyncDelegate"/> test double backed by a fixed responder-URI-to-response map
/// prepared at construction — a configured object holding its data explicitly, rather than a lambda capturing
/// per-test state, per the codebase's no-closure-capture convention for callback seams. A missing map entry,
/// or one mapped to <see langword="null"/>, simulates an unreachable responder.
/// </summary>
internal sealed class MapBackedOcspResponder: IDisposable
{
    /// <summary>The prepared responder-URI-to-response map; a <see langword="null"/> value simulates an unreachable responder.</summary>
    private IReadOnlyDictionary<string, PkiCertificateMemory?> ResponsesByUri { get; }


    /// <summary>Initializes a new <see cref="MapBackedOcspResponder"/> over a prepared response map. Ownership of every non-<see langword="null"/> map value transfers to this instance.</summary>
    /// <param name="responsesByUri">The responder URI to response map.</param>
    internal MapBackedOcspResponder(IReadOnlyDictionary<string, PkiCertificateMemory?> responsesByUri)
    {
        ResponsesByUri = responsesByUri;
    }


    /// <summary>Implements <see cref="FetchOcspResponseAsyncDelegate"/>: returns a fresh pooled clone of the mapped response, or <see langword="null"/> when the URI is unmapped or maps to <see langword="null"/>.</summary>
    /// <param name="context">The fetch context; only <see cref="OcspFetchContext.ResponderUri"/> is consulted.</param>
    /// <param name="pool">The memory pool the returned clone is rented from.</param>
    /// <param name="cancellationToken">A cancellation token; unused, as this test double performs no I/O.</param>
    /// <returns>The cloned response, or <see langword="null"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the cloned carrier transfers to the caller via the returned ValueTask.")]
    internal ValueTask<PkiCertificateMemory?> FetchAsync(OcspFetchContext context, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(!ResponsesByUri.TryGetValue(context.ResponderUri, out PkiCertificateMemory? stored) || stored is null)
        {
            return ValueTask.FromResult<PkiCertificateMemory?>(null);
        }

        IMemoryOwner<byte> owner = pool.Rent(stored.Length);
        stored.AsReadOnlySpan().CopyTo(owner.Memory.Span);

        return ValueTask.FromResult<PkiCertificateMemory?>(new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse));
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        foreach(PkiCertificateMemory? response in ResponsesByUri.Values)
        {
            response?.Dispose();
        }
    }
}
