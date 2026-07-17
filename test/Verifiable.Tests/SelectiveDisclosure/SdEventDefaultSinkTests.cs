using System.Buffers;
using System.Linq;
using System.Text;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Coverage for the wave-7 <see cref="CryptoEventSink"/> widening of the two SD-JWT/SD-CWT pipeline sign
/// sites (<see cref="SdJwtPipeline"/>/<see cref="SdCwtPipeline"/>, internal to <c>Verifiable.Json</c>/
/// <c>Verifiable.Cbor</c>). Unlike the JOSE/COSE sites, these two resolve and invoke a
/// <see cref="SigningDelegate"/> behind the fixed <see cref="SignPayloadDelegate"/> method-group contract
/// every caller (<c>SdJwtIssuanceExtensions</c>/<c>SdCwtIssuanceExtensions</c> and every test in this
/// project) wires as a method group — a trailing optional <see cref="CryptoEventSink"/> parameter would
/// break every one of those method-group conversions (C# requires exact arity), so the two sites instead
/// route unconditionally to <see cref="CryptographicKeyEvents.DefaultSink"/>, with no per-call override.
/// These tests prove the produced <see cref="SignatureProducedEvent"/> reaches the global
/// <see cref="CryptographicKeyEvents.Events"/> stream, closing the two sites the wave-7 scout censused.
/// </summary>
[TestClass]
internal sealed class SdEventDefaultSinkTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// <see cref="SdJwtPipeline.Sign"/>, reached through <see cref="SdJwtIssuance.IssueVerboseAsync(ReadOnlyMemory{byte}, IReadOnlySet{CredentialPath}, GenerateDisclosureSaltDelegate, PrivateKeyMemory, string, MemoryPool{byte}, string?, string?, DecoyDigestOptions, CancellationToken)"/>,
    /// publishes a <see cref="SignatureProducedEvent"/> to the global stream by default.
    /// </summary>
    [TestMethod]
    public async Task SdJwtIssuanceSignEmitsSignatureProducedEventToGlobalStream()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        byte[] payload = Encoding.UTF8.GetBytes("""{"iss":"did:example:wave7-sdjwt","given_name":"Alice"}""");
        var disclosablePaths = new HashSet<CredentialPath> { CredentialPath.FromJsonPointer("/given_name") };

        var observer = new TestObserver<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(observer))
        {
            (SdTokenResult result, _) = await SdJwtIssuance.IssueVerboseAsync(
                payload, disclosablePaths, TestSalts.DefaultGenerator(),
                privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsGreaterThan(0, result.SignedToken.Length);
        }

        Assert.Contains(
            (SignatureProducedEvent e) => e.Algorithm == CryptoAlgorithm.Ed25519,
            observer.Received.OfType<SignatureProducedEvent>(),
            "SdJwtPipeline.Sign must publish a SignatureProducedEvent to the global stream by default.");
    }


    /// <summary>
    /// <see cref="SdCwtPipeline.Sign"/>, reached through <see cref="SdCwtIssuance.IssueVerboseAsync(ReadOnlyMemory{byte}, IReadOnlySet{CredentialPath}, GenerateDisclosureSaltDelegate, PrivateKeyMemory, string, MemoryPool{byte}, string?, string?, DecoyDigestOptions, CancellationToken)"/>,
    /// publishes a <see cref="SignatureProducedEvent"/> to the global stream by default.
    /// </summary>
    [TestMethod]
    public async Task SdCwtIssuanceSignEmitsSignatureProducedEventToGlobalStream()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = "https://issuer.example/wave7-sdcwt",
            [501] = "wave7-disclosable"
        };
        byte[] cborBytes = SdCwtWireFixtures.SerializeCwtClaimMap(claims).ToArray();
        var disclosablePaths = new HashSet<CredentialPath> { CredentialPath.FromJsonPointer("/501") };

        var observer = new TestObserver<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(observer))
        {
            (SdTokenResult result, _) = await SdCwtIssuance.IssueVerboseAsync(
                cborBytes, disclosablePaths, TestSalts.DefaultGenerator(),
                privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsGreaterThan(0, result.SignedToken.Length);
        }

        Assert.Contains(
            (SignatureProducedEvent e) => e.Algorithm == CryptoAlgorithm.Ed25519,
            observer.Received.OfType<SignatureProducedEvent>(),
            "SdCwtPipeline.Sign must publish a SignatureProducedEvent to the global stream by default.");
    }
}
