using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The PKG-A state-level half of contract R2's <c>hmac-secret</c> CredRandom unconditional-mint proof
/// (CTAP 2.3 §12.7, snapshot line 13191's declarative generation step, line 13192's SHOULD, adopted):
/// <c>authenticatorMakeCredential</c> mints <see cref="CtapCredentialRecord.CredRandomWithUV"/>/
/// <see cref="CtapCredentialRecord.CredRandomWithoutUV"/> on EVERY credential regardless of whether the
/// request's own <c>extensions</c> map ever names <c>hmac-secret</c>.
/// </summary>
/// <remarks>
/// CredRandom is never echoed on any response (trap 9;
/// <see cref="CtapAuthenticatorTransitions.BuildCredentialEnumerationResponse"/>'s documented omission
/// of it despite echoing <c>largeBlobKey</c>), so decoding wire bytes alone cannot observe it — unlike
/// <see cref="CtapAuthenticatorLargeBlobKeyExtensionTests"/>'s wire-only convention, this file subscribes
/// to <see cref="CtapAuthenticatorSimulator"/>'s <see cref="TraceEntry{TState, TInput}.StateAfter"/>
/// stream, the same "state is otherwise unobservable" seam
/// <see cref="CtapAuthenticatorPinTokenIssuanceTests"/> already uses for token state. The full
/// mint-without-then-ga-serves proof (contract R2c) lives in
/// <see cref="CtapAuthenticatorHmacSecretGetAssertionFlowTests.HmacSecretServesAssertionForCredentialMintedWithoutTheExtension"/>,
/// which drives <c>authenticatorGetAssertion</c>'s own hmac-secret processing to consume the pair on the
/// wire; this file's own coverage is the state-level half alone.
/// </remarks>
[TestClass]
internal sealed class CtapAuthenticatorHmacSecretCredRandomStateTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An <c>authenticatorMakeCredential</c> request that never mentions <c>hmac-secret</c> still stores
    /// a credential whose <see cref="CtapCredentialRecord.CredRandomWithUV"/>/
    /// <see cref="CtapCredentialRecord.CredRandomWithoutUV"/> are both populated, exactly 32 bytes each,
    /// and mutually distinct — contract R2's unconditional mint, made observable through the trace
    /// stream rather than any response, since a credential minted here MUST be able to serve a LATER
    /// <c>hmac-secret</c> assertion the note's own rationale describes (snapshot line 13192).
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialWithoutHmacSecretExtensionStillMintsDistinctCredRandomPair()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("waveclose-credrandom-unconditional-mint");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        byte[] credentialIdBytes;
        using(simulator.Subscribe(trace))
        {
            CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
            using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
            CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            credentialIdBytes = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        string credentialIdHex = Convert.ToHexStringLower(credentialIdBytes);
        CtapCredentialRecord record = trace.Received[^1].StateAfter.CredentialsByCredentialId[credentialIdHex];

        Assert.HasCount(32, record.CredRandomWithUV.Memory);
        Assert.HasCount(32, record.CredRandomWithoutUV.Memory);
        Assert.IsFalse(
            record.CredRandomWithUV.Memory.Span.SequenceEqual(record.CredRandomWithoutUV.Memory.Span),
            "CredRandomWithUV and CredRandomWithoutUV must be two independently random values, never the same content.");
    }


    /// <summary>
    /// Two credentials minted by the SAME authenticator, neither requesting <c>hmac-secret</c>, receive
    /// mutually distinct CredRandom pairs — the entropy source is genuinely consulted per credential, not
    /// a fixed per-authenticator constant (mirrors <c>largeBlobKey</c>'s own per-credential distinctness
    /// proof, <see cref="CtapAuthenticatorLargeBlobKeyExtensionTests.MakeCredentialWithLargeBlobKeyMintsADifferentKeyPerCredential"/>).
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialMintsDistinctCredRandomPairsAcrossTwoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("waveclose-credrandom-distinct-per-credential");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        byte[] firstCredentialIdBytes;
        byte[] secondCredentialIdBytes;
        using(simulator.Subscribe(trace))
        {
            CtapMakeCredentialRequest firstRequest = BuildMakeCredentialRequest(pool, userId: BuildFixedBytes(16, 0x94));
            using PooledMemory firstResponse = await SendMakeCredentialAsync(simulator, firstRequest, pool, TestContext.CancellationToken);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstResponse.AsReadOnlySpan()[0]);
            CtapMakeCredentialResponse firstDecoded = CtapMakeCredentialResponseCborReader.Read(firstResponse.AsReadOnlyMemory()[1..]);
            using AuthenticatorData firstAuthenticatorData = AuthenticatorDataReader.Read(firstDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            firstCredentialIdBytes = firstAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();

            CtapMakeCredentialRequest secondRequest = BuildMakeCredentialRequest(pool, userId: BuildFixedBytes(16, 0x95));
            using PooledMemory secondResponse = await SendMakeCredentialAsync(simulator, secondRequest, pool, TestContext.CancellationToken);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, secondResponse.AsReadOnlySpan()[0]);
            CtapMakeCredentialResponse secondDecoded = CtapMakeCredentialResponseCborReader.Read(secondResponse.AsReadOnlyMemory()[1..]);
            using AuthenticatorData secondAuthenticatorData = AuthenticatorDataReader.Read(secondDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            secondCredentialIdBytes = secondAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        CtapAuthenticatorState finalState = trace.Received[^1].StateAfter;
        CtapCredentialRecord firstRecord = finalState.CredentialsByCredentialId[Convert.ToHexStringLower(firstCredentialIdBytes)];
        CtapCredentialRecord secondRecord = finalState.CredentialsByCredentialId[Convert.ToHexStringLower(secondCredentialIdBytes)];

        Assert.IsFalse(firstRecord.CredRandomWithUV.Memory.Span.SequenceEqual(secondRecord.CredRandomWithUV.Memory.Span));
        Assert.IsFalse(firstRecord.CredRandomWithoutUV.Memory.Span.SequenceEqual(secondRecord.CredRandomWithoutUV.Memory.Span));
    }
}
