using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorSimulator"/>'s <c>authenticatorGetNextAssertion</c> handler and
/// the multi-account <c>authenticatorGetAssertion</c> path that feeds it: most-recent-first ordering,
/// disclosure minimality (<c>user.id</c> only, on every response in the sequence), signature-counter
/// progression per credential, remembered-state lifecycle (exhaustion, discard-on-intervening-command,
/// replace-on-fresh-getAssertion, timer expiry via an injected <see cref="FakeTimeProvider"/>), and every
/// <c>CTAP2_ERR_NOT_ALLOWED</c> path — driven over <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>
/// with the shipped CBOR codecs.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorGetNextAssertionTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A multi-account <c>authenticatorGetAssertion</c> (two resident credentials at the same rp.id)
    /// signs and returns the MOST RECENTLY created credential first, carrying <c>numberOfCredentials: 2</c>
    /// and a <c>user</c> member with <c>id</c> only.
    /// </summary>
    [TestMethod]
    public async Task MultiAccountGetAssertionReturnsMostRecentCredentialWithNumberOfCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-multi-account-initial");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] olderUserId = BuildFixedBytes(16, 0xC0);
        byte[] newerUserId = BuildFixedBytes(16, 0xC1);

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, olderUserId, TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, newerUserId, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        try
        {
            Assert.AreEqual(2, decoded.NumberOfCredentials);
            Assert.IsNull(decoded.UserSelected);
            Assert.IsNotNull(decoded.User);
            Assert.AreSequenceEqual(newerUserId, decoded.User!.Id.AsReadOnlySpan().ToArray());
            Assert.IsNull(decoded.User.Name);
            Assert.IsNull(decoded.User.DisplayName);
        }
        finally
        {
            decoded.Credential.Id.Dispose();
            decoded.User?.Id.Dispose();
        }
    }


    /// <summary>
    /// <c>authenticatorGetNextAssertion</c> following a multi-account <c>authenticatorGetAssertion</c>
    /// returns the OLDER credential, omitting <c>numberOfCredentials</c> entirely, with a <c>user</c>
    /// member carrying <c>id</c> only.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionReturnsOlderCredentialWithoutNumberOfCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-multi-account-next");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] olderUserId = BuildFixedBytes(16, 0xC2);
        byte[] newerUserId = BuildFixedBytes(16, 0xC3);

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, olderUserId, TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, newerUserId, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        try
        {
            Assert.IsNull(decoded.NumberOfCredentials);
            Assert.IsNull(decoded.UserSelected);
            Assert.IsNotNull(decoded.User);
            Assert.AreSequenceEqual(olderUserId, decoded.User!.Id.AsReadOnlySpan().ToArray());
            Assert.IsNull(decoded.User.Name);
            Assert.IsNull(decoded.User.DisplayName);
        }
        finally
        {
            decoded.Credential.Id.Dispose();
            decoded.User?.Id.Dispose();
        }
    }


    /// <summary>
    /// Three resident credentials at the same rp.id are walked in strict most-recent-first order across
    /// the initial <c>authenticatorGetAssertion</c> and two <c>authenticatorGetNextAssertion</c> calls —
    /// verifying <see cref="CtapCredentialRecord.CreationSequence"/> ordering rather than just a
    /// two-credential swap.
    /// </summary>
    [TestMethod]
    public async Task ThreeAccountSequenceWalksInCreationOrderNewestFirst()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-three-account", residentCredentialCapacity: 3);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] firstUserId = BuildFixedBytes(16, 0xD0);
        byte[] secondUserId = BuildFixedBytes(16, 0xD1);
        byte[] thirdUserId = BuildFixedBytes(16, 0xD2);

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, firstUserId, TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, secondUserId, TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, thirdUserId, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        byte[] userIdFromFirstResponse = ReadAndDisposeUserId(
            await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken), pool);
        Assert.AreSequenceEqual(thirdUserId, userIdFromFirstResponse);

        byte[] userIdFromSecondResponse = ReadAndDisposeUserId(
            await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken), pool);
        Assert.AreSequenceEqual(secondUserId, userIdFromSecondResponse);

        byte[] userIdFromThirdResponse = ReadAndDisposeUserId(
            await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken), pool);
        Assert.AreSequenceEqual(firstUserId, userIdFromThirdResponse);
    }


    /// <summary>
    /// Each credential's signature counter advances independently: the initially returned (newer)
    /// credential reaches signCount 1 while the older credential — asserted for the first time via
    /// <c>authenticatorGetNextAssertion</c> — also starts from and reaches 1, not 2.
    /// </summary>
    [TestMethod]
    public async Task EachCredentialsSignCountAdvancesIndependently()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-signcount-independent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] olderUserId = BuildFixedBytes(16, 0xC4);
        byte[] newerUserId = BuildFixedBytes(16, 0xC5);

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, olderUserId, TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, newerUserId, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);
        CtapGetAssertionResponse firstDecoded = CtapGetAssertionResponseCborReader.Read(first.AsReadOnlyMemory()[1..], pool);
        using AuthenticatorData firstAuthenticatorData = AuthenticatorDataReader.Read(firstDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.AreEqual(1u, firstAuthenticatorData.SignCount);
        firstDecoded.Credential.Id.Dispose();
        firstDecoded.User?.Id.Dispose();

        using PooledMemory next = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        CtapGetAssertionResponse nextDecoded = CtapGetAssertionResponseCborReader.Read(next.AsReadOnlyMemory()[1..], pool);
        using AuthenticatorData nextAuthenticatorData = AuthenticatorDataReader.Read(nextDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.AreEqual(1u, nextAuthenticatorData.SignCount, "The older credential's own counter must start from zero, independent of the newer credential's.");
        nextDecoded.Credential.Id.Dispose();
        nextDecoded.User?.Id.Dispose();
    }


    /// <summary>
    /// The <c>authenticatorGetNextAssertion</c> signature covers the SAME <c>clientDataHash</c> the
    /// originating <c>authenticatorGetAssertion</c> request carried, verified independently with
    /// <see cref="ECDsa"/> against the credential's own public key.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionSignatureReusesOriginalClientDataHashAndVerifiesIndependently()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-clientdatahash-reuse");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] olderUserId = BuildFixedBytes(16, 0xC6);
        byte[] newerUserId = BuildFixedBytes(16, 0xC7);

        CtapWave2RegisteredCredential olderCredential = await RegisterCredentialAsync(simulator, pool, olderUserId, TestContext.CancellationToken);
        olderCredential.CredentialId.Dispose();
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, newerUserId, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);

        byte[] x = olderCredential.PublicKey.X!.Value.ToArray();
        byte[] y = olderCredential.PublicKey.Y!.Value.ToArray();

        //Independent-oracle site: a framework ECDsa instance, built from the credential's own
        //wire-exported public key, verifies the library-produced signature as a self-consistency
        //check against an implementation the library itself does not control.
        using ECDsa oracleKey = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });

        byte[] expectedClientDataHash = BuildFixedBytes(32, 0x20);
        byte[] message = new byte[decoded.AuthData.Length + expectedClientDataHash.Length];
        decoded.AuthData.Span.CopyTo(message);
        expectedClientDataHash.CopyTo(message, decoded.AuthData.Length);

        bool verified = oracleKey.VerifyData(message, decoded.Signature.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.IsTrue(verified, "The authenticatorGetNextAssertion signature must cover the originating request's own clientDataHash.");

        decoded.Credential.Id.Dispose();
        decoded.User?.Id.Dispose();
    }


    /// <summary>An <c>authenticatorGetNextAssertion</c> with no prior remembered state is rejected with <c>CTAP2_ERR_NOT_ALLOWED</c>.</summary>
    [TestMethod]
    public async Task NoRememberedStateReturnsNotAllowed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-no-state");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
        Assert.AreEqual(1, response.Length);
    }


    /// <summary>
    /// A single-credential <c>authenticatorGetAssertion</c> (the ordinary wave-2 case) remembers no
    /// sequence at all: a following <c>authenticatorGetNextAssertion</c> is rejected with
    /// <c>CTAP2_ERR_NOT_ALLOWED</c>.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionAfterSingleCredentialGetAssertionReturnsNotAllowed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-single-credential");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC8), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// Once every applicable credential has been returned (the initial response plus one
    /// <c>authenticatorGetNextAssertion</c> for a two-account sequence), a further
    /// <c>authenticatorGetNextAssertion</c> is rejected with <c>CTAP2_ERR_NOT_ALLOWED</c> — the
    /// credentialCounter-exhausted path.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionAfterCounterExhaustedReturnsNotAllowed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-counter-exhausted");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC9), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCA), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        using(PooledMemory next = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, next.AsReadOnlySpan()[0]);
        }

        using PooledMemory exhausted = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, exhausted.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// An intervening <c>authenticatorGetInfo</c> between a multi-account <c>authenticatorGetAssertion</c>
    /// and <c>authenticatorGetNextAssertion</c> discards the remembered sequence outright.
    /// </summary>
    [TestMethod]
    public async Task InterveningGetInfoDiscardsRememberedStateReturningNotAllowed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-intervening-getinfo");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCB), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCC), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        byte[] getInfoRequest = [WellKnownCtapCommands.GetInfo];
        using(PooledMemory getInfoResponse = await simulator.TransceiveAsync(getInfoRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getInfoResponse.AsReadOnlySpan()[0]);
        }

        using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// An intervening <c>authenticatorMakeCredential</c> discards the remembered sequence even when that
    /// intervening command itself is REJECTED (an unsupported algorithm here) — the discard is
    /// unconditional on the intervening operation happening, not on it succeeding.
    /// </summary>
    [TestMethod]
    public async Task InterveningFailedMakeCredentialStillDiscardsRememberedState()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-intervening-makecredential");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCD), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCE), TestContext.CancellationToken);

        CtapGetAssertionRequest getAssertionRequest = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, getAssertionRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        CtapMakeCredentialRequest failingRequest = BuildMakeCredentialRequest(pool, alg: WellKnownCoseAlgorithms.Rs256);
        using(PooledMemory makeCredentialResponse = await SendMakeCredentialAsync(simulator, failingRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.UnsupportedAlgorithm, makeCredentialResponse.AsReadOnlySpan()[0]);
        }

        using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An intervening unrecognized command byte discards the remembered sequence.</summary>
    [TestMethod]
    public async Task InterveningUnsupportedCommandDiscardsRememberedState()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-intervening-unsupported");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCF), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xD9), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        byte[] unsupportedRequest = [0xFE];
        using(PooledMemory unsupportedResponse = await simulator.TransceiveAsync(unsupportedRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCommand, unsupportedResponse.AsReadOnlySpan()[0]);
        }

        using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A fresh multi-account <c>authenticatorGetAssertion</c> for a DIFFERENT relying party REPLACES the
    /// remembered sequence: the following <c>authenticatorGetNextAssertion</c> walks the new relying
    /// party's accounts, never the earlier one's.
    /// </summary>
    [TestMethod]
    public async Task FreshGetAssertionForDifferentRelyingPartyReplacesRememberedState()
    {
        const string firstRpId = "gna-replace-a.example";
        const string secondRpId = "gna-replace-b.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-replace");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xE0), TestContext.CancellationToken, rpId: firstRpId);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xE1), TestContext.CancellationToken, rpId: firstRpId);

        byte[] secondRpOlderUserId = BuildFixedBytes(16, 0xE2);
        byte[] secondRpNewerUserId = BuildFixedBytes(16, 0xE3);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, secondRpOlderUserId, TestContext.CancellationToken, rpId: secondRpId);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, secondRpNewerUserId, TestContext.CancellationToken, rpId: secondRpId);

        using(PooledMemory firstRpResponse = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: firstRpId), pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstRpResponse.AsReadOnlySpan()[0]);
        }

        using(PooledMemory secondRpResponse = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: secondRpId), pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, secondRpResponse.AsReadOnlySpan()[0]);
        }

        byte[] userIdFromNext = ReadAndDisposeUserId(
            await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken), pool);
        Assert.AreSequenceEqual(secondRpOlderUserId, userIdFromNext, "authenticatorGetNextAssertion must walk the SECOND (replacing) relying party's sequence.");
    }


    /// <summary>
    /// An <c>authenticatorGetNextAssertion</c> issued within the 30-second timer window succeeds
    /// normally, using an injected <see cref="FakeTimeProvider"/> to control elapsed time deterministically.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionWithinTimerWindowSucceeds()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-timer-ok", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xF0), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xF1), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        timeProvider.Advance(TimeSpan.FromSeconds(29));

        using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// An <c>authenticatorGetNextAssertion</c> issued more than 30 seconds after the last stateful step
    /// is rejected with <c>CTAP2_ERR_NOT_ALLOWED</c> and discards the remembered sequence — a SECOND
    /// immediate <c>authenticatorGetNextAssertion</c>, with no further time advance, also fails with
    /// <c>CTAP2_ERR_NOT_ALLOWED</c> via the no-remembered-state path, proving the discard actually happened.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionAfterTimerExpiryReturnsNotAllowedAndDiscardsState()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-timer-expired", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xF2), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xF3), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        timeProvider.Advance(TimeSpan.FromSeconds(31));

        using(PooledMemory expired = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, expired.AsReadOnlySpan()[0]);
        }

        using PooledMemory second = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, second.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// The 30-second timer resets on every successful <c>authenticatorGetNextAssertion</c>: a
    /// three-account sequence with 20 seconds between each of the two follow-on calls (40 seconds total,
    /// exceeding the window measured from the very first call) still succeeds throughout, since each
    /// step only needs to stay within 30 seconds of the PREVIOUS stateful step, not the first one.
    /// </summary>
    [TestMethod]
    public async Task TimerResetsOnEachSuccessfulGetNextAssertion()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("gna-timer-reset", timeProvider: timeProvider, residentCredentialCapacity: 3);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xF4), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xF5), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xF6), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        timeProvider.Advance(TimeSpan.FromSeconds(20));
        using(PooledMemory second = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, second.AsReadOnlySpan()[0]);
        }

        timeProvider.Advance(TimeSpan.FromSeconds(20));
        using PooledMemory third = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, third.AsReadOnlySpan()[0]);
    }


    /// <summary>Decodes a response envelope's <c>user.id</c> bytes, disposing every carrier the decode produced.</summary>
    private static byte[] ReadAndDisposeUserId(PooledMemory response, MemoryPool<byte> pool)
    {
        using(response)
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

            CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
            byte[] userId = decoded.User!.Id.AsReadOnlySpan().ToArray();

            decoded.Credential.Id.Dispose();
            decoded.User.Id.Dispose();

            return userId;
        }
    }
}
