using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Exercises the card simulator's GET CHALLENGE command and the effectful RNG action layer it introduces —
/// the first card command that needs entropy, the card-side equivalent of the TPM simulator's GetRandom.
/// The card draws its chip nonce RND.IC from an injected deterministic backend, so the real terminal
/// <see cref="ApduCommandExtensions"/> <c>GetChallengeAsync</c> returns exactly the modelled octets, and the
/// state-level trace shows the request → generate fold-back of the action loop.
/// </summary>
[TestClass]
internal sealed class CardSimulatorChallengeTests
{
    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task ReturnsTheModelledChallengeBytes()
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-challenge", [efCom], FillAscending);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        ApduResult<GetChallengeResponse> result = await device.GetChallengeAsync(
            8, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "GET CHALLENGE must succeed.");

        using GetChallengeResponse challenge = result.Value;
        Assert.AreEqual("A0A1A2A3A4A5A6A7", Convert.ToHexString(challenge.Challenge),
            "The card must return exactly the octets its RNG backend produced.");
    }


    [TestMethod]
    public async Task EmitsRequestedAndGeneratedTraceEntries()
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-challenge-trace", [efCom], FillAscending);
        var observer = new TestObserver<TraceEntry<CardSimulatorState, CardSimulatorInput>>();
        using IDisposable subscription = card.Subscribe(observer);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        using GetChallengeResponse challenge = (await device.GetChallengeAsync(
            8, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).Value;

        IReadOnlyList<TraceEntry<CardSimulatorState, CardSimulatorInput>> entries = observer.Received;
        Assert.HasCount(2, entries, "GET CHALLENGE steps twice: the command then the RNG fold-back.");

        Assert.IsInstanceOfType<GetChallengeRequested>(entries[0].Input, "The first step is the GET CHALLENGE command.");
        Assert.AreEqual("GetChallenge:Requested", entries[0].Label, "The command declares the entropy request.");
        Assert.IsInstanceOfType<CardRngAction>(entries[0].StateAfter.NextAction, "The command leaves the RNG action pending.");

        Assert.IsInstanceOfType<CardEntropyGenerated>(entries[1].Input, "The second step is the RNG fold-back.");
        Assert.AreEqual("GetChallenge:Generated", entries[1].Label, "The fold-back frames the response.");
        Assert.IsInstanceOfType<NullAction>(entries[1].StateAfter.NextAction, "The action is cleared once consumed.");
        Assert.IsInstanceOfType<ChallengeResponse>(entries[1].StateAfter.ResponseIntent, "The fold-back produced the challenge response.");
    }


    [TestMethod]
    public async Task DefaultRngAdvancesAcrossDraws()
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);

        //No RNG injected: the default deterministic counter stream must still differ across successive draws.
        using var card = new CardSimulator("passport-default-rng", [efCom]);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        using GetChallengeResponse first = (await device.GetChallengeAsync(
            8, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).Value;
        string firstHex = Convert.ToHexString(first.Challenge);

        using GetChallengeResponse second = (await device.GetChallengeAsync(
            8, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).Value;
        string secondHex = Convert.ToHexString(second.Challenge);

        Assert.AreNotEqual(firstHex, secondHex, "Successive challenges from the default RNG must differ.");
    }


    /// <summary>A deterministic RNG backend filling the destination with ascending octets from <c>0xA0</c>.</summary>
    private static void FillAscending(Span<byte> destination)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(0xA0 + i);
        }
    }
}
