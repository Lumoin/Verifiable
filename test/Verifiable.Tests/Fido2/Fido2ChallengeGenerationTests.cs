using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2ChallengeGeneration"/>: default length, the CR §13.4.3 minimum-length
/// floor, uniqueness across calls, Base64url round-tripping, and that generation flows through the
/// registered <see cref="CryptographicKeyEvents"/> entropy seam rather than a raw CSPRNG call.
/// </summary>
[TestClass]
internal sealed class Fido2ChallengeGenerationTests
{
    /// <summary>The default challenge length in bytes, mirrored from <see cref="Fido2ChallengeGeneration"/>.</summary>
    private const int DefaultByteLength = 32;


    /// <summary>The default-length overload produces a challenge decoding to exactly 32 bytes.</summary>
    [TestMethod]
    public void DefaultOverloadProducesThirtyTwoByteChallenge()
    {
        string challenge = Fido2ChallengeGeneration.Generate(BaseMemoryPool.Shared);

        byte[] decoded = Base64Url.DecodeFromChars(challenge);

        Assert.HasCount(DefaultByteLength, decoded);
    }


    /// <summary>A byte length at the CR §13.4.3 SHOULD-level floor (16) is accepted.</summary>
    [TestMethod]
    public void MinimumByteLengthIsAccepted()
    {
        string challenge = Fido2ChallengeGeneration.Generate(16, BaseMemoryPool.Shared);

        byte[] decoded = Base64Url.DecodeFromChars(challenge);

        Assert.HasCount(16, decoded);
    }


    /// <summary>A byte length one below the floor (15) is rejected.</summary>
    [TestMethod]
    public void BelowMinimumByteLengthIsRejected()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Fido2ChallengeGeneration.Generate(15, BaseMemoryPool.Shared));
    }


    /// <summary>A <see langword="null"/> pool is rejected.</summary>
    [TestMethod]
    public void NullPoolIsRejected()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => Fido2ChallengeGeneration.Generate(32, null!));
    }


    /// <summary>Two successive calls produce different challenges.</summary>
    [TestMethod]
    public void TwoCallsProduceDifferentChallenges()
    {
        string first = Fido2ChallengeGeneration.Generate(BaseMemoryPool.Shared);
        string second = Fido2ChallengeGeneration.Generate(BaseMemoryPool.Shared);

        Assert.AreNotEqual(first, second);
    }


    /// <summary>The returned string is valid Base64url and round-trips to the requested byte length.</summary>
    [TestMethod]
    public void ChallengeRoundTripsThroughBase64Url()
    {
        const int RequestedLength = 48;
        string challenge = Fido2ChallengeGeneration.Generate(RequestedLength, BaseMemoryPool.Shared);

        byte[] decoded = Base64Url.DecodeFromChars(challenge);
        string reencoded = Base64Url.EncodeToString(decoded);

        Assert.HasCount(RequestedLength, decoded);
        Assert.AreEqual(challenge, reencoded);
    }


    /// <summary>
    /// Generation flows through the registered <see cref="GenerateNonceDelegate"/> seam: an
    /// <see cref="EntropyConsumedEvent"/> is observed on <see cref="CryptographicKeyEvents.Events"/>,
    /// asserted by presence (via <see cref="Enumerable.OfType{TResult}(System.Collections.IEnumerable)"/>),
    /// never by an exact count — the subject is process-wide static and shared with concurrent tests.
    /// </summary>
    [TestMethod]
    public void GenerationEmitsEntropyEventThroughRegisteredSeam()
    {
        List<CryptoEvent> observed = new();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            string challenge = Fido2ChallengeGeneration.Generate(BaseMemoryPool.Shared);
            Assert.IsFalse(string.IsNullOrEmpty(challenge));
        }

        CryptoEvent[] snapshot;
        lock(observed)
        {
            snapshot = observed.ToArray();
        }

        EntropyConsumedEvent? nonceEvent = snapshot.OfType<EntropyConsumedEvent>().FirstOrDefault(e => e.Purpose == Purpose.Nonce);
        Assert.IsNotNull(nonceEvent);
    }


    /// <summary>
    /// Minimal <see cref="IObserver{T}"/> that appends every observed event to a shared sink,
    /// synchronizing every append: <see cref="CryptographicKeyEvents.Events"/>'s own remarks state the
    /// stream "may deliver concurrently from multiple threads" and that "a subscriber observing more
    /// than one operation at a time ... must synchronize its own state" — true here whenever this test
    /// runs alongside other parallel tests that also exercise the registered entropy seam, since <see
    /// cref="List{T}"/> is not itself thread-safe.
    /// </summary>
    private sealed class CollectingObserver(List<CryptoEvent> sink): IObserver<CryptoEvent>
    {
        /// <summary>No-op: this test never completes the observed sequence.</summary>
        public void OnCompleted()
        {
        }


        /// <summary>No-op: this test never expects an error from the observed sequence.</summary>
        public void OnError(Exception error)
        {
        }


        /// <summary>Appends <paramref name="value"/> to the sink under a lock.</summary>
        public void OnNext(CryptoEvent value)
        {
            lock(sink)
            {
                sink.Add(value);
            }
        }
    }
}
