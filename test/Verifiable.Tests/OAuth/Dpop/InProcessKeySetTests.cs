using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.OAuth.Server.Keys;

namespace Verifiable.Tests.OAuth.Dpop;

/// <summary>
/// Exercises <see cref="InProcessKeySet{TKey}"/>'s slot semantics with
/// <see cref="HmacKey"/> as the concrete type. The slot transitions are
/// parameter-uniform across <typeparamref name="TKey"/>; using HmacKey
/// here mirrors the consumer that actually uses this primitive today.
/// </summary>
[TestClass]
internal sealed class InProcessKeySetTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void AddIncomingPopulatesIncomingSlot()
    {
        InProcessKeySet<HmacKey> keySet = new();
        HmacKey key = NewKey("kid-1");

        keySet.AddIncoming(key);

        KeySet<HmacKey> snap = keySet.Snapshot();
        Assert.HasCount(1, snap.Incoming);
        Assert.AreEqual("kid-1", snap.Incoming[0].Kid);
        Assert.IsTrue(snap.Current.IsEmpty);
    }


    [TestMethod]
    public void PromoteIncomingToCurrentMovesKey()
    {
        InProcessKeySet<HmacKey> keySet = new();
        keySet.AddIncoming(NewKey("kid-1"));

        keySet.PromoteIncomingToCurrent("kid-1");

        KeySet<HmacKey> snap = keySet.Snapshot();
        Assert.IsTrue(snap.Incoming.IsEmpty);
        Assert.HasCount(1, snap.Current);
        Assert.AreEqual("kid-1", snap.Current[0].Kid);
    }


    [TestMethod]
    public void RetireCurrentMovesKeyToRetiring()
    {
        InProcessKeySet<HmacKey> keySet = new(new KeySet<HmacKey>
        {
            Current = [NewKey("kid-1")]
        });

        keySet.RetireCurrent("kid-1");

        KeySet<HmacKey> snap = keySet.Snapshot();
        Assert.IsTrue(snap.Current.IsEmpty);
        Assert.HasCount(1, snap.Retiring);
    }


    [TestMethod]
    public void ArchiveRetiringMovesKeyToHistorical()
    {
        InProcessKeySet<HmacKey> keySet = new(new KeySet<HmacKey>
        {
            Retiring = [NewKey("kid-1")]
        });

        keySet.ArchiveRetiring("kid-1");

        KeySet<HmacKey> snap = keySet.Snapshot();
        Assert.IsTrue(snap.Retiring.IsEmpty);
        Assert.HasCount(1, snap.Historical);
    }


    [TestMethod]
    public void PromoteIncomingThrowsForUnknownKid()
    {
        InProcessKeySet<HmacKey> keySet = new();

        Assert.ThrowsExactly<InvalidOperationException>(
            () => keySet.PromoteIncomingToCurrent("kid-missing"));
    }


    [TestMethod]
    public void RetireCurrentThrowsForUnknownKid()
    {
        InProcessKeySet<HmacKey> keySet = new();

        Assert.ThrowsExactly<InvalidOperationException>(
            () => keySet.RetireCurrent("kid-missing"));
    }


    [TestMethod]
    public void ResolveByKidFindsKeyInAnySlot()
    {
        HmacKey incoming = NewKey("k-incoming");
        HmacKey current = NewKey("k-current");
        HmacKey retiring = NewKey("k-retiring");
        HmacKey historical = NewKey("k-historical");

        InProcessKeySet<HmacKey> keySet = new(new KeySet<HmacKey>
        {
            Incoming = [incoming],
            Current = [current],
            Retiring = [retiring],
            Historical = [historical]
        });

        Assert.AreSame(incoming, keySet.ResolveByKid("k-incoming"));
        Assert.AreSame(current, keySet.ResolveByKid("k-current"));
        Assert.AreSame(retiring, keySet.ResolveByKid("k-retiring"));
        Assert.AreSame(historical, keySet.ResolveByKid("k-historical"));
        Assert.IsNull(keySet.ResolveByKid("k-unknown"));
    }


    [TestMethod]
    public void SnapshotIsImmutableAcrossTransitions()
    {
        InProcessKeySet<HmacKey> keySet = new();
        keySet.AddIncoming(NewKey("kid-1"));

        KeySet<HmacKey> snap1 = keySet.Snapshot();

        keySet.PromoteIncomingToCurrent("kid-1");

        //snap1 was captured before the promotion and must still reflect
        //the pre-promotion state.
        Assert.HasCount(1, snap1.Incoming);
        Assert.IsTrue(snap1.Current.IsEmpty);
    }


    [TestMethod]
    public void IsKidValidForVerificationAcceptsCurrentAndRetiring()
    {
        InProcessKeySet<HmacKey> keySet = new(new KeySet<HmacKey>
        {
            Incoming = [NewKey("k-incoming")],
            Current = [NewKey("k-current")],
            Retiring = [NewKey("k-retiring")],
            Historical = [NewKey("k-historical")]
        });

        KeySet<HmacKey> snap = keySet.Snapshot();

        Assert.IsFalse(snap.IsKidValidForVerification("k-incoming"));
        Assert.IsTrue(snap.IsKidValidForVerification("k-current"));
        Assert.IsTrue(snap.IsKidValidForVerification("k-retiring"));
        Assert.IsFalse(snap.IsKidValidForVerification("k-historical"));
        Assert.IsFalse(snap.IsKidValidForVerification("k-unknown"));
    }


    [TestMethod]
    public void ValidForVerificationEnumeratesCurrentAndRetiring()
    {
        InProcessKeySet<HmacKey> keySet = new(new KeySet<HmacKey>
        {
            Incoming = [NewKey("k-incoming")],
            Current = [NewKey("k-current")],
            Retiring = [NewKey("k-retiring")],
            Historical = [NewKey("k-historical")]
        });

        string[] valid = keySet.Snapshot().ValidForVerification()
            .Select(k => k.Kid).ToArray();

        Assert.HasCount(2, valid);
        Assert.Contains("k-current", valid);
        Assert.Contains("k-retiring", valid);
    }


    [TestMethod]
    public void PublishableEnumeratesIncomingCurrentRetiring()
    {
        InProcessKeySet<HmacKey> keySet = new(new KeySet<HmacKey>
        {
            Incoming = [NewKey("k-incoming")],
            Current = [NewKey("k-current")],
            Retiring = [NewKey("k-retiring")],
            Historical = [NewKey("k-historical")]
        });

        string[] publishable = keySet.Snapshot().Publishable()
            .Select(k => k.Kid).ToArray();

        Assert.HasCount(3, publishable);
        Assert.Contains("k-incoming", publishable);
        Assert.Contains("k-current", publishable);
        Assert.Contains("k-retiring", publishable);
        Assert.DoesNotContain("k-historical", publishable);
    }


    private static HmacKey NewKey(string kid) => new()
    {
        Kid = kid,
        Material = CreateHmacMaterial()
    };


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKeyMemory ownership transfers to the returned SymmetricKey, owned by the InProcessKeySet under test.")]
    private static SymmetricKey CreateHmacMaterial()
    {
        IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        SymmetricKeyMemory material;
        try
        {
            RandomNumberGenerator.Fill(owner.Memory.Span[..32]);
            material = new SymmetricKeyMemory(owner, CryptoTags.HmacSha256Key);
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        return new SymmetricKey(
            material,
            Guid.NewGuid().ToString("N"),
            MicrosoftHmacFunctions.ComputeHmacAsync,
            MicrosoftHmacFunctions.VerifyHmacAsync);
    }
}
