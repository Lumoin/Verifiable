using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.OAuth.Server.Keys;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Exercises <see cref="InProcessKeySet"/>'s slot semantics: AddCurrent /
/// AddIncoming / PromoteIncomingToCurrent / RetireCurrent / ArchiveRetiring
/// transitions plus <see cref="InProcessKeySet.ResolveMaterial"/> material
/// lookup. Structurally mirrors <see cref="Verifiable.OAuth.SigningKeySet"/>'s
/// slot model.
/// </summary>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKey ownership transfers from CreateHmacMaterial() to the InProcessKeySet via AddCurrent/AddIncoming; the keyset is held in a using and disposes all materials.")]
[TestClass]
internal sealed class InProcessKeySetTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly KeyId KidA = new("kid-A");
    private static readonly KeyId KidB = new("kid-B");
    private static readonly KeyId KidC = new("kid-C");


    [TestMethod]
    public void AddIncomingPopulatesIncomingSlot()
    {
        using InProcessKeySet keySet = new();

        keySet.AddIncoming(KidA, CreateHmacMaterial());

        KeySet snap = keySet.Snapshot();
        Assert.HasCount(1, snap.Incoming);
        Assert.AreEqual(KidA, snap.Incoming[0]);
        Assert.IsTrue(snap.Current.IsEmpty);
    }


    [TestMethod]
    public void PromoteIncomingToCurrentMovesKey()
    {
        using InProcessKeySet keySet = new();
        keySet.AddIncoming(KidA, CreateHmacMaterial());

        keySet.PromoteIncomingToCurrent(KidA);

        KeySet snap = keySet.Snapshot();
        Assert.IsTrue(snap.Incoming.IsEmpty);
        Assert.HasCount(1, snap.Current);
        Assert.AreEqual(KidA, snap.Current[0]);
    }


    [TestMethod]
    public void RetireCurrentMovesKeyToRetiring()
    {
        using InProcessKeySet keySet = new();
        keySet.AddCurrent(KidA, CreateHmacMaterial());

        keySet.RetireCurrent(KidA);

        KeySet snap = keySet.Snapshot();
        Assert.IsTrue(snap.Current.IsEmpty);
        Assert.HasCount(1, snap.Retiring);
    }


    [TestMethod]
    public void ArchiveRetiringMovesKeyToHistorical()
    {
        using InProcessKeySet keySet = new();
        keySet.AddCurrent(KidA, CreateHmacMaterial());
        keySet.RetireCurrent(KidA);

        keySet.ArchiveRetiring(KidA);

        KeySet snap = keySet.Snapshot();
        Assert.IsTrue(snap.Retiring.IsEmpty);
        Assert.HasCount(1, snap.Historical);
    }


    [TestMethod]
    public void PromoteIncomingThrowsForUnknownKid()
    {
        using InProcessKeySet keySet = new();

        Assert.ThrowsExactly<InvalidOperationException>(
            () => keySet.PromoteIncomingToCurrent(new KeyId("kid-missing")));
    }


    [TestMethod]
    public void RetireCurrentThrowsForUnknownKid()
    {
        using InProcessKeySet keySet = new();

        Assert.ThrowsExactly<InvalidOperationException>(
            () => keySet.RetireCurrent(new KeyId("kid-missing")));
    }


    [TestMethod]
    public void ResolveMaterialFindsKeyAcrossAllSlots()
    {
        using InProcessKeySet keySet = new();
        SymmetricKey matA = CreateHmacMaterial();
        SymmetricKey matB = CreateHmacMaterial();
        SymmetricKey matC = CreateHmacMaterial();

        //KidA: Incoming. KidB: Current → Retiring. KidC: never added.
        keySet.AddIncoming(KidA, matA);
        keySet.AddCurrent(KidB, matB);
        keySet.RetireCurrent(KidB);

        Assert.AreSame(matA, keySet.ResolveMaterial(KidA));
        Assert.AreSame(matB, keySet.ResolveMaterial(KidB));
        Assert.IsNull(keySet.ResolveMaterial(KidC));

        //Side material store retains entries through slot transitions —
        //including past archival.
        keySet.ArchiveRetiring(KidB);
        Assert.AreSame(matB, keySet.ResolveMaterial(KidB));
    }


    [TestMethod]
    public void SnapshotIsImmutableAcrossTransitions()
    {
        using InProcessKeySet keySet = new();
        keySet.AddIncoming(KidA, CreateHmacMaterial());

        KeySet snap1 = keySet.Snapshot();

        keySet.PromoteIncomingToCurrent(KidA);

        Assert.HasCount(1, snap1.Incoming);
        Assert.IsTrue(snap1.Current.IsEmpty);
    }


    [TestMethod]
    public void IsKidValidForVerificationAcceptsCurrentAndRetiring()
    {
        using InProcessKeySet keySet = new();
        keySet.AddIncoming(new KeyId("k-incoming"), CreateHmacMaterial());
        keySet.AddCurrent(new KeyId("k-current"), CreateHmacMaterial());
        keySet.AddCurrent(new KeyId("k-retiring"), CreateHmacMaterial());
        keySet.RetireCurrent(new KeyId("k-retiring"));
        keySet.AddCurrent(new KeyId("k-historical"), CreateHmacMaterial());
        keySet.RetireCurrent(new KeyId("k-historical"));
        keySet.ArchiveRetiring(new KeyId("k-historical"));

        KeySet snap = keySet.Snapshot();

        Assert.IsFalse(snap.IsKidValidForVerification(new KeyId("k-incoming")));
        Assert.IsTrue(snap.IsKidValidForVerification(new KeyId("k-current")));
        Assert.IsTrue(snap.IsKidValidForVerification(new KeyId("k-retiring")));
        Assert.IsFalse(snap.IsKidValidForVerification(new KeyId("k-historical")));
        Assert.IsFalse(snap.IsKidValidForVerification(new KeyId("k-unknown")));
    }


    [TestMethod]
    public void ValidForVerificationEnumeratesCurrentAndRetiring()
    {
        using InProcessKeySet keySet = new();
        keySet.AddIncoming(new KeyId("k-incoming"), CreateHmacMaterial());
        keySet.AddCurrent(new KeyId("k-current"), CreateHmacMaterial());
        keySet.AddCurrent(new KeyId("k-retiring"), CreateHmacMaterial());
        keySet.RetireCurrent(new KeyId("k-retiring"));

        KeyId[] valid = keySet.Snapshot().ValidForVerification().ToArray();

        Assert.HasCount(2, valid);
        Assert.Contains(new KeyId("k-current"), valid);
        Assert.Contains(new KeyId("k-retiring"), valid);
    }


    [TestMethod]
    public void PublishableEnumeratesIncomingCurrentRetiring()
    {
        using InProcessKeySet keySet = new();
        keySet.AddIncoming(new KeyId("k-incoming"), CreateHmacMaterial());
        keySet.AddCurrent(new KeyId("k-current"), CreateHmacMaterial());
        keySet.AddCurrent(new KeyId("k-retiring"), CreateHmacMaterial());
        keySet.RetireCurrent(new KeyId("k-retiring"));
        keySet.AddCurrent(new KeyId("k-historical"), CreateHmacMaterial());
        keySet.RetireCurrent(new KeyId("k-historical"));
        keySet.ArchiveRetiring(new KeyId("k-historical"));

        KeyId[] publishable = keySet.Snapshot().Publishable().ToArray();

        Assert.HasCount(3, publishable);
        Assert.Contains(new KeyId("k-incoming"), publishable);
        Assert.Contains(new KeyId("k-current"), publishable);
        Assert.Contains(new KeyId("k-retiring"), publishable);
        Assert.DoesNotContain(new KeyId("k-historical"), publishable);
    }


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
