using System.Collections.Generic;
using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriKeyStateMachine"/> — folding KERI key events into key state. An inception establishes
/// the initial state, and interaction events advance the sequence without changing the keys; the ordering
/// invariants (an inception is the first event, each event advances the sequence by one for the same identifier)
/// are enforced. The inception is built from the KERI specification's worked inception example.
/// </summary>
[TestClass]
internal sealed class KeriKeyStateMachineTests
{
    private const string Aid = "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB";

    private static readonly string[] SigningKeys =
    [
        "DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu",
        "DG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5",
        "DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV"
    ];

    private static readonly string[] NextKeyDigests =
    [
        "ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB",
        "ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YT",
        "EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG"
    ];

    private static readonly string[] Backers =
    [
        "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
        "BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt",
        "BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH",
        "BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"
    ];

    private static readonly string[] ConfigurationTraits = ["DID"];


    /// <summary>
    /// An inception event establishes the initial key state with every field carried through.
    /// </summary>
    [TestMethod]
    public void InceptEstablishesKeyState()
    {
        KeriKeyState state = KeriKeyStateMachine.Incept(Inception());

        Assert.AreEqual(Aid, state.Prefix);
        Assert.AreEqual(KeriThreshold.Unweighted(2), state.SigningThreshold);
        Assert.AreSequenceEqual(SigningKeys, (System.Collections.ICollection)state.SigningKeys);
        Assert.AreEqual(KeriThreshold.Unweighted(2), state.NextThreshold);
        Assert.AreSequenceEqual(NextKeyDigests, (System.Collections.ICollection)state.NextKeyDigests);
        Assert.AreEqual("3", state.BackerThreshold);
        Assert.HasCount(4, state.Backers);
        Assert.AreSequenceEqual(ConfigurationTraits, (System.Collections.ICollection)state.ConfigurationTraits);
        Assert.AreEqual(0, state.SequenceNumber);
        Assert.AreEqual(Aid, state.LastEventSaid, "The inception SAID becomes the last event SAID the next event chains to.");
    }


    /// <summary>
    /// An inception whose sequence number is not zero is rejected.
    /// </summary>
    [TestMethod]
    public void InceptRejectsNonZeroSequenceNumber()
    {
        KeriInceptionEvent malformed = Inception() with { SequenceNumber = 1 };

        Assert.ThrowsExactly<KeriException>(() => KeriKeyStateMachine.Incept(malformed));
    }


    /// <summary>
    /// An inception that establishes no signing keys is rejected.
    /// </summary>
    [TestMethod]
    public void InceptRejectsNoSigningKeys()
    {
        KeriInceptionEvent malformed = Inception() with { SigningKeys = [] };

        Assert.ThrowsExactly<KeriException>(() => KeriKeyStateMachine.Incept(malformed));
    }


    /// <summary>
    /// An interaction event advances the sequence and records the new last event SAID, leaving the keys unchanged.
    /// </summary>
    [TestMethod]
    public void InteractAdvancesSequenceAndRecordsSaid()
    {
        KeriKeyState inception = KeriKeyStateMachine.Incept(Inception());
        var interaction = new KeriInteractionEvent("EInteractionSaid000000000000000000000000000", Aid, 1, Aid);

        KeriKeyState advanced = KeriKeyStateMachine.Interact(inception, interaction);

        Assert.AreEqual(1, advanced.SequenceNumber);
        Assert.AreEqual("EInteractionSaid000000000000000000000000000", advanced.LastEventSaid);
        Assert.AreSequenceEqual(SigningKeys, (System.Collections.ICollection)advanced.SigningKeys, "An interaction does not change the signing keys.");
        Assert.AreSequenceEqual(inception.NextKeyDigests, advanced.NextKeyDigests, "An interaction does not change the pre-rotation commitments.");
    }


    /// <summary>
    /// An interaction event that does not advance the sequence by exactly one is rejected.
    /// </summary>
    [TestMethod]
    public void InteractRejectsSequenceGap()
    {
        KeriKeyState inception = KeriKeyStateMachine.Incept(Inception());
        var skipping = new KeriInteractionEvent("EGap00000000000000000000000000000000000000", Aid, 2, Aid);

        Assert.ThrowsExactly<KeriException>(() => KeriKeyStateMachine.Interact(inception, skipping));
    }


    /// <summary>
    /// An interaction event for a different identifier is rejected.
    /// </summary>
    [TestMethod]
    public void InteractRejectsPrefixMismatch()
    {
        KeriKeyState inception = KeriKeyStateMachine.Incept(Inception());
        var foreign = new KeriInteractionEvent("EForeign0000000000000000000000000000000000", "EDifferentAid000000000000000000000000000000", 1, Aid);

        Assert.ThrowsExactly<KeriException>(() => KeriKeyStateMachine.Interact(inception, foreign));
    }


    private static KeriInceptionEvent Inception() => new(
        Said: Aid,
        Prefix: Aid,
        SequenceNumber: 0,
        SigningThreshold: "2",
        SigningKeys: SigningKeys,
        NextThreshold: "2",
        NextKeyDigests: NextKeyDigests,
        BackerThreshold: "3",
        Backers: Backers,
        ConfigurationTraits: ConfigurationTraits);
}
