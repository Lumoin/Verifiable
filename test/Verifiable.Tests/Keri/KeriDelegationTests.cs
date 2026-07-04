using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for KERI delegated events — reading a <c>dip</c> / <c>drt</c> field map into the typed delegated events,
/// folding them into key state (a delegated inception captures its delegator, a delegated rotation preserves it),
/// and the cooperative-delegation seal matching (<see cref="KeriDelegation"/>) that binds a delegated event to a
/// delegating key event seal in the delegator's KEL. The field maps mirror the KERI specification's delegated
/// event examples; the seal binding is the specification's cooperative-delegation rule.
/// </summary>
[TestClass]
internal sealed class KeriDelegationTests
{
    private const string DelegateeAid = "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur";
    private const string DelegatorAid = "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB";

    private static readonly string[] SigningKeys =
    [
        "DEE-HCMSwqMDkEBzlmUNmVBAGIinGu7wZ5_hfY6bSMz3",
        "DHyJFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkv"
    ];

    private static readonly string[] NextKeyDigests =
    [
        "EFzr1nnfHpT-nkSfd6vQvbPC-Kq6zy8vbVvUmwxcM1e-",
        "EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJM"
    ];

    private static readonly string[] NoStrings = [];


    /// <summary>
    /// A <c>dip</c> field map reads into a typed delegated inception that carries its delegator AID and is, by
    /// inheritance, an inception event.
    /// </summary>
    [TestMethod]
    public void ReadsDelegatedInceptionFieldMap()
    {
        KeriKeyEvent read = KeriEventReader.Read(DelegatedInceptionFields());

        Assert.IsInstanceOfType<KeriDelegatedInceptionEvent>(read);
        Assert.IsInstanceOfType<KeriInceptionEvent>(read, "A delegated inception is an inception for key-state folding.");
        var dip = (KeriDelegatedInceptionEvent)read;
        Assert.AreEqual(DelegateeAid, dip.Prefix);
        Assert.AreEqual(DelegatorAid, dip.DelegatorPrefix);
    }


    /// <summary>
    /// A <c>drt</c> field map reads into a typed delegated rotation that is, by inheritance, a rotation event.
    /// </summary>
    [TestMethod]
    public void ReadsDelegatedRotationFieldMap()
    {
        KeriKeyEvent read = KeriEventReader.Read(DelegatedRotationFields());

        Assert.IsInstanceOfType<KeriDelegatedRotationEvent>(read);
        Assert.IsInstanceOfType<KeriRotationEvent>(read, "A delegated rotation is a rotation for key-state folding.");
        Assert.AreEqual(1, read.SequenceNumber);
    }


    /// <summary>
    /// A delegated inception missing its delegator AID (field <c>di</c>) is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsDelegatedInceptionMissingDelegator()
    {
        MessageFieldMap fields = DelegatedInceptionFields();
        fields.Remove(KeriMessageFields.DelegatorPrefix);

        Assert.ThrowsExactly<KeriException>(() => KeriEventReader.Read(fields));
    }


    /// <summary>
    /// Folding a delegated inception establishes key state that records the delegator AID.
    /// </summary>
    [TestMethod]
    public void DelegatedInceptionFoldsAndCapturesDelegator()
    {
        var dip = (KeriDelegatedInceptionEvent)KeriEventReader.Read(DelegatedInceptionFields());

        KeriKeyState state = KeriKeyStateMachine.Incept(dip);

        Assert.AreEqual(DelegateeAid, state.Prefix);
        Assert.AreEqual(DelegatorAid, state.DelegatorPrefix, "The delegated inception binds the key state to its delegator.");
    }


    /// <summary>
    /// A plain inception establishes key state with no delegator.
    /// </summary>
    [TestMethod]
    public void PlainInceptionHasNoDelegator()
    {
        var inception = new KeriInceptionEvent(
            DelegateeAid, DelegateeAid, 0, "1", SigningKeys, "1", NextKeyDigests, "0", NoStrings, NoStrings);

        KeriKeyState state = KeriKeyStateMachine.Incept(inception);

        Assert.IsNull(state.DelegatorPrefix, "A non-delegated inception has no delegator.");
    }


    /// <summary>
    /// A key event seal whose identifier, sequence number, and SAID match a delegated event is its delegating seal.
    /// </summary>
    [TestMethod]
    public void IsDelegationSealForMatchesEvent()
    {
        var dip = (KeriDelegatedInceptionEvent)KeriEventReader.Read(DelegatedInceptionFields());
        var seal = new KeriKeyEventSeal(DelegateeAid, 0, DelegateeAid);

        Assert.IsTrue(KeriDelegation.IsDelegationSealFor(seal, dip), "The seal anchors exactly this delegated inception.");
    }


    /// <summary>
    /// A key event seal whose SAID differs from the delegated event's is not its delegating seal.
    /// </summary>
    [TestMethod]
    public void IsDelegationSealForRejectsMismatch()
    {
        var dip = (KeriDelegatedInceptionEvent)KeriEventReader.Read(DelegatedInceptionFields());
        var wrongSaid = new KeriKeyEventSeal(DelegateeAid, 0, "EDifferentSaid000000000000000000000000000000");
        var wrongSequence = new KeriKeyEventSeal(DelegateeAid, 1, DelegateeAid);

        Assert.IsFalse(KeriDelegation.IsDelegationSealFor(wrongSaid, dip), "A different SAID is not a delegating seal.");
        Assert.IsFalse(KeriDelegation.IsDelegationSealFor(wrongSequence, dip), "A different sequence number is not a delegating seal.");
    }


    /// <summary>
    /// The delegating seal for a delegated event is found among a delegator event's mixed anchors, and a list with
    /// no matching key event seal yields none.
    /// </summary>
    [TestMethod]
    public void FindDelegationSealLocatesTheAnchor()
    {
        var dip = (KeriDelegatedInceptionEvent)KeriEventReader.Read(DelegatedInceptionFields());
        var anchors = new List<KeriSeal>
        {
            new KeriDigestSeal("EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5"),
            new KeriKeyEventSeal(DelegateeAid, 0, DelegateeAid),
            new KeriLatestEstablishmentEventSeal(DelegatorAid)
        };

        KeriKeyEventSeal? found = KeriDelegation.FindDelegationSeal(anchors, dip);

        Assert.IsNotNull(found, "The delegating seal is among the anchors.");
        Assert.AreEqual(DelegateeAid, found.Said);

        var withoutSeal = new List<KeriSeal> { new KeriDigestSeal("EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5") };
        Assert.IsNull(KeriDelegation.FindDelegationSeal(withoutSeal, dip), "No key event seal means no delegating seal.");
    }


    private static MessageFieldMap DelegatedInceptionFields() => new(StringComparer.Ordinal)
    {
        [KeriMessageFields.Version] = "KERICAACAAJSONAAL4.",
        [KeriMessageFields.MessageType] = KeriMessageTypes.DelegatedInception,
        [KeriMessageFields.Said] = DelegateeAid,
        [KeriMessageFields.Prefix] = DelegateeAid,
        [KeriMessageFields.SequenceNumber] = "0",
        [KeriMessageFields.KeysSigningThreshold] = "1",
        [KeriMessageFields.SigningKeys] = SigningKeys,
        [KeriMessageFields.NextKeysSigningThreshold] = "1",
        [KeriMessageFields.NextKeyDigests] = NextKeyDigests,
        [KeriMessageFields.BackerThreshold] = "0",
        [KeriMessageFields.Backers] = NoStrings,
        [KeriMessageFields.ConfigurationTraits] = NoStrings,
        [KeriMessageFields.Anchors] = NoStrings,
        [KeriMessageFields.DelegatorPrefix] = DelegatorAid
    };


    private static MessageFieldMap DelegatedRotationFields() => new(StringComparer.Ordinal)
    {
        [KeriMessageFields.Version] = "KERICAACAAJSONAAKh.",
        [KeriMessageFields.MessageType] = KeriMessageTypes.DelegatedRotation,
        [KeriMessageFields.Said] = "ENl9GdcDY-4hlg5GtVwOg2E9X7JHw-7Dr5Zq5KNirISF",
        [KeriMessageFields.Prefix] = DelegateeAid,
        [KeriMessageFields.SequenceNumber] = "1",
        [KeriMessageFields.PriorSaid] = DelegateeAid,
        [KeriMessageFields.KeysSigningThreshold] = "1",
        [KeriMessageFields.SigningKeys] = SigningKeys,
        [KeriMessageFields.NextKeysSigningThreshold] = "1",
        [KeriMessageFields.NextKeyDigests] = NextKeyDigests,
        [KeriMessageFields.BackerThreshold] = "0",
        [KeriMessageFields.BackersToRemove] = NoStrings,
        [KeriMessageFields.BackersToAdd] = NoStrings,
        [KeriMessageFields.ConfigurationTraits] = NoStrings,
        [KeriMessageFields.Anchors] = NoStrings
    };
}
