using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriMessageFields"/> and <see cref="KeriMessageTypes"/> — the KERI wire vocabulary. The
/// field labels and message type values are pinned to their specification wire forms, and the message-type
/// classification (key event, establishment event, delegated event) is checked against the specification's
/// message type table, since a key event log replayer keys on that classification.
/// </summary>
[TestClass]
internal sealed class KeriMessageVocabularyTests
{
    /// <summary>
    /// The reserved field labels carry their compact specification wire forms.
    /// </summary>
    [TestMethod]
    public void FieldLabelsAreTheSpecificationWireForms()
    {
        Assert.AreEqual("v", KeriMessageFields.Version);
        Assert.AreEqual("t", KeriMessageFields.MessageType);
        Assert.AreEqual("d", KeriMessageFields.Said);
        Assert.AreEqual("i", KeriMessageFields.Prefix);
        Assert.AreEqual("s", KeriMessageFields.SequenceNumber);
        Assert.AreEqual("kt", KeriMessageFields.KeysSigningThreshold);
        Assert.AreEqual("n", KeriMessageFields.NextKeyDigests);
        Assert.AreEqual("di", KeriMessageFields.DelegatorPrefix);
    }


    /// <summary>
    /// Reserved labels are recognized as reserved and an unknown label is not.
    /// </summary>
    [TestMethod]
    public void RecognizesReservedFieldLabels()
    {
        Assert.IsTrue(KeriMessageFields.IsReserved(KeriMessageFields.NextKeysSigningThreshold));
        Assert.IsTrue(KeriMessageFields.IsReserved(KeriMessageFields.Anchors));
        Assert.IsFalse(KeriMessageFields.IsReserved("zz"), "An unknown label is not reserved.");
    }


    /// <summary>
    /// The message type values carry their three-character specification ilk forms.
    /// </summary>
    [TestMethod]
    public void MessageTypesAreTheSpecificationIlkValues()
    {
        Assert.AreEqual("icp", KeriMessageTypes.Inception);
        Assert.AreEqual("rot", KeriMessageTypes.Rotation);
        Assert.AreEqual("ixn", KeriMessageTypes.Interaction);
        Assert.AreEqual("dip", KeriMessageTypes.DelegatedInception);
        Assert.AreEqual("drt", KeriMessageTypes.DelegatedRotation);
        Assert.AreEqual("rct", KeriMessageTypes.Receipt);
    }


    /// <summary>
    /// The five key event types are key events; a receipt is not.
    /// </summary>
    [TestMethod]
    public void ClassifiesKeyEvents()
    {
        Assert.IsTrue(KeriMessageTypes.IsKeyEvent(KeriMessageTypes.Inception));
        Assert.IsTrue(KeriMessageTypes.IsKeyEvent(KeriMessageTypes.Rotation));
        Assert.IsTrue(KeriMessageTypes.IsKeyEvent(KeriMessageTypes.Interaction));
        Assert.IsTrue(KeriMessageTypes.IsKeyEvent(KeriMessageTypes.DelegatedInception));
        Assert.IsTrue(KeriMessageTypes.IsKeyEvent(KeriMessageTypes.DelegatedRotation));
        Assert.IsFalse(KeriMessageTypes.IsKeyEvent(KeriMessageTypes.Receipt), "A receipt is not part of the key event log.");
    }


    /// <summary>
    /// Inception, rotation, and the delegated establishment events change key state; an interaction does not.
    /// </summary>
    [TestMethod]
    public void ClassifiesEstablishmentEvents()
    {
        Assert.IsTrue(KeriMessageTypes.IsEstablishmentEvent(KeriMessageTypes.Inception));
        Assert.IsTrue(KeriMessageTypes.IsEstablishmentEvent(KeriMessageTypes.Rotation));
        Assert.IsTrue(KeriMessageTypes.IsEstablishmentEvent(KeriMessageTypes.DelegatedInception));
        Assert.IsTrue(KeriMessageTypes.IsEstablishmentEvent(KeriMessageTypes.DelegatedRotation));
        Assert.IsFalse(KeriMessageTypes.IsEstablishmentEvent(KeriMessageTypes.Interaction), "An interaction event does not change key state.");
    }


    /// <summary>
    /// Only the delegated inception and rotation are delegated events.
    /// </summary>
    [TestMethod]
    public void ClassifiesDelegatedEvents()
    {
        Assert.IsTrue(KeriMessageTypes.IsDelegatedEvent(KeriMessageTypes.DelegatedInception));
        Assert.IsTrue(KeriMessageTypes.IsDelegatedEvent(KeriMessageTypes.DelegatedRotation));
        Assert.IsFalse(KeriMessageTypes.IsDelegatedEvent(KeriMessageTypes.Inception), "A non-delegated inception is not a delegated event.");
    }
}
