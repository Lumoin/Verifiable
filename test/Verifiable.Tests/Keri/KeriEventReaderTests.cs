using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriEventReader"/> — reading a decoded, serialization-agnostic field map into a typed
/// <see cref="KeriKeyEvent"/>. The field maps mirror the KERI specification's worked event examples; because the
/// reader works on a neutral map (scalars as strings, lists as string lists), the same path serves a map decoded
/// from JSON, CBOR, MGPK, or CESR-native. A reader result is also folded into key state to show the two compose.
/// </summary>
[TestClass]
internal sealed class KeriEventReaderTests
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
        "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
    ];

    private static readonly string[] ConfigurationTraits = ["DID"];
    private static readonly string[] NoTraits = [];


    /// <summary>
    /// An inception field map reads into a typed inception event with every field carried through, and decodes the
    /// hexadecimal sequence number.
    /// </summary>
    [TestMethod]
    public void ReadsInceptionFieldMap()
    {
        KeriKeyEvent read = KeriEventReader.Read(InceptionFields("0"));

        Assert.IsInstanceOfType<KeriInceptionEvent>(read);
        var inception = (KeriInceptionEvent)read;
        Assert.AreEqual(Aid, inception.Prefix);
        Assert.AreEqual(0, inception.SequenceNumber);
        Assert.AreEqual(KeriThreshold.Unweighted(2), inception.SigningThreshold);
        CollectionAssert.AreEqual(SigningKeys, (System.Collections.ICollection)inception.SigningKeys);
        CollectionAssert.AreEqual(NextKeyDigests, (System.Collections.ICollection)inception.NextKeyDigests);
        CollectionAssert.AreEqual(ConfigurationTraits, (System.Collections.ICollection)inception.ConfigurationTraits);
    }


    /// <summary>
    /// An interaction field map reads into a typed interaction event.
    /// </summary>
    [TestMethod]
    public void ReadsInteractionFieldMap()
    {
        var fields = new MessageFieldMap(StringComparer.Ordinal)
        {
            [KeriMessageFields.Version] = "KERICAACAAJSONAAAA.",
            [KeriMessageFields.MessageType] = KeriMessageTypes.Interaction,
            [KeriMessageFields.Said] = "EIxnSaid000000000000000000000000000000000000",
            [KeriMessageFields.Prefix] = Aid,
            [KeriMessageFields.SequenceNumber] = "1",
            [KeriMessageFields.PriorSaid] = Aid,
            [KeriMessageFields.Anchors] = NoTraits
        };

        KeriKeyEvent read = KeriEventReader.Read(fields);

        Assert.IsInstanceOfType<KeriInteractionEvent>(read);
        var interaction = (KeriInteractionEvent)read;
        Assert.AreEqual(1, interaction.SequenceNumber);
        Assert.AreEqual(Aid, interaction.PriorSaid);
    }


    /// <summary>
    /// A rotation field map reads into a typed rotation event, including its backer remove and add lists.
    /// </summary>
    [TestMethod]
    public void ReadsRotationFieldMap()
    {
        string[] toRemove = ["BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"];
        string[] toAdd = ["BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt"];
        var fields = new MessageFieldMap(StringComparer.Ordinal)
        {
            [KeriMessageFields.Version] = "KERICAACAAJSONAAAA.",
            [KeriMessageFields.MessageType] = KeriMessageTypes.Rotation,
            [KeriMessageFields.Said] = "ERotSaid0000000000000000000000000000000000000",
            [KeriMessageFields.Prefix] = Aid,
            [KeriMessageFields.SequenceNumber] = "1",
            [KeriMessageFields.PriorSaid] = Aid,
            [KeriMessageFields.KeysSigningThreshold] = "1",
            [KeriMessageFields.SigningKeys] = NextKeyDigests,
            [KeriMessageFields.NextKeysSigningThreshold] = "1",
            [KeriMessageFields.NextKeyDigests] = NextKeyDigests,
            [KeriMessageFields.BackerThreshold] = "1",
            [KeriMessageFields.BackersToRemove] = toRemove,
            [KeriMessageFields.BackersToAdd] = toAdd,
            [KeriMessageFields.ConfigurationTraits] = NoTraits,
            [KeriMessageFields.Anchors] = NoTraits
        };

        KeriKeyEvent read = KeriEventReader.Read(fields);

        Assert.IsInstanceOfType<KeriRotationEvent>(read);
        var rotation = (KeriRotationEvent)read;
        CollectionAssert.AreEqual(toRemove, (System.Collections.ICollection)rotation.BackersToRemove);
        CollectionAssert.AreEqual(toAdd, (System.Collections.ICollection)rotation.BackersToAdd);
    }


    /// <summary>
    /// The sequence number is decoded from hexadecimal.
    /// </summary>
    [TestMethod]
    public void DecodesHexadecimalSequenceNumber()
    {
        KeriKeyEvent read = KeriEventReader.Read(InceptionFields("1a"));

        Assert.AreEqual(26, read.SequenceNumber, "Sequence number '1a' is hexadecimal 26.");
    }


    /// <summary>
    /// A field map missing a required field is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsMissingRequiredField()
    {
        MessageFieldMap fields = InceptionFields("0");
        fields.Remove(KeriMessageFields.SigningKeys);

        Assert.ThrowsExactly<KeriException>(() => KeriEventReader.Read(fields));
    }


    /// <summary>
    /// An event carrying a top-level field beyond those its type defines is rejected; the field set is exhaustive.
    /// </summary>
    [TestMethod]
    public void RejectsUnexpectedTopLevelField()
    {
        MessageFieldMap fields = InceptionFields("0");
        fields["di"] = Aid;

        Assert.ThrowsExactly<KeriException>(() => KeriEventReader.Read(fields));
    }


    /// <summary>
    /// An event missing a spec-required top-level field that the typed model does not itself carry (the anchor
    /// list) is still rejected.
    /// </summary>
    [TestMethod]
    public void RejectsMissingAnchorField()
    {
        MessageFieldMap fields = InceptionFields("0");
        fields.Remove(KeriMessageFields.Anchors);

        Assert.ThrowsExactly<KeriException>(() => KeriEventReader.Read(fields));
    }


    /// <summary>
    /// A field map with the correct, complete field set but whose fields are not in the canonical order is
    /// rejected; the field order is fixed and bears on the SAID over the serialization.
    /// </summary>
    [TestMethod]
    public void RejectsNonCanonicalFieldOrder()
    {
        //A complete, correctly typed inception field set with the prefix (i) placed before the SAID (d), the
        //reverse of the canonical order.
        var fields = new MessageFieldMap(StringComparer.Ordinal)
        {
            [KeriMessageFields.Version] = "KERICAACAAJSONAAKp.",
            [KeriMessageFields.MessageType] = KeriMessageTypes.Inception,
            [KeriMessageFields.Prefix] = Aid,
            [KeriMessageFields.Said] = Aid,
            [KeriMessageFields.SequenceNumber] = "0",
            [KeriMessageFields.KeysSigningThreshold] = "2",
            [KeriMessageFields.SigningKeys] = SigningKeys,
            [KeriMessageFields.NextKeysSigningThreshold] = "2",
            [KeriMessageFields.NextKeyDigests] = NextKeyDigests,
            [KeriMessageFields.BackerThreshold] = "1",
            [KeriMessageFields.Backers] = Backers,
            [KeriMessageFields.ConfigurationTraits] = ConfigurationTraits,
            [KeriMessageFields.Anchors] = NoTraits
        };

        Assert.ThrowsExactly<KeriException>(() => KeriEventReader.Read(fields));
    }


    /// <summary>
    /// A message type that is not a modeled key event is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsUnmodeledMessageType()
    {
        var fields = new MessageFieldMap(StringComparer.Ordinal)
        {
            [KeriMessageFields.MessageType] = KeriMessageTypes.Receipt,
            [KeriMessageFields.Said] = Aid,
            [KeriMessageFields.Prefix] = Aid,
            [KeriMessageFields.SequenceNumber] = "0"
        };

        Assert.ThrowsExactly<KeriException>(() => KeriEventReader.Read(fields));
    }


    /// <summary>
    /// A read inception event folds into key state, showing the reader and the state machine compose.
    /// </summary>
    [TestMethod]
    public void ReadInceptionFoldsIntoKeyState()
    {
        var inception = (KeriInceptionEvent)KeriEventReader.Read(InceptionFields("0"));

        KeriKeyState state = KeriKeyStateMachine.Incept(inception);

        Assert.AreEqual(Aid, state.Prefix);
        Assert.AreEqual(0, state.SequenceNumber);
        CollectionAssert.AreEqual(SigningKeys, (System.Collections.ICollection)state.SigningKeys);
    }


    private static MessageFieldMap InceptionFields(string sequenceNumber) => new(StringComparer.Ordinal)
    {
        [KeriMessageFields.Version] = "KERICAACAAJSONAAKp.",
        [KeriMessageFields.MessageType] = KeriMessageTypes.Inception,
        [KeriMessageFields.Said] = Aid,
        [KeriMessageFields.Prefix] = Aid,
        [KeriMessageFields.SequenceNumber] = sequenceNumber,
        [KeriMessageFields.KeysSigningThreshold] = "2",
        [KeriMessageFields.SigningKeys] = SigningKeys,
        [KeriMessageFields.NextKeysSigningThreshold] = "2",
        [KeriMessageFields.NextKeyDigests] = NextKeyDigests,
        [KeriMessageFields.BackerThreshold] = "1",
        [KeriMessageFields.Backers] = Backers,
        [KeriMessageFields.ConfigurationTraits] = ConfigurationTraits,
        [KeriMessageFields.Anchors] = NoTraits
    };
}
