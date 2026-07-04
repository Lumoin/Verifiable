using System.Collections.Generic;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriEventJson"/> — the JSON arm of the bytes-to-field-map decode seam. Each test starts
/// from the wire bytes a verifier would receive and decodes them into the neutral field map, then folds that map
/// through <see cref="KeriEventReader"/> into a typed event: the firewalled path a consumer runs, with no shared
/// in-memory object between the producer of the bytes and the reader.
/// </summary>
[TestClass]
internal sealed class KeriEventJsonTests
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

    private static readonly string[] ConfigurationTraits = ["DID"];

    private const string InceptionJson =
        """
        {"v":"KERI10JSON0001b7_","t":"icp","d":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","s":"0","kt":"2","k":["DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu","DG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5","DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV"],"nt":"2","n":["ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB","ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YT","EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG"],"bt":"1","b":["BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"],"c":["DID"],"a":[]}
        """;


    /// <summary>
    /// JSON inception bytes decode and fold into a typed inception event carrying every key-state field.
    /// </summary>
    [TestMethod]
    public void DecodesInceptionBytesToTypedEvent()
    {
        MessageFieldMap fields = KeriEventJson.DecodeFieldMap(Encoding.UTF8.GetBytes(InceptionJson));

        var inception = (KeriInceptionEvent)KeriEventReader.Read(fields);

        Assert.AreEqual(Aid, inception.Said);
        Assert.AreEqual(Aid, inception.Prefix);
        Assert.AreEqual(0, inception.SequenceNumber);
        Assert.AreEqual(KeriThreshold.Unweighted(2), inception.SigningThreshold);
        CollectionAssert.AreEqual(SigningKeys, (System.Collections.ICollection)inception.SigningKeys);
        CollectionAssert.AreEqual(NextKeyDigests, (System.Collections.ICollection)inception.NextKeyDigests);
        CollectionAssert.AreEqual(ConfigurationTraits, (System.Collections.ICollection)inception.ConfigurationTraits);
    }


    /// <summary>
    /// A homogeneous string array decodes to a string list (the neutral-map list convention), while an empty array
    /// decodes to an empty string list a reader list field accepts.
    /// </summary>
    [TestMethod]
    public void DecodesArraysToStringLists()
    {
        MessageFieldMap fields = KeriEventJson.DecodeFieldMap(Encoding.UTF8.GetBytes(InceptionJson));

        Assert.IsInstanceOfType<IReadOnlyList<string>>(fields[KeriMessageFields.SigningKeys]);
        Assert.IsInstanceOfType<IReadOnlyList<string>>(fields[KeriMessageFields.Anchors]);
        Assert.IsEmpty((IReadOnlyList<string>)fields[KeriMessageFields.Anchors]!);
    }


    /// <summary>
    /// An anchored-seal array of objects decodes to a list of maps rather than a string list, so the data plane is
    /// preserved without being interpreted as key state.
    /// </summary>
    [TestMethod]
    public void PreservesAnchoredSealObjects()
    {
        const string interactionJson =
            """
            {"v":"KERI10JSON000000_","t":"ixn","d":"EIxnSaid000000000000000000000000000000000000","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","s":"1","p":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","a":[{"i":"EHng2fV42DdKb5TLMIs6bbRPwtVrLuJtZBxiyKfP1QPF","s":"0","d":"EEqkE0aMP5sB7sX-Vq2QzKMzdQTy6YK7ZqzD4iLfPQ8B"}]}
            """;

        MessageFieldMap fields = KeriEventJson.DecodeFieldMap(Encoding.UTF8.GetBytes(interactionJson));

        Assert.IsInstanceOfType<IReadOnlyList<object>>(fields[KeriMessageFields.Anchors]);
        var interaction = (KeriInteractionEvent)KeriEventReader.Read(fields);
        Assert.AreEqual(1, interaction.SequenceNumber);
    }


    /// <summary>
    /// Bytes that are not a JSON object are rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonObjectBytes()
    {
        Assert.ThrowsExactly<System.Text.Json.JsonException>(() => KeriEventJson.DecodeFieldMap(Encoding.UTF8.GetBytes("[]")));
    }
}
