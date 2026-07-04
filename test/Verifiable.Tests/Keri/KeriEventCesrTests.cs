using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Lumoin.Base;
using Verifiable.BouncyCastle;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Keri;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriEventCesr"/> — the CESR-native arm of the bytes-to-field-map decode seam. Each test
/// starts from the native (qb64) bytes a verifier would receive and decodes them into the neutral field map, then
/// folds that map through <see cref="KeriEventReader"/> into a typed event and verifies the SAID over the received
/// bytes — the firewalled path a consumer runs, with no shared in-memory object between producer and reader. The
/// inception vector is the worked CESR-native example from the KERI specification's key event messages, so the
/// decode is checked against an authoritative external serialization rather than a self-produced one.
/// </summary>
[TestClass]
internal sealed class KeriEventCesrTests
{
    /// <summary>
    /// The CESR-native inception (<c>icp</c>) serialization from the KERI specification's key event message
    /// examples, concatenated verbatim from the specification's wrapped byte-string lines.
    /// </summary>
    private const string InceptionNative =
        "-FCS0OKERICAACAAXicpEDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsEDZOA3y_b_0L" +
        "G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsMAAAMAAC-JAhDBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1H" +
        "xpDx95bFvufuDG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5DGIAk2jkC3xuLIe-DI9r" +
        "cA0naevtZiKuU9wz91L_qBAVMAAC-JAhELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB" +
        "ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YTEGyJ7y3TlewCW97dgBN-4pckhCqsni-z" +
        "HNZ_G8zVerPGMAAD-JAsBGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3BBJfueFAYc7N_" +
        "V-zmDEn2SPCoVFx3H20alWsNZKgsS1vtBAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH" +
        "BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB-JABXDID-JAA";

    /// <summary>
    /// The CESR-native interaction (<c>ixn</c>) serialization from the KERI specification's key event message
    /// examples; its anchor list carries one anchoring event seal (<c>-T</c>).
    /// </summary>
    private const string InteractionNative =
        "-FA_0OKERICAACAAXixnEDmgVuwPOXDjIW3reg4_k8SeJoQEKJKP24fGzeMV4uKDEDZOA3y_b_0L" +
        "G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsMAABEDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7f" +
        "rTYs-JAY-TAXEF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3MAAAEF-jViYoBr8p3vkp" +
        "ZuHlkvxAAY5GZkmQ0QaaHfiE0kg3";

    /// <summary>
    /// The CESR-native rotation (<c>rot</c>) serialization from the KERI specification's key event message
    /// examples; it exercises the prior-SAID, removed/added backers, an empty configuration list, and an anchored
    /// event seal.
    /// </summary>
    private const string RotationNative =
        "-FCq0OKERICAACAAXrotEADBM_Gjzv1_mImlJPPD0bzYmUXmXmCiFIncRYfZMaFcEDZOA3y_b_0L" +
        "G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsMAACEDmgVuwPOXDjIW3reg4_k8SeJoQEKJKP24fGzeMV" +
        "4uKDMAAC-JAhDLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8djDCx3WypeBym3fCkVizTg" +
        "18qEThSrVnB63dFq2oX5c3mzDO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXfMAAC-JAh" +
        "EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpeEERS8udHp2FW89nmaHweQWnZz7I8v9FT" +
        "QdA-LZ_amqGhEAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTgMAAE-JALBA4PSatfQMw1" +
        "lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB-JAWBO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-V" +
        "IsCoBPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW-JAA-JAY-TAXEF-jViYoBr8p3vkp" +
        "ZuHlkvxAAY5GZkmQ0QaaHfiE0kg3MAABEFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwv";

    /// <summary>
    /// The CESR-native delegated inception (<c>dip</c>) serialization from the KERI specification's key event
    /// message examples; it carries fractionally weighted signing and next-key thresholds and the delegator AID.
    /// </summary>
    private const string DelegatedInceptionNative =
        "-FCi0OKERICAACAAXdipEF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3EF-jViYoBr8p" +
        "3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3MAAA4AADA1s2c1s2c1s2-JAhDEE-HCMSwqMDkEBzlmUN" +
        "mVBAGIinGu7wZ5_hfY6bSMz3DHyJFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkvDN3JXVEv" +
        "IjTbisPC4maYQWy6eQIRNdJsxqGFXYUm_ygr4AADA1s2c1s2c1s2-JAhEFzr1nnfHpT-nkSfd6vQ" +
        "vbPC-Kq6zy8vbVvUmwxcM1e-EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJMEGVvq4Nj" +
        "kki3EZv838rJrYShBtwXY9o8RUrG2w3nbujnMAAD-JAsBFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ" +
        "4npNEmIW_gPXBOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsFBEzZUvashpXh_nfPoR6a" +
        "iqvag0a8E_tbhpeJIgHhOXzlBCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6-JAA-JAA" +
        "EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs";

    /// <summary>
    /// The CESR-native delegated rotation (<c>drt</c>) serialization from the KERI specification's key event
    /// message examples; like the delegated inception it carries fractionally weighted thresholds.
    /// </summary>
    private const string DelegatedRotationNative =
        "-FCN0OKERICAACAAXdrtEFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwvEF-jViYoBr8p" +
        "3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3MAABEF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE" +
        "0kg34AADA1s2c1s2c1s2-JAhDB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctRDDCDFlbG" +
        "4dCAX6oIbNffB1mkZqLAS_eHnYUUIPH7BeXBDP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z" +
        "0zs14AADA1s2c1s2c1s2-JAhEKUlc5Ml4HLSvdk39k_vh0m6rc061mfM1a4qoEuiBwXWEJdqHiij" +
        "mjII-ZtlhFAM5D7myuNeESQkzHoqeWJMMHzWEDyk8pj0YPHjGNfrG2qZI866WwevwlHEbWYMsKGT" +
        "Gqj2MAAD-JALBOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF-JALBOMrYd5izsqbqaq1" +
        "WZYa3nbEeTYLPwccfqfhirybKKqx-JAA-JAA";

    /// <summary>The inception SAID and (self-addressing) identifier; for an inception the controller identifier equals the SAID.</summary>
    private const string Aid = "EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs";

    /// <summary>The in-memory placeholder version string the native decode reconstructs (kind CESR, length from the framing), as the specification shows it.</summary>
    private const string ExpectedVersion = "KERICAACAACESRAAJM.";

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

    private static readonly string[] RotationBackersToRemove = ["BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"];

    private static readonly string[] RotationBackersToAdd =
    [
        "BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo",
        "BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW"
    ];

    /// <summary>The fractionally weighted threshold <c>["1/2", "1/2", "1/2"]</c> the delegated event vectors carry, as weight strings and as a parsed threshold.</summary>
    private static readonly string[] WeightedThresholdWeights = ["1/2", "1/2", "1/2"];

    private static readonly KeriThreshold HalfWeightThreshold = KeriThreshold.Parse(new List<string>(WeightedThresholdWeights));

    private static readonly string[] DelegatedInceptionKeys =
    [
        "DEE-HCMSwqMDkEBzlmUNmVBAGIinGu7wZ5_hfY6bSMz3",
        "DHyJFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkv",
        "DN3JXVEvIjTbisPC4maYQWy6eQIRNdJsxqGFXYUm_ygr"
    ];

    private static readonly string[] DelegatedInceptionBackers =
    [
        "BFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ4npNEmIW_gPX",
        "BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF",
        "BEzZUvashpXh_nfPoR6aiqvag0a8E_tbhpeJIgHhOXzl",
        "BCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6"
    ];

    private static readonly string[] DelegatedRotationKeys =
    [
        "DB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctR",
        "DDCDFlbG4dCAX6oIbNffB1mkZqLAS_eHnYUUIPH7BeXB",
        "DP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z0zs1"
    ];

    private static readonly string[] DelegatedRotationBackersToRemove = ["BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF"];

    private static readonly string[] DelegatedRotationBackersToAdd = ["BOMrYd5izsqbqaq1WZYa3nbEeTYLPwccfqfhirybKKqx"];


    /// <summary>
    /// An algorithm-agile digest oracle independent of the production registry: a Blake3 request routes to the
    /// BouncyCastle backend, every other to the Microsoft backend.
    /// </summary>
    private static readonly ComputeDigestDelegate AgileDigest = (input, outputByteLength, tag, pool, context, cancellationToken) =>
        tag.TryGet<CryptoAlgorithm>(out CryptoAlgorithm algorithm) && algorithm == CryptoAlgorithm.Blake3
            ? BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync(input, outputByteLength, tag, pool, context, cancellationToken)
            : MicrosoftEntropyFunctions.ComputeDigestAsync(input, outputByteLength, tag, pool, context, cancellationToken);


    /// <summary>
    /// The native inception decodes to the neutral field map: every scalar a string, the key-state lists string
    /// lists, the version reconstructed as the in-memory placeholder, and the empty anchors a list.
    /// </summary>
    [TestMethod]
    public void DecodesNativeInceptionToNeutralMap()
    {
        using NativeEvent native = RentNative(InceptionNative);

        MessageFieldMap fields = KeriEventCesr.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        Assert.AreEqual(ExpectedVersion, fields[KeriMessageFields.Version]);
        Assert.AreEqual(KeriMessageTypes.Inception, fields[KeriMessageFields.MessageType]);
        Assert.AreEqual(Aid, fields[KeriMessageFields.Said]);
        Assert.AreEqual(Aid, fields[KeriMessageFields.Prefix]);
        Assert.AreEqual("0", fields[KeriMessageFields.SequenceNumber]);
        Assert.AreEqual("2", fields[KeriMessageFields.KeysSigningThreshold]);
        Assert.AreEqual("2", fields[KeriMessageFields.NextKeysSigningThreshold]);
        Assert.AreEqual("3", fields[KeriMessageFields.BackerThreshold]);
        CollectionAssert.AreEqual(SigningKeys, (System.Collections.ICollection)fields[KeriMessageFields.SigningKeys]!);
        CollectionAssert.AreEqual(NextKeyDigests, (System.Collections.ICollection)fields[KeriMessageFields.NextKeyDigests]!);
        CollectionAssert.AreEqual(Backers, (System.Collections.ICollection)fields[KeriMessageFields.Backers]!);
        CollectionAssert.AreEqual(ConfigurationTraits, (System.Collections.ICollection)fields[KeriMessageFields.ConfigurationTraits]!);
        Assert.IsEmpty((IReadOnlyList<object?>)fields[KeriMessageFields.Anchors]!);
    }


    /// <summary>
    /// The native inception folds through the serialization-agnostic reader into a typed inception carrying every
    /// key-state field — the same reader the JSON, CBOR, and MGPK arms feed.
    /// </summary>
    [TestMethod]
    public void FoldsNativeInceptionToTypedEvent()
    {
        using NativeEvent native = RentNative(InceptionNative);
        MessageFieldMap fields = KeriEventCesr.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        var inception = (KeriInceptionEvent)KeriEventReader.Read(fields);

        Assert.AreEqual(Aid, inception.Said);
        Assert.AreEqual(Aid, inception.Prefix);
        Assert.AreEqual(0, inception.SequenceNumber);
        Assert.AreEqual(KeriThreshold.Unweighted(2), inception.SigningThreshold);
        Assert.AreEqual(KeriThreshold.Unweighted(2), inception.NextThreshold);
        CollectionAssert.AreEqual(SigningKeys, (System.Collections.ICollection)inception.SigningKeys);
        CollectionAssert.AreEqual(NextKeyDigests, (System.Collections.ICollection)inception.NextKeyDigests);
        CollectionAssert.AreEqual(Backers, (System.Collections.ICollection)inception.Backers);
        CollectionAssert.AreEqual(ConfigurationTraits, (System.Collections.ICollection)inception.ConfigurationTraits);
    }


    /// <summary>
    /// The inception SAID verifies over the received native bytes: the SAID digests the native serialization with
    /// its <c>d</c> (and, for an inception, equal <c>i</c>) field dummied, the same derivation as for the other
    /// serializations.
    /// </summary>
    [TestMethod]
    public async Task VerifiesNativeInceptionSaid()
    {
        using NativeEvent native = RentNative(InceptionNative);

        Assert.IsTrue(await KeriEventSaid.VerifyAsync(native.Memory, Aid, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The native interaction decodes through the reader into a typed interaction, and its anchored event seal
    /// (<c>-T</c>) decodes through the serialization-agnostic seal reader into a typed key event seal.
    /// </summary>
    [TestMethod]
    public async Task DecodesNativeInteractionWithAnchoredSeal()
    {
        using NativeEvent native = RentNative(InteractionNative);
        MessageFieldMap fields = KeriEventCesr.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        Assert.AreEqual("KERICAACAACESRAAEA.", fields[KeriMessageFields.Version]);

        var interaction = (KeriInteractionEvent)KeriEventReader.Read(fields);
        Assert.AreEqual("EDmgVuwPOXDjIW3reg4_k8SeJoQEKJKP24fGzeMV4uKD", interaction.Said);
        Assert.AreEqual(Aid, interaction.Prefix);
        Assert.AreEqual(1, interaction.SequenceNumber);
        Assert.AreEqual(Aid, interaction.PriorSaid);

        IReadOnlyList<KeriSeal> seals = KeriSealReader.ReadList(fields[KeriMessageFields.Anchors]);
        Assert.HasCount(1, seals);
        var seal = (KeriKeyEventSeal)seals[0];
        Assert.AreEqual("EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3", seal.Prefix);
        Assert.AreEqual(0, seal.SequenceNumber);
        Assert.AreEqual("EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3", seal.Said);

        Assert.IsTrue(await KeriEventSaid.VerifyAsync(native.Memory, interaction.Said, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The native rotation decodes through the reader into a typed rotation carrying the removed and added backers
    /// and an empty configuration list, its anchored event seal decodes, and the SAID verifies.
    /// </summary>
    [TestMethod]
    public async Task DecodesNativeRotationWithBackersAndSeal()
    {
        using NativeEvent native = RentNative(RotationNative);
        MessageFieldMap fields = KeriEventCesr.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        Assert.AreEqual("KERICAACAACESRAAKs.", fields[KeriMessageFields.Version]);

        var rotation = (KeriRotationEvent)KeriEventReader.Read(fields);
        Assert.AreEqual("EADBM_Gjzv1_mImlJPPD0bzYmUXmXmCiFIncRYfZMaFc", rotation.Said);
        Assert.AreEqual(Aid, rotation.Prefix);
        Assert.AreEqual(2, rotation.SequenceNumber);
        Assert.AreEqual("EDmgVuwPOXDjIW3reg4_k8SeJoQEKJKP24fGzeMV4uKD", rotation.PriorSaid);
        Assert.AreEqual(KeriThreshold.Unweighted(2), rotation.SigningThreshold);
        Assert.AreEqual(KeriThreshold.Unweighted(2), rotation.NextThreshold);
        CollectionAssert.AreEqual(RotationBackersToRemove, (System.Collections.ICollection)rotation.BackersToRemove);
        CollectionAssert.AreEqual(RotationBackersToAdd, (System.Collections.ICollection)rotation.BackersToAdd);
        Assert.IsEmpty((IReadOnlyList<string>)rotation.ConfigurationTraits);

        IReadOnlyList<KeriSeal> seals = KeriSealReader.ReadList(fields[KeriMessageFields.Anchors]);
        Assert.HasCount(1, seals);
        var seal = (KeriKeyEventSeal)seals[0];
        Assert.AreEqual("EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3", seal.Prefix);
        Assert.AreEqual(1, seal.SequenceNumber);
        Assert.AreEqual("EFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwv", seal.Said);

        Assert.IsTrue(await KeriEventSaid.VerifyAsync(native.Memory, rotation.Said, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The native delegated inception decodes its fractionally weighted signing and next-key thresholds and its
    /// delegator AID, folding through the reader into a typed delegated inception, with the SAID verified.
    /// </summary>
    [TestMethod]
    public async Task DecodesNativeDelegatedInceptionWithWeightedThreshold()
    {
        using NativeEvent native = RentNative(DelegatedInceptionNative);
        MessageFieldMap fields = KeriEventCesr.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        Assert.AreEqual("KERICAACAACESRAAKM.", fields[KeriMessageFields.Version]);
        CollectionAssert.AreEqual(WeightedThresholdWeights, (System.Collections.ICollection)fields[KeriMessageFields.KeysSigningThreshold]!);
        CollectionAssert.AreEqual(WeightedThresholdWeights, (System.Collections.ICollection)fields[KeriMessageFields.NextKeysSigningThreshold]!);

        var dip = (KeriDelegatedInceptionEvent)KeriEventReader.Read(fields);
        Assert.AreEqual("EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3", dip.Said);
        Assert.AreEqual("EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3", dip.Prefix);
        Assert.AreEqual(0, dip.SequenceNumber);
        Assert.AreEqual(Aid, dip.DelegatorPrefix);
        Assert.AreEqual(HalfWeightThreshold, dip.SigningThreshold);
        Assert.AreEqual(HalfWeightThreshold, dip.NextThreshold);
        Assert.IsTrue(dip.SigningThreshold.IsWeighted);
        CollectionAssert.AreEqual(DelegatedInceptionKeys, (System.Collections.ICollection)dip.SigningKeys);
        CollectionAssert.AreEqual(DelegatedInceptionBackers, (System.Collections.ICollection)dip.Backers);
        Assert.IsEmpty((IReadOnlyList<string>)dip.ConfigurationTraits);

        Assert.IsTrue(await KeriEventSaid.VerifyAsync(native.Memory, dip.Said, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The native delegated rotation decodes its weighted thresholds and removed/added backers, folding through the
    /// reader into a typed delegated rotation, with the SAID verified over the received bytes.
    /// </summary>
    [TestMethod]
    public async Task DecodesNativeDelegatedRotationWithWeightedThreshold()
    {
        using NativeEvent native = RentNative(DelegatedRotationNative);
        MessageFieldMap fields = KeriEventCesr.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        Assert.AreEqual("KERICAACAACESRAAI4.", fields[KeriMessageFields.Version]);

        var drt = (KeriDelegatedRotationEvent)KeriEventReader.Read(fields);
        Assert.AreEqual("EFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwv", drt.Said);
        Assert.AreEqual("EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3", drt.Prefix);
        Assert.AreEqual(1, drt.SequenceNumber);
        Assert.AreEqual("EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3", drt.PriorSaid);
        Assert.AreEqual(HalfWeightThreshold, drt.SigningThreshold);
        Assert.AreEqual(HalfWeightThreshold, drt.NextThreshold);
        CollectionAssert.AreEqual(DelegatedRotationKeys, (System.Collections.ICollection)drt.SigningKeys);
        CollectionAssert.AreEqual(DelegatedRotationBackersToRemove, (System.Collections.ICollection)drt.BackersToRemove);
        CollectionAssert.AreEqual(DelegatedRotationBackersToAdd, (System.Collections.ICollection)drt.BackersToAdd);

        Assert.IsTrue(await KeriEventSaid.VerifyAsync(native.Memory, drt.Said, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// Bytes framed by a code other than the fixed-field native body code are rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonFixedFrame()
    {
        using NativeEvent native = RentNative("-JAA");

        Assert.ThrowsExactly<CesrFormatException>(() => KeriEventCesr.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A frame whose declared body length does not match the bytes present is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsFrameLengthMismatch()
    {
        using NativeEvent native = RentNative(InceptionNative + "AAAA");

        Assert.ThrowsExactly<CesrFormatException>(() => KeriEventCesr.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared));
    }


    //Rents a pooled buffer holding the native serialization's ASCII bytes — the verifier-facing input — owned by
    //the returned carrier and disposed by the caller rather than left as a naked array.
    private static NativeEvent RentNative(string serialization)
    {
        int length = Encoding.ASCII.GetByteCount(serialization);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.ASCII.GetBytes(serialization, owner.Memory.Span);

        return new NativeEvent(owner, length);
    }


    //A native serialization carried in a pooled buffer the test owns and disposes.
    private sealed class NativeEvent: IDisposable
    {
        private readonly IMemoryOwner<byte> owner;
        private readonly int length;

        public NativeEvent(IMemoryOwner<byte> owner, int length)
        {
            this.owner = owner;
            this.length = length;
        }

        public ReadOnlyMemory<byte> Memory => owner.Memory[..length];

        public ReadOnlySpan<byte> Span => owner.Memory.Span[..length];

        public void Dispose() => owner.Dispose();
    }
}
