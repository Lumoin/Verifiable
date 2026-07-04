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
/// Tests for the rotation fold <see cref="KeriKeyStateMachine.Rotate"/> — pre-rotation verification and key state
/// roll-forward. The pre-rotation commitments and the keys they hide are the KERI specification's worked
/// inception example: the example's next keys, when digested, MUST equal the example's published next-key digests,
/// which is checked directly against an independent Blake3 oracle before the rotation fold is exercised over them.
/// </summary>
[TestClass]
internal sealed class KeriRotationTests
{
    private const string Aid = "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB";
    private const string InceptionSaid = Aid;

    //The current signing keys of the inception (not under test here; any valid keys).
    private static readonly string[] InitialSigningKeys =
    [
        "DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu",
        "DG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5",
        "DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV"
    ];

    //The pre-rotated next keys from the specification's inception example; these become the rotation's current keys.
    private static readonly string[] NextKeys =
    [
        "DLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8dj",
        "DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz",
        "DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf"
    ];

    //The published next-key digests (the inception 'n' field) committing to NextKeys.
    private static readonly string[] CommittedDigests =
    [
        "ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB",
        "ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YT",
        "EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG"
    ];

    private static readonly string[] Backers =
    [
        "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
        "BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt"
    ];

    private static readonly string[] Empty = [];


    /// <summary>
    /// An algorithm-agile digest oracle: a BLAKE3-tagged request routes to the BouncyCastle backend, every other
    /// request to the Microsoft backend. An independent oracle constructed in the test, not the production registry.
    /// </summary>
    private static readonly ComputeDigestDelegate AgileDigest = (input, outputByteLength, tag, pool, context, cancellationToken) =>
        tag.TryGet<CryptoAlgorithm>(out CryptoAlgorithm algorithm) && algorithm == CryptoAlgorithm.Blake3
            ? BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync(input, outputByteLength, tag, pool, context, cancellationToken)
            : MicrosoftEntropyFunctions.ComputeDigestAsync(input, outputByteLength, tag, pool, context, cancellationToken);


    /// <summary>
    /// The next-key digest derivation is a qualified Blake3-256 digest of the qualified (qb64) public key: each of
    /// the specification example's next keys digests to its published commitment.
    /// </summary>
    [TestMethod]
    public async Task NextKeyDigestMatchesSpecificationExample()
    {
        for(int i = 0; i < NextKeys.Length; i++)
        {
            string digest = await CesrSaid.ComputeAsync(Encoding.UTF8.GetBytes(NextKeys[i]), CesrDigestCodes.Blake3Bits256, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None);

            Assert.AreEqual(CommittedDigests[i], digest, $"The digest of next key {i} must equal the specification's published commitment.");
        }
    }


    /// <summary>
    /// A rotation that reveals the committed next keys verifies pre-rotation and rolls the key state forward.
    /// </summary>
    [TestMethod]
    public async Task RotateVerifiesPreRotationAndRollsState()
    {
        KeriKeyState inception = KeriKeyStateMachine.Incept(Inception(CommittedDigests));
        KeriRotationEvent rotation = Rotation(NextKeys, backersToRemove: Empty, backersToAdd: Empty);

        KeriKeyState rotated = await KeriKeyStateMachine.RotateAsync(inception, rotation, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(1, rotated.SequenceNumber);
        CollectionAssert.AreEqual(NextKeys, (System.Collections.ICollection)rotated.SigningKeys, "The newly current keys are the revealed next keys.");
        Assert.AreEqual(KeriThreshold.Unweighted(1), rotated.SigningThreshold);
        Assert.AreEqual(rotation.Said, rotated.LastEventSaid);
    }


    /// <summary>
    /// A partial rotation that reveals a proper subset of the committed next keys sufficient to satisfy the prior
    /// next threshold verifies and rolls forward to exactly the revealed keys; the unrevealed committed key is held
    /// in reserve.
    /// </summary>
    [TestMethod]
    public async Task RotatePartialRotationRevealsSatisfyingSubset()
    {
        KeriKeyState inception = KeriKeyStateMachine.Incept(Inception(CommittedDigests));

        //Reveal two of the three committed next keys; the prior next threshold is "2", so the subset satisfies it.
        string[] subset = [NextKeys[0], NextKeys[1]];
        KeriRotationEvent rotation = Rotation(subset, backersToRemove: Empty, backersToAdd: Empty);

        KeriKeyState rotated = await KeriKeyStateMachine.RotateAsync(inception, rotation, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(1, rotated.SequenceNumber);
        CollectionAssert.AreEqual(subset, (System.Collections.ICollection)rotated.SigningKeys, "The newly current keys are exactly the revealed subset; the third committed key was held in reserve.");
    }


    /// <summary>
    /// A rotation whose exposed (committed) keys are too few to satisfy the prior next threshold is rejected, even
    /// though each revealed key individually matches a commitment — rotation authority requires a satisfying
    /// subset.
    /// </summary>
    [TestMethod]
    public async Task RotateRejectsExposedSubsetBelowPriorNextThreshold()
    {
        KeriKeyState inception = KeriKeyStateMachine.Incept(Inception(CommittedDigests));

        //Reveal only one of the three committed next keys; the prior next threshold "2" cannot be satisfied.
        string[] tooFew = [NextKeys[0]];
        KeriRotationEvent rotation = Rotation(tooFew, backersToRemove: Empty, backersToAdd: Empty);

        await Assert.ThrowsExactlyAsync<KeriException>(async () => await KeriKeyStateMachine.RotateAsync(inception, rotation, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// An augmented rotation that adds a key never pre-rotated verifies as long as the exposed committed subset
    /// satisfies the prior next threshold; the added key becomes a current key with no rotation authority.
    /// </summary>
    [TestMethod]
    public async Task RotateAllowsAugmentedKey()
    {
        KeriKeyState inception = KeriKeyStateMachine.Incept(Inception(CommittedDigests));

        //Two committed next keys (satisfying the prior next threshold "2") plus one key that was never committed.
        string augmented = "DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu";
        string[] revealed = [NextKeys[0], NextKeys[1], augmented];
        KeriRotationEvent rotation = Rotation(revealed, backersToRemove: Empty, backersToAdd: Empty);

        KeriKeyState rotated = await KeriKeyStateMachine.RotateAsync(inception, rotation, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None);

        CollectionAssert.AreEqual(revealed, (System.Collections.ICollection)rotated.SigningKeys, "The augmented key is carried as a current key alongside the exposed pre-rotated keys.");
    }


    /// <summary>
    /// A rotation applies its backer remove and add lists to the inherited backer set.
    /// </summary>
    [TestMethod]
    public async Task RotateAppliesBackerChanges()
    {
        KeriKeyState inception = KeriKeyStateMachine.Incept(Inception(CommittedDigests));
        string[] toAdd = ["BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH"];
        string[] toRemove = [Backers[0]];
        KeriRotationEvent rotation = Rotation(NextKeys, backersToRemove: toRemove, backersToAdd: toAdd);

        KeriKeyState rotated = await KeriKeyStateMachine.RotateAsync(inception, rotation, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None);

        CollectionAssert.AreEqual(new[] { Backers[1], toAdd[0] }, (System.Collections.ICollection)rotated.Backers, "The removed backer is gone and the added backer is appended.");
    }


    private static KeriInceptionEvent Inception(IReadOnlyList<string> nextKeyDigests) => new(
        Said: InceptionSaid,
        Prefix: Aid,
        SequenceNumber: 0,
        SigningThreshold: "2",
        SigningKeys: InitialSigningKeys,
        NextThreshold: "2",
        NextKeyDigests: nextKeyDigests,
        BackerThreshold: "2",
        Backers: Backers,
        ConfigurationTraits: Empty);


    private static KeriRotationEvent Rotation(IReadOnlyList<string> signingKeys, IReadOnlyList<string> backersToRemove, IReadOnlyList<string> backersToAdd) => new(
        Said: "ERotationSaid00000000000000000000000000000",
        Prefix: Aid,
        SequenceNumber: 1,
        PriorSaid: InceptionSaid,
        SigningThreshold: "1",
        SigningKeys: signingKeys,
        NextThreshold: "2",
        NextKeyDigests: CommittedDigests,
        BackerThreshold: "2",
        BackersToRemove: backersToRemove,
        BackersToAdd: backersToAdd,
        ConfigurationTraits: Empty);
}
