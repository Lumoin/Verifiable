using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for <see cref="MdocIssuance.BuildDocument"/> — verifies that the
/// static issuance function produces a pure logical
/// <see cref="MdocDocument"/> (no wire bytes, no signed MSO) with the
/// structural invariants ISO/IEC 18013-5 §8.3 and §9.1.2.5 require:
/// per-item random salts ≥ 16 bytes, sequential digestIDs, ordered
/// per-namespace claim lists, and salt ownership flowing through the
/// returned document so the caller can dispose without leaking sensitive
/// memory.
/// </summary>
/// <remarks>
/// <para>
/// The function's contract stops at the logical model. Serialization (CBOR
/// Tag 24 wrapping, MSO digest computation, COSE_Sign1 production) is the
/// downstream serializer's responsibility and is tested separately when that
/// chunk lands. Tests here therefore assert that
/// <see cref="MdocIssuerSignedItem.WireBytes"/> and
/// <see cref="MdocIssuerSigned.EncodedIssuerAuth"/> are <see langword="null"/>
/// on the function's output — the serializer fills them.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocIssuanceTests
{
    private const string MdlDocType = "org.iso.18013.5.1.mDL";
    private const string MdlNamespace = "org.iso.18013.5.1";
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";
    private const string PidNamespace = "eu.europa.ec.eudi.pid.1";


    [TestMethod]
    public void BuildDocumentProducesLogicalDocumentWithExpectedShape()
    {
        //The type system carries the "no WireBytes, no IssuerAuth, no
        //DeviceSigned" invariants for the logical build-scaffold form —
        //MdocLogicalDocument has no DeviceSigned slot, MdocLogicalIssuerSigned
        //has no IssuerAuth slot, MdocLogicalIssuerSignedItem has no WireBytes
        //slot. There is nothing left to assert at runtime beyond the
        //structural fields we DID populate.
        using MdocLogicalDocument document = MdocIssuance.BuildDocument(
            MdlDocType,
            [Claim(MdlNamespace, "family_name", "Mustermann")],
            DefaultRandomGenerator);

        Assert.AreEqual(MdlDocType, document.DocType);
        Assert.HasCount(1, document.IssuerSigned.NameSpaces[MdlNamespace]);

        MdocLogicalIssuerSignedItem onlyItem = document.IssuerSigned.NameSpaces[MdlNamespace][0];
        Assert.AreEqual("family_name", onlyItem.ElementIdentifier);
        Assert.AreEqual(0u, onlyItem.DigestId);
    }


    [TestMethod]
    public void BuildDocumentAssignsSequentialDigestIdsAcrossTheWholeDocument()
    {
        using MdocLogicalDocument document = MdocIssuance.BuildDocument(
            MdlDocType,
            [
                Claim(MdlNamespace, "family_name", "Mustermann"),
                Claim(MdlNamespace, "given_name", "Erika"),
                Claim("org.iso.18013.5.1.aamva", "DHS_compliance", "F")
            ],
            DefaultRandomGenerator);

        IReadOnlyList<MdocLogicalIssuerSignedItem> mdlItems = document.IssuerSigned.NameSpaces[MdlNamespace];
        IReadOnlyList<MdocLogicalIssuerSignedItem> aamvaItems = document.IssuerSigned.NameSpaces["org.iso.18013.5.1.aamva"];

        Assert.AreEqual(0u, mdlItems[0].DigestId);
        Assert.AreEqual(1u, mdlItems[1].DigestId);
        Assert.AreEqual(2u, aamvaItems[0].DigestId,
            "Globally sequential — the third claim across namespaces yields digestID 2.");
    }


    [TestMethod]
    public void BuildDocumentGeneratesAtLeastSixteenByteRandoms()
    {
        using MdocLogicalDocument document = MdocIssuance.BuildDocument(
            MdlDocType,
            [
                Claim(MdlNamespace, "family_name", "Mustermann"),
                Claim(MdlNamespace, "given_name", "Erika")
            ],
            DefaultRandomGenerator);

        foreach(MdocLogicalIssuerSignedItem item in document.IssuerSigned.NameSpaces[MdlNamespace])
        {
            Assert.IsGreaterThanOrEqualTo(
                MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength,
                item.Random.Length,
                "ISO/IEC 18013-5 §9.1.2.5 requires the per-item random to be at least 16 bytes.");
        }
    }


    [TestMethod]
    public void BuildDocumentRejectsRandomShorterThanIsoMinimum()
    {
        //A misconfigured delegate that hands back an undersized salt must be
        //surfaced as an error — silently accepting it would let an issuer
        //publish digest commitments with a sub-16-byte salt and violate the
        //§9.1.2.5 security margin.
        //Deliberately undersized (8 bytes, below the ISO §9.1.2.5 16-byte minimum) to prove the
        //issuer rejects it. Routed through the provider like every other salt; the 8 is the point.
        Salt UnderSizedRandom() =>
            TestSalts.Generate(8, CryptoTags.MdocIssuerSignedItemRandom, BaseMemoryPool.Shared);

        InvalidOperationException ex = Assert.ThrowsExactly<InvalidOperationException>(() =>
            MdocIssuance.BuildDocument(
                MdlDocType,
                [Claim(MdlNamespace, "family_name", "Mustermann")],
                UnderSizedRandom));

        Assert.Contains("8 bytes", ex.Message);
        Assert.Contains("16", ex.Message);
    }


    [TestMethod]
    public void BuildDocumentPreservesInsertionOrderWithinAnamespace()
    {
        //ISO/IEC 18013-5 §9.1.2 commits the MSO digests against per-item wire
        //bytes which depend on map insertion order. The logical model must
        //preserve the caller's authored order so the downstream serializer
        //can emit them in that order verbatim.
        string[] elements = ["family_name", "given_name", "birth_date", "issuing_country"];

        using MdocLogicalDocument document = MdocIssuance.BuildDocument(
            MdlDocType,
            elements.Select(e => Claim(MdlNamespace, e, e + "-value")).ToArray(),
            DefaultRandomGenerator);

        IReadOnlyList<MdocLogicalIssuerSignedItem> items = document.IssuerSigned.NameSpaces[MdlNamespace];

        Assert.HasCount(elements.Length, items);
        for(int i = 0; i < elements.Length; i++)
        {
            Assert.AreEqual(elements[i], items[i].ElementIdentifier);
        }
    }


    [TestMethod]
    public void BuildDocumentSeparatesNamespacesIntoDistinctKeyedLists()
    {
        using MdocLogicalDocument document = MdocIssuance.BuildDocument(
            PidDocType,
            [
                Claim(PidNamespace, "family_name", "Mustermann"),
                Claim(PidNamespace, "given_name", "Erika"),
                Claim("eu.europa.ec.eudi.pid.de.1", "id_card_number", "DE-123")
            ],
            DefaultRandomGenerator);

        Assert.HasCount(2, document.IssuerSigned.NameSpaces);
        Assert.HasCount(2, document.IssuerSigned.NameSpaces[PidNamespace]);
        Assert.HasCount(1, document.IssuerSigned.NameSpaces["eu.europa.ec.eudi.pid.de.1"]);
    }


    [TestMethod]
    public void BuildDocumentWithoutClaimsThrows()
    {
        InvalidOperationException ex = Assert.ThrowsExactly<InvalidOperationException>(() =>
            MdocIssuance.BuildDocument(MdlDocType, [], DefaultRandomGenerator));

        Assert.Contains("zero claims", ex.Message);
    }


    [TestMethod]
    public void BuildDocumentRandomsAreDistinctAcrossClaims()
    {
        //A regression guard against an entropy source so broken it returns
        //identical bytes. Two 16-byte randoms colliding by chance is a 2^-128
        //event; if it ever fires it's a real bug, not a flake.
        using MdocLogicalDocument document = MdocIssuance.BuildDocument(
            MdlDocType,
            [
                Claim(MdlNamespace, "family_name", "Mustermann"),
                Claim(MdlNamespace, "given_name", "Erika")
            ],
            DefaultRandomGenerator);

        IReadOnlyList<MdocLogicalIssuerSignedItem> items = document.IssuerSigned.NameSpaces[MdlNamespace];
        Assert.IsFalse(
            items[0].Random.AsReadOnlySpan().SequenceEqual(items[1].Random.AsReadOnlySpan()),
            "Two freshly-generated mdoc randoms must differ.");
    }


    [TestMethod]
    public void BuildDocumentRoutesRandomGenerationThroughDelegate()
    {
        //The delegate is the only path through which randoms enter the
        //function — proven by observing the call count.
        int invocations = 0;
        Salt TrackingRandom()
        {
            invocations++;
            return MdocTestFixtures.ItemRandomSalt();
        }

        using MdocLogicalDocument document = MdocIssuance.BuildDocument(
            MdlDocType,
            [
                Claim(MdlNamespace, "family_name", "Mustermann"),
                Claim(MdlNamespace, "given_name", "Erika"),
                Claim(MdlNamespace, "birth_date", "1971-09-01")
            ],
            TrackingRandom);

        Assert.AreEqual(3, invocations, "One salt per claim, generated via the supplied delegate.");
    }


    [TestMethod]
    public void RandomCarriesMdocIssuerSignedItemRandomPurposeAndProviderProvenance()
    {
        //The random is generated through the entropy provider, which stamps CBOM provenance onto the
        //salt's tag while preserving the mdoc IssuerSignedItem-random purpose. The item exposes the salt
        //verbatim, so both the purpose (semantic identity) and the provenance (CBOM flows) are
        //recoverable downstream — provenance the removed Salt.Generate convenience could not have carried.
        using MdocLogicalDocument document = MdocIssuance.BuildDocument(
            MdlDocType,
            [Claim(MdlNamespace, "family_name", "Mustermann")],
            DefaultRandomGenerator);

        MdocLogicalIssuerSignedItem item = document.IssuerSigned.NameSpaces[MdlNamespace][0];

        Assert.AreEqual(Purpose.Salt, item.Random.Tag.Get<Purpose>(), "The mdoc random must retain the Salt purpose.");
        Assert.IsTrue(item.Random.Tag.TryGet<ProviderLibrary>(out _), "The entropy provider must stamp CBOM provenance onto the random's tag.");
    }


    [TestMethod]
    public void BuildDocumentRejectsNullDocType()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            MdocIssuance.BuildDocument(string.Empty, [Claim(MdlNamespace, "x", "y")], DefaultRandomGenerator));
    }


    [TestMethod]
    public void BuildDocumentRejectsNullDelegate()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            MdocIssuance.BuildDocument(MdlDocType, [Claim(MdlNamespace, "x", "y")], generateRandom: null!));
    }


    [TestMethod]
    public void DocumentDisposesEverySaltUnderEveryNamespace()
    {
        MdocLogicalDocument document = MdocIssuance.BuildDocument(
            MdlDocType,
            [
                Claim(MdlNamespace, "family_name", "Mustermann"),
                Claim(MdlNamespace, "given_name", "Erika"),
                Claim("org.iso.18013.5.1.aamva", "DHS_compliance", "F")
            ],
            DefaultRandomGenerator);

        //Snapshot the salt references before disposal so we can probe them after.
        List<Salt> allSalts = [];
        foreach(IReadOnlyList<MdocLogicalIssuerSignedItem> items in document.IssuerSigned.NameSpaces.Values)
        {
            foreach(MdocLogicalIssuerSignedItem item in items)
            {
                allSalts.Add(item.Random);
            }
        }

        document.Dispose();

        //Disposed salts throw ObjectDisposedException when accessed; that's
        //the proof the cascade walked through every item and disposed each
        //salt.
        foreach(Salt salt in allSalts)
        {
            Assert.ThrowsExactly<ObjectDisposedException>(() => _ = salt.AsReadOnlySpan().Length);
        }
    }


    /// <summary>
    /// Default test salt source — 16 bytes, tagged with
    /// <see cref="CryptoTags.MdocIssuerSignedItemRandom"/>, allocated from
    /// the shared sensitive memory pool per the test memory rule.
    /// </summary>
    private static Salt DefaultRandomGenerator() =>
        MdocTestFixtures.ItemRandomSalt();


    /// <summary>
    /// Builds an <see cref="MdocClaimInput"/> from a UTF-8 string value. The
    /// function under test is format-agnostic, so the bytes here are just a
    /// marker; the assertions in this class operate on the structural fields
    /// rather than parsing the encoded element value.
    /// </summary>
    private static MdocClaimInput Claim(string nameSpace, string elementIdentifier, string value) =>
        new()
        {
            NameSpace = nameSpace,
            ElementIdentifier = elementIdentifier,
            EncodedElementValue = System.Text.Encoding.UTF8.GetBytes(value)
        };
}
