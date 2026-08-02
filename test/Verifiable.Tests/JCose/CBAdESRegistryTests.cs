using System;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the CB-AdES stage-1 vocabulary registries — <see cref="CBAdESHeaderParameters"/> (clause 5.2.1
/// Table 1 label assignments plus the clause 5.3.1 Table 8 <c>uHeaders</c> tag) and
/// <see cref="CBAdESCommitmentTypes"/> (Annex C's six well-known commitment-type URI/OID pairs), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
[TestClass]
internal sealed class CBAdESRegistryTests
{
    /// <summary>One CB-AdES header parameter label under test: its wire name and Table 1/Table 8 integer value.</summary>
    /// <param name="WireName">The CDDL parameter name, e.g. <c>x5ts</c>.</param>
    /// <param name="Label">The registered integer label.</param>
    private sealed record HeaderParameterLabel(string WireName, int Label);


    /// <summary>The eight labels <see cref="CBAdESHeaderParameters"/> registers, paired with their wire names.</summary>
    /// <returns>Every registered label, in Table 1/Table 8 order.</returns>
    private static HeaderParameterLabel[] AllHeaderParameterLabels() =>
    [
        new("x5ts", CBAdESHeaderParameters.X5ts),
        new("srCms", CBAdESHeaderParameters.SrCms),
        new("sigPl", CBAdESHeaderParameters.SigPl),
        new("srAts", CBAdESHeaderParameters.SrAts),
        new("adoTst", CBAdESHeaderParameters.AdoTst),
        new("sigPId", CBAdESHeaderParameters.SigPId),
        new("sigD", CBAdESHeaderParameters.SigD),
        new("uHeaders", CBAdESHeaderParameters.UHeaders)
    ];


    /// <summary>
    /// Table 1 (clause 5.2.1) and Table 8 (clause 5.3.1) assign 261-268 to the eight labels, in that order,
    /// cross-verified by the preflight leg against Annex B's IANA registry entries and the inline CDDL
    /// <c>_l</c> assignments — all three sources agree.
    /// </summary>
    [TestMethod]
    public void HeaderParameterLabelsMatchTable1AndTable8Assignments()
    {
        //MSTEST0032: both sides are compile-time constants (Table 1/Table 8's assigned integer literals
        //pinned against the registry's own const int fields) — the assertion is deliberately a conformance
        //pin against the spec table, not a runtime-varying check.
#pragma warning disable MSTEST0032 // Assertion condition is always true
        Assert.AreEqual(261, CBAdESHeaderParameters.X5ts);
        Assert.AreEqual(262, CBAdESHeaderParameters.SrCms);
        Assert.AreEqual(263, CBAdESHeaderParameters.SigPl);
        Assert.AreEqual(264, CBAdESHeaderParameters.SrAts);
        Assert.AreEqual(265, CBAdESHeaderParameters.AdoTst);
        Assert.AreEqual(266, CBAdESHeaderParameters.SigPId);
        Assert.AreEqual(267, CBAdESHeaderParameters.SigD);
        Assert.AreEqual(268, CBAdESHeaderParameters.UHeaders);
#pragma warning restore MSTEST0032 // Assertion condition is always true
    }


    /// <summary><see cref="CBAdESHeaderParameters.IsCBAdESLabel"/> recognizes every one of the eight registered labels.</summary>
    [TestMethod]
    public void IsCBAdESLabelReturnsTrueForEveryRegisteredLabel()
    {
        foreach(HeaderParameterLabel entry in AllHeaderParameterLabels())
        {
            Assert.IsTrue(CBAdESHeaderParameters.IsCBAdESLabel(entry.Label), $"{entry.WireName} (label {entry.Label}) must be recognized as a CB-AdES label.");
        }
    }


    /// <summary>
    /// <see cref="CBAdESHeaderParameters.IsCBAdESLabel"/> rejects labels outside the registered 261-268 range,
    /// including the RFC 9360 <c>x5chain</c> label (33) this document reuses in <c>UHeaderInstance</c> but
    /// does not itself register in this table.
    /// </summary>
    [TestMethod]
    public void IsCBAdESLabelReturnsFalseForLabelsOutsideTheRegisteredRange()
    {
        foreach(int label in new[] { 0, -1, 33, 260, 269, int.MaxValue })
        {
            Assert.IsFalse(CBAdESHeaderParameters.IsCBAdESLabel(label), $"Label {label} must not be recognized as a CB-AdES label.");
        }
    }


    /// <summary><see cref="CBAdESHeaderParameters.GetParameterName"/> returns each label's exact CDDL wire name.</summary>
    [TestMethod]
    public void GetParameterNameReturnsTheWireNameForEveryRegisteredLabel()
    {
        foreach(HeaderParameterLabel entry in AllHeaderParameterLabels())
        {
            Assert.AreEqual(entry.WireName, CBAdESHeaderParameters.GetParameterName(entry.Label));
        }
    }


    /// <summary><see cref="CBAdESHeaderParameters.GetParameterName"/> returns <see langword="null"/> for an unregistered label.</summary>
    [TestMethod]
    public void GetParameterNameReturnsNullForAnUnregisteredLabel()
    {
        Assert.IsNull(CBAdESHeaderParameters.GetParameterName(33));
        Assert.IsNull(CBAdESHeaderParameters.GetParameterName(0));
    }


    /// <summary>
    /// One Annex C commitment-type entry under test: its URI form, its <c>id-cti-ets-*</c> OID form, and the
    /// <c>Is*</c> predicate that recognizes both.
    /// </summary>
    /// <param name="Uri">The Annex C commitment-type URI.</param>
    /// <param name="Oid">The paired <c>id-cti-ets-*</c> OID, per RFC 5126 Annex B.2.</param>
    /// <param name="Predicate">The <see cref="CBAdESCommitmentTypes"/> predicate that should recognize this entry.</param>
    private sealed record CommitmentType(string Uri, string Oid, Func<string, bool> Predicate);


    /// <summary>The six Annex C commitment types, each paired with the <c>Is*</c> predicate that should recognize it.</summary>
    /// <returns>Every Annex C entry, in Annex C row order.</returns>
    private static CommitmentType[] AllCommitmentTypes() =>
    [
        new("http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin", "1.2.840.113549.1.9.16.6.1", CBAdESCommitmentTypes.IsProofOfOrigin),
        new("http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt", "1.2.840.113549.1.9.16.6.2", CBAdESCommitmentTypes.IsProofOfReceipt),
        new("http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery", "1.2.840.113549.1.9.16.6.3", CBAdESCommitmentTypes.IsProofOfDelivery),
        new("http://uri.etsi.org/01903/v1.2.2#ProofOfSender", "1.2.840.113549.1.9.16.6.4", CBAdESCommitmentTypes.IsProofOfSender),
        new("http://uri.etsi.org/01903/v1.2.2#ProofOfApproval", "1.2.840.113549.1.9.16.6.5", CBAdESCommitmentTypes.IsProofOfApproval),
        new("http://uri.etsi.org/01903/v1.2.2#ProofOfCreation", "1.2.840.113549.1.9.16.6.6", CBAdESCommitmentTypes.IsProofOfCreation)
    ];


    /// <summary>
    /// Annex C's six commitment-type URIs match exactly, character for character, against the
    /// <see cref="CBAdESCommitmentTypes"/> registry's exposed constants.
    /// </summary>
    [TestMethod]
    public void AnnexCCommitmentTypeUrisMatchTheRegisteredValues()
    {
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin", CBAdESCommitmentTypes.ProofOfOriginUri);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt", CBAdESCommitmentTypes.ProofOfReceiptUri);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery", CBAdESCommitmentTypes.ProofOfDeliveryUri);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#ProofOfSender", CBAdESCommitmentTypes.ProofOfSenderUri);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#ProofOfApproval", CBAdESCommitmentTypes.ProofOfApprovalUri);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#ProofOfCreation", CBAdESCommitmentTypes.ProofOfCreationUri);
    }


    /// <summary>
    /// Annex C's six commitment-type OIDs (<c>id-cti-ets-*</c>, RFC 5126 Annex B.2) match exactly against the
    /// <see cref="CBAdESCommitmentTypes"/> registry's exposed constants.
    /// </summary>
    [TestMethod]
    public void AnnexCCommitmentTypeOidsMatchTheRegisteredValues()
    {
        Assert.AreEqual("1.2.840.113549.1.9.16.6.1", CBAdESCommitmentTypes.ProofOfOriginOid);
        Assert.AreEqual("1.2.840.113549.1.9.16.6.2", CBAdESCommitmentTypes.ProofOfReceiptOid);
        Assert.AreEqual("1.2.840.113549.1.9.16.6.3", CBAdESCommitmentTypes.ProofOfDeliveryOid);
        Assert.AreEqual("1.2.840.113549.1.9.16.6.4", CBAdESCommitmentTypes.ProofOfSenderOid);
        Assert.AreEqual("1.2.840.113549.1.9.16.6.5", CBAdESCommitmentTypes.ProofOfApprovalOid);
        Assert.AreEqual("1.2.840.113549.1.9.16.6.6", CBAdESCommitmentTypes.ProofOfCreationOid);
    }


    /// <summary>Each <c>Is*</c> predicate recognizes its own entry, by both its URI and its OID form.</summary>
    [TestMethod]
    public void EachCommitmentTypePredicateRecognizesItsOwnUriAndOidForms()
    {
        foreach(CommitmentType entry in AllCommitmentTypes())
        {
            Assert.IsTrue(entry.Predicate(entry.Uri), $"The predicate for {entry.Uri} must recognize its own URI form.");
            Assert.IsTrue(entry.Predicate(entry.Oid), $"The predicate for {entry.Uri} must recognize its own OID form ({entry.Oid}).");
        }
    }


    /// <summary>
    /// Each <c>Is*</c> predicate rejects every one of the other five commitment types' URI and OID forms — the
    /// six entries are pairwise distinguishable, not just individually recognizable.
    /// </summary>
    [TestMethod]
    public void EachCommitmentTypePredicateRejectsTheOtherFiveCommitmentTypes()
    {
        CommitmentType[] entries = AllCommitmentTypes();
        for(int i = 0; i < entries.Length; i++)
        {
            for(int j = 0; j < entries.Length; j++)
            {
                if(i == j)
                {
                    continue;
                }

                Assert.IsFalse(entries[i].Predicate(entries[j].Uri), $"The predicate for {entries[i].Uri} must reject {entries[j].Uri}.");
                Assert.IsFalse(entries[i].Predicate(entries[j].Oid), $"The predicate for {entries[i].Uri} must reject {entries[j].Oid}.");
            }
        }
    }


    /// <summary>
    /// <see cref="CBAdESCommitmentTypes.IsWellKnownCommitmentType"/> recognizes every one of the six Annex C
    /// entries, by URI or OID.
    /// </summary>
    [TestMethod]
    public void IsWellKnownCommitmentTypeReturnsTrueForEveryAnnexCEntry()
    {
        foreach(CommitmentType entry in AllCommitmentTypes())
        {
            Assert.IsTrue(CBAdESCommitmentTypes.IsWellKnownCommitmentType(entry.Uri));
            Assert.IsTrue(CBAdESCommitmentTypes.IsWellKnownCommitmentType(entry.Oid));
        }
    }


    /// <summary>
    /// <see cref="CBAdESCommitmentTypes.IsWellKnownCommitmentType"/> rejects a URI outside the Annex C
    /// vocabulary — the commitment-type value space is an open registry (clause 5.2.3 NOTE 2), so an
    /// unrecognized URI is not itself malformed, only outside this closed six-entry lookup.
    /// </summary>
    [TestMethod]
    public void IsWellKnownCommitmentTypeReturnsFalseForAnArbitraryUri()
    {
        Assert.IsFalse(CBAdESCommitmentTypes.IsWellKnownCommitmentType("http://example.org/not-a-commitment-type"));
    }


    /// <summary>
    /// <see cref="CBAdESCommitmentTypes.Equals(string, string)"/> compares as an exact ordinal character
    /// sequence — the type's own remarks record that identifiers are compared and written as exact character
    /// sequences specifically because <see cref="Uri"/> normalization would collapse spellings that should
    /// compare unequal — so an upper-cased spelling of a registered URI is a different value, not the same
    /// commitment type.
    /// </summary>
    [TestMethod]
    public void EqualsUsesOrdinalCaseSensitiveComparison()
    {
        string upperCased = CBAdESCommitmentTypes.ProofOfOriginUri.ToUpperInvariant();

        Assert.IsFalse(CBAdESCommitmentTypes.Equals(CBAdESCommitmentTypes.ProofOfOriginUri, upperCased));
        Assert.IsFalse(CBAdESCommitmentTypes.IsProofOfOrigin(upperCased));
    }


    /// <summary>
    /// <see cref="CBAdESCommitmentTypes.Equals(string, string)"/> returns <see langword="true"/> both for a
    /// value compared with an equal-but-distinct string instance and for a value compared with itself by
    /// reference (the two branches of the method's own implementation).
    /// </summary>
    [TestMethod]
    public void EqualsReturnsTrueForEqualValuesAndForReferenceEqualValues()
    {
        string origin = CBAdESCommitmentTypes.ProofOfOriginUri;
        string equalButDistinctInstance = new(origin.ToCharArray());

        Assert.IsTrue(CBAdESCommitmentTypes.Equals(origin, origin));
        Assert.IsTrue(CBAdESCommitmentTypes.Equals(origin, equalButDistinctInstance));
        Assert.IsTrue(CBAdESCommitmentTypes.Equals(CBAdESCommitmentTypes.ProofOfOriginOid, CBAdESCommitmentTypes.ProofOfOriginOid));
    }
}
