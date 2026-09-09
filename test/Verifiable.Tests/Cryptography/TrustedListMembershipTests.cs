using System;
using System.Collections.Generic;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Proves <see cref="TrustedListMembership.Evaluate(IReadOnlyList{PkiCertificateMemory}, IReadOnlyList{TrustedList}, ReadCertificateSubjectKeyIdentifierDelegate, ReadCertificateSubjectNameDelegate)"/>
/// realises the OID4VP 1.0 §6.1.1.2 <c>etsi_tl</c> membership rule over the ETSI TS 119 612 V2.4.1 model: the
/// trust chain of a matching Credential must contain at least one X.509 certificate that matches one of the
/// entries of the named Trusted List or its cascading Trusted Lists. Fixtures are built from
/// <see cref="X509ChainTestRing"/> certificates and <see cref="TrustedListFixtures"/> list graphs; an
/// <see cref="X509SubjectKeyIdentifierIdentity"/> entry's base64 and an <see cref="X509SubjectNameIdentity"/>
/// entry's string are derived from the certificate itself, never read back through the backend reader the walk
/// exercises.
/// </summary>
[TestClass]
internal sealed class TrustedListMembershipTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The identifier of the member-state list the fixtures publish and hold the matching entry on.</summary>
    private const string MemberStateListIdentifier = "https://tl.example-state.test/tsl";

    /// <summary>The identifier of the regional list the two-level cascade routes through.</summary>
    private const string RegionalListIdentifier = "https://tl.example-region.test/tsl";

    /// <summary>The Microsoft-backend name selecting <see cref="MicrosoftX509Functions"/>'s readers.</summary>
    private const string MicrosoftBackend = "Microsoft";

    /// <summary>The BouncyCastle-backend name selecting <see cref="BouncyCastleX509Functions"/>'s readers.</summary>
    private const string BouncyCastleBackend = "BouncyCastle";


    /// <summary>
    /// Proves the <c>X509Certificate</c> entry kind of ETSI TS 119 612 clause 5.5.3: a held list whose service
    /// digital identity carries the leaf's issuer certificate by DER matches, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see> — "The trust chain of a matching Credential MUST
    /// contain at least one X.509 Certificate that matches one of the entries of the Trusted List or its
    /// cascading Trusted Lists."
    /// </summary>
    [TestMethod]
    public void ChainCertificateMatchingAnX509CertificateEntryYieldsTheListIdentifier()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("cert-entry.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList list = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.CertificateEntry(ring.Intermediate.Certificate, BaseMemoryPool.Shared)]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [list],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.Contains(new TrustedListIdentifier(MemberStateListIdentifier), result, "§6.1.1.2: a chain certificate matching an X509Certificate entry of a held list must place that list's identifier in the membership set.");
    }


    /// <summary>
    /// Proves the <c>X509SKI</c> entry kind of ETSI TS 119 612 clause 5.5.3: a held list whose service digital
    /// identity carries the standard base64 of the leaf's issuer certificate's SubjectKeyIdentifier
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2">RFC 5280, Section 4.2.1.2</see>)
    /// matches, per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">ETSI
    /// TS 119 612, clause 5.5.3</see>, satisfying
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s "at least one X.509 Certificate that matches
    /// one of the entries of the Trusted List" — read through each X.509 backend's SubjectKeyIdentifier reader.
    /// </summary>
    /// <param name="backend">The X.509 backend whose SubjectKeyIdentifier reader the walk uses.</param>
    [TestMethod]
    [DataRow(MicrosoftBackend)]
    [DataRow(BouncyCastleBackend)]
    public void ChainCertificateMatchingAnX509SubjectKeyIdentifierEntryYieldsTheListIdentifier(string backend)
    {
        (ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier, ReadCertificateSubjectNameDelegate readSubjectName) = BackendReaders(backend);

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("ski-entry.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList list = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.SubjectKeyIdentifierEntry(ring.Intermediate.Certificate)]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(chain, [list], readSubjectKeyIdentifier, readSubjectName);

        Assert.Contains(new TrustedListIdentifier(MemberStateListIdentifier), result, "clause 5.5.3 X509SKI: a chain certificate whose SubjectKeyIdentifier equals a held list's X509SKI entry bytes must place that list's identifier in the membership set.");
    }


    /// <summary>
    /// Proves the <c>X509SubjectName</c> entry kind of ETSI TS 119 612 clause 5.5.3: a held list whose service
    /// digital identity carries the leaf's issuer certificate Subject as an
    /// <see href="https://www.rfc-editor.org/rfc/rfc4514">RFC 4514</see> distinguished name string matches, per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">ETSI
    /// TS 119 612, clause 5.5.3</see>, satisfying
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s "at least one X.509 Certificate that matches
    /// one of the entries of the Trusted List" — read through each X.509 backend's Subject reader.
    /// </summary>
    /// <param name="backend">The X.509 backend whose Subject reader the walk uses.</param>
    [TestMethod]
    [DataRow(MicrosoftBackend)]
    [DataRow(BouncyCastleBackend)]
    public void ChainCertificateMatchingAnX509SubjectNameEntryYieldsTheListIdentifier(string backend)
    {
        (ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier, ReadCertificateSubjectNameDelegate readSubjectName) = BackendReaders(backend);

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("subject-name-entry.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        //Hand-authored from the intermediate's known Subject "CN=Verifiable Test Intermediate CA, O=Verifiable
        //Test Infrastructure" per RFC 4514: descriptors CN/O, the RDNSequence rendered most-specific first,
        //comma-joined without spaces — never read through the reader under test.
        using TrustedList list = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.SubjectNameEntry("CN=Verifiable Test Intermediate CA,O=Verifiable Test Infrastructure")]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(chain, [list], readSubjectKeyIdentifier, readSubjectName);

        Assert.Contains(new TrustedListIdentifier(MemberStateListIdentifier), result, "clause 5.5.3 X509SubjectName: a chain certificate whose RFC 4514 Subject equals a held list's X509SubjectName entry must place that list's identifier in the membership set.");
    }


    /// <summary>
    /// Proves the <c>Other</c> entry kind of ETSI TS 119 612 clause 5.5.3 is never matched against a chain
    /// certificate — a held list whose only entry recognising the chain's issuer is an
    /// <see cref="OtherDigitalIdentity"/> contributes no membership, so
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s "at least one X.509 Certificate that matches
    /// one of the entries of the Trusted List" is not satisfied by a non-certificate identity form.
    /// </summary>
    [TestMethod]
    public void AnOtherDigitalIdentityEntryNeverMatches()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("other-entry.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList list = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.OtherEntry()]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [list],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.IsEmpty(result, "clause 5.5.3 Other: a non-certificate digital identity form never matches a chain certificate, so no list identifier is produced.");
    }


    /// <summary>
    /// Proves a prior service state matches: a held list whose current service digital identity does not
    /// recognise the chain but whose <see cref="TrustService.History"/> entry carries the leaf's issuer
    /// certificate matches, per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">ETSI
    /// TS 119 612, clause 5.6</see>'s historical service states, satisfying
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s "at least one X.509 Certificate that matches
    /// one of the entries of the Trusted List".
    /// </summary>
    [TestMethod]
    public void AnEntryInAServiceHistoryMatches()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("history-entry.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList list = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.OtherEntry()],
            historyEntries: [TrustedListFixtures.CertificateEntry(ring.Intermediate.Certificate, BaseMemoryPool.Shared)]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [list],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.Contains(new TrustedListIdentifier(MemberStateListIdentifier), result, "clause 5.6: a chain certificate matching a service history entry's digital identity must place the list's identifier in the membership set.");
    }


    /// <summary>
    /// Proves the cascading limb of
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see> — "the entries of the Trusted List or its
    /// cascading Trusted Lists" — over an ETSI TS 119 612 clause 5.3.13 pointer: the List Of the Trusted Lists
    /// identifier from the section's own example (<c>https://lotl.example.com</c>) is in the membership set when
    /// the LOTL points at the member-state list that holds the matching entry.
    /// </summary>
    [TestMethod]
    public void TheListOfTheListsIdentifierIsInTheResultWhenItPointsAtTheMemberStateListHoldingTheEntry()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("lotl-cascade.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList memberList = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.CertificateEntry(ring.Intermediate.Certificate, BaseMemoryPool.Shared)]);
        using TrustedList listOfTheLists = TrustedListFixtures.BuildListOfTheLists(
            [TrustedListFixtures.ListOfTheListsIdentifier],
            [MemberStateListIdentifier]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [memberList, listOfTheLists],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.Contains(new TrustedListIdentifier(TrustedListFixtures.ListOfTheListsIdentifier), result, "§6.1.1.2 cascading: a List Of the Trusted Lists pointing at the member-state list holding the entry must have its own identifier in the membership set.");
        Assert.Contains(new TrustedListIdentifier(MemberStateListIdentifier), result, "§6.1.1.2: the member-state list that directly holds the matching entry must also be in the membership set.");
    }


    /// <summary>
    /// Proves cascading follows more than one pointer hop: a List Of the Trusted Lists pointing at a regional
    /// list pointing at the member-state list that holds the matching entry places all three identifiers in the
    /// membership set, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s "cascading Trusted Lists" over ETSI TS 119 612
    /// clause 5.3.13 pointers.
    /// </summary>
    [TestMethod]
    public void ATwoLevelCascadeYieldsEveryListIdentifierOnThePathToTheHoldingList()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("two-level-cascade.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList memberList = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.CertificateEntry(ring.Intermediate.Certificate, BaseMemoryPool.Shared)]);
        using TrustedList regionalList = TrustedListFixtures.BuildListOfTheLists(
            [RegionalListIdentifier],
            [MemberStateListIdentifier]);
        using TrustedList listOfTheLists = TrustedListFixtures.BuildListOfTheLists(
            [TrustedListFixtures.ListOfTheListsIdentifier],
            [RegionalListIdentifier]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [memberList, regionalList, listOfTheLists],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.Contains(new TrustedListIdentifier(MemberStateListIdentifier), result, "§6.1.1.2: the holding member-state list is in the set.");
        Assert.Contains(new TrustedListIdentifier(RegionalListIdentifier), result, "§6.1.1.2 cascading: the regional list one hop above the holding list is in the set.");
        Assert.Contains(new TrustedListIdentifier(TrustedListFixtures.ListOfTheListsIdentifier), result, "§6.1.1.2 cascading: the List Of the Trusted Lists two hops above the holding list is in the set.");
    }


    /// <summary>
    /// Proves cascading over a pointer cycle terminates: two held lists pointing at each other, one holding the
    /// matching entry, place both identifiers in the membership set and the walk halts, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s "cascading Trusted Lists" — a
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">ETSI
    /// TS 119 612, clause 5.3.13</see> pointer graph a hostile document could make cyclic must not loop.
    /// </summary>
    [TestMethod]
    public void APointerCycleTerminatesWithBothListIdentifiersPresent()
    {
        const string firstListIdentifier = "https://tl-a.example.test/tsl";
        const string secondListIdentifier = "https://tl-b.example.test/tsl";

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("pointer-cycle.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList firstList = TrustedListFixtures.BuildTrustedList(
            [firstListIdentifier],
            [TrustedListFixtures.CertificateEntry(ring.Intermediate.Certificate, BaseMemoryPool.Shared)],
            pointerTargets: [secondListIdentifier]);
        using TrustedList secondList = TrustedListFixtures.BuildListOfTheLists(
            [secondListIdentifier],
            [firstListIdentifier]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [firstList, secondList],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.Contains(new TrustedListIdentifier(firstListIdentifier), result, "§6.1.1.2: the list directly holding the entry is in the set.");
        Assert.Contains(new TrustedListIdentifier(secondListIdentifier), result, "§6.1.1.2 cascading: the list pointing at the holding list across a cycle is in the set, and the walk terminates.");
    }


    /// <summary>
    /// Proves cascading follows held lists only: a held list holding the matching entry that also points at a
    /// list the wallet does not hold contributes only its own identifier — the unheld pointer target adds
    /// nothing — per the held-list-only reading of
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s "cascading Trusted Lists" over
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">ETSI
    /// TS 119 612, clause 5.3.13</see> pointers.
    /// </summary>
    [TestMethod]
    public void APointerToAListTheWalletDoesNotHoldContributesNothing()
    {
        const string unheldListIdentifier = "https://tl-unheld.example.test";

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("unheld-pointer.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList memberList = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.CertificateEntry(ring.Intermediate.Certificate, BaseMemoryPool.Shared)],
            pointerTargets: [unheldListIdentifier]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [memberList],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.Contains(new TrustedListIdentifier(MemberStateListIdentifier), result, "§6.1.1.2: the held list holding the entry is in the set.");
        Assert.DoesNotContain(new TrustedListIdentifier(unheldListIdentifier), result, "clause 5.3.13: a pointer whose target the wallet does not hold contributes no identifier.");
        Assert.HasCount(1, result, "§6.1.1.2: only the held list's own identifier is produced.");
    }


    /// <summary>
    /// Proves a held list whose entries match no chain certificate is absent from the membership set: a second
    /// held list recognising an unrelated certificate is not produced alongside the one that matches, so
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s membership is exactly the lists a chain
    /// certificate matches.
    /// </summary>
    [TestMethod]
    public void AListWhoseEntriesMatchNoChainCertificateIsAbsent()
    {
        const string unmatchedListIdentifier = "https://tl-unmatched.example.test";

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("matched.example.test", timeProvider);
        using X509ChainTestRingChain strangerRing = X509ChainTestRing.BuildThreeLevelChain("stranger.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList matchingList = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.CertificateEntry(ring.Intermediate.Certificate, BaseMemoryPool.Shared)]);
        using TrustedList unmatchedList = TrustedListFixtures.BuildTrustedList(
            [unmatchedListIdentifier],
            [TrustedListFixtures.CertificateEntry(strangerRing.Intermediate.Certificate, BaseMemoryPool.Shared)]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [matchingList, unmatchedList],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.Contains(new TrustedListIdentifier(MemberStateListIdentifier), result, "§6.1.1.2: the list whose entry matches a chain certificate is in the set.");
        Assert.DoesNotContain(new TrustedListIdentifier(unmatchedListIdentifier), result, "§6.1.1.2: a held list whose entries match no chain certificate is absent from the set.");
    }


    /// <summary>
    /// Proves the empty held-list set yields the empty membership set: with no lists to consider there is no
    /// list whose entries a chain certificate could match, so
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s condition holds for nothing.
    /// </summary>
    [TestMethod]
    public void AnEmptyHeldListSetYieldsTheEmptySet()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("empty-lists.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.IsEmpty(result, "§6.1.1.2: an empty held-list set produces no membership.");
    }


    /// <summary>
    /// Proves a chain of zero certificates yields the empty membership set: with no chain certificate to test,
    /// no held list's entry can be matched, so
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>'s "at least one X.509 Certificate that matches"
    /// is unsatisfiable.
    /// </summary>
    [TestMethod]
    public void AChainOfZeroCertificatesYieldsTheEmptySet()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("zero-cert-chain.example.test", timeProvider);

        using TrustedList list = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.CertificateEntry(ring.Intermediate.Certificate, BaseMemoryPool.Shared)]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            [],
            [list],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.IsEmpty(result, "§6.1.1.2: a zero-certificate chain matches no entry, so no membership is produced.");
    }


    /// <summary>
    /// Proves the walk is self-contained and dereferences no pointer URL: a held list holding the matching
    /// entry that also points at an unfamiliar third-party location produces only its own identifier, treating
    /// the unfamiliar URL "purely as an identifier and not actually retrieved", per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">OpenID for
    /// Verifiable Presentations 1.0, Section 15.10</see> — "Wallets SHOULD NOT access URLs included in a request
    /// from the Verifier if those URLs are unfamiliar or hosted by untrusted third parties." The evaluation
    /// exposes no fetch seam: its only delegates read certificates the caller already holds in memory.
    /// </summary>
    [TestMethod]
    public void TheWalkDereferencesNoPointerUrlAndReadsOnlyHeldLists()
    {
        const string unfamiliarThirdPartyLocation = "https://unfamiliar-third-party.example/trusted-list";

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("no-fetch.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate];

        using TrustedList memberList = TrustedListFixtures.BuildTrustedList(
            [MemberStateListIdentifier],
            [TrustedListFixtures.CertificateEntry(ring.Intermediate.Certificate, BaseMemoryPool.Shared)],
            pointerTargets: [unfamiliarThirdPartyLocation]);

        IReadOnlySet<TrustedListIdentifier> result = TrustedListMembership.Evaluate(
            chain,
            [memberList],
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName);

        Assert.Contains(new TrustedListIdentifier(MemberStateListIdentifier), result, "§6.1.1.2: the held list holding the entry is in the set.");
        Assert.DoesNotContain(new TrustedListIdentifier(unfamiliarThirdPartyLocation), result, "§15.10: the unfamiliar third-party pointer URL is treated purely as an identifier and never retrieved, so it contributes no membership.");
        Assert.HasCount(1, result, "§15.10: evaluation is self-contained over held lists, producing only the held list's own identifier.");
    }


    /// <summary>
    /// Selects the pair of certificate readers implemented by the named X.509 backend, so the
    /// <c>X509SKI</c> and <c>X509SubjectName</c> membership tests run against both
    /// <see cref="MicrosoftX509Functions"/> and <see cref="BouncyCastleX509Functions"/>.
    /// </summary>
    /// <param name="backend">The backend name from the test's <c>DataRow</c>.</param>
    /// <returns>The backend's SubjectKeyIdentifier and Subject readers.</returns>
    private static (ReadCertificateSubjectKeyIdentifierDelegate ReadSubjectKeyIdentifier, ReadCertificateSubjectNameDelegate ReadSubjectName) BackendReaders(string backend) => backend switch
    {
        MicrosoftBackend => (MicrosoftX509Functions.GetSubjectKeyIdentifier, MicrosoftX509Functions.GetSubjectName),
        BouncyCastleBackend => (BouncyCastleX509Functions.GetSubjectKeyIdentifier, BouncyCastleX509Functions.GetSubjectName),
        _ => throw new ArgumentOutOfRangeException(nameof(backend), backend, "Unknown X.509 backend name.")
    };
}
