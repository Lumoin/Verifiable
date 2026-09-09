using System;
using System.Collections.Generic;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.X509;

/// <summary>
/// Proves <see cref="AuthorityKeyIdentifier"/> and the X.509 <c>aki</c> evidence arm realise the OID4VP 1.0
/// §6.1.1.1 rule that "The raw byte representation of this element MUST match with the AuthorityKeyIdentifier
/// element of an X.509 certificate in the certificate chain present in the Credential", per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
/// Presentations 1.0, Section 6.1.1.1</see>. The value type compares raw bytes rather than base64url spellings;
/// the backend delegates read an X.509 certificate's AuthorityKeyIdentifier (RFC 5280 §4.2.1.1) and its raw
/// byte content equals the issuer certificate's SubjectKeyIdentifier (RFC 5280 §4.2.1.2). Certificate fixtures
/// are minted by <see cref="X509ChainTestRing"/>; expected SubjectKeyIdentifier bytes and Subject strings are
/// read through the backends' own SubjectKeyIdentifier and Subject readers, never back through the
/// AuthorityKeyIdentifier extractor the tests exercise.
/// </summary>
[TestClass]
internal sealed class AuthorityKeyIdentifierTests
{
    /// <summary>The Section 6.1.1.1 non-normative example <c>aki</c> value, in canonical unpadded base64url.</summary>
    private const string ExampleAkiBase64Url = "s9tIpPmhxdiuNkHMEWNpYim8S8Y";

    /// <summary>The Section 6.1.1.1 example value re-spelled with base64url padding — the same raw bytes.</summary>
    private const string ExampleAkiBase64UrlPadded = "s9tIpPmhxdiuNkHMEWNpYim8S8Y=";

    /// <summary>The Microsoft-backend name selecting <see cref="MicrosoftX509Functions"/>'s certificate readers.</summary>
    private const string MicrosoftBackend = "Microsoft";

    /// <summary>The BouncyCastle-backend name selecting <see cref="BouncyCastleX509Functions"/>'s certificate readers.</summary>
    private const string BouncyCastleBackend = "BouncyCastle";


    /// <summary>
    /// Proves <see cref="AuthorityKeyIdentifier.TryParse(string, out AuthorityKeyIdentifier)"/> accepts the
    /// Section 6.1.1.1 example value, whose transport form is "encoded as base64url", per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.1</see>.
    /// </summary>
    [TestMethod]
    public void TryParseAcceptsTheSectionExampleAkiValue()
    {
        bool parsed = AuthorityKeyIdentifier.TryParse(ExampleAkiBase64Url, out AuthorityKeyIdentifier identifier);

        Assert.IsTrue(parsed, "§6.1.1.1: the base64url-encoded example aki value must parse into a KeyIdentifier.");
        Assert.AreEqual(ExampleAkiBase64Url, identifier.ToBase64Url(), "§6.1.1.1: the parsed raw byte KeyIdentifier re-encodes to the canonical example value.");
    }


    /// <summary>
    /// Proves the padded and unpadded base64url spellings of the Section 6.1.1.1 example decode to equal
    /// identifiers and equal hash codes — "The raw byte representation of this element MUST match", per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.1</see>: a base64url string is a transport form, and two spellings of
    /// the same bytes identify the same authority.
    /// </summary>
    [TestMethod]
    public void PaddedAndUnpaddedFormsOfTheSameValueParseEqual()
    {
        bool unpaddedParsed = AuthorityKeyIdentifier.TryParse(ExampleAkiBase64Url, out AuthorityKeyIdentifier unpadded);
        bool paddedParsed = AuthorityKeyIdentifier.TryParse(ExampleAkiBase64UrlPadded, out AuthorityKeyIdentifier padded);

        Assert.IsTrue(unpaddedParsed, "§6.1.1.1: the canonical unpadded base64url form must parse.");
        Assert.IsTrue(paddedParsed, "§6.1.1.1: a padded base64url spelling of the same bytes must parse.");
        Assert.AreEqual(unpadded, padded, "§6.1.1.1: padded and unpadded spellings of one raw byte representation are equal.");
        Assert.AreEqual(unpadded.GetHashCode(), padded.GetHashCode(), "§6.1.1.1: equal raw byte representations agree on GetHashCode.");
    }


    /// <summary>
    /// Proves <see cref="AuthorityKeyIdentifier.TryParse(string, out AuthorityKeyIdentifier)"/> refuses input
    /// that is not base64url — a non-alphabet character, an invalid length, or the standard-base64 <c>+</c>/<c>/</c>
    /// characters — returning <see langword="false"/> and <see langword="default"/> without throwing, since the
    /// value carried by a Section 6.1.1.1 <c>aki</c> entry is "encoded as base64url", per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.1</see>. Wire input never faults evaluation.
    /// </summary>
    /// <param name="value">The malformed candidate value.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("not base64url!")]
    [DataRow("AAAAA")]
    [DataRow("s9+/")]
    public void TryParseRefusesNonBase64UrlValues(string? value)
    {
        bool parsed = AuthorityKeyIdentifier.TryParse(value, out AuthorityKeyIdentifier identifier);

        Assert.IsFalse(parsed, "§6.1.1.1: a value that is not base64url cannot be the raw byte representation and must be refused.");
        Assert.AreEqual(default, identifier, "§6.1.1.1: a refused parse yields the default identifier, never a partial one.");
    }


    /// <summary>
    /// Proves equality and hashing compare the raw <c>KeyIdentifier</c> bytes, not any string form: identifiers
    /// built from equal byte sequences are equal with agreeing hash codes, and one built from different bytes is
    /// unequal — the "raw byte representation" comparison of
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.1</see>.
    /// </summary>
    [TestMethod]
    public void EqualityIsByteEqualityAndGetHashCodeAgrees()
    {
        var left = new AuthorityKeyIdentifier(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        var sameBytes = new AuthorityKeyIdentifier(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        var otherBytes = new AuthorityKeyIdentifier(new byte[] { 0x09, 0x09 });

        Assert.AreEqual(left, sameBytes, "§6.1.1.1: identifiers over equal raw bytes are equal.");
        Assert.AreEqual(left.GetHashCode(), sameBytes.GetHashCode(), "§6.1.1.1: equal raw bytes agree on GetHashCode.");
        Assert.AreNotEqual(left, otherBytes, "§6.1.1.1: identifiers over different raw bytes are unequal.");
    }


    /// <summary>
    /// Proves <see cref="AuthorityKeyIdentifier.ToBase64Url"/> renders the canonical unpadded base64url form and
    /// round-trips: parsing the padded example, re-encoding it drops the padding to the canonical Section 6.1.1.1
    /// spelling, and re-parsing that yields an equal identifier, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.1</see>.
    /// </summary>
    [TestMethod]
    public void ToBase64UrlIsCanonicalUnpaddedAndRoundTrips()
    {
        _ = AuthorityKeyIdentifier.TryParse(ExampleAkiBase64UrlPadded, out AuthorityKeyIdentifier fromPadded);

        string canonical = fromPadded.ToBase64Url();

        Assert.AreEqual(ExampleAkiBase64Url, canonical, "§6.1.1.1: ToBase64Url renders the canonical unpadded base64url spelling.");

        bool reparsed = AuthorityKeyIdentifier.TryParse(canonical, out AuthorityKeyIdentifier roundTripped);

        Assert.IsTrue(reparsed, "§6.1.1.1: the canonical form re-parses.");
        Assert.AreEqual(fromPadded, roundTripped, "§6.1.1.1: encoding then parsing preserves the raw byte representation.");
    }


    /// <summary>
    /// Proves <see cref="AuthorityKeyIdentifier.ToString"/> returns the same canonical base64url text as
    /// <see cref="AuthorityKeyIdentifier.ToBase64Url"/> — the transport form of the Section 6.1.1.1 value, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.1</see>.
    /// </summary>
    [TestMethod]
    public void ToStringEqualsToBase64Url()
    {
        _ = AuthorityKeyIdentifier.TryParse(ExampleAkiBase64Url, out AuthorityKeyIdentifier identifier);

        Assert.AreEqual(identifier.ToBase64Url(), identifier.ToString(), "§6.1.1.1: ToString renders the canonical base64url transport form.");
    }


    /// <summary>
    /// Proves the backend <see cref="ExtractAuthorityKeyIdentifierDelegate"/> reads a certificate's
    /// AuthorityKeyIdentifier <c>keyIdentifier</c> (<see href="https://www.rfc-editor.org/rfc/rfc5280">RFC 5280,
    /// Section 4.2.1.1</see>) as raw bytes equal to the issuer certificate's SubjectKeyIdentifier
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280">RFC 5280, Section 4.2.1.2</see>): over a chain minted
    /// by <see cref="X509ChainTestRing"/> the leaf's AuthorityKeyIdentifier equals the intermediate's
    /// SubjectKeyIdentifier and the intermediate's equals the root's — the byte identity OID4VP 1.0 §6.1.1.1
    /// matches against. The expected bytes are read through the same backend's SubjectKeyIdentifier reader, an
    /// independent oracle to the AuthorityKeyIdentifier extractor under test.
    /// </summary>
    /// <param name="backend">The X.509 backend whose readers the test exercises.</param>
    [TestMethod]
    [DataRow(MicrosoftBackend)]
    [DataRow(BouncyCastleBackend)]
    public void ExtractedAuthorityKeyIdentifierEqualsTheIssuersSubjectKeyIdentifier(string backend)
    {
        (ExtractAuthorityKeyIdentifierDelegate extractAuthorityKeyIdentifier, ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier, _) = Backend(backend);

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("aki-issuer-ski.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory root = TrustedListFixtures.ToCertificateCarrier(ring.Root.Certificate, BaseMemoryPool.Shared);

        AuthorityKeyIdentifier? leafAuthorityKeyIdentifier = extractAuthorityKeyIdentifier(leaf);
        AuthorityKeyIdentifier? intermediateAuthorityKeyIdentifier = extractAuthorityKeyIdentifier(intermediate);

        Assert.IsNotNull(leafAuthorityKeyIdentifier, "RFC 5280 §4.2.1.1: the leaf carries an AuthorityKeyIdentifier chaining to its issuer.");
        Assert.IsNotNull(intermediateAuthorityKeyIdentifier, "RFC 5280 §4.2.1.1: the intermediate carries an AuthorityKeyIdentifier chaining to its issuer.");
        Assert.AreEqual(new AuthorityKeyIdentifier(readSubjectKeyIdentifier(intermediate)), leafAuthorityKeyIdentifier.Value, "RFC 5280 §4.2.1.1/4.2.1.2: the leaf's AuthorityKeyIdentifier equals its issuer's (the intermediate's) SubjectKeyIdentifier.");
        Assert.AreEqual(new AuthorityKeyIdentifier(readSubjectKeyIdentifier(root)), intermediateAuthorityKeyIdentifier.Value, "RFC 5280 §4.2.1.1/4.2.1.2: the intermediate's AuthorityKeyIdentifier equals its issuer's (the root's) SubjectKeyIdentifier.");
    }


    /// <summary>
    /// Proves the backend <see cref="ExtractAuthorityKeyIdentifierDelegate"/> returns <see langword="null"/> for
    /// a self-signed root that <see cref="X509ChainTestRing"/> mints without an AuthorityKeyIdentifier extension,
    /// and that <see cref="X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers(IReadOnlyList{PkiCertificateMemory}, ExtractAuthorityKeyIdentifierDelegate)"/>
    /// over that single-certificate chain contributes nothing — "the chain can consist of a single certificate",
    /// per <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.1</see>: a certificate lacking the extension yields no matchable
    /// identifier.
    /// </summary>
    /// <param name="backend">The X.509 backend whose reader the test exercises.</param>
    [TestMethod]
    [DataRow(MicrosoftBackend)]
    [DataRow(BouncyCastleBackend)]
    public void SelfSignedRootCarriesNoAuthorityKeyIdentifier(string backend)
    {
        (ExtractAuthorityKeyIdentifierDelegate extractAuthorityKeyIdentifier, _, _) = Backend(backend);

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("self-signed-root.example.test", timeProvider);
        using PkiCertificateMemory root = TrustedListFixtures.ToCertificateCarrier(ring.Root.Certificate, BaseMemoryPool.Shared);

        AuthorityKeyIdentifier? rootAuthorityKeyIdentifier = extractAuthorityKeyIdentifier(root);

        Assert.IsNull(rootAuthorityKeyIdentifier, "RFC 5280 §4.2.1.1: a self-signed root minted without an AuthorityKeyIdentifier extension reads as null.");

        IReadOnlySet<AuthorityKeyIdentifier> identifiers = X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers([root], extractAuthorityKeyIdentifier);

        Assert.IsEmpty(identifiers, "§6.1.1.1: a single-certificate chain whose only certificate carries no AuthorityKeyIdentifier contributes no matchable value.");
    }


    /// <summary>
    /// Proves <see cref="X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers(IReadOnlyList{PkiCertificateMemory}, ExtractAuthorityKeyIdentifierDelegate)"/>
    /// over a full leaf → intermediate → root chain yields the two distinct AuthorityKeyIdentifiers the leaf and
    /// intermediate carry — "the AuthorityKeyIdentifier element of an X.509 certificate in the certificate
    /// chain", per <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.1.1.1</see>: every chain certificate counts, not only the leaf.
    /// </summary>
    /// <param name="backend">The X.509 backend whose reader the test exercises.</param>
    [TestMethod]
    [DataRow(MicrosoftBackend)]
    [DataRow(BouncyCastleBackend)]
    public void CollectAuthorityKeyIdentifiersOverAThreeLevelChainYieldsLeafAndIntermediate(string backend)
    {
        (ExtractAuthorityKeyIdentifierDelegate extractAuthorityKeyIdentifier, ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier, _) = Backend(backend);

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("collect-three-level.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory root = TrustedListFixtures.ToCertificateCarrier(ring.Root.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leaf, intermediate, root];

        IReadOnlySet<AuthorityKeyIdentifier> identifiers = X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers(chain, extractAuthorityKeyIdentifier);

        var expectedLeafIdentifier = new AuthorityKeyIdentifier(readSubjectKeyIdentifier(intermediate));
        var expectedIntermediateIdentifier = new AuthorityKeyIdentifier(readSubjectKeyIdentifier(root));

        Assert.HasCount(2, identifiers, "§6.1.1.1: the leaf and intermediate each contribute one distinct AuthorityKeyIdentifier; the root carries none.");
        Assert.Contains(expectedLeafIdentifier, identifiers, "§6.1.1.1: the leaf's AuthorityKeyIdentifier (its issuer's SubjectKeyIdentifier) is collected.");
        Assert.Contains(expectedIntermediateIdentifier, identifiers, "§6.1.1.1: the intermediate's AuthorityKeyIdentifier (its issuer's SubjectKeyIdentifier) is collected.");
    }


    /// <summary>
    /// Proves <see cref="X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers(IReadOnlyList{PkiCertificateMemory}, ExtractAuthorityKeyIdentifierDelegate)"/>
    /// over a leaf-only partial chain yields the leaf's single AuthorityKeyIdentifier — "the Credential can
    /// include the entire X.509 chain or parts of it", per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.1</see>.
    /// </summary>
    /// <param name="backend">The X.509 backend whose reader the test exercises.</param>
    [TestMethod]
    [DataRow(MicrosoftBackend)]
    [DataRow(BouncyCastleBackend)]
    public void CollectAuthorityKeyIdentifiersOverALeafOnlyPartialChainYieldsTheLeafsIdentifier(string backend)
    {
        (ExtractAuthorityKeyIdentifierDelegate extractAuthorityKeyIdentifier, ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier, _) = Backend(backend);

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("collect-leaf-only.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);

        IReadOnlySet<AuthorityKeyIdentifier> identifiers = X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers([leaf], extractAuthorityKeyIdentifier);

        Assert.HasCount(1, identifiers, "§6.1.1.1: a leaf-only partial chain contributes exactly the leaf's AuthorityKeyIdentifier.");
        Assert.Contains(new AuthorityKeyIdentifier(readSubjectKeyIdentifier(intermediate)), identifiers, "§6.1.1.1: the collected value is the leaf's AuthorityKeyIdentifier, equal to its issuer's SubjectKeyIdentifier.");
    }


    /// <summary>
    /// Proves the backend <see cref="ReadCertificateSubjectNameDelegate"/> renders a certificate Subject as the
    /// <see href="https://www.rfc-editor.org/rfc/rfc4514">RFC 4514</see> distinguished name string matching what
    /// <see cref="X509ChainTestRing"/> minted — descriptors most-specific first, comma-joined without spaces — so
    /// both backends produce the identical string an ETSI TS 119 612 <c>X509SubjectName</c> entry is compared
    /// against for OID4VP 1.0 §6.1.1.2 matching. The expected string is authored from the ring's known Subject,
    /// never read back through the reader under test.
    /// </summary>
    /// <param name="backend">The X.509 backend whose Subject reader the test exercises.</param>
    [TestMethod]
    [DataRow(MicrosoftBackend)]
    [DataRow(BouncyCastleBackend)]
    public void ReadCertificateSubjectNameReturnsTheRfc4514SubjectString(string backend)
    {
        (_, _, ReadCertificateSubjectNameDelegate readSubjectName) = Backend(backend);

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("subject-name.example.test", timeProvider);
        using PkiCertificateMemory leaf = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);

        string subjectName = readSubjectName(leaf);

        Assert.AreEqual("CN=subject-name.example.test,O=Verifiable Test Infrastructure", subjectName, "RFC 4514: the leaf's Subject renders as its known distinguished name, most-specific descriptor first, comma-joined without spaces.");
    }


    /// <summary>
    /// Selects the trio of certificate readers implemented by the named X.509 backend, so the delegate-facing
    /// tests run against both <see cref="MicrosoftX509Functions"/> and <see cref="BouncyCastleX509Functions"/>.
    /// </summary>
    /// <param name="backend">The backend name from the test's <c>DataRow</c>.</param>
    /// <returns>The backend's AuthorityKeyIdentifier extractor, SubjectKeyIdentifier reader and Subject reader.</returns>
    private static (ExtractAuthorityKeyIdentifierDelegate ExtractAuthorityKeyIdentifier, ReadCertificateSubjectKeyIdentifierDelegate ReadSubjectKeyIdentifier, ReadCertificateSubjectNameDelegate ReadSubjectName) Backend(string backend) => backend switch
    {
        MicrosoftBackend => (MicrosoftX509Functions.GetAuthorityKeyIdentifier, MicrosoftX509Functions.GetSubjectKeyIdentifier, MicrosoftX509Functions.GetSubjectName),
        BouncyCastleBackend => (BouncyCastleX509Functions.GetAuthorityKeyIdentifier, BouncyCastleX509Functions.GetSubjectKeyIdentifier, BouncyCastleX509Functions.GetSubjectName),
        _ => throw new ArgumentOutOfRangeException(nameof(backend), backend, "Unknown X.509 backend name.")
    };
}
