using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the Annex D (normative) alternative-mechanism disclosure convention —
/// <see cref="JAdESAlternativeMechanismDisclosure"/> (the three-shall-item, four-member model) and
/// <see cref="JAdESAlternativeMechanismDisclosureRegistry"/> (the registration convention wiring a disclosure
/// to the <c>etsiU</c> catch-all extension point), plus its opt-in consumer in
/// <see cref="JAdESLevelRules.Check"/>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, Annex D, mirroring <c>CBAdESAlternativeMechanismDisclosureTests</c>'s
/// own shape one document removed.
/// </summary>
/// <remarks>
/// <strong>No new wire codec.</strong> The extension-point wiring test round-trips a
/// <see cref="JAdESUnsignedHeaderElementUnknown"/> element through the EXISTING
/// <see cref="JAdESEtsiUJson"/> codec, unmodified, and separately proves a disclosure registered
/// against that element's own kind is reachable — the registry adds no bytes to the wire.
/// </remarks>
[TestClass]
internal sealed class JAdESAlternativeMechanismDisclosureTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>JA-D-02 (items 1-3): constructing a disclosure with all four members present succeeds and every member is reachable exactly as supplied.</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithAllFourItemsSucceeds()
    {
        var disclosure = new JAdESAlternativeMechanismDisclosure(
            "urn:example:alt-ltaia-mechanism",
            "https://example.org/specs/alt-ltaia-mechanism",
            "Every protected object's digest is chained into a hash tree rooted in a token this mechanism itself issues.",
            "Instances of xVals/rVals/axVals/arVals/anyValData/tstVD/refs/sigRTst/rfsTst/arcTst incorporated per clause 5.3 are left untouched and validated independently.");

        Assert.AreEqual("urn:example:alt-ltaia-mechanism", disclosure.UniqueIdentifier);
        Assert.AreEqual("https://example.org/specs/alt-ltaia-mechanism", disclosure.SemanticsAndSyntaxReference);
        Assert.AreEqual("Every protected object's digest is chained into a hash tree rooted in a token this mechanism itself issues.", disclosure.ProtectionStrategy);
        Assert.AreEqual("Instances of xVals/rVals/axVals/arVals/anyValData/tstVD/refs/sigRTst/rfsTst/arcTst incorporated per clause 5.3 are left untouched and validated independently.", disclosure.CoexistenceStrategy);
    }


    /// <summary>A missing unique identifier fails closed rather than representing a partial disclosure.</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithNullUniqueIdentifierThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => _ = new JAdESAlternativeMechanismDisclosure(null!, "ref", "protection", "coexistence"));
    }


    /// <summary>A whitespace-only unique identifier is treated as absent, not as a stated blank value.</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithWhiteSpaceUniqueIdentifierThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => _ = new JAdESAlternativeMechanismDisclosure("   ", "ref", "protection", "coexistence"));
    }


    /// <summary>A missing specification reference fails closed.</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithNullSemanticsAndSyntaxReferenceThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => _ = new JAdESAlternativeMechanismDisclosure("id", null!, "protection", "coexistence"));
    }


    /// <summary>A missing protection-strategy statement fails closed (Annex D item 2).</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithNullProtectionStrategyThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => _ = new JAdESAlternativeMechanismDisclosure("id", "ref", null!, "coexistence"));
    }


    /// <summary>A missing coexistence-strategy statement fails closed (Annex D item 3).</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithNullCoexistenceStrategyThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => _ = new JAdESAlternativeMechanismDisclosure("id", "ref", "protection", null!));
    }


    /// <summary><see cref="JAdESAlternativeMechanismDisclosureRegistry.Register"/> rejects a null/empty kind.</summary>
    [TestMethod]
    public void RegisterThrowsOnNullOrEmptyKind()
    {
        var registry = new JAdESAlternativeMechanismDisclosureRegistry();
        JAdESAlternativeMechanismDisclosure disclosure = MakeDisclosure();

        Assert.ThrowsExactly<ArgumentNullException>(() => registry.Register(null!, disclosure));
        Assert.ThrowsExactly<ArgumentException>(() => registry.Register(string.Empty, disclosure));
    }


    /// <summary><see cref="JAdESAlternativeMechanismDisclosureRegistry.Register"/> rejects a <see langword="null"/> disclosure.</summary>
    [TestMethod]
    public void RegisterThrowsOnNullDisclosure()
    {
        var registry = new JAdESAlternativeMechanismDisclosureRegistry();

        Assert.ThrowsExactly<ArgumentNullException>(() => registry.Register("customMechanism", null!));
    }


    /// <summary>
    /// <see cref="JAdESAlternativeMechanismDisclosureRegistry.Register"/> refuses every one of this document's
    /// own sixteen named <c>etsiU</c> kinds — Annex D's registry exists only for the catch-all a mechanism THIS
    /// document does not itself define uses, never for a kind the document already assigns a fixed meaning to.
    /// </summary>
    /// <param name="profiledKind">One of the sixteen profiled kinds.</param>
    [TestMethod]
    [DataRow(JAdESUnsignedHeaderElement.SignaturePolicyStoreKind)]
    [DataRow(JAdESUnsignedHeaderElement.CounterSignatureKind)]
    [DataRow(JAdESUnsignedHeaderElement.SignatureTimestampKind)]
    [DataRow(JAdESUnsignedHeaderElement.CertificateValuesKind)]
    [DataRow(JAdESUnsignedHeaderElement.RevocationValuesKind)]
    [DataRow(JAdESUnsignedHeaderElement.AttributeCertificateValuesKind)]
    [DataRow(JAdESUnsignedHeaderElement.AttributeRevocationValuesKind)]
    [DataRow(JAdESUnsignedHeaderElement.AnyValidationDataKind)]
    [DataRow(JAdESUnsignedHeaderElement.TimestampValidationDataKind)]
    [DataRow(JAdESUnsignedHeaderElement.ArchiveTimestampKind)]
    [DataRow(JAdESUnsignedHeaderElement.CertificateReferencesKind)]
    [DataRow(JAdESUnsignedHeaderElement.RevocationReferencesKind)]
    [DataRow(JAdESUnsignedHeaderElement.AttributeCertificateReferencesKind)]
    [DataRow(JAdESUnsignedHeaderElement.AttributeRevocationReferencesKind)]
    [DataRow(JAdESUnsignedHeaderElement.SignatureAndReferencesTimestampKind)]
    [DataRow(JAdESUnsignedHeaderElement.ReferencesTimestampKind)]
    public void RegisterThrowsOnProfiledKind(string profiledKind)
    {
        var registry = new JAdESAlternativeMechanismDisclosureRegistry();
        JAdESAlternativeMechanismDisclosure disclosure = MakeDisclosure();

        Assert.ThrowsExactly<ArgumentException>(() => registry.Register(profiledKind, disclosure));
    }


    /// <summary>Registering a second disclosure under an already-registered kind throws rather than silently replacing the first.</summary>
    [TestMethod]
    public void RegisteringDuplicateKindThrows()
    {
        var registry = new JAdESAlternativeMechanismDisclosureRegistry();
        registry.Register("customMechanism", MakeDisclosure());

        Assert.ThrowsExactly<ArgumentException>(() => registry.Register("customMechanism", MakeDisclosure()));
    }


    /// <summary><see cref="JAdESAlternativeMechanismDisclosureRegistry.TryGetDisclosure"/> reports no match for a kind nothing was registered under.</summary>
    [TestMethod]
    public void TryGetDisclosureReturnsFalseWhenNoneRegistered()
    {
        var registry = new JAdESAlternativeMechanismDisclosureRegistry();

        bool found = registry.TryGetDisclosure("neverRegistered", out JAdESAlternativeMechanismDisclosure? disclosure);

        Assert.IsFalse(found);
        Assert.IsNull(disclosure);
    }


    /// <summary>
    /// The extension-point wiring: a <see cref="JAdESUnsignedHeaderElementUnknown"/> catch-all element
    /// (JA-5.3.1-13) carrying an alternative mechanism's own JSON value round-trips byte-exactly through the
    /// EXISTING <see cref="JAdESEtsiUJson"/> codec, unmodified by registering a disclosure against it — and
    /// that disclosure is reachable, by ordinal string comparison, from the kind the round-tripped (freshly
    /// parsed) element itself carries.
    /// </summary>
    [TestMethod]
    public void RegisteredDisclosureIsReachableAfterUnknownKindElementRoundTripsByteExactly()
    {
        const string kind = "customLtaiaMechanism";
        byte[] etsiUBytes = Encoding.UTF8.GetBytes($"[{{\"{kind}\":{{\"v\":42}}}}]");

        JAdESAlternativeMechanismDisclosure disclosure = MakeDisclosure();
        var registry = new JAdESAlternativeMechanismDisclosureRegistry();
        registry.Register(kind, disclosure);

        bool parsed = JAdESEtsiUJson.TryParse(etsiUBytes, Base64UrlDecoderStub, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? result);

        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            JAdESUnsignedHeaders unsignedHeaders = result!;
            Assert.HasCount(1, unsignedHeaders);
            Assert.IsTrue(unsignedHeaders[0] is JAdESUnsignedHeaderElementUnknown, "The catch-all arm must round-trip the unrecognized kind, not drop it.");

            var unknown = (JAdESUnsignedHeaderElementUnknown)unsignedHeaders[0];
            Assert.AreEqual(kind, unknown.Kind);

            bool reached = registry.TryGetDisclosure(unknown.Kind, out JAdESAlternativeMechanismDisclosure? reachedDisclosure);
            Assert.IsTrue(reached, "A disclosure registered under a kind must be reachable from an element parsed off the wire carrying the SAME kind.");
            Assert.AreSame(disclosure, reachedDisclosure);
        }
    }


    /// <summary>Opt-in consumer: a <see langword="null"/> registry performs no check at all — no violation for an undisclosed catch-all kind.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element construction is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' aggregate's own construction, which the local using disposes.")]
    [TestMethod]
    public void Check_UndisclosedCatchAllKind_WithNullRegistry_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [new JAdESUnsignedHeaderElementUnknown("customMechanism", PooledMemory.FromBytes("{\"customMechanism\":1}"u8, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders, AlternativeMechanismDisclosures = null };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasUndisclosedViolation(violations));
    }


    /// <summary>Opt-in consumer: a supplied registry with no matching disclosure reports <see cref="JAdESUndisclosedAlternativeMechanismViolation"/>.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element construction is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' aggregate's own construction, which the local using disposes.")]
    [TestMethod]
    public void Check_UndisclosedCatchAllKind_WithRegistry_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [new JAdESUnsignedHeaderElementUnknown("customMechanism", PooledMemory.FromBytes("{\"customMechanism\":1}"u8, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        var registry = new JAdESAlternativeMechanismDisclosureRegistry();
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders, AlternativeMechanismDisclosures = registry };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsTrue(HasUndisclosedViolation(violations));
        var violation = (JAdESUndisclosedAlternativeMechanismViolation)Find(violations);
        Assert.AreEqual("customMechanism", violation.Kind);
    }


    /// <summary>Opt-in consumer: a matching registered disclosure suppresses the violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element construction is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' aggregate's own construction, which the local using disposes.")]
    [TestMethod]
    public void Check_DisclosedCatchAllKind_WithRegistry_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [new JAdESUnsignedHeaderElementUnknown("customMechanism", PooledMemory.FromBytes("{\"customMechanism\":1}"u8, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        var registry = new JAdESAlternativeMechanismDisclosureRegistry();
        registry.Register("customMechanism", MakeDisclosure());
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders, AlternativeMechanismDisclosures = registry };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasUndisclosedViolation(violations));
    }


    /// <summary>Builds a fully-populated disclosure fixture for the registry tests, which do not exercise the four items' own content.</summary>
    private static JAdESAlternativeMechanismDisclosure MakeDisclosure() => new("id", "ref", "protection", "coexistence");


    private static bool HasUndisclosedViolation(IReadOnlyList<JAdESRuleViolation> violations)
    {
        for(int i = 0; i < violations.Count; ++i)
        {
            if(violations[i] is JAdESUndisclosedAlternativeMechanismViolation)
            {
                return true;
            }
        }

        return false;
    }


    private static JAdESRuleViolation Find(IReadOnlyList<JAdESRuleViolation> violations)
    {
        for(int i = 0; i < violations.Count; ++i)
        {
            if(violations[i] is JAdESUndisclosedAlternativeMechanismViolation)
            {
                return violations[i];
            }
        }

        throw new InvalidOperationException("No undisclosed-alternative-mechanism violation found.");
    }


    /// <summary>A base64url decoder stub — never invoked, since the fixture is entirely clear-JSON.</summary>
    private static IMemoryOwner<byte> Base64UrlDecoderStub(ReadOnlySpan<char> source, BaseMemoryPool pool) =>
        throw new InvalidOperationException("This fixture is clear-JSON only; the base64url decoder should never be invoked.");
}
