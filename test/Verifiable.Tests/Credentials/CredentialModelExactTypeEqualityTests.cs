using System;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Credentials;

/// <summary>
/// Tests that the VC Data Model 2.0 credential model types' equality is exact-type: a subtype
/// adding further identity-bearing members is never equal to a same-valued base instance,
/// through either the typed <see cref="IEquatable{T}.Equals(T)"/> overload or the
/// <see cref="object.Equals(object)"/> override, in either comparison direction.
/// </summary>
[TestClass]
internal sealed class CredentialModelExactTypeEqualityTests
{
    /// <summary>A <see cref="VerifiableCredential"/> subtype with no additional identity members.</summary>
    private sealed class DerivedVerifiableCredential: VerifiableCredential
    {
    }

    /// <summary>A <see cref="VerifiablePresentation"/> subtype with no additional identity members.</summary>
    private sealed class DerivedVerifiablePresentation: VerifiablePresentation
    {
    }

    /// <summary>A <see cref="CredentialSchema"/> subtype with no additional identity members.</summary>
    private sealed class DerivedCredentialSchema: CredentialSchema
    {
    }

    /// <summary>A <see cref="CredentialStatus"/> subtype with no additional identity members.</summary>
    private sealed class DerivedCredentialStatus: CredentialStatus
    {
    }

    /// <summary>A <see cref="CredentialSubject"/> subtype with no additional identity members.</summary>
    private sealed class DerivedCredentialSubject: CredentialSubject
    {
    }

    /// <summary>An <see cref="Evidence"/> subtype with no additional identity members.</summary>
    private sealed class DerivedEvidence: Evidence
    {
    }

    /// <summary>An <see cref="Issuer"/> subtype with no additional identity members.</summary>
    private sealed class DerivedIssuer: Issuer
    {
    }

    /// <summary>A <see cref="RefreshService"/> subtype with no additional identity members.</summary>
    private sealed class DerivedRefreshService: RefreshService
    {
    }

    /// <summary>A <see cref="RelatedResource"/> subtype with no additional identity members.</summary>
    private sealed class DerivedRelatedResource: RelatedResource
    {
    }

    /// <summary>A <see cref="TermsOfUse"/> subtype with no additional identity members.</summary>
    private sealed class DerivedTermsOfUse: TermsOfUse
    {
    }

    /// <summary>
    /// A <see cref="DidDocumentMetadata"/> subtype with no additional identity members. This type is not a
    /// VC Data Model 2.0 credential model type — it sits in this file because it shares the same exact-type
    /// equality shape as the other thirteen types tested here and no DID-scoped equatable test class exists
    /// to host it instead.
    /// </summary>
    private sealed class DerivedDidDocumentMetadata: DidDocumentMetadata
    {
    }


    /// <summary>
    /// Asserts that <paramref name="instance"/> and <paramref name="subtypeInstance"/> compare
    /// unequal through both the typed <see cref="IEquatable{T}"/> overload and the
    /// <see cref="object.Equals(object)"/> override, checked in both comparison directions.
    /// </summary>
    /// <typeparam name="T">The base type whose equality is under test.</typeparam>
    /// <param name="instance">A base-type instance.</param>
    /// <param name="subtypeInstance">A same-valued instance of a subtype, held as the base type.</param>
    private static void AssertExactTypeInequality<T>(T instance, T subtypeInstance) where T : class, IEquatable<T>
    {
        Assert.IsFalse(instance.Equals(subtypeInstance));
        Assert.IsFalse(subtypeInstance.Equals(instance));
        Assert.IsFalse(((object)instance).Equals(subtypeInstance));
        Assert.IsFalse(((object)subtypeInstance).Equals(instance));
    }


    /// <summary>
    /// Asserts that two same-valued, same-type instances compare equal through both the typed
    /// <see cref="IEquatable{T}"/> overload and the <see cref="object.Equals(object)"/> override,
    /// checked in both comparison directions.
    /// </summary>
    /// <typeparam name="T">The type whose equality is under test.</typeparam>
    /// <param name="first">An instance.</param>
    /// <param name="second">A same-valued instance of the same type.</param>
    private static void AssertEquality<T>(T first, T second) where T : class, IEquatable<T>
    {
        Assert.IsTrue(first.Equals(second));
        Assert.IsTrue(second.Equals(first));
        Assert.IsTrue(((object)first).Equals(second));
        Assert.IsTrue(((object)second).Equals(first));
    }


    /// <summary>
    /// Proves <see cref="VerifiableCredential.Equals(VerifiableCredential?)"/> and its
    /// <see cref="VerifiableCredential.Equals(object?)"/> override are exact-type: a same-valued subtype
    /// instance is unequal to a base instance through both overloads in both directions, while two base
    /// instances with the same values remain equal through both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedVerifiableCredentialIsNotEqualToBaseInstance()
    {
        var baseCredential = new VerifiableCredential { Id = "urn:vc:1", Issuer = Issuer.FromUri("urn:issuer:1"), ValidFrom = "2026-01-01T00:00:00Z" };
        VerifiableCredential derived = new DerivedVerifiableCredential { Id = baseCredential.Id, Issuer = baseCredential.Issuer, ValidFrom = baseCredential.ValidFrom };

        AssertExactTypeInequality(baseCredential, derived);

        var otherBase = new VerifiableCredential { Id = baseCredential.Id, Issuer = baseCredential.Issuer, ValidFrom = baseCredential.ValidFrom };
        AssertEquality(baseCredential, otherBase);
    }


    /// <summary>
    /// Proves the exact-type rule against a real in-repo subtype rather than only a test-local one:
    /// <see cref="DataIntegritySecuredCredential"/> carrying the same values as a base
    /// <see cref="VerifiableCredential"/> is unequal to it through both overloads in both directions.
    /// </summary>
    [TestMethod]
    public void DataIntegritySecuredCredentialIsNotEqualToBaseVerifiableCredential()
    {
        var baseCredential = new VerifiableCredential { Id = "urn:vc:2", Issuer = Issuer.FromUri("urn:issuer:2") };
        VerifiableCredential secured = new DataIntegritySecuredCredential { Id = baseCredential.Id, Issuer = baseCredential.Issuer };

        AssertExactTypeInequality(baseCredential, secured);
    }


    /// <summary>
    /// <see cref="DataIntegritySecuredCredential"/> folds <see cref="DataIntegritySecuredCredential.Proof"/>
    /// into equality on top of the inherited <see cref="VerifiableCredential"/> content: two secured
    /// credentials agreeing on every inherited member but carrying a different proof are unequal —
    /// a secured document's identity includes the proof that secures it — while two carrying
    /// equal-valued (not reference-shared) proof lists remain equal. Per
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>
    /// the <c>proof</c> member sits at the same object level as the secured document's own members,
    /// so it is part of what the document asserts.
    /// </summary>
    [TestMethod]
    public void DataIntegritySecuredCredentialEqualityIncludesProof()
    {
        var withProofA = new DataIntegritySecuredCredential
        {
            Id = "urn:vc:4",
            Issuer = Issuer.FromUri("urn:issuer:4"),
            Proof = [new DataIntegrityProof { ProofValue = "zProofA" }]
        };
        var withProofB = new DataIntegritySecuredCredential
        {
            Id = "urn:vc:4",
            Issuer = Issuer.FromUri("urn:issuer:4"),
            Proof = [new DataIntegrityProof { ProofValue = "zProofB" }]
        };
        Assert.IsFalse(withProofA.Equals(withProofB), "A different proof must break equality.");

        var otherWithProofA = new DataIntegritySecuredCredential
        {
            Id = "urn:vc:4",
            Issuer = Issuer.FromUri("urn:issuer:4"),
            Proof = [new DataIntegrityProof { ProofValue = "zProofA" }]
        };
        AssertEquality(withProofA, otherWithProofA);
    }


    /// <summary>
    /// <see cref="VerifiableCredential.Equals(VerifiableCredential?)"/> is
    /// <see langword="virtual"/>, so <see cref="DataIntegritySecuredCredential"/>'s proof fold
    /// proved by <see cref="DataIntegritySecuredCredentialEqualityIncludesProof"/> is reached
    /// even when both instances are held as the base <see cref="VerifiableCredential"/> static
    /// type: a differently-signed credential must compare unequal through
    /// <see cref="IEquatable{T}"/>, the <see cref="object.Equals(object)"/> override,
    /// <see cref="EqualityComparer{T}.Default"/>, and <c>operator ==</c> alike, and two
    /// equal-valued instances must still hash the same when compared this way.
    /// </summary>
    [TestMethod]
    public void DataIntegritySecuredCredentialEqualityIncludesProofThroughBaseStaticType()
    {
        VerifiableCredential withProofA = new DataIntegritySecuredCredential
        {
            Id = "urn:vc:5",
            Issuer = Issuer.FromUri("urn:issuer:5"),
            Proof = [new DataIntegrityProof { ProofValue = "zProofA" }]
        };
        VerifiableCredential withProofB = new DataIntegritySecuredCredential
        {
            Id = "urn:vc:5",
            Issuer = Issuer.FromUri("urn:issuer:5"),
            Proof = [new DataIntegrityProof { ProofValue = "zProofB" }]
        };

        Assert.IsFalse(withProofA.Equals(withProofB), "A different proof must break equality through the base static type.");
        Assert.IsFalse(((object)withProofA).Equals(withProofB));
        Assert.IsFalse(EqualityComparer<VerifiableCredential>.Default.Equals(withProofA, withProofB));
        Assert.IsFalse(withProofA == withProofB);
        Assert.IsTrue(withProofA != withProofB);

        VerifiableCredential otherWithProofA = new DataIntegritySecuredCredential
        {
            Id = "urn:vc:5",
            Issuer = Issuer.FromUri("urn:issuer:5"),
            Proof = [new DataIntegrityProof { ProofValue = "zProofA" }]
        };

        Assert.IsTrue(withProofA.Equals(otherWithProofA));
        Assert.IsTrue(((object)withProofA).Equals(otherWithProofA));
        Assert.IsTrue(EqualityComparer<VerifiableCredential>.Default.Equals(withProofA, otherWithProofA));
        Assert.IsTrue(withProofA == otherWithProofA);
        Assert.AreEqual(withProofA.GetHashCode(), otherWithProofA.GetHashCode());
    }


    /// <summary>
    /// <see cref="VerifiableCredential.Equals(VerifiableCredential?)"/> folds
    /// <see cref="VerifiableCredential.Context"/> into identity: two otherwise-identical credentials
    /// with different contexts are unequal, and two distinct <see cref="Context"/> instances
    /// carrying the same entries make the credentials compare equal.
    /// </summary>
    [TestMethod]
    public void VerifiableCredentialEqualityIncludesContext()
    {
        var withCredentials20 = new VerifiableCredential { Id = "urn:vc:3", Context = Context.FromIris(Context.Credentials20) };
        var withDidCore10 = new VerifiableCredential { Id = "urn:vc:3", Context = Context.FromIris(Context.DidCore10) };
        Assert.IsFalse(withCredentials20.Equals(withDidCore10), "A different context must break equality.");

        var otherWithCredentials20 = new VerifiableCredential { Id = "urn:vc:3", Context = Context.FromIris(Context.Credentials20) };
        AssertEquality(withCredentials20, otherWithCredentials20);
    }


    /// <summary>
    /// Proves <see cref="VerifiablePresentation.Equals(VerifiablePresentation?)"/> and its
    /// <see cref="VerifiablePresentation.Equals(object?)"/> override are exact-type, mirroring
    /// <see cref="VerifiableCredential"/>'s pattern: a same-valued subtype instance is unequal to a
    /// base instance through both overloads in both directions, while two base instances with the
    /// same full structural content — <see cref="VerifiablePresentation.Type"/>,
    /// <see cref="VerifiablePresentation.VerifiableCredential"/>,
    /// <see cref="VerifiablePresentation.TermsOfUse"/>, and
    /// <see cref="VerifiablePresentation.AdditionalData"/> included, each a distinct same-valued
    /// instance rather than a shared reference — remain equal through both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedVerifiablePresentationIsNotEqualToBaseInstance()
    {
        var basePresentation = new VerifiablePresentation
        {
            Id = "urn:vp:1",
            Holder = "did:example:holder",
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            VerifiableCredential = [new VerifiableCredential { Id = "urn:vc:shared" }],
            TermsOfUse = [new TermsOfUse { Type = "IssuerPolicy" }],
            AdditionalData = new Dictionary<string, object> { ["foo"] = "bar" }
        };
        VerifiablePresentation derived = new DerivedVerifiablePresentation
        {
            Id = basePresentation.Id,
            Holder = basePresentation.Holder,
            Context = basePresentation.Context,
            Type = basePresentation.Type,
            VerifiableCredential = basePresentation.VerifiableCredential,
            TermsOfUse = basePresentation.TermsOfUse,
            AdditionalData = basePresentation.AdditionalData
        };

        AssertExactTypeInequality(basePresentation, derived);

        var otherBase = new VerifiablePresentation
        {
            Id = basePresentation.Id,
            Holder = basePresentation.Holder,
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            VerifiableCredential = [new VerifiableCredential { Id = "urn:vc:shared" }],
            TermsOfUse = [new TermsOfUse { Type = "IssuerPolicy" }],
            AdditionalData = new Dictionary<string, object> { ["foo"] = "bar" }
        };
        AssertEquality(basePresentation, otherBase);
    }


    /// <summary>
    /// Proves the exact-type rule against a real in-repo subtype: <see cref="DataIntegritySecuredPresentation"/>
    /// carrying the same values as a base <see cref="VerifiablePresentation"/> is unequal to it through
    /// both overloads in both directions.
    /// </summary>
    [TestMethod]
    public void DataIntegritySecuredPresentationIsNotEqualToBaseVerifiablePresentation()
    {
        var basePresentation = new VerifiablePresentation { Id = "urn:vp:2", Holder = "did:example:holder" };
        VerifiablePresentation secured = new DataIntegritySecuredPresentation { Id = basePresentation.Id, Holder = basePresentation.Holder };

        AssertExactTypeInequality(basePresentation, secured);
    }


    /// <summary>
    /// <see cref="DataIntegritySecuredPresentation"/> folds <see cref="DataIntegritySecuredPresentation.Proof"/>
    /// into equality on top of the inherited <see cref="VerifiablePresentation"/> content: two secured
    /// presentations agreeing on every inherited member but carrying a different proof are unequal —
    /// a secured document's identity includes the proof that secures it — while two carrying
    /// equal-valued (not reference-shared) proof lists remain equal. Per
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>
    /// the <c>proof</c> member sits at the same object level as the secured document's own members,
    /// so it is part of what the document asserts.
    /// </summary>
    [TestMethod]
    public void DataIntegritySecuredPresentationEqualityIncludesProof()
    {
        var withProofA = new DataIntegritySecuredPresentation
        {
            Id = "urn:vp:4",
            Holder = "did:example:holder",
            Proof = [new DataIntegrityProof { ProofValue = "zProofA" }]
        };
        var withProofB = new DataIntegritySecuredPresentation
        {
            Id = "urn:vp:4",
            Holder = "did:example:holder",
            Proof = [new DataIntegrityProof { ProofValue = "zProofB" }]
        };
        Assert.IsFalse(withProofA.Equals(withProofB), "A different proof must break equality.");

        var otherWithProofA = new DataIntegritySecuredPresentation
        {
            Id = "urn:vp:4",
            Holder = "did:example:holder",
            Proof = [new DataIntegrityProof { ProofValue = "zProofA" }]
        };
        AssertEquality(withProofA, otherWithProofA);
    }


    /// <summary>
    /// <see cref="VerifiablePresentation.Equals(VerifiablePresentation?)"/> is
    /// <see langword="virtual"/>, so <see cref="DataIntegritySecuredPresentation"/>'s proof fold
    /// proved by <see cref="DataIntegritySecuredPresentationEqualityIncludesProof"/> is reached
    /// even when both instances are held as the base <see cref="VerifiablePresentation"/> static
    /// type: a differently-signed presentation must compare unequal through
    /// <see cref="IEquatable{T}"/>, the <see cref="object.Equals(object)"/> override,
    /// <see cref="EqualityComparer{T}.Default"/>, and <c>operator ==</c> alike, and two
    /// equal-valued instances must still hash the same when compared this way.
    /// </summary>
    [TestMethod]
    public void DataIntegritySecuredPresentationEqualityIncludesProofThroughBaseStaticType()
    {
        VerifiablePresentation withProofA = new DataIntegritySecuredPresentation
        {
            Id = "urn:vp:5",
            Holder = "did:example:holder",
            Proof = [new DataIntegrityProof { ProofValue = "zProofA" }]
        };
        VerifiablePresentation withProofB = new DataIntegritySecuredPresentation
        {
            Id = "urn:vp:5",
            Holder = "did:example:holder",
            Proof = [new DataIntegrityProof { ProofValue = "zProofB" }]
        };

        Assert.IsFalse(withProofA.Equals(withProofB), "A different proof must break equality through the base static type.");
        Assert.IsFalse(((object)withProofA).Equals(withProofB));
        Assert.IsFalse(EqualityComparer<VerifiablePresentation>.Default.Equals(withProofA, withProofB));
        Assert.IsFalse(withProofA == withProofB);
        Assert.IsTrue(withProofA != withProofB);

        VerifiablePresentation otherWithProofA = new DataIntegritySecuredPresentation
        {
            Id = "urn:vp:5",
            Holder = "did:example:holder",
            Proof = [new DataIntegrityProof { ProofValue = "zProofA" }]
        };

        Assert.IsTrue(withProofA.Equals(otherWithProofA));
        Assert.IsTrue(((object)withProofA).Equals(otherWithProofA));
        Assert.IsTrue(EqualityComparer<VerifiablePresentation>.Default.Equals(withProofA, otherWithProofA));
        Assert.IsTrue(withProofA == otherWithProofA);
        Assert.AreEqual(withProofA.GetHashCode(), otherWithProofA.GetHashCode());
    }


    /// <summary>
    /// <see cref="VerifiablePresentation.Equals(VerifiablePresentation?)"/> folds
    /// <see cref="VerifiablePresentation.Context"/> into identity, mirroring
    /// <see cref="VerifiableCredentialEqualityIncludesContext"/>.
    /// </summary>
    [TestMethod]
    public void VerifiablePresentationEqualityIncludesContext()
    {
        var withCredentials20 = new VerifiablePresentation { Id = "urn:vp:3", Context = Context.FromIris(Context.Credentials20) };
        var withDidCore10 = new VerifiablePresentation { Id = "urn:vp:3", Context = Context.FromIris(Context.DidCore10) };
        Assert.IsFalse(withCredentials20.Equals(withDidCore10), "A different context must break equality.");

        var otherWithCredentials20 = new VerifiablePresentation { Id = "urn:vp:3", Context = Context.FromIris(Context.Credentials20) };
        AssertEquality(withCredentials20, otherWithCredentials20);
    }


    /// <summary>
    /// <see cref="EnvelopedVerifiableCredential"/> is identity-based on <see cref="EnvelopedVerifiableCredential.Id"/>
    /// (the <c>data:</c> URL) and <see cref="EnvelopedVerifiableCredential.Context"/>: two instances with the
    /// same id but different contexts are unequal, and two distinct same-valued contexts are equal.
    /// </summary>
    [TestMethod]
    public void EnvelopedVerifiableCredentialEqualityIncludesContext()
    {
        var withCredentials20 = new EnvelopedVerifiableCredential { Id = "data:application/vc+jwt,abc", Context = Context.FromIris(Context.Credentials20) };
        var withDidCore10 = new EnvelopedVerifiableCredential { Id = "data:application/vc+jwt,abc", Context = Context.FromIris(Context.DidCore10) };
        Assert.IsFalse(withCredentials20.Equals(withDidCore10), "A different context must break equality.");

        var otherWithCredentials20 = new EnvelopedVerifiableCredential { Id = "data:application/vc+jwt,abc", Context = Context.FromIris(Context.Credentials20) };
        AssertEquality(withCredentials20, otherWithCredentials20);
    }


    /// <summary>
    /// <see cref="EnvelopedVerifiableCredential.Equals(EnvelopedVerifiableCredential?)"/> does not
    /// consult <see cref="EnvelopedVerifiableCredential.Type"/>: two instances with the same
    /// <see cref="EnvelopedVerifiableCredential.Id"/> and <see cref="EnvelopedVerifiableCredential.Context"/>
    /// compare equal even when <see cref="EnvelopedVerifiableCredential.Type"/> differs, because
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials">VC-DM
    /// 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Credentials"</see> fixes the type
    /// to the single value <c>"EnvelopedVerifiableCredential"</c> for every conformant instance of
    /// this type.
    /// </summary>
    [TestMethod]
    public void EnvelopedVerifiableCredentialEqualityExcludesType()
    {
        var withType = new EnvelopedVerifiableCredential { Id = "data:application/vc+jwt,abc", Type = ["EnvelopedVerifiableCredential"] };
        var withoutType = new EnvelopedVerifiableCredential { Id = "data:application/vc+jwt,abc", Type = null };

        AssertEquality(withType, withoutType);
    }


    /// <summary>
    /// <see cref="EnvelopedVerifiablePresentation"/> is identity-based on <see cref="EnvelopedVerifiablePresentation.Id"/>
    /// (the <c>data:</c> URL) and <see cref="EnvelopedVerifiablePresentation.Context"/>, mirroring
    /// <see cref="EnvelopedVerifiableCredentialEqualityIncludesContext"/>.
    /// </summary>
    [TestMethod]
    public void EnvelopedVerifiablePresentationEqualityIncludesContext()
    {
        var withCredentials20 = new EnvelopedVerifiablePresentation { Id = "data:application/vp+jwt,abc", Context = Context.FromIris(Context.Credentials20) };
        var withDidCore10 = new EnvelopedVerifiablePresentation { Id = "data:application/vp+jwt,abc", Context = Context.FromIris(Context.DidCore10) };
        Assert.IsFalse(withCredentials20.Equals(withDidCore10), "A different context must break equality.");

        var otherWithCredentials20 = new EnvelopedVerifiablePresentation { Id = "data:application/vp+jwt,abc", Context = Context.FromIris(Context.Credentials20) };
        AssertEquality(withCredentials20, otherWithCredentials20);
    }


    /// <summary>
    /// <see cref="EnvelopedVerifiablePresentation.Equals(EnvelopedVerifiablePresentation?)"/> does not
    /// consult <see cref="EnvelopedVerifiablePresentation.Type"/>: two instances with the same
    /// <see cref="EnvelopedVerifiablePresentation.Id"/> and <see cref="EnvelopedVerifiablePresentation.Context"/>
    /// compare equal even when <see cref="EnvelopedVerifiablePresentation.Type"/> differs, because
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-presentations">
    /// VC-DM 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Presentations"</see> fixes the
    /// type to the single value <c>"EnvelopedVerifiablePresentation"</c> for every conformant
    /// instance of this type.
    /// </summary>
    [TestMethod]
    public void EnvelopedVerifiablePresentationEqualityExcludesType()
    {
        var withType = new EnvelopedVerifiablePresentation { Id = "data:application/vp+jwt,abc", Type = ["EnvelopedVerifiablePresentation"] };
        var withoutType = new EnvelopedVerifiablePresentation { Id = "data:application/vp+jwt,abc", Type = null };

        AssertEquality(withType, withoutType);
    }


    /// <summary>
    /// Proves <see cref="CredentialSchema.Equals(CredentialSchema?)"/> and its
    /// <see cref="CredentialSchema.Equals(object?)"/> override are exact-type: a same-valued subtype
    /// instance is unequal to a base instance through both overloads in both directions, while two base
    /// instances with the same values remain equal through both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedCredentialSchemaIsNotEqualToBaseInstance()
    {
        var baseSchema = new CredentialSchema { Id = "https://example.com/schema", Type = "JsonSchema" };
        CredentialSchema derived = new DerivedCredentialSchema { Id = baseSchema.Id, Type = baseSchema.Type };

        AssertExactTypeInequality(baseSchema, derived);

        var otherBase = new CredentialSchema { Id = baseSchema.Id, Type = baseSchema.Type };
        AssertEquality(baseSchema, otherBase);
    }


    /// <summary>
    /// Proves <see cref="CredentialStatus.Equals(CredentialStatus?)"/> and its
    /// <see cref="CredentialStatus.Equals(object?)"/> override are exact-type: a same-valued subtype
    /// instance is unequal to a base instance through both overloads in both directions, while two base
    /// instances with the same values remain equal through both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedCredentialStatusIsNotEqualToBaseInstance()
    {
        var baseStatus = new CredentialStatus { Id = "https://example.com/status#1", Type = "BitstringStatusListEntry" };
        CredentialStatus derived = new DerivedCredentialStatus { Id = baseStatus.Id, Type = baseStatus.Type };

        AssertExactTypeInequality(baseStatus, derived);

        var otherBase = new CredentialStatus { Id = baseStatus.Id, Type = baseStatus.Type };
        AssertEquality(baseStatus, otherBase);
    }


    /// <summary>
    /// Proves <see cref="CredentialSubject.Equals(CredentialSubject?)"/> and its
    /// <see cref="CredentialSubject.Equals(object?)"/> override are exact-type: a same-valued subtype
    /// instance is unequal to a base instance through both overloads in both directions, while two base
    /// instances with the same values remain equal through both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedCredentialSubjectIsNotEqualToBaseInstance()
    {
        var baseSubject = new CredentialSubject { Id = "did:example:subject" };
        CredentialSubject derived = new DerivedCredentialSubject { Id = baseSubject.Id };

        AssertExactTypeInequality(baseSubject, derived);

        var otherBase = new CredentialSubject { Id = baseSubject.Id };
        AssertEquality(baseSubject, otherBase);
    }


    /// <summary>
    /// Proves <see cref="Evidence.Equals(Evidence?)"/> and its <see cref="Evidence.Equals(object?)"/>
    /// override are exact-type: a same-valued subtype instance is unequal to a base instance through
    /// both overloads in both directions, while two base instances with the same values remain equal
    /// through both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedEvidenceIsNotEqualToBaseInstance()
    {
        var baseEvidence = new Evidence { Id = "https://example.com/evidence#1", Type = "DocumentVerification" };
        Evidence derived = new DerivedEvidence { Id = baseEvidence.Id, Type = baseEvidence.Type };

        AssertExactTypeInequality(baseEvidence, derived);

        var otherBase = new Evidence { Id = baseEvidence.Id, Type = baseEvidence.Type };
        AssertEquality(baseEvidence, otherBase);
    }


    /// <summary>
    /// Proves <see cref="Issuer.Equals(Issuer?)"/> and its <see cref="Issuer.Equals(object?)"/> override
    /// are exact-type: a same-valued subtype instance is unequal to a base instance through both
    /// overloads in both directions, while two base instances with the same values remain equal through
    /// both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedIssuerIsNotEqualToBaseInstance()
    {
        var baseIssuer = new Issuer { Id = "did:example:issuer", Name = "Example Issuer" };
        Issuer derived = new DerivedIssuer { Id = baseIssuer.Id, Name = baseIssuer.Name };

        AssertExactTypeInequality(baseIssuer, derived);

        var otherBase = new Issuer { Id = baseIssuer.Id, Name = baseIssuer.Name };
        AssertEquality(baseIssuer, otherBase);
    }


    /// <summary>
    /// Proves <see cref="RefreshService.Equals(RefreshService?)"/> and its
    /// <see cref="RefreshService.Equals(object?)"/> override are exact-type: a same-valued subtype
    /// instance is unequal to a base instance through both overloads in both directions, while two base
    /// instances with the same values remain equal through both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedRefreshServiceIsNotEqualToBaseInstance()
    {
        var baseService = new RefreshService { Id = "https://example.com/refresh", Type = "ManualRefreshService2018" };
        RefreshService derived = new DerivedRefreshService { Id = baseService.Id, Type = baseService.Type };

        AssertExactTypeInequality(baseService, derived);

        var otherBase = new RefreshService { Id = baseService.Id, Type = baseService.Type };
        AssertEquality(baseService, otherBase);
    }


    /// <summary>
    /// Proves <see cref="RelatedResource.Equals(RelatedResource?)"/> and its
    /// <see cref="RelatedResource.Equals(object?)"/> override are exact-type: a same-valued subtype
    /// instance is unequal to a base instance through both overloads in both directions, while two base
    /// instances with the same values remain equal through both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedRelatedResourceIsNotEqualToBaseInstance()
    {
        var baseResource = new RelatedResource { Id = "https://example.com/resource", DigestSRI = "sha384-abc" };
        RelatedResource derived = new DerivedRelatedResource { Id = baseResource.Id, DigestSRI = baseResource.DigestSRI };

        AssertExactTypeInequality(baseResource, derived);

        var otherBase = new RelatedResource { Id = baseResource.Id, DigestSRI = baseResource.DigestSRI };
        AssertEquality(baseResource, otherBase);
    }


    /// <summary>
    /// Proves <see cref="TermsOfUse.Equals(TermsOfUse?)"/> and its <see cref="TermsOfUse.Equals(object?)"/>
    /// override are exact-type: a same-valued subtype instance is unequal to a base instance through both
    /// overloads in both directions, while two base instances with the same values remain equal through
    /// both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedTermsOfUseIsNotEqualToBaseInstance()
    {
        var baseTerms = new TermsOfUse { Id = "https://example.com/terms", Type = "IssuerPolicy" };
        TermsOfUse derived = new DerivedTermsOfUse { Id = baseTerms.Id, Type = baseTerms.Type };

        AssertExactTypeInequality(baseTerms, derived);

        var otherBase = new TermsOfUse { Id = baseTerms.Id, Type = baseTerms.Type };
        AssertEquality(baseTerms, otherBase);
    }


    /// <summary>
    /// Proves <see cref="DidDocumentMetadata.Equals(DidDocumentMetadata?)"/> and its
    /// <see cref="DidDocumentMetadata.Equals(object?)"/> override are exact-type: a same-valued subtype
    /// instance is unequal to a base instance through both overloads in both directions, while two base
    /// instances with the same values remain equal through both overloads.
    /// </summary>
    [TestMethod]
    public void DerivedDidDocumentMetadataIsNotEqualToBaseInstance()
    {
        var baseMetadata = new DidDocumentMetadata { VersionId = "1", CanonicalId = "did:example:1", Deactivated = false };
        DidDocumentMetadata derived = new DerivedDidDocumentMetadata { VersionId = baseMetadata.VersionId, CanonicalId = baseMetadata.CanonicalId, Deactivated = baseMetadata.Deactivated };

        AssertExactTypeInequality(baseMetadata, derived);

        var otherBase = new DidDocumentMetadata { VersionId = baseMetadata.VersionId, CanonicalId = baseMetadata.CanonicalId, Deactivated = baseMetadata.Deactivated };
        AssertEquality(baseMetadata, otherBase);
    }
}
