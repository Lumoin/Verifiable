using System.Text.Json;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Shape-preservation tests for <see cref="ProofOptionsSerializer"/>: a proof parsed
/// from the wire reconstructs its Data Integrity 1.0 §4.2 proof options (the proof
/// with <c>proofValue</c> removed) from the RECEIVED bytes, so the signer's member
/// shapes — a multi-domain set, the scalar-versus-array choice, extension members —
/// survive exactly into the canonicalized form; and the typed (signing) path covers
/// every member the wire proof will carry, including <c>id</c>, <c>previousProof</c>,
/// <c>challenge</c>, and <c>domain</c>.
/// </summary>
[TestClass]
internal sealed class ProofOptionsShapePreservationTests
{
    private static JsonSerializerOptions Options { get; } = TestSetup.DefaultSerializationOptions;


    /// <summary>
    /// §2.1 allows <c>domain</c> as an unordered set of strings; a foreign signer's
    /// array form must survive the §4.2 reconstruction byte-shape intact, with
    /// <c>proofValue</c> removed and nothing else touched.
    /// </summary>
    [TestMethod]
    public void ReceivedArrayDomainSurvivesReconstruction()
    {
        var proofOptions = ProofOptionsDocument.FromProof(
            ParseProof(/*lang=json,strict*/ """
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "created": "2024-06-15T12:00:00Z",
                    "verificationMethod": "did:example:holder#key-1",
                    "proofPurpose": "authentication",
                    "challenge": "challenge-1",
                    "domain": ["one.example", "two.example"],
                    "proofValue": "z58DAdFfa9SkqZMVPxAQp"
                }
                """),
            context: null);

        string serialized = ProofOptionsSerializer.Serialize(proofOptions, Options);
        using var doc = JsonDocument.Parse(serialized);

        Assert.AreEqual(JsonValueKind.Array, doc.RootElement.GetProperty("domain").ValueKind,
            "The signer's array shape must survive into the canonicalized options.");
        Assert.AreEqual(2, doc.RootElement.GetProperty("domain").GetArrayLength());
        Assert.IsFalse(doc.RootElement.TryGetProperty("proofValue", out _),
            "§4.2: the options are the proof with proofValue removed.");
        Assert.AreEqual("challenge-1", doc.RootElement.GetProperty("challenge").GetString());
    }


    /// <summary>
    /// A foreign signer's scalar <c>domain</c> stays scalar, and an extension member
    /// unknown to the typed model survives — the received bytes rule preserves what
    /// re-serializing the typed members would silently drop or reshape.
    /// </summary>
    [TestMethod]
    public void ReceivedScalarDomainAndExtensionMemberSurvive()
    {
        var proofOptions = ProofOptionsDocument.FromProof(
            ParseProof(/*lang=json,strict*/ """
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "created": "2024-06-15T12:00:00Z",
                    "verificationMethod": "did:example:holder#key-1",
                    "proofPurpose": "authentication",
                    "domain": "verifier.example",
                    "proofOfWork": "0000abcd",
                    "proofValue": "z58DAdFfa9SkqZMVPxAQp"
                }
                """),
            context: null);

        string serialized = ProofOptionsSerializer.Serialize(proofOptions, Options);
        using var doc = JsonDocument.Parse(serialized);

        Assert.AreEqual(JsonValueKind.String, doc.RootElement.GetProperty("domain").ValueKind,
            "The signer's scalar shape must survive.");
        Assert.AreEqual("0000abcd", doc.RootElement.GetProperty("proofOfWork").GetString(),
            "An extension member the typed model does not name must survive the reconstruction.");
        Assert.IsFalse(doc.RootElement.TryGetProperty("proofValue", out _));
    }


    /// <summary>
    /// The typed (signing) path mirrors the wire converter member-for-member minus
    /// <c>proofValue</c>: <c>id</c>, <c>previousProof</c>, <c>challenge</c>, and the
    /// singleton-scalar <c>domain</c> are all in the canonicalized options — coverage
    /// by the signature is what makes them bindings rather than advisory fields.
    /// </summary>
    [TestMethod]
    public void TypedPathCoversEveryWireMember()
    {
        var proofOptions = ProofOptionsDocument.FromProof(
            new DataIntegrityProof
            {
                Id = "urn:uuid:00000000-0000-0000-0000-000000000001",
                Type = DataIntegrityProof.DataIntegrityProofType,
                Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
                Created = "2024-06-15T12:00:00Z",
                VerificationMethod = new Verifiable.Core.Model.Did.AuthenticationMethod("did:example:holder#key-1"),
                ProofPurpose = "authentication",
                Challenge = "challenge-1",
                Domain = ["verifier.example"],
                PreviousProof = "urn:uuid:00000000-0000-0000-0000-000000000000"
            },
            context: null);

        string serialized = ProofOptionsSerializer.Serialize(proofOptions, Options);
        using var doc = JsonDocument.Parse(serialized);

        Assert.AreEqual("urn:uuid:00000000-0000-0000-0000-000000000001", doc.RootElement.GetProperty("id").GetString());
        Assert.AreEqual("urn:uuid:00000000-0000-0000-0000-000000000000", doc.RootElement.GetProperty("previousProof").GetString());
        Assert.AreEqual("challenge-1", doc.RootElement.GetProperty("challenge").GetString());
        Assert.AreEqual(JsonValueKind.String, doc.RootElement.GetProperty("domain").ValueKind,
            "A one-element domain set writes the scalar wire form, mirroring the converter.");
        Assert.AreEqual("verifier.example", doc.RootElement.GetProperty("domain").GetString());
        Assert.IsFalse(doc.RootElement.TryGetProperty("proofValue", out _));

        //A multi-domain set writes the array form.
        var multiDomain = ProofOptionsDocument.FromProof(
            new DataIntegrityProof
            {
                Type = DataIntegrityProof.DataIntegrityProofType,
                Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
                Created = "2024-06-15T12:00:00Z",
                VerificationMethod = new Verifiable.Core.Model.Did.AuthenticationMethod("did:example:holder#key-1"),
                ProofPurpose = "authentication",
                Domain = ["one.example", "two.example"]
            },
            context: null);

        using var multiDoc = JsonDocument.Parse(ProofOptionsSerializer.Serialize(multiDomain, Options));
        Assert.AreEqual(JsonValueKind.Array, multiDoc.RootElement.GetProperty("domain").ValueKind);
    }


    /// <summary>
    /// Parses a wire proof through the registered converter so the received JSON is
    /// retained, the way verification sees a proof.
    /// </summary>
    private static DataIntegrityProof ParseProof(string proofJson)
    {
        var proof = JsonSerializerExtensions.Deserialize<DataIntegrityProof>(proofJson, Options)!;
        Assert.IsNotNull(proof.ReceivedProofJson, "The converter must retain the received proof JSON.");

        return proof;
    }
}
