using System.Security.Cryptography;
using System.Text;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Test vectors from W3C VC Data Integrity ECDSA Cryptosuites v1.0 specification.
/// Section A.7: Representation ecdsa-sd-2023.
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#representation-ecdsa-sd-2023"/>.
/// </summary>
[TestClass]
internal sealed class BlankNodeRelabelingW3CTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The HMAC key from W3C test vectors (Example 71).
    /// 32 bytes as required by HMAC-SHA256.
    /// </summary>
    private static readonly byte[] W3CHmacKey = Convert.FromHexString(
        "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");


    /// <summary>
    /// Verifies HMAC computation produces correct label for c14n0.
    /// From W3C Example 75→76: c14n0 (VC root) maps to u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38.
    /// Evidence: Example 75 index 1 has "_:c14n0 type EmploymentAuthorizationDocumentCredential"
    /// and Example 76 index 12 has "_:u4YIOZn1... type EmploymentAuthorizationDocumentCredential".
    /// </summary>
    [TestMethod]
    public void HmacLabelForC14n0MatchesW3CTestVector()
    {
        const string CanonicalId = "c14n0";
        const string ExpectedHmacLabel = "u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38";

        byte[] hmacBytes = HMACSHA256.HashData(W3CHmacKey, Encoding.UTF8.GetBytes(CanonicalId));
        string actualLabel = "u" + TestSetup.Base64UrlEncoder(hmacBytes);

        Assert.AreEqual(ExpectedHmacLabel, actualLabel);
    }


    /// <summary>
    /// Verifies HMAC computation produces correct label for c14n1.
    /// From W3C Example 75→76: c14n1 (credentialSubject) maps to u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg.
    /// Evidence: Example 75 index 9 has "_:c14n1 type Person"
    /// and Example 76 index 1 has "_:u3Lv2... type Person".
    /// </summary>
    [TestMethod]
    public void HmacLabelForC14n1MatchesW3CTestVector()
    {
        const string CanonicalId = "c14n1";
        const string ExpectedHmacLabel = "u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg";

        byte[] hmacBytes = HMACSHA256.HashData(W3CHmacKey, Encoding.UTF8.GetBytes(CanonicalId));
        string actualLabel = "u" + TestSetup.Base64UrlEncoder(hmacBytes);

        Assert.AreEqual(ExpectedHmacLabel, actualLabel);
    }


    /// <summary>
    /// Verifies HMAC computation produces correct label for c14n2.
    /// From W3C Example 75→76: c14n2 (employmentAuthorizationDocument) maps to uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw.
    /// Evidence: Example 75 index 21 has "_:c14n2 type EmploymentAuthorizationDocument"
    /// and Example 76 index 20 has "_:uVkUu... type EmploymentAuthorizationDocument".
    /// </summary>
    [TestMethod]
    public void HmacLabelForC14n2MatchesW3CTestVector()
    {
        const string CanonicalId = "c14n2";
        const string ExpectedHmacLabel = "uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw";

        byte[] hmacBytes = HMACSHA256.HashData(W3CHmacKey, Encoding.UTF8.GetBytes(CanonicalId));
        string actualLabel = "u" + TestSetup.Base64UrlEncoder(hmacBytes);

        Assert.AreEqual(ExpectedHmacLabel, actualLabel);
    }


    /// <summary>
    /// Verifies that the first statement (index 0) is relabeled correctly.
    /// This is an IRI-only statement with no blank nodes.
    /// From W3C Example 75 → Example 76.
    /// </summary>
    [TestMethod]
    public void FirstStatementWithNoBlankNodesRemainsUnchanged()
    {
        const string CanonicalStatement =
            "<did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76> <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg==> .\n";

        string relabeled = BlankNodeRelabeling.RelabelNQuad(
            CanonicalStatement,
            W3CHmacKey,
            HMACSHA256.HashData,
            TestSetup.Base64UrlEncoder);

        Assert.AreEqual(CanonicalStatement, relabeled);
    }


    /// <summary>
    /// Verifies statement with c14n1 subject is correctly relabeled.
    /// From W3C Example 75 (index 9): _:c14n1 type Person
    /// To W3C Example 76 (index 1): _:u3Lv2... type Person
    /// </summary>
    [TestMethod]
    public void StatementWithC14n1SubjectIsRelabeledCorrectly()
    {
        const string CanonicalStatement =
            "_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .\n";

        const string ExpectedRelabeled =
            "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .\n";

        string actual = BlankNodeRelabeling.RelabelNQuad(
            CanonicalStatement,
            W3CHmacKey,
            HMACSHA256.HashData,
            TestSetup.Base64UrlEncoder);

        Assert.AreEqual(ExpectedRelabeled, actual);
    }


    /// <summary>
    /// Verifies statement with c14n0 subject (VC root) is correctly relabeled.
    /// From W3C Example 75 (index 1): _:c14n0 type EmploymentAuthorizationDocumentCredential
    /// To W3C Example 76 (index 12): _:u4YIOZn1... type EmploymentAuthorizationDocumentCredential
    /// </summary>
    [TestMethod]
    public void StatementWithC14n0SubjectIsRelabeledCorrectly()
    {
        const string CanonicalStatement =
            "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential> .\n";

        const string ExpectedRelabeled =
            "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential> .\n";

        string actual = BlankNodeRelabeling.RelabelNQuad(
            CanonicalStatement,
            W3CHmacKey,
            HMACSHA256.HashData,
            TestSetup.Base64UrlEncoder);

        Assert.AreEqual(ExpectedRelabeled, actual);
    }


    /// <summary>
    /// Verifies statement with c14n2 subject is correctly relabeled.
    /// From W3C Example 75: _:c14n2 type EmploymentAuthorizationDocument
    /// To W3C Example 76: _:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw type EmploymentAuthorizationDocument
    /// </summary>
    [TestMethod]
    public void StatementWithC14n2SubjectIsRelabeledCorrectly()
    {
        const string CanonicalStatement =
            "_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocument> .\n";

        const string ExpectedRelabeled =
            "_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocument> .\n";

        string actual = BlankNodeRelabeling.RelabelNQuad(
            CanonicalStatement,
            W3CHmacKey,
            HMACSHA256.HashData,
            TestSetup.Base64UrlEncoder);

        Assert.AreEqual(ExpectedRelabeled, actual);
    }


    /// <summary>
    /// Verifies statement with both subject and object blank nodes is relabeled correctly.
    /// From W3C Example 75: _:c14n1 employmentAuthorizationDocument _:c14n2
    /// To W3C Example 76: _:u3Lv2... employmentAuthorizationDocument _:uVkUu...
    /// </summary>
    [TestMethod]
    public void StatementWithSubjectAndObjectBlankNodesIsRelabeledCorrectly()
    {
        const string CanonicalStatement =
            "_:c14n1 <https://w3id.org/citizenship#employmentAuthorizationDocument> _:c14n2 .\n";

        const string ExpectedRelabeled =
            "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://w3id.org/citizenship#employmentAuthorizationDocument> _:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw .\n";

        string actual = BlankNodeRelabeling.RelabelNQuad(
            CanonicalStatement,
            W3CHmacKey,
            HMACSHA256.HashData,
            TestSetup.Base64UrlEncoder);

        Assert.AreEqual(ExpectedRelabeled, actual);
    }


    /// <summary>
    /// Verifies that relabeling a complete set of canonical N-Quads produces
    /// the expected label map matching W3C test vectors.
    /// Based on mappings derived from W3C Example 75 → Example 76.
    /// </summary>
    [TestMethod]
    public void LabelMapFromRelabelingMatchesW3CTestVector()
    {
        //A subset of canonical statements sufficient to establish the label map.
        var canonicalStatements = new[]
        {
            "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential> .\n",
            "_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .\n",
            "_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocument> .\n"
        };

        RelabelingResult result = BlankNodeRelabeling.RelabelNQuadsWithMap(
            canonicalStatements,
            W3CHmacKey,
            HMACSHA256.HashData,
            TestSetup.Base64UrlEncoder);

        Assert.HasCount(3, result.LabelMap);

        //c14n0 (VC root) → u4YIOZn1...
        Assert.AreEqual("u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38", result.LabelMap["c14n0"]);

        //c14n1 (credentialSubject) → u3Lv2...
        Assert.AreEqual("u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg", result.LabelMap["c14n1"]);

        //c14n2 (employmentAuthorizationDocument) → uVkUu...
        Assert.AreEqual("uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw", result.LabelMap["c14n2"]);
    }


    /// <summary>
    /// Verifies that HMAC blank node identifiers contain valid base64url characters
    /// including hyphen (-) and underscore (_).
    /// This validates the regex fix for blank node pattern matching.
    /// </summary>
    [TestMethod]
    public void HmacIdentifiersContainBase64UrlCharacters()
    {
        //The HMAC identifiers from W3C test vectors contain both hyphen and underscore.
        const string HmacIdWithHyphen = "u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg";
        const string HmacIdWithUnderscore = "uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw";

        Assert.IsTrue(HmacIdWithHyphen.Contains('-', StringComparison.Ordinal), "W3C test vector should contain hyphen.");
        Assert.Contains('_', HmacIdWithUnderscore, "W3C test vector should contain underscore.");

        //Verify these can be extracted from relabeled statements.
        string statement = $"_:{HmacIdWithHyphen} <http://example.org/pred> _:{HmacIdWithUnderscore} .\n";
        var blankNodes = BlankNodeRelabelingExtensions.ExtractBlankNodes(statement);

        Assert.HasCount(2, blankNodes);
        Assert.AreEqual($"_:{HmacIdWithHyphen}", blankNodes[0]);
        Assert.AreEqual($"_:{HmacIdWithUnderscore}", blankNodes[1]);
    }


    /// <summary>
    /// Verifies the complete transformation from W3C Example 75 to Example 76
    /// for a representative subset of statements.
    /// Mapping: c14n0→u4YIOZn1..., c14n1→u3Lv2..., c14n2→uVkUu...
    /// </summary>
    [TestMethod]
    public void CompleteTransformationMatchesW3CTestVectors()
    {
        //Selected statements from W3C Example 75: Canonical Document.
        var canonicalStatements = new[]
        {
            "<did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76> <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg==> .\n",
            "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential> .\n",
            "_:c14n0 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n1 .\n",
            "_:c14n1 <https://schema.org/givenName> \"JOHN\" .\n",
            "_:c14n1 <https://w3id.org/citizenship#employmentAuthorizationDocument> _:c14n2 .\n",
            "_:c14n2 <https://schema.org/identifier> \"83627465\" .\n"
        };

        //Expected results using correct mappings: c14n0→u4YIOZn1..., c14n1→u3Lv2..., c14n2→uVkUu...
        var expectedRelabeled = new[]
        {
            "<did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76> <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg==> .\n",
            "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential> .\n",
            "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://www.w3.org/2018/credentials#credentialSubject> _:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg .\n",
            "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://schema.org/givenName> \"JOHN\" .\n",
            "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://w3id.org/citizenship#employmentAuthorizationDocument> _:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw .\n",
            "_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://schema.org/identifier> \"83627465\" .\n"
        };

        IReadOnlyList<string> actualRelabeled = BlankNodeRelabeling.RelabelNQuads(
            canonicalStatements,
            W3CHmacKey,
            HMACSHA256.HashData,
            TestSetup.Base64UrlEncoder);

        Assert.HasCount(expectedRelabeled.Length, actualRelabeled);
        for(int i = 0; i < expectedRelabeled.Length; i++)
        {
            Assert.AreEqual(expectedRelabeled[i], actualRelabeled[i], $"Mismatch at statement index {i}.");
        }
    }


    /// <summary>
    /// Verifies IsHmacBlankNode correctly identifies HMAC-relabeled blank nodes
    /// using identifiers from W3C test vectors.
    /// </summary>
    [TestMethod]
    public void IsHmacBlankNodeIdentifiesW3CTestVectorIdentifiers()
    {
        Assert.IsTrue(BlankNodeRelabelingExtensions.IsHmacBlankNode("_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg"));
        Assert.IsTrue(BlankNodeRelabelingExtensions.IsHmacBlankNode("_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38"));
        Assert.IsTrue(BlankNodeRelabelingExtensions.IsHmacBlankNode("_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw"));
        Assert.IsFalse(BlankNodeRelabelingExtensions.IsHmacBlankNode("_:c14n0"));
        Assert.IsFalse(BlankNodeRelabelingExtensions.IsHmacBlankNode("_:c14n1"));
    }
}