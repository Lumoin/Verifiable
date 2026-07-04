using System;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Json;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebPlusDataModelValidation"/> — the single-document validation of a did:webplus DID
/// document (did:webplus Draft v0.4, Validation of DID Documents, steps 1–5 and the root <c>versionId</c>
/// constraint). Anchored on the worked-example root and non-root documents from the specification; each
/// negative case mutates one field and re-canonicalizes, so the byte-equality step still holds and the targeted
/// obligation is the one that fails closed. Parsing and JCS canonicalization come from the firewalled
/// <c>Verifiable.Json</c> leaf.
/// </summary>
[TestClass]
internal sealed class WebPlusDataModelValidationTests
{
    //The worked-example root DID document (versionId 0). Every fully-qualified key id carries the root self-hash
    //value and the versionId 0 query parameter.
    private const string RootDidDocument =
        """
        {
          "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
          "selfHash": "uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
          "updateRules": {
            "key": "u7QFCWKaWNQ5FsNShO8BlZwjHa5xkGleeETKwu-vjf1SZXg"
          },
          "validFrom": "2025-11-19T01:21:47.699Z",
          "versionId": 0,
          "verificationMethod": [
            {
              "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w&versionId=0#0",
              "type": "JsonWebKey2020",
              "controller": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
              "publicKeyJwk": {
                "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w&versionId=0#0",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ"
              }
            }
          ],
          "authentication": [
            "#0"
          ],
          "assertionMethod": [
            "#0"
          ]
        }
        """;


    //The worked-example non-root DID document (versionId 1). It carries prevDIDDocumentSelfHash, so it is a
    //non-root document and is not bound by the root versionId-0 constraint.
    private const string NonRootDidDocument =
        """
        {
          "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
          "selfHash": "uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q",
          "prevDIDDocumentSelfHash": "uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
          "updateRules": {
            "key": "u7QFNzTwiEH-gYlFQ_jb01lEFnWnyZPzq-rcehFEbF-rPFg"
          },
          "validFrom": "2025-11-19T01:21:47.715Z",
          "versionId": 1,
          "verificationMethod": [
            {
              "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#0",
              "type": "JsonWebKey2020",
              "controller": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
              "publicKeyJwk": {
                "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#0",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ"
              }
            }
          ],
          "authentication": [
            "#0"
          ]
        }
        """;


    /// <summary>Validates the canonicalized document through the production seams, returning the failure reason or <see langword="null"/>.</summary>
    private static string? Validate(string didDocumentJson)
    {
        byte[] jcs = Jcs.CanonicalizeToUtf8Bytes(didDocumentJson);

        return WebPlusDataModelValidation.Validate(jcs, WebPlusDidDocumentJson.Parser, WebPlusDidDocumentJson.Canonicalizer);
    }


    /// <summary>The worked-example root DID document satisfies every single-document obligation.</summary>
    [TestMethod]
    public void ValidatesSpecificationRootDocument()
    {
        Assert.IsNull(Validate(RootDidDocument));
    }


    /// <summary>The worked-example non-root DID document satisfies every single-document obligation (WP-VAL-10: classified non-root by the prevDIDDocumentSelfHash field).</summary>
    [TestMethod]
    public void ValidatesSpecificationNonRootDocument()
    {
        Assert.IsNull(Validate(NonRootDidDocument));
    }


    /// <summary>WP-VAL-1: a document whose bytes are not their JCS-serialized form is rejected.</summary>
    [TestMethod]
    public void RejectsNonCanonicalDocument()
    {
        //The pretty-printed bytes (indentation, newlines) are not the JCS canonical form.
        byte[] pretty = Encoding.UTF8.GetBytes(RootDidDocument);

        string? error = WebPlusDataModelValidation.Validate(pretty, WebPlusDidDocumentJson.Parser, WebPlusDidDocumentJson.Canonicalizer);

        Assert.IsNotNull(error);
    }


    /// <summary>WP-DM-2: the document <c>id</c> MUST NOT contain a fragment.</summary>
    [TestMethod]
    public void RejectsIdWithFragment()
    {
        string mutated = RootDidDocument.Replace(
            "\"id\": \"did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w\"",
            "\"id\": \"did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w#0\"",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-DM-2: the document <c>id</c> MUST be a did:webplus DID.</summary>
    [TestMethod]
    public void RejectsIdWrongMethod()
    {
        string mutated = RootDidDocument.Replace(
            "\"id\": \"did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w\"",
            "\"id\": \"did:example:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w\"",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-DM-3: the <c>selfHash</c> field MUST be a valid MBHash (a multibase value).</summary>
    [TestMethod]
    public void RejectsSelfHashNotMultibase()
    {
        string mutated = RootDidDocument.Replace(
            "\"selfHash\": \"uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w\"",
            "\"selfHash\": \"XHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w\"",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-DM-5: the document MUST have an <c>updateRules</c> field.</summary>
    [TestMethod]
    public void RejectsMissingUpdateRules()
    {
        //Rename the field so updateRules is absent (the renamed field is merely an allowed extra field).
        string mutated = RootDidDocument.Replace(
            "\"updateRules\":",
            "\"someOtherRules\":",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-DM-8: <c>versionId</c> MUST be an unsigned integer, not a string.</summary>
    [TestMethod]
    public void RejectsVersionIdAsString()
    {
        string mutated = RootDidDocument.Replace(
            "\"versionId\": 0,",
            "\"versionId\": \"0\",",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-VAL-3: <c>validFrom</c> MUST have precision no greater than milliseconds.</summary>
    [TestMethod]
    public void RejectsValidFromSubMillisecondPrecision()
    {
        string mutated = RootDidDocument.Replace(
            "\"2025-11-19T01:21:47.699Z\"",
            "\"2025-11-19T01:21:47.699999Z\"",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-VAL-4: <c>validFrom</c> MUST NOT be before the UNIX epoch.</summary>
    [TestMethod]
    public void RejectsValidFromBeforeEpoch()
    {
        string mutated = RootDidDocument.Replace(
            "\"2025-11-19T01:21:47.699Z\"",
            "\"1969-12-31T23:59:59.000Z\"",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-VAL-5d: a verification method <c>id</c> MUST have a URL fragment.</summary>
    [TestMethod]
    public void RejectsVerificationMethodIdWithoutFragment()
    {
        string mutated = RootDidDocument.Replace(
            "versionId=0#0\"",
            "versionId=0\"",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-VAL-5b: a verification method <c>id</c> <c>selfHash</c> query parameter MUST equal the document <c>selfHash</c>.</summary>
    [TestMethod]
    public void RejectsVerificationMethodSelfHashMismatch()
    {
        string mutated = RootDidDocument.Replace(
            "selfHash=uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
            "selfHash=uHiZZ77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-DM-4: <c>prevDIDDocumentSelfHash</c>, when non-null, MUST be a valid MBHash.</summary>
    [TestMethod]
    public void RejectsPrevDidDocumentSelfHashNotMultibase()
    {
        string mutated = NonRootDidDocument.Replace(
            "\"prevDIDDocumentSelfHash\": \"uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w\"",
            "\"prevDIDDocumentSelfHash\": \"XHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w\"",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>WP-VAL-5c: a verification method <c>id</c> <c>versionId</c> query parameter MUST equal the document <c>versionId</c>.</summary>
    [TestMethod]
    public void RejectsVerificationMethodVersionIdMismatch()
    {
        //Change only the verification method id's versionId query parameter; the document versionId field stays 0.
        string mutated = RootDidDocument.Replace(
            "versionId=0#0",
            "versionId=1#0",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>
    /// WP-DM-9: a <c>verificationMethod</c> field that is present MUST be an array. A non-array value is a
    /// shape-level data-model violation the parser rejects (the resolver rejects the document on the parse
    /// failure, mirroring did:webvh's line-parser contract).
    /// </summary>
    [TestMethod]
    public void RejectsVerificationMethodNotArray()
    {
        const string nonArrayVerificationMethod =
            """
            {
              "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
              "selfHash": "uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
              "updateRules": { "key": "u7QFCWKaWNQ5FsNShO8BlZwjHa5xkGleeETKwu-vjf1SZXg" },
              "validFrom": "2025-11-19T01:21:47.699Z",
              "versionId": 0,
              "verificationMethod": "not-an-array"
            }
            """;
        byte[] jcs = Jcs.CanonicalizeToUtf8Bytes(nonArrayVerificationMethod);

        Assert.ThrowsExactly<JsonException>(() => WebPlusDidDocumentJson.Parser(jcs));
    }


    /// <summary>WP-DM-12 / WP-VAL-7root: a root DID document's <c>versionId</c> MUST be 0.</summary>
    [TestMethod]
    public void RejectsRootVersionIdNonZero()
    {
        //Bump both the versionId field and the verification method id query parameter, so the verification
        //method checks pass and the root versionId-0 constraint is the one that fails.
        string mutated = RootDidDocument
            .Replace("\"versionId\": 0,", "\"versionId\": 5,", StringComparison.Ordinal)
            .Replace("versionId=0#0", "versionId=5#0", StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>
    /// WP-DM-7 / WP-VAL-3: a <c>validFrom</c> without an explicit RFC 3339 offset is rejected. An offset-less
    /// timestamp is not RFC 3339 and <c>DateTimeOffset</c> would bind it to the resolver host's local zone, so two
    /// resolvers in different zones could order the history differently.
    /// </summary>
    [TestMethod]
    public void RejectsValidFromWithoutOffset()
    {
        string mutated = RootDidDocument.Replace(
            "\"2025-11-19T01:21:47.699Z\"",
            "\"2025-11-19T01:21:47.699\"",
            StringComparison.Ordinal);

        Assert.IsNotNull(Validate(mutated));
    }


    /// <summary>
    /// WP-VAL-1 / RFC 8785 Section 3.1: a document repeating a top-level member is ambiguous; the strict parser
    /// rejects it (<c>AllowDuplicateProperties = false</c>) rather than resolving the duplicate last-wins while the
    /// self-hash is computed over the raw duplicate-preserving bytes.
    /// </summary>
    [TestMethod]
    public void RejectsDuplicateTopLevelKeysDocument()
    {
        //A minimal document repeating the security-critical selfHash member with two different values.
        const string duplicateKeyDocument =
            """{"id":"did:webplus:example.com:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w","selfHash":"uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w","selfHash":"uHiZZ77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w","updateRules":{"key":"u7QFCWKaWNQ5FsNShO8BlZwjHa5xkGleeETKwu-vjf1SZXg"},"validFrom":"2025-11-19T01:21:47.699Z","versionId":0}""";
        byte[] bytes = Encoding.UTF8.GetBytes(duplicateKeyDocument);

        Assert.ThrowsExactly<JsonException>(() => WebPlusDidDocumentJson.Parser(bytes));
    }
}
