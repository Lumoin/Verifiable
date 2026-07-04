using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Core.Model.Did;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests the method-polymorphic deserialization of a <c>did:webplus</c> document: the shared
/// <c>DidDocumentConverter</c> recognizes the method from the <c>id</c> and materializes a typed
/// <see cref="WebPlusDidDocument"/> (rather than a bare <see cref="DidDocument"/>), surfacing the
/// method-specific control fields as typed properties while round-tripping the document faithfully.
/// </summary>
[TestClass]
internal sealed class WebPlusDidDocumentSerializationTests
{
    /// <summary>The shared serialization options (includes the DidDocumentConverter).</summary>
    private static System.Text.Json.JsonSerializerOptions Options => TestSetup.DefaultSerializationOptions;

    //A worked-example did:webplus root DID document (versionId 0). It carries the method-specific control fields
    //(selfHash, updateRules, validFrom, versionId) alongside the W3C core members.
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
          ]
        }
        """;


    /// <summary>A did:webplus document deserializes to a typed <see cref="WebPlusDidDocument"/> via the shared converter.</summary>
    [TestMethod]
    public void DeserializesToWebPlusDidDocumentSubtype()
    {
        DidDocument? document = JsonSerializerExtensions.Deserialize<DidDocument>(RootDidDocument, Options);

        Assert.IsInstanceOfType<WebPlusDidDocument>(document);
        var webPlus = (WebPlusDidDocument)document!;

        Assert.AreEqual("uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w", webPlus.SelfHash);
        Assert.IsNull(webPlus.PrevDidDocumentSelfHash, "A root document has no prevDIDDocumentSelfHash.");
        Assert.AreEqual(0UL, webPlus.VersionId);
        Assert.AreEqual("2025-11-19T01:21:47.699Z", webPlus.ValidFrom);
        Assert.IsNotNull(webPlus.UpdateRules);
        //The W3C core members are populated on the base.
        Assert.IsNotNull(webPlus.Id);
        Assert.IsNotNull(webPlus.VerificationMethod);
    }


    /// <summary>The did:webplus document round-trips faithfully through the typed subtype.</summary>
    [TestMethod]
    public void WebPlusDidDocumentRoundtripsFaithfully()
    {
        var (deserialized, reserialized) = JsonSerializationUtilities.PerformSerializationCycle<DidDocument>(RootDidDocument, Options);

        Assert.IsInstanceOfType<WebPlusDidDocument>(deserialized);
        Assert.IsTrue(
            JsonSerializationUtilities.CompareJsonElements(RootDidDocument, reserialized),
            $"did:webplus document roundtrip changed structure. Reserialized: {reserialized}");
    }
}
