using System;
using System.Threading.Tasks;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebPlusProofs"/> — the did:webplus detached-JWS proof verification (WP-PRF-1/2/3,
/// WP-VAL-6). Anchored on the versionId-1 DID document from the specification's "Creating and Updating a DID"
/// worked example (LedgerDomain Draft v0.4), whose Ed25519 <c>b64:false</c> proof was minted by the independent
/// Rust reference implementation. The verifier reconstructs the signing input from the document's wire bytes only
/// and resolves the verifying key from the proof's <c>kid</c> MBPubKey (firewall).
/// </summary>
[TestClass]
internal sealed class WebPlusProofsTests
{
    private const int Blake3DigestLength = 32;

    private static EncodeDelegate Base64UrlEncoder => TestSetup.Base64UrlEncoder;

    private static DecodeDelegate Base64UrlDecoder => TestSetup.Base64UrlDecoder;

    private static DecodeDelegate Base58Decoder => TestSetup.Base58Decoder;

    private static WebPlusProofExtractor ProofExtractor => WebPlusDidDocumentJson.ProofExtractor;


    /// <summary>The non-root document's <c>selfHash</c>, occupying every self-hash slot.</summary>
    private const string NonRootSelfHash = "uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q";

    /// <summary>The single Ed25519 <c>b64:false</c> proof carried by the non-root document.</summary>
    private const string Proof =
        "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRkNXS2FXTlE1RnNOU2hPOEJsWndqSGE1eGtHbGVlRVRLd3UtdmpmMVNaWGciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..DlqKjcvzBqMk8fE0AMqOr1Lnj6NgiMTv6iZMFWxHHWYLRz2KFVs9uTCVUfRrEBS2FAqLWY2u2lve8TNopSUkBA";

    //The versionId-1 DID document from the worked example, JCS-canonicalized below to the bytes the proof's
    //signing input is reconstructed from. Its proofs array carries the proof signed by the previous (root)
    //update key over this document with proofs removed and self-hash slots set to the placeholder.
    private const string NonRootDidDocument =
        """
        {
          "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
          "selfHash": "uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q",
          "prevDIDDocumentSelfHash": "uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
          "updateRules": {
            "key": "u7QFNzTwiEH-gYlFQ_jb01lEFnWnyZPzq-rcehFEbF-rPFg"
          },
          "proofs": [
            "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRkNXS2FXTlE1RnNOU2hPOEJsWndqSGE1eGtHbGVlRVRLd3UtdmpmMVNaWGciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..DlqKjcvzBqMk8fE0AMqOr1Lnj6NgiMTv6iZMFWxHHWYLRz2KFVs9uTCVUfRrEBS2FAqLWY2u2lve8TNopSUkBA"
          ],
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
            },
            {
              "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#1",
              "type": "JsonWebKey2020",
              "controller": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
              "publicKeyJwk": {
                "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#1",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "g2AYHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg"
              }
            }
          ],
          "authentication": [
            "#0",
            "#1"
          ],
          "assertionMethod": [
            "#0"
          ],
          "keyAgreement": [
            "#0"
          ],
          "capabilityInvocation": [
            "#1"
          ],
          "capabilityDelegation": [
            "#0"
          ]
        }
        """;


    //The root (versionId 0) document from the same worked example. A root document is self-authorizing and
    //carries no proofs.
    private const string RootSelfHash = "uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w";

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
          ],
          "keyAgreement": [
            "#0"
          ],
          "capabilityInvocation": [
            "#0"
          ],
          "capabilityDelegation": [
            "#0"
          ]
        }
        """;


    /// <summary>Verifies all proofs of a JCS document, supplying the BLAKE3 self-hash algorithm of the worked example, and returns the rejection reason (or <see langword="null"/> when all proofs verify).</summary>
    private async ValueTask<string?> VerifyAsync(string document, string selfHash)
    {
        byte[] jcs = Jcs.CanonicalizeToUtf8Bytes(document);

        WebPlusProofVerificationResult result = await WebPlusProofs.VerifyAllAsync(
            jcs,
            selfHash,
            MultihashHeaders.Blake3.ToArray(),
            Blake3DigestLength,
            ProofExtractor,
            Base64UrlDecoder,
            Base64UrlEncoder,
            Base58Decoder,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return result.Error;
    }


    /// <summary>The cancellation token source for the test.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The specification's non-root document proof verifies: its detached Ed25519 b64:false JWS reproduces over the reconstructed signing input under the kid MBPubKey.</summary>
    [TestMethod]
    public async Task VerifiesSpecificationNonRootDocumentProof()
    {
        string? error = await VerifyAsync(NonRootDidDocument, NonRootSelfHash).ConfigureAwait(false);

        Assert.IsNull(error, $"A faithfully minted did:webplus proof MUST verify. Error: {error}.");
    }


    /// <summary>A root document carries no proofs; proof verification trivially succeeds (the genesis authorization is a separate, microledger-level rule).</summary>
    [TestMethod]
    public async Task RootDocumentWithoutProofsSucceeds()
    {
        string? error = await VerifyAsync(RootDidDocument, RootSelfHash).ConfigureAwait(false);

        Assert.IsNull(error, $"A root document carries no proofs and MUST pass proof verification. Error: {error}.");
    }


    /// <summary>A single-bit tamper of the signed document content changes the signing input, so the proof no longer verifies (WP-VAL-6).</summary>
    [TestMethod]
    public async Task RejectsTamperedDocument()
    {
        //Change a verification method public key (not the selfHash, not the proof) so the reconstructed signing
        //input differs from the one the proof signed.
        string tampered = NonRootDidDocument.Replace(
            "g2AYHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg",
            "AAAAHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg",
            StringComparison.Ordinal);

        string? error = await VerifyAsync(tampered, NonRootSelfHash).ConfigureAwait(false);

        Assert.IsNotNull(error, "A document tampered after signing MUST fail proof verification.");
    }


    /// <summary>A tampered proof signature does not verify (WP-VAL-6).</summary>
    [TestMethod]
    public async Task RejectsTamperedProofSignature()
    {
        //Flip the last base64url character of the proof's signature segment.
        char lastCharacter = Proof[^1];
        string tamperedProof = Proof[..^1] + (lastCharacter == 'A' ? 'B' : 'A');
        string tampered = NonRootDidDocument.Replace(Proof, tamperedProof, StringComparison.Ordinal);

        string? error = await VerifyAsync(tampered, NonRootSelfHash).ConfigureAwait(false);

        Assert.IsNotNull(error, "A tampered proof signature MUST fail verification.");
    }
}
