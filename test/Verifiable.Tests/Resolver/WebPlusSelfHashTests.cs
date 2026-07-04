using System;
using Org.BouncyCastle.Crypto.Digests;
using Verifiable.BouncyCastle;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebPlusSelfHash.Verify"/> — the did:webplus self-hash. Anchored on the root DID document
/// from the specification's "Creating and Updating a DID" worked example (LedgerDomain Draft v0.4), whose
/// <c>selfHash</c> was minted by the independent Rust reference implementation. BLAKE3 is supplied here from
/// BouncyCastle as an independent oracle (firewall): the verifier reconstructs the hash from the document's JCS
/// bytes only.
/// </summary>
[TestClass]
internal sealed class WebPlusSelfHashTests
{
    private const int Blake3DigestLength = 32;

    private static EncodeDelegate Base64UrlEncoder => TestSetup.Base64UrlEncoder;

    //The root DID document from the worked example (shown 'pretty'; JCS-canonicalized below to the bytes that
    //were hashed). Its selfHash, and every fully-qualified key id, carry the root self-hash value.
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


    //The next DID document (versionId 1) from the same worked example. Its selfHash (uHiCB0z…) differs from the
    //root self-hash (uHiCa77…), which appears here only in the unchanged id, prevDIDDocumentSelfHash and VM
    //controller — exercising that only the current self-hash value is replaced. It also carries a proofs array,
    //which the self-hash commits to.
    private const string NonRootSelfHash = "uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q";

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


    //BLAKE3-256 via BouncyCastle, exposed as the span-based HashFunctionDelegate the primitive consumes.
    private static int Blake3_256(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        var digest = new Blake3Digest();
        digest.BlockUpdate(source);
        return digest.DoFinal(destination);
    }


    /// <summary>Sanity-check the independent BLAKE3 oracle against the published empty-input known-answer vector.</summary>
    [TestMethod]
    public void Blake3OracleMatchesKnownAnswerVector()
    {
        Span<byte> digest = stackalloc byte[Blake3DigestLength];
        int written = Blake3_256(ReadOnlySpan<byte>.Empty, digest);

        Assert.AreEqual(Blake3DigestLength, written);
        Assert.AreEqual(
            "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262",
            Convert.ToHexString(digest));
    }


    /// <summary>The specification's root DID document self-hash verifies against its JCS bytes.</summary>
    [TestMethod]
    public async Task VerifiesSpecificationRootDocumentSelfHash()
    {
        byte[] jcs = Jcs.CanonicalizeToUtf8Bytes(RootDidDocument);

        bool valid = await WebPlusSelfHash.VerifyAsync(
            jcs, RootSelfHash.AsMemory(), MultihashHeaders.Blake3.ToArray(), Blake3DigestLength, BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync, CryptoTags.Blake3Digest, Base64UrlEncoder, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.IsTrue(valid, "The root DID document's selfHash must reproduce from its JCS bytes.");
    }


    /// <summary>
    /// The specification's non-root (versionId 1) DID document self-hash verifies: only the current self-hash
    /// value is substituted, while the root self-hash in id/prevDIDDocumentSelfHash/controller and the proofs are
    /// committed to unchanged.
    /// </summary>
    [TestMethod]
    public async Task VerifiesSpecificationNonRootDocumentSelfHash()
    {
        byte[] jcs = Jcs.CanonicalizeToUtf8Bytes(NonRootDidDocument);

        bool valid = await WebPlusSelfHash.VerifyAsync(
            jcs, NonRootSelfHash.AsMemory(), MultihashHeaders.Blake3.ToArray(), Blake3DigestLength, BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync, CryptoTags.Blake3Digest, Base64UrlEncoder, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.IsTrue(valid, "The non-root DID document's selfHash must reproduce from its JCS bytes.");
    }


    /// <summary>A single-bit tamper of the document content fails self-hash verification.</summary>
    [TestMethod]
    public async Task RejectsTamperedDocument()
    {
        //Change the public key's x coordinate; the selfHash no longer commits to the altered content.
        string tampered = RootDidDocument.Replace(
            "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ",
            "AAAAV0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ",
            StringComparison.Ordinal);

        byte[] jcs = Jcs.CanonicalizeToUtf8Bytes(tampered);

        bool valid = await WebPlusSelfHash.VerifyAsync(
            jcs, RootSelfHash.AsMemory(), MultihashHeaders.Blake3.ToArray(), Blake3DigestLength, BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync, CryptoTags.Blake3Digest, Base64UrlEncoder, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.IsFalse(valid, "A tampered document must not verify against the original selfHash.");
    }
}
