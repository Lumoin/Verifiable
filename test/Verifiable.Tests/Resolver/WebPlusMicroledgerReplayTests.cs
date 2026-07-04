using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebPlusMicroledger"/> driven through the
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> — the did:webplus microledger replay that folds
/// a <c>did-documents.jsonl</c> history and decides its validity (did:webplus Draft v0.4, Validation of DID
/// Documents; WP-VAL-6/7/8). Anchored on the root and versionId-1 documents of the specification's "Creating and
/// Updating a DID" worked example, minted by the independent Rust reference implementation; BLAKE3 is supplied
/// here from BouncyCastle as an independent oracle (firewall).
/// </summary>
[TestClass]
internal sealed class WebPlusMicroledgerReplayTests
{
    private const int Blake3DigestLength = 32;

    /// <summary>The cancellation-token source for the test.</summary>
    public TestContext TestContext { get; set; } = null!;


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


    //The specification's SECOND worked example: a three-document history whose root updateRules is a hashedKey
    //pre-rotation commitment (WP-UR-4), whose versionId-1 document rotates to a key rule, and whose versionId-2
    //document deactivates the DID by setting updateRules to {} (DID Deactivate).
    private const string PreRotationRootDocument =
        """
        {
          "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
          "selfHash": "uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
          "updateRules": {
            "hashedKey": "uHiCMmFumKCTx6yxWPtoRM_VZj4DvdcHs2KEBK941pr8SXQ"
          },
          "validFrom": "2025-11-19T01:43:26.979Z",
          "versionId": 0,
          "verificationMethod": [
            {
              "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ&versionId=0#0",
              "type": "JsonWebKey2020",
              "controller": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
              "publicKeyJwk": {
                "kid": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ&versionId=0#0",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "iR2bJQmYXszbiuW1yfeRmLtBkGsEczp99ZfEuQSPxwM"
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

    private const string PreRotationV1Document =
        """
        {
          "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
          "selfHash": "uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw",
          "prevDIDDocumentSelfHash": "uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
          "updateRules": {
            "key": "u7QF0zsY-DxwlvuzDsosc0ZgD5drHhvNHXVkxwDDCMZHSIQ"
          },
          "proofs": [
            "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRzJPMlZtMjJlMWc0djZWUnhqWTlRZ205WHFKQUtmX2IzY0g2T2M0UjBiaHciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..gjcKygeSmc9XC8h6Eosu1zPkjVF9_vPTI5Dm0PbNT7UZU4GvfvN1NsVEBWcXTEcCL22CW1ID5rb3SmjtsJnxBg"
          ],
          "validFrom": "2025-11-19T01:43:26.992Z",
          "versionId": 1,
          "verificationMethod": [
            {
              "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#0",
              "type": "JsonWebKey2020",
              "controller": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
              "publicKeyJwk": {
                "kid": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#0",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "I87S--BfzauBtdJ4FkYLj9-bOF8gwj6iOMIx_lE-vhM"
              }
            },
            {
              "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#1",
              "type": "JsonWebKey2020",
              "controller": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
              "publicKeyJwk": {
                "kid": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#1",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "iR2bJQmYXszbiuW1yfeRmLtBkGsEczp99ZfEuQSPxwM"
              }
            }
          ],
          "authentication": [
            "#0"
          ],
          "assertionMethod": [
            "#1"
          ],
          "keyAgreement": [
            "#1"
          ],
          "capabilityInvocation": [
            "#0"
          ],
          "capabilityDelegation": [
            "#1"
          ]
        }
        """;

    private const string PreRotationV2DeactivationDocument =
        """
        {
          "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
          "selfHash": "uHiCrJkmyeDz01JHbmu-ft17Gwx11Les974G0BIV9fGWoDQ",
          "prevDIDDocumentSelfHash": "uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw",
          "updateRules": {},
          "proofs": [
            "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRjB6c1ktRHh3bHZ1ekRzb3NjMFpnRDVkckhodk5IWFZreHdERENNWkhTSVEiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..qBBCb1-4OHtnfyV_0KrUBpDE0aXhjBkYmCT5h7A0vtYtCGBVhfjUIRCrj3rJeO5h3N627uSdFcj2308Iaf6fAA"
          ],
          "validFrom": "2025-11-19T01:43:27.032Z",
          "versionId": 2,
          "verificationMethod": [],
          "authentication": [],
          "assertionMethod": [],
          "keyAgreement": [],
          "capabilityInvocation": [],
          "capabilityDelegation": []
        }
        """;


    private static WebPlusValidationContext Context()
    {
        return new WebPlusValidationContext
        {
            Parser = WebPlusDidDocumentJson.Parser,
            Canonicalizer = WebPlusDidDocumentJson.Canonicalizer,
            ProofExtractor = WebPlusDidDocumentJson.ProofExtractor,
            ComputeDigest = BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync,
            DigestTag = CryptoTags.Blake3Digest,
            MultihashCode = MultihashHeaders.Blake3.ToArray(),
            DigestLength = Blake3DigestLength,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            Base64UrlDecoder = TestSetup.Base64UrlDecoder,
            Base58Decoder = TestSetup.Base58Decoder,
            HashedKeyMatcher = WebPlusHashedKey.CreateMatcher(
                MultihashHeaders.Blake3.ToArray(), Blake3DigestLength, BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync, CryptoTags.Blake3Digest, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            MemoryPool = BaseMemoryPool.Shared,
            TimeProvider = TimeProvider.System
        };
    }


    //Builds a microledger entry from a DID document line, exactly as the resolver would: JCS-canonicalize, parse
    //the document and its updateRules, extract its proofs, and chain it by selfHash / prevDIDDocumentSelfHash.
    private static LogEntry<WebPlusRawEntry, string> BuildEntry(string documentJson, ulong index)
    {
        byte[] jcs = Jcs.CanonicalizeToUtf8Bytes(documentJson);
        WebPlusDidDocument document = WebPlusDidDocumentJson.Parser(jcs);
        WebPlusUpdateRule updateRules = WebPlusUpdateRulesJson.Parser(jcs);
        WebPlusProofExtraction extraction = WebPlusDidDocumentJson.ProofExtractor(jcs);

        ReadOnlyMemory<byte>? previousDigest = document.PrevDidDocumentSelfHash is { Length: > 0 } previous
            ? Encoding.UTF8.GetBytes(previous)
            : null;

        return new LogEntry<WebPlusRawEntry, string>
        {
            Index = index,
            PreviousDigest = previousDigest,
            Digest = Encoding.UTF8.GetBytes(document.SelfHash!),
            CanonicalBytes = jcs,
            Operation = new WebPlusRawEntry(document, updateRules),
            Proofs = extraction.Proofs
        };
    }


    private async Task<List<LogReplayResult<WebPlusState, WebPlusRawEntry, string>>> ReplayAsync(params LogEntry<WebPlusRawEntry, string>[] entries)
    {
        WebPlusValidationContext context = Context();
        var replayContext = new LogReplayContext<WebPlusState, WebPlusRawEntry, string, WebPlusValidationContext>
        {
            Classify = WebPlusMicroledger.ClassifyEntry,
            VerifyChainIntegrity = WebPlusMicroledger.CreateChainVerification(context),
            ValidateProof = WebPlusMicroledger.ValidateProofAsync,
            ValidationContext = context,
            Apply = WebPlusMicroledger.ApplyEntry,
            TimeProvider = TimeProvider.System
        };

        var replayer = new LogReplayer<WebPlusState, WebPlusRawEntry, string, WebPlusValidationContext>();
        var results = new List<LogReplayResult<WebPlusState, WebPlusRawEntry, string>>();
        await foreach(LogReplayResult<WebPlusState, WebPlusRawEntry, string> result in
            replayer.ReplayAsync(ToAsync(entries, TestContext.CancellationToken), replayContext, TestContext.CancellationToken).ConfigureAwait(false))
        {
            results.Add(result);
        }

        return results;
    }


    private static async IAsyncEnumerable<LogEntry<WebPlusRawEntry, string>> ToAsync(
        LogEntry<WebPlusRawEntry, string>[] entries,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach(LogEntry<WebPlusRawEntry, string> entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;

            await Task.CompletedTask.ConfigureAwait(false);
        }
    }


    /// <summary>The specification's two-document history replays clean: both entries verify and the final state is the active versionId-1 document.</summary>
    [TestMethod]
    public async Task ReplaysSpecificationHistory()
    {
        List<LogReplayResult<WebPlusState, WebPlusRawEntry, string>> results =
            await ReplayAsync(BuildEntry(RootDidDocument, 0), BuildEntry(NonRootDidDocument, 1)).ConfigureAwait(false);

        Assert.HasCount(2, results);
        Assert.IsNull(results[0].Error, $"The root entry MUST verify. Error: {results[0].Error}.");
        Assert.IsNull(results[1].Error, $"The versionId-1 entry MUST verify. Error: {results[1].Error}.");

        var finalState = (ActiveLogState<WebPlusState>)results[1].State;
        Assert.AreEqual(1UL, finalState.Value.VersionId);
        Assert.AreEqual("uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q", finalState.Value.SelfHash);
    }


    /// <summary>
    /// The specification's second history replays clean across all three obligations it exercises: the versionId-1
    /// proof satisfies the root's <c>hashedKey</c> pre-rotation rule (WP-UR-4/7e), the versionId-2 proof satisfies
    /// the versionId-1 <c>key</c> rule, and the versionId-2 <c>{}</c> updateRules deactivates the DID — the final
    /// state is terminal (<see cref="DeactivatedLogState{TState}"/>).
    /// </summary>
    [TestMethod]
    public async Task ReplaysHashedKeyAndDeactivationHistory()
    {
        List<LogReplayResult<WebPlusState, WebPlusRawEntry, string>> results = await ReplayAsync(
            BuildEntry(PreRotationRootDocument, 0),
            BuildEntry(PreRotationV1Document, 1),
            BuildEntry(PreRotationV2DeactivationDocument, 2)).ConfigureAwait(false);

        Assert.HasCount(3, results);
        Assert.IsNull(results[0].Error, $"The root entry MUST verify. Error: {results[0].Error}.");
        Assert.IsNull(results[1].Error, $"The hashedKey-authorized versionId-1 entry MUST verify. Error: {results[1].Error}.");
        Assert.IsNull(results[2].Error, $"The deactivation versionId-2 entry MUST verify. Error: {results[2].Error}.");

        var finalState = (DeactivatedLogState<WebPlusState>)results[2].State;
        Assert.AreEqual(2UL, finalState.Value.VersionId);
        Assert.IsInstanceOfType<DisallowUpdateRule>(finalState.Value.UpdateRules, "The deactivated document's updateRules MUST be the disallow form.");
    }


    /// <summary>A single root document replays as a valid one-entry history (the active versionId-0 state).</summary>
    [TestMethod]
    public async Task ReplaysRootOnlyHistory()
    {
        List<LogReplayResult<WebPlusState, WebPlusRawEntry, string>> results =
            await ReplayAsync(BuildEntry(RootDidDocument, 0)).ConfigureAwait(false);

        Assert.HasCount(1, results);
        Assert.IsNull(results[0].Error, $"The root entry MUST verify. Error: {results[0].Error}.");

        var state = (ActiveLogState<WebPlusState>)results[0].State;
        Assert.AreEqual(0UL, state.Value.VersionId);
    }


    /// <summary>A non-root document presented as the genesis entry is rejected: a root document MUST NOT reference a predecessor.</summary>
    [TestMethod]
    public async Task RejectsNonRootAsGenesis()
    {
        List<LogReplayResult<WebPlusState, WebPlusRawEntry, string>> results =
            await ReplayAsync(BuildEntry(NonRootDidDocument, 0)).ConfigureAwait(false);

        Assert.HasCount(1, results);
        Assert.IsNotNull(results[0].Error, "A non-root document as the genesis entry MUST be rejected.");
    }


    /// <summary>A second-entry document tampered after signing breaks the chain — its self-hash no longer verifies.</summary>
    [TestMethod]
    public async Task RejectsTamperedSecondEntry()
    {
        //Change a verification method public key in the versionId-1 document; the selfHash no longer commits to it.
        string tampered = NonRootDidDocument.Replace(
            "g2AYHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg",
            "AAAAHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg",
            StringComparison.Ordinal);

        List<LogReplayResult<WebPlusState, WebPlusRawEntry, string>> results =
            await ReplayAsync(BuildEntry(RootDidDocument, 0), BuildEntry(tampered, 1)).ConfigureAwait(false);

        Assert.IsNull(results[0].Error, "The root entry MUST still verify.");
        Assert.IsNotNull(results[1].Error, "The tampered second entry MUST be rejected, ending the verified chain.");
    }


    /// <summary>
    /// When the second entry's <c>prevDIDDocumentSelfHash</c> is altered to a value that is not the verified
    /// predecessor's selfHash, the entry is rejected (the chain link does not hold).
    /// </summary>
    [TestMethod]
    public async Task RejectsBrokenPrevDidDocumentSelfHash()
    {
        //Repoint prevDIDDocumentSelfHash at a different (well-formed) MBHash than the verified root's selfHash.
        string tampered = NonRootDidDocument.Replace(
            "\"prevDIDDocumentSelfHash\": \"uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w\"",
            "\"prevDIDDocumentSelfHash\": \"uHiCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
            StringComparison.Ordinal);

        List<LogReplayResult<WebPlusState, WebPlusRawEntry, string>> results =
            await ReplayAsync(BuildEntry(RootDidDocument, 0), BuildEntry(tampered, 1)).ConfigureAwait(false);

        Assert.IsNull(results[0].Error, "The root entry MUST still verify.");
        Assert.IsNotNull(results[1].Error, "A second entry whose prevDIDDocumentSelfHash is not the verified predecessor's selfHash MUST be rejected.");
    }
}
