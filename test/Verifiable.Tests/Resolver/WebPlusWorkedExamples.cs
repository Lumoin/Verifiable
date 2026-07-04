using System;
using System.Text;
using Verifiable.Json;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// The did:webplus specification's "Creating and Updating a DID" worked examples, minted by the independent
/// LedgerDomain Rust reference implementation, used as the firewalled oracle for the resolver and microledger
/// tests. Example 1 is a two-document history authorized by a <c>key</c> update rule; example 2 is a
/// three-document history whose root is a <c>hashedKey</c> pre-rotation commitment, whose versionId-1 rotates to
/// a <c>key</c> rule, and whose versionId-2 deactivates the DID with an empty <c>updateRules</c>.
/// </summary>
internal static class WebPlusWorkedExamples
{
    /// <summary>The DID of the first worked example (a path-bearing did:webplus DID).</summary>
    public const string Example1Did = "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w";

    /// <summary>The DID of the second (pre-rotation + deactivation) worked example.</summary>
    public const string Example2Did = "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ";

    /// <summary>The selfHash of example 1's root (versionId-0) document.</summary>
    public const string Example1RootSelfHash = "uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w";


    /// <summary>Example 1's root (versionId-0) DID document.</summary>
    public const string Example1Root =
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

    /// <summary>Example 1's versionId-1 (non-root) DID document, authorized by the root's <c>key</c> rule.</summary>
    public const string Example1NonRoot =
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

    /// <summary>Example 2's root (versionId-0) document, whose <c>updateRules</c> is a <c>hashedKey</c> pre-rotation commitment.</summary>
    public const string Example2Root =
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

    /// <summary>Example 2's versionId-1 document, authorized by the root's <c>hashedKey</c> pre-rotation rule.</summary>
    public const string Example2V1 =
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

    /// <summary>Example 2's versionId-2 document, which deactivates the DID by setting <c>updateRules</c> to <c>{}</c>.</summary>
    public const string Example2V2Deactivation =
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


    /// <summary>
    /// Builds a <c>did-documents.jsonl</c> body from the given DID documents: each is JCS-canonicalized to its
    /// single-line wire form and the lines are newline-joined, exactly as a VDR serves the microledger
    /// (did:webplus Draft v0.4: a newline-delimited concatenation of the ordered, JCS-serialized DID documents).
    /// </summary>
    /// <param name="documents">The ordered DID documents, from the root forward.</param>
    /// <returns>The microledger body.</returns>
    public static string ToMicroledger(params string[] documents)
    {
        var builder = new StringBuilder();
        for(int i = 0; i < documents.Length; i++)
        {
            if(i > 0)
            {
                builder.Append('\n');
            }

            builder.Append(Encoding.UTF8.GetString(Jcs.CanonicalizeToUtf8Bytes(documents[i])));
        }

        return builder.ToString();
    }
}
