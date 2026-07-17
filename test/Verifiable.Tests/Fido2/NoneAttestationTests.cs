using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="NoneAttestation"/>, the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">WebAuthn L3 section 8.7</see> "none"
/// attestation statement format: the statement is the canonical empty CBOR map, single byte <c>0xA0</c> per
/// the <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4</see> CTAP2
/// canonical CBOR encoding form requirement — no other encoding of an empty map, and nothing else, is accepted.
/// </summary>
[TestClass]
internal sealed class NoneAttestationTests
{
    /// <summary>The canonical CTAP2 CBOR encoding of an empty map, the only <c>attStmt</c> the format accepts.</summary>
    internal const byte CanonicalEmptyMap = 0xA0;

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The single canonical empty-map byte verifies to <see cref="NoneAttestationResult"/> per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">section 8.7</see>.
    /// </summary>
    [TestMethod]
    public async Task CanonicalEmptyMapReturnsNoneAttestationResult()
    {
        AttestationVerifyDelegate verify = NoneAttestation.Build();
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), null, out byte[] authDataBytes);

        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authenticatorDataBytes: authDataBytes,
            authenticatorData: authenticatorData,
            clientDataHash: clientDataHash,
            attestationStatement: new byte[] { CanonicalEmptyMap },
            trustAnchors: Array.Empty<PkiCertificateMemory>(),
            validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<NoneAttestationResult>(result);
    }


    /// <summary>An empty <c>attStmt</c> (zero bytes) is not the canonical empty map and is rejected.</summary>
    [TestMethod]
    public async Task EmptyStatementIsRejectedWithStatementNotEmpty()
    {
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync([]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.StatementNotEmpty.Code, error.Code);
    }


    /// <summary>A non-empty CBOR map (one key/value pair) is rejected — the format permits only an empty map.</summary>
    [TestMethod]
    public async Task NonEmptyMapIsRejectedWithStatementNotEmpty()
    {
        //CBOR map with one text-key/uint-value pair: A1 61 61 01 ("a": 1).
        byte[] nonEmptyMap = [0xA1, 0x61, 0x61, 0x01];

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(nonEmptyMap);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.StatementNotEmpty.Code, error.Code);
    }


    /// <summary>
    /// A trailing byte after an otherwise-canonical empty map is rejected: the statement must be exactly the
    /// single <c>0xA0</c> byte, not a valid-prefix-plus-garbage encoding.
    /// </summary>
    [TestMethod]
    public async Task TrailingByteAfterCanonicalEmptyMapIsRejectedWithStatementNotEmpty()
    {
        byte[] trailingByte = [CanonicalEmptyMap, 0x00];

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(trailingByte);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.StatementNotEmpty.Code, error.Code);
    }


    /// <summary>
    /// Demonstrates consuming an <see cref="AttestationResult"/> through an exhaustive switch expression over
    /// its closed set of sibling records, classifying both a successful and a rejected outcome.
    /// </summary>
    [TestMethod]
    public async Task ConsumingResultViaExhaustiveSwitchClassifiesEachOutcome()
    {
        AttestationVerifyDelegate verify = NoneAttestation.Build();
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([9, 9, 9], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), null, out byte[] authDataBytes);

        AttestationResult noneResult = await verify(
            Fido2AttestationTestVectors.CreateRequest(authDataBytes, authenticatorData, clientDataHash, new byte[] { CanonicalEmptyMap }, Array.Empty<PkiCertificateMemory>(), TestClock.CanonicalEpoch),
            TestContext.CancellationToken);
        AttestationResult rejectedResult = await verify(
            Fido2AttestationTestVectors.CreateRequest(authDataBytes, authenticatorData, clientDataHash, Array.Empty<byte>(), Array.Empty<PkiCertificateMemory>(), TestClock.CanonicalEpoch),
            TestContext.CancellationToken);

        Assert.AreEqual("none", Classify(noneResult));
        Assert.AreEqual($"rejected:{Fido2AttestationErrors.StatementNotEmpty.Code}", Classify(rejectedResult));

        //Exhaustive over the closed AttestationResult sum; the discard arm can never be reached from this
        //assembly (all sibling records are sealed and the base constructor is private protected) but is kept
        //per the codebase's switch-expression convention of mapping with a final throw rather than proving
        //completeness structurally.
        static string Classify(AttestationResult result) => result switch
        {
            NoneAttestationResult => "none",
            SelfAttestationResult => "self",
            CertifiedAttestationResult certified => $"certified:{certified.Type}",
            RejectedAttestationResult rejected => $"rejected:{rejected.Error.Code}",
            _ => throw new NotSupportedException($"Unknown attestation result type '{result.GetType().Name}'.")
        };
    }


    /// <summary>
    /// Runs <see cref="NoneAttestation.Build"/> against a request carrying <paramref name="attestationStatement"/>
    /// and returns the rejection error, or <see langword="null"/> when verification did not reject.
    /// </summary>
    /// <param name="attestationStatement">The raw <c>attStmt</c> bytes to verify.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    internal static async Task<Fido2AttestationError?> VerifyAndGetRejectionErrorAsync(byte[] attestationStatement)
    {
        AttestationVerifyDelegate verify = NoneAttestation.Build();
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([4, 5, 6], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), null, out byte[] authDataBytes);

        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authenticatorDataBytes: authDataBytes,
            authenticatorData: authenticatorData,
            clientDataHash: clientDataHash,
            attestationStatement: attestationStatement,
            trustAnchors: Array.Empty<PkiCertificateMemory>(),
            validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, CancellationToken.None);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }
}
