using CsCheck;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Property-based tests (CsCheck) for <see cref="NoneAttestation"/>, the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">WebAuthn L3 section 8.7</see> "none"
/// attestation statement format: the invariant that every byte sequence other than the single canonical CTAP2
/// empty-map encoding is rejected, for every input in the class, not just the hand-picked vectors in
/// <see cref="NoneAttestationTests"/>.
/// </summary>
[TestClass]
internal sealed class NoneAttestationPropertyTests
{
    /// <summary>
    /// Property: for every byte sequence other than the single canonical <c>0xA0</c> byte, verification rejects
    /// with <see cref="Fido2AttestationErrors.StatementNotEmpty"/> and never anything else — mutations near the
    /// valid encoding (extra bytes, alternative map encodings, empty input) all fail closed the same way.
    /// </summary>
    [TestMethod]
    public void AnyStatementOtherThanCanonicalEmptyMapIsRejectedWithStatementNotEmpty() =>
        Gen.Byte.Array[0, 8]
            .Where(bytes => bytes.Length != 1 || bytes[0] != NoneAttestationTests.CanonicalEmptyMap)
            .Sample(bytes =>
            {
                Fido2AttestationError? error = NoneAttestationTests.VerifyAndGetRejectionErrorAsync(bytes).GetAwaiter().GetResult();

                return error is not null && error.Code == Fido2AttestationErrors.StatementNotEmpty.Code;
            });
}
