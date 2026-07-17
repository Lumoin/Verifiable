using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Firewalled end-to-end hardening battery for <see cref="Fido2AssertionVerifier"/>: exercises the
/// WebAuthn L3 <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">section 7.2</see>
/// assertion-signature check together with the verifier-level ceremony rules, through the real
/// <see cref="Fido2AssertionVerifier.VerifyAsync(CoseKey, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, AssertionCeremonyInput, string, MemoryPool{byte}, TimeProvider?, CancellationToken)"/>
/// entry point, complementing <see cref="Fido2AssertionVerifierTests"/>'s algorithm-matrix and
/// single-axis coverage with adversarial wire-tampering and multi-signal scenarios.
/// </summary>
/// <remarks>
/// <para>
/// Every test reconstructs the ceremony input from wire bytes <see cref="Fido2AssertionOracle"/>
/// mints — parsing <c>clientDataJSON</c> via <see cref="ClientDataJsonReader"/> and <c>authData</c>
/// via <see cref="AuthenticatorDataReader"/> — and hands the verifier only the stored credential
/// <see cref="CoseKey"/> plus wire bytes, never the oracle's private key or any other in-memory
/// object, mirroring the issuer/holder/verifier firewall <see cref="Fido2AssertionVerifierTests"/>
/// already establishes.
/// </para>
/// <para>
/// <c>credential.id</c> and <c>response.userHandle</c> are top-level fields of a real
/// <c>AuthenticatorAssertionResponse</c>, carried alongside — not inside — <c>authData</c> or
/// <c>clientDataJSON</c>. <see cref="Fido2AssertionOracle"/> mints no such fields, so the allowlist
/// and user-handle tests below supply them directly on the reconstructed
/// <see cref="AssertionCeremonyInput"/>, exactly as <see cref="Fido2AssertionRulesTests"/> and
/// <see cref="Fido2UserHandleRuleTests"/> do at the rule level — only here the signature check runs
/// alongside them, end to end.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Fido2AssertionHardeningTests
{
    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The credential identifier asserted in the allowlist tests, distinct from <see cref="OtherAllowedCredentialId"/>.</summary>
    private static byte[] AssertedCredentialId { get; } = [0x10, 0x11, 0x12, 0x13];

    /// <summary>A credential identifier distinct from <see cref="AssertedCredentialId"/>, standing in for an allowlist entry that does not match.</summary>
    private static byte[] OtherAllowedCredentialId { get; } = [0x20, 0x21, 0x22, 0x23];

    /// <summary>The user handle a matching <c>response.userHandle</c> / stored user account pair shares by default.</summary>
    private static byte[] DefaultUserHandle { get; } = [0x55, 0x66, 0x77, 0x88];

    /// <summary>A user handle distinct from <see cref="DefaultUserHandle"/>, for the mismatch axis.</summary>
    private static byte[] OtherUserHandle { get; } = [0x99, 0x9A, 0x9B, 0x9C];

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Inserting a single space into <c>clientDataJSON</c> between a member's <c>:</c> and its value
    /// — a change no JSON parser treats as semantically significant — still invalidates the
    /// assertion signature: the signature covers the raw <c>clientDataJSON</c> bytes hashed as-is,
    /// never a re-serialization of the parsed members.
    /// </summary>
    [TestMethod]
    public async Task InsertedWhitespaceInClientDataJsonFailsSignatureDespiteIdenticalParsedMembers()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        byte[] tamperedClientDataJson = InsertSpaceAfterFirstColon(minted.ClientDataJson);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            oracle.CredentialPublicKey,
            minted.Signature.AsReadOnlySpan().ToArray(),
            minted.AuthenticatorData,
            tamperedClientDataJson);

        Assert.IsFalse(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);

        static byte[] InsertSpaceAfterFirstColon(byte[] clientDataJson)
        {
            int colonIndex = Array.IndexOf(clientDataJson, (byte)':');
            byte[] tampered = new byte[clientDataJson.Length + 1];
            Array.Copy(clientDataJson, 0, tampered, 0, colonIndex + 1);
            tampered[colonIndex + 1] = (byte)' ';
            Array.Copy(clientDataJson, colonIndex + 1, tampered, colonIndex + 2, clientDataJson.Length - colonIndex - 1);

            return tampered;
        }
    }


    /// <summary>
    /// An ES256 wire signature left in fixed-width IEEE P1363 form — skipping the ASN.1 DER
    /// re-encode WebAuthn L3 section 6.5.5 requires — fails verification: the verifier treats
    /// every EC wire signature as DER and the raw P1363 bytes do not parse as a well-formed
    /// <c>Ecdsa-Sig-Value</c>.
    /// </summary>
    [TestMethod]
    public async Task Es256WireSignatureLeftAsP1363InsteadOfDerFailsSignature()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        using IMemoryOwner<byte> p1363Owner = EcdsaSignatureEncoding.ConvertDerToP1363(
            minted.Signature.AsReadOnlySpan(), EllipticCurveConstants.P256.PointArrayLength, BaseMemoryPool.Shared, out int p1363Length);
        byte[] p1363Signature = p1363Owner.Memory.Span[..p1363Length].ToArray();

        Fido2AssertionOutcome outcome = await VerifyAsync(oracle.CredentialPublicKey, p1363Signature, minted.AuthenticatorData, minted.ClientDataJson);

        Assert.IsFalse(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
    }


    /// <summary>
    /// An EdDSA wire signature wrapped in an ASN.1 DER <c>SEQUENCE</c> — the encoding WebAuthn L3
    /// section 6.5.5 reserves for ECDSA — fails verification: <see cref="Fido2EcdsaWireSignature"/>
    /// passes a non-ECDSA algorithm's wire bytes through unchanged, so the DER wrapper reaches the
    /// Ed25519 primitive as if it were the raw 64-byte signature, and it is not.
    /// </summary>
    [TestMethod]
    public async Task EdDsaWireSignatureWrappedInDerFailsSignature()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEdDsa();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        using IMemoryOwner<byte> derOwner = EcdsaSignatureEncoding.ConvertP1363ToDer(minted.Signature.AsReadOnlySpan(), BaseMemoryPool.Shared, out int derLength);
        byte[] derWrappedSignature = derOwner.Memory.Span[..derLength].ToArray();

        Fido2AssertionOutcome outcome = await VerifyAsync(oracle.CredentialPublicKey, derWrappedSignature, minted.AuthenticatorData, minted.ClientDataJson);

        Assert.IsFalse(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
    }


    /// <summary>
    /// An allowlist that does not contain the asserted credential identifier fails
    /// <see cref="Fido2ClaimIds.Fido2AssertionAllowedCredentials"/> end to end, while the assertion
    /// signature — unaffected by the relying party's allowlist policy — remains valid.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the ceremony input, which the verifier helper's using declaration disposes.")]
    public async Task AllowlistNotContainingAssertedCredentialFailsAllowedCredentialsClaimWithSignatureStillValid()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            oracle.CredentialPublicKey,
            minted.Signature.AsReadOnlySpan().ToArray(),
            minted.AuthenticatorData,
            minted.ClientDataJson,
            allowedCredentialIds: [CredentialId.Create(OtherAllowedCredentialId, BaseMemoryPool.Shared)],
            credentialId: CredentialId.Create(AssertedCredentialId, BaseMemoryPool.Shared));

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionAllowedCredentials));
    }


    /// <summary>An allowlist that contains the asserted credential identifier is acceptable end to end.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the ceremony input, which the verifier helper's using declaration disposes.")]
    public async Task AllowlistContainingAssertedCredentialIsAcceptable()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            oracle.CredentialPublicKey,
            minted.Signature.AsReadOnlySpan().ToArray(),
            minted.AuthenticatorData,
            minted.ClientDataJson,
            allowedCredentialIds: [CredentialId.Create(AssertedCredentialId, BaseMemoryPool.Shared)],
            credentialId: CredentialId.Create(AssertedCredentialId, BaseMemoryPool.Shared));

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
    }


    /// <summary>
    /// A relying party that requires user verification, against a minted assertion with the
    /// <c>UV</c> bit clear, fails <see cref="Fido2ClaimIds.Fido2AssertionUserVerified"/> end to end.
    /// </summary>
    [TestMethod]
    public async Task RequiredUserVerificationClearFailsUserVerifiedClaim()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(
            ValidChallenge, ValidOrigin, userVerified: false, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            oracle.CredentialPublicKey,
            minted.Signature.AsReadOnlySpan().ToArray(),
            minted.AuthenticatorData,
            minted.ClientDataJson,
            userVerification: UserVerificationRequirement.Required);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionUserVerified));
    }


    /// <summary>
    /// A stored backup eligibility that contradicts the minted <c>BE</c> bit fails
    /// <see cref="Fido2ClaimIds.Fido2AssertionBackupStateConsistency"/> end to end.
    /// </summary>
    [TestMethod]
    public async Task StoredBackupEligibleContradictingMintedFlagFailsBackupStateConsistencyClaim()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(
            ValidChallenge, ValidOrigin, backupEligible: false, backupState: false, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            oracle.CredentialPublicKey,
            minted.Signature.AsReadOnlySpan().ToArray(),
            minted.AuthenticatorData,
            minted.ClientDataJson,
            storedBackupEligible: true);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionBackupStateConsistency));
    }


    /// <summary>
    /// A tracked backup state that differs from the minted <c>BS</c> bit — with backup eligibility
    /// consistent — yields <see cref="ClaimOutcome.Inconclusive"/> for
    /// <see cref="Fido2ClaimIds.Fido2AssertionBackupStateConsistency"/> and the overall outcome
    /// stays acceptable: the specification leaves the response to relying party policy rather than
    /// mandating success or failure.
    /// </summary>
    [TestMethod]
    public async Task TrackedBackupStateChangedFromMintedFlagYieldsInconclusiveButStaysAcceptable()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(
            ValidChallenge, ValidOrigin, backupEligible: true, backupState: true, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            oracle.CredentialPublicKey,
            minted.Signature.AsReadOnlySpan().ToArray(),
            minted.AuthenticatorData,
            minted.ClientDataJson,
            storedBackupEligible: true,
            storedBackupState: false);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Inconclusive, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionBackupStateConsistency));
    }


    /// <summary>
    /// A discoverable-credential assertion (no allowlist) with no <c>response.userHandle</c> fails
    /// <see cref="Fido2ClaimIds.Fido2AssertionUserHandle"/> end to end, while the signature remains
    /// valid.
    /// </summary>
    [TestMethod]
    public async Task DiscoverablePathWithoutUserHandleFailsUserHandleClaimWithSignatureStillValid()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            oracle.CredentialPublicKey,
            minted.Signature.AsReadOnlySpan().ToArray(),
            minted.AuthenticatorData,
            minted.ClientDataJson,
            omitResponseUserHandle: true);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionUserHandle));
    }


    /// <summary>A <c>response.userHandle</c> that does not match the stored user handle fails <see cref="Fido2ClaimIds.Fido2AssertionUserHandle"/> end to end.</summary>
    [TestMethod]
    public async Task MismatchedUserHandleFailsUserHandleClaimWithSignatureStillValid()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            oracle.CredentialPublicKey,
            minted.Signature.AsReadOnlySpan().ToArray(),
            minted.AuthenticatorData,
            minted.ClientDataJson,
            storedUserHandleBytes: OtherUserHandle);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionUserHandle));
    }


    /// <summary>A <c>response.userHandle</c> matching the stored user handle is acceptable end to end.</summary>
    [TestMethod]
    public async Task MatchingUserHandleIsAcceptable()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            oracle.CredentialPublicKey,
            minted.Signature.AsReadOnlySpan().ToArray(),
            minted.AuthenticatorData,
            minted.ClientDataJson);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Success, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionUserHandle));
    }


    /// <summary>
    /// Reconstructs an <see cref="AssertionCeremonyInput"/> from wire bytes and the caller-supplied
    /// verifier-level fields — <c>credential.id</c>, <c>allowCredentials</c>, and
    /// <c>response.userHandle</c> are top-level assertion-response fields no minted wire slice
    /// carries, so every axis is supplied directly here, never derived from
    /// <see cref="Fido2AssertionOracle"/>'s output — and runs <see cref="Fido2AssertionVerifier"/>
    /// against it.
    /// </summary>
    /// <param name="credentialPublicKey">The stored credential public key established at registration time.</param>
    /// <param name="signature">The wire signature bytes to verify, possibly tampered by the caller.</param>
    /// <param name="authenticatorDataBytes">The wire <c>authData</c> bytes.</param>
    /// <param name="clientDataJsonBytes">The wire <c>clientDataJSON</c> bytes.</param>
    /// <param name="userVerification">The relying party's user-verification policy. Defaults to <see cref="UserVerificationRequirement.Required"/>.</param>
    /// <param name="allowedCredentialIds">The relying party's <c>allowCredentials</c> allowlist. Defaults to <see langword="null"/> — the discoverable-credential path.</param>
    /// <param name="credentialId">The asserted credential identifier. Defaults to <see langword="null"/>.</param>
    /// <param name="storedBackupEligible">The stored credential record's backup eligibility. Defaults to <see langword="null"/> — not tracked.</param>
    /// <param name="storedBackupState">The stored credential record's backup state. Defaults to <see langword="null"/> — not tracked.</param>
    /// <param name="responseUserHandleBytes">The wire-reported <c>response.userHandle</c> bytes. Defaults to <see cref="DefaultUserHandle"/>.</param>
    /// <param name="omitResponseUserHandle">Forces <see cref="AssertionCeremonyInput.ResponseUserHandle"/> to <see langword="null"/> regardless of <paramref name="responseUserHandleBytes"/>.</param>
    /// <param name="storedUserHandleBytes">The relying party's stored user handle. Defaults to <see cref="DefaultUserHandle"/> — matching <paramref name="responseUserHandleBytes"/>'s default.</param>
    /// <param name="omitStoredUserHandle">Forces <see cref="AssertionCeremonyInput.StoredUserHandle"/> to <see langword="null"/> regardless of <paramref name="storedUserHandleBytes"/>.</param>
    /// <returns>The combined signature and ceremony-rule outcome.</returns>
    private async Task<Fido2AssertionOutcome> VerifyAsync(
        CoseKey credentialPublicKey,
        byte[] signature,
        byte[] authenticatorDataBytes,
        byte[] clientDataJsonBytes,
        UserVerificationRequirement userVerification = UserVerificationRequirement.Required,
        IReadOnlyList<CredentialId>? allowedCredentialIds = null,
        CredentialId? credentialId = null,
        bool? storedBackupEligible = null,
        bool? storedBackupState = null,
        byte[]? responseUserHandleBytes = null,
        bool omitResponseUserHandle = false,
        byte[]? storedUserHandleBytes = null,
        bool omitStoredUserHandle = false)
    {
        ClientData clientData = ClientDataJsonReader.Read(clientDataJsonBytes);
        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(authenticatorDataBytes, Fido2TestVectors.TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        UserHandle? responseUserHandle = omitResponseUserHandle
            ? null
            : UserHandle.Create(responseUserHandleBytes ?? DefaultUserHandle, BaseMemoryPool.Shared);
        UserHandle? storedUserHandle = omitStoredUserHandle
            ? null
            : UserHandle.Create(storedUserHandleBytes ?? DefaultUserHandle, BaseMemoryPool.Shared);

        using var ceremonyInput = new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = ValidChallenge,
            ExpectedOrigins = new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(Fido2TestVectors.CreateRpIdHash(), BaseMemoryPool.Shared),
            UserVerification = userVerification,
            AllowedCredentialIds = allowedCredentialIds,
            CredentialId = credentialId,
            StoredSignCount = 0,
            StoredUvInitialized = true,
            StoredBackupEligible = storedBackupEligible,
            StoredBackupState = storedBackupState,
            ResponseUserHandle = responseUserHandle,
            StoredUserHandle = storedUserHandle
        };

        return await Fido2AssertionVerifier.VerifyAsync(
            credentialPublicKey,
            signature,
            authenticatorDataBytes,
            clientDataJsonBytes,
            ceremonyInput,
            correlationId: "fido2-assertion-hardening-test-correlation",
            pool: BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Finds the outcome of the claim carrying <paramref name="claimId"/> in <paramref name="outcome"/>.</summary>
    private static ClaimOutcome GetClaimOutcome(Fido2AssertionOutcome outcome, ClaimId claimId)
    {
        foreach(Claim claim in outcome.Claims.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return claim.Outcome;
            }
        }

        throw new InvalidOperationException($"Claim '{claimId}' was not present in the result.");
    }
}
