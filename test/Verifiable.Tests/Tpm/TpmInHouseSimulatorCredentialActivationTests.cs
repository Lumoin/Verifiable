using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using System.Security.Cryptography;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives credential activation (<c>TPM2_MakeCredential()</c> + <c>TPM2_ActivateCredential()</c>) against the
/// in-house behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same
/// production command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="MakeCredentialInput"/> / <see cref="ActivateCredentialInput"/> and response codecs). Credential
/// activation is the challenge-response that proves an attestation key (AK) is bound to a specific credential /
/// endorsement key (EK) in the same TPM (TPM 2.0 Library Part 1, clause 21; Part 3, clauses 12.6 and 12.5).
/// </summary>
/// <remarks>
/// <para>
/// A challenger holding the EK public key wraps a secret bound to the AK's Name with <c>TPM2_MakeCredential()</c>;
/// the device recovers it with <c>TPM2_ActivateCredential()</c> only because it holds both the EK (to recover the
/// seed) and the AK (whose Name the credential's integrity is keyed to). Recovering the secret is the proof of
/// co-residence that lets an enrollment authority trust the AK. A restricted-decrypt ECC storage primary stands in
/// for the EK; the standard EK adds the well-known authorization policy (a policy session over the endorsement
/// hierarchy) but is otherwise the same mechanism.
/// </para>
/// <para>
/// The simulator runs both sides, so its credential-protection crypto is self-consistent by construction: the seed
/// is transported by a faithful ECDH exchange with the EK's public point fed to <c>KDFe</c> (Part 1, clause
/// 9.4.10.3), and the credential blob is the real AK-Name-bound outer wrap (<c>KDFa</c>-derived AES-CFB encryption
/// and an outer HMAC over the ciphertext and the AK's Name, Part 1, clause 21), all through the shipped
/// <see cref="Kdfa"/> / <see cref="Kdfe"/> and the registered digest/HMAC seams. The negative test confirms the
/// binding is to the AK's <i>Name</i>: a credential bound to one AK cannot be activated against a different object,
/// even with the same EK — the re-derivation keyed on the activate object's Name yields a different HMAC key, so the
/// integrity check fails.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCredentialActivationTests
{
    /// <summary>The secret credential wrapped and recovered by the tests (16 bytes, within the EK nameAlg digest size).</summary>
    private static byte[] CredentialSecret { get; } =
        [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF];

    /// <summary>The policy session hash algorithm used by the standard-EK (PolicyA) tests.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The activate object's (attestation key's) real password used by the authValue verification proofs.</summary>
    private const string ActivatePassword = "activate-object-auth-proof";

    /// <summary>A wrong guess at the activate object's password, distinct from <see cref="ActivatePassword"/>.</summary>
    private const string WrongActivatePassword = "wrong-activate-auth-guess";

    /// <summary>The credential key's (endorsement key's) real password used by the authValue verification proof.</summary>
    private const string CredentialKeyPassword = "credential-key-auth-proof";

    /// <summary>A wrong guess at the credential key's password, distinct from <see cref="CredentialKeyPassword"/>.</summary>
    private const string WrongCredentialKeyPassword = "wrong-credential-key-auth-guess";

    /// <summary>
    /// A transient handle value naming no loaded object in a freshly-brought-operational simulator — stands in
    /// for <c>@activateHandle</c> in tests whose refusal fires before (or independent of) the handle actually
    /// resolving.
    /// </summary>
    private const uint ArbitraryActivateHandle = 0x8000_0001;

    /// <summary>The <c>@keyHandle</c> counterpart of <see cref="ArbitraryActivateHandle"/>, distinct from it.</summary>
    private const uint ArbitraryKeyHandle = 0x8000_0002;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task MakeAndActivateCredentialRecoversTheSecret()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                //Challenger side: wrap the secret to the EK public key, bound to the AK's Name.
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);
                Assert.IsFalse(made.CredentialBlob.IsEmpty, "The credential blob must not be empty.");
                Assert.IsFalse(made.Secret.IsEmpty, "The encrypted secret must not be empty.");

                //Device side: recover the secret. The AK is the activate object (ADMIN role), the EK recovers the
                //seed (USER role); both authorized with empty-auth password sessions in handle order.
                using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(activateResult.IsSuccess, $"TPM2_ActivateCredential failed: '{activateResult.ResponseCode}'.");

                using ActivateCredentialResponse activated = activateResult.Value;
                Assert.IsTrue(
                    activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret),
                    "The recovered credential must equal the secret wrapped by TPM2_MakeCredential, proving AK and EK co-reside.");
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task ActivateWithWrongObjectIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            using CreatePrimaryResponse otherAk = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
            try
            {
                //The credential is bound to the AK's Name.
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

                //Activating against a different object (otherAk) must fail: the credential's integrity is keyed to
                //the bound AK's Name, so a mismatched activate object cannot recover the secret.
                using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                    otherAk.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(
                    activateResult.IsSuccess,
                    "A credential bound to one attestation key's Name must not be activatable against a different object.");
            }
            finally
            {
                await FlushAsync(tpm, registry, otherAk.ObjectHandle.Value, pool).ConfigureAwait(false);
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task ActivateCredentialRejectsUndersizedCredentialBlob()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                //A wire-legal but empty credentialBlob and secret (size-zero TPM2B fields) reach the effect executor
                //after the handles resolve; a too-small buffer must fail closed with TPM_RC_SIZE rather than throw an
                //out-of-range exception out of the executor, which the PDA runner does not catch (Part 3, clause 12.5).
                using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(activateResult.IsSuccess, "An undersized credentialBlob/secret must be rejected, not crash.");
                Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, activateResult.ResponseCode);
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_ActivateCredential()</c>'s <c>credentialBlob</c> (<c>TPM2B_ID_OBJECT</c>) declaring a size wider
    /// than a <c>TPMS_ID_OBJECT</c> can ever be — two <c>TPM2B_DIGEST</c> values, at most 132 octets — is
    /// refused with <c>TPM_RC_SIZE</c> even though the frame genuinely carries every declared octet
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.4.3, Table 245). The parse fails before either
    /// handle is resolved, so arbitrary handle values stand in for a real activate object and credential key.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialWithCredentialBlobOverBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitActivateCredentialCommandAsync(
            simulator, pool, ArbitraryActivateHandle, ArbitraryKeyHandle,
            declaredCredentialBlobSize: Tpm2bIdObject.MaxSize + 1, actualCredentialBlobBytesProvided: Tpm2bIdObject.MaxSize + 1,
            declaredSecretSize: 0, actualSecretBytesProvided: 0).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, code,
            "A credentialBlob declaring more than TPMS_ID_OBJECT's own bound is TPM_RC_SIZE (Table 245) even when the frame supplies every declared octet.");
    }

    /// <summary>
    /// The <c>secret</c> (<c>TPM2B_ENCRYPTED_SECRET</c>) counterpart of
    /// <see cref="ActivateCredentialWithCredentialBlobOverBoundReturnsSize"/>: a declared size past
    /// <c>TPMU_ENCRYPTED_SECRET</c>'s widest arm (an RSA-4096 modulus, 512 octets) is refused with
    /// <c>TPM_RC_SIZE</c>, again with every declared octet genuinely present
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.4.3, Table 224).
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialWithSecretOverBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitActivateCredentialCommandAsync(
            simulator, pool, ArbitraryActivateHandle, ArbitraryKeyHandle,
            declaredCredentialBlobSize: 0, actualCredentialBlobBytesProvided: 0,
            declaredSecretSize: Tpm2bEncryptedSecret.MaxSize + 1, actualSecretBytesProvided: Tpm2bEncryptedSecret.MaxSize + 1).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, code,
            "A secret declaring more than TPMU_ENCRYPTED_SECRET's own bound is TPM_RC_SIZE (Table 224) even when the frame supplies every declared octet.");
    }

    /// <summary>
    /// A <c>credentialBlob</c> that is BOTH over <see cref="Tpm2bIdObject.MaxSize"/> (declaring 200 octets) AND
    /// truncated (the frame carries only 10) is refused with <c>TPM_RC_SIZE</c>, not <c>TPM_RC_INSUFFICIENT</c>:
    /// the declared size is checked against the bound before the remaining-octets truncation probe ever runs
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.4.3, Table 245; Part 4, Marshal.c, which checks a
    /// TPM2B's own bound ahead of the array read that would otherwise report a short buffer).
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialWithOverBoundAndTruncatedCredentialBlobReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitActivateCredentialCommandAsync(
            simulator, pool, ArbitraryActivateHandle, ArbitraryKeyHandle,
            declaredCredentialBlobSize: Tpm2bIdObject.MaxSize + 68, actualCredentialBlobBytesProvided: 10,
            declaredSecretSize: 0, actualSecretBytesProvided: 0).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, code,
            "An over-bound credentialBlob is TPM_RC_SIZE even when the frame is also too short to supply it (Table 245).");
    }

    /// <summary>
    /// The <c>secret</c> counterpart of
    /// <see cref="ActivateCredentialWithOverBoundAndTruncatedCredentialBlobReturnsSize"/>: a declared size past
    /// <see cref="Tpm2bEncryptedSecret.MaxSize"/> wins over the frame's own truncation, answering
    /// <c>TPM_RC_SIZE</c> rather than <c>TPM_RC_INSUFFICIENT</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.4.3, Table 224).
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialWithOverBoundAndTruncatedSecretReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitActivateCredentialCommandAsync(
            simulator, pool, ArbitraryActivateHandle, ArbitraryKeyHandle,
            declaredCredentialBlobSize: 0, actualCredentialBlobBytesProvided: 0,
            declaredSecretSize: Tpm2bEncryptedSecret.MaxSize + 68, actualSecretBytesProvided: 10).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, code,
            "An over-bound secret is TPM_RC_SIZE even when the frame is also too short to supply it (Table 224).");
    }

    /// <summary>
    /// A <c>credentialBlob</c> declaring a size WITHIN <see cref="Tpm2bIdObject.MaxSize"/> but that the frame
    /// does not actually carry is refused with <c>TPM_RC_INSUFFICIENT</c>, not <c>TPM_RC_SIZE</c>: unlike
    /// <see cref="ActivateCredentialWithOverBoundAndTruncatedCredentialBlobReturnsSize"/>, the declared size
    /// never exceeds the structure's own bound, so the parser's remaining-octets probe — the check
    /// <c>TryReadTpm2bSpanBounded</c> falls through to once the bound check itself has passed — is what answers
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 245, Table 245; Part 3: Commands, clause 5.8.2, Table 2).
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialWithTruncatedCredentialBlobWithinBoundReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitActivateCredentialCommandAsync(
            simulator, pool, ArbitraryActivateHandle, ArbitraryKeyHandle,
            declaredCredentialBlobSize: 50, actualCredentialBlobBytesProvided: 10,
            declaredSecretSize: 0, actualSecretBytesProvided: 0).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_INSUFFICIENT, code,
            "A credentialBlob declared within Tpm2bIdObject.MaxSize but not fully present in the frame is TPM_RC_INSUFFICIENT (Table 245).");
    }

    /// <summary>
    /// The <c>secret</c> counterpart of <see cref="ActivateCredentialWithTruncatedCredentialBlobWithinBoundReturnsInsufficient"/>:
    /// a declared size within <see cref="Tpm2bEncryptedSecret.MaxSize"/> that the frame does not actually carry
    /// is refused with <c>TPM_RC_INSUFFICIENT</c>, not <c>TPM_RC_SIZE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.4.3, Table 224; Part 3: Commands, clause 5.8.2, Table 2).
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialWithTruncatedSecretWithinBoundReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitActivateCredentialCommandAsync(
            simulator, pool, ArbitraryActivateHandle, ArbitraryKeyHandle,
            declaredCredentialBlobSize: 0, actualCredentialBlobBytesProvided: 0,
            declaredSecretSize: 50, actualSecretBytesProvided: 10).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_INSUFFICIENT, code,
            "A secret declared within Tpm2bEncryptedSecret.MaxSize but not fully present in the frame is TPM_RC_INSUFFICIENT (Table 224).");
    }

    /// <summary>
    /// Proves the pooled-carrier ownership of <c>TPM2_ActivateCredential()</c>'s <c>credentialBlob</c> capture
    /// against an ABSOLUTE metered-pool baseline: an over-bound <c>credentialBlob</c> rents nothing (the parser
    /// refuses on the declared size alone, before any carrier is created).
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialOverBoundCredentialBlobRefusalBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants code = await SubmitActivateCredentialCommandAsync(
            simulator, trackingPool.Pool, ArbitraryActivateHandle, ArbitraryKeyHandle,
            declaredCredentialBlobSize: Tpm2bIdObject.MaxSize + 1, actualCredentialBlobBytesProvided: Tpm2bIdObject.MaxSize + 1,
            declaredSecretSize: 0, actualSecretBytesProvided: 0).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An over-bound credentialBlob must still answer TPM_RC_SIZE under the metered pool.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The parser must rent nothing for a credentialBlob it refuses on its declared size alone.");
    }

    /// <summary>
    /// The <c>secret</c> counterpart of <see cref="ActivateCredentialOverBoundCredentialBlobRefusalBalancesThePool"/>,
    /// but with a genuinely non-empty, in-bound <c>credentialBlob</c> ahead of the refusing <c>secret</c> field.
    /// <c>TryParseActivateCredential</c> reads both TPM2B fields as spans and rents neither carrier until AFTER
    /// both reads succeed (its rent-last discipline), so this proves the pool stays balanced even once an
    /// EARLIER field's span read has already succeeded — the scenario the credentialBlob-only refusal above
    /// cannot exercise, since nothing follows a first-field refusal to prove an earlier successful read left no
    /// carrier behind.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialOverBoundSecretAfterValidCredentialBlobSpanBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants code = await SubmitActivateCredentialCommandAsync(
            simulator, trackingPool.Pool, ArbitraryActivateHandle, ArbitraryKeyHandle,
            declaredCredentialBlobSize: 16, actualCredentialBlobBytesProvided: 16,
            declaredSecretSize: Tpm2bEncryptedSecret.MaxSize + 1, actualSecretBytesProvided: Tpm2bEncryptedSecret.MaxSize + 1).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An over-bound secret must still answer TPM_RC_SIZE under the metered pool.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The parser must rent nothing for either TPM2B field when secret's declared size alone refuses the parse, even though credentialBlob's own span read succeeded first.");
    }

    /// <summary>
    /// Proves the pooled ownership of <see cref="Automata.TpmActivateCredentialRequested.CredentialBlob"/> and
    /// <see cref="Automata.TpmActivateCredentialRequested.Secret"/> across a refusal that happens AFTER the
    /// parse has fully rented both: a genuinely non-empty credentialBlob/secret pair against unknown handles
    /// parses cleanly (both carriers are rented as the parse's last act), then <c>OnActivateCredential</c>
    /// refuses with <c>TPM_RC_HANDLE</c> and releases the request's carriers — including the two new fields —
    /// through <see cref="IDisposable.Dispose"/> rather than leaking either pinned rental.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialWithUnknownHandlesReleasesTheParsedCredentialBlobAndSecret()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        //Scoped so the CLIENT-side activateInput/activateAuth/keyAuth locals are disposed before the balance
        //assertion below reads the pool — otherwise their own still-live rentals, not the simulator's
        //parse-rented carriers, would be what the assertion is really observing.
        {
            byte[] credentialBlobBytes = new byte[48];
            Array.Fill(credentialBlobBytes, (byte)0xE1);
            byte[] secretBytes = new byte[64];
            Array.Fill(secretBytes, (byte)0xE2);

            using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                TpmiDhObject.FromValue(ArbitraryActivateHandle), TpmiDhObject.FromValue(ArbitraryKeyHandle),
                credentialBlobBytes, secretBytes, trackingPool.Pool);
            using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<ActivateCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                tpm, activateInput, [activateAuth, keyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "Unknown activate/key handles must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must release the parse-rented, non-empty credentialBlob and secret carriers along with the rest of the request.");
    }

    /// <summary>
    /// Verifies the canonical standard-EK activation (TCG EK Credential Profile, Annex B.3.2): a real policy
    /// session satisfied by <c>TPM2_PolicySecret()</c> against the Endorsement Hierarchy authorizes the standard
    /// EK's USER role at <c>TPM2_ActivateCredential()</c>'s <c>keyHandle</c>, and the wrapped credential round-trips.
    /// </summary>
    [TestMethod]
    public async Task StandardEkActivatesCredentialThroughThePolicyAPath()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStandardEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

                uint policyHandle = 0;
                try
                {
                    //Satisfy PolicyA the canonical way: TPM2_PolicySecret() against the Endorsement Hierarchy (TCG
                    //EK Credential Profile, Annex B.3.2), authorized here with the hierarchy's empty auth value.
                    TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
                        SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");
                    using StartAuthSessionResponse policyStart = policyStartResult.Value;
                    policyHandle = policyStart.SessionHandle.Value;

                    TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                        (uint)TpmRh.TPM_RH_ENDORSEMENT, policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret failed: '{secretResult.ResponseCode}'.");
                    secretResult.Value.Dispose();

                    //Device side: the AK is the activate object (ADMIN role, password), the EK recovers the seed
                    //(USER role) — but the EK's userWithAuth is CLEAR, so its session must be the satisfied policy
                    //session rather than a password. Both handles are transient objects, so the executor needs their
                    //Names to compute cpHash for the policy session (Part 1, clause 15.7, equation 15).
                    using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                    using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmPolicySession keySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
                    ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), ek.Name.Span.ToArray()];

                    TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, activateInput, [activateAuth, keySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(activateResult.IsSuccess, $"TPM2_ActivateCredential (PolicyA path) failed: '{activateResult.ResponseCode}'.");

                    using ActivateCredentialResponse activated = activateResult.Value;
                    Assert.IsTrue(
                        activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret),
                        "The recovered credential must equal the secret wrapped by TPM2_MakeCredential, proving the PolicyA path authorizes the standard EK.");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
                }
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a <c>TPM2_PolicyParameters()</c> binding on the credential key's policy session is judged against
    /// <c>TPM2_ActivateCredential()</c>'s real parameter area: a key whose authPolicy is
    /// <c>PolicyParameters(pHash)</c> over a pHash computed elsewhere is satisfied at the digest gate, then refused
    /// with a bare <c>TPM_RC_POLICY_FAIL</c> when the digest recomputed over <c>TPM_CC_ActivateCredential ||
    /// credentialBlob || secret</c> differs — and the refusal releases the request's raw parameter area along with
    /// its other carriers, leaving the pool balanced.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24; clause 12.5, Table 26; Part 4 CompareParametersHash</see>.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialOverAPolicySessionRefusesAPHashBoundElsewhereAndBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A pHash over some other command's code and parameters: the policy binds a command this one is not.
        byte[] otherParametersHash = SHA256.HashData([0x00, 0x00, 0x01, 0x5E]);
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] authPolicy = new byte[size];
        _ = TpmPolicyDigest.ExtendForParameters(new byte[size], otherParametersHash, SessionAlg, authPolicy);

        using CreatePrimaryResponse key = await CreatePolicyBoundEndorsementShapedKeyAsync(tpm, registry, pool, authPolicy).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, key.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);
                uint policyHandle = 0;
                try
                {
                    TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");
                    using StartAuthSessionResponse policyStart = policyStartResult.Value;
                    policyHandle = policyStart.SessionHandle.Value;

                    TpmResult<PolicyParametersResponse> parametersResult = await tpm.PolicyParametersAsync(policyHandle, otherParametersHash, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(parametersResult.IsSuccess, $"PolicyParameters failed: '{parametersResult.ResponseCode}'.");

                    using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, key.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                    using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmPolicySession keySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
                    ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), key.Name.Span.ToArray()];

                    long baseline = trackingPool.OutstandingCount;
                    TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, activateInput, [activateAuth, keySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(activateResult.IsSuccess, "A pHash over another command must refuse the real ActivateCredential.");
                    Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, activateResult.ResponseCode, "The pHash binding mismatch is the policy's own bare TPM_RC_POLICY_FAIL.");
                    Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refusal must release the raw parameter area, the credential blob, the secret and the password carriers.");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
                }
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, key.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a policy session — here a fresh one — cannot authorize the credential key's USER role when the
    /// key's authPolicy is EMPTY: an ordinary storage primary at <c>keyHandle</c> is refused with
    /// <c>TPM_RC_POLICY_FAIL</c>, since a loaded object's policy is always available to the session machinery
    /// (Part 4 <c>IsAuthPolicyAvailable</c>'s transient arm) and a digest-width policyDigest never equals an empty
    /// authPolicy (<c>CheckPolicyAuthSession</c>) — its authValue is the only way in.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6; clause 12.5; Part 1, clause 19.2; Part 4 CheckPolicyAuthSession</see>.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialOverAPolicySessionRefusesAKeyWithAnEmptyAuthPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, key.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);
                uint policyHandle = 0;
                try
                {
                    TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");
                    using StartAuthSessionResponse policyStart = policyStartResult.Value;
                    policyHandle = policyStart.SessionHandle.Value;

                    using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, key.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                    using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmPolicySession keySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
                    ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), key.Name.Span.ToArray()];

                    TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, activateInput, [activateAuth, keySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(activateResult.IsSuccess, "A key with an empty authPolicy must not be authorized by a policy session.");
                    Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, activateResult.ResponseCode, "An empty authPolicy never equals a session's policyDigest: TPM_RC_POLICY_FAIL.");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
                }
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, key.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that a password session on the standard EK's <c>keyHandle</c> is rejected with
    /// <c>TPM_RC_POLICY_FAIL</c>: the standard template clears <c>userWithAuth</c>, so USER-role authorization by
    /// authValue is not available (TPM 2.0 Library Part 3, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task StandardEkRejectsPasswordAuthOnTheKeyHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStandardEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

                //Both sessions password: the standard EK clears userWithAuth, so USER-role authorization by password
                //is not available at all (Part 3, clause 5.6, check 7.1) — this must fail regardless of the credential
                //blob's validity.
                using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(activateResult.IsSuccess, "A password session on the standard EK's keyHandle must be rejected.");
                Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, activateResult.ResponseCode);
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that a real policy session whose accumulated policyDigest does not reproduce the standard EK's
    /// authPolicy is rejected with <c>TPM_RC_POLICY_FAIL</c> (TPM 2.0 Library Part 3, clause 5.6: the session's
    /// policyDigest must match the authPolicy associated with the handle).
    /// </summary>
    [TestMethod]
    public async Task StandardEkRejectsAnUnsatisfiedPolicySession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStandardEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

                uint policyHandle = 0;
                try
                {
                    //A real policy session that never ran TPM2_PolicySecret() (or any assertion): its accumulated
                    //policyDigest stays at all-zero, which cannot equal PolicyA.
                    TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
                        SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");
                    using StartAuthSessionResponse policyStart = policyStartResult.Value;
                    policyHandle = policyStart.SessionHandle.Value;

                    using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                    using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmPolicySession keySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
                    ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), ek.Name.Span.ToArray()];

                    TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, activateInput, [activateAuth, keySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(activateResult.IsSuccess, "An unsatisfied policy session must not authorize the standard EK.");
                    Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, activateResult.ResponseCode);
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
                }
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that a trial policy session cannot authorize the standard EK even when its accumulated
    /// policyDigest is byte-identical to PolicyA — proving the trial check, not the digest comparison, rejects it
    /// (TPM 2.0 Library Part 1, clause 18.3: a trial session authorizes nothing).
    /// </summary>
    [TestMethod]
    public async Task StandardEkRejectsATrialPolicySession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStandardEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

                uint trialHandle = 0;
                try
                {
                    //A trial session that ran the SAME TPM2_PolicySecret() assertion, so its accumulated policyDigest
                    //is byte-identical to PolicyA — proving that it is the IsTrial check, not the digest comparison,
                    //that rejects it (Part 1, clause 18.3: a trial session authorizes nothing).
                    TpmResult<StartAuthSessionResponse> trialStartResult = await tpm.StartTrialPolicySessionAsync(
                        SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(trialStartResult.IsSuccess, $"StartAuthSession (trial) failed: '{trialStartResult.ResponseCode}'.");
                    using StartAuthSessionResponse trialStart = trialStartResult.Value;
                    trialHandle = trialStart.SessionHandle.Value;

                    TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                        (uint)TpmRh.TPM_RH_ENDORSEMENT, trialHandle, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(secretResult.IsSuccess, $"Trial PolicySecret failed: '{secretResult.ResponseCode}'.");
                    secretResult.Value.Dispose();

                    using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                    using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmPolicySession trialSession = TpmPolicySession.ForSession(trialHandle, SessionAlg, pool);
                    ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), ek.Name.Span.ToArray()];

                    TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, activateInput, [activateAuth, trialSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(activateResult.IsSuccess,
                        "A trial policy session must not authorize the standard EK even when its digest equals PolicyA.");
                    Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, activateResult.ResponseCode);
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, trialHandle).ConfigureAwait(false);
                }
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that TPM2_ActivateCredential()'s activate-object slot (Auth Index 1, Auth Role ADMIN, session
    /// 0; TPM 2.0 Library Part 3, clause 12.5) is checked against the attestation key's own retained authValue
    /// over a plain <c>TPM_RS_PW</c> session: a WRONG password against a DA-protected activate object is
    /// refused with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> (Part 2, clause 6.6.2) and charges
    /// <c>failedTries</c> exactly once (Part 1, clause 16.8.7), while the CORRECT password recovers the
    /// wrapped credential exactly as the empty-auth baseline does.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialVerifiesTheActivateObjectsAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreatePasswordProtectedSigningPrimaryAsync(
                tpm, registry, pool, TpmRh.TPM_RH_OWNER, ActivatePassword, noDa: false).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

                using ActivateCredentialInput wrongInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession wrongActivateAuth = TpmPasswordSession.Create(WrongActivatePassword, pool);
                using TpmPasswordSession emptyKeyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, wrongInput, [wrongActivateAuth, emptyKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(wrongResult.IsTpmError, "A wrong activate-object password must be refused.");
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
                    "A wrong password against the DA-protected activate object (session 0) must be the session-index-encoded TPM_RC_AUTH_FAIL (TPM 2.0 Library Part 2, clause 6.6.2).");

                TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    before.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
                    "A wrong activate-object password against a DA-protected object must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 16.8.7).");

                using ActivateCredentialInput correctInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession correctActivateAuth = TpmPasswordSession.Create(ActivatePassword, pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, correctInput, [correctActivateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(correctResult.IsSuccess, $"TPM2_ActivateCredential with the activate object's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");

                using ActivateCredentialResponse activated = correctResult.Value;
                Assert.IsTrue(
                    activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret),
                    "The recovered credential must equal the secret wrapped by TPM2_MakeCredential once the activate object's correct password authorizes it.");
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that TPM2_ActivateCredential()'s credential-key slot (Auth Index 2, Auth Role USER, session 1;
    /// TPM 2.0 Library Part 3, clause 12.5) is checked against the credential key's own retained authValue over
    /// a plain <c>TPM_RS_PW</c> session once <c>TPMA_OBJECT.userWithAuth</c> is SET (unlike the standard EK's
    /// cleared template, which <see cref="StandardEkRejectsPasswordAuthOnTheKeyHandle"/> covers): a WRONG
    /// password against a DA-protected credential key is refused with the session-index-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> at session 1 and charges <c>failedTries</c> exactly once, while the CORRECT
    /// password recovers the wrapped credential.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialVerifiesTheCredentialKeysAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreatePasswordProtectedStoragePrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, CredentialKeyPassword, noDa: false).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

                using ActivateCredentialInput wrongInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession wrongKeyAuth = TpmPasswordSession.Create(WrongCredentialKeyPassword, pool);

                TpmResult<ActivateCredentialResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, wrongInput, [activateAuth, wrongKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(wrongResult.IsTpmError, "A wrong credential-key password must be refused.");
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), wrongResult.ResponseCode,
                    "A wrong password against the DA-protected credential key (session 1) must be the session-index-encoded TPM_RC_AUTH_FAIL (TPM 2.0 Library Part 2, clause 6.6.2).");

                TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    before.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
                    "A wrong credential-key password against a DA-protected key must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 16.8.7).");

                using ActivateCredentialInput correctInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession correctActivateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession correctKeyAuth = TpmPasswordSession.Create(CredentialKeyPassword, pool);

                TpmResult<ActivateCredentialResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, correctInput, [correctActivateAuth, correctKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(correctResult.IsSuccess, $"TPM2_ActivateCredential with the credential key's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");

                using ActivateCredentialResponse activated = correctResult.Value;
                Assert.IsTrue(
                    activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret),
                    "The recovered credential must equal the secret wrapped by TPM2_MakeCredential once the credential key's correct password authorizes it.");
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that the activate-object slot's authValue check (Auth Index 1, Auth Role ADMIN, session 0) runs
    /// independently of the credential-key slot's authorization form: with the standard EK's <c>keyHandle</c>
    /// authorized by a satisfied <c>TPM2_PolicySecret()</c> session over the Endorsement Hierarchy exactly as
    /// <see cref="StandardEkActivatesCredentialThroughThePolicyAPath"/> establishes, a WRONG password on the
    /// DA-protected activate object is still refused with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> at
    /// session 0 and charges <c>failedTries</c> exactly once (TPM 2.0 Library Part 1, clause 16.8.7; Part 2,
    /// clause 6.6.2), while the CORRECT password recovers the wrapped credential over the same policy-session
    /// path.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialOverAPolicySessionVerifiesTheActivateObjectsAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStandardEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreatePasswordProtectedSigningPrimaryAsync(
                tpm, registry, pool, TpmRh.TPM_RH_OWNER, ActivatePassword, noDa: false).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), ek.Name.Span.ToArray()];

                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

                uint wrongPolicyHandle = 0;
                try
                {
                    wrongPolicyHandle = await OpenSatisfiedEndorsementPolicySessionAsync(tpm).ConfigureAwait(false);

                    using ActivateCredentialInput wrongInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                    using TpmPasswordSession wrongActivateAuth = TpmPasswordSession.Create(WrongActivatePassword, pool);
                    using TpmPolicySession wrongKeySession = TpmPolicySession.ForSession(wrongPolicyHandle, SessionAlg, pool);

                    TpmResult<ActivateCredentialResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, wrongInput, [wrongActivateAuth, wrongKeySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(wrongResult.IsTpmError, "A wrong activate-object password must be refused even over a satisfied policy session at the key slot.");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
                        "A wrong password against the DA-protected activate object (session 0) must be the session-index-encoded TPM_RC_AUTH_FAIL, whatever the policy session's own standing (TPM 2.0 Library Part 2, clause 6.6.2).");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, wrongPolicyHandle).ConfigureAwait(false);
                }

                TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    before.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
                    "A wrong activate-object password against a DA-protected object must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 16.8.7).");

                uint correctPolicyHandle = 0;
                try
                {
                    correctPolicyHandle = await OpenSatisfiedEndorsementPolicySessionAsync(tpm).ConfigureAwait(false);

                    using ActivateCredentialInput correctInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                    using TpmPasswordSession correctActivateAuth = TpmPasswordSession.Create(ActivatePassword, pool);
                    using TpmPolicySession correctKeySession = TpmPolicySession.ForSession(correctPolicyHandle, SessionAlg, pool);

                    TpmResult<ActivateCredentialResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, correctInput, [correctActivateAuth, correctKeySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(correctResult.IsSuccess, $"TPM2_ActivateCredential (PolicyA path) with the activate object's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");

                    using ActivateCredentialResponse activated = correctResult.Value;
                    Assert.IsTrue(
                        activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret),
                        "The recovered credential must equal the secret wrapped by TPM2_MakeCredential once the activate object's correct password authorizes the policy-session path.");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, correctPolicyHandle).ConfigureAwait(false);
                }
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that <c>TPM2_ActivateCredential()</c>'s <c>keyHandle</c> DA/Lockout gate (TPM 2.0 Library Part 3,
    /// clause 5.6, check 3) answers before its userWithAuth gate (clause 5.6, check 7.1): clause 5.6's checks run
    /// in their numbered order, so a TPM already in general Lockout mode answers the bare <c>TPM_RC_LOCKOUT</c>
    /// for a password session on the standard EK's DA-protected <c>keyHandle</c> without ever reaching the
    /// userWithAuth-CLEAR check that would otherwise answer <c>TPM_RC_POLICY_FAIL</c> (the response
    /// <see cref="StandardEkRejectsPasswordAuthOnTheKeyHandle"/> proves outside Lockout mode). The activate
    /// object is built dictionary-attack exempt and always supplied its correct password, so the observed error
    /// is attributable solely to the standard EK's own <c>keyHandle</c> slot, not to session 0's identical gate.
    /// </summary>
    [TestMethod]
    public async Task StandardEkKeyHandleIsRefusedWithLockoutRatherThanPolicyFailWhileLockedOut()
    {
        const uint LoweredMaxTries = 1;
        const string BurnerKeyPassword = "burner-credential-key-auth-proof";
        const string WrongBurnerKeyPassword = "wrong-burner-credential-key-auth-guess";

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStandardEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            //The activate object (ADMIN role, session 0) is dictionary-attack exempt and always supplied its
            //correct password below, so Lockout mode can only ever be observed through the standard EK's
            //keyHandle slot (session 1) in this test, never through session 0's identical gate.
            using CreatePrimaryResponse ak = await CreatePasswordProtectedSigningPrimaryAsync(
                tpm, registry, pool, TpmRh.TPM_RH_OWNER, ActivatePassword, noDa: true).ConfigureAwait(false);
            try
            {
                //A throwaway DA-protected credential key used only to seed one counted auth-failure.
                using CreatePrimaryResponse burnerKey = await CreatePasswordProtectedStoragePrimaryAsync(
                    tpm, registry, pool, TpmRh.TPM_RH_OWNER, BurnerKeyPassword, noDa: false).ConfigureAwait(false);
                try
                {
                    TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
                        ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
                        TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

                    //Seed exactly one counted failure against the DA-protected burner credential key (Auth Index
                    //2, Auth Role USER, session 1). The auth-value compare runs before any credential-blob content
                    //is inspected (the undersized-blob proof establishes the same ordering for TPM_RC_SIZE), so an
                    //empty blob/secret reaches this failure undisturbed.
                    using ActivateCredentialInput burnInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, burnerKey.ObjectHandle, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, pool);
                    using TpmPasswordSession burnActivateAuth = TpmPasswordSession.Create(ActivatePassword, pool);
                    using TpmPasswordSession wrongBurnerKeyAuth = TpmPasswordSession.Create(WrongBurnerKeyPassword, pool);

                    TpmResult<ActivateCredentialResponse> burnResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, burnInput, [burnActivateAuth, wrongBurnerKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(burnResult.IsTpmError, "The seeding failure against the burner credential key must be refused.");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), burnResult.ResponseCode,
                        "A wrong password against the DA-protected burner credential key (session 1) must count as an auth-failure.");

                    TpmResult<TpmDictionaryAttackParameters> afterBurn = await tpm.GetDictionaryAttackParametersAsync(
                        pool, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(
                        afterBurn.Value.IsLockedOut,
                        "One failure at the lowered maxTries must put the TPM into general Lockout mode (TPM 2.0 Library Part 1, clause 16.8.3).");

                    //The proving call: the activate object's CORRECT password authorizes session 0 cleanly (it is
                    //dictionary-attack exempt, so Lockout mode never touches it), so session 1's outcome is
                    //attributable solely to the standard EK's own keyHandle checks.
                    using ActivateCredentialInput lockedInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, ek.ObjectHandle, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, pool);
                    using TpmPasswordSession lockedActivateAuth = TpmPasswordSession.Create(ActivatePassword, pool);
                    using TpmPasswordSession lockedKeyAuth = TpmPasswordSession.CreateEmpty(pool);

                    TpmResult<ActivateCredentialResponse> lockedResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, lockedInput, [lockedActivateAuth, lockedKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(
                        lockedResult.IsSuccess,
                        "A password session on the standard EK's keyHandle while the TPM is in general Lockout mode must be refused.");
                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_LOCKOUT, lockedResult.ResponseCode,
                        "The keyHandle's DA/Lockout gate (clause 5.6, check 3) must answer before its userWithAuth gate (clause 5.6, check 7.1): the bare TPM_RC_LOCKOUT, not the TPM_RC_POLICY_FAIL a userWithAuth-CLEAR key would otherwise answer.");

                    TpmResult<TpmDictionaryAttackParameters> afterLocked = await tpm.GetDictionaryAttackParametersAsync(
                        pool, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(
                        afterBurn.Value.LockoutCounter, afterLocked.Value.LockoutCounter,
                        "A TPM_RC_LOCKOUT refusal must not itself advance failedTries further (TPM 2.0 Library Part 1, clause 16.8.3).");
                }
                finally
                {
                    await FlushAsync(tpm, registry, burnerKey.ObjectHandle.Value, pool).ConfigureAwait(false);
                }
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that <c>TPM2_ActivateCredential()</c>'s credential-key slot (session index 1), when it is a
    /// <c>TPM_RS_PW</c> authorization, is refused with <c>TPM_RC_ATTRIBUTES</c> encoded to that index once its
    /// attributes octet claims <c>audit</c>: the attribute "has no meaning for a password authorization and is
    /// required to be CLEAR" (TPM 2.0 Library Part 1, clause 15.6.4, Table 15), because a password authorization
    /// keeps no session context an audit digest could live in.
    /// </summary>
    /// <remarks>
    /// This command is where the rule has to hold at a slot the area check never sees: its two slots are read by
    /// the wire reader and answered there, so the structural rules must travel with the reader rather than with
    /// the per-command area helper. Driving it at index 1 also pins the encoding — the reference applies this
    /// same pair of rules at every slot it unmarshals, at that slot's own error index — so a rule pinned to index
    /// 0 would answer here with the wrong modifier and be caught. The host never composes such an octet, so it is
    /// planted on the wire by an intervening transport, and the refusal precedes every authorization check (Part
    /// 3, clause 5.5 precedes clause 5.6), leaving both slots' credentials unexamined.
    /// </remarks>
    [TestMethod]
    public async Task ActivateCredentialKeySlotClaimingAuditIsRefusedWithAttributesAtItsOwnIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

                using TpmDevice plantingTpm = TpmDevice.Create(async (command, commandPool, cancellationToken) =>
                {
                    byte[] bytes = command.ToArray();
                    if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_ActivateCredential)
                    {
                        SetSessionAttributeBit(bytes, handleCount: 2, sessionIndex: 1, TpmaSession.AUDIT);
                    }

                    return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
                });

                using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    plantingTpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(result.IsSuccess)
                {
                    result.Value.Dispose();
                }

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
                    "A password slot may carry no attribute but continueSession, so audit there is an attribute error.");
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), result.ResponseCode,
                    "The refusal names the credential-key slot at index 1, session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_ActivateCredential()</c> command whose <c>credentialBlob</c>
    /// (<c>TPM2B_ID_OBJECT</c>) and <c>secret</c> (<c>TPM2B_ENCRYPTED_SECRET</c>) each independently declare a
    /// size the frame may or may not actually carry in full — the declared/actual pair per field lets one
    /// builder express a clean over-bound refusal (declared and actual equal, past the type's own bound), a
    /// clean truncation (declared within bound, actual short), and the bound-before-truncation precedence case
    /// (declared past the bound AND actual short) for both fields. The handle area carries two
    /// password-authorized slots (<c>@activateHandle</c> ADMIN role, <c>@keyHandle</c> USER role) with empty
    /// supplied passwords, mirroring
    /// <c>TpmInHouseSimulatorCreationParameterTests.FrameCreateFamilyCommandWithTruncatedOutsideInfo</c>'s
    /// technique for the same shape of refusal.
    /// </summary>
    private static IMemoryOwner<byte> FrameActivateCredentialCommand(
        BaseMemoryPool pool, uint activateHandle, uint keyHandle,
        ushort declaredCredentialBlobSize, int actualCredentialBlobBytesProvided,
        ushort declaredSecretSize, int actualSecretBytesProvided,
        out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        length =
            TpmHeader.HeaderSize
            + 2 * sizeof(uint)                             //Handle area: @activateHandle, @keyHandle.
            + sizeof(uint) + 2 * PasswordSlotSize          //authorizationSize + two TPM_RS_PW slots.
            + sizeof(ushort) + actualCredentialBlobBytesProvided
            + sizeof(ushort) + actualSecretBytesProvided;

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_ActivateCredential);
            header.WriteTo(ref writer);
            writer.WriteUInt32(activateHandle);
            writer.WriteUInt32(keyHandle);
            writer.WriteUInt32((uint)(2 * PasswordSlotSize));
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteUInt16(declaredCredentialBlobSize);
            if(actualCredentialBlobBytesProvided > 0)
            {
                writer.WriteBytes(new byte[actualCredentialBlobBytesProvided]);
            }

            writer.WriteUInt16(declaredSecretSize);
            if(actualSecretBytesProvided > 0)
            {
                writer.WriteBytes(new byte[actualSecretBytesProvided]);
            }

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_ActivateCredential()</c> built by <see cref="FrameActivateCredentialCommand"/>
    /// straight to the simulator (bypassing <see cref="TpmCommandExecutor"/>, whose typed
    /// <see cref="ActivateCredentialInput"/> cannot express a declared/actual size mismatch or an over-bound
    /// declared size — <see cref="Tpm2bIdObject.Create(ReadOnlySpan{byte}, BaseMemoryPool)"/>/
    /// <see cref="Tpm2bEncryptedSecret.Create(ReadOnlySpan{byte}, BaseMemoryPool)"/> refuse those shapes on the
    /// client side before a command is ever framed) and yields the response code.
    /// </summary>
    private async Task<TpmRcConstants> SubmitActivateCredentialCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint activateHandle, uint keyHandle,
        ushort declaredCredentialBlobSize, int actualCredentialBlobBytesProvided,
        ushort declaredSecretSize, int actualSecretBytesProvided)
    {
        using IMemoryOwner<byte> commandOwner = FrameActivateCredentialCommand(
            pool, activateHandle, keyHandle,
            declaredCredentialBlobSize, actualCredentialBlobBytesProvided,
            declaredSecretSize, actualSecretBytesProvided, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
    }

    /// <summary>
    /// Sets attribute bits in one existing authorization slot's <c>sessionAttributes</c> octet, in place, leaving
    /// every other octet of the framed command untouched.
    /// </summary>
    /// <param name="command">The framed command to rewrite.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
    /// <param name="sessionIndex">The zero-based slot whose attributes octet is rewritten.</param>
    /// <param name="sessionAttributes">The attribute bits to set.</param>
    private static void SetSessionAttributeBit(byte[] command, int handleCount, int sessionIndex, TpmaSession sessionAttributes)
    {
        int offset = TpmHeader.HeaderSize + (handleCount * sizeof(uint)) + sizeof(uint);
        for(int slot = 0; slot < sessionIndex; slot++)
        {
            offset += sizeof(uint);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
            offset += sizeof(byte);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        }

        offset += sizeof(uint);
        offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        command[offset] |= (byte)sessionAttributes;
    }

    /// <summary>
    /// Wraps <see cref="CredentialSecret"/> to the given key's public area, bound to <paramref name="objectName"/>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The credential key (EK) whose public area protects the seed.</param>
    /// <param name="objectName">The Name of the object the credential is bound to (the AK).</param>
    /// <returns>The MakeCredential response (the caller owns it).</returns>
    private async Task<MakeCredentialResponse> MakeCredentialAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] objectName)
    {
        using MakeCredentialInput input = MakeCredentialInput.Create(keyHandle, CredentialSecret, objectName, pool);

        //TPM2_MakeCredential uses only the public area of the key, so it takes no authorization session.
        TpmResult<MakeCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_MakeCredential failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a restricted-decrypt ECC storage primary (the EK stand-in) under the given hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateStoragePrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage key ({hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a restricted-decrypt ECC storage primary (a credential-key stand-in) under the given hierarchy
    /// with a real, non-empty password — the fixture the credential key's authValue verification proof needs.
    /// <see cref="CreatePrimaryInput.ForEccStorageParent"/>'s template sets <c>TPMA_OBJECT.userWithAuth</c>,
    /// admitting a plain <c>TPM_RS_PW</c> session at the resulting key's USER-role slot (unlike the standard
    /// EK's cleared template that <see cref="CreateStandardEndorsementKeyAsync"/> builds).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The key's password.</param>
    /// <param name="noDa">Whether the key is dictionary-attack exempt (<c>TPMA_OBJECT.NO_DA</c>).</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreatePasswordProtectedStoragePrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string password, bool noDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (password-protected storage key, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates the standard ECC NIST P-256 endorsement key (TCG EK Credential Profile, Annex B.3.4, Template L-2)
    /// under the Endorsement Hierarchy, through <see cref="CreatePrimaryInput.ForEndorsementKey"/>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateStandardEndorsementKeyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (standard EK) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a restricted-decrypt ECC P-256 storage key in the standard endorsement key's shape (TCG EK
    /// Credential Profile, Annex B.3.4, Template L-2: <c>userWithAuth</c> CLEAR, <c>adminWithPolicy</c> SET) but
    /// under a caller-chosen authPolicy, so its USER role at <c>keyHandle</c> is reachable only through a policy
    /// session that reproduces that digest.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authPolicy">The 32-octet SHA-256 authPolicy the key is created under.</param>
    /// <returns>The CreatePrimary response; the caller owns and flushes it.</returns>
    private async Task<CreatePrimaryResponse> CreatePolicyBoundEndorsementShapedKeyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> authPolicy)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateEccEndorsementKeyTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, authPolicy.Span);
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_ENDORSEMENT, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (policy-bound EK-shaped key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key (the AK) under the given hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary signing key ({hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key (an attestation-key stand-in) under the given hierarchy with a
    /// real, non-empty password — the fixture the activate-object's authValue verification proofs need to
    /// exercise TPM2_ActivateCredential()'s Auth Index 1, Auth Role ADMIN slot against a genuine retained
    /// authValue rather than the empty one <see cref="CreateSigningPrimaryAsync"/>'s key carries.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The key's password.</param>
    /// <param name="noDa">Whether the key is dictionary-attack exempt (<c>TPMA_OBJECT.NO_DA</c>).</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreatePasswordProtectedSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string password, bool noDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (password-protected signing key, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Starts a real (non-trial) policy session and satisfies it with <c>TPM2_PolicySecret()</c> against the
    /// Endorsement Hierarchy's empty authorization (TCG EK Credential Profile, Annex B.3.2), reproducing
    /// "PolicyA" in the session's accumulated policyDigest — the fixture the policy-session activation proof
    /// needs at the credential key's slot, built fresh per attempt since a session's continuation after a
    /// command that fails at a different slot is not itself under test here.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <returns>The satisfied policy session's handle (the caller flushes it).</returns>
    private async Task<uint> OpenSatisfiedEndorsementPolicySessionAsync(TpmDevice tpm)
    {
        TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");
        using StartAuthSessionResponse policyStart = policyStartResult.Value;
        uint policyHandle = policyStart.SessionHandle.Value;

        TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
            (uint)TpmRh.TPM_RH_ENDORSEMENT, policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret failed: '{secretResult.ResponseCode}'.");
        secretResult.Value.Dispose();

        return policyHandle;
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator services
    /// <c>TPM2_CreatePrimary()</c> for the EK and AK primaries and the ECDH secret exchange of credential activation.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-credactivation", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>
    /// Creates a response codec registry covering the commands these tests issue.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object handle, ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="handle">The handle to flush.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle, BaseMemoryPool pool)
    {
        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Flushes a policy session handle if one was actually started (<paramref name="handle"/> non-zero), ignoring
    /// the result. A test that fails before starting its policy session leaves nothing to flush.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="handle">The session handle to flush, or <c>0</c> if none was started.</param>
    private async Task FlushIfPresentAsync(TpmDevice tpm, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await tpm.FlushContextAsync(handle, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
