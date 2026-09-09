using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Pins the <c>adminWithPolicy</c> rule on <c>TPM2_Certify()</c>'s ADMIN-role <c>objectHandle</c> slot against
/// the in-house behavioural <see cref="TpmSimulator"/> through the production command path: with the attribute SET
/// a password or an HMAC session at the slot is a kind of authorization the object does not accept (check 5.1 of
/// the authorization ladder, TPM 2.0 Library Part 3, clause 5.6; Part 2, clause 8.3.3), judged after the
/// object's lockout standing (check 3) and charging nothing; with the attribute CLEAR the password authorizes as
/// it always has (Part 3, clause 18.2, Table 97).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorCertifyAdminPolicyTests
{
    /// <summary>The Name and session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The qualifying data the certifications carry.</summary>
    private static byte[] Nonce { get; } = "Certify nonce for the adminWithPolicy pins."u8.ToArray();

    /// <summary>The certified subject's password, within the SHA-256 Name algorithm's 32-octet authValue bound.</summary>
    private const string SubjectPassword = "certify-admin-policy-auth";

    /// <summary>The subject's authorization value in wire form.</summary>
    private static byte[] SubjectAuth { get; } = System.Text.Encoding.UTF8.GetBytes(SubjectPassword);

    /// <summary>A wrong guess at a subject's password.</summary>
    private static byte[] WrongSubjectAuth { get; } = [0xD1, 0xD2, 0xD3, 0xD4];

    /// <summary>The attribute word of an ordinary primary signing key: bound, TPM-generated, USER-role by password.</summary>
    private const TpmaObject SigningAttributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN | TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Check 5.1 of the authorization ladder on the plain form: with <c>adminWithPolicy</c> SET — "ADMIN role
    /// actions may only be approved with a policy session" (TPM 2.0 Library Part 2, clause 8.3.3) — a
    /// <c>TPM_RS_PW</c> slot for the certified object is refused with the bare <c>TPM_RC_AUTH_TYPE</c> before its
    /// compare, and the dictionary-attack counter does not move.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task CertifyWithAPasswordOnAnAdminWithPolicySubjectIsRefusedWithAuthTypeUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(CertifyWithAPasswordOnAnAdminWithPolicySubjectIsRefusedWithAuthTypeUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, SigningAttributes | TpmaObject.ADMIN_WITH_POLICY | TpmaObject.NO_DA, SubjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateAttestationKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CertifyResponse> result = await CertifyWithPasswordsAsync(tpm, registry, pool, subject, ak, SubjectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
            "adminWithPolicy SET admits only a policy session at the ADMIN slot, so a password is the bare TPM_RC_AUTH_TYPE (Part 3, clause 5.6, check 5.1; Part 2, clause 8.3.3).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Check 5.1 reads no credential, so it moves no dictionary-attack counter.");
    }

    /// <summary>
    /// Check 5.1 on the session form: an HMAC session at the certified object's slot is refused with the bare
    /// <c>TPM_RC_AUTH_TYPE</c> exactly as a password is, since the ADMIN role of an <c>adminWithPolicy</c>-SET
    /// object is a policy session's alone (TPM 2.0 Library Part 2, clause 8.3.3).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverAnHmacSessionOnAnAdminWithPolicySubjectIsRefusedWithAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(CertifyOverAnHmacSessionOnAnAdminWithPolicySubjectIsRefusedWithAuthType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, SigningAttributes | TpmaObject.ADMIN_WITH_POLICY | TpmaObject.NO_DA, SubjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateAttestationKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (object slot) failed: '{startResult.ResponseCode}'.");
        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        try
        {
            using TpmSession objectSession = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
            objectSession.SetAuthValue(SubjectAuth, pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, SessionAlg, pool);

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [objectSession, signAuth], [subject.Name.AsReadOnlyMemory(), ak.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                "An HMAC session at an adminWithPolicy-SET object's ADMIN slot is TPM_RC_AUTH_TYPE (Part 3, clause 5.6, check 5.1).");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Check 3 precedes check 5.1: a dictionary-attack-protected, <c>adminWithPolicy</c>-SET subject with the TPM
    /// in Lockout mode answers a password with <c>TPM_RC_LOCKOUT</c>, not <c>TPM_RC_AUTH_TYPE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task CertifyInLockoutOnAnAdminWithPolicySubjectIsRefusedWithLockoutBeforeAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(CertifyInLockoutOnAnAdminWithPolicySubjectIsRefusedWithLockoutBeforeAuthType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, SigningAttributes | TpmaObject.ADMIN_WITH_POLICY, SubjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse throwaway = await CreateSigningPrimaryAsync(tpm, registry, pool, SigningAttributes, SubjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateAttestationKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        const uint LoweredMaxTries = 1;
        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds, TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        TpmResult<CertifyResponse> priming = await CertifyWithPasswordsAsync(tpm, registry, pool, throwaway, ak, WrongSubjectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), priming.ResponseCode,
            "The priming certification with a wrong password must fail and count, taking the TPM into Lockout mode.");

        TpmResult<CertifyResponse> result = await CertifyWithPasswordsAsync(tpm, registry, pool, subject, ak, SubjectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
            "Check 3 (Lockout) is judged before check 5.1 (the session kind), so the answer is TPM_RC_LOCKOUT rather than TPM_RC_AUTH_TYPE (Part 3, clause 5.6).");
    }

    /// <summary>
    /// With <c>adminWithPolicy</c> CLEAR the certified object's password authorizes the ADMIN slot and the
    /// certification succeeds with a signed attestation (TPM 2.0 Library Part 3, clause 18.2, Table 97).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task CertifyWithAPasswordOnAnAdminWithPolicyClearSubjectSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(CertifyWithAPasswordOnAnAdminWithPolicyClearSubjectSucceeds), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, SigningAttributes | TpmaObject.NO_DA, SubjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateAttestationKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<CertifyResponse> result = await CertifyWithPasswordsAsync(tpm, registry, pool, subject, ak, SubjectAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A password authorizes the ADMIN slot of an adminWithPolicy-CLEAR object (Part 3, clause 5.6), but failed: '{result.ResponseCode}'.");
        using CertifyResponse response = result.Value;
        Assert.IsFalse(response.CertifyInfo.GetRawBytes().IsEmpty, "The certification carries a TPM2B_ATTEST (Part 3, clause 18.2, Table 98).");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, response.SignatureAlgorithm, "The attestation is signed under the requested ECDSA scheme.");
    }

    /// <summary>Creates an operational simulator with the elliptic-curve backend.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool) =>
        HmacKeyHarness.CreateOperationalAsync($"tpm-in-house-certify-admin-policy-{name}", pool, TestContext.CancellationToken);

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the owner hierarchy with an exact attribute word — the
    /// composition <see cref="CreatePrimaryInput.ForEccSigningKey"/> cannot express, since it never sets
    /// <c>adminWithPolicy</c> — and the given password.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The exact <c>TPMA_OBJECT</c> word.</param>
    /// <param name="password">The key's password.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the CreatePrimaryInput, whose Dispose releases them.")]
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmaObject attributes, string password)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.WithPassword(password, pool);
        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(SessionAlg, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg));
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key, attributes {attributes}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates the empty-auth ECC P-256 attestation key under the endorsement hierarchy.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateAttestationKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (attestation key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Certifies <paramref name="subject"/> with <paramref name="ak"/> over two <c>TPM_RS_PW</c> slots — the
    /// object slot presenting <paramref name="subjectAuth"/>, the sign slot the attestation key's empty value —
    /// and returns the raw result.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="subject">The certified object.</param>
    /// <param name="ak">The attestation key.</param>
    /// <param name="subjectAuth">The password presented for the certified object.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<CertifyResponse>> CertifyWithPasswordsAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse subject, CreatePrimaryResponse ak, ReadOnlyMemory<byte> subjectAuth)
    {
        using TpmPasswordSession objectAuth = HmacKeyHarness.PasswordSession(subjectAuth, pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput input = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, SessionAlg, pool);

        return await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, input, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
