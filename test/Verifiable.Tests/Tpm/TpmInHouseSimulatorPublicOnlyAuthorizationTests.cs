using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
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
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The public-only object state across every command of the in-house behavioural <see cref="TpmSimulator"/>:
/// "The public and sensitive portions of the object shall be present on the TPM" is check 1 of the
/// authorization ladder (TPM 2.0 Library Part 3, clause 5.6), so every <c>@</c>-decorated use of an object
/// <c>TPM2_LoadExternal()</c> loaded from its public area alone is refused with the bare
/// <c>TPM_RC_AUTH_UNAVAILABLE</c> — ahead of the dictionary-attack gate, charging nothing — while the
/// public-key operations that need no authorization keep working, and a co-resident TPM holding the full key
/// completes what the public-only one began (credential activation, decapsulation). Every object here is a key
/// the framework's own ECDSA minted off the TPM or a public area a second simulator exported.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPublicOnlyAuthorizationTests
{
    /// <summary>The Name and session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width of <see cref="SessionAlg"/>.</summary>
    private const int DigestSize = 32;

    /// <summary>The width of a P-256 coordinate or scalar.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The NV Index <c>TPM2_NV_Certify()</c> attests.</summary>
    private const uint CertifiedIndexHandle = 0x0100_0170;

    /// <summary>The dictionary-attack-protected NV Index whose wrong write drives the TPM into Lockout mode.</summary>
    private const uint LockoutDriverIndexHandle = 0x0100_0171;

    /// <summary>The Indexes' declared data size.</summary>
    private const ushort IndexDataSize = 16;

    /// <summary>Ordinary Index attributes with dictionary-attack protection (<c>TPMA_NV_NO_DA</c> CLEAR).</summary>
    private const TpmaNv IndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>The Indexes' authorization value.</summary>
    private static byte[] IndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value for the Indexes.</summary>
    private static byte[] WrongIndexAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The octets written into an Index.</summary>
    private static byte[] IndexData { get; } = [0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39];

    /// <summary>The message the signatures are over.</summary>
    private static byte[] MessageBytes { get; } = "A public-only object cannot be authorized."u8.ToArray();

    /// <summary>The qualifying data the attestations carry.</summary>
    private static byte[] Nonce { get; } = "public-only nonce"u8.ToArray();

    /// <summary>The secret <c>TPM2_MakeCredential()</c> wraps.</summary>
    private static byte[] CredentialSecret { get; } = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF];

    /// <summary>RFC 4231 test case 1's 20-octet key, the value the KEYEDHASH public areas bind to.</summary>
    private static byte[] Rfc4231Case1Key { get; } = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    /// <summary>The attribute word of an external signing key exempt from dictionary-attack protection.</summary>
    private const TpmaObject NoDaSigningAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

    /// <summary>The attribute word of an external signing key under dictionary-attack protection.</summary>
    private const TpmaObject DaProtectedSigningAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT;

    /// <summary>The attribute word of an external HMAC key.</summary>
    private const TpmaObject HmacKeyAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

    /// <summary>The attribute word of an external, duplicable sealed data object.</summary>
    private const TpmaObject SealedAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Every signing-family command whose <c>@keyHandle</c> names a public-only ECC key — <c>TPM2_Sign()</c>,
    /// <c>TPM2_SignDigest()</c>, <c>TPM2_SignSequenceStart()</c> — is refused with the bare
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> and moves no dictionary-attack counter.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    /// <param name="command">The signing-family command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_Sign)]
    [DataRow(TpmCcConstants.TPM_CC_SignDigest)]
    [DataRow(TpmCcConstants.TPM_CC_SignSequenceStart)]
    public async Task SigningCommandsOnAPublicOnlyEccKeyAreRefusedWithAuthUnavailable(TpmCcConstants command)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(SigningCommandsOnAPublicOnlyEccKeyAreRefusedWithAuthUnavailable)}-{command}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        TpmiDhObject handle = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, NoDaSigningAttributes).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmRcConstants code;
        switch(command)
        {
            case TpmCcConstants.TPM_CC_Sign:
            {
                using SignInput input = SignInput.ForEcdsa(handle, digest, SessionAlg, pool);
                code = (await TpmCommandExecutor.ExecuteAsync<SignResponse>(tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            case TpmCcConstants.TPM_CC_SignDigest:
            {
                using SignDigestInput input = SignDigestInput.Create(handle, digest, pool);
                code = (await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            default:
            {
                using SignSequenceStartInput input = SignSequenceStartInput.Create(handle, [], pool);
                code = (await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, code, $"{command} on a public-only key has no sensitive portion to authorize (Part 3, clause 5.6, check 1).");
        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Check 1 reads no credential, so it moves no dictionary-attack counter.");
    }

    /// <summary>
    /// The KEYEDHASH arms: <c>TPM2_HMAC()</c>, <c>TPM2_HMAC_Start()</c> and the HMAC arm of <c>TPM2_Sign()</c> on a
    /// public-only HMAC key, and <c>TPM2_Unseal()</c> on a public-only sealed data object, are each refused with
    /// the bare <c>TPM_RC_AUTH_UNAVAILABLE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    /// <param name="command">The command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_HMAC)]
    [DataRow(TpmCcConstants.TPM_CC_HMAC_Start)]
    [DataRow(TpmCcConstants.TPM_CC_Sign)]
    [DataRow(TpmCcConstants.TPM_CC_Unseal)]
    public async Task KeyedHashCommandsOnAPublicOnlyObjectAreRefusedWithAuthUnavailable(TpmCcConstants command)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(KeyedHashCommandsOnAPublicOnlyObjectAreRefusedWithAuthUnavailable)}-{command}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        bool isSealed = command == TpmCcConstants.TPM_CC_Unseal;
        TpmiDhObject handle = await LoadPublicOnlyKeyedHashAsync(tpm, registry, pool, isSealed).ConfigureAwait(false);

        TpmRcConstants code;
        switch(command)
        {
            case TpmCcConstants.TPM_CC_HMAC:
            {
                code = (await HmacKeyHarness.HmacAsync(tpm, registry, pool, handle.Value, MessageBytes, SessionAlg, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            case TpmCcConstants.TPM_CC_HMAC_Start:
            {
                code = (await HmacKeyHarness.HmacStartAsync(tpm, registry, pool, handle.Value, SessionAlg, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            case TpmCcConstants.TPM_CC_Sign:
            {
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
                using SignInput input = SignInput.Create(handle, SHA256.HashData(MessageBytes), TpmAlgIdConstants.TPM_ALG_HMAC, SessionAlg, pool);
                code = (await TpmCommandExecutor.ExecuteAsync<SignResponse>(tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            default:
            {
                using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
                code = (await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(tpm, UnsealInput.ForItem(handle), [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, code, $"{command} on a public-only KEYEDHASH object has no key value to authorize (Part 3, clause 5.6, check 1).");
    }

    /// <summary>
    /// The attestation family with a public-only ECC key at the signing slot — <c>TPM2_Certify()</c>'s
    /// <c>signHandle</c>, <c>TPM2_CertifyCreation()</c>, <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c> and
    /// <c>TPM2_NV_Certify()</c> — is refused with the bare <c>TPM_RC_AUTH_UNAVAILABLE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    /// <param name="command">The attestation command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_Certify)]
    [DataRow(TpmCcConstants.TPM_CC_CertifyCreation)]
    [DataRow(TpmCcConstants.TPM_CC_Quote)]
    [DataRow(TpmCcConstants.TPM_CC_GetTime)]
    [DataRow(TpmCcConstants.TPM_CC_NV_Certify)]
    public async Task AttestationCommandsWithAPublicOnlySignerAreRefusedWithAuthUnavailable(TpmCcConstants command)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(AttestationCommandsWithAPublicOnlySignerAreRefusedWithAuthUnavailable)}-{command}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        TpmiDhObject signer = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, NoDaSigningAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession otherAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmRcConstants code;
        switch(command)
        {
            case TpmCcConstants.TPM_CC_Certify:
            {
                using CertifyInput input = CertifyInput.ForEcdsa(subject.ObjectHandle, signer, Nonce, SessionAlg, pool);
                code = (await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(tpm, input, [otherAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            case TpmCcConstants.TPM_CC_CertifyCreation:
            {
                using CertifyCreationInput input = CertifyCreationInput.ForEcdsa(signer, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, SessionAlg, pool);
                code = (await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(tpm, input, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            case TpmCcConstants.TPM_CC_Quote:
            {
                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(SessionAlg, [0], pool);
                using QuoteInput input = QuoteInput.ForEcdsa(signer, Nonce, SessionAlg, pcrSelection, pool);
                code = (await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(tpm, input, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            case TpmCcConstants.TPM_CC_GetTime:
            {
                using GetTimeInput input = GetTimeInput.ForEcdsa(signer, Nonce, SessionAlg, pool);
                code = (await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(tpm, input, [otherAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            default:
            {
                await DefineAndWriteIndexAsync(tpm, registry, pool, CertifiedIndexHandle).ConfigureAwait(false);
                using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
                using NvCertifyInput input = NvCertifyInput.ForEcdsa(signer, CertifiedIndexHandle, CertifiedIndexHandle, Nonce, SessionAlg, IndexDataSize, 0, pool);
                code = (await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(tpm, input, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, code, $"{command} with a public-only signing key has no sensitive portion to sign with (Part 3, clause 5.6, check 1).");
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>'s ADMIN-role <c>objectHandle</c> slot on a public-only subject is refused with the
    /// bare <c>TPM_RC_AUTH_UNAVAILABLE</c> on the password form and on the session form alike (an HMAC session
    /// at the object slot), the check preceding every session-shape and credential rule.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    /// <param name="isOverSession">Whether the object slot carries an HMAC session (else a password).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task CertifyOfAPublicOnlySubjectIsRefusedWithAuthUnavailable(bool isOverSession)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(CertifyOfAPublicOnlySubjectIsRefusedWithAuthUnavailable)}-{isOverSession}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        TpmiDhObject subject = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, NoDaSigningAttributes).ConfigureAwait(false);
        byte[] subjectName = TranscribeEccName(pool, key, NoDaSigningAttributes);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput input = CertifyInput.ForEcdsa(subject, ak.ObjectHandle, Nonce, SessionAlg, pool);
        TpmRcConstants code;
        if(isOverSession)
        {
            (uint sessionHandle, TpmSession objectSession) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
            try
            {
                using(objectSession)
                {
                    code = (await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                        tpm, input, [objectSession, signAuth], [subjectName, ak.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                }
            }
            finally
            {
                await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        else
        {
            using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
            code = (await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(tpm, input, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, code, "A public-only subject's ADMIN slot has no authorization available (Part 3, clause 5.6, check 1).");
    }

    /// <summary>
    /// <c>TPM2_Decapsulate()</c> on a public-only KEM key, <c>TPM2_Duplicate()</c> of a public-only sealed
    /// object, and <c>TPM2_ActivateCredential()</c> with a public-only object at either slot are each refused
    /// with the bare <c>TPM_RC_AUTH_UNAVAILABLE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    /// <param name="scenario">The command and slot under test.</param>
    [TestMethod]
    [DataRow(PublicOnlyScenario.Decapsulate)]
    [DataRow(PublicOnlyScenario.Duplicate)]
    [DataRow(PublicOnlyScenario.ActivateCredentialActivateHandle)]
    [DataRow(PublicOnlyScenario.ActivateCredentialKeyHandle)]
    public async Task ObjectCommandsOnAPublicOnlyObjectAreRefusedWithAuthUnavailable(PublicOnlyScenario scenario)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ObjectCommandsOnAPublicOnlyObjectAreRefusedWithAuthUnavailable)}-{scenario}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmRcConstants code;
        switch(scenario)
        {
            case PublicOnlyScenario.Decapsulate:
            {
                using CreatePrimaryResponse kemTwin = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
                TpmiDhObject kem = await LoadPublicAreaAsync(tpm, registry, pool, kemTwin.OutPublic, TpmiRhHierarchy.Owner).ConfigureAwait(false);
                byte[] ciphertext = EccPointOf(kemTwin.OutPublic);
                using DecapsulateInput input = DecapsulateInput.Create(kem, ciphertext, pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
                code = (await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            case PublicOnlyScenario.Duplicate:
            {
                TpmiDhObject sealedObject = await LoadPublicOnlyKeyedHashAsync(tpm, registry, pool, isSealed: true).ConfigureAwait(false);
                byte[] objectName = await ReadNameAsync(tpm, registry, pool, sealedObject).ConfigureAwait(false);
                TpmResult<StartAuthSessionResponse> policyResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(policyResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyResult.ResponseCode}'.");
                uint policyHandle;
                using(StartAuthSessionResponse policyStarted = policyResult.Value)
                {
                    policyHandle = policyStarted.SessionHandle.Value;
                }

                try
                {
                    using TpmPolicySession policySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
                    var input = new DuplicateInput(sealedObject.Value, (uint)TpmRh.TPM_RH_NULL);
                    code = (await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
                        tpm, input, [policySession], [objectName, HandleName((uint)TpmRh.TPM_RH_NULL)], pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                }
                finally
                {
                    await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
                }

                break;
            }
            case PublicOnlyScenario.ActivateCredentialActivateHandle:
            {
                using EccKeyMaterial key = EccKeyMaterial.Generate();
                TpmiDhObject activate = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, NoDaSigningAttributes).ConfigureAwait(false);
                using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
                code = await ActivateCredentialCodeAsync(tpm, registry, pool, activate, ek.ObjectHandle).ConfigureAwait(false);
                break;
            }
            default:
            {
                using CreatePrimaryResponse ekTwin = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
                TpmiDhObject ek = await LoadPublicAreaAsync(tpm, registry, pool, ekTwin.OutPublic, TpmiRhHierarchy.Endorsement).ConfigureAwait(false);
                using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
                code = await ActivateCredentialCodeAsync(tpm, registry, pool, ak.ObjectHandle, ek).ConfigureAwait(false);
                break;
            }
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, code, $"{scenario}: a public-only object at an authorized slot has no authorization available (Part 3, clause 5.6, check 1).");
    }

    /// <summary>
    /// <c>TPM2_Create()</c>, <c>TPM2_Load()</c> and <c>TPM2_Import()</c> under a public-only Storage Parent —
    /// a parent whose public area alone was loaded — are refused at the parent's USER-role slot with the bare
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c>, ahead of every rule about the child.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    /// <param name="command">The command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_Create)]
    [DataRow(TpmCcConstants.TPM_CC_Load)]
    [DataRow(TpmCcConstants.TPM_CC_Import)]
    public async Task ChildCommandsUnderAPublicOnlyParentAreRefusedWithAuthUnavailable(TpmCcConstants command)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ChildCommandsUnderAPublicOnlyParentAreRefusedWithAuthUnavailable)}-{command}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parentTwin = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject parent = await LoadPublicAreaAsync(tpm, registry, pool, parentTwin.OutPublic, TpmiRhHierarchy.Owner).ConfigureAwait(false);

        byte[] blob = new byte[64];
        blob.AsSpan().Fill(0x5A);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmRcConstants code;
        switch(command)
        {
            case TpmCcConstants.TPM_CC_Create:
            {
                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(MessageBytes, pool);
                using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
                using CreateInput input = new(parent.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);
                code = (await TpmCommandExecutor.ExecuteAsync<CreateResponse>(tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            case TpmCcConstants.TPM_CC_Load:
            {
                using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(blob, pool);
                using Tpm2bPublic inPublic = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
                using LoadInput input = new(parent.Value, inPrivate, inPublic);
                code = (await TpmCommandExecutor.ExecuteAsync<LoadResponse>(tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
            default:
            {
                using Tpm2bPublic objectPublic = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true, isDuplicable: true);
                byte[] marshaledPublic = new byte[objectPublic.GetSerializedSize()];
                var writer = new TpmWriter(marshaledPublic);
                objectPublic.WriteTo(ref writer);
                using ImportInput input = ImportInput.Create(parent.Value, marshaledPublic, blob, ReadOnlySpan<byte>.Empty, pool);
                code = (await TpmCommandExecutor.ExecuteAsync<ImportResponse>(tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
                break;
            }
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, code, $"{command} under a public-only parent has no parent authorization available (Part 3, clause 5.6, check 1).");
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c> admits a permanent hierarchy alone as its <c>authHandle</c> in this model, so a
    /// public-only object there is refused with <c>TPM_RC_HANDLE</c> before any object could resolve — the
    /// pre-existing scope of the command's arm, pinned as it stands rather than as check 1 would answer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.4</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithAPublicOnlyObjectIsRefusedWithHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PolicySecretWithAPublicOnlyObjectIsRefusedWithHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        TpmiDhObject handle = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, NoDaSigningAttributes).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> policyResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyResult.ResponseCode}'.");
        uint policyHandle;
        using(StartAuthSessionResponse policyStarted = policyResult.Value)
        {
            policyHandle = policyStarted.SessionHandle.Value;
        }

        try
        {
            using PolicySecretInput input = PolicySecretInput.CreateImmediate(handle.Value, policyHandle, pool);
            using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<PolicySecretResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(tpm, input, [objectAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode, "authHandle, handle 1 of Table 146, admits permanent hierarchies alone here, so an object handle is refused with handle-encoded TPM_RC_HANDLE.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Check 1 precedes check 3: a dictionary-attack-protected public-only key while the TPM is in Lockout mode
    /// answers <c>TPM_RC_AUTH_UNAVAILABLE</c>, not <c>TPM_RC_LOCKOUT</c> — the ladder's order is the spec's (the
    /// reference judges lockout first), and the refusal charges nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task PublicOnlyDaProtectedKeyInLockoutIsRefusedWithAuthUnavailableBeforeLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PublicOnlyDaProtectedKeyInLockoutIsRefusedWithAuthUnavailableBeforeLockout), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        TpmiDhObject handle = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, DaProtectedSigningAttributes).ConfigureAwait(false);

        await DriveIntoLockoutAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<TpmDictionaryAttackParameters> lockedOut = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput input = SignInput.ForEcdsa(handle, SHA256.HashData(MessageBytes), SessionAlg, pool);
        TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode, "Check 1 (the sensitive portion is absent) is judged before check 3 (Lockout) (Part 3, clause 5.6).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(lockedOut.Value.LockoutCounter, after.Value.LockoutCounter, "The refusal moves failedTries no further.");
    }

    /// <summary>
    /// A session may not be salted to a public-only key: <c>tpmKey</c> must hold the private part that recovers
    /// the salt, so <c>TPM2_StartAuthSession()</c> answers <c>TPM_RC_HANDLE</c> for it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task StartAuthSessionSaltedToAPublicOnlyKeyIsRefusedWithHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(StartAuthSessionSaltedToAPublicOnlyKeyIsRefusedWithHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse storageTwin = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject tpmKey = await LoadPublicAreaAsync(tpm, registry, pool, storageTwin.OutPublic, TpmiRhHierarchy.Owner).ConfigureAwait(false);

        TpmEccSigningBackend backend = BouncyCastleTpmEccSigningBackend.Create();
        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
            tpmKey.Value, EccPointOf(storageTwin.OutPublic), TpmEccCurveConstants.TPM_ECC_NIST_P256, SessionAlg, SessionAlg,
            backend.GenerateKey, backend.ComputeSharedSecret, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using(salt)
        {
            Assert.IsGreaterThan(0, saltLength, "The host recovers a salt to encrypt to the public point.");
            TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode, "tpmKey, handle 1 of Table 14, cannot recover the salt when public-only, so it is refused with handle-encoded TPM_RC_HANDLE (Part 3, clause 11.1).");
        }
    }

    /// <summary>
    /// The public-key operations a public-only ECC key keeps: <c>TPM2_VerifyDigestSignature()</c> over an
    /// off-TPM signature succeeds with a real ticket, <c>TPM2_VerifySequenceStart()</c>/<c>Update</c>/
    /// <c>VerifySequenceComplete()</c> over a message succeed with a real <c>TPM_ST_MESSAGE_VERIFIED</c> ticket,
    /// <c>TPM2_ReadPublic()</c> answers, and <c>TPM2_FlushContext()</c> releases the object.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PublicOnlyEccKeyVerifiesReadsAndFlushes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PublicOnlyEccKeyVerifiesReadsAndFlushes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        TpmiDhObject handle = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, NoDaSigningAttributes).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);
        byte[] signature = key.Key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        using VerifyDigestSignatureInput digestInput = VerifyDigestSignatureInput.ForEcdsa(handle, digest, signature, SessionAlg, pool);
        TpmResult<VerifyDigestSignatureResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(tpm, digestInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(digestResult.IsSuccess, $"TPM2_VerifyDigestSignature() over a public-only key must succeed, but failed: '{digestResult.ResponseCode}'.");
        using(VerifyDigestSignatureResponse digestVerified = digestResult.Value)
        {
            Assert.IsFalse(digestVerified.Validation.IsNull, "A public-only key under a real hierarchy earns a real ticket.");
        }

        using VerifySequenceStartInput startInput = VerifySequenceStartInput.Create(handle, [], pool);
        TpmResult<VerifySequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_VerifySequenceStart() over a public-only key must succeed, but failed: '{startResult.ResponseCode}'.");
        TpmiDhObject sequence = startResult.Value.SequenceHandle;

        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using SequenceUpdateInput updateInput = SequenceUpdateInput.Create(sequence, MessageBytes, pool);
        TpmResult<SequenceUpdateResponse> updateResult = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(tpm, updateInput, [sequenceAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(updateResult.IsSuccess, $"TPM2_SequenceUpdate() failed: '{updateResult.ResponseCode}'.");

        using TpmPasswordSession completeAuth = TpmPasswordSession.CreateEmpty(pool);
        using VerifySequenceCompleteInput completeInput = VerifySequenceCompleteInput.ForEcdsa(sequence, handle, signature, SessionAlg, pool);
        TpmResult<VerifySequenceCompleteResponse> completeResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(tpm, completeInput, [completeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_VerifySequenceComplete() over a public-only key must succeed, but failed: '{completeResult.ResponseCode}'.");
        using(VerifySequenceCompleteResponse sequenceVerified = completeResult.Value)
        {
            Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, sequenceVerified.Validation.Tag, "The sequence ticket is TPM_ST_MESSAGE_VERIFIED.");
            Assert.IsFalse(sequenceVerified.Validation.IsNull, "A public-only key under a real hierarchy earns a real ticket.");
        }

        byte[] name = await ReadNameAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        Assert.IsTrue(name.AsSpan().SequenceEqual(TranscribeEccName(pool, key, NoDaSigningAttributes)), "TPM2_ReadPublic() answers the transcribed Name.");

        TpmResult<FlushContextResponse> flushResult = await HmacKeyHarness.FlushAsync(tpm, registry, pool, handle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"TPM2_FlushContext() over a public-only key must succeed, but failed: '{flushResult.ResponseCode}'.");
        TpmResult<ReadPublicResponse> afterFlush = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(tpm, ReadPublicInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, afterFlush.ResponseCode, "The flushed transient handle names no loaded object.");
    }

    /// <summary>
    /// <c>TPM2_PolicySigned()</c> with a public-only ECC key as <c>authObject</c> succeeds: the authority's
    /// signature over <c>aHash</c> is made off the TPM with the framework's own ECDSA and verified against the
    /// public point alone, a public-key operation needing no authorization.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.3</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithAPublicOnlyAuthorityKeySucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PolicySignedWithAPublicOnlyAuthorityKeySucceeds), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        TpmiDhObject authority = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, NoDaSigningAttributes).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> policyResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyResult.ResponseCode}'.");
        using StartAuthSessionResponse policyStarted = policyResult.Value;
        uint policyHandle = policyStarted.SessionHandle.Value;
        try
        {
            byte[] nonceTpm = policyStarted.NonceTPM.AsReadOnlySpan().ToArray();
            byte[] policyRef = "public-only authority"u8.ToArray();
            const int Expiration = 0;

            //aHash = H(nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef) (Part 3, clause 23.3), signed off the TPM.
            byte[] aHashInput = new byte[nonceTpm.Length + sizeof(int) + policyRef.Length];
            var writer = new TpmWriter(aHashInput);
            writer.WriteBytes(nonceTpm);
            writer.WriteInt32(Expiration);
            writer.WriteBytes(policyRef);
            byte[] aHash = SHA256.HashData(aHashInput);
            byte[] signature = key.Key.SignHash(aHash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            TpmResult<PolicySignedResponse> result = await tpm.PolicySignedAsync(
                authority.Value, policyHandle, nonceTpm, ReadOnlyMemory<byte>.Empty, policyRef, Expiration, signature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_PolicySigned() over a public-only authority key must succeed (Part 3, clause 23.3), but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c> "uses only the public area of the key": a second simulator's endorsement key is
    /// loaded public-only here, the credential is made to it, and the second simulator — holding the full key —
    /// recovers the secret with <c>TPM2_ActivateCredential()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.5</see>.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialToAPublicOnlyKeyActivatesOnTheSimulatorHoldingTheFullKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator challenger = await CreateOperationalAsync($"{nameof(MakeCredentialToAPublicOnlyKeyActivatesOnTheSimulatorHoldingTheFullKey)}-challenger", pool).ConfigureAwait(false);
        using TpmSimulator holder = await CreateOperationalAsync($"{nameof(MakeCredentialToAPublicOnlyKeyActivatesOnTheSimulatorHoldingTheFullKey)}-holder", pool).ConfigureAwait(false);
        using TpmDevice challengerDevice = TpmDevice.Create(challenger.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using TpmDevice holderDevice = TpmDevice.Create(holder.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(holderDevice, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(holderDevice, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject publicEk = await LoadPublicAreaAsync(challengerDevice, registry, pool, ek.OutPublic, TpmiRhHierarchy.Endorsement).ConfigureAwait(false);

        using MakeCredentialInput makeInput = MakeCredentialInput.Create(publicEk, CredentialSecret, ak.Name.Span, pool);
        TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(challengerDevice, makeInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(makeResult.IsSuccess, $"TPM2_MakeCredential() to a public-only key must succeed (Part 3, clause 12.5), but failed: '{makeResult.ResponseCode}'.");
        using MakeCredentialResponse made = makeResult.Value;

        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(holderDevice, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(activateResult.IsSuccess, $"TPM2_ActivateCredential() on the simulator holding the full key must succeed, but failed: '{activateResult.ResponseCode}'.");
        using ActivateCredentialResponse activated = activateResult.Value;
        Assert.IsTrue(activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret), "The full key recovers the secret the public-only twin wrapped.");
    }

    /// <summary>
    /// <c>TPM2_Encapsulate()</c> on a public-only KEM key — a second simulator's KEM key loaded from its public
    /// area — produces a ciphertext the second simulator, holding the full key, decapsulates to the same shared
    /// secret: encapsulation is a public-key operation needing no authorization.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.10</see>.
    /// </summary>
    [TestMethod]
    public async Task EncapsulateOnAPublicOnlyKemKeyDecapsulatesOnTheSimulatorHoldingTheFullKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator sender = await CreateOperationalAsync($"{nameof(EncapsulateOnAPublicOnlyKemKeyDecapsulatesOnTheSimulatorHoldingTheFullKey)}-sender", pool).ConfigureAwait(false);
        using TpmSimulator holder = await CreateOperationalAsync($"{nameof(EncapsulateOnAPublicOnlyKemKeyDecapsulatesOnTheSimulatorHoldingTheFullKey)}-holder", pool).ConfigureAwait(false);
        using TpmDevice senderDevice = TpmDevice.Create(sender.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using TpmDevice holderDevice = TpmDevice.Create(holder.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse kem = await CreateKemPrimaryAsync(holderDevice, registry, pool).ConfigureAwait(false);
        TpmiDhObject publicKem = await LoadPublicAreaAsync(senderDevice, registry, pool, kem.OutPublic, TpmiRhHierarchy.Owner).ConfigureAwait(false);

        TpmResult<EncapsulateResponse> encapsulateResult = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(senderDevice, EncapsulateInput.ForHandle(publicKem), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(encapsulateResult.IsSuccess, $"TPM2_Encapsulate() on a public-only KEM key must succeed (Part 3, clause 14.10), but failed: '{encapsulateResult.ResponseCode}'.");
        using EncapsulateResponse encapsulated = encapsulateResult.Value;

        using DecapsulateInput decapsulateInput = DecapsulateInput.Create(kem.ObjectHandle, encapsulated.Ciphertext.Ciphertext, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<DecapsulateResponse> decapsulateResult = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(holderDevice, decapsulateInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(decapsulateResult.IsSuccess, $"TPM2_Decapsulate() on the simulator holding the full key must succeed, but failed: '{decapsulateResult.ResponseCode}'.");
        using DecapsulateResponse decapsulated = decapsulateResult.Value;
        Assert.IsTrue(decapsulated.SharedSecret.AsReadOnlySpan().SequenceEqual(encapsulated.SharedSecret.AsReadOnlySpan()), "The full key recovers the shared secret the public-only twin encapsulated.");
    }

    /// <summary>The command-and-slot scenarios <see cref="ObjectCommandsOnAPublicOnlyObjectAreRefusedWithAuthUnavailable"/> drives.</summary>
    internal enum PublicOnlyScenario
    {
        /// <summary><c>TPM2_Decapsulate()</c> on a public-only KEM key.</summary>
        Decapsulate,

        /// <summary><c>TPM2_Duplicate()</c> of a public-only sealed object.</summary>
        Duplicate,

        /// <summary><c>TPM2_ActivateCredential()</c> with a public-only object at <c>activateHandle</c>.</summary>
        ActivateCredentialActivateHandle,

        /// <summary><c>TPM2_ActivateCredential()</c> with a public-only key at <c>keyHandle</c>.</summary>
        ActivateCredentialKeyHandle,
    }

    /// <summary>A P-256 key pair minted by the framework, its coordinates padded to the field width.</summary>
    private sealed class EccKeyMaterial: IDisposable
    {
        /// <summary>Gets the framework key, the off-TPM signing oracle.</summary>
        public ECDsa Key { get; }

        /// <summary>Gets the public point's X coordinate, 32 octets.</summary>
        public byte[] X { get; }

        /// <summary>Gets the public point's Y coordinate, 32 octets.</summary>
        public byte[] Y { get; }

        /// <summary>Initializes the material from the framework key.</summary>
        /// <param name="key">The framework key; owned.</param>
        private EccKeyMaterial(ECDsa key)
        {
            Key = key;
            ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
            X = PadLeft(parameters.Q.X!, P256ComponentSize);
            Y = PadLeft(parameters.Q.Y!, P256ComponentSize);
        }

        /// <summary>Mints a fresh P-256 key pair.</summary>
        /// <returns>The material; the caller disposes it.</returns>
        public static EccKeyMaterial Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

        /// <summary>Releases the framework key.</summary>
        public void Dispose() => Key.Dispose();
    }

    /// <summary>Left-pads an unsigned big-endian integer to a fixed width.</summary>
    /// <param name="value">The integer's octets.</param>
    /// <param name="width">The target width.</param>
    /// <returns>The padded octets.</returns>
    private static byte[] PadLeft(byte[] value, int width)
    {
        byte[] padded = new byte[width];
        value.CopyTo(padded, width - value.Length);

        return padded;
    }

    /// <summary>Creates an operational simulator with the elliptic-curve backend.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool) =>
        HmacKeyHarness.CreateOperationalAsync($"tpm-in-house-public-only-{name}", pool, TestContext.CancellationToken);

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal)
            .Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign)
            .Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest)
            .Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart)
            .Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature)
            .Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature)
            .Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart)
            .Register(TpmCcConstants.TPM_CC_VerifySequenceComplete, TpmResponseCodec.VerifySequenceComplete)
            .Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify)
            .Register(TpmCcConstants.TPM_CC_CertifyCreation, TpmResponseCodec.CertifyCreation)
            .Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote)
            .Register(TpmCcConstants.TPM_CC_GetTime, TpmResponseCodec.GetTime)
            .Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_Decapsulate, TpmResponseCodec.Decapsulate)
            .Register(TpmCcConstants.TPM_CC_Encapsulate, TpmResponseCodec.Encapsulate)
            .Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential)
            .Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential)
            .Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);

    /// <summary>Builds an ECC P-256 ECDSA-SHA-256 signing public area carrying the key's point.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <returns>The public area; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the point transfers to the returned public area, which its owner disposes.")]
    private static Tpm2bPublic BuildEccPublic(BaseMemoryPool pool, EccKeyMaterial key, TpmaObject attributes) =>
        Tpm2bPublic.CreateEccSigningKey(SessionAlg, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), TpmsEccPoint.Create(key.X, key.Y, pool), pool);

    /// <summary>Transcribes the Name the TPM must compute for the key's public area: <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> (TPM 2.0 Library Part 1, clause 13, Table 9).</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <returns>The Name octets.</returns>
    private static byte[] TranscribeEccName(BaseMemoryPool pool, EccKeyMaterial key, TpmaObject attributes)
    {
        using Tpm2bPublic publicArea = BuildEccPublic(pool, key, attributes);
        byte[] marshaled = new byte[publicArea.GetSerializedSize()];
        var writer = new TpmWriter(marshaled);
        publicArea.WriteTo(ref writer);
        byte[] digest = SHA256.HashData(marshaled.AsSpan(sizeof(ushort)));
        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)SessionAlg);
        digest.CopyTo(name, sizeof(ushort));

        return name;
    }

    /// <summary>A permanent handle's Name: its own 4-octet big-endian value (TPM 2.0 Library Part 1, clause 13, Table 9).</summary>
    /// <param name="handle">The permanent handle.</param>
    /// <returns>The Name octets.</returns>
    private static byte[] HandleName(uint handle)
    {
        byte[] name = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(name, handle);

        return name;
    }

    /// <summary>The SEC1 uncompressed point (<c>0x04 ‖ X ‖ Y</c>) an ECC public area carries.</summary>
    /// <param name="publicArea">The public area.</param>
    /// <returns>The encoded point.</returns>
    private static byte[] EccPointOf(Tpm2bPublic publicArea)
    {
        TpmsEccPoint point = publicArea.PublicArea.Unique.Ecc!;
        byte[] encoded = new byte[1 + (2 * P256ComponentSize)];
        encoded[0] = 0x04;
        point.X.AsReadOnlySpan().CopyTo(encoded.AsSpan(1 + P256ComponentSize - point.X.AsReadOnlySpan().Length));
        point.Y.AsReadOnlySpan().CopyTo(encoded.AsSpan(1 + (2 * P256ComponentSize) - point.Y.AsReadOnlySpan().Length));

        return encoded;
    }

    /// <summary>Loads a public-only ECC signing key under the owner hierarchy and returns its handle.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <returns>The loaded handle.</returns>
    private async Task<TpmiDhObject> LoadPublicOnlyEccAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, EccKeyMaterial key, TpmaObject attributes)
    {
        using Tpm2bPublic publicArea = BuildEccPublic(pool, key, attributes);

        return await LoadPublicAreaAsync(tpm, registry, pool, publicArea, TpmiRhHierarchy.Owner).ConfigureAwait(false);
    }

    /// <summary>
    /// Loads a public-only KEYEDHASH object under the owner hierarchy — an HMAC key or a sealed data object, its
    /// <c>unique</c> the off-TPM <c>H_nameAlg(seedValue ‖ value)</c> (TPM 2.0 Library Part 2, clause 12.2.3.1) —
    /// and returns its handle.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="isSealed">Whether to load a sealed data object (else an HMAC key).</param>
    /// <returns>The loaded handle.</returns>
    private async Task<TpmiDhObject> LoadPublicOnlyKeyedHashAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, bool isSealed)
    {
        byte[] seed = new byte[DigestSize];
        seed.AsSpan().Fill(0xC3);
        byte[] value = isSealed ? MessageBytes : Rfc4231Case1Key;
        byte[] message = new byte[seed.Length + value.Length];
        seed.CopyTo(message, 0);
        value.CopyTo(message, seed.Length);
        byte[] unique = SHA256.HashData(message);

        using Tpm2bPublic publicArea = isSealed
            ? Tpm2bPublic.CreateKeyedHashTemplate(SessionAlg, SealedAttributes, TpmsKeyedHashParms.SealedData, default, pool, unique)
            : Tpm2bPublic.CreateKeyedHashTemplate(SessionAlg, HmacKeyAttributes, TpmsKeyedHashParms.Hmac(SessionAlg), default, pool, unique);

        return await LoadPublicAreaAsync(tpm, registry, pool, publicArea, TpmiRhHierarchy.Owner).ConfigureAwait(false);
    }

    /// <summary>Loads a public area alone through <c>TPM2_LoadExternal()</c> — a wire-exact clone of <paramref name="source"/> — under <paramref name="hierarchy"/> and returns the handle.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="source">The public area to load; borrowed, cloned through the wire form.</param>
    /// <param name="hierarchy">The hierarchy the object joins.</param>
    /// <returns>The loaded handle.</returns>
    private async Task<TpmiDhObject> LoadPublicAreaAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, Tpm2bPublic source, TpmiRhHierarchy hierarchy)
    {
        using LoadExternalInput input = LoadExternalInput.PublicOnly(HmacKeyHarness.ClonePublic(source, pool), hierarchy);
        TpmResult<LoadExternalResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_LoadExternal() of the public area failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        return loaded.ObjectHandle;
    }

    /// <summary>Reads an object's Name through <c>TPM2_ReadPublic()</c>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The object.</param>
    /// <returns>The Name octets.</returns>
    private async Task<byte[]> ReadNameAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject handle)
    {
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(tpm, ReadPublicInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadPublic() failed: '{result.ResponseCode}'.");
        using ReadPublicResponse response = result.Value;

        return response.Name.Span.ToArray();
    }

    /// <summary>Creates an empty-auth, dictionary-attack-exempt ECC P-256 signing primary under <paramref name="hierarchy"/>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(hierarchy, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (signing key, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an empty-auth ECC P-256 storage primary under <paramref name="hierarchy"/>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy.</param>
    /// <returns>The response; the caller owns it.</returns>
    private Task<CreatePrimaryResponse> CreateStoragePrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy) =>
        HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken, hierarchy);

    /// <summary>Creates an empty-auth ECC P-256 KEM primary (DHKEM(P-256, HKDF-SHA256)) under the owner hierarchy.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateKemPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccKemKey(TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, SessionAlg, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (KEM key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Issues <c>TPM2_ActivateCredential()</c> over two empty password slots with an arbitrary blob and secret and returns the response code.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="activateHandle">The activate object.</param>
    /// <param name="keyHandle">The credential key.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> ActivateCredentialCodeAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject activateHandle, TpmiDhObject keyHandle)
    {
        byte[] blob = new byte[48];
        blob.AsSpan().Fill(0xB1);
        byte[] secret = new byte[65];
        secret.AsSpan().Fill(0xB2);
        using ActivateCredentialInput input = ActivateCredentialInput.Create(activateHandle, keyHandle, blob, secret, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

        return (await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(tpm, input, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ResponseCode;
    }

    /// <summary>Starts an unbound, unsalted HMAC session carrying an empty authValue and composes the host-side session.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle (to flush) and the composed session (to dispose).</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        //The response owns nothing but nonceTPM, which the session takes over.
        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Defines an Ordinary Index with <see cref="IndexAuth"/> as its authValue and writes <see cref="IndexData"/> into it.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle.</param>
    private async Task DefineAndWriteIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using var auth = Tpm2bAuth.Create(IndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, SessionAlg, IndexAttributes, Tpm2bDigest.Empty, IndexDataSize);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(tpm, defineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace(0x{nvIndex:X8}) failed: '{defineResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(tpm, registry, pool, nvIndex, IndexAuth).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write(0x{nvIndex:X8}) failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_Write()</c> of <see cref="IndexData"/> at offset zero over a password session.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index.</param>
    /// <param name="suppliedAuth">The authorization value supplied for the Index.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(IndexData, pool);
        var input = new NvWriteInput(nvIndex, nvIndex, buffer, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Lowers <c>maxTries</c> to one and drives the TPM into Lockout mode with one wrong-password write against a freshly defined dictionary-attack-protected Index (TPM 2.0 Library Part 1, clause 16.8).</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DriveIntoLockoutAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        const uint LoweredMaxTries = 1;
        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds, TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineAndWriteIndexAsync(tpm, registry, pool, LockoutDriverIndexHandle).ConfigureAwait(false);
        TpmResult<NvWriteResponse> wrongResult = await WriteIndexAsync(tpm, registry, pool, LockoutDriverIndexHandle, WrongIndexAuth).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, "The priming write must fail and count, taking the TPM into Lockout mode.");

        TpmResult<TpmDictionaryAttackParameters> state = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(state.Value.IsLockedOut, "The TPM must be in Lockout mode before the case under proof runs.");
    }
}
