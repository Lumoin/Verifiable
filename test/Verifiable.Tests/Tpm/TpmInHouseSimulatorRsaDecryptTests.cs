using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the password (all-<c>TPM_RS_PW</c>/single-slot) form of <c>TPM2_RSA_Decrypt()</c> against the in-house
/// behavioural <see cref="TpmSimulator"/> through the production command path (<see cref="TpmCommandExecutor"/>
/// with <see cref="RsaDecryptInput"/> and <see cref="TpmResponseCodecExtensions.RsaDecrypt"/>): the private-key
/// operation under a padding scheme selected between the key's own scheme and <c>inScheme</c>, authorized at
/// <c>@keyHandle</c>'s USER slot.
/// </summary>
/// <remarks>
/// Every recovered plaintext is checked against an independent, off-TPM primitive that shares no code with the
/// simulator's own RSA backend: BouncyCastle's <see cref="OaepEncoding"/> for OAEP, the framework
/// <see cref="RSA.Encrypt(byte[], RSAEncryptionPadding)"/> for RSAES, and <see cref="BigInteger.ModPow"/> for the
/// raw scheme
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 14.3, Tables 46/47).
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorRsaDecryptTests
{
    /// <summary>The Name/scheme hash algorithm used throughout unless a case names another.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA modulus size in bits every key in this class uses.</summary>
    private const ushort RsaKeyBits = 2048;

    /// <summary>The RSA modulus width in octets (<c>k</c>) for <see cref="RsaKeyBits"/>.</summary>
    private const int ModulusOctets = RsaKeyBits / 8;

    /// <summary>An RSA decrypt key's real password.</summary>
    private const string KeyPassword = "rsa-decrypt-key-auth";

    /// <summary>The UTF-8 octets of <see cref="KeyPassword"/>.</summary>
    private static byte[] KeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(KeyPassword);

    /// <summary>A wrong guess at <see cref="KeyPassword"/>.</summary>
    private static byte[] WrongKeyPasswordBytes { get; } = [0x11, 0x22, 0x33, 0x44];

    /// <summary>An OAEP label carrying the required terminating zero octet.</summary>
    private static byte[] TestLabelBytes { get; } = [0x54, 0x45, 0x53, 0x54, 0x00];

    /// <summary>The session-salt OAEP label a salted <c>TPM2_StartAuthSession()</c> uses (TPM 2.0 Library Part 1, clause 16.6.13): <c>"SECRET"</c> plus its terminating zero octet.</summary>
    private static byte[] SaltOaepLabelBytes { get; } = [0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x00];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The padding scheme a test drives a decrypt key's own <c>TPMS_RSA_PARMS.scheme</c> or <c>inScheme</c> as, per Table 190's admitted members.</summary>
    internal enum RsaSchemeKind
    {
        /// <summary><c>TPM_ALG_NULL</c> — no scheme (the raw RSAEP/RSADP primitive when selected).</summary>
        Null,

        /// <summary><c>TPM_ALG_RSAES</c> (PKCS#1 v1.5 encryption).</summary>
        RsaEs,

        /// <summary><c>TPM_ALG_OAEP</c> with SHA-256.</summary>
        Oaep
    }

    /// <summary>The shape of a policy session driven at <c>TPM2_RSA_Decrypt()</c>'s USER slot, every shape answering the same posture.</summary>
    internal enum PolicySessionShape
    {
        /// <summary>A real policy session whose digest reproduces the key's own <c>authPolicy</c>.</summary>
        SatisfyingTheKeysAuthPolicy,

        /// <summary>A real policy session latched to a different command code than the key's <c>authPolicy</c> names.</summary>
        LatchedToAnotherCommand,

        /// <summary>A <c>TPM_SE_TRIAL</c> session, which authorizes nothing.</summary>
        Trial
    }

    /// <summary>
    /// OAEP round trip: BouncyCastle <see cref="OaepEncoding"/> encrypts off-TPM to the key's exported modulus
    /// under a label carrying a terminating zero octet, and the empty label, and the TPM recovers the plaintext
    /// byte-exact — including when the plaintext itself begins with zero octets, since "this may include leading
    /// zeros if the original encrypted value contained leading zeros"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    /// <param name="isLabelPresent">Whether the label is <see cref="TestLabelBytes"/> or empty.</param>
    /// <param name="hasLeadingZeroPlaintext">Whether the plaintext begins with zero octets.</param>
    [TestMethod]
    [DataRow(true, false)]
    [DataRow(false, false)]
    [DataRow(true, true)]
    public async Task RsaDecryptOaepRoundTripRecoversThePlaintextByteExact(bool isLabelPresent, bool hasLeadingZeroPlaintext)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(
            nameof(RsaDecryptOaepRoundTripRecoversThePlaintextByteExact) + isLabelPresent + hasLeadingZeroPlaintext, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Oaep(NameAlg), noDa: true).ConfigureAwait(false);
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] label = isLabelPresent ? TestLabelBytes : [];
        byte[] plaintext = hasLeadingZeroPlaintext ? [0x00, 0x00, 0xAA, 0xBB] : [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        byte[] cipherText = EncryptOaepOffTpm(modulus, label, NameAlg, plaintext);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, label).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"OAEP decrypt must succeed, but failed: '{result.ResponseCode}'.");

        using RsaDecryptResponse response = result.Value;
        Assert.AreEqual(plaintext.Length, response.Message.Size, "The recovered message's own size must equal the original plaintext's, leading zeros counted.");
        Assert.IsTrue(plaintext.AsSpan().SequenceEqual(response.Message.Buffer), "The TPM must recover the exact plaintext BouncyCastle encrypted off-TPM, leading zeros included.");
    }

    /// <summary>
    /// RSAES round trip: the framework <see cref="RSA.Encrypt(byte[], RSAEncryptionPadding)"/> (PKCS#1 v1.5)
    /// encrypts off-TPM to the key's exported modulus, and the TPM recovers the plaintext byte-exact — including
    /// when the plaintext itself begins with zero octets, since "this may include leading zeros if the original
    /// encrypted value contained leading zeros"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 43.5; Part 3, clause 14.3.1).
    /// </summary>
    /// <param name="hasLeadingZeroPlaintext">Whether the plaintext begins with zero octets.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RsaDecryptRsaesRoundTripRecoversThePlaintextByteExact(bool hasLeadingZeroPlaintext)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptRsaesRoundTripRecoversThePlaintextByteExact) + hasLeadingZeroPlaintext, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, noDa: true).ConfigureAwait(false);
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] plaintext = hasLeadingZeroPlaintext ? [0x00, 0x00, 0xAA, 0xBB] : [0xAA, 0xBB, 0xCC, 0xDD];
        byte[] cipherText = EncryptPkcs1OffTpm(modulus, plaintext);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"RSAES decrypt must succeed, but failed: '{result.ResponseCode}'.");

        using RsaDecryptResponse response = result.Value;
        Assert.AreEqual(plaintext.Length, response.Message.Size, "The recovered message's own size must equal the original plaintext's, leading zeros counted.");
        Assert.IsTrue(plaintext.AsSpan().SequenceEqual(response.Message.Buffer), "The TPM must recover the exact plaintext the framework encrypted off-TPM, leading zeros included.");
    }

    /// <summary>
    /// The NULL (raw RSADP) scheme: "the TPM will perform a modular exponentiation of ciphertext using the
    /// private exponent" — a random <c>k</c>-wide value below the modulus raised to <c>e</c> off-TPM via
    /// <see cref="BigInteger.ModPow"/> is answered by the TPM as the full <c>k</c>-octet value, leading zeros
    /// included (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptNullSchemeRawRoundTripRecoversTheKWideValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptNullSchemeRawRoundTripRecoversTheKWideValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);
        BigInteger n = ToUnsignedBigInteger(key.OutPublic.PublicArea.Unique.GetRsaModulus());
        uint e = key.OutPublic.PublicArea.Parameters.RsaDetail!.Value.EffectiveExponent;

        //A value with a leading zero octet once encoded to k-wide big-endian, so the round trip also proves the
        //TPM does not strip the leading zero from a raw-scheme answer.
        byte[] value = new byte[ModulusOctets];
        RandomNumberGenerator.Fill(value);
        value[0] = 0x00;
        value[1] &= 0x7F;
        BigInteger m = ToUnsignedBigInteger(value);
        byte[] cipherText = RawEncryptOffTpm(m, e, n);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NULL-scheme decrypt must succeed, but failed: '{result.ResponseCode}'.");

        using RsaDecryptResponse response = result.Value;
        Assert.HasCount(ModulusOctets, response.Message.Buffer.ToArray(), "The raw scheme's answer is always the full k-octet width.");
        Assert.IsTrue(value.AsSpan().SequenceEqual(response.Message.Buffer), "The TPM must recover the exact k-wide value raised off-TPM, leading zeros included.");
    }

    /// <summary>
    /// The known-private-key path: a framework RSA key's full sensitive area (<c>P</c>) is loaded through
    /// <c>TPM2_LoadExternal()</c> under <c>TPM_RH_NULL</c> as an unrestricted RSA decrypt key with a NULL scheme,
    /// and the TPM recovers what the SAME framework key encrypted off-TPM under RSAES — the framework
    /// <see cref="RSA.Decrypt(byte[], RSAEncryptionPadding)"/> cross-checks the TPM's answer
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 12.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptLoadExternalFullRsaKeyRecoversWhatTheFrameworkKeyEncrypted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptLoadExternalFullRsaKeyRecoversWhatTheFrameworkKeyEncrypted), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> loadResult = await LoadFullRsaDecryptKeyAsync(tpm, registry, pool, key, TpmtRsaScheme.Null).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"LoadExternal of the full RSA decrypt key failed: '{loadResult.ResponseCode}'.");
        using LoadExternalResponse loaded = loadResult.Value;

        byte[] plaintext = [0x01, 0x02, 0x03, 0x04, 0x05];
        byte[] cipherText = key.Key.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, loaded.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.RsaEs, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Decrypt over the LoadExternal-loaded key must succeed, but failed: '{result.ResponseCode}'.");

        using RsaDecryptResponse response = result.Value;
        Assert.IsTrue(plaintext.AsSpan().SequenceEqual(response.Message.Buffer), "The TPM must recover the plaintext the framework key encrypted.");

        byte[] frameworkDecrypted = key.Key.Decrypt(cipherText, RSAEncryptionPadding.Pkcs1);
        Assert.IsTrue(plaintext.AsSpan().SequenceEqual(frameworkDecrypted), "The framework key's own decrypt must cross-check the same plaintext (sanity on the oracle itself).");
    }

    /// <summary>
    /// Table 42's nine key-scheme/<c>inScheme</c> cells: NULL/RSAES/OAEP crossed with NULL/RSAES/OAEP either
    /// selects the resulting scheme (decrypting off-TPM) or is refused with <c>TPM_RC_SCHEME</c> at inScheme,
    /// parameter 2 of Table 46
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.2.1, Table 42; reused verbatim by clause 14.3.1). The (Null, Null)
    /// cell's recovered plaintext is additionally compared against a LITERAL k-wide array — a zeroed span of the
    /// modulus width with the last octet <c>7</c> — written directly here rather than through this class's own
    /// fixed-width helper, so the oracle is never self-consistent with a defect in that shared helper.
    /// </summary>
    /// <param name="keyScheme">The decrypt key's own <c>TPMS_RSA_PARMS.scheme</c>.</param>
    /// <param name="inSchemeKind">The command's <c>inScheme</c>.</param>
    /// <param name="isSuccessExpected">Whether the cell selects a scheme (else <c>TPM_RC_SCHEME</c>).</param>
    [TestMethod]
    [DataRow(RsaSchemeKind.Null, RsaSchemeKind.Null, true)]
    [DataRow(RsaSchemeKind.Null, RsaSchemeKind.RsaEs, true)]
    [DataRow(RsaSchemeKind.Null, RsaSchemeKind.Oaep, true)]
    [DataRow(RsaSchemeKind.RsaEs, RsaSchemeKind.Null, true)]
    [DataRow(RsaSchemeKind.RsaEs, RsaSchemeKind.RsaEs, true)]
    [DataRow(RsaSchemeKind.RsaEs, RsaSchemeKind.Oaep, false)]
    [DataRow(RsaSchemeKind.Oaep, RsaSchemeKind.Null, true)]
    [DataRow(RsaSchemeKind.Oaep, RsaSchemeKind.RsaEs, false)]
    [DataRow(RsaSchemeKind.Oaep, RsaSchemeKind.Oaep, true)]
    public async Task RsaDecryptTableFortyTwoSchemeSelectionGridSelectsOrRefusesWithScheme(RsaSchemeKind keyScheme, RsaSchemeKind inSchemeKind, bool isSuccessExpected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaDecryptTableFortyTwoSchemeSelectionGridSelectsOrRefusesWithScheme)}-{keyScheme}-{inSchemeKind}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, ToKeyScheme(keyScheme), noDa: true).ConfigureAwait(false);
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        uint exponent = key.OutPublic.PublicArea.Parameters.RsaDetail!.Value.EffectiveExponent;
        RsaSchemeKind effective = keyScheme == RsaSchemeKind.Null ? inSchemeKind : keyScheme;
        byte[] cipherText = BuildCipherTextForScheme(effective, modulus, exponent);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, ToInScheme(inSchemeKind), ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        if(isSuccessExpected)
        {
            Assert.IsTrue(result.IsSuccess, $"Key scheme '{keyScheme}' + inScheme '{inSchemeKind}' must select and decrypt, but failed: '{result.ResponseCode}'.");
            using RsaDecryptResponse response = result.Value;

            if(keyScheme == RsaSchemeKind.Null && inSchemeKind == RsaSchemeKind.Null)
            {
                //A LITERAL k-wide array, written directly rather than through this class's own fixed-width
                //helper: a fresh zeroed span of the modulus width with the last octet 7, matching the value
                //RawEncryptOffTpm raised.
                byte[] literalExpectedPlaintext = new byte[ModulusOctets];
                literalExpectedPlaintext[^1] = 0x07;
                Assert.IsTrue(
                    literalExpectedPlaintext.AsSpan().SequenceEqual(response.Message.Buffer),
                    "The (Null, Null) cell's recovered plaintext must equal the literal k-wide value 7, built independently of this class's own fixed-width helper.");
            }
        }
        else
        {
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 1), result.ResponseCode, $"Key scheme '{keyScheme}' + inScheme '{inSchemeKind}' is a Table 42 conflict cell.");
        }
    }

    /// <summary>
    /// A bounded in-process contention instrument: 32 concurrently running simulators, each with its own
    /// <c>TPM2_CreatePrimary()</c>'d NULL-scheme decrypt key, share only <see cref="BaseMemoryPool.Shared"/> —
    /// the process-wide house pool singleton every test in this class rents from — while each repeatedly
    /// decrypts the Table 42 (Null, Null) cell's own raw ciphertext (<c>7^e mod n</c>, below the modulus by
    /// construction). Every answer must be <see cref="TpmRcConstants.TPM_RC_SUCCESS"/> carrying the exact
    /// k-wide plaintext, per
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1 ("If no padding is used, the returned value is an unsigned
    /// integer value that is the result of the modular exponentiation of cipherText using the private
    /// exponent") and Part 1, clause 43.2's RSAEP/RSADP requirement <c>0 &lt;= m &lt; n</c>: a pool-buffer
    /// aliasing fault under contention corrupting a modulus or ciphertext octet would surface here as a bare
    /// <c>TPM_RC_VALUE</c> or a wrong recovered plaintext, at a scale the full suite's own contention cannot
    /// reach in one run. The expected plaintext is a LITERAL k-wide array — a zeroed span of the modulus width
    /// with the last octet <c>7</c> — written directly here rather than through this class's own fixed-width
    /// helper, so this oracle is never self-consistent with a defect in that shared helper.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptNullSchemeConcurrentSimulatorsAllSucceedWithTheExactPlaintext()
    {
        const int WorkerCount = 32;
        const int DecryptsPerWorker = 100;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] expectedPlaintext = new byte[ModulusOctets];
        expectedPlaintext[^1] = 0x07;

        async Task RunWorkerAsync(int workerIndex)
        {
            using TpmSimulator simulator = await CreateOperationalAsync(
                $"{nameof(RsaDecryptNullSchemeConcurrentSimulatorsAllSucceedWithTheExactPlaintext)}-{workerIndex}", pool).ConfigureAwait(false);
            using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
            TpmResponseRegistry registry = CreateRegistry();

            using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);
            byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            uint exponent = key.OutPublic.PublicArea.Parameters.RsaDetail!.Value.EffectiveExponent;
            byte[] cipherText = BuildCipherTextForScheme(RsaSchemeKind.Null, modulus, exponent);

            using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);

            for(int cycle = 0; cycle < DecryptsPerWorker; cycle++)
            {
                TpmResult<RsaDecryptResponse> result = await DecryptAsync(
                    tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.IsTrue(
                    result.IsSuccess,
                    $"Worker {workerIndex}, cycle {cycle}: expected TPM_RC_SUCCESS but got '{result.ResponseCode}'. " +
                    $"modulus={Convert.ToHexString(modulus)} cipherText={Convert.ToHexString(cipherText)}.");

                using RsaDecryptResponse response = result.Value;
                Assert.IsTrue(
                    expectedPlaintext.AsSpan().SequenceEqual(response.Message.Buffer),
                    $"Worker {workerIndex}, cycle {cycle}: recovered plaintext did not match the expected k-wide value 7. " +
                    $"modulus={Convert.ToHexString(modulus)} cipherText={Convert.ToHexString(cipherText)}.");
            }
        }

        var workers = new Task[WorkerCount];
        for(int workerIndex = 0; workerIndex < WorkerCount; workerIndex++)
        {
            int capturedWorkerIndex = workerIndex;
            workers[workerIndex] = Task.Run(() => RunWorkerAsync(capturedWorkerIndex), TestContext.CancellationToken);
        }

        await Task.WhenAll(workers).WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The OAEP hash selection: both <c>lhash</c> and the mask-generation function use the selected scheme's own
    /// hash — the key's own OAEP hash when the key's scheme is not NULL — never independently, so a plaintext
    /// BouncyCastle encoded off-TPM under any other combination of the two hashes fails the padding check. That
    /// check is fed by <c>cipherText</c>, <c>label</c>, and the scheme together (TPM 2.0 Library Part 3, clause
    /// 14.3, Table 46's three parameters), so the failure is not a property of any one of them designable
    /// alone — Table 15's closing sentence gives P and N as zero, bare <c>TPM_RC_VALUE</c>, even when one of the
    /// two hashes matches
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.2.1, Table 42; Part 1, clause 43.4).
    /// </summary>
    /// <param name="lhashAlg">The hash algorithm the off-TPM oracle uses for <c>lhash</c>.</param>
    /// <param name="mgfHashAlg">The hash algorithm the off-TPM oracle uses for the mask-generation function.</param>
    /// <param name="isSuccessExpected">Whether the TPM recovers the plaintext (else bare <c>TPM_RC_VALUE</c>).</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA384, TpmAlgIdConstants.TPM_ALG_SHA384, true)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA384, TpmAlgIdConstants.TPM_ALG_SHA256, false)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256, false)]
    public async Task RsaDecryptOaepKeySchemeHashDrivesBothLhashAndMgfOrIsRefusedWithValue(TpmAlgIdConstants lhashAlg, TpmAlgIdConstants mgfHashAlg, bool isSuccessExpected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(
            $"{nameof(RsaDecryptOaepKeySchemeHashDrivesBothLhashAndMgfOrIsRefusedWithValue)}-{lhashAlg}-{mgfHashAlg}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Oaep(TpmAlgIdConstants.TPM_ALG_SHA384), noDa: true).ConfigureAwait(false);
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] plaintext = [0x0A, 0x0B, 0x0C, 0x0D];
        byte[] cipherText = EncryptOaepOffTpmMixedHash(modulus, TestLabelBytes, lhashAlg, mgfHashAlg, plaintext);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, TestLabelBytes).ConfigureAwait(false);

        if(isSuccessExpected)
        {
            Assert.IsTrue(result.IsSuccess, $"lhash '{lhashAlg}' + MGF1 '{mgfHashAlg}', both the key's own SHA-384 scheme hash, must decrypt: '{result.ResponseCode}'.");
            using RsaDecryptResponse response = result.Value;
            Assert.IsTrue(plaintext.AsSpan().SequenceEqual(response.Message.Buffer), "The TPM must recover the exact plaintext BouncyCastle encrypted under the key's own scheme hash for both lhash and MGF1.");
        }
        else
        {
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode, $"lhash '{lhashAlg}' + MGF1 '{mgfHashAlg}' diverging from the key's SHA-384 scheme hash fails the padding check that cipherText, label, and scheme (Table 46) feed jointly, so Table 15's closing sentence gives bare TPM_RC_VALUE, not a fault of one parameter.");
        }
    }

    /// <summary>
    /// A label at decrypt time that does not match the label used at encryption fails the padding check: "If
    /// label is not the same, the decrypt operation is very likely to fail." The check is fed by
    /// <c>cipherText</c>, <c>label</c>, and the scheme together (TPM 2.0 Library Part 3, clause 14.3, Table
    /// 46's three parameters), so it is not a property of <c>label</c> alone — Table 15's closing sentence gives
    /// P and N as zero, bare <c>TPM_RC_VALUE</c>, never an authorization failure, so the DA-protected key's own
    /// <c>TPM_PT_LOCKOUT_COUNTER</c> is left unchanged by it, exactly as a <c>noDA</c> key's is
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1; Part 1, clause 16.8.1).
    /// </summary>
    /// <param name="noDa">Whether the decrypt key is exempt from dictionary-attack protection.</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task RsaDecryptWrongLabelUnderOaepIsRefusedWithValue(bool noDa)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptWrongLabelUnderOaepIsRefusedWithValue) + noDa, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Oaep(NameAlg), noDa).ConfigureAwait(false);
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] cipherText = EncryptOaepOffTpm(modulus, TestLabelBytes, NameAlg, [0x01, 0x02]);
        byte[] wrongLabel = [0x4F, 0x54, 0x48, 0x00];
        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, wrongLabel).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode, "A label mismatch under OAEP fails the padding check that cipherText, label, and scheme (Table 46) feed jointly, so Table 15's closing sentence gives bare TPM_RC_VALUE, not a fault of one parameter.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A padding failure must never charge failedTries, DA-protected key or not.");
    }

    /// <summary>
    /// A tampered ciphertext (one flipped bit) fails the OAEP or RSAES padding check immediately, never
    /// deferred: "If the padding checks fail, TPM_RC_VALUE is returned." The check is fed by <c>cipherText</c>,
    /// <c>label</c>, and the scheme together (TPM 2.0 Library Part 3, clause 14.3, Table 46's three
    /// parameters), so it is not a property of <c>cipherText</c> alone — Table 15's closing sentence gives P and
    /// N as zero, bare <c>TPM_RC_VALUE</c>, never an authorization failure, so it never charges
    /// <c>TPM_PT_LOCKOUT_COUNTER</c>, DA protection or not
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1; Part 1, clause 16.8.1).
    /// </summary>
    /// <param name="isOaep">Whether the scheme under test is OAEP (else RSAES).</param>
    /// <param name="noDa">Whether the decrypt key is exempt from dictionary-attack protection.</param>
    [TestMethod]
    [DataRow(true, true)]
    [DataRow(true, false)]
    [DataRow(false, true)]
    [DataRow(false, false)]
    public async Task RsaDecryptTamperedCipherTextIsRefusedWithValue(bool isOaep, bool noDa)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptTamperedCipherTextIsRefusedWithValue) + isOaep + noDa, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtRsaScheme scheme = isOaep ? TpmtRsaScheme.Oaep(NameAlg) : TpmtRsaScheme.RsaEs;
        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, scheme, noDa).ConfigureAwait(false);
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] cipherText = isOaep
            ? EncryptOaepOffTpm(modulus, ReadOnlySpan<byte>.Empty, NameAlg, [0x03, 0x04])
            : EncryptPkcs1OffTpm(modulus, [0x03, 0x04]);
        cipherText[^1] ^= 0x01;
        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode, "A tampered ciphertext fails the padding check that cipherText, label, and scheme (Table 46) feed jointly, so Table 15's closing sentence gives bare TPM_RC_VALUE immediately, not a fault of one parameter.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A padding failure must never charge failedTries, DA-protected key or not.");
    }

    /// <summary>
    /// "The TPM will still verify that label is properly formatted if label is present" for every scheme,
    /// including RSAES and NULL, which use no label at all: a supplied label whose last octet is not zero is
    /// refused <c>TPM_RC_VALUE</c>, parameter-encoded to the same index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.2.1).
    /// </summary>
    /// <param name="isNullScheme">Whether the effective scheme is NULL (else RSAES).</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task RsaDecryptLabelWithNonZeroLastOctetIsRefusedWithValueRegardlessOfScheme(bool isNullScheme)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptLabelWithNonZeroLastOctetIsRefusedWithValueRegardlessOfScheme) + isNullScheme, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtRsaScheme scheme = isNullScheme ? TpmtRsaScheme.Null : TpmtRsaScheme.RsaEs;
        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, scheme, noDa: true).ConfigureAwait(false);
        BigInteger n = ToUnsignedBigInteger(key.OutPublic.PublicArea.Unique.GetRsaModulus());
        uint e = key.OutPublic.PublicArea.Parameters.RsaDetail!.Value.EffectiveExponent;
        byte[] cipherText = isNullScheme
            ? RawEncryptOffTpm(BigInteger.One, e, n)
            : EncryptPkcs1OffTpm(key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(), [0x01]);
        byte[] malformedLabel = [0x01, 0x02];

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, malformedLabel).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 2), result.ResponseCode, "A label without a terminating zero is refused at label, parameter 3 of Table 46, even under a scheme that uses no label.");
    }

    /// <summary>
    /// <c>cipherText.size != k</c> is refused <c>TPM_RC_SIZE</c>, parameter-encoded to the same index for every declared width other than the
    /// modulus width, zero included ("An encrypted RSA data block is the size of the public modulus")
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3, Table 46, NOTE).
    /// </summary>
    /// <param name="widthDelta">The ciphertext width relative to <c>k</c>: -1, 0 (meaning zero octets), or +1.</param>
    [TestMethod]
    [DataRow(-1)]
    [DataRow(0)]
    [DataRow(1)]
    public async Task RsaDecryptCipherTextWidthOtherThanTheModulusIsRefusedWithSize(int widthDelta)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptCipherTextWidthOtherThanTheModulusIsRefusedWithSize) + widthDelta, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);
        int width = widthDelta == 0 ? 0 : ModulusOctets + widthDelta;
        byte[] cipherText = new byte[width];

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), result.ResponseCode, $"A cipherText of {width} octets against a {ModulusOctets}-octet modulus is refused at cipherText, parameter 1 of Table 46.");
    }

    /// <summary>
    /// A <c>k</c>-wide ciphertext numerically equal to or greater than the modulus is refused parameter-encoded
    /// <c>TPM_RC_VALUE</c>: its size field is correct, only its value falls outside the admitted range, which is
    /// exactly Table 2's own <c>TPM_RC_VALUE</c> row — "a parameter does not have one of its allowed values" —
    /// and, unlike a padding-check or backend outcome, is a property of <c>cipherText</c> alone,
    /// <c>TPM2_RSA_Decrypt()</c>'s first parameter (Table 46, index 0)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 5.8.2, Table 2; clause 14.3, Table 46; Part 2, clause 6.6.2, Table 15).
    /// </summary>
    /// <param name="isModulusPlusOne">Whether the value is <c>n + 1</c> (else exactly <c>n</c>).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RsaDecryptCipherTextValueAtOrAboveTheModulusIsRefusedWithParameterEncodedValue(bool isModulusPlusOne)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptCipherTextValueAtOrAboveTheModulusIsRefusedWithParameterEncodedValue) + isModulusPlusOne, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);
        BigInteger n = ToUnsignedBigInteger(key.OutPublic.PublicArea.Unique.GetRsaModulus());
        BigInteger value = isModulusPlusOne ? n + BigInteger.One : n;
        byte[] cipherText = ToFixedUnsignedBigEndian(value, ModulusOctets);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "A k-wide ciphertext value at or above the modulus is designated to cipherText, parameter 1 of Table 46, not bare.");
    }

    /// <summary>
    /// "The key referenced by keyHandle shall be an RSA key (TPM_RC_KEY) with restricted CLEAR and decrypt SET
    /// (TPM_RC_ATTRIBUTES)": an ordinary RSA storage parent (restricted, decrypt SET) is refused
    /// <c>TPM_RC_ATTRIBUTES</c>, handle-encoded to the same index, after its own authorization succeeds
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptRestrictedDecryptKeyIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptRestrictedDecryptKeyIsRefusedWithAttributes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, KeyPassword, RsaKeyBits, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary (RSA storage parent) failed: '{parentResult.ResponseCode}'.");
        using CreatePrimaryResponse parent = parentResult.Value;

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, parent.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), result.ResponseCode, "A restricted decrypt key (restricted SET) is refused at keyHandle, handle 1 of Table 46.");
    }

    /// <summary>
    /// An unrestricted RSA signing key has <c>decrypt</c> CLEAR, so it too is refused
    /// <c>TPM_RC_ATTRIBUTES</c>, handle-encoded to the same index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptSigningKeyIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptSigningKeyIsRefusedWithAttributes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput signingInput = CreatePrimaryInput.ForRsaSigningKey(TpmRh.TPM_RH_OWNER, KeyPassword, RsaKeyBits, TpmtRsaScheme.Null, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signingResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signingInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signingResult.IsSuccess, $"CreatePrimary (RSA signing key) failed: '{signingResult.ResponseCode}'.");
        using CreatePrimaryResponse signingKey = signingResult.Value;

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, signingKey.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), result.ResponseCode, "A signing key (decrypt CLEAR) is refused at keyHandle, handle 1 of Table 46.");
    }

    /// <summary>
    /// "The key referenced by keyHandle shall be an RSA key" — an ECC key at <c>@keyHandle</c> is refused
    /// <c>TPM_RC_KEY</c>, handle-encoded to the same index, once its own authorization succeeds
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptEccKeyIsRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptEccKeyIsRefusedWithKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput eccInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, KeyPassword, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(NameAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> eccResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, eccInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(eccResult.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{eccResult.ResponseCode}'.");
        using CreatePrimaryResponse eccKey = eccResult.Value;

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, eccKey.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), result.ResponseCode, "An ECC key is refused at keyHandle, handle 1 of Table 46.");
    }

    /// <summary>
    /// A wrong password against an HMAC (KEYEDHASH) object at <c>@keyHandle</c> is refused from the KEYEDHASH
    /// ladder's own authorization — proving it runs BEFORE <c>TPM2_RSA_Decrypt()</c>'s type gate is ever
    /// reached — with the same charged/uncharged distinction a decrypt key's own ladder carries: a DA-protected
    /// HMAC key's wrong password is the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> and advances
    /// <c>TPM_PT_LOCKOUT_COUNTER</c> by one, while a <c>noDA</c> HMAC key's is the uncharged session-index-
    /// encoded <c>TPM_RC_BAD_AUTH</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 16.8.7).
    /// </summary>
    /// <param name="isNoDa">Whether the HMAC key is exempt from dictionary-attack protection.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RsaDecryptHmacKeyWithAWrongPasswordIsRefusedFromItsOwnKeyedHashLadder(bool isNoDa)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptHmacKeyWithAWrongPasswordIsRefusedFromItsOwnKeyedHashLadder) + isNoDa, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        uint hmacKeyHandle = await CreateAndLoadHmacKeyAsync(tpm, registry, pool, KeyPasswordBytes, isNoDa).ConfigureAwait(false);
        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(WrongKeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(hmacKeyHandle), wrongAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        TpmRcConstants expectedCode = isNoDa
            ? SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0)
            : SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0);
        Assert.AreEqual(expectedCode, result.ResponseCode, "A wrong password on the HMAC key names the KEYEDHASH ladder's own charged or uncharged code, session-index-encoded.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        if(isNoDa)
        {
            Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A noDA HMAC key's wrong password must not charge failedTries.");
        }
        else
        {
            Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "A DA-protected HMAC key's wrong password charges failedTries exactly once.");
        }
    }

    /// <summary>
    /// Once the KEYEDHASH ladder's own authorization succeeds (the correct password), <c>TPM2_RSA_Decrypt()</c>'s
    /// type gate answers <c>TPM_RC_KEY</c>, handle-encoded to the same index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptHmacKeyWithTheCorrectPasswordIsRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptHmacKeyWithTheCorrectPasswordIsRefusedWithKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        uint hmacKeyHandle = await CreateAndLoadHmacKeyAsync(tpm, registry, pool, KeyPasswordBytes, isNoDa: true).ConfigureAwait(false);

        using TpmPasswordSession correctAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(hmacKeyHandle), correctAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), result.ResponseCode, "An HMAC object at keyHandle, correctly authorized, is refused at keyHandle, handle 1 of Table 46.");
    }

    /// <summary>
    /// A hash sequence context at <c>@keyHandle</c> runs <c>TPM2_SequenceUpdate()</c>'s own USER ladder (the
    /// correct sequence password) and then answers <c>TPM_RC_KEY</c>, handle-encoded to the same index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptHashSequenceIsRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptHashSequenceIsRefusedWithKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using HashSequenceStartInput startInput = HashSequenceStartInput.CreateFromPassword(KeyPassword, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"HashSequenceStart failed: '{startResult.ResponseCode}'.");
        uint sequenceHandle = startResult.Value.SequenceHandle.Value;

        using TpmPasswordSession sequenceAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(sequenceHandle), sequenceAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), result.ResponseCode, "A hash sequence context, correctly authorized, is refused at keyHandle, handle 1 of Table 46.");
    }

    /// <summary>
    /// Check 1: "The public and sensitive portions of the object shall be present on the TPM" — a public-only
    /// RSA decrypt key loaded through <c>TPM2_LoadExternal()</c> is refused bare <c>TPM_RC_AUTH_UNAVAILABLE</c>
    /// ahead of every command-specific rule
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptPublicOnlyKeyIsRefusedWithAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptPublicOnlyKeyIsRefusedWithAuthUnavailable), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> loadResult = await LoadPublicOnlyRsaDecryptKeyAsync(tpm, registry, pool, key, TpmtRsaScheme.Null).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"LoadExternal of the public-only key failed: '{loadResult.ResponseCode}'.");
        using LoadExternalResponse loaded = loadResult.Value;

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, loaded.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode, "A public-only key has no private portion to decrypt with: bare TPM_RC_AUTH_UNAVAILABLE.");
    }

    /// <summary>
    /// Check 1 precedes check 3: a public-only key answers <c>TPM_RC_AUTH_UNAVAILABLE</c> even while the TPM is
    /// in Lockout mode, never <c>TPM_RC_LOCKOUT</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptPublicOnlyKeyInLockoutIsRefusedWithAuthUnavailableNotLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptPublicOnlyKeyInLockoutIsRefusedWithAuthUnavailableNotLockout), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> loadResult = await LoadPublicOnlyRsaDecryptKeyAsync(tpm, registry, pool, key, TpmtRsaScheme.Null).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"LoadExternal of the public-only key failed: '{loadResult.ResponseCode}'.");
        using LoadExternalResponse loaded = loadResult.Value;

        using CreatePrimaryResponse lockoutKey = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: false).ConfigureAwait(false);
        await DriveIntoLockoutAsync(tpm, registry, pool, lockoutKey.ObjectHandle).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, loaded.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode, "Check 1 (no sensitive portion) is judged before check 3 (Lockout).");
    }

    /// <summary>
    /// A wrong password against a DA-protected decrypt key is refused with the session-index-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> and charges <c>TPM_PT_LOCKOUT_COUNTER</c> exactly once
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 16.8.7).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptWrongPasswordOnADaProtectedKeyChargesTheLockoutCounter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptWrongPasswordOnADaProtectedKeyChargesTheLockoutCounter), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: false).ConfigureAwait(false);
        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(WrongKeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, wrongAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), result.ResponseCode, "A wrong password on a DA-protected key is session-index-encoded TPM_RC_AUTH_FAIL.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "A DA-protected key's wrong password charges failedTries exactly once.");
    }

    /// <summary>
    /// A wrong password against a <c>noDA</c> decrypt key is refused with the bare (uncharged) session-index-
    /// encoded <c>TPM_RC_BAD_AUTH</c>, distinct from a DA-protected key's <c>TPM_RC_AUTH_FAIL</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 16.8.7).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptWrongPasswordOnANoDaKeyIsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptWrongPasswordOnANoDaKeyIsBadAuthUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);
        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(WrongKeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, wrongAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "A wrong password on a noDA key is session-index-encoded TPM_RC_BAD_AUTH.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A noDA key's wrong password must not charge failedTries.");
    }

    /// <summary>
    /// Check 3: the TPM in Lockout mode refuses a DA-protected decrypt key with the bare <c>TPM_RC_LOCKOUT</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptLockoutIsRefusedWithLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptLockoutIsRefusedWithLockout), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: false).ConfigureAwait(false);
        await DriveIntoLockoutAsync(tpm, registry, pool, key.ObjectHandle).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode, "The TPM in Lockout mode refuses a DA-protected key with bare TPM_RC_LOCKOUT, even with its correct password.");
    }

    /// <summary>
    /// Check 7.1: a <c>userWithAuth</c>-CLEAR decrypt key refuses a plain password session with
    /// <c>TPM_RC_POLICY_FAIL</c>, session-encoded to the same index — it is the session's shape that is inadmissible, not its credential — even
    /// when the password supplied is correct
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptUserWithAuthClearKeyWithAPasswordIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptUserWithAuthClearKeyWithAPasswordIsRefusedWithPolicyFail), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmaObject attributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN | TpmaObject.NO_DA | TpmaObject.DECRYPT;
        using CreatePrimaryResponse key = await CreateDecryptKeyWithAttributesAsync(tpm, registry, pool, attributes, TpmtRsaScheme.Null, authPolicy: default).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode, "userWithAuth CLEAR admits only a policy session at the keyHandle authorization, session 1 of Table 46, even with the correct password.");
    }

    /// <summary>
    /// <c>TPM2_RSA_Decrypt()</c>'s USER slot, like <c>TPM2_Sign()</c>'s, admits a password or an HMAC session: a
    /// policy session at the slot is refused the authorization type this slot does not accept, bare
    /// <c>TPM_RC_AUTH_TYPE</c>, before any digest is ever compared — whether the session's digest satisfies the
    /// key's <c>authPolicy</c>, is latched to a different command, or is a trial session that authorizes
    /// nothing
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 5.6; Part 1, clause 16.2).
    /// </summary>
    /// <param name="shape">The policy session's shape under test.</param>
    [TestMethod]
    [DataRow(PolicySessionShape.SatisfyingTheKeysAuthPolicy)]
    [DataRow(PolicySessionShape.LatchedToAnotherCommand)]
    [DataRow(PolicySessionShape.Trial)]
    public async Task RsaDecryptPolicySessionAtTheUserSlotIsRefusedWithAuthType(PolicySessionShape shape)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptPolicySessionAtTheUserSlotIsRefusedWithAuthType) + shape, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmCcConstants latchedCommandCode = shape == PolicySessionShape.LatchedToAnotherCommand ? TpmCcConstants.TPM_CC_Sign : TpmCcConstants.TPM_CC_RSA_Decrypt;
        byte[] authPolicy = PolicyCommandCodeDigest(TpmCcConstants.TPM_CC_RSA_Decrypt);
        TpmaObject attributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN | TpmaObject.NO_DA | TpmaObject.DECRYPT;
        using CreatePrimaryResponse key = await CreateDecryptKeyWithAttributesAsync(tpm, registry, pool, attributes, TpmtRsaScheme.Null, authPolicy).ConfigureAwait(false);

        bool isTrial = shape == PolicySessionShape.Trial;
        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, pool, isTrial).ConfigureAwait(false);
        try
        {
            await LatchCommandCodeAsync(tpm, registry, pool, sessionHandle, latchedCommandCode).ConfigureAwait(false);
            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, NameAlg, TestEntropy.NewCounterStream(), pool);

            TpmResult<RsaDecryptResponse> result = await DecryptAsync(
                tpm, registry, pool, key.ObjectHandle, policySession, [key.Name.AsReadOnlyMemory()], new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode, $"A policy session ('{shape}') at TPM2_RSA_Decrypt()'s USER slot is refused bare TPM_RC_AUTH_TYPE.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM_RS_PW</c> authorization at index 0 and a LOADED policy session claiming <c>encrypt</c> at index 1
    /// together succeed: the password slot authorizes <c>@keyHandle</c>, and the handle-less companion behind it
    /// is admitted exactly like an HMAC companion — "a policy authorization session can also be
    /// used for encryption and decryption" — and the response's <c>message</c> is recovered under the POLICY
    /// companion's OWN AES-CFB key, independently recomputed here from the response's own nonces and the (Empty
    /// Buffer) key an unbound, unsalted session carries.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 15.6.1, Table 12, footnote [2]; clause 18</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOverAPasswordSlotAndAPolicyEncryptCompanionRecoversTheMessageUnderTheCompanionsOwnKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOverAPasswordSlotAndAPolicyEncryptCompanionRecoversTheMessageUnderTheCompanionsOwnKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Oaep(NameAlg), noDa: true).ConfigureAwait(false);
        byte[] keyName = key.Name.Span.ToArray();
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] plaintext = [0x21, 0x22, 0x23, 0x24, 0x25];
        byte[] cipherText = EncryptOaepOffTpm(modulus, [], NameAlg, plaintext);

        TpmtSymDef aesCfb = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB);
        var policyInput = new StartAuthSessionInput
        {
            TpmKey = (uint)TpmRh.TPM_RH_NULL,
            Bind = (uint)TpmRh.TPM_RH_NULL,
            NonceCaller = RandomNumberGenerator.GetBytes(32),
            EncryptedSalt = ReadOnlyMemory<byte>.Empty,
            SessionType = TpmSeConstants.TPM_SE_POLICY,
            AuthHash = NameAlg,
            Symmetric = aesCfb
        };
        TpmResult<StartAuthSessionResponse> policyResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, policyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyResult.ResponseCode}'.");
        StartAuthSessionResponse policyStarted = policyResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;
        var policySession = new TpmSession(new TpmHandle(policySessionHandle), policyStarted.NonceTPM, NameAlg, TestEntropy.NewCounterStream(), pool, aesCfb);

        try
        {
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using Tpm2bPublicKeyRsa cipherTextCarrier = Tpm2bPublicKeyRsa.Create(cipherText, pool);
                using Tpm2bData labelCarrier = Tpm2bData.Empty;
                var input = new RsaDecryptInput(key.ObjectHandle, cipherTextCarrier, TpmtRsaDecrypt.Oaep(NameAlg), labelCarrier);
                byte[] parameters = new byte[input.GetSerializedSize() - sizeof(uint)];
                var paramWriter = new TpmWriter(parameters);
                input.WriteParameters(ref paramWriter);

                policySession.RollNonceCaller(pool);

                byte[] cpHashInput = new byte[sizeof(uint) + keyName.Length + parameters.Length];
                var cpHashWriter = new TpmWriter(cpHashInput);
                cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_RSA_Decrypt);
                cpHashWriter.WriteBytes(keyName);
                cpHashWriter.WriteBytes(parameters);
                using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                    cpHashInput, outputByteLength: 32, tag: CryptoTags.Sha256Digest, pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                using TpmPasswordSession keyPassword = TpmPasswordSession.Create(KeyPasswordBytes, pool);
                using Tpm2bAuth? pwHmac = await keyPassword.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] pwBlock = new byte[keyPassword.GetAuthCommandSize()];
                var pwWriter = new TpmWriter(pwBlock);
                keyPassword.WriteAuthCommand(ref pwWriter, pwHmac);

                using Tpm2bAuth? policyHmac = await policySession.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] policyBlock = new byte[policySession.GetAuthCommandSize()];
                var policyWriter = new TpmWriter(policyBlock);
                policySession.WriteAuthCommand(ref policyWriter, policyHmac);

                byte[] authArea = [.. pwBlock, .. policyBlock];

                //Independently captured from the wire block this test itself built, so the response's own
                //decrypted `message` can be recomputed without trusting any session object's internal state.
                var policyBlockReader = new TpmReader(policyBlock);
                _ = policyBlockReader.ReadUInt32();
                byte[] nonceCallerSent = policyBlockReader.ReadBytes(policyBlockReader.ReadUInt16()).ToArray();

                int length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + authArea.Length + parameters.Length;
                byte[] command = new byte[length];
                var writer = new TpmWriter(command);
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_RSA_Decrypt);
                header.WriteTo(ref writer);
                writer.WriteUInt32(key.ObjectHandle.Value);
                writer.WriteUInt32((uint)authArea.Length);
                writer.WriteBytes(authArea);
                writer.WriteBytes(parameters);

                TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(submitResult.IsSuccess, "The simulator must answer a refused command rather than fault.");
                using TpmResponse rawResponse = submitResult.Value;
                byte[] response = rawResponse.AsReadOnlySpan().ToArray();
                var codeReader = new TpmReader(response);
                TpmRcConstants code = (TpmRcConstants)TpmHeader.Parse(ref codeReader).Code;

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"TPM2_RSA_Decrypt() over a password slot and a policy encrypt companion must succeed: '{code}'.");

                byte[] cipherResponseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);

                //The last of both response-session entries (index 0: the PW slot's degenerate empty entry; index
                //1: the policy companion's own) carries the nonceTPM this decrypt is keyed on.
                byte[] nonceTpmReturned = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseNonceTpm(response, outHandleCount: 0, sessionIndex: 1);

                ushort messageLength = BinaryPrimitives.ReadUInt16BigEndian(cipherResponseParameters);
                byte[] cipherMessage = cipherResponseParameters.AsSpan(sizeof(ushort), messageLength).ToArray();

                await TpmParameterEncryption.CfbAsync(
                    HashAlgorithmName.SHA256, 128, ReadOnlyMemory<byte>.Empty, nonceTpmReturned, nonceCallerSent, cipherMessage, false, pool, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    plaintext.AsSpan().SequenceEqual(cipherMessage),
                    "The recovered message must equal the original plaintext, decrypted under the POLICY companion's own AES-CFB key.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, policySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Table 192's <c>#TPM_RC_VALUE</c>: an <c>inScheme</c> selector outside {RSAES, OAEP, NULL} — RSASSA, a
    /// signing scheme — is refused parameter-encoded <c>TPM_RC_VALUE</c> at parse, before the handle even
    /// resolves; <c>inScheme</c> is <c>TPM2_RSA_Decrypt()</c>'s second parameter (Table 46, index 1)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 11.2.4.4, Table 192; Part 3, clause 14.3.2, Table 46).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptInSchemeRsassaIsRefusedWithValueAtParse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptInSchemeRsassaIsRefusedWithValueAtParse), pool).ConfigureAwait(false);
        byte[] inSchemeBody = BuildInSchemeBody(TpmAlgIdConstants.TPM_ALG_RSASSA, includeHash: false, default);

        TpmRcConstants code = await SubmitHandFramedAsync(simulator, pool, TpmSimulatorState.TransientHandleBase, new byte[ModulusOctets], inSchemeBody, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 1), code,
            "Table 46: inScheme is TPM2_RSA_Decrypt()'s second parameter (index 1); an RSASSA selector outside Table 192's admitted set is parameter-encoded TPM_RC_VALUE at parse.");
    }

    /// <summary>
    /// Table 173/77: an OAEP <c>inScheme</c> whose hash algorithm is <c>TPM_ALG_NULL</c> is refused
    /// parameter-encoded <c>TPM_RC_HASH</c> at parse ("If inScheme is used, and the scheme requires a hash
    /// algorithm it may not be TPM_ALG_NULL"); <c>inScheme</c> is <c>TPM2_RSA_Decrypt()</c>'s second parameter
    /// (Table 46, index 1)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1, clause 14.3.2, Table 46).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOaepInSchemeWithHashNullIsRefusedWithHashAtParse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOaepInSchemeWithHashNullIsRefusedWithHashAtParse), pool).ConfigureAwait(false);
        byte[] inSchemeBody = BuildInSchemeBody(TpmAlgIdConstants.TPM_ALG_OAEP, includeHash: true, TpmAlgIdConstants.TPM_ALG_NULL);

        TpmRcConstants code = await SubmitHandFramedAsync(simulator, pool, TpmSimulatorState.TransientHandleBase, new byte[ModulusOctets], inSchemeBody, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), code,
            "Table 46: inScheme is TPM2_RSA_Decrypt()'s second parameter (index 1); an OAEP inScheme with hashAlg TPM_ALG_NULL is parameter-encoded TPM_RC_HASH at parse.");
    }

    /// <summary>
    /// A <c>cipherText</c> declaring 513 octets exceeds Table 194's <c>MAX_RSA_KEY_BYTES</c> bound and is refused
    /// parameter-encoded <c>TPM_RC_SIZE</c> at parse; <c>cipherText</c> is <c>TPM2_RSA_Decrypt()</c>'s first
    /// parameter (Table 46, index 0) — unlike <c>TPM2_RSA_Encrypt()</c>'s own first parameter, this command
    /// carries no NoAuth decrypt-continuation form to conflict with, so its own field position designates
    /// directly
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 11.2.4.6, Table 194; Part 3, clause 14.3.2, Table 46).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptCipherTextOverFiveHundredTwelveOctetsIsRefusedWithSizeAtParse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptCipherTextOverFiveHundredTwelveOctetsIsRefusedWithSizeAtParse), pool).ConfigureAwait(false);
        byte[] inSchemeBody = BuildInSchemeBody(TpmAlgIdConstants.TPM_ALG_NULL, includeHash: false, default);
        byte[] oversizedCipherText = new byte[Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1];

        TpmRcConstants code = await SubmitHandFramedAsync(simulator, pool, TpmSimulatorState.TransientHandleBase, oversizedCipherText, inSchemeBody, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
            "Table 46: cipherText is TPM2_RSA_Decrypt()'s first parameter (index 0); a 513-octet cipherText exceeding MAX_RSA_KEY_BYTES is parameter-encoded TPM_RC_SIZE at parse.");
    }

    /// <summary>
    /// An octet after every declared field has been consumed leaves <c>Remaining != 0</c>, refused bare
    /// <c>TPM_RC_SIZE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 5.8.2, Table 2).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptATrailingOctetIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptATrailingOctetIsRefusedWithSize), pool).ConfigureAwait(false);
        byte[] inSchemeBody = BuildInSchemeBody(TpmAlgIdConstants.TPM_ALG_NULL, includeHash: false, default);

        TpmRcConstants code = await SubmitHandFramedAsync(
            simulator, pool, TpmSimulatorState.TransientHandleBase, new byte[ModulusOctets], inSchemeBody, ReadOnlyMemory<byte>.Empty, hasTrailingOctet: true).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A trailing octet after every declared field is bare TPM_RC_SIZE.");
    }

    /// <summary>
    /// Table 46's tag column carries no <c>TPM_ST_NO_SESSIONS</c> branch — authorization is unconditionally
    /// required, so a <c>TPM_ST_NO_SESSIONS</c> frame is refused with <c>TPM_RC_AUTH_MISSING</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3, Table 46).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptNoSessionsIsRefusedWithAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptNoSessionsIsRefusedWithAuthMissing), pool).ConfigureAwait(false);
        byte[] inSchemeBody = BuildInSchemeBody(TpmAlgIdConstants.TPM_ALG_NULL, includeHash: false, default);
        using IMemoryOwner<byte> commandOwner = FrameRsaDecryptNoSessionsCommand(
            pool, TpmSimulatorState.TransientHandleBase, new byte[ModulusOctets], inSchemeBody, ReadOnlySpan<byte>.Empty, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");
        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, "TPM_ST_NO_SESSIONS on TPM2_RSA_Decrypt() is TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// Table 49 (Part 2, clause 9.3) admits only the transient and persistent handle ranges for a
    /// <c>TPMI_DH_OBJECT</c> — no <c>+</c> extends it to a permanent handle — so <c>TPM_RH_NULL</c> at
    /// <c>@keyHandle</c> is refused <c>TPM_RC_VALUE</c>, handle-encoded to the same index, judged by the range gate before the resolver — and
    /// so before any session is ever authorized
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 14.3, Table 46).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptTpmRhNullHandleIsRefusedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptTpmRhNullHandleIsRefusedWithValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue((uint)TpmRh.TPM_RH_NULL), keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode, "TPM_RH_NULL is outside the transient/persistent ranges Table 49 admits for a TPMI_DH_OBJECT.");
    }

    /// <summary>
    /// <c>keyHandle</c> is <c>TPM2_RSA_Decrypt()</c>'s sole handle (index 0, TPM 2.0 Library Part 3, Table 46); a
    /// well-formed TRANSIENT-range value passes Table 49's range gate but resolves to nothing loaded, refused
    /// <c>TPM_RC_REFERENCE_H0</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 5.4, step 2.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptUnloadedTransientHandleAnswersReferenceH0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptUnloadedTransientHandleAnswersReferenceH0), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(TpmHandleRanges.TRANSIENT_FIRST), keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_H0, result.ResponseCode,
            "keyHandle is TPM2_RSA_Decrypt()'s sole handle (index 0); an untouched TRANSIENT-range handle names nothing loaded, TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
    }

    /// <summary>
    /// A persistent decrypt key decrypts successfully; once its owner hierarchy is disabled through
    /// <c>TPM2_HierarchyControl()</c>, the same persistent handle resolves to nothing —
    /// <c>TPM_RC_HANDLE</c>, handle-encoded to the same index, the resolver's answer, not an eviction
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.2.1; Part 2, clause 9.3, Table 49).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptPersistentKeySucceedsThenDisabledHierarchyIsRefusedWithHandle()
    {
        const uint DisabledHierarchyPersistentHandle = 0x8100_1DD1;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptPersistentKeySucceedsThenDisabledHierarchyIsRefusedWithHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);
        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, DisabledHierarchyPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        using TpmPasswordSession keyAuthWhileEnabled = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> decryptedWhileEnabled = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(DisabledHierarchyPersistentHandle), keyAuthWhileEnabled, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(decryptedWhileEnabled.IsSuccess, $"The persistent key must decrypt while its hierarchy is enabled: '{decryptedWhileEnabled.ResponseCode}'.");
        decryptedWhileEnabled.Value.Dispose();

        await SetOwnerHierarchyEnabledAsync(tpm, registry, pool, TpmiYesNo.No).ConfigureAwait(false);

        using TpmPasswordSession keyAuthWhileDisabled = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> decryptedWhileDisabled = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(DisabledHierarchyPersistentHandle), keyAuthWhileDisabled, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), decryptedWhileDisabled.ResponseCode, "The disabled hierarchy's persistent object resolves to nothing (Part 3, clause 24.2.1).");
    }

    /// <summary>
    /// A persistent RSA decrypt key at <c>@keyHandle</c> resolves and decrypts exactly as a transient one does
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptPersistentDecryptKeySucceeds()
    {
        const uint PersistentHandle = 0x8100_1DD0;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptPersistentDecryptKeySucceeds), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);
        var evictInput = new EvictControlInput(TpmRh.TPM_RH_OWNER, key.ObjectHandle.Value, PersistentHandle);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<EvictControlResponse> evictResult = await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, evictInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(evictResult.IsSuccess, $"EvictControl (persist) failed: '{evictResult.ResponseCode}'.");

        BigInteger n = ToUnsignedBigInteger(key.OutPublic.PublicArea.Unique.GetRsaModulus());
        uint e = key.OutPublic.PublicArea.Parameters.RsaDetail!.Value.EffectiveExponent;
        byte[] value = ToFixedUnsignedBigEndian(new BigInteger(999), ModulusOctets);
        byte[] cipherText = RawEncryptOffTpm(ToUnsignedBigInteger(value), e, n);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(PersistentHandle), keyAuth, null, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Decrypt over a persistent handle must succeed, but failed: '{result.ResponseCode}'.");

        using RsaDecryptResponse response = result.Value;
        Assert.IsTrue(value.AsSpan().SequenceEqual(response.Message.Buffer), "A persistent decrypt key must decrypt exactly as its transient twin does.");
    }

    /// <summary>
    /// A command sent before <c>TPM2_Startup()</c> is answered with <c>TPM_RC_INITIALIZE</c>; the command's own
    /// rules are never reached
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 9.3).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptPreStartupIsRefusedWithInitialize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator($"tpm-in-house-rsa-decrypt-{nameof(RsaDecryptPreStartupIsRefusedWithInitialize)}", rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase), keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, result.ResponseCode, "Before TPM2_Startup() the TPM answers TPM_RC_INITIALIZE.");
    }

    /// <summary>
    /// In Failure Mode the TPM answers <c>TPM_RC_FAILURE</c> to every command but the few the mode admits
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 9.4).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptFailureModeIsRefusedWithFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator($"tpm-in-house-rsa-decrypt-{nameof(RsaDecryptFailureModeIsRefusedWithFailure)}",selfTest: TpmSelfTestBehavior.Fails, rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        TpmRcConstants selfTestCode = await SubmitSelfTestAsync(simulator, pool).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode, "A failing self-test enters Failure Mode.");

        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase), keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, result.ResponseCode, "In Failure Mode TPM2_RSA_Decrypt() is TPM_RC_FAILURE.");
    }

    /// <summary>
    /// A simulator constructed without an RSA backend answers bare <c>TPM_RC_COMMAND_CODE</c> at parse, never a
    /// fault from the effect
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 5.8.2, Table 2).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptNoRsaBackendIsRefusedWithCommandCode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator($"tpm-in-house-rsa-decrypt-{nameof(RsaDecryptNoRsaBackendIsRefusedWithCommandCode)}", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase), keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_CODE, result.ResponseCode, "A simulator with no RSA backend answers bare TPM_RC_COMMAND_CODE.");
    }

    /// <summary>
    /// The pool balance across a parse refusal (an over-wide cipherText), a transition refusal (a restricted
    /// key, ATTRIBUTES), an effect refusal (a tampered ciphertext, VALUE) and a success is unchanged: every
    /// refusal path and every success path returns every carrier it rented
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptThePoolStaysBalancedAcrossAParseATransitionAnEffectRefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptThePoolStaysBalancedAcrossAParseATransitionAnEffectRefusalAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);

        //The ATTRIBUTES leg's restricted key is minted here, alongside the decrypt key, so both keys' own loaded
        //carriers are already outstanding when the baseline is captured below: a key loaded after the baseline
        //would keep its own carriers outstanding for the rest of the test while it stays loaded, which is not a
        //leak but would misread as one against a baseline taken before it existed.
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, KeyPassword, RsaKeyBits, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary (RSA storage parent) failed: '{parentResult.ResponseCode}'.");
        using CreatePrimaryResponse parent = parentResult.Value;

        long baseline = trackingPool.OutstandingCount;

        //Parse refusal: an over-wide cipherText — hand-framed, since RsaDecryptInput's own Tpm2bPublicKeyRsa carrier enforces the same 512-octet bound client-side and could never construct the oversized wire value under test.
        byte[] nullInSchemeBody = BuildInSchemeBody(TpmAlgIdConstants.TPM_ALG_NULL, includeHash: false, default);
        TpmRcConstants parseRefusedCode = await SubmitHandFramedAsync(
            simulator, pool, key.ObjectHandle.Value, new byte[Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1], nullInSchemeBody, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), parseRefusedCode,
            "Table 46: cipherText is TPM2_RSA_Decrypt()'s first parameter (index 0); the oversized cipherText must be refused with parameter-encoded TPM_RC_SIZE at parse.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A parse refusal must return every carrier it rented.");

        //Transition refusal: the restricted decrypt key minted above, ATTRIBUTES.
        using(TpmPasswordSession parentAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool))
        {
            TpmResult<RsaDecryptResponse> transitionRefused = await DecryptAsync(
                tpm, registry, pool, parent.ObjectHandle, parentAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), transitionRefused.ResponseCode, "The restricted key must be refused with ATTRIBUTES.");
        }
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A transition refusal must return every carrier it rented.");

        //Effect refusal: a tampered ciphertext, VALUE.
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] tampered = EncryptPkcs1OffTpm(modulus, [0x05, 0x06]);
        tampered[^1] ^= 0x01;
        using(TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool))
        {
            TpmResult<RsaDecryptResponse> effectRefused = await DecryptAsync(
                tpm, registry, pool, key.ObjectHandle, keyAuth, null, tampered, TpmtRsaDecrypt.RsaEs, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, effectRefused.ResponseCode, "The tampered ciphertext must be refused with VALUE.");
        }
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "An effect refusal must return every carrier it rented.");

        //Success.
        BigInteger n = ToUnsignedBigInteger(modulus);
        uint e = key.OutPublic.PublicArea.Parameters.RsaDetail!.Value.EffectiveExponent;
        byte[] value = ToFixedUnsignedBigEndian(new BigInteger(42), ModulusOctets);
        byte[] cipherText = RawEncryptOffTpm(ToUnsignedBigInteger(value), e, n);
        using(TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool))
        {
            TpmResult<RsaDecryptResponse> success = await DecryptAsync(
                tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(success.IsSuccess, $"The final decrypt must succeed, but failed: '{success.ResponseCode}'.");
            success.Value.Dispose();
        }
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A success must return every carrier it rented once the response is disposed.");
    }

    /// <summary>
    /// "If an unrestricted tpmKey is used for salted session generation, then the encapsulated salt may be
    /// recoverable by a user or attacker that can call a decryption primitive (e.g., TPM2_RSA_Decrypt() or
    /// TPM2_ECDH_ZGen()). Users are urged to only use restricted keys for salted sessions.": an unrestricted
    /// decrypt key admitted as a salted <c>TPM2_StartAuthSession()</c>'s <c>tpmKey</c> — an unrestricted
    /// <c>tpmKey</c> was deprecated for this purpose in TPM 2.0 version 185 (TPM 2.0 Library Part 0, clause
    /// 3.1.4.3) but the TPM still admits it here — then answers <c>TPM2_RSA_Decrypt()</c> over that very same
    /// <c>encryptedSalt</c> byte-exact
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 16.6.14).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOnAnUnrestrictedSaltedSessionKeyRecoversTheSaltByteExact()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOnAnUnrestrictedSaltedSessionKeyRecoversTheSaltByteExact), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;
        ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
            tpmKeyHandle, modulus, TpmsRsaParms.DefaultExponent, NameAlg, NameAlg, rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted, unrestricted tpmKey) must succeed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse started = startResult.Value;
            await FlushIfPresentAsync(tpm, registry, pool, started.SessionHandle.Value).ConfigureAwait(false);

            using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
            TpmResult<RsaDecryptResponse> decryptResult = await DecryptAsync(
                tpm, registry, pool, tpmKey.ObjectHandle, keyAuth, null, startInput.EncryptedSalt, TpmtRsaDecrypt.Oaep(NameAlg), SaltOaepLabelBytes).ConfigureAwait(false);
            Assert.IsTrue(decryptResult.IsSuccess, $"TPM2_RSA_Decrypt() over the unrestricted salt key must succeed: '{decryptResult.ResponseCode}'.");

            using RsaDecryptResponse decrypted = decryptResult.Value;
            Assert.IsTrue(
                salt.Memory.Span[..saltLength].SequenceEqual(decrypted.Message.Buffer),
                "TPM2_RSA_Decrypt() must recover exactly the salt this same session's own encryptedSalt encapsulates.");
        }
    }

    /// <summary>
    /// The restricted attribute is what protects a restricted salt key against
    /// <see cref="RsaDecryptOnAnUnrestrictedSaltedSessionKeyRecoversTheSaltByteExact"/>'s recovery: the same
    /// salted-session recipe against a restricted RSA storage parent — <c>userWithAuth</c> SET, so its USER role
    /// is a password's to satisfy — still starts the session successfully, but <c>TPM2_RSA_Decrypt()</c> over
    /// the identical <c>encryptedSalt</c>, its authorization passed, answers <c>TPM_RC_ATTRIBUTES</c>, handle-encoded to the same index: "Users
    /// are urged to only use restricted keys for salted sessions."
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 16.6.14; Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOnARestrictedSaltedSessionKeyIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOnARestrictedSaltedSessionKeyIsRefusedWithAttributes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, KeyPassword, RsaKeyBits, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary (RSA storage parent) failed: '{parentResult.ResponseCode}'.");
        using CreatePrimaryResponse parent = parentResult.Value;

        ReadOnlyMemory<byte> modulus = parent.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int _) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
            parent.ObjectHandle.Value, modulus, TpmsRsaParms.DefaultExponent, NameAlg, NameAlg, rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted, restricted storage-parent tpmKey) must succeed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse started = startResult.Value;
            await FlushIfPresentAsync(tpm, registry, pool, started.SessionHandle.Value).ConfigureAwait(false);

            using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
            TpmResult<RsaDecryptResponse> decryptResult = await DecryptAsync(
                tpm, registry, pool, parent.ObjectHandle, keyAuth, null, startInput.EncryptedSalt, TpmtRsaDecrypt.Oaep(NameAlg), SaltOaepLabelBytes).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), decryptResult.ResponseCode,
                "The restricted attribute, not authorization, is what refuses TPM2_RSA_Decrypt() on the salted session's restricted tpmKey.");
        }
    }

    /// <summary>
    /// The standard endorsement key's salt is doubly protected: its USER role is policy-only (<c>userWithAuth</c>
    /// CLEAR), so a password at <c>@keyHandle</c> is refused <c>TPM_RC_POLICY_FAIL</c> by the authorization
    /// ladder's check 7.1 before the restricted attribute is ever judged — the same salted-session recipe
    /// against the EK starts the session successfully, and <c>TPM2_RSA_Decrypt()</c> over the identical
    /// <c>encryptedSalt</c> never reaches the command's own rules
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 5.6; Part 1, clause 16.6.14).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOnTheEndorsementKeySaltWithAPasswordIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOnTheEndorsementKeySaltWithAPasswordIsRefusedWithPolicyFail), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput ekInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> ekResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, ekInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(ekResult.IsSuccess, $"CreatePrimary (standard RSA EK) failed: '{ekResult.ResponseCode}'.");
        using CreatePrimaryResponse ek = ekResult.Value;
        uint ekHandle = ek.ObjectHandle.Value;

        ReadOnlyMemory<byte> modulus = ek.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int _) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
            ekHandle, modulus, TpmsRsaParms.DefaultExponent, NameAlg, NameAlg, rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted, restricted EK tpmKey) must succeed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse started = startResult.Value;
            await FlushIfPresentAsync(tpm, registry, pool, started.SessionHandle.Value).ConfigureAwait(false);

            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<RsaDecryptResponse> decryptResult = await DecryptAsync(
                tpm, registry, pool, TpmiDhObject.FromValue(ekHandle), keyAuth, null, startInput.EncryptedSalt, TpmtRsaDecrypt.Oaep(NameAlg), SaltOaepLabelBytes).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), decryptResult.ResponseCode,
                "A password at the EK's policy-only USER slot is refused TPM_RC_POLICY_FAIL (check 7.1) ahead of the restricted-attribute rule.");
        }
    }

    /// <summary>
    /// An OAEP-decrypt backend that throws is collapsed to the same bare <c>TPM_RC_VALUE</c> a documented padding
    /// failure answers, never an unhandled exception out of the executor: every internal decryption failure
    /// answers <c>TPM_RC_VALUE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptThrowingOaepBackendIsRefusedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmRsaSigningBackend faultingBackend = MicrosoftTpmRsaSigningBackend.Create() with { DecryptOaep = ThrowingDecryptOaep };
        using TpmSimulator simulator = await CreateOperationalWithRsaBackendAsync(nameof(RsaDecryptThrowingOaepBackendIsRefusedWithValue), pool, faultingBackend).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Oaep(NameAlg), noDa: true).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode, "An OAEP-decrypt backend throw collapses to bare TPM_RC_VALUE, never an unhandled exception.");
    }

    /// <summary>
    /// A raw-scheme (<c>TPM_ALG_NULL</c>) backend answer narrower than the modulus width is a result the scheme
    /// does not admit, and every internal decryption failure answers bare <c>TPM_RC_VALUE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptShortRawBackendAnswerIsRefusedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmRsaSigningBackend faultingBackend = MicrosoftTpmRsaSigningBackend.Create() with { DecryptRaw = ShortDecryptRaw };
        using TpmSimulator simulator = await CreateOperationalWithRsaBackendAsync(nameof(RsaDecryptShortRawBackendAnswerIsRefusedWithValue), pool, faultingBackend).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode, "A raw-scheme backend answer narrower than the modulus width is bare TPM_RC_VALUE.");
    }

    /// <summary>
    /// An RSAES backend answer one octet wider than the modulus width is a result the scheme does not admit, and
    /// every internal decryption failure answers bare <c>TPM_RC_VALUE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOverWideRsaesBackendAnswerIsRefusedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmRsaSigningBackend faultingBackend = MicrosoftTpmRsaSigningBackend.Create() with { DecryptRsaes = OverWideDecryptRsaes };
        using TpmSimulator simulator = await CreateOperationalWithRsaBackendAsync(nameof(RsaDecryptOverWideRsaesBackendAnswerIsRefusedWithValue), pool, faultingBackend).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, noDa: true).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        TpmRcConstants actualCode = result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, actualCode, "An RSAES backend answer wider than the modulus width must be refused bare TPM_RC_VALUE, a result the scheme does not admit.");
    }

    /// <summary>
    /// An RSAES backend answer grossly past <see cref="Tpm2bPublicKeyRsa.MaxRsaKeyBytes"/> is a result the
    /// scheme does not admit, and every internal decryption failure answers bare <c>TPM_RC_VALUE</c>, never an
    /// unhandled exception out of the executor
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOversizedRsaesBackendAnswerIsRefusedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmRsaSigningBackend faultingBackend = MicrosoftTpmRsaSigningBackend.Create() with { DecryptRsaes = OversizedDecryptRsaes };
        using TpmSimulator simulator = await CreateOperationalWithRsaBackendAsync(nameof(RsaDecryptOversizedRsaesBackendAnswerIsRefusedWithValue), pool, faultingBackend).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, noDa: true).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        TpmRcConstants actualCode = result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, actualCode, "An RSAES backend answer past MaxRsaKeyBytes must be refused bare TPM_RC_VALUE, never an unhandled exception.");
    }

    /// <summary>A <see cref="TpmRsaOaepDecryptDelegate"/> that always throws, modelling an internal backend fault during OAEP decryption.</summary>
    /// <param name="privateKey">Unused.</param>
    /// <param name="ciphertext">Unused.</param>
    /// <param name="label">Unused.</param>
    /// <param name="lhashAlg">Unused.</param>
    /// <param name="mgfHashAlg">Unused.</param>
    /// <param name="pool">Unused.</param>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>Never returns; always throws.</returns>
    private static ValueTask<IMemoryOwner<byte>?> ThrowingDecryptOaep(
        ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> ciphertext, ReadOnlyMemory<byte> label,
        TpmAlgIdConstants lhashAlg, TpmAlgIdConstants mgfHashAlg, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("Simulated OAEP-decrypt backend fault.");

    /// <summary>A <see cref="TpmRsaPrivateOperationDelegate"/> that answers one octet narrower than the modulus width, modelling a malformed raw-scheme backend answer.</summary>
    /// <param name="privateKey">Unused.</param>
    /// <param name="value">Unused.</param>
    /// <param name="pool">The pool the narrow answer is rented from.</param>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>A pooled buffer one octet narrower than <see cref="ModulusOctets"/>.</returns>
    private static ValueTask<IMemoryOwner<byte>> ShortDecryptRaw(
        ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> value, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(ModulusOctets - 1);
        RandomNumberGenerator.Fill(owner.Memory.Span);

        return ValueTask.FromResult(owner);
    }

    /// <summary>A <see cref="TpmRsaEsDecryptDelegate"/> that answers one octet wider than the modulus width, modelling an RSAES backend answer the scheme does not admit.</summary>
    /// <param name="privateKey">Unused.</param>
    /// <param name="ciphertext">Unused.</param>
    /// <param name="pool">The pool the over-wide answer is rented from.</param>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>A pooled buffer one octet wider than <see cref="ModulusOctets"/>.</returns>
    private static ValueTask<IMemoryOwner<byte>?> OverWideDecryptRsaes(
        ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> ciphertext, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(ModulusOctets + 1);
        RandomNumberGenerator.Fill(owner.Memory.Span);

        return ValueTask.FromResult<IMemoryOwner<byte>?>(owner);
    }

    /// <summary>A <see cref="TpmRsaEsDecryptDelegate"/> that answers 600 octets, past <see cref="Tpm2bPublicKeyRsa.MaxRsaKeyBytes"/>, modelling a grossly oversized RSAES backend answer.</summary>
    /// <param name="privateKey">Unused.</param>
    /// <param name="ciphertext">Unused.</param>
    /// <param name="pool">The pool the oversized answer is rented from.</param>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>A 600-octet pooled buffer.</returns>
    private static ValueTask<IMemoryOwner<byte>?> OversizedDecryptRsaes(
        ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> ciphertext, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(600);
        RandomNumberGenerator.Fill(owner.Memory.Span);

        return ValueTask.FromResult<IMemoryOwner<byte>?>(owner);
    }

    /// <summary>An RSA-2048 key pair minted by the framework, its modulus and first prime exported.</summary>
    private sealed class RsaKeyMaterial: IDisposable
    {
        /// <summary>Gets the framework key, the off-TPM decryption oracle.</summary>
        public RSA Key { get; }

        /// <summary>Gets the public modulus, <see cref="ModulusOctets"/> octets.</summary>
        public byte[] Modulus { get; }

        /// <summary>Gets the first prime factor.</summary>
        public byte[] P { get; }

        /// <summary>Initializes the material from the framework key.</summary>
        /// <param name="key">The framework key; owned.</param>
        private RsaKeyMaterial(RSA key)
        {
            Key = key;
            RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);
            Modulus = PadLeft(parameters.Modulus!, ModulusOctets);
            P = PadLeft(parameters.P!, ModulusOctets / 2);
        }

        /// <summary>Mints a fresh RSA-2048 key pair.</summary>
        /// <returns>The material; the caller disposes it.</returns>
        public static RsaKeyMaterial Generate() => new(RSA.Create(RsaKeyBits));

        /// <summary>Releases the framework key and clears the prime.</summary>
        public void Dispose()
        {
            Array.Clear(P);
            Key.Dispose();
        }
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

    /// <summary>Maps a padding-scheme kind to the decrypt key's own <see cref="TpmtRsaScheme"/>.</summary>
    /// <param name="kind">The scheme kind.</param>
    /// <returns>The scheme.</returns>
    private static TpmtRsaScheme ToKeyScheme(RsaSchemeKind kind) => kind switch
    {
        RsaSchemeKind.Null => TpmtRsaScheme.Null,
        RsaSchemeKind.RsaEs => TpmtRsaScheme.RsaEs,
        RsaSchemeKind.Oaep => TpmtRsaScheme.Oaep(NameAlg),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    /// <summary>Maps a padding-scheme kind to the command's <see cref="TpmtRsaDecrypt"/> <c>inScheme</c>.</summary>
    /// <param name="kind">The scheme kind.</param>
    /// <returns>The scheme.</returns>
    private static TpmtRsaDecrypt ToInScheme(RsaSchemeKind kind) => kind switch
    {
        RsaSchemeKind.Null => TpmtRsaDecrypt.Null,
        RsaSchemeKind.RsaEs => TpmtRsaDecrypt.RsaEs,
        RsaSchemeKind.Oaep => TpmtRsaDecrypt.Oaep(NameAlg),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    /// <summary>Builds a ciphertext off-TPM under the effective scheme Table 42 selects, so the decrypt is expected to succeed.</summary>
    /// <param name="effective">The effective (selected) scheme.</param>
    /// <param name="modulus">The key's public modulus.</param>
    /// <param name="exponent">The key's effective public exponent.</param>
    /// <returns>The ciphertext.</returns>
    private static byte[] BuildCipherTextForScheme(RsaSchemeKind effective, byte[] modulus, uint exponent) => effective switch
    {
        RsaSchemeKind.Null => RawEncryptOffTpm(ToUnsignedBigInteger(ToFixedUnsignedBigEndian(new BigInteger(7), ModulusOctets)), exponent, ToUnsignedBigInteger(modulus)),
        RsaSchemeKind.RsaEs => EncryptPkcs1OffTpm(modulus, [0x07]),
        RsaSchemeKind.Oaep => EncryptOaepOffTpm(modulus, ReadOnlySpan<byte>.Empty, NameAlg, [0x07]),
        _ => throw new ArgumentOutOfRangeException(nameof(effective))
    };

    /// <summary>Encrypts off-TPM under OAEP via BouncyCastle's <see cref="OaepEncoding"/>, an independent oracle sharing no code with the simulator's own backend, using the SAME hash for <c>lhash</c> and the mask-generation function.</summary>
    /// <param name="modulus">The public modulus, unsigned big-endian.</param>
    /// <param name="label">The OAEP label, terminating zero included when present.</param>
    /// <param name="hashAlg">The OAEP hash algorithm, used for both <c>lhash</c> and MGF1.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <returns>The ciphertext, exactly <see cref="ModulusOctets"/> octets.</returns>
    private static byte[] EncryptOaepOffTpm(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> label, TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> plaintext) =>
        EncryptOaepOffTpmMixedHash(modulus, label, hashAlg, hashAlg, plaintext);

    /// <summary>Encrypts off-TPM under OAEP via BouncyCastle's four-argument <see cref="OaepEncoding"/> constructor, which admits an <c>lhash</c> algorithm independent of the mask-generation function's — an independent oracle sharing no code with the simulator's own backend.</summary>
    /// <param name="modulus">The public modulus, unsigned big-endian.</param>
    /// <param name="label">The OAEP label, terminating zero included when present.</param>
    /// <param name="lhashAlg">The hash algorithm computing <c>lhash = H(L)</c>.</param>
    /// <param name="mgfHashAlg">The hash algorithm driving MGF1.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <returns>The ciphertext, exactly <see cref="ModulusOctets"/> octets.</returns>
    private static byte[] EncryptOaepOffTpmMixedHash(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> label, TpmAlgIdConstants lhashAlg, TpmAlgIdConstants mgfHashAlg, ReadOnlySpan<byte> plaintext)
    {
        var oaep = new OaepEncoding(new RsaEngine(), ResolveDigest(lhashAlg), ResolveDigest(mgfHashAlg), label.ToArray());
        var publicKey = new RsaKeyParameters(
            isPrivate: false, new Org.BouncyCastle.Math.BigInteger(1, modulus.ToArray()), Org.BouncyCastle.Math.BigInteger.ValueOf(TpmsRsaParms.DefaultExponent));
        oaep.Init(forEncryption: true, publicKey);
        byte[] plaintextBytes = plaintext.ToArray();

        return oaep.ProcessBlock(plaintextBytes, 0, plaintextBytes.Length);
    }

    /// <summary>Maps a TPM hash algorithm identifier to the matching BouncyCastle digest instance, shared by every off-TPM OAEP oracle in this class.</summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <returns>The digest instance.</returns>
    private static IDigest ResolveDigest(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => new Sha1Digest(),
        TpmAlgIdConstants.TPM_ALG_SHA256 => new Sha256Digest(),
        TpmAlgIdConstants.TPM_ALG_SHA384 => new Sha384Digest(),
        TpmAlgIdConstants.TPM_ALG_SHA512 => new Sha512Digest(),
        _ => throw new NotSupportedException($"'{hashAlg}' is not supported by this oracle.")
    };

    /// <summary>Encrypts off-TPM under RSAES (PKCS#1 v1.5) via the framework <see cref="RSA"/>, an independent oracle.</summary>
    /// <param name="modulus">The public modulus, unsigned big-endian.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <returns>The ciphertext, exactly <see cref="ModulusOctets"/> octets.</returns>
    private static byte[] EncryptPkcs1OffTpm(byte[] modulus, byte[] plaintext)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = [0x01, 0x00, 0x01] });

        return rsa.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);
    }

    /// <summary>Computes the raw RSAEP primitive off-TPM: <c>m^e mod n</c>, left-padded to <see cref="ModulusOctets"/> octets, an independent oracle sharing no code with the simulator's own backend.</summary>
    /// <param name="m">The message value.</param>
    /// <param name="e">The public exponent.</param>
    /// <param name="n">The public modulus.</param>
    /// <returns>The ciphertext, exactly <see cref="ModulusOctets"/> octets.</returns>
    private static byte[] RawEncryptOffTpm(BigInteger m, uint e, BigInteger n) =>
        ToFixedUnsignedBigEndian(BigInteger.ModPow(m, e, n), ModulusOctets);

    /// <summary>Reads unsigned big-endian octets as a non-negative <see cref="BigInteger"/>.</summary>
    /// <param name="value">The unsigned big-endian octets.</param>
    /// <returns>The value.</returns>
    private static BigInteger ToUnsignedBigInteger(ReadOnlySpan<byte> value) =>
        new(value, isUnsigned: true, isBigEndian: true);

    /// <summary>
    /// Encodes a non-negative <see cref="BigInteger"/> as exactly <paramref name="width"/> unsigned big-endian
    /// octets, left-padded with zeros — the fixed <c>k</c>-octet field an RSA modulus, ciphertext, and raw
    /// plaintext each occupy (TPM 2.0 Library Part 2, clause 11.2.4.6, Table 194's <c>TPM2B_PUBLIC_KEY_RSA</c>).
    /// <see cref="BigInteger.TryWriteBytes"/> writes only the value's MINIMAL representation, and writes it at
    /// the start of the destination it is handed, so the destination is offset by the padding width: a value
    /// whose leading octet is zero would otherwise land left-aligned and denote the value multiplied by a power
    /// of 256.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <param name="width">The fixed width to produce.</param>
    /// <returns>A new array of exactly <paramref name="width"/> bytes.</returns>
    private static byte[] ToFixedUnsignedBigEndian(BigInteger value, int width)
    {
        int byteCount = value.GetByteCount(isUnsigned: true);
        if(byteCount > width)
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"The value needs {byteCount} octets, which exceeds the fixed width of {width}.");
        }

        byte[] result = new byte[width];
        _ = value.TryWriteBytes(result.AsSpan(width - byteCount), out int _, isUnsigned: true, isBigEndian: true);

        return result;
    }

    /// <summary>Issues <c>TPM2_RSA_Decrypt()</c> through the production command path, owning and releasing the borrowed <c>cipherText</c>/<c>label</c> carriers itself.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="handleNames">The key's Name, required for an HMAC or policy session; <see langword="null"/> for a plain password.</param>
    /// <param name="cipherText">The ciphertext to decrypt.</param>
    /// <param name="inScheme">The command's <c>inScheme</c>.</param>
    /// <param name="label">The label.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<RsaDecryptResponse>> DecryptAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, TpmSessionBase session,
        System.Collections.Generic.IReadOnlyList<ReadOnlyMemory<byte>>? handleNames, ReadOnlyMemory<byte> cipherText, TpmtRsaDecrypt inScheme, ReadOnlyMemory<byte> label)
    {
        using Tpm2bPublicKeyRsa cipherTextCarrier = Tpm2bPublicKeyRsa.Create(cipherText.Span, pool);
        using Tpm2bData labelCarrier = Tpm2bData.Create(label.Span, pool);
        var input = new RsaDecryptInput(keyHandle, cipherTextCarrier, inScheme, labelCarrier);

        return await TpmCommandExecutor.ExecuteAsync<RsaDecryptResponse>(
            tpm, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a <c>CreatePrimary</c>'d unrestricted RSA decrypt key with <see cref="KeyPassword"/>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="scheme">The key's own scheme.</param>
    /// <param name="noDa">Whether the key is exempt from dictionary-attack protection.</param>
    /// <returns>The CreatePrimary response; the caller disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtRsaScheme scheme, bool noDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaDecryptKey(TpmRh.TPM_RH_OWNER, KeyPassword, RsaKeyBits, scheme, pool, noDa);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a <c>CreatePrimary</c>'d RSA decrypt key with an explicit attribute word and authPolicy — the shape <see cref="CreatePrimaryInput.ForRsaDecryptKey"/> cannot express.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The exact <c>TPMA_OBJECT</c> word.</param>
    /// <param name="scheme">The key's own scheme.</param>
    /// <param name="authPolicy">The authorization policy digest, or empty for none.</param>
    /// <returns>The CreatePrimary response; the caller disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateDecryptKeyWithAttributesAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmaObject attributes, TpmtRsaScheme scheme, ReadOnlyMemory<byte> authPolicy)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.WithPassword(KeyPassword, pool);
        using Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningKey(NameAlg, attributes, RsaKeyBits, scheme, ReadOnlySpan<byte>.Empty, pool, authPolicy.Span);
        using var input = new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (custom-attribute RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Loads a framework RSA key's full sensitive area (<c>P</c>) as an unrestricted decrypt key under
    /// <c>TPM_RH_NULL</c>. The object's attributes carry only <c>USER_WITH_AUTH</c>, <c>NO_DA</c> and
    /// <c>DECRYPT</c> — never <c>FIXED_TPM</c>, <c>FIXED_PARENT</c> or <c>restricted</c> — per "The object's
    /// TPMA_OBJECT attributes will be checked according to the rules defined in "TPMA_OBJECT" in TPM 2.0 Part
    /// 2. In particular, fixedTPM, fixedParent, and restricted shall be CLEAR if inPrivate is not the Empty
    /// Buffer"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 12.3.1).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The framework key material.</param>
    /// <param name="scheme">The key's own scheme.</param>
    /// <returns>The raw LoadExternal result; the caller disposes the value on success.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the authValue and sensitive-composite carriers transfers to the TpmtSensitive constructed around them, which the using declaration disposes.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadFullRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, RsaKeyMaterial key, TpmtRsaScheme scheme)
    {
        TpmaObject attributes = TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA | TpmaObject.DECRYPT;
        using Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningKey(NameAlg, attributes, RsaKeyBits, scheme, key.Modulus, pool);
        using TpmtSensitive inPrivate = new(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, TpmuSensitiveComposite.FromRsa(Tpm2bPrivateKeyRsa.Create(key.P, pool)));
        using var input = new LoadExternalInput(inPrivate, inPublic, TpmiRhHierarchy.Null);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Loads a framework RSA key's public area only (no sensitive area) as an unrestricted decrypt key under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The framework key material.</param>
    /// <param name="scheme">The key's own scheme.</param>
    /// <returns>The raw LoadExternal result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<LoadExternalResponse>> LoadPublicOnlyRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, RsaKeyMaterial key, TpmtRsaScheme scheme)
    {
        TpmaObject attributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA | TpmaObject.DECRYPT;
        using Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningKey(NameAlg, attributes, RsaKeyBits, scheme, key.Modulus, pool);
        using var input = new LoadExternalInput(null, inPublic, TpmiRhHierarchy.Owner);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates and loads a password-protected HMAC (KEYEDHASH) key under a fresh RSA storage parent.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The key's authorization value.</param>
    /// <param name="isNoDa">Whether the HMAC key is exempt from dictionary-attack protection.</param>
    /// <returns>The loaded key's transient handle.</returns>
    private async Task<uint> CreateAndLoadHmacKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> password, bool isNoDa)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, null, RsaKeyBits, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary (RSA storage parent) failed: '{parentResult.ResponseCode}'.");
        using CreatePrimaryResponse parent = parentResult.Value;

        using Tpm2bSensitiveCreate hmacSensitive = Tpm2bSensitiveCreate.ForHmacKey(ReadOnlySpan<byte>.Empty, password.Span, pool);
        using Tpm2bPublic hmacTemplate = Tpm2bPublic.CreateHmacKeyTemplate(
            NameAlg, TpmAlgIdConstants.TPM_ALG_SHA256, pool, authPolicy: default, noDa: isNoDa, userWithAuth: true, isDuplicable: false, isRestricted: false, isSensitiveDataOrigin: true);
        using var createInput = new CreateInput(parent.ObjectHandle.Value, hmacSensitive, hmacTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        using var loadInput = new LoadInput(parent.ObjectHandle.Value, created.OutPrivate, created.OutPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (HMAC key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return loaded.ObjectHandle.Value;
    }

    /// <summary>Lowers <c>maxTries</c> to one and drives the TPM into Lockout mode with a single wrong-password decrypt against <paramref name="keyHandle"/>, a DA-protected key.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The DA-protected decrypt key to prime the lockout against.</param>
    private async Task DriveIntoLockoutAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle)
    {
        const uint LoweredMaxTries = 1;
        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds, TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(WrongKeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> primingResult = await DecryptAsync(
            tpm, registry, pool, keyHandle, wrongAuth, null, new byte[ModulusOctets], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), primingResult.ResponseCode, "The priming decrypt must fail and count, taking the TPM into Lockout mode.");

        TpmResult<TpmDictionaryAttackParameters> state = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(state.Value.IsLockedOut, "The TPM must be in Lockout mode before the case under proof runs.");
    }

    /// <summary>Computes the <c>TPM2_PolicyCommandCode(commandCode)</c> policy digest over a fresh session — the minimal USER-role policy a key binds its <c>authPolicy</c> to.</summary>
    /// <param name="commandCode">The command the policy selects.</param>
    /// <returns>The SHA-256 policy digest.</returns>
    private static byte[] PolicyCommandCodeDigest(TpmCcConstants commandCode)
    {
        byte[] digest = new byte[32];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[32], commandCode, NameAlg, digest, BaseMemoryPool.Shared);

        return digest;
    }

    /// <summary>Starts an unbound, unsalted policy session — real or trial.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="isTrial">Whether to start a <c>TPM_SE_TRIAL</c> session.</param>
    /// <returns>The session handle.</returns>
    private async Task<uint> StartPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, bool isTrial)
    {
        StartAuthSessionInput input = isTrial
            ? StartAuthSessionInputExtensions.CreateTrialPolicySession(NameAlg, TestEntropy.NewCounterStream(), pool)
            : StartAuthSessionInputExtensions.CreateUnboundUnsaltedPolicySession(NameAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession ({(isTrial ? "trial" : "policy")}) failed: '{result.ResponseCode}'.");
        using StartAuthSessionResponse response = result.Value;

        return response.SessionHandle.Value;
    }

    /// <summary>Issues <c>TPM2_PolicyCommandCode()</c> over the session and asserts it succeeded.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The policy session.</param>
    /// <param name="commandCode">The command to latch.</param>
    private async Task LatchCommandCodeAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint sessionHandle, TpmCcConstants commandCode)
    {
        PolicyCommandCodeInput input = PolicyCommandCodeInput.Create(sessionHandle, commandCode);
        TpmResult<PolicyCommandCodeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyCommandCodeResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicyCommandCode failed: '{result.ResponseCode}'.");
    }

    /// <summary>Flushes a session handle if it is still loaded, ignoring the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        FlushContextInput flushInput = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S + TPM_RC_n(0x100·(index+1)).</summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Creates a simulator with both the ECC and RSA signing backends wired, powers it on, and brings it into the operational phase.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            $"tpm-in-house-rsa-decrypt-{name}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, moving it into the operational phase.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, "TPM2_Startup(CLEAR) must succeed.");
    }

    /// <summary>Issues <c>TPM2_SelfTest(NO)</c> directly against the simulator and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSelfTestAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new SelfTestInput(IsFullTest: false);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer TPM2_SelfTest() rather than fault.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_RSA_Decrypt, TpmResponseCodec.RsaDecrypt);
        _ = registry.Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);

        return registry;
    }

    /// <summary>Writes the owner hierarchy's enable state through <c>TPM2_HierarchyControl()</c> under platform authorization and asserts success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="state">The enable state to write.</param>
    private async Task SetOwnerHierarchyEnabledAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiYesNo state)
    {
        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            tpm, new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, TpmRh.TPM_RH_OWNER, state), [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl(OWNER, {state}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Creates an operational simulator wired with a caller-supplied RSA backend, so a test can substitute one delegate to model a faulting decrypt backend.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="rsaSigningBackend">The RSA backend to wire.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalWithRsaBackendAsync(string name, BaseMemoryPool pool, TpmRsaSigningBackend rsaSigningBackend)
    {
        var simulator = new TpmSimulator(
            $"tpm-in-house-rsa-decrypt-{name}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: rsaSigningBackend, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Builds a <c>TPMT_RSA_DECRYPT</c> body: the <c>scheme</c> selector, followed by a hash-only detail pair when <paramref name="includeHash"/> is <see langword="true"/>.</summary>
    /// <param name="scheme">The scheme selector to write.</param>
    /// <param name="includeHash">Whether to also write a hash-only detail pair.</param>
    /// <param name="hashAlg">The hash algorithm to write when <paramref name="includeHash"/> is <see langword="true"/>.</param>
    /// <returns>The marshaled body.</returns>
    private static byte[] BuildInSchemeBody(TpmAlgIdConstants scheme, bool includeHash, TpmAlgIdConstants hashAlg)
    {
        byte[] body = new byte[includeHash ? 2 * sizeof(ushort) : sizeof(ushort)];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)scheme);
        if(includeHash)
        {
            writer.WriteUInt16((ushort)hashAlg);
        }

        return body;
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_RSA_Decrypt()</c> command over a single empty <c>TPM_RS_PW</c> slot, letting a
    /// caller submit an arbitrary, possibly non-Table-192-shaped <c>inScheme</c> or an over-wide <c>cipherText</c>
    /// directly against the simulator, bypassing <see cref="RsaDecryptInput"/>'s own admitted-shape framing.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="cipherText">The already-unmarshaled <c>cipherText</c> octets.</param>
    /// <param name="inSchemeBody">The already-marshaled <c>TPMT_RSA_DECRYPT</c> body, verbatim.</param>
    /// <param name="label">The already-unmarshaled <c>label</c> octets.</param>
    /// <param name="hasTrailingOctet">Whether to append one octet after every declared field.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameRsaDecryptCommand(
        BaseMemoryPool pool, uint keyHandle, ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> inSchemeBody, ReadOnlySpan<byte> label, bool hasTrailingOctet, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

        length =
            TpmHeader.HeaderSize
            + sizeof(uint)
            + sizeof(uint) + PasswordSlotSize
            + sizeof(ushort) + cipherText.Length
            + inSchemeBody.Length
            + sizeof(ushort) + label.Length
            + (hasTrailingOctet ? 1 : 0);

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_RSA_Decrypt);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteUInt32((uint)PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(cipherText);
            writer.WriteBytes(inSchemeBody);
            writer.WriteTpm2b(label);
            if(hasTrailingOctet)
            {
                writer.WriteByte(0xFF);
            }

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>Hand-frames a <c>TPM2_RSA_Decrypt()</c> command with no authorization area at all — the <c>TPM_ST_NO_SESSIONS</c> shape Table 46's tag column has no branch for.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="cipherText">The already-unmarshaled <c>cipherText</c> octets.</param>
    /// <param name="inSchemeBody">The already-marshaled <c>TPMT_RSA_DECRYPT</c> body, verbatim.</param>
    /// <param name="label">The already-unmarshaled <c>label</c> octets.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameRsaDecryptNoSessionsCommand(
        BaseMemoryPool pool, uint keyHandle, ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> inSchemeBody, ReadOnlySpan<byte> label, out int length)
    {
        length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(ushort) + cipherText.Length + inSchemeBody.Length + sizeof(ushort) + label.Length;
        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_RSA_Decrypt);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteTpm2b(cipherText);
            writer.WriteBytes(inSchemeBody);
            writer.WriteTpm2b(label);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>Submits a hand-framed <c>TPM2_RSA_Decrypt()</c> built by <see cref="FrameRsaDecryptCommand"/> straight to the simulator and yields the response code.</summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="cipherText">The already-unmarshaled <c>cipherText</c> octets.</param>
    /// <param name="inSchemeBody">The already-marshaled <c>TPMT_RSA_DECRYPT</c> body, verbatim.</param>
    /// <param name="label">The already-unmarshaled <c>label</c> octets.</param>
    /// <param name="hasTrailingOctet">Whether to append one octet after every declared field.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitHandFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, byte[] cipherText, byte[] inSchemeBody, ReadOnlyMemory<byte> label, bool hasTrailingOctet = false)
    {
        using IMemoryOwner<byte> commandOwner = FrameRsaDecryptCommand(pool, keyHandle, cipherText, inSchemeBody, label.Span, hasTrailingOctet, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");
        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// "If no padding is used, the returned value is an unsigned integer value that is the result of the modular
    /// exponentiation of cipherText using the private exponent" — a NULL-scheme ciphertext whose k-wide encoding
    /// carries a LEADING ZERO octet (found by searching small off-TPM messages for one whose raw RSAEP result is
    /// shorter than the modulus width) still decrypts to the exact plaintext. Neither the ciphertext nor the
    /// expected plaintext is built through this class's own fixed-width helper: both are hand-encoded here by
    /// right-aligning each value's minimal octets into a fresh zeroed span of the modulus width — the right-aligned,
    /// zero-padded wire form Part 2's <c>TPM2B_PUBLIC_KEY_RSA</c> field requires.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 14.3.1; Part 1, clause 43.2.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptNullSchemeCiphertextWithALeadingZeroOctetRecoversTheExactPlaintext()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptNullSchemeCiphertextWithALeadingZeroOctetRecoversTheExactPlaintext), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateDecryptKeyAsync(tpm, registry, pool, TpmtRsaScheme.Null, noDa: true).ConfigureAwait(false);
        BigInteger n = ToUnsignedBigInteger(key.OutPublic.PublicArea.Unique.GetRsaModulus());
        uint e = key.OutPublic.PublicArea.Parameters.RsaDetail!.Value.EffectiveExponent;

        int plaintextValue = 0;
        BigInteger cipherValue = BigInteger.Zero;
        for(int candidate = 2; candidate < 4000; candidate++)
        {
            BigInteger candidateCipher = BigInteger.ModPow(candidate, e, n);
            int candidateByteCount = candidateCipher.GetByteCount(isUnsigned: true);
            if(candidateByteCount < ModulusOctets)
            {
                plaintextValue = candidate;
                cipherValue = candidateCipher;

                break;
            }
        }

        Assert.AreNotEqual(0, plaintextValue, "The search must find a small candidate message whose raw RSAEP result is shorter than the modulus width.");

        byte[] cipherMinimal = cipherValue.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] cipherText = new byte[ModulusOctets];
        cipherMinimal.CopyTo(cipherText, ModulusOctets - cipherMinimal.Length);
        Assert.AreEqual(0x00, cipherText[0], "The chosen ciphertext must actually carry a leading zero octet once right-aligned into the modulus width.");

        byte[] plaintextMinimal = new BigInteger(plaintextValue).ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] expectedPlaintext = new byte[ModulusOctets];
        plaintextMinimal.CopyTo(expectedPlaintext, ModulusOctets - plaintextMinimal.Length);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(KeyPasswordBytes, pool);
        TpmResult<RsaDecryptResponse> result = await DecryptAsync(
            tpm, registry, pool, key.ObjectHandle, keyAuth, null, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A NULL-scheme ciphertext below the modulus, leading zero octet included, must decrypt: '{result.ResponseCode}'.");

        using RsaDecryptResponse response = result.Value;
        Assert.IsTrue(
            expectedPlaintext.AsSpan().SequenceEqual(response.Message.Buffer),
            "The recovered plaintext must equal the exact k-wide value right-aligned by hand, matching neither a left-aligned nor a 256-scaled encoding.");
    }
}
