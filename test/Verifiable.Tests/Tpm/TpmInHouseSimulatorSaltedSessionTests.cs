using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives salted-session establishment (<c>TPM2_StartAuthSession()</c>'s RSA and ECC arms, TPM 2.0 Library Part
/// 3, clause 11.1) and real bind authorization-value resolution against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="StartAuthSessionInput"/>, <see cref="TpmSession"/>, <see cref="UnsealInput"/>, and the real
/// response codecs).
/// </summary>
/// <remarks>
/// <para>
/// Every accepted-path test proves the session key the simulator derived agrees with the host's: a genuine
/// <see cref="TpmSession"/> both signs the command HMAC and verifies the response HMAC, so a divergent salt,
/// bind authValue, or hash selection surfaces as a command failure, never a silent pass.
/// </para>
/// <para>
/// <see cref="MixedHashSaltedEccSessionUsesTpmKeysNameAlgorithmNotAuthHash"/> is the one test per Annex C.6
/// arm built from an INDEPENDENT transcription: raw BouncyCastle point arithmetic (never
/// <c>TpmEccSigningBackend</c>) composes the ECDH shared value by hand, then the project's own <c>Kdfe</c>
/// derives the salt from it, so a KDFe hash-selection leak (the session's <c>authHash</c> instead of
/// <c>tpmKey</c>'s own Name algorithm) cannot pass merely because both sides share the same buggy point
/// arithmetic. Independence here is that this test drives the ECDH agreement itself rather than through the
/// production signing backend; the KDFe primitive is proven separately by its own known-answer tests.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSaltedSessionTests
{
    /// <summary>The session hash algorithm most tests negotiate.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>Every RSA/ECC storage-parent-shaped template this simulator builds fixes nameAlg to SHA-256.</summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework RSA key generator uses (the wire template's own "0" encodes this default, TPM 2.0 Library Part 2, Table 215).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The modulus width, in octets, of the 2048-bit RSA endorsement-key template <see cref="CreateRsaDecryptKeyAsync"/> builds.</summary>
    private const int RsaEndorsementKeyModulusOctets = 256;

    /// <summary>The SHA-256 digest width, in octets, used by the mixed-hash KDFe transcription.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The fixed secret sealed and recovered by the bound-and-salted Unseal tests.</summary>
    private static byte[] SecretBytes { get; } = "Salted-session-authorized secret."u8.ToArray();

    /// <summary>The correct authValue assigned to a sealed object under test.</summary>
    private static byte[] CorrectUserAuth { get; } = [0x11, 0x22, 0x33, 0x44];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Salted, unbound HMAC session against an RSA tpmKey: the response-encrypted <c>TPM2_GetRandom()</c> round
    /// trips through the production path, proving the host and the simulator derived the same session key from
    /// the RSA-OAEP-recovered salt (TPM 2.0 Library Part 1, Annex B.10.1/B.10.2).
    /// </summary>
    [TestMethod]
    public async Task RsaSaltedUnboundSessionRoundTripsEncryptedGetRandom()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

            (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
                tpmKeyHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg, SessionAlg, rsaBackend.EncryptOaep, pool, TestContext.CancellationToken,
                symmetric: TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

            using(salt)
            {
                await RunSaltedGetRandomRoundTripAsync(
                    tpm, registry, pool, startInput, ReadOnlyMemory<byte>.Empty, salt.Memory[..saltLength], TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Salted, unbound HMAC session against an ECC tpmKey: the response-encrypted <c>TPM2_GetRandom()</c> round
    /// trips through the production path, proving the host and the simulator derived the same session key from
    /// the ECDH+KDFe-recovered salt (TPM 2.0 Library Part 1, Annex C.6.1/C.6.2).
    /// </summary>
    [TestMethod]
    public async Task EccSaltedUnboundSessionRoundTripsEncryptedGetRandom()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            ReadOnlyMemory<byte> point = ExtractEccPoint(tpmKey);
            TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();

            (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
                tpmKeyHandle, point, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmKeyNameAlg, SessionAlg,
                eccBackend.GenerateKey, eccBackend.ComputeSharedSecret, pool, TestContext.CancellationToken,
                symmetric: TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);

            using(salt)
            {
                await RunSaltedGetRandomRoundTripAsync(
                    tpm, registry, pool, startInput, ReadOnlyMemory<byte>.Empty, salt.Memory[..saltLength], TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A salted ECC session whose session hash (<c>authHash</c>, SHA-384) differs from tpmKey's own Name
    /// algorithm (SHA-256, every ECC storage-parent template this simulator builds) — catching a KDFe
    /// hash-selection leak (TPM 2.0 Library Part 1, Annex C.6.1: <c>hashAlg</c> is the recipient key's OWN
    /// nameAlg, never the session's <c>authHash</c>). Builds <c>encryptedSalt</c> and the expected salt from an
    /// INDEPENDENT transcription — raw BouncyCastle point arithmetic and a hand-rolled single-block KDFe over
    /// <see cref="SHA256"/>, never <see cref="Kdfe"/> or <see cref="TpmEccSigningBackend"/> — so the round trip
    /// can only succeed if the simulator, too, keyed its recovery on SHA-256 (tpmKey's nameAlg), not SHA-384 (the
    /// session's authHash): a same-bug-on-both-sides false pass is impossible here.
    /// </summary>
    [TestMethod]
    public async Task MixedHashSaltedEccSessionUsesTpmKeysNameAlgorithmNotAuthHash()
    {
        const TpmAlgIdConstants MixedSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA384;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            ReadOnlyMemory<byte> tpmKeyPoint = ExtractEccPoint(tpmKey);

            X9ECParameters curveParameters = SecNamedCurves.GetByName("secp256r1");
            var domain = new ECDomainParameters(curveParameters.Curve, curveParameters.G, curveParameters.N, curveParameters.H, curveParameters.GetSeed());

            //A fixed ephemeral scalar: any value in [1, n) is a legitimate one-time key for this oracle, and
            //determinism keeps the test reproducible.
            byte[] ephemeralScalarBytes = new byte[32];
            ephemeralScalarBytes[31] = 0x2A;
            var ephemeralScalar = new BigInteger(1, ephemeralScalarBytes);

            Org.BouncyCastle.Math.EC.ECPoint ephemeralPointBc = domain.G.Multiply(ephemeralScalar).Normalize();
            byte[] ephemeralX = PadTo32(ephemeralPointBc.AffineXCoord.ToBigInteger().ToByteArrayUnsigned());
            byte[] ephemeralY = PadTo32(ephemeralPointBc.AffineYCoord.ToBigInteger().ToByteArrayUnsigned());

            Org.BouncyCastle.Math.EC.ECPoint tpmKeyPointBc = domain.Curve.DecodePoint(tpmKeyPoint.ToArray());
            Org.BouncyCastle.Math.EC.ECPoint sharedPointBc = tpmKeyPointBc.Multiply(ephemeralScalar).Normalize();
            byte[] z = PadTo32(sharedPointBc.AffineXCoord.ToBigInteger().ToByteArrayUnsigned());

            byte[] tpmKeyX = tpmKeyPoint.Span.Slice(1, 32).ToArray();

            //KDFe(SHA256, Z, "SECRET", partyU=ephemeralX, partyV=tpmKeyX, bits=256): a single SHA-256 block since
            //the requested output exactly matches the digest width (TPM 2.0 Library Part 1, clause 9.4.10.3) —
            //via the project's own Kdfe, over the hand-composed ECDH shared value.
            using IMemoryOwner<byte> saltOwner = await Kdfe.DeriveAsync(
                HashAlgorithmName.SHA256, z, "SECRET", ephemeralX, tpmKeyX, Sha256DigestSize * 8, pool, TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte> salt = saltOwner.Memory[..Sha256DigestSize];

            using TpmsEccPoint eccPoint = TpmsEccPoint.Create(ephemeralX, ephemeralY, pool);
            byte[] encryptedSalt = new byte[eccPoint.GetSerializedSize()];
            var pointWriter = new TpmWriter(encryptedSalt);
            eccPoint.WriteTo(ref pointWriter);

            var startInput = new StartAuthSessionInput
            {
                TpmKey = tpmKeyHandle,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = RandomNonceCaller(MixedSessionAlg),
                EncryptedSalt = encryptedSalt,
                SessionType = TpmSeConstants.TPM_SE_HMAC,
                AuthHash = MixedSessionAlg,
                Symmetric = TpmtSymDef.Xor(MixedSessionAlg)
            };

            await RunSaltedGetRandomRoundTripAsync(
                tpm, registry, pool, startInput, ReadOnlyMemory<byte>.Empty, salt, TpmtSymDef.Xor(MixedSessionAlg), MixedSessionAlg).ConfigureAwait(false);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A salted-and-bound session (RSA tpmKey) bound to a storage parent (empty auth) authorizing a DIFFERENT
    /// entity — a sealed item with a real, non-empty userAuth — over <c>TPM2_Unseal()</c>: the per-command
    /// authValue is supplied (equation 21/25, no bind-omission), proving salting composes with a genuine
    /// non-empty authorization.
    /// </summary>
    [TestMethod]
    public async Task SaltedAndBoundSessionIncludesAuthValueWhenAuthorizingADifferentEntity()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;
        using CreatePrimaryResponse parent = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

            (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(
                tpmKeyHandle, parentHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg, SessionAlg, rsaBackend.EncryptOaep, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using(salt)
            {
                TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                    tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted-and-bound, RSA) failed: '{startResult.ResponseCode}'.");
                StartAuthSessionResponse startResponse = startResult.Value;

                //The bound entity (the storage parent) carries empty auth — this model tracks no authValue for a
                //signing/storage key — so bindAuthValue is empty; the item's REAL userAuth is supplied per-command.
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(startResponse.SessionHandle.Value), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller,
                    startResponse.NonceTPM, SessionAlg, pool, symmetric: TpmtSymDef.Null, salt: salt.Memory[..saltLength],
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                session.SetAuthValue(CorrectUserAuth, pool);

                try
                {
                    UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                    TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                        tpm, unsealInput, [session], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(unsealResult.IsSuccess, $"Unseal over a salted-and-bound session authorizing a different entity failed: '{unsealResult.ResponseCode}'.");
                    using UnsealResponse unsealed = unsealResult.Value;
                    Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The recovered secret must equal the sealed one.");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, startResponse.SessionHandle.Value).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A salted-and-bound session (ECC tpmKey) bound DIRECTLY to the sealed item it then authorizes over
    /// <c>TPM2_Unseal()</c>, with NO per-command authValue supplied: only the eq. 26 bind-omission (the bound
    /// entity's real userAuth folded into the session key, then omitted from the per-command HMAC key because
    /// the entity being authorized now IS the bound entity) lets this succeed — proving bind resolution to a
    /// sealed object (with its real userAuth) composes correctly with salting.
    /// </summary>
    [TestMethod]
    public async Task SaltedAndBoundSessionOmitsAuthValueForTheBoundObjectItself()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;
        using CreatePrimaryResponse parent = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            ReadOnlyMemory<byte> point = ExtractEccPoint(tpmKey);
            TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();

            (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(
                tpmKeyHandle, itemHandle, point, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmKeyNameAlg, SessionAlg,
                eccBackend.GenerateKey, eccBackend.ComputeSharedSecret, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using(salt)
            {
                TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                    tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted-and-bound to the item itself, ECC) failed: '{startResult.ResponseCode}'.");
                StartAuthSessionResponse startResponse = startResult.Value;

                //bindAuthValue MUST be the item's real userAuth: the simulator resolved the SAME value from the
                //loaded sealed object's state (R-C5), so the two session keys agree by construction only if this
                //matches exactly.
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(startResponse.SessionHandle.Value), CorrectUserAuth, startInput.NonceCaller,
                    startResponse.NonceTPM, SessionAlg, pool, symmetric: TpmtSymDef.Null, salt: salt.Memory[..saltLength],
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

                //Deliberately NOT calling session.SetAuthValue: the per-command authValue stays empty, relying
                //entirely on the bind-omission (equation 26) to authorize the Unseal.
                try
                {
                    UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                    TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                        tpm, unsealInput, [session], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(unsealResult.IsSuccess, $"Unseal over a session bound to (and authorizing) the same object failed: '{unsealResult.ResponseCode}'. A failure means the bind-omission or the sealed-object bind resolution diverged.");
                    using UnsealResponse unsealed = unsealResult.Value;
                    Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The recovered secret must equal the sealed one.");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, startResponse.SessionHandle.Value).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>A nonceCaller one octet short of the fixed 16-octet floor is rejected with TPM_RC_SIZE, unconditionally (Part 3, clause 11.1).</summary>
    [TestMethod]
    public async Task ShortNonceCallerIsRejectedWithSize()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg) with { NonceCaller = new byte[15] };

        TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, rc, "A 15-octet nonceCaller is one short of the fixed 16-octet floor.");
    }

    /// <summary>A non-empty encryptedSalt with tpmKey = TPM_RH_NULL is malformed the other way around: TPM_RC_VALUE.</summary>
    [TestMethod]
    public async Task EncryptedSaltWithNullTpmKeyIsRejectedWithValue()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg) with { EncryptedSalt = new byte[] { 0x01, 0x02, 0x03, 0x04 } };

        TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, rc, "An unsalted request (tpmKey = TPM_RH_NULL) naming a non-empty encryptedSalt must be rejected.");
    }

    /// <summary>
    /// A corrupted RSA-OAEP ciphertext fails salt recovery and is reported immediately as TPM_RC_VALUE — never
    /// poisoned-and-deferred (Part 3, clause 11.1 has no later integrity check to defer to).
    /// </summary>
    [TestMethod]
    public async Task CorruptedRsaOaepCiphertextIsRejectedWithValueImmediately()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

            (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, _) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
                tpmKeyHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg, SessionAlg, rsaBackend.EncryptOaep, pool, TestContext.CancellationToken).ConfigureAwait(false);
            salt.Dispose();

            //Flip one interior octet of the flat OAEP ciphertext — a corrupted blob a genuine session start with
            //the SAME tpmKey and an uncorrupted ciphertext (the tests above) succeeds against, proving this
            //negative is non-vacuous rather than an artifact of a malformed request shape.
            byte[] corrupted = startInput.EncryptedSalt.ToArray();
            corrupted[^1] ^= 0xFF;
            startInput = startInput with { EncryptedSalt = corrupted };

            TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, rc, "A corrupted OAEP ciphertext must fail salt recovery with TPM_RC_VALUE.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// F2 regression (adversarial review, MAJOR crash/DoS), RSA sibling: <c>RecoverRsaSessionSaltAsync</c> had NO
    /// try/catch at all around <c>backend.DecryptOaep</c>. <see cref="TpmRsaOaepDecryptDelegate"/>'s own contract
    /// signals a decode failure by returning <see langword="null"/> rather than throwing, and the composed
    /// BouncyCastle-backed test backend already honors that contract even for a malformed-length ciphertext — so
    /// this drives a DELIBERATELY non-conforming backend (modelling a plausible alternative RSA provider that
    /// raises a framework exception instead of returning <see langword="null"/>) through the production
    /// <c>TPM2_StartAuthSession()</c> path, proving the call site itself now collapses ANY backend throw to
    /// <c>TPM_RC_VALUE</c> rather than depending on every conceivable backend honoring the delegate's
    /// never-throws contract (TPM 2.0 Library Part 3, clause 11.1).
    /// </summary>
    [TestMethod]
    public async Task RsaWrongLengthCiphertextThroughAThrowingBackendIsRejectedWithValue()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmRsaSigningBackend throwingRsaBackend = MicrosoftTpmRsaSigningBackend.Create() with { DecryptOaep = ThrowOnWrongLengthCiphertextAsync };
        var simulator = new TpmSimulator(
            "tpm-in-house-salted-session-throwing-rsa", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: throwingRsaBackend);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            //A ciphertext deliberately shorter than the RSA modulus (256 octets for the 2048-bit endorsement-key
            //template): the injected backend below throws for any length mismatch instead of returning null.
            byte[] wrongLengthCiphertext = new byte[16];
            Array.Fill(wrongLengthCiphertext, (byte)0x42);

            var startInput = new StartAuthSessionInput
            {
                TpmKey = tpmKeyHandle,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = RandomNonceCaller(SessionAlg),
                EncryptedSalt = wrongLengthCiphertext,
                SessionType = TpmSeConstants.TPM_SE_HMAC,
                AuthHash = SessionAlg,
                Symmetric = TpmtSymDef.Null
            };

            TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, rc,
                "A backend that throws over a wrong-length RSA-OAEP ciphertext must still collapse to TPM_RC_VALUE, never an unhandled exception.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <see cref="TpmRsaOaepDecryptDelegate"/> that models a hypothetical RSA provider NOT honoring the
    /// delegate's own never-throws contract: it raises <see cref="CryptographicException"/> for a
    /// malformed-length ciphertext instead of returning <see langword="null"/>, exactly the "any backend throw"
    /// case the F2 fix hardens <c>RecoverRsaSessionSaltAsync</c>'s call site against. Delegates to the real
    /// BouncyCastle backend for a correctly-sized ciphertext, so this stands in for the production delegate in
    /// every other respect.
    /// </summary>
    private static ValueTask<IMemoryOwner<byte>?> ThrowOnWrongLengthCiphertextAsync(
        ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> ciphertext, ReadOnlyMemory<byte> label,
        TpmAlgIdConstants lhashAlg, TpmAlgIdConstants mgfHashAlg, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(ciphertext.Length != RsaEndorsementKeyModulusOctets)
        {
            throw new CryptographicException("Simulated RSA provider that does not itself guard a malformed-length OAEP ciphertext.");
        }

        return BouncyCastleTpmRsaOaepBackend.DecryptOaep(privateKey, ciphertext, label, lhashAlg, mgfHashAlg, pool, cancellationToken);
    }

    /// <summary>A malformed/off-curve ECC point in encryptedSalt fails salt recovery and is reported immediately as TPM_RC_VALUE.</summary>
    [TestMethod]
    public async Task OffCurveEccPointIsRejectedWithValue()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            //A garbage 32-byte X/Y pair: with overwhelming probability not a point satisfying the P-256 curve
            //equation, and not the point at infinity either (both non-empty).
            byte[] garbageX = new byte[32];
            byte[] garbageY = new byte[32];
            Array.Fill(garbageX, (byte)0xAB);
            Array.Fill(garbageY, (byte)0xCD);

            using TpmsEccPoint eccPoint = TpmsEccPoint.Create(garbageX, garbageY, pool);
            byte[] encryptedSalt = new byte[eccPoint.GetSerializedSize()];
            var writer = new TpmWriter(encryptedSalt);
            eccPoint.WriteTo(ref writer);

            var startInput = new StartAuthSessionInput
            {
                TpmKey = tpmKeyHandle,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = RandomNonceCaller(SessionAlg),
                EncryptedSalt = encryptedSalt,
                SessionType = TpmSeConstants.TPM_SE_HMAC,
                AuthHash = SessionAlg,
                Symmetric = TpmtSymDef.Null
            };

            TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, rc, "An off-curve ECC point must fail salt recovery with TPM_RC_VALUE.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// F2 regression (adversarial review, MAJOR crash/DoS): a genuinely on-curve P-256 point whose y-coordinate
    /// is marshaled with an EXTRA leading zero octet (33 bytes instead of the canonical 32) must be rejected
    /// with <c>TPM_RC_VALUE</c>, not crash the simulator. <see cref="EllipticCurveUtilities.CheckPointOnCurve"/>
    /// parses each coordinate as an unsigned <see cref="System.Numerics.BigInteger"/>, so the leading zero octet
    /// does not change the numeric value — the point still passes the on-curve check — but before the fix,
    /// <see cref="EllipticCurveUtilities.CombineToUncompressedPoint"/> (called next to build the ECDH input)
    /// throws the base <see cref="ArgumentException"/> because <c>x.Length</c> (32) no longer equals
    /// <c>y.Length</c> (33), escaping the narrow <c>catch(ArgumentOutOfRangeException)</c> as an unhandled
    /// exception (TPM 2.0 Library Part 3, clause 11.1; a wire-reachable denial of service via a crafted
    /// <c>encryptedSalt</c> on a loaded ECC decrypt tpmKey).
    /// </summary>
    [TestMethod]
    public async Task MismatchedYCoordinateLengthOnCurvePointIsRejectedWithValue()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            //The tpmKey's own exported static point is a genuine on-curve P-256 point — any on-curve point
            //serves here, since the exploit is purely about the Y encoding's octet length, not which point it
            //is. Re-encode Y with an extra leading zero octet: numerically identical (big-endian unsigned), but
            //33 octets long instead of the canonical 32.
            ReadOnlyMemory<byte> point = ExtractEccPoint(tpmKey);
            byte[] x = EllipticCurveUtilities.SliceXCoordinate(point.Span).ToArray();
            byte[] canonicalY = EllipticCurveUtilities.SliceYCoordinate(point.Span).ToArray();
            byte[] paddedY = new byte[canonicalY.Length + 1];
            canonicalY.CopyTo(paddedY, 1);

            using TpmsEccPoint eccPoint = TpmsEccPoint.Create(x, paddedY, pool);
            byte[] encryptedSalt = new byte[eccPoint.GetSerializedSize()];
            var writer = new TpmWriter(encryptedSalt);
            eccPoint.WriteTo(ref writer);

            var startInput = new StartAuthSessionInput
            {
                TpmKey = tpmKeyHandle,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = RandomNonceCaller(SessionAlg),
                EncryptedSalt = encryptedSalt,
                SessionType = TpmSeConstants.TPM_SE_HMAC,
                AuthHash = SessionAlg,
                Symmetric = TpmtSymDef.Null
            };

            TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, rc,
                "A P-256 point whose y-coordinate is marshaled as 33 octets (a numerically-identical, leading-zero-padded " +
                "encoding of the canonical 32-octet value) must be rejected with TPM_RC_VALUE, not crash the simulator.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>A sealed (KEYEDHASH) object named as tpmKey is never asymmetric: TPM_RC_KEY.</summary>
    [TestMethod]
    public async Task SealedObjectAsTpmKeyIsRejectedWithKey()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            var startInput = new StartAuthSessionInput
            {
                TpmKey = itemHandle,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = RandomNonceCaller(SessionAlg),
                EncryptedSalt = new byte[] { 0x01, 0x02, 0x03, 0x04 },
                SessionType = TpmSeConstants.TPM_SE_HMAC,
                AuthHash = SessionAlg,
                Symmetric = TpmtSymDef.Null
            };

            TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, rc, "A sealed (KEYEDHASH) object is never an asymmetric key.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>A PIN Fail Index named as bind can never bind, closing the PIN-extraction vector: TPM_RC_HANDLE.</summary>
    [TestMethod]
    public async Task PinIndexBindIsRejectedWithHandle()
    {
        const uint PinFailIndexHandle = 0x0100_0031;
        const TpmaNv PinFailAttributes =
            TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
            | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);
        const ushort PinCounterParametersSize = 8;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);

        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using var auth = Tpm2bAuth.Create([0x01, 0x02, 0x03, 0x04], pool);
        using var publicInfo = new TpmsNvPublic(PinFailIndexHandle, TpmAlgIdConstants.TPM_ALG_SHA256, PinFailAttributes, Tpm2bDigest.Empty, PinCounterParametersSize);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace (PIN Fail Index) failed: '{defineResult.ResponseCode}'.");

        try
        {
            StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(PinFailIndexHandle, SessionAlg);

            TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, rc, "A PIN Fail Index can never bind a session.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, PinFailIndexHandle).ConfigureAwait(false);
        }
    }

    /// <summary>An AES definition negotiating a mode other than CFB is rejected with TPM_RC_MODE (distinct from an entirely unsupported algorithm, which stays TPM_RC_SYMMETRIC).</summary>
    [TestMethod]
    public async Task NonCfbAesModeIsRejectedWithMode()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CTR));

        TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_MODE, rc, "AES with a non-CFB mode must be TPM_RC_MODE, not TPM_RC_SYMMETRIC.");
    }

    /// <summary>Left-pads (or trims) a big-endian value to 32 bytes, as SEC1 P-256 coordinates require.</summary>
    private static byte[] PadTo32(byte[] value)
    {
        if(value.Length == 32)
        {
            return value;
        }

        byte[] result = new byte[32];
        if(value.Length < 32)
        {
            value.CopyTo(result, 32 - value.Length);
        }
        else
        {
            value.AsSpan(value.Length - 32, 32).CopyTo(result);
        }

        return result;
    }

    /// <summary>
    /// Draws a nonceCaller of <paramref name="authHash"/>'s digest width — within the fixed 16-octet floor and
    /// the hash-sized ceiling — through the registered <see cref="GenerateNonceDelegate"/> (never a bare
    /// <see cref="RandomNumberGenerator"/> call), materialized as a plain octet array to match
    /// <see cref="StartAuthSessionInput.NonceCaller"/>'s own <see cref="ReadOnlyMemory{T}"/> field shape.
    /// </summary>
    private static byte[] RandomNonceCaller(TpmAlgIdConstants authHash)
    {
        using Nonce nonce = CryptographicKeyEvents.GenerateNonce(
            TpmPolicyDigest.Size(authHash), Tag.Create((typeof(Purpose), Purpose.Nonce)), BaseMemoryPool.Shared);

        return nonce.AsReadOnlySpan().ToArray();
    }

    /// <summary>Extracts an ECC primary's exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</summary>
    private static ReadOnlyMemory<byte> ExtractEccPoint(CreatePrimaryResponse primary)
    {
        TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;
        return EllipticCurveUtilities.CombineToUncompressedPoint(point.X.AsReadOnlySpan(), point.Y.AsReadOnlySpan());
    }

    /// <summary>
    /// Submits <paramref name="startInput"/> through the production <c>TPM2_StartAuthSession()</c> path, wraps
    /// the result as a <see cref="TpmSession"/> seeded with <paramref name="salt"/>, and runs one
    /// encrypt-attributed <c>TPM2_GetRandom()</c> over it — a failure at either step means the host and the
    /// simulator derived different session keys.
    /// </summary>
    private async Task RunSaltedGetRandomRoundTripAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, StartAuthSessionInput startInput,
        ReadOnlyMemory<byte> bindAuthValue, ReadOnlyMemory<byte> salt, TpmtSymDef symmetric, TpmAlgIdConstants? sessionAlgOverride = null)
    {
        TpmAlgIdConstants sessionAlg = sessionAlgOverride ?? SessionAlg;

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted) failed: '{startResult.ResponseCode}'.");
        StartAuthSessionResponse startResponse = startResult.Value;

        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuthValue, startInput.NonceCaller, startResponse.NonceTPM,
            sessionAlg, pool, symmetric: symmetric, salt: salt, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

        try
        {
            var getRandomInput = new GetRandomInput(16);
            TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(randomResult.IsSuccess,
                $"Encrypted GetRandom over a salted session failed: '{randomResult.ResponseCode}'. A failure means the host and the simulator derived different session keys.");
            randomResult.Value.Dispose();
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, startResponse.SessionHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>Submits <paramref name="startInput"/> and returns the response code, disposing a successful response (only the negative-path tests use this).</summary>
    private async Task<TpmRcConstants> AttemptStartAuthSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, StartAuthSessionInput startInput)
    {
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(startResult.IsSuccess)
        {
            startResult.Value.Dispose();
        }

        return startResult.ResponseCode;
    }

    /// <summary>Creates the standard RSA endorsement-key-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as a salted session's RSA tpmKey.</summary>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an ECC storage-parent-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as a salted session's ECC tpmKey, and doubles as a sealing parent where needed.</summary>
    private async Task<CreatePrimaryResponse> CreateEccDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccStorageParent(TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Seals <see cref="SecretBytes"/> under <paramref name="userAuth"/>, persists-and-reloads it through wire bytes only, and returns the loaded object's response.</summary>
    private async Task<LoadResponse> SealAndLoadAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint parentHandle, byte[] userAuth, bool noDa)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, userAuth, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: noDa);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

        return loadResult.Value;
    }

    /// <summary>Reserializes a public area into a fresh <see cref="Tpm2bPublic"/> (a disk-persisted round trip).</summary>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, MemoryPool<byte> pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);
        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Flushes a transient object or session handle when one is present (non-zero), ignoring the result.</summary>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        if(!registry.TryGet(TpmCcConstants.TPM_CC_FlushContext, out _))
        {
            _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        }

        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a response codec registry covering every command these tests drive.</summary>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with BOTH the ECC (BouncyCastle) and RSA (framework key generation, BouncyCastle
    /// OAEP) signing backends wired, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase.
    /// </summary>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-salted-session", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an unauthorized command on the wire.</summary>
    private async Task IssueStartupClearAsync(TpmSimulator simulator, MemoryPool<byte> pool)
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
}
