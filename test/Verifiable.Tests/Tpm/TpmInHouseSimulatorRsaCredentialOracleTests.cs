using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Independent challenger-side oracle for the RSA arm of the TPM2_MakeCredential / TPM2_ActivateCredential seed
/// transport (TPM 2.0 Library Part 1, clause 24; Annex B.3 "RSADP", B.4 "RSAES_OAEP", B.10.3, B.10.4; RFC 8017
/// §7.1.1 EME-OAEP encoding), the RSA counterpart of <see cref="TpmInHouseSimulatorCredentialOracleTests"/>.
/// </summary>
/// <remarks>
/// <para>
/// The OAEP encoding's outer shape — the zero-filled <c>PS</c>, the <c>DB</c> assembly, the seed/DB masking —
/// is composed by hand, and the raw RSAEP step is a plain
/// <see cref="BigInteger.ModPow(BigInteger, BigInteger, BigInteger)"/> over the EK's exported modulus and the
/// default public exponent 65537, with no BouncyCastle and no framework RSA involved: the project's only
/// registered OAEP-encrypt seam (<see cref="Verifiable.Tpm.Automata.TpmRsaOaepEncryptDelegate"/>, as
/// <see cref="MicrosoftTpmRsaSigningBackend.Create"/> composes it) itself delegates to
/// <see cref="BouncyCastleTpmRsaOaepBackend"/> — the SAME implementation this file's simulator uses to decrypt
/// on TPM2_ActivateCredential() (<see cref="CreateOperationalAsync"/>), so calling it here would make the
/// encrypt and decrypt sides share one implementation, exactly the same-implementation round-trip this oracle
/// exists to avoid; there is no independent OAEP-with-custom-label seam to route through instead (a documented
/// finding, not an oversight). The underlying <c>lHash</c>/MGF1 SHA-256 calls, however, DO have a library seam
/// and go through it: <see cref="EncodeEmeOaep"/> and <see cref="Mgf1Sha256"/> compute their digests via
/// <see cref="CryptographicKeyEvents.ComputeDigest(ReadOnlySpan{byte}, int, Tag, BaseMemoryPool, string?)"/>
/// (the registered, sync-by-nature digest seam), never a bare <see cref="SHA256"/> call. The shared inner wrap
/// mirrors the ECC oracle: KDFa and the outer HMAC (<see cref="BuildCredentialBlobAsync"/>) compose the spec
/// message by hand but compute it through the project's own <see cref="Kdfa"/> and the registered HMAC seam;
/// framework <see cref="Aes.EncryptCfb"/> stays independent of the shipped ECB-loop CFB helper
/// (<c>TpmParameterEncryption.AesCfb</c>), and the one-AES-block 14-octet credential sizing accommodates
/// framework CFB's lack of short-final-block handling (see
/// <see cref="TpmInHouseSimulatorCredentialOracleTests.CredentialSecret"/>'s doc comment for the recorded
/// rationale, inherited unchanged since the outer wrap does not change between the ECC and RSA arms, TPM 2.0
/// Library Part 1, clause 24). This file never calls TPM2_MakeCredential(): the credential blob and encrypted
/// secret are assembled here from first principles and driven only through the production
/// TPM2_ActivateCredential() executor path, so a shared bug in the simulator's own MakeCredential/
/// ActivateCredential crypto cannot round-trip silently against this oracle.
/// </para>
/// <para>
/// Unlike the ECC oracle's plain password-authorized storage parent, no non-standard RSA storage-parent input
/// factory exists in this codebase (only the standard endorsement key, <see cref="CreatePrimaryInput.ForRsaEndorsementKey"/>,
/// which this file uses) — so every test here authorizes <c>keyHandle</c> through the real PolicyA path
/// (<c>TPM2_PolicySecret()</c> against the Endorsement Hierarchy) rather than a password session.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorRsaCredentialOracleTests
{
    /// <summary>
    /// The challenger's secret credential. Fourteen octets — see
    /// <see cref="TpmInHouseSimulatorCredentialOracleTests.CredentialSecret"/> for the block-alignment rationale
    /// this file inherits unchanged (the outer wrap, <see cref="BuildCredentialBlobAsync"/>, is identical between
    /// the ECC and RSA arms).
    /// </summary>
    private static IMemoryOwner<byte> CredentialSecret { get; } =
        RentLiteral([0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD]);

    /// <summary>The SHA-256 digest size in octets — also the OAEP <c>hLen</c> and the credential-protection seed width for L-1.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The RSA-2048 modulus width in octets — the OAEP block size <c>k</c>.</summary>
    private const int RsaModulusBytes = 256;

    /// <summary>The RSA modulus size in bits used by these tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The credential symmetric key width in bits (Part 1, clause 25.2: AES-128 for the L-1 storage/EK template).</summary>
    private const int SymmetricKeyBits = 128;

    /// <summary>The credential symmetric key width in octets.</summary>
    private const int SymmetricKeyBytes = SymmetricKeyBits / 8;

    /// <summary>The AES block size in octets, also the width of the all-zero CFB feedback register (IV).</summary>
    private const int AesBlockSize = 16;

    /// <summary>The KDFa use label for the inner symmetric key (Part 1, clause 24.4, eq. (44)) — shared with the ECC arm.</summary>
    private const string StorageLabel = "STORAGE";

    /// <summary>The KDFa use label for the outer HMAC key (Part 1, clause 24.4, eq. (46)) — shared with the ECC arm.</summary>
    private const string IntegrityLabel = "INTEGRITY";

    /// <summary>The RSA default public exponent (TPM 2.0 Library Part 2, Table 215: <c>exponent = 0</c> wire convention).</summary>
    private static BigInteger PublicExponent { get; } = 65537;

    /// <summary>
    /// The OAEP label octets (<c>L</c>): ASCII <c>"IDENTITY"</c> plus a trailing NUL that is part of the
    /// <c>lhash</c> digest input (TPM 2.0 Library Part 1, Annex B.4, B.10.4).
    /// </summary>
    private static ReadOnlyMemory<byte> OaepLabelOctets { get; } = "IDENTITY\0"u8.ToArray();

    /// <summary>The policy session hash algorithm used to satisfy the standard RSA EK's PolicyA.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Releases the pooled <see cref="CredentialSecret"/> buffer shared across every test in this class.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        CredentialSecret.Dispose();
    }

    /// <summary>
    /// Verifies that a credential blob and RSA-OAEP-encrypted secret built entirely from independent primitives
    /// (no call to TPM2_MakeCredential(), no BouncyCastle, no framework RSA OAEP) is recovered correctly by the
    /// production TPM2_ActivateCredential() executor over the standard RSA endorsement key.
    /// </summary>
    [TestMethod]
    public async Task ChallengerBuiltRsaCredentialActivatesThroughTheProductionExecutor()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateRsaEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                byte[] ekModulus = ek.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
                byte[] akName = ak.Name.Span.ToArray();

                (IMemoryOwner<byte> blob, int blobLength, IMemoryOwner<byte> secret, int secretLength) =
                    await BuildChallengerRsaCredentialAsync(CredentialSecret.Memory, akName, ekModulus, pool, TestContext.CancellationToken).ConfigureAwait(false);
                try
                {
                    TpmResult<ActivateCredentialResponse> activateResult = await ActivateOverPolicyAsync(
                        tpm, registry, pool, ak.ObjectHandle, ek.ObjectHandle, blob.Memory[..blobLength], secret.Memory[..secretLength], ak.Name.Span.ToArray(), ek.Name.Span.ToArray()).ConfigureAwait(false);
                    Assert.IsTrue(activateResult.IsSuccess, $"TPM2_ActivateCredential failed: '{activateResult.ResponseCode}'.");

                    using ActivateCredentialResponse activated = activateResult.Value;
                    Assert.IsTrue(
                        activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret.Memory.Span),
                        "The recovered credential must equal the challenger's independently wrapped secret.");
                }
                finally
                {
                    blob.Dispose();
                    secret.Dispose();
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
    /// Verifies that flipping one octet of the independently built outer HMAC is rejected with
    /// TPM_RC_INTEGRITY: the challenger-built blob and secret are otherwise valid, so the failure isolates the
    /// executor's integrity check rather than any other malformation.
    /// </summary>
    [TestMethod]
    public async Task ChallengerBuiltRsaCredentialWithATamperedOuterHmacIsRejectedWithIntegrityError()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateRsaEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                byte[] ekModulus = ek.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
                byte[] akName = ak.Name.Span.ToArray();

                (IMemoryOwner<byte> blob, int blobLength, IMemoryOwner<byte> secret, int secretLength) =
                    await BuildChallengerRsaCredentialAsync(CredentialSecret.Memory, akName, ekModulus, pool, TestContext.CancellationToken).ConfigureAwait(false);
                try
                {
                    //The blob layout is TPM2B(outerHmac) || encIdentity; flip one octet of the outerHmac itself
                    //(immediately after the 2-octet size prefix), leaving encIdentity and the secret untouched.
                    blob.Memory.Span[sizeof(ushort)] ^= 0xFF;

                    TpmResult<ActivateCredentialResponse> activateResult = await ActivateOverPolicyAsync(
                        tpm, registry, pool, ak.ObjectHandle, ek.ObjectHandle, blob.Memory[..blobLength], secret.Memory[..secretLength], ak.Name.Span.ToArray(), ek.Name.Span.ToArray()).ConfigureAwait(false);

                    Assert.IsFalse(activateResult.IsSuccess, "A credential blob with a tampered outer HMAC must not activate.");
                    Assert.AreEqual(TpmRcConstants.TPM_RC_INTEGRITY, activateResult.ResponseCode);
                }
                finally
                {
                    blob.Dispose();
                    secret.Dispose();
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
    /// Verifies that flipping one octet of the OAEP ciphertext is rejected with TPM_RC_INTEGRITY and NOT any
    /// other response code — the R-5 regression probe: a naive implementation that reports an OAEP decode
    /// failure directly (a distinct RC, or an unhandled exception) would fail this test, proving the simulator's
    /// deferred-failure discipline (TPM 2.0 Library Part 1, Annex B.10.3) is actually wired in, not merely
    /// documented.
    /// </summary>
    [TestMethod]
    public async Task ChallengerBuiltRsaCredentialWithATamperedOaepCiphertextIsRejectedWithIntegrityError()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateRsaEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                byte[] ekModulus = ek.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
                byte[] akName = ak.Name.Span.ToArray();

                (IMemoryOwner<byte> blob, int blobLength, IMemoryOwner<byte> secret, int secretLength) =
                    await BuildChallengerRsaCredentialAsync(CredentialSecret.Memory, akName, ekModulus, pool, TestContext.CancellationToken).ConfigureAwait(false);
                try
                {
                    //The secret IS the raw ciphertext directly (R-9: TPM2B_ENCRYPTED_SECRET's content has no
                    //sub-structure for RSA, unlike the ECC arm's marshaled point); flip its first octet, corrupting
                    //the OAEP padding RSADP recovers.
                    secret.Memory.Span[0] ^= 0xFF;

                    TpmResult<ActivateCredentialResponse> activateResult = await ActivateOverPolicyAsync(
                        tpm, registry, pool, ak.ObjectHandle, ek.ObjectHandle, blob.Memory[..blobLength], secret.Memory[..secretLength], ak.Name.Span.ToArray(), ek.Name.Span.ToArray()).ConfigureAwait(false);

                    Assert.IsFalse(activateResult.IsSuccess, "A credential secret with a tampered OAEP ciphertext must not activate.");
                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_INTEGRITY,
                        activateResult.ResponseCode,
                        "An OAEP decode failure must be deferred to the outer-HMAC TPM_RC_INTEGRITY rejection, never surfaced as a distinct code (Part 1, Annex B.10.3).");
                }
                finally
                {
                    blob.Dispose();
                    secret.Dispose();
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
    /// Regression probe for the deferred-failure substitute-seed forgery oracle (TPM 2.0 Library Part 1, Annex
    /// B.10.3). Mounts the exact attack a <em>fixed</em> substitute seed would enable: the challenger forges an
    /// outer HMAC under the all-zero seed — the value a naive deferral substitutes on OAEP decode failure — using
    /// only public inputs (the activate object's Name), pairs it with a deliberately decode-failing secret (an
    /// all-zero ciphertext, whose recovered OAEP block fails the <c>lHash</c> check), and drives the production
    /// executor. Because the substitute seed is drawn unpredictably from the RNG seam (not a constant), the
    /// forged HMAC — keyed on the zero seed — cannot match, so activation is rejected with TPM_RC_INTEGRITY. A
    /// build that substituted a fixed all-zero seed would instead derive the same attacker-known HMAC key, match
    /// the forged HMAC, and return TPM_RC_SUCCESS with an attacker-chosen credential that never validly decrypted
    /// to the endorsement key — a forgery/distinguishing oracle defeating attestation soundness. This test fails
    /// against that build and passes only when the substitute is unpredictable.
    /// </summary>
    [TestMethod]
    public async Task ForgedCredentialUnderTheZeroSubstituteSeedIsRejectedWithIntegrityError()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateRsaEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                byte[] akName = ak.Name.Span.ToArray();

                //Forge the outer wrap under the all-zero seed — every input (the seed, the AK Name, the KDFa
                //labels) is public, so no secret and no endorsement-key private key participates. This is the
                //blob a fixed-substitute-seed implementation would accept.
                using IMemoryOwner<byte> zeroSeedOwner = pool.Rent(Sha256DigestSize);
                zeroSeedOwner.Memory.Span[..Sha256DigestSize].Clear();
                (IMemoryOwner<byte> blob, int blobLength) = await BuildCredentialBlobAsync(
                    zeroSeedOwner.Memory[..Sha256DigestSize], CredentialSecret.Memory, akName, pool, TestContext.CancellationToken).ConfigureAwait(false);

                //A secret whose RSADP recovery cannot OAEP-decode (an all-zero ciphertext fails the lHash check),
                //forcing the executor onto the deferred-substitution branch under attacker control.
                using IMemoryOwner<byte> secret = pool.Rent(RsaModulusBytes);
                secret.Memory.Span[..RsaModulusBytes].Clear();
                try
                {
                    TpmResult<ActivateCredentialResponse> activateResult = await ActivateOverPolicyAsync(
                        tpm, registry, pool, ak.ObjectHandle, ek.ObjectHandle, blob.Memory[..blobLength], secret.Memory[..RsaModulusBytes], ak.Name.Span.ToArray(), ek.Name.Span.ToArray()).ConfigureAwait(false);

                    Assert.IsFalse(
                        activateResult.IsSuccess,
                        "A credential forged under the fixed all-zero substitute seed must never activate — that would bypass the endorsement key entirely.");
                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_INTEGRITY,
                        activateResult.ResponseCode,
                        "An OAEP decode failure must derive an unpredictable substitute seed, so the forged outer HMAC fails and activation is rejected with TPM_RC_INTEGRITY (Part 1, Annex B.10.3).");
                }
                finally
                {
                    blob.Dispose();
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
    /// Builds a credential blob and RSA-OAEP-encrypted secret: a fresh random credential-protection seed drawn
    /// through the registered entropy seam, hand-composed EME-OAEP encoding (<see cref="EncodeEmeOaep"/>, whose
    /// underlying hash primitives route through the registered digest seam) straight to the EK's exported
    /// modulus via raw RSAEP (<see cref="Rsaep"/>), and the outer wrap (<see cref="BuildCredentialBlobAsync"/>)
    /// bound to <paramref name="objectName"/>.
    /// </summary>
    /// <param name="credential">The plaintext credential to wrap.</param>
    /// <param name="objectName">The Name of the object the credential is bound to (the AK).</param>
    /// <param name="ekModulus">The credential key's (EK's) exported public modulus, unsigned big-endian.</param>
    /// <param name="pool">The memory pool for all pooled allocations.</param>
    /// <param name="cancellationToken">A token observed across the KDF/HMAC computations.</param>
    /// <returns>The credential blob and encrypted secret, each with its written length; the caller disposes both owners.</returns>
    private static async Task<(IMemoryOwner<byte> Blob, int BlobLength, IMemoryOwner<byte> Secret, int SecretLength)> BuildChallengerRsaCredentialAsync(
        ReadOnlyMemory<byte> credential, ReadOnlyMemory<byte> objectName, ReadOnlyMemory<byte> ekModulus, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> seedOwner = pool.Rent(Sha256DigestSize);
        using IMemoryOwner<byte> emOwner = pool.Rent(RsaModulusBytes);
        try
        {
            using(Nonce seedNonce = CryptographicKeyEvents.GenerateNonce(Sha256DigestSize, Tag.Create((typeof(Purpose), Purpose.Nonce)), pool))
            {
                seedNonce.AsReadOnlySpan().CopyTo(seedOwner.Memory.Span[..Sha256DigestSize]);
            }

            EncodeEmeOaep(seedOwner.Memory.Span[..Sha256DigestSize], emOwner.Memory.Span[..RsaModulusBytes], pool);

            (IMemoryOwner<byte> blobOwner, int blobLength) = await BuildCredentialBlobAsync(
                seedOwner.Memory[..Sha256DigestSize], credential, objectName, pool, cancellationToken).ConfigureAwait(false);
            try
            {
                byte[] ciphertext = Rsaep(emOwner.Memory.Span[..RsaModulusBytes], ekModulus.Span);
                (IMemoryOwner<byte> secretOwner, int secretLength) = FrameRsaSecret(ciphertext, pool);

                return (blobOwner, blobLength, secretOwner, secretLength);
            }
            catch
            {
                blobOwner.Dispose();
                throw;
            }
        }
        finally
        {
            seedOwner.Memory.Span[..Sha256DigestSize].Clear();
            emOwner.Memory.Span[..RsaModulusBytes].Clear();
        }
    }

    /// <summary>
    /// Composes RFC 8017 §7.1.1 EME-OAEP encoding for the credential-protection seed: <c>lHash =
    /// SHA-256(OaepLabelOctets)</c>, <c>DB = lHash ‖ PS ‖ 0x01 ‖ seed</c> (158 zero-octet <c>PS</c> for the
    /// L-1/32-octet-seed sizing), <c>dbMask</c>/<c>seedMask</c> from <see cref="Mgf1Sha256"/>, and <c>EM = 0x00 ‖
    /// maskedSeed ‖ maskedDB</c> — the padding/masking structure by hand, but every SHA-256 call through the
    /// registered digest seam (never a bare <see cref="SHA256"/> call), and the OAEP internal random octet
    /// string through the registered entropy seam (never a bare <see cref="RandomNumberGenerator"/> call).
    /// </summary>
    /// <param name="seed">The 32-octet credential-protection seed — OAEP's message <c>M</c> (not to be confused with OAEP's own internal random "seed", <c>seedOaep</c> below).</param>
    /// <param name="em">The 256-octet destination for the encoded message <c>EM</c>.</param>
    /// <param name="pool">The memory pool for the digest/entropy computations.</param>
    private static void EncodeEmeOaep(ReadOnlySpan<byte> seed, Span<byte> em, BaseMemoryPool pool)
    {
        int hLen = Sha256DigestSize;
        int k = em.Length;
        int mLen = seed.Length;
        int psLen = k - mLen - (2 * hLen) - 2;
        int dbLen = k - hLen - 1;

        //DB = lHash || PS || 0x01 || seed. Reused in place below to become maskedDB.
        Span<byte> db = stackalloc byte[dbLen];
        using(DigestValue lHash = CryptographicKeyEvents.ComputeDigest(OaepLabelOctets.Span, hLen, DigestTag(), pool))
        {
            lHash.AsReadOnlySpan().CopyTo(db);
        }
        db.Slice(hLen, psLen).Clear();
        db[hLen + psLen] = 0x01;
        seed.CopyTo(db[(hLen + psLen + 1)..]);

        //OAEP's own internal random octet string (RFC 8017's "seed") — a distinct value from the TPM credential
        //seed this method's own "seed" parameter carries; reused in place below to become maskedSeed.
        Span<byte> seedOaep = stackalloc byte[hLen];
        try
        {
            using(Nonce seedOaepNonce = CryptographicKeyEvents.GenerateNonce(hLen, Tag.Create((typeof(Purpose), Purpose.Nonce)), pool))
            {
                seedOaepNonce.AsReadOnlySpan().CopyTo(seedOaep);
            }

            Span<byte> dbMask = stackalloc byte[dbLen];
            try
            {
                Mgf1Sha256(seedOaep, dbMask, pool);
                for(int i = 0; i < dbLen; i++)
                {
                    db[i] ^= dbMask[i];
                }
            }
            finally
            {
                dbMask.Clear();
            }

            Span<byte> seedMask = stackalloc byte[hLen];
            try
            {
                Mgf1Sha256(db, seedMask, pool);
                for(int i = 0; i < hLen; i++)
                {
                    seedOaep[i] ^= seedMask[i];
                }
            }
            finally
            {
                seedMask.Clear();
            }

            em[0] = 0x00;
            seedOaep.CopyTo(em[1..]);
            db.CopyTo(em[(1 + hLen)..]);
        }
        finally
        {
            seedOaep.Clear();
            db.Clear();
        }
    }

    /// <summary>
    /// Composes the MGF1 mask-generation function (RFC 8017 §B.2.1): <c>T = Hash(seed ‖ 0) ‖ Hash(seed ‖ 1) ‖
    /// ...</c>, truncated to <paramref name="mask"/>'s length — each block computed through the registered
    /// digest seam, never a bare <see cref="SHA256"/> call.
    /// </summary>
    /// <param name="seed">The MGF1 seed octets.</param>
    /// <param name="mask">The destination for the generated mask.</param>
    /// <param name="pool">The memory pool for the digest computations.</param>
    private static void Mgf1Sha256(ReadOnlySpan<byte> seed, Span<byte> mask, BaseMemoryPool pool)
    {
        int hLen = Sha256DigestSize;
        Span<byte> counterInput = stackalloc byte[seed.Length + sizeof(uint)];
        seed.CopyTo(counterInput);

        int produced = 0;
        for(uint counter = 0; produced < mask.Length; counter++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(counterInput[seed.Length..], counter);

            using DigestValue block = CryptographicKeyEvents.ComputeDigest(counterInput, hLen, DigestTag(), pool);

            int take = Math.Min(hLen, mask.Length - produced);
            block.AsReadOnlySpan()[..take].CopyTo(mask[produced..]);
            produced += take;
        }

        counterInput.Clear();
    }

    /// <summary>
    /// Performs raw RSAEP (TPM 2.0 Library Part 1, Annex B.2): <c>c = EM^e mod n</c>, via
    /// <see cref="BigInteger.ModPow(BigInteger, BigInteger, BigInteger)"/> directly over the EK's exported
    /// modulus and the default public exponent 65537 — no BouncyCastle, no framework RSA (R-3).
    /// </summary>
    /// <param name="em">The OAEP-encoded message, the same octet width as <paramref name="modulus"/>.</param>
    /// <param name="modulus">The RSA public modulus, unsigned big-endian.</param>
    /// <returns>The ciphertext, unsigned big-endian, left-padded to <paramref name="modulus"/>'s width.</returns>
    private static byte[] Rsaep(ReadOnlySpan<byte> em, ReadOnlySpan<byte> modulus)
    {
        var message = new BigInteger(em, isUnsigned: true, isBigEndian: true);
        var n = new BigInteger(modulus, isUnsigned: true, isBigEndian: true);
        BigInteger ciphertext = BigInteger.ModPow(message, PublicExponent, n);

        return ToFixedWidthBigEndian(ciphertext, modulus.Length);
    }

    /// <summary>
    /// Left-pads an unsigned <see cref="BigInteger"/> to a fixed big-endian octet width, as RSA's modulus-width
    /// wire encoding requires (<see cref="BigInteger.TryWriteBytes"/> writes only the minimal representation).
    /// </summary>
    /// <param name="value">The non-negative value to encode.</param>
    /// <param name="width">The fixed output width in octets.</param>
    /// <returns>A new array of exactly <paramref name="width"/> octets.</returns>
    private static byte[] ToFixedWidthBigEndian(BigInteger value, int width)
    {
        byte[] result = new byte[width];
        int byteCount = value.GetByteCount(isUnsigned: true);
        if(byteCount > width)
        {
            throw new InvalidOperationException($"The value requires {byteCount} octets, which exceeds the requested width of {width}.");
        }

        bool written = value.TryWriteBytes(result.AsSpan(width - byteCount), out _, isUnsigned: true, isBigEndian: true);
        if(!written)
        {
            throw new InvalidOperationException("Failed to write the value into the fixed-width destination.");
        }

        return result;
    }

    /// <summary>
    /// Builds the credential blob (TPMS_ID_OBJECT), the outer wrap of TPM2_MakeCredential() (Part 1, clauses
    /// 24.3-24.6) — identical between the ECC and RSA arms (clause 24 does not branch on the credential key's
    /// algorithm), so this mirrors
    /// <see cref="TpmInHouseSimulatorCredentialOracleTests.BuildCredentialBlobAsync"/> exactly: <c>symKey =
    /// KDFa(seed, "STORAGE", objectName, empty, symBits)</c> keys the AES-CFB encryption of the marshaled
    /// credential (a zero feedback register, framework <see cref="Aes"/> — a different code path from the
    /// shipped ECB-loop CFB helper, <c>TpmParameterEncryption.AesCfb</c>), and <c>hmacKey = KDFa(seed,
    /// "INTEGRITY", empty, empty, digestBits)</c> keys <c>outerHmac = HMAC(hmacKey, encIdentity ||
    /// objectName)</c>, both derived/computed through the project's own <see cref="Kdfa"/> and the registered
    /// HMAC seam. The blob is <c>TPM2B(outerHmac) || encIdentity</c>.
    /// </summary>
    /// <param name="seed">The credential-protection seed (recovered independently on the RSA arm via <see cref="Rsaep"/>/<see cref="EncodeEmeOaep"/>).</param>
    /// <param name="credential">The plaintext credential.</param>
    /// <param name="objectName">The Name of the bound object (the AK).</param>
    /// <param name="pool">The memory pool for all pooled allocations.</param>
    /// <param name="cancellationToken">A token observed across the KDF/HMAC computations.</param>
    /// <returns>The credential blob owner and its written length; the caller disposes the owner.</returns>
    private static async Task<(IMemoryOwner<byte> Owner, int Length)> BuildCredentialBlobAsync(
        ReadOnlyMemory<byte> seed, ReadOnlyMemory<byte> credential, ReadOnlyMemory<byte> objectName, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int innerLength = sizeof(ushort) + credential.Length;

        //symKey = KDFa(SHA256, seed, "STORAGE", objectName, Empty, 128) — Part 1, clause 24.4, eq. (44).
        using IMemoryOwner<byte> symKeyOwner = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, seed, StorageLabel, objectName, ReadOnlyMemory<byte>.Empty, SymmetricKeyBits, pool, cancellationToken).ConfigureAwait(false);

        using IMemoryOwner<byte> encIdentityOwner = pool.Rent(innerLength);
        try
        {
            using IMemoryOwner<byte> plainOwner = pool.Rent(innerLength);
            Span<byte> plain = plainOwner.Memory.Span[..innerLength];
            BinaryPrimitives.WriteUInt16BigEndian(plain, (ushort)credential.Length);
            credential.Span.CopyTo(plain[sizeof(ushort)..]);

            Span<byte> zeroFeedback = stackalloc byte[AesBlockSize];
            byte[] symKeyArray = symKeyOwner.Memory.Span[..SymmetricKeyBytes].ToArray();
            try
            {
                using Aes aes = Aes.Create();
                aes.Key = symKeyArray;

                //Independent oracle: the framework's native CFB mode with a 128-bit feedback register, a
                //different code path from the shipped ECB-loop CFB helper (TpmParameterEncryption.AesCfb).
                aes.EncryptCfb(plain, zeroFeedback, encIdentityOwner.Memory.Span[..innerLength], PaddingMode.None, feedbackSizeInBits: AesBlockSize * 8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(symKeyArray);
            }

            plain.Clear();
        }
        finally
        {
            symKeyOwner.Memory.Span[..SymmetricKeyBytes].Clear();
        }

        //hmacKey = KDFa(SHA256, seed, "INTEGRITY", Empty, Empty, 256) — Part 1, clause 24.4, eq. (46).
        using IMemoryOwner<byte> hmacKeyOwner = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, seed, IntegrityLabel, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, Sha256DigestSize * 8, pool, cancellationToken).ConfigureAwait(false);

        int messageLength = innerLength + objectName.Length;
        using IMemoryOwner<byte> messageOwner = pool.Rent(messageLength);
        {
            Span<byte> message = messageOwner.Memory.Span[..messageLength];
            encIdentityOwner.Memory.Span[..innerLength].CopyTo(message);
            objectName.Span.CopyTo(message[innerLength..]);
        }

        try
        {
            //outerHmac = HMAC_SHA256(hmacKey, encIdentity || objectName) — Part 1, clause 24.4, eq. (47).
            using HmacValue outerHmac = await CryptographicKeyEvents.ComputeHmacAsync(
                messageOwner.Memory[..messageLength], hmacKeyOwner.Memory[..Sha256DigestSize], outputByteLength: Sha256DigestSize, tag: HmacTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            int blobLength = sizeof(ushort) + Sha256DigestSize + innerLength;
            IMemoryOwner<byte> blobOwner = pool.Rent(blobLength);
            try
            {
                Span<byte> blob = blobOwner.Memory.Span[..blobLength];
                BinaryPrimitives.WriteUInt16BigEndian(blob, (ushort)Sha256DigestSize);
                outerHmac.AsReadOnlySpan().CopyTo(blob[sizeof(ushort)..]);
                encIdentityOwner.Memory.Span[..innerLength].CopyTo(blob[(sizeof(ushort) + Sha256DigestSize)..]);

                return (blobOwner, blobLength);
            }
            catch
            {
                blobOwner.Dispose();
                throw;
            }
        }
        finally
        {
            hmacKeyOwner.Memory.Span[..Sha256DigestSize].Clear();
            messageOwner.Memory.Span[..messageLength].Clear();
        }
    }

    /// <summary>
    /// Builds the digest <see cref="Tag"/> exactly as <c>TpmCommandExecutor.BuildDigestTag</c> does: SHA-256
    /// digest, raw encoding, direct material.
    /// </summary>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>
    /// Builds the HMAC <see cref="Tag"/> exactly as <c>TpmSession.ComputeSessionHmacAsync</c> does: SHA-256
    /// HMAC, raw encoding, direct material.
    /// </summary>
    private static Tag HmacTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Hmac).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>
    /// Copies the OAEP ciphertext into a pooled buffer as the encrypted-secret transport. R-9: the RSA arm's
    /// <c>TPM2B_ENCRYPTED_SECRET</c> content has no sub-structure (TPM 2.0 Library Part 2, clauses 11.4.2 and
    /// 11.4.3, Table 190/191) — unlike the ECC arm's marshaled <c>TPMS_ECC_POINT</c>, the ciphertext IS the
    /// content verbatim; <see cref="ActivateCredentialInput.Create"/> supplies the one
    /// <c>TPM2B_ENCRYPTED_SECRET</c> size prefix the wire command carries, so no additional framing belongs here.
    /// </summary>
    /// <param name="ciphertext">The OAEP ciphertext.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The secret owner and its written length; the caller disposes the owner.</returns>
    private static (IMemoryOwner<byte> Owner, int Length) FrameRsaSecret(ReadOnlySpan<byte> ciphertext, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(ciphertext.Length);
        try
        {
            ciphertext.CopyTo(owner.Memory.Span[..ciphertext.Length]);

            return (owner, ciphertext.Length);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Drives <c>TPM2_ActivateCredential()</c> over a policy session satisfying PolicyA: starts a policy
    /// session, runs <c>TPM2_PolicySecret()</c> against the Endorsement Hierarchy, then submits the challenger's
    /// blob/secret with the activate object authorized by an empty password and the credential key authorized by
    /// the satisfied policy session (TCG EK Credential Profile, Annex B.3.2).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="activateHandle">The attestation key handle (ADMIN role).</param>
    /// <param name="keyHandle">The credential key (EK) handle (USER role, authorized by the policy session).</param>
    /// <param name="credentialBlob">The challenger-built credential blob.</param>
    /// <param name="secret">The challenger-built encrypted secret.</param>
    /// <param name="activateName">The activate object's Name (for the policy session's handle-name binding).</param>
    /// <param name="keyName">The credential key's Name (for the policy session's handle-name binding).</param>
    /// <returns>The TPM2_ActivateCredential() result.</returns>
    private async Task<TpmResult<ActivateCredentialResponse>> ActivateOverPolicyAsync(
        TpmDevice tpm,
        TpmResponseRegistry registry,
        BaseMemoryPool pool,
        TpmiDhObject activateHandle,
        TpmiDhObject keyHandle,
        ReadOnlyMemory<byte> credentialBlob,
        ReadOnlyMemory<byte> secret,
        ReadOnlyMemory<byte> activateName,
        ReadOnlyMemory<byte> keyName)
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

        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(activateHandle, keyHandle, credentialBlob.Span, secret.Span, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPolicySession keySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
        ReadOnlyMemory<byte>[] handleNames = [activateName, keyName];

        return await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            tpm, activateInput, [activateAuth, keySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates the standard RSA 2048 endorsement key (TCG EK Credential Profile, Annex B.3.3, Template L-1)
    /// under the Endorsement Hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateRsaEndorsementKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (standard RSA EK) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary RSA-2048 signing key (the AK) under the given hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            hierarchy, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary signing key ({hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a simulator with the RSA (framework key generation and sign/verify, BouncyCastle OAEP) signing
    /// backend wired, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// No ECC backend is wired — this file creates only RSA keys.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-rsa-credoracle", rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
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
    /// Creates a response codec registry covering the commands these tests issue. TPM2_MakeCredential is
    /// deliberately not registered: this file never calls it.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
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
    /// Rents a buffer from <see cref="BaseMemoryPool.Shared"/> sized to <paramref name="literal"/> and copies the
    /// literal's bytes into it, so a fixed test constant is pool-backed rather than a naked array.
    /// </summary>
    /// <param name="literal">The compile-time literal bytes to copy into pooled memory.</param>
    /// <returns>A pooled owner holding exactly <paramref name="literal"/>'s bytes.</returns>
    private static IMemoryOwner<byte> RentLiteral(ReadOnlySpan<byte> literal)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(literal.Length);
        literal.CopyTo(owner.Memory.Span);

        return owner;
    }
}
