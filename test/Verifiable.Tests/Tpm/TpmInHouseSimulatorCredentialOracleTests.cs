using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Independent challenger-side oracle for the TPM2_MakeCredential / TPM2_ActivateCredential outer wrap (TPM 2.0
/// Library Part 1, clauses 24.3-24.6; Annex C.6.1 "ECDH", C.6.4 "ECC Secret Sharing for Credentials"). Every
/// primitive on the challenger side is independent of the simulator's own implementation: framework
/// <see cref="ECDiffieHellman"/> performs the P-256 agreement (a different provider from the simulator's ECC
/// signing backend, <see cref="BouncyCastleTpmEccSigningBackend.ComputeSharedSecret"/>), KDFa and KDFe (Part 1,
/// §11.4.10.2/§11.4.10.3) are transcribed in-test directly against <see cref="HMACSHA256"/>/<see cref="SHA256"/>
/// rather than calling the shipped <see cref="Kdfa"/>/<see cref="Kdfe"/> classes, and the inner encryption uses
/// framework <see cref="Aes"/> in its native CFB mode (a different code path from the shipped ECB-loop CFB
/// helper, <c>TpmParameterEncryption.AesCfb</c>). This file never calls TPM2_MakeCredential(): the credential
/// blob and encrypted secret are assembled here from first principles and driven only through the production
/// TPM2_ActivateCredential() executor path, so a shared bug in the simulator's own MakeCredential/
/// ActivateCredential crypto — which would round-trip silently against a same-implementation test — cannot
/// hide from this oracle.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorCredentialOracleTests
{
    /// <summary>
    /// The challenger's secret credential. Fourteen octets, so the marshaled inner data (a 2-octet size prefix
    /// plus the credential) is exactly one 16-octet AES block: framework <see cref="Aes.EncryptCfb"/> with a
    /// full-width (128-bit) feedback register and <see cref="PaddingMode.None"/> requires block-aligned input
    /// (it has no short-final-block handling, unlike the shipped hand-rolled CFB helper), so this length sidesteps
    /// that framework constraint rather than reimplementing partial-block chaining in the independent oracle.
    /// </summary>
    private static IMemoryOwner<byte> CredentialSecret { get; } =
        RentLiteral([0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD]);

    /// <summary>The SHA-256 digest size in octets, also the size of every P-256 field element.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The credential symmetric key width in bits (Part 1, clause 25.2: AES-128 for the ECC storage/EK template).</summary>
    private const int SymmetricKeyBits = 128;

    /// <summary>The credential symmetric key width in octets.</summary>
    private const int SymmetricKeyBytes = SymmetricKeyBits / 8;

    /// <summary>The AES block size in octets, also the width of the all-zero CFB feedback register (IV).</summary>
    private const int AesBlockSize = 16;

    /// <summary>The KDFe use label for seed derivation (Part 1, clause 24.4; Annex C.6.4).</summary>
    private const string IdentityLabel = "IDENTITY";

    /// <summary>The KDFa use label for the inner symmetric key (Part 1, clause 24.4, eq. (44)).</summary>
    private const string StorageLabel = "STORAGE";

    /// <summary>The KDFa use label for the outer HMAC key (Part 1, clause 24.4, eq. (46)).</summary>
    private const string IntegrityLabel = "INTEGRITY";

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Releases the pooled <see cref="CredentialSecret"/> buffer shared across every test in this class.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        CredentialSecret.Dispose();
    }

    /// <summary>
    /// Verifies that a credential blob and encrypted secret built entirely from independent primitives (no call
    /// to TPM2_MakeCredential(), no call to the shipped KDFs or parameter-encryption helpers) is recovered
    /// correctly by the production TPM2_ActivateCredential() executor.
    /// </summary>
    [TestMethod]
    public async Task ChallengerBuiltCredentialActivatesThroughTheProductionExecutor()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                TpmsEccPoint ekPoint = ek.OutPublic.PublicArea.Unique.Ecc!;
                byte[] ekX = ekPoint.X.AsReadOnlySpan().ToArray();
                byte[] ekY = ekPoint.Y.AsReadOnlySpan().ToArray();
                byte[] akName = ak.Name.Span.ToArray();

                (IMemoryOwner<byte> blob, int blobLength, IMemoryOwner<byte> secret, int secretLength) =
                    BuildChallengerCredential(CredentialSecret.Memory.Span, akName, ekX, ekY, pool);
                try
                {
                    using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, ek.ObjectHandle, blob.Memory.Span[..blobLength], secret.Memory.Span[..secretLength], pool);
                    using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                    TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
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
    /// TPM_RC_INTEGRITY: the challenger-built blob is otherwise valid, so the failure isolates the executor's
    /// integrity check rather than any other malformation.
    /// </summary>
    [TestMethod]
    public async Task ChallengerBuiltCredentialWithATamperedOuterHmacIsRejectedWithIntegrityError()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                TpmsEccPoint ekPoint = ek.OutPublic.PublicArea.Unique.Ecc!;
                byte[] ekX = ekPoint.X.AsReadOnlySpan().ToArray();
                byte[] ekY = ekPoint.Y.AsReadOnlySpan().ToArray();
                byte[] akName = ak.Name.Span.ToArray();

                (IMemoryOwner<byte> blob, int blobLength, IMemoryOwner<byte> secret, int secretLength) =
                    BuildChallengerCredential(CredentialSecret.Memory.Span, akName, ekX, ekY, pool);
                try
                {
                    //The blob layout is TPM2B(outerHmac) || encIdentity; flip one octet of the outerHmac itself
                    //(immediately after the 2-octet size prefix), leaving encIdentity and the secret untouched.
                    blob.Memory.Span[sizeof(ushort)] ^= 0xFF;

                    using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                        ak.ObjectHandle, ek.ObjectHandle, blob.Memory.Span[..blobLength], secret.Memory.Span[..secretLength], pool);
                    using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                    TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                        tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

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
    /// Builds a credential blob and encrypted secret entirely from independent primitives: a fresh ephemeral
    /// P-256 key agreed with the credential key's public point via framework <see cref="ECDiffieHellman"/>, an
    /// in-test KDFe transcription for the seed (Annex C.6.1, eq. (65)), and the outer wrap
    /// (<see cref="BuildCredentialBlob"/>) bound to <paramref name="objectName"/>.
    /// </summary>
    /// <param name="credential">The plaintext credential to wrap.</param>
    /// <param name="objectName">The Name of the object the credential is bound to (the AK).</param>
    /// <param name="credentialKeyX">The credential key's (EK's) public point X coordinate.</param>
    /// <param name="credentialKeyY">The credential key's (EK's) public point Y coordinate.</param>
    /// <param name="pool">The memory pool for all pooled allocations.</param>
    /// <returns>The credential blob and encrypted secret, each with its written length; the caller disposes both owners.</returns>
    private static (IMemoryOwner<byte> Blob, int BlobLength, IMemoryOwner<byte> Secret, int SecretLength) BuildChallengerCredential(
        ReadOnlySpan<byte> credential,
        ReadOnlySpan<byte> objectName,
        ReadOnlySpan<byte> credentialKeyX,
        ReadOnlySpan<byte> credentialKeyY,
        MemoryPool<byte> pool)
    {
        //Independent oracle: framework ECDiffieHellman performs the P-256 agreement, a different provider from
        //the simulator's own ECC signing backend, so the agreement itself is cross-checked rather than assumed.
        using ECDiffieHellman ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters ephemeralParameters = ephemeral.ExportParameters(includePrivateParameters: false);
        byte[] ephemeralX = ephemeralParameters.Q.X!;
        byte[] ephemeralY = ephemeralParameters.Q.Y!;

        using ECDiffieHellman credentialKeyEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = credentialKeyX.ToArray(), Y = credentialKeyY.ToArray() }
        });

        byte[] z = ephemeral.DeriveRawSecretAgreement(credentialKeyEcdh.PublicKey);
        try
        {
            Span<byte> seed = stackalloc byte[Sha256DigestSize];
            TranscribeKdfe(z, IdentityLabel, ephemeralX, credentialKeyX, Sha256DigestSize * 8, seed, pool);

            (IMemoryOwner<byte> blobOwner, int blobLength) = BuildCredentialBlob(seed, credential, objectName, pool);
            try
            {
                (IMemoryOwner<byte> secretOwner, int secretLength) = FrameEccPointSecret(ephemeralX, ephemeralY, pool);

                return (blobOwner, blobLength, secretOwner, secretLength);
            }
            catch
            {
                blobOwner.Dispose();
                throw;
            }
            finally
            {
                seed.Clear();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(z);
        }

        //Transcribes the TPM 2.0 KDFe construction (Part 1, §11.4.10.3, eqs. (9)(11)) directly against
        //SHA-256, independent of the shipped Kdfe class, so a shared bug in that class's digest-loop
        //implementation cannot round-trip silently against this oracle.
        static void TranscribeKdfe(
            ReadOnlySpan<byte> z, string label, ReadOnlySpan<byte> partyUInfo, ReadOnlySpan<byte> partyVInfo, int outputBits, Span<byte> destination, MemoryPool<byte> pool)
        {
            int outputBytes = outputBits / 8;
            int labelLength = Encoding.ASCII.GetByteCount(label);
            int inputLength = sizeof(uint) + z.Length + labelLength + 1 + partyUInfo.Length + partyVInfo.Length;

            using IMemoryOwner<byte> inputOwner = pool.Rent(inputLength);
            Span<byte> input = inputOwner.Memory.Span[..inputLength];
            int offset = sizeof(uint);
            z.CopyTo(input[offset..]);
            offset += z.Length;
            offset += Encoding.ASCII.GetBytes(label, input[offset..]);
            input[offset] = 0x00;
            offset += 1;
            partyUInfo.CopyTo(input[offset..]);
            offset += partyUInfo.Length;
            partyVInfo.CopyTo(input[offset..]);

            int produced = 0;
            Span<byte> block = stackalloc byte[Sha256DigestSize];
            for(uint counter = 1; produced < outputBytes; counter++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(input[..sizeof(uint)], counter);
                _ = SHA256.HashData(input, block);

                int take = Math.Min(Sha256DigestSize, outputBytes - produced);
                block[..take].CopyTo(destination[produced..]);
                produced += take;
            }

            input.Clear();
        }
    }

    /// <summary>
    /// Builds the credential blob (TPMS_ID_OBJECT), the outer wrap of TPM2_MakeCredential() (Part 1, clauses
    /// 24.3-24.6): <c>symKey = KDFa(seed, "STORAGE", objectName, empty, symBits)</c> keys the AES-CFB encryption
    /// of the marshaled credential (a zero feedback register), and
    /// <c>hmacKey = KDFa(seed, "INTEGRITY", empty, empty, digestBits)</c> keys
    /// <c>outerHmac = HMAC(hmacKey, encIdentity || objectName)</c>. The blob is <c>TPM2B(outerHmac) || encIdentity</c>.
    /// </summary>
    /// <param name="seed">The KDFe-derived seed.</param>
    /// <param name="credential">The plaintext credential.</param>
    /// <param name="objectName">The Name of the bound object (the AK).</param>
    /// <param name="pool">The memory pool for all pooled allocations.</param>
    /// <returns>The credential blob owner and its written length; the caller disposes the owner.</returns>
    private static (IMemoryOwner<byte> Owner, int Length) BuildCredentialBlob(
        ReadOnlySpan<byte> seed, ReadOnlySpan<byte> credential, ReadOnlySpan<byte> objectName, MemoryPool<byte> pool)
    {
        int innerLength = sizeof(ushort) + credential.Length;

        Span<byte> symKey = stackalloc byte[SymmetricKeyBytes];
        TranscribeKdfa(seed, StorageLabel, objectName, ReadOnlySpan<byte>.Empty, SymmetricKeyBits, symKey, pool);

        using IMemoryOwner<byte> encIdentityOwner = pool.Rent(innerLength);
        Span<byte> encIdentity = encIdentityOwner.Memory.Span[..innerLength];
        {
            using IMemoryOwner<byte> plainOwner = pool.Rent(innerLength);
            Span<byte> plain = plainOwner.Memory.Span[..innerLength];
            BinaryPrimitives.WriteUInt16BigEndian(plain, (ushort)credential.Length);
            credential.CopyTo(plain[sizeof(ushort)..]);

            Span<byte> zeroFeedback = stackalloc byte[AesBlockSize];
            byte[] symKeyArray = symKey.ToArray();
            try
            {
                using Aes aes = Aes.Create();
                aes.Key = symKeyArray;

                //Independent oracle: the framework's native CFB mode with a 128-bit feedback register, a
                //different code path from the shipped ECB-loop CFB helper (TpmParameterEncryption.AesCfb).
                aes.EncryptCfb(plain, zeroFeedback, encIdentity, PaddingMode.None, feedbackSizeInBits: AesBlockSize * 8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(symKeyArray);
            }

            plain.Clear();
        }

        symKey.Clear();

        Span<byte> hmacKey = stackalloc byte[Sha256DigestSize];
        TranscribeKdfa(seed, IntegrityLabel, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Sha256DigestSize * 8, hmacKey, pool);

        int messageLength = innerLength + objectName.Length;
        using IMemoryOwner<byte> messageOwner = pool.Rent(messageLength);
        Span<byte> message = messageOwner.Memory.Span[..messageLength];
        encIdentity.CopyTo(message);
        objectName.CopyTo(message[innerLength..]);

        Span<byte> outerHmac = stackalloc byte[Sha256DigestSize];
        _ = HMACSHA256.HashData(hmacKey, message, outerHmac);
        hmacKey.Clear();
        message.Clear();

        int blobLength = sizeof(ushort) + Sha256DigestSize + innerLength;
        IMemoryOwner<byte> blobOwner = pool.Rent(blobLength);
        try
        {
            Span<byte> blob = blobOwner.Memory.Span[..blobLength];
            BinaryPrimitives.WriteUInt16BigEndian(blob, (ushort)Sha256DigestSize);
            outerHmac.CopyTo(blob[sizeof(ushort)..]);
            encIdentity.CopyTo(blob[(sizeof(ushort) + Sha256DigestSize)..]);

            return (blobOwner, blobLength);
        }
        catch
        {
            blobOwner.Dispose();
            throw;
        }
        finally
        {
            outerHmac.Clear();
        }

        //Transcribes the TPM 2.0 KDFa construction (Part 1, §11.4.10.2, eqs. (6)(8)) directly against
        //HMAC-SHA-256, independent of the shipped Kdfa class, so a shared bug in that class's HMAC-loop
        //implementation cannot round-trip silently against this oracle.
        static void TranscribeKdfa(
            ReadOnlySpan<byte> key, string label, ReadOnlySpan<byte> contextU, ReadOnlySpan<byte> contextV, int outputBits, Span<byte> destination, MemoryPool<byte> pool)
        {
            int outputBytes = outputBits / 8;
            int labelLength = Encoding.ASCII.GetByteCount(label);
            int inputLength = sizeof(uint) + labelLength + 1 + contextU.Length + contextV.Length + sizeof(uint);

            using IMemoryOwner<byte> inputOwner = pool.Rent(inputLength);
            Span<byte> input = inputOwner.Memory.Span[..inputLength];
            int offset = sizeof(uint);
            offset += Encoding.ASCII.GetBytes(label, input[offset..]);
            input[offset] = 0x00;
            offset += 1;
            contextU.CopyTo(input[offset..]);
            offset += contextU.Length;
            contextV.CopyTo(input[offset..]);
            offset += contextV.Length;
            BinaryPrimitives.WriteUInt32BigEndian(input[offset..], (uint)outputBits);

            int produced = 0;
            Span<byte> block = stackalloc byte[Sha256DigestSize];
            for(uint counter = 1; produced < outputBytes; counter++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(input[..sizeof(uint)], counter);
                _ = HMACSHA256.HashData(key, input, block);

                int take = Math.Min(Sha256DigestSize, outputBytes - produced);
                block[..take].CopyTo(destination[produced..]);
                produced += take;
            }

            input.Clear();
        }
    }

    /// <summary>
    /// Frames the ephemeral public point as the encrypted-secret transport: a marshaled TPMS_ECC_POINT
    /// (<c>TPM2B(x) || TPM2B(y)</c>), the ECC form of TPM2B_ENCRYPTED_SECRET (Part 2, clauses 11.2.5 and 11.4.33).
    /// </summary>
    /// <param name="x">The ephemeral public point's X coordinate.</param>
    /// <param name="y">The ephemeral public point's Y coordinate.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The secret owner and its written length; the caller disposes the owner.</returns>
    private static (IMemoryOwner<byte> Owner, int Length) FrameEccPointSecret(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, MemoryPool<byte> pool)
    {
        int length = 2 * (sizeof(ushort) + x.Length);
        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            writer.WriteTpm2b(x);
            writer.WriteTpm2b(y);

            return (owner, length);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
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
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
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
    /// Creates a primary ECC P-256 signing key (the AK) under the given hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
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
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it
    /// through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-credoracle", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
    private async Task BringOperationalAsync(TpmSimulator simulator, MemoryPool<byte> pool)
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
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle, MemoryPool<byte> pool)
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
