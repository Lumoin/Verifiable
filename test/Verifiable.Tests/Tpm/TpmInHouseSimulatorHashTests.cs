using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The one-shot <c>TPM2_Hash()</c> on the in-house simulator through the production executor and codec (TPM
/// 2.0 Library Part 3, clause 15.4): the digest against the framework's own SHA-2, and the
/// <c>TPMT_TK_HASHCHECK</c> ticket proved end to end against <c>TPM2_SignDigest()</c> on a restricted key
/// (clause 20.7).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorHashTests
{
    private const int P256ComponentSize = 32;

    private const int Sha512DigestSize = 64;

    private const uint OutOfTableHierarchy = 0x4000_0099;

    private static byte[] TpmGeneratedValueBytes { get; } = [0xFF, 0x54, 0x43, 0x47];

    private static TpmiAlgHash Sha256 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

    private static TpmiAlgHash Sha512 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA512);

    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Clause 15.4.1: "This command performs a hash operation on a data buffer and returns the results" —
    /// <c>outHash</c> is SHA-256 of the data — and its ticket "can indicate that the hash is safe to sign":
    /// per clause 20.7 a RESTRICTED key accepts it, the signature verified off-TPM.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 15.4.1 and 20.7</see>.
    /// </summary>
    [TestMethod]
    public async Task HashReturnsTheSha256DigestAndATicketARestrictedKeyAccepts()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] data = RandomNumberGenerator.GetBytes(777);
        byte[] expectedDigest = SHA256.HashData(data);

        TpmResult<HashResponse> hashResult = await SubmitHashAsync(tpm, registry, pool, data, Sha256, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.IsTrue(hashResult.IsSuccess, $"TPM2_Hash() failed: '{hashResult.ResponseCode}'.");

        using HashResponse hash = hashResult.Value;
        Assert.AreSequenceEqual(expectedDigest, hash.OutHash.AsReadOnlySpan().ToArray(), "outHash must be the SHA-256 of the data.");
        Assert.IsFalse(hash.Validation.IsNull, "Safe-to-sign data under a real hierarchy must carry a non-NULL ticket.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, hash.Validation.Hierarchy, "The ticket's hierarchy must be the one the command named.");

        using CreatePrimaryResponse restrictedKey = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using SignDigestInput signInput = SignDigestInput.CreateForRestrictedKey(restrictedKey.ObjectHandle, expectedDigest, hash.Validation, pool);
        using TpmPasswordSession keySession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest() on a restricted key must accept the ticket TPM2_Hash() minted: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;
        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(restrictedKey.OutPublic.PublicArea.Unique.Ecc!, expectedDigest, signature.Signature),
            "The restricted key's signature over the TPM2_Hash() digest must verify off-TPM.");
    }

    /// <summary>
    /// Table 69: <c>hashAlg</c> selects the algorithm — SHA-512 returns a 64-octet <c>outHash</c> equal to the
    /// independent SHA-512; empty data hashes to SHA-256 of the empty message.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.4.2, Table 69</see>.
    /// </summary>
    [TestMethod]
    public async Task HashUnderSha512ReturnsTheSha512DigestAndEmptyDataHashesToTheEmptyMessageDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] data = RandomNumberGenerator.GetBytes(Tpm2bMaxBuffer.MaxSize);

        TpmResult<HashResponse> sha512Result = await SubmitHashAsync(tpm, registry, pool, data, Sha512, TpmiRhHierarchy.Platform).ConfigureAwait(false);
        Assert.IsTrue(sha512Result.IsSuccess, $"TPM2_Hash() under SHA-512 failed: '{sha512Result.ResponseCode}'.");
        using HashResponse sha512 = sha512Result.Value;
        Assert.AreEqual(Sha512DigestSize, sha512.OutHash.Size, "SHA-512 returns a 64-octet digest.");
        Assert.AreSequenceEqual(SHA512.HashData(data), sha512.OutHash.AsReadOnlySpan().ToArray(), "outHash must be the SHA-512 of the data.");
        Assert.AreEqual(TpmiRhHierarchy.Platform, sha512.Validation.Hierarchy, "The ticket carries the named hierarchy.");

        TpmResult<HashResponse> emptyResult = await SubmitHashAsync(tpm, registry, pool, [], Sha256, TpmiRhHierarchy.Null).ConfigureAwait(false);
        Assert.IsTrue(emptyResult.IsSuccess, $"TPM2_Hash() over empty data failed: '{emptyResult.ResponseCode}'.");
        using HashResponse empty = emptyResult.Value;
        Assert.AreSequenceEqual(SHA256.HashData([]), empty.OutHash.AsReadOnlySpan().ToArray(), "Empty data hashes to the SHA-256 of the empty message.");
    }

    /// <summary>
    /// Table 69: <c>hashAlg</c> "shall not be TPM_ALG_NULL" — the <c>TPMI_ALG_HASH</c> carries no <c>+</c>, so
    /// <c>TPM_ALG_NULL</c> fails the unmarshal with <c>#TPM_RC_HASH</c> (Part 2, Table 77); an unimplemented TCG
    /// hash (<c>TPM_ALG_SHA3_256</c>) is refused with the same code.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.4.2, Table 69; Part 2, clause 9.31, Table 77</see>.
    /// </summary>
    [TestMethod]
    public async Task HashWithNullOrAnUnimplementedHashAlgorithmReturnsHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<HashResponse> nullResult = await SubmitHashAsync(
            tpm, registry, pool, [0x01], TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL), TpmiRhHierarchy.Owner).ConfigureAwait(false);
        //TPM_ALG_NULL fails the TPMI_ALG_HASH unmarshal itself (Table 69's "shall not be TPM_ALG_NULL"; Part
        //2, Table 77's "TPMI_ALG_HASH carries no +"), through the same TPMI_ALG_HASH unmarshal gate as the
        //unimplemented-algorithm case below — hashAlg is TPM2_Hash()'s second parameter, index 1.
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), nullResult.ResponseCode, "hashAlg is TPM2_Hash()'s second parameter (Table 69, index 1); TPM_ALG_NULL must be refused with parameter-encoded TPM_RC_HASH.");

        TpmResult<HashResponse> sha3Result = await SubmitHashAsync(
            tpm, registry, pool, [0x01], TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA3_256), TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), sha3Result.ResponseCode, "hashAlg is TPM2_Hash()'s second parameter (Table 69, index 1); an unimplemented hash algorithm must be refused with parameter-encoded TPM_RC_HASH.");
    }

    /// <summary>
    /// Clause 15.4.1: "If the digest is not safe to sign, then the TPM will return a TPMT_TK_HASHCHECK with the
    /// hierarchy set to TPM_RH_NULL and digest set to the Empty Buffer" — data beginning with
    /// <c>TPM_GENERATED_VALUE</c>; and clause 20.7: a restricted key then refuses the digest.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 15.4.1 and 20.7</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOfDataBeginningWithTpmGeneratedReturnsTheNullTicketAndARestrictedKeyRefuses()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] data = [.. TpmGeneratedValueBytes, .. RandomNumberGenerator.GetBytes(40)];
        byte[] expectedDigest = SHA256.HashData(data);

        TpmResult<HashResponse> hashResult = await SubmitHashAsync(tpm, registry, pool, data, Sha256, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.IsTrue(hashResult.IsSuccess, $"TPM2_Hash() must still succeed: '{hashResult.ResponseCode}'.");

        using HashResponse hash = hashResult.Value;
        Assert.AreSequenceEqual(expectedDigest, hash.OutHash.AsReadOnlySpan().ToArray(), "The digest itself is unaffected by the ticket verdict.");
        Assert.IsTrue(hash.Validation.IsNull, "Data beginning with TPM_GENERATED_VALUE is not safe to sign, so the ticket is NULL even though a hierarchy was named.");

        using CreatePrimaryResponse restrictedKey = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using SignDigestInput signInput = SignDigestInput.CreateForRestrictedKey(restrictedKey.ObjectHandle, expectedDigest, hash.Validation, pool);
        using TpmPasswordSession keySession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), signResult.ResponseCode, "A restricted key must refuse a digest that carries only the NULL ticket.");
    }

    /// <summary>
    /// The ticket is withheld only when <c>data.size &gt;= sizeof(TPM_GENERATED_VALUE)</c>
    /// AND the data begins with it — three octets cannot begin with the four-octet constant, so the one-shot IS
    /// ticketed (the opposite of a sequence's short first block, clause 17.8.1's note).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.4.1; Part 4, TPM2_Hash()</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOfDataShorterThanFourOctetsIsTicketed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] data = [0xFF, 0x54, 0x43];

        TpmResult<HashResponse> hashResult = await SubmitHashAsync(tpm, registry, pool, data, Sha256, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.IsTrue(hashResult.IsSuccess, $"TPM2_Hash() failed: '{hashResult.ResponseCode}'.");

        using HashResponse hash = hashResult.Value;
        Assert.AreSequenceEqual(SHA256.HashData(data), hash.OutHash.AsReadOnlySpan().ToArray(), "outHash must be the SHA-256 of the three octets.");
        Assert.IsFalse(hash.Validation.IsNull, "Data shorter than sizeof(TPM_GENERATED_VALUE) cannot begin with it and is safe to sign.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, hash.Validation.Hierarchy, "The ticket carries the named hierarchy.");
    }

    /// <summary>
    /// Clause 15.4.1: "If hierarchy is TPM_RH_NULL, then digest in the ticket will be the Empty Buffer."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HashWithTheNullHierarchyReturnsTheNullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] data = RandomNumberGenerator.GetBytes(32);

        TpmResult<HashResponse> hashResult = await SubmitHashAsync(tpm, registry, pool, data, Sha256, TpmiRhHierarchy.Null).ConfigureAwait(false);
        Assert.IsTrue(hashResult.IsSuccess, $"TPM2_Hash() failed: '{hashResult.ResponseCode}'.");

        using HashResponse hash = hashResult.Value;
        Assert.AreSequenceEqual(SHA256.HashData(data), hash.OutHash.AsReadOnlySpan().ToArray(), "The digest is returned regardless of the ticket.");
        Assert.IsTrue(hash.Validation.IsNull, "TPM_RH_NULL asks for no ticket: hierarchy TPM_RH_NULL and an empty digest.");
    }

    /// <summary>
    /// Table 69: the tag is <c>TPM_ST_SESSIONS</c> only when an audit, encrypt, or decrypt session is present.
    /// This frame carries no authorization area at all behind that tag, so the TPM reads its own
    /// <c>data</c>/<c>hashAlg</c> octets as <c>authorizationSize</c> and answers the area's own structural
    /// refusal, <c>TPM_RC_AUTHSIZE</c> (clause 5.5, step 4.3), rather than misreading them as command
    /// parameters. A trailing octet after <c>hierarchy</c> is <c>TPM_RC_SIZE</c> (clause 5.8.2, Table 2);
    /// a hierarchy outside Part 2, Table 59 is <c>TPM_RC_VALUE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.4.2, Table 69, clause 5.5; Part 2, clause 9.13, Table 59</see>.
    /// </summary>
    [TestMethod]
    public async Task HashHandFramedWithSessionsReturnsAuthsizeATrailingOctetReturnsSizeAndAnOutOfTableHierarchyReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        TpmRcConstants sessionTagged = await SubmitHashCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, [0x01], (uint)TpmRh.TPM_RH_OWNER, trailing: []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, sessionTagged, "A TPM_ST_SESSIONS frame with no well-formed authorization area behind it must be refused with the area's own TPM_RC_AUTHSIZE.");

        TpmRcConstants trailing = await SubmitHashCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, [0x01], (uint)TpmRh.TPM_RH_OWNER, trailing: [0x00]).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, trailing, "An octet after the final parameter must be refused with TPM_RC_SIZE.");

        TpmRcConstants badHierarchy = await SubmitHashCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, [0x01], OutOfTableHierarchy, trailing: []).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 2), badHierarchy, "hierarchy is TPM2_Hash()'s third parameter (Table 69, index 2); one outside Table 59 must be refused with parameter-encoded TPM_RC_VALUE.");
    }

    /// <summary>Submits <c>TPM2_Hash()</c> through the production executor and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="data">The data to hash.</param>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <param name="hierarchy">The ticket hierarchy.</param>
    /// <returns>The executor result; the caller owns a successful value.</returns>
    private async Task<TpmResult<HashResponse>> SubmitHashAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, byte[] data, TpmiAlgHash hashAlg, TpmiRhHierarchy hierarchy)
    {
        using HashInput input = HashInput.Create(data, hashAlg, hierarchy, pool);

        return await TpmCommandExecutor.ExecuteAsync<HashResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_Hash()</c> command (Table 69: <c>data</c>, <c>hashAlg</c> = SHA-256,
    /// <c>hierarchy</c>) with a caller-chosen tag, raw hierarchy value, and trailing octets, and returns the
    /// response code.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="data">The data to hash.</param>
    /// <param name="rawHierarchy">The raw <c>hierarchy</c> value.</param>
    /// <param name="trailing">Octets appended after the final parameter.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitHashCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, ushort tag, byte[] data, uint rawHierarchy, byte[] trailing)
    {
        int length = TpmHeader.HeaderSize + sizeof(ushort) + data.Length + sizeof(ushort) + sizeof(uint) + trailing.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_Hash);
        header.WriteTo(ref writer);
        writer.WriteTpm2b(data);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        writer.WriteUInt32(rawHierarchy);
        writer.WriteBytes(trailing);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>Creates a RESTRICTED ECC P-256 signing primary under the owner hierarchy, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted ECC P-256) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Composes a restricted ECC signing key template — <c>TPMA_OBJECT.restricted</c> SET alongside <c>sign</c>,
    /// with no password — the key whose <c>TPM2_SignDigest()</c> demands a valid <c>TPMT_TK_HASHCHECK</c>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateRestrictedEccSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT |
            TpmaObject.RESTRICTED |
            TpmaObject.NO_DA;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>
    /// Verifies a P-256 ECDSA signature off-TPM against a public key reconstructed solely from the simulator's
    /// exported public point — sharing no code path with the signer.
    /// </summary>
    /// <param name="point">The exported public point.</param>
    /// <param name="digest">The digest that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns><see langword="true"/> when the signature verifies.</returns>
    private static bool VerifyEcdsaSignatureOffTpm(TpmsEccPoint point, byte[] digest, TpmuSignature signature)
    {
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);

        return ecdsa.VerifyHash(digest, p1363Signature);
    }

    /// <summary>Left-pads (or left-trims) a big-endian integer to exactly <paramref name="length"/> octets.</summary>
    /// <param name="value">The integer octets.</param>
    /// <param name="length">The fixed width.</param>
    /// <returns>The fixed-width octets.</returns>
    private static byte[] ToFixed(ReadOnlySpan<byte> value, int length)
    {
        byte[] result = new byte[length];
        if(value.Length <= length)
        {
            value.CopyTo(result.AsSpan(length - value.Length));
        }
        else
        {
            value[^length..].CopyTo(result);
        }

        return result;
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Hash, TpmResponseCodec.Hash);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);

        return registry;
    }

    /// <summary>Creates a powered-on simulator brought to the Operational phase with <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The simulator (the caller owns it).</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-hash",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Submits <c>TPM2_Startup(CLEAR)</c> to a powered-on simulator, asserting success.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>A task that completes when the TPM is Operational.</returns>
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
        Assert.AreEqual((uint)TpmRcConstants.TPM_RC_SUCCESS, responseHeader.Code, "TPM2_Startup(CLEAR) must answer TPM_RC_SUCCESS.");
    }
}
