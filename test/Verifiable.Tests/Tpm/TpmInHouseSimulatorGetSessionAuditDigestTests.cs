using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_GetSessionAuditDigest()</c> against the in-house behavioural <see cref="TpmSimulator"/>,
/// entirely in-process with no external assets, through the production command path
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="GetSessionAuditDigestInput"/> and response
/// codecs), on <c>TPM2_GetTime()</c>'s exact shape plus a third, unauthorized handle naming the audit session
/// whose digest is attested.
/// </summary>
/// <remarks>
/// <para>
/// Every expected digest is chained by the test itself from the raw octets it sent and read — cpHash per
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
/// clause 15.7, equation 15</see>, rpHash per
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
/// clause 15.8, equation 16</see>, and the extend per
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
/// clause 17.1, equation 30</see> — never read from <see cref="TpmSession"/>'s internals, the serializer, or
/// the simulator's own state. An audit session is first ESTABLISHED by hand-framing a single
/// <c>TPM2_GetRandom()</c> call over an unbound HMAC session claiming only <c>audit</c> (the one slot the
/// zero-handle command's authorization area admits for a session authorizing no entity), because
/// <see cref="TpmCommandExecutor"/>'s own client-side guards refuse that composition before any octet reaches
/// the wire; every subsequent <c>TPM2_GetSessionAuditDigest()</c> call then runs through the production
/// executor, naming the established session's raw handle at <c>sessionHandle</c>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorGetSessionAuditDigestTests
{
    /// <summary>The hash algorithm every session and signing scheme these tests negotiate.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width, in octets — the audit digest and cpHash/rpHash width used here.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The number of bytes <c>TPM2_GetRandom()</c> is asked to draw when establishing an audit session.</summary>
    private const ushort RandomDrawLength = 16;

    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA signer tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The real password installed on the endorsement hierarchy for the wrong-endorsement-password proof.</summary>
    private const string EndorsementHierarchyPassword = "gsad-endorsement-auth-proof";

    /// <summary>The real password the DA-protected signing key proof creates its signer with.</summary>
    private const string SigningKeyPassword = "gsad-signing-key-auth-proof";

    /// <summary>The caller nonce (qualifyingData) every attesting call echoes into the attestation's extraData.</summary>
    private static byte[] QualifyingData { get; } = "GetSessionAuditDigest qualifying data nonce."u8.ToArray();

    /// <summary>The Zero Digest of SHA-256 width — the audit digest's initialization value on first use (TPM 2.0 Library Part 1, clause 17.1).</summary>
    private static byte[] ZeroDigest { get; } = new byte[Sha256DigestSize];

    /// <summary>The endorsement hierarchy's installed password in wire form.</summary>
    private static byte[] EndorsementHierarchyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(EndorsementHierarchyPassword);

    /// <summary>A wrong guess at the endorsement hierarchy's password.</summary>
    private static byte[] WrongEndorsementHierarchyPasswordBytes { get; } = [0xC1, 0xC2, 0xC3, 0xC4];

    /// <summary>The DA-protected signer's own password in wire form.</summary>
    private static byte[] SigningKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SigningKeyPassword);

    /// <summary>A wrong guess at the signing key's password.</summary>
    private static byte[] WrongSigningKeyPasswordBytes { get; } = [0xD1, 0xD2, 0xD3, 0xD4];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// An ECC signer attests an established audit session's digest: the parsed <c>TPMS_ATTEST</c> carries type
    /// <c>TPM_ST_ATTEST_SESSION_AUDIT</c>, <c>exclusiveSession</c> YES, and <c>sessionDigest</c> equal to the
    /// chain this test computed from the establishing command's own octets, <c>extraData</c> echoes
    /// <c>qualifyingData</c>, and the signature verifies off-TPM under the signer's exported public key.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5.1; Part 2, clause 10.11.6, Table 148</see>.
    /// </summary>
    [TestMethod]
    public async Task EcdsaSignerOverEstablishedAuditSessionAttestsTheChainedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint auditHandle, TpmSession auditSession, byte[] expectedDigest) = await EstablishAuditSessionAsync(simulator, tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            using(TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool))
            using(TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool))
            using(GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
            {
                TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest (ECDSA) failed: '{result.ResponseCode}'.");

                using GetSessionAuditDigestResponse response = result.Value;
                AssertSessionAuditAttestation(response, expectedDigest, isExclusive: true);

                TpmsEccPoint akPoint = signer.OutPublic.PublicArea.Unique.Ecc!;
                var ecParameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = ToFixed(akPoint.X.AsReadOnlySpan(), P256ComponentSize),
                        Y = ToFixed(akPoint.Y.AsReadOnlySpan(), P256ComponentSize)
                    }
                };

                byte[] attestDigest = await ComputeSha256Async(response.AuditInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] p1363Signature = new byte[2 * P256ComponentSize];
                ToFixed(response.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
                ToFixed(response.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

                using ECDsa ecdsa = ECDsa.Create(ecParameters);
                Assert.IsTrue(
                    ecdsa.VerifyHash(attestDigest, p1363Signature),
                    "The signature must verify against the signer's exported public key.");
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An RSASSA signer attests an established audit session's digest identically to the ECC case, verified
    /// against the signer's exported RSA modulus.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaSsaSignerOverEstablishedAuditSessionAttestsTheChainedDigest()
    {
        await RunRsaSignerAsync(usePss: false).ConfigureAwait(false);
    }

    /// <summary>
    /// An RSAPSS signer attests an established audit session's digest identically to the RSASSA case, under
    /// PSS padding rather than PKCS#1 v1.5.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaPssSignerOverEstablishedAuditSessionAttestsTheChainedDigest()
    {
        await RunRsaSignerAsync(usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// The NULL signer performs every action of the command but "signs" with the NULL Signature:
    /// <c>sigAlg = TPM_ALG_NULL</c>, <c>qualifiedSigner</c> is the four-octet <c>TPM_RH_NULL</c> handle Name
    /// (never the Empty Buffer), and the attested digest is the same chain a real signer would attest.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.1; clause 18.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NullSignerOverEstablishedAuditSessionAttestsWithTheNullSignature()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint auditHandle, TpmSession auditSession, byte[] expectedDigest) = await EstablishAuditSessionAsync(simulator, tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            using(TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool))
            using(TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool))
            using(GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), QualifyingData, pool))
            {
                TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest (NULL signer) failed: '{result.ResponseCode}'.");

                using GetSessionAuditDigestResponse response = result.Value;
                Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_NULL, response.SignatureAlgorithm, "The NULL signer's sigAlg must be TPM_ALG_NULL.");
                Assert.IsTrue(response.Signature.IsNull, "The NULL signer produces the dispose-immune NULL Signature.");
                Assert.IsTrue(
                    response.AuditInfo.AttestationData.QualifiedSigner.Span.SequenceEqual(NullHandleNameBytes()),
                    "qualifiedSigner must be the 4-octet TPM_RH_NULL handle Name, not the Empty Buffer (Part 4, FillInAttestInfo).");
                AssertSessionAuditAttestation(response, expectedDigest, isExclusive: true);
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The atypical case (TPM 2.0 Library Part 1, clause 17.4): when the same session is both the audited
    /// companion and <c>sessionHandle</c>, the attested digest EXCLUDES this command's own cpHash/rpHash
    /// (equal to the pre-command chain, because the digest is signed before it is updated), while a
    /// subsequent, unaudited call over the same handle shows the chain now includes it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.4</see>.
    /// </summary>
    [TestMethod]
    public async Task SameSessionAsAuditedCompanionAndSessionHandleExcludesItsOwnCommandThenTheChainIncludesIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint auditHandle, TpmSession auditSession, byte[] establishedDigest) = await EstablishAuditSessionAsync(simulator, tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray(), HandleBytes(auditHandle)];

                byte[] cpHash;
                byte[] rpHash;
                using(TpmPasswordSession firstPrivacyAdminAuth = TpmPasswordSession.CreateEmpty(pool))
                using(TpmPasswordSession firstSignAuth = TpmPasswordSession.CreateEmpty(pool))
                using(GetSessionAuditDigestInput firstInput = GetSessionAuditDigestInput.ForEcdsa(
                    signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
                {
                    TpmResult<GetSessionAuditDigestResponse> firstResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                        tpm, firstInput, [firstPrivacyAdminAuth, firstSignAuth, auditSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(firstResult.IsSuccess, $"TPM2_GetSessionAuditDigest (self-audited) failed: '{firstResult.ResponseCode}'.");

                    using GetSessionAuditDigestResponse firstResponse = firstResult.Value;
                    AssertSessionAuditAttestation(firstResponse, establishedDigest, isExclusive: true);

                    using GetSessionAuditDigestInput cpHashInput = GetSessionAuditDigestInput.ForEcdsa(
                        signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                    byte[] sentParameters = new byte[cpHashInput.GetSerializedSize() - (3 * sizeof(uint))];
                    var parameterWriter = new TpmWriter(sentParameters);
                    cpHashInput.WriteParameters(ref parameterWriter);

                    cpHash = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_GetSessionAuditDigest, handleNames, sentParameters, pool).ConfigureAwait(false);

                    byte[] readParameters = new byte[
                        firstResponse.AuditInfo.GetSerializedSize() + sizeof(ushort) + firstResponse.Signature.GetSerializedSize()];
                    var responseWriter = new TpmWriter(readParameters);
                    firstResponse.AuditInfo.WriteTo(ref responseWriter);
                    responseWriter.WriteUInt16((ushort)firstResponse.SignatureAlgorithm);
                    firstResponse.Signature.WriteTo(ref responseWriter);

                    rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_GetSessionAuditDigest, readParameters, pool).ConfigureAwait(false);
                }

                byte[] expectedSecondDigest = await ExtendDigestAsync(establishedDigest, cpHash, rpHash, pool).ConfigureAwait(false);

                using TpmPasswordSession secondPrivacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession secondSignAuth = TpmPasswordSession.CreateEmpty(pool);
                using GetSessionAuditDigestInput secondInput = GetSessionAuditDigestInput.ForEcdsa(
                    signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

                TpmResult<GetSessionAuditDigestResponse> secondResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    tpm, secondInput, [secondPrivacyAdminAuth, secondSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(secondResult.IsSuccess, $"TPM2_GetSessionAuditDigest (follow-up) failed: '{secondResult.ResponseCode}'.");

                using GetSessionAuditDigestResponse secondResponse = secondResult.Value;
                AssertSessionAuditAttestation(secondResponse, expectedSecondDigest, isExclusive: true);
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An audited command over a DIFFERENT session, followed by a successful session-admitting command that
    /// does not use the audit session, clears exclusivity: <c>exclusiveSession</c> answers NO, while the
    /// digest itself is unchanged, since the intervening command was never audited.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ExclusiveSessionIsClearedByAnInterveningNoSessionsCommand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint auditHandle, TpmSession auditSession, byte[] establishedDigest) = await EstablishAuditSessionAsync(simulator, tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            {
                TpmResult<GetRandomResponse> intervening = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, new GetRandomInput(RandomDrawLength), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(intervening.IsSuccess, $"The intervening TPM2_GetRandom() must succeed: '{intervening.ResponseCode}'.");
                intervening.Value.Dispose();

                using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
                using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                    signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

                TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest failed: '{result.ResponseCode}'.");

                using GetSessionAuditDigestResponse response = result.Value;
                AssertSessionAuditAttestation(response, establishedDigest, isExclusive: false);
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The command "does not cause the audit session to be closed and does not reset the digest value": two
    /// calls in a row, with nothing intervening, return the identical digest both times. The first call reports
    /// <c>exclusiveSession</c> YES and the second NO, because the first call is itself a session-admitting command
    /// executed without the audit session — "The session is no longer the current exclusive audit session ... if
    /// an auditable command is executed that does not use the current exclusive audit session" (Part 1, clause
    /// 17.2) — while the digest it attests is untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5.1; Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task SecondCallReturnsTheSameDigestWithoutResettingIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint auditHandle, TpmSession auditSession, byte[] establishedDigest) = await EstablishAuditSessionAsync(simulator, tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            {
                for(int i = 0; i < 2; i++)
                {
                    using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
                    using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                    using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                        signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

                    TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                        tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest (call {i}) failed: '{result.ResponseCode}'.");

                    using GetSessionAuditDigestResponse response = result.Value;
                    AssertSessionAuditAttestation(response, establishedDigest, isExclusive: i == 0);
                }
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A loaded HMAC session that has never been used with the <c>audit</c> attribute set is refused with the
    /// <c>TPM_RC_TYPE</c>, handle-encoded to the same index: "If sessionHandle is not an audit session, the TPM shall return TPM_RC_TYPE."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5.1; Part 1, clause 17.4</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadedHmacSessionNeverUsedForAuditReturnsType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint plainHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        started.Dispose();

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                signer.ObjectHandle, TpmiShHmac.FromValue(plainHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), result.ResponseCode, "A never-audited loaded HMAC session is refused at sessionHandle, handle 3 of Table 103.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, plainHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>sessionHandle</c> is <c>TPM2_GetSessionAuditDigest()</c>'s 3rd handle (index 2, Table 103:
    /// privacyAdminHandle 0, signHandle 1, sessionHandle 2); an HMAC-range value naming no loaded session is a
    /// session in the handle area that is not present, <c>TPM_RC_REFERENCE_H2</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, step 2.4</see>.
    /// </summary>
    [TestMethod]
    public async Task UnloadedHmacRangeSessionHandleAnswersReferenceH2()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
            signer.ObjectHandle, TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H2, result.ResponseCode, "An in-range HMAC sessionHandle (index 2) naming no loaded session must be refused with TPM_RC_REFERENCE_H2 (TPM 2.0 Library Part 3, clause 5.4, step 2.4).");
    }

    /// <summary>
    /// A handle in the POLICY session range at <c>sessionHandle</c> is outside <c>TPMI_SH_HMAC</c>'s admitted
    /// range and is refused with <c>TPM_RC_VALUE</c> at parse, before the transition ever runs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.9, Table 55</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyRangeHandleAtSessionHandleReturnsValue()
    {
        await AssertSessionHandleOutOfRangeIsValueAsync(0x0300_0000u).ConfigureAwait(false);
    }

    /// <summary>
    /// A handle in the TRANSIENT-OBJECT range at <c>sessionHandle</c> is likewise outside <c>TPMI_SH_HMAC</c>'s
    /// admitted range and is refused with <c>TPM_RC_VALUE</c> at parse.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.9, Table 55</see>.
    /// </summary>
    [TestMethod]
    public async Task TransientHandleAtSessionHandleReturnsValue()
    {
        await AssertSessionHandleOutOfRangeIsValueAsync(0x8000_0000u).ConfigureAwait(false);
    }

    /// <summary>
    /// A privacyAdminHandle other than <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> is refused with <c>TPM_RC_VALUE</c>,
    /// H-encoded to privacyAdminHandle's own index: Table 66 (TPMI_RH_ENDORSEMENT) states "#TPM_RC_VALUE response
    /// code returned when the unmarshaling of this type fails" — <c>TPMI_RH_ENDORSEMENT</c> has exactly one legal
    /// value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.20, Table 66; Part 3, clause 18.5, Table 103</see>.
    /// </summary>
    [TestMethod]
    public async Task OwnerHandleAsPrivacyAdminReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.Create(
            TpmRh.TPM_RH_OWNER, signer.ObjectHandle, TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST),
            QualifyingData, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode, "TPM_RH_OWNER at privacyAdminHandle must be refused: only TPM_RH_ENDORSEMENT is admitted.");
    }

    /// <summary>
    /// A wrong endorsement hierarchy password answers the plain, never session-index-encoded, uncharged
    /// <c>TPM_RC_BAD_AUTH</c>: permanent hierarchies other than <c>lockoutAuth</c> are dictionary-attack exempt.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task WrongEndorsementPasswordReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, EndorsementHierarchyPasswordBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"Installing the endorsement hierarchy's authorization value failed: '{rotation.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession wrongPrivacyAdminAuth = TpmPasswordSession.Create(WrongEndorsementHierarchyPasswordBytes, pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
            signer.ObjectHandle, TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [wrongPrivacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "A wrong endorsement hierarchy password fails at the privacyAdminHandle authorization, session 1 of Table 103.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A wrong hierarchy authorization value must never move the dictionary-attack counter.");
    }

    /// <summary>
    /// A wrong password against a dictionary-attack-protected signer names the sign slot (index 1),
    /// session-index-encoded, with <c>TPM_RC_AUTH_FAIL</c>, and charges <c>failedTries</c> exactly once.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.7; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task WrongSignerPasswordChargesAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongSigningKeyPasswordBytes, pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
            signer.ObjectHandle, TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, wrongSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), result.ResponseCode,
            "A wrong signing-key password must name the sign slot (index 1), session-index-encoded.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "A wrong password against a DA-protected signer must charge failedTries exactly once.");
    }

    /// <summary>
    /// A non-signing (decrypt-only) key at <c>signHandle</c> is refused with <c>TPM_RC_KEY</c>: "If the sign
    /// attribute is not SET in the key referenced by signHandle then the TPM shall return TPM_RC_KEY."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NonSigningKeyReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                decryptKey.ObjectHandle, TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 1), result.ResponseCode, "A non-signing signHandle key must be refused with TPM_RC_KEY.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, decryptKey.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An RSA signing scheme against an ECC signing key is a genuine scheme/key-type mismatch, refused with
    /// <c>TPM_RC_SCHEME</c>, distinct from an unresolved handle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SchemeMismatchedToSignerKeyTypeReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForRsaSsa(
            signer.ObjectHandle, TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 1), result.ResponseCode, "An RSA scheme against an ECC signing key must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// An unsupported scheme hash algorithm (SHA-1) is refused with <c>TPM_RC_HASH</c> for a real signer,
    /// distinct from the key-type mismatch a wrong scheme selector produces.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task UnsupportedHashReturnsHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.Create(
            TpmRh.TPM_RH_ENDORSEMENT, signer.ObjectHandle, TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST),
            QualifyingData, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA1, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), result.ResponseCode, "An unsupported scheme hash algorithm must be refused with TPM_RC_HASH.");
    }

    /// <summary>
    /// A <c>qualifyingData</c> longer than <c>TPM2B_DATA</c>'s bound is refused with <c>TPM_RC_SIZE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5, Table 103</see>.
    /// </summary>
    [TestMethod]
    public async Task QualifyingDataOverBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        byte[] overWideData = new byte[Tpm2bData.MaxSize + 1];

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
            signer.ObjectHandle, TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST), overWideData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), result.ResponseCode, "qualifyingData over TPM2B_DATA's bound must be refused with TPM_RC_SIZE at qualifyingData, parameter 1 of Table 103.");
    }

    /// <summary>
    /// Both authorization slots require authorization, so a <c>TPM_ST_NO_SESSIONS</c> request is refused with
    /// <c>TPM_RC_AUTH_MISSING</c> — the GetTime idiom this command's Table 103 shares.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5, Table 103</see>.
    /// </summary>
    [TestMethod]
    public async Task NoSessionsTagReturnsAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(
            TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST), QualifyingData, pool);

        TpmRcConstants code = await SubmitNoSessionsAsync(simulator, pool, input).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_MISSING, code,
            "Both @privacyAdminHandle and @signHandle require authorization, so TPM_ST_NO_SESSIONS is TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// The over-sessions form: the endorsement slot rides a real, unbound HMAC session while a decrypt
    /// companion protects <c>qualifyingData</c>; both response HMACs verify through the production executor,
    /// and the attestation still carries the established digest. The two sessions are started BEFORE the audit
    /// session is established, since <c>TPM2_StartAuthSession()</c> admits sessions and would itself clear the
    /// exclusive session were it to run afterwards (Part 1, clause 17.2).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5, Table 103; TPM 2.0 Library Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task OverSessionsFormWithHmacPrivacyAdminAndDecryptCompanionAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint privacyAdminHandle, TpmSession privacyAdminSession) = await StartUnboundSessionWrapperAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartBoundSessionAsync(
            tpm, registry, pool, signer.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg)).ConfigureAwait(false);
        (uint auditHandle, TpmSession auditSession, byte[] establishedDigest) = await EstablishAuditSessionAsync(simulator, tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            using(privacyAdminSession)
            using(companion)
            {
                privacyAdminSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                    signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray(), HandleBytes(auditHandle)];

                TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    tpm, input, [privacyAdminSession, signAuth, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest (over sessions) failed: '{result.ResponseCode}'.");

                using GetSessionAuditDigestResponse response = result.Value;
                AssertSessionAuditAttestation(response, establishedDigest, isExclusive: true);
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, auditHandle).ConfigureAwait(false);
            await FlushHandleAsync(tpm, registry, pool, privacyAdminHandle).ConfigureAwait(false);
            await FlushHandleAsync(tpm, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// This implementation's tail order is KEY, then SCHEME, then TYPE: a non-signing signHandle combined with
    /// a non-audit sessionHandle answers KEY, not TYPE — the KEY gate runs before the audited session's own
    /// gates are ever reached (TPM 2.0 Library Part 3, clause 18.5).
    /// </summary>
    [TestMethod]
    public async Task NonSigningKeyAndNonAuditSessionReturnsKeyBeforeType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse decryptKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint plainHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        started.Dispose();

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                decryptKey.ObjectHandle, TpmiShHmac.FromValue(plainHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 1), result.ResponseCode,
                "A non-signing key must answer TPM_RC_KEY even when sessionHandle would separately earn TPM_RC_TYPE — Part 4 orders KEY ahead of the session's own gates.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, decryptKey.ObjectHandle.Value).ConfigureAwait(false);
            await FlushHandleAsync(tpm, registry, pool, plainHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A command submitted before <c>TPM2_Startup()</c> is refused before any of this command's own rules run.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.2</see>.
    /// </summary>
    [TestMethod]
    public async Task PreStartupReturnsInitialize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator(
            "tpm-in-house-get-session-audit-digest-pre-startup",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
            TpmiDhObject.FromValue(TpmHandleRanges.TRANSIENT_FIRST), TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST),
            QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, result.ResponseCode, "Before TPM2_Startup() every command is TPM_RC_INITIALIZE.");
    }

    /// <summary>
    /// Once a failed self-test has entered Failure Mode, every command but the few Failure Mode admits is
    /// refused before its own rules run.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task FailureModeReturnsFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator(
            "tpm-in-house-get-session-audit-digest-failure-mode",selfTest: TpmSelfTestBehavior.Fails,
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmRcConstants selfTestCode = await SubmitSelfTestAsync(simulator, pool).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode, "A failing self-test enters Failure Mode.");

        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
            TpmiDhObject.FromValue(TpmHandleRanges.TRANSIENT_FIRST), TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST),
            QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, result.ResponseCode, "In Failure Mode TPM2_GetSessionAuditDigest() is TPM_RC_FAILURE.");
    }

    /// <summary>
    /// A parse refusal (an out-of-range <c>sessionHandle</c>, <c>TPM_RC_VALUE</c>) returns every carrier the
    /// house pool rented, the caller-supplied sessions and input included.
    /// </summary>
    [TestMethod]
    public async Task MeteredPoolBalancesAcrossAParseRefusal()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(
                TpmiShHmac.FromValue(0x0300_0000u), QualifyingData, trackingPool.Pool);

            TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, input, [privacyAdminAuth, signAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, handleIndex: 2), result.ResponseCode,
                "Table 103: sessionHandle is TPM2_GetSessionAuditDigest()'s third handle (index 2).");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A parse refusal must return every carrier it rented.");
    }

    /// <summary>
    /// A transition refusal (a never-audited sessionHandle, <c>TPM_RC_TYPE</c>) returns every carrier the house
    /// pool rented.
    /// </summary>
    [TestMethod]
    public async Task MeteredPoolBalancesAcrossATransitionRefusal()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint plainHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        started.Dispose();

        try
        {
            long baseline = trackingPool.OutstandingCount;
            {
                using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
                using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                    signer.ObjectHandle, TpmiShHmac.FromValue(plainHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

                TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    tpm, input, [privacyAdminAuth, signAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), result.ResponseCode, "Table 103: sessionHandle is TPM2_GetSessionAuditDigest()'s third handle (handle 3); a handle that is not an audit session is handle-encoded TPM_RC_TYPE at index 2.");
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A transition refusal must return every carrier it rented.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, trackingPool.Pool, plainHandle).ConfigureAwait(false);
        }
    }

    /// <summary>A completed ECC signer attestation returns every carrier the house pool rented.</summary>
    [TestMethod]
    public async Task MeteredPoolBalancesForTheEccSignerForm()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint auditHandle, TpmSession auditSession, byte[] establishedDigest) = await EstablishAuditSessionAsync(simulator, tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            {
                long baseline = trackingPool.OutstandingCount;
                {
                    using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
                    using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
                    using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                        signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

                    TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                        tpm, input, [privacyAdminAuth, signAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest (ECDSA) failed: '{result.ResponseCode}'.");
                    result.Value.Dispose();
                }

                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A completed ECC attestation must return every carrier it rented.");
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, trackingPool.Pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>A completed NULL-signer attestation returns every carrier the house pool rented.</summary>
    [TestMethod]
    public async Task MeteredPoolBalancesForTheNullSignerForm()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint auditHandle, TpmSession auditSession, byte[] establishedDigest) = await EstablishAuditSessionAsync(simulator, tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            {
                long baseline = trackingPool.OutstandingCount;
                {
                    using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
                    using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
                    using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), QualifyingData, trackingPool.Pool);

                    TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                        tpm, input, [privacyAdminAuth, signAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest (NULL signer) failed: '{result.ResponseCode}'.");
                    result.Value.Dispose();
                }

                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A completed NULL-signer attestation must return every carrier it rented.");
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, trackingPool.Pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A hand-framed request whose <c>inScheme</c> is the bare two-octet <c>TPM_ALG_NULL</c> selector (Part 2,
    /// clause 11.2.1.4/11.2.1.5, Tables 182/183) parses to a <c>schemeHashAlg</c> of <c>TPM_ALG_NULL</c> (no
    /// trailing octets carry a detail). Against a real signing key this transition's HASH gate runs over that
    /// parsed <c>schemeHashAlg</c> directly and admits only SHA-256/384/512 — TPM_ALG_NULL is not among them —
    /// so the request is refused with <c>TPM_RC_HASH</c> even though the key's own scheme is ECDSA/SHA-256 and
    /// Part 3, clause 18.1 says "inScheme.scheme shall be TPM_ALG_NULL or the same as scheme in the public area
    /// of the key" for a key whose scheme is not itself TPM_ALG_NULL. The request is framed by hand, independent
    /// of <see cref="GetSessionAuditDigestInput"/>'s own framing, so this proves the wire behavior rather than
    /// the host type under test elsewhere in this suite.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.1; clause 18.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HandFramedTwoOctetNullInSchemeOverASignerWithItsOwnSchemeReturnsHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint auditHandle, TpmSession auditSession, byte[] _) = await EstablishAuditSessionAsync(simulator, tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            {
                byte[] rawParameters = [0x00, 0x00, 0x00, 0x10];
                using TpmResponse response = await SubmitHandFramedGetSessionAuditDigestAsync(
                    simulator, pool, signer.ObjectHandle.Value, auditHandle, rawParameters).ConfigureAwait(false);

                var reader = new TpmReader(response.AsReadOnlySpan());
                TpmHeader header = TpmHeader.Parse(ref reader);
                Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), (TpmRcConstants)header.Code, "A two-octet NULL inScheme against a signer whose own scheme is ECDSA must answer TPM_RC_HASH: the parsed schemeHashAlg is TPM_ALG_NULL, which IsSupportedAttestHashAlg does not admit.");
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A four-octet <c>inScheme</c> (<c>00 10 00 10</c>) — the <c>TPM_ALG_NULL</c> selector followed by a hash
    /// octet pair the NULL scheme does not carry (Part 2, Table 182's <c>null</c> row selects no member) — is
    /// refused: once the two-octet selector is read, the trailing two octets are refused by the "no octets may
    /// follow" rule this parser applies to every command parameter area.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task HandFramedFourOctetNullInSchemeIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint auditHandle, TpmSession auditSession, byte[] _) = await EstablishAuditSessionAsync(simulator, tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using(auditSession)
            {
                byte[] rawParameters = [0x00, 0x00, 0x00, 0x10, 0x00, 0x10];
                using TpmResponse response = await SubmitHandFramedGetSessionAuditDigestAsync(
                    simulator, pool, signer.ObjectHandle.Value, auditHandle, rawParameters).ConfigureAwait(false);

                var reader = new TpmReader(response.AsReadOnlySpan());
                TpmHeader header = TpmHeader.Parse(ref reader);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, (TpmRcConstants)header.Code, "A four-octet NULL inScheme leaves two trailing octets, refused by the parameter area's own \"no octets may follow\" arm.");
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Hand-frames one <c>TPM2_GetSessionAuditDigest()</c> request over <c>TPM_ST_SESSIONS</c> with two
    /// empty-password authorization slots (<c>@privacyAdminHandle</c> then <c>@signHandle</c>) and
    /// <paramref name="rawParameters"/> as the entire parameter area, bypassing
    /// <see cref="GetSessionAuditDigestInput"/>'s own framing so the wire behaviour is proved independent of
    /// the host type this class exercises elsewhere.
    /// </summary>
    /// <param name="simulator">The simulator to submit the framed octets to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="signHandle">The signing key's handle.</param>
    /// <param name="sessionHandle">The audited session's handle.</param>
    /// <param name="rawParameters">The exact parameter-area octets to send.</param>
    /// <returns>The raw TPM response.</returns>
    private async Task<TpmResponse> SubmitHandFramedGetSessionAuditDigestAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint signHandle, uint sessionHandle, byte[] rawParameters)
    {
        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);

        int authAreaLength = privacyAdminAuth.GetAuthCommandSize() + signAuth.GetAuthCommandSize();
        int handleAreaLength = 3 * sizeof(uint);
        int commandLength = TpmHeader.HeaderSize + handleAreaLength + sizeof(uint) + authAreaLength + rawParameters.Length;

        byte[] command = new byte[commandLength];
        var writer = new TpmWriter(command);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)commandLength, (uint)TpmCcConstants.TPM_CC_GetSessionAuditDigest);
        header.WriteTo(ref writer);
        writer.WriteUInt32((uint)TpmRh.TPM_RH_ENDORSEMENT);
        writer.WriteUInt32(signHandle);
        writer.WriteUInt32(sessionHandle);
        writer.WriteUInt32((uint)authAreaLength);
        privacyAdminAuth.WriteAuthCommand(ref writer, null);
        signAuth.WriteAuthCommand(ref writer, null);
        writer.WriteBytes(rawParameters);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer rather than fault.");

        return result.Value;
    }

    /// <summary>
    /// Attests over an established audit session with the given RSA scheme and verifies the signature against
    /// the signer's exported modulus, sharing the RSASSA and RSAPSS cases.
    /// </summary>
    /// <param name="usePss">When <see langword="true"/>, attests and verifies RSAPSS; otherwise RSASSA.</param>
    private async Task RunRsaSignerAsync(bool usePss)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        (uint auditHandle, TpmSession auditSession, byte[] expectedDigest) = await EstablishAuditSessionAsync(simulator, tpm, registry, pool).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = signer.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        try
        {
            using(auditSession)
            using(TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool))
            using(TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool))
            using(GetSessionAuditDigestInput input = usePss
                ? GetSessionAuditDigestInput.ForRsaPss(signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
                : GetSessionAuditDigestInput.ForRsaSsa(signer.ObjectHandle, TpmiShHmac.FromValue(auditHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
            {
                TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                string schemeName = usePss ? "RSAPSS" : "RSASSA";
                Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest ({schemeName}) failed: '{result.ResponseCode}'.");

                using GetSessionAuditDigestResponse response = result.Value;
                AssertSessionAuditAttestation(response, expectedDigest, isExclusive: true);

                byte[] attestDigest = await ComputeSha256Async(response.AuditInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
                RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                using RSA rsa = RSA.Create(rsaParameters);
                Assert.IsTrue(
                    rsa.VerifyHash(attestDigest, response.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding),
                    $"The {schemeName} signature must verify against the signer's exported modulus.");
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Submits a <c>GetSessionAuditDigestInput</c> whose <c>sessionHandle</c> is outside the HMAC range and asserts the parse-time TPM_RC_VALUE.</summary>
    /// <param name="sessionHandleValue">The out-of-range raw handle value to place at <c>sessionHandle</c>.</param>
    private async Task AssertSessionHandleOutOfRangeIsValueAsync(uint sessionHandleValue)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandleValue), QualifyingData, pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, handleIndex: 2), result.ResponseCode,
            $"Table 103: sessionHandle is TPM2_GetSessionAuditDigest()'s third handle (index 2); 0x{sessionHandleValue:X8} is outside TPMI_SH_HMAC's range and must be refused at parse there.");
    }

    /// <summary>Asserts the common shape every successful attestation this class drives must carry.</summary>
    /// <param name="response">The parsed response.</param>
    /// <param name="expectedDigest">The digest the test independently chained.</param>
    /// <param name="isExclusive">Whether the audited session is expected to be the current exclusive audit session.</param>
    private static void AssertSessionAuditAttestation(GetSessionAuditDigestResponse response, ReadOnlySpan<byte> expectedDigest, bool isExclusive)
    {
        TpmsAttest attest = response.AuditInfo.AttestationData;
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_SESSION_AUDIT, attest.Type, "The attestation type must be TPM_ST_ATTEST_SESSION_AUDIT.");
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(QualifyingData), "extraData must echo the caller's qualifyingData.");

        TpmsSessionAuditInfo sessionAudit = attest.Attested.SessionAudit!;
        Assert.AreEqual(isExclusive, sessionAudit.ExclusiveSession.IsYes, "exclusiveSession must reflect whether the audited session is the current exclusive audit session.");
        Assert.IsTrue(
            sessionAudit.SessionDigest.AsReadOnlySpan().SequenceEqual(expectedDigest),
            "sessionDigest must equal the chain the test independently computed from the wire.");
    }

    /// <summary>
    /// Establishes an audit session: starts an unbound HMAC session through the production path, then
    /// hand-frames one <c>TPM2_GetRandom()</c> call over it claiming only <c>audit | continueSession</c> —
    /// the lone slot a session authorizing no entity may occupy on a zero-handle command — and returns the
    /// session alongside the digest the test independently chained from the octets it sent and read.
    /// </summary>
    /// <param name="simulator">The simulator to hand-frame the establishing call against.</param>
    /// <param name="tpm">The device the session's own lifecycle command runs through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session's handle, the session (the caller owns disposal), and the established digest.</returns>
    private async Task<(uint SessionHandle, TpmSession Session, byte[] Digest)> EstablishAuditSessionAsync(
        TpmSimulator simulator, TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        //TPM2_GetRandom()'s over-session response framer always protects randomBytes with the session's
        //negotiated symmetric algorithm once a companion is present (regardless of the encrypt attribute), so
        //the establishing session negotiates XOR obfuscation even though only audit is claimed here.
        TpmtSymDef symmetric = TpmtSymDef.Xor(HmacSessionAlg);
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        var session = new TpmSession(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool, symmetric)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT
        };

        byte[] digest = await ExtendAuditDigestOverGetRandomAsync(simulator, session, ZeroDigest, pool).ConfigureAwait(false);

        return (sessionHandle, session, digest);
    }

    /// <summary>
    /// Hand-frames one <c>TPM2_GetRandom()</c> call over <paramref name="session"/>, which must already claim
    /// <c>audit</c>, verifies the response HMAC under the session's own key with the rpHash this method
    /// independently computed, and returns the extended digest: <c>H(oldDigest || cpHash || rpHash)</c>.
    /// </summary>
    /// <param name="simulator">The simulator to submit the framed octets to.</param>
    /// <param name="session">The audit-claiming session.</param>
    /// <param name="oldDigest">The digest before this call — the Zero Digest on first use.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The extended digest.</returns>
    private async Task<byte[]> ExtendAuditDigestOverGetRandomAsync(TpmSimulator simulator, TpmSession session, ReadOnlyMemory<byte> oldDigest, BaseMemoryPool pool)
    {
        var input = new GetRandomInput(RandomDrawLength);
        byte[] parameters = new byte[input.GetSerializedSize()];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);

        byte[] cpHash = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_GetRandom, [], parameters, pool).ConfigureAwait(false);

        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] authArea = new byte[session.GetAuthCommandSize()];
        var authWriter = new TpmWriter(authArea);
        session.WriteAuthCommand(ref authWriter, hmac);

        int commandLength = TpmHeader.HeaderSize + sizeof(uint) + authArea.Length + parameters.Length;
        byte[] command = new byte[commandLength];
        var writer = new TpmWriter(command);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)commandLength, (uint)TpmCcConstants.TPM_CC_GetRandom);
        header.WriteTo(ref writer);
        writer.WriteUInt32((uint)authArea.Length);
        writer.WriteBytes(authArea);
        writer.WriteBytes(parameters);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The establishing TPM2_GetRandom() must answer rather than fault.");
        using TpmResponse response = result.Value;
        ReadOnlySpan<byte> responseSpan = response.AsReadOnlySpan();

        var headerReader = new TpmReader(responseSpan);
        TpmHeader responseHeader = TpmHeader.Parse(ref headerReader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "The establishing TPM2_GetRandom() must succeed.");

        int cursor = TpmHeader.HeaderSize;
        var sizeReader = new TpmReader(responseSpan[cursor..]);
        uint responseParamsLength = sizeReader.ReadUInt32();
        cursor += sizeof(uint);
        byte[] responseParams = responseSpan.Slice(cursor, (int)responseParamsLength).ToArray();
        cursor += (int)responseParamsLength;

        var sessionReader = new TpmReader(responseSpan[cursor..]);
        using TpmsAuthResponse authResponse = TpmsAuthResponse.Parse(ref sessionReader, pool);
        Assert.AreEqual(TpmaSession.AUDIT, authResponse.SessionAttributes & TpmaSession.AUDIT, "The response must echo audit (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

        byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_GetRandom, responseParams, pool).ConfigureAwait(false);

        bool verified = await session.VerifyAndUpdateAsync(authResponse, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified, "The response HMAC must verify under the session's own key and the independently computed rpHash.");

        return await ExtendDigestAsync(oldDigest, cpHash, rpHash, pool).ConfigureAwait(false);
    }

    /// <summary>Computes cpHash independently: <c>H(commandCode || Names || parameters)</c> (TPM 2.0 Library Part 1, clause 15.7, equation 15).</summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="names">Each handle's Name term, in handle order.</param>
    /// <param name="parameters">The parameter area as sent.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The 32-octet cpHash.</returns>
    private async Task<byte[]> ComputeCpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte>[] names, ReadOnlyMemory<byte> parameters, BaseMemoryPool pool)
    {
        int length = sizeof(uint) + parameters.Length;
        foreach(ReadOnlyMemory<byte> name in names)
        {
            length += name.Length;
        }

        byte[] buffer = new byte[length];
        var writer = new TpmWriter(buffer);
        writer.WriteUInt32((uint)commandCode);
        foreach(ReadOnlyMemory<byte> name in names)
        {
            writer.WriteBytes(name.Span);
        }

        writer.WriteBytes(parameters.Span);

        return await ComputeSha256Async(buffer, pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Computes rpHash independently: <c>H(TPM_RC_SUCCESS || commandCode || parameters)</c> (TPM 2.0 Library Part 1, clause 15.8, equation 16).</summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="parameters">The response parameter area as read.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The 32-octet rpHash.</returns>
    private async Task<byte[]> ComputeRpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> parameters, BaseMemoryPool pool)
    {
        byte[] buffer = new byte[(2 * sizeof(uint)) + parameters.Length];
        var writer = new TpmWriter(buffer);
        writer.WriteUInt32((uint)TpmRcConstants.TPM_RC_SUCCESS);
        writer.WriteUInt32((uint)commandCode);
        writer.WriteBytes(parameters.Span);

        return await ComputeSha256Async(buffer, pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Extends an audit digest independently: <c>H(old || cpHash || rpHash)</c> (TPM 2.0 Library Part 1, clause 17.1, equation 30).</summary>
    /// <param name="oldDigest">The digest before the extend.</param>
    /// <param name="cpHash">The command's cpHash.</param>
    /// <param name="rpHash">The command's rpHash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The extended digest.</returns>
    private async Task<byte[]> ExtendDigestAsync(ReadOnlyMemory<byte> oldDigest, ReadOnlyMemory<byte> cpHash, ReadOnlyMemory<byte> rpHash, BaseMemoryPool pool)
    {
        byte[] buffer = new byte[oldDigest.Length + cpHash.Length + rpHash.Length];
        oldDigest.Span.CopyTo(buffer);
        cpHash.Span.CopyTo(buffer.AsSpan(oldDigest.Length));
        rpHash.Span.CopyTo(buffer.AsSpan(oldDigest.Length + cpHash.Length));

        return await ComputeSha256Async(buffer, pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).</summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: Sha256DigestSize,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>Submits <paramref name="input"/> tagged <c>TPM_ST_NO_SESSIONS</c>, with no authorization area at all.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command input.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitNoSessionsAsync(TpmSimulator simulator, BaseMemoryPool pool, GetSessionAuditDigestInput input)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer rather than fault.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>The 4-octet big-endian wire form of <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>.</summary>
    private static byte[] EndorsementHandleBytes() => HandleBytes((uint)TpmRh.TPM_RH_ENDORSEMENT);

    /// <summary>The 4-octet big-endian wire form of <see cref="TpmRh.TPM_RH_NULL"/> — the NULL signer's qualifiedSigner (TPM 2.0 Library Part 4, FillInAttestInfo).</summary>
    private static byte[] NullHandleNameBytes() => HandleBytes((uint)TpmRh.TPM_RH_NULL);

    /// <summary>The 4-octet big-endian wire form of a raw handle value — a permanent or session handle's Name (TPM 2.0 Library Part 1, clause 13, Table 9).</summary>
    /// <param name="value">The raw handle value.</param>
    private static byte[] HandleBytes(uint value)
    {
        byte[] bytes = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);

        return bytes;
    }

    /// <summary>Left-pads a big-endian integer to a fixed width, as the IEEE P1363 / ECPoint encodings require.</summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to pad to.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
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

    /// <summary>The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2), transcribed independently since the production helper is private.</summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Creates a response codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        return registry;
    }

    /// <summary>Creates a primary ECC P-256 signing key under the given hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a primary ECC P-256 signing key with a real, DA-protected password (<c>noDa</c> clear).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The signing key's password.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreatePasswordProtectedSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: false);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, password-protected, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a primary RSA-2048 signing key under the given hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(hierarchy, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a password-authorizable RSA storage-parent key (RESTRICTED+DECRYPT, USER_WITH_AUTH SET, no SIGN) under TPM_RH_OWNER.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, authPassword: null, keyBits: Rsa2048KeyBits, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Starts a fresh, unbound, unsalted HMAC session through the production path.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the StartAuthSession response (the caller owns its disposal, or ownership of its NonceTPM transfers into a <see cref="TpmSession"/>).</returns>
    private async Task<(uint SessionHandle, StartAuthSessionResponse Started)> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;

        return (started.SessionHandle.Value, started);
    }

    /// <summary>Starts an unbound HMAC session and wraps it as a <see cref="TpmSession"/> for the over-sessions form's privacy-admin slot.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the wrapped session; the caller owns both.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundSessionWrapperAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        var session = new TpmSession(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);

        return (sessionHandle, session);
    }

    /// <summary>Starts an HMAC session bound to <paramref name="bindHandle"/> with an empty bind authValue, negotiating <paramref name="symmetric"/> — the decrypt companion's fixture.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The handle to bind the session to.</param>
    /// <param name="bindAuthValue">The bind entity's authValue.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <returns>The session handle and the wrapped session; the caller owns both.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartBoundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuthValue, TpmtSymDef symmetric)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, HmacSessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(started.SessionHandle.Value), bindAuthValue, startInput.NonceCaller, started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool,
            symmetric: symmetric, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Flushes a session or object handle, ignoring the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private static async Task FlushHandleAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>Creates a simulator with both signing backends wired, powers it on, and brings it through TPM2_Startup(CLEAR) into the operational phase.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-get-session-audit-digest",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues TPM2_Startup(CLEAR) directly against the simulator, mirroring how the executor frames an unauthorized command on the wire.</summary>
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
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, "TPM2_Startup(CLEAR) must succeed.");
    }

    /// <summary>Issues TPM2_SelfTest(NO) directly against the simulator and returns its response code.</summary>
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
}
