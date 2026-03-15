using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Secdsa;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.Tpm;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Secdsa;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Secdsa;

/// <summary>
/// Hardware TPM tests for the full SECDSA protocol, including the Native Cryptographic
/// Hardware (NCH) signing boundary (TPM2_Sign) and the ECDH blinding boundary
/// (TPM2_ECDH_ZGen).
/// </summary>
/// <remarks>
/// <para>
/// These tests are the hardware counterparts of the software-only tests in
/// SecdsaAlgorithmsSoftwareTests. Each test that passes in software should also pass here
/// with the TPM performing the hardware-bounded operations. If a software invariant
/// holds but the corresponding hardware test fails, the TPM is not producing the
/// expected output for that protocol step.
/// </para>
/// <para>
/// Who can operate the Wallet Provider (Wallet Secure Cryptographic Application (WSCA)
/// and Wallet Secure Cryptographic Device (WSCD)):
/// </para>
/// <para>
/// The WSCA is a software process -- a container or server application -- with no
/// bespoke HSM firmware required. This means the wallet provider can be a government
/// body (the Finnish state operating a public wallet, where it acts as both Person
/// Identification Data (PID) issuer and wallet provider) or a private company building
/// a wallet product. In both cases the Verifiable library provides the WSCA-side
/// implementation: the SECDSA cryptographic types, NCH and WSCD delegate abstractions,
/// InstructionTranscript, and BlindedSecdsaInstruction. The wallet provider wires up
/// their own hardware delegates and transport; the cryptographic protocol is implemented
/// here.
/// </para>
/// <para>
/// The architecture these tests exercise:
/// </para>
/// <code>
///  SCI  = Secure Cryptographic Interface: the authenticated channel between
///         the Wallet APP and the WSCA.
///  WSCA = Wallet Secure Cryptographic Application: the wallet provider's
///         server-side trusted process that authenticates signing instructions
///         and manages access to the WSCD. A software container; no bespoke
///         HSM firmware is required.
///  WSCD = Wallet Secure Cryptographic Device: the hardware that holds user
///         keys (blinding key aU). A PKCS#11 HSM or a TPM with wrapped keys.
///  NCH  = Native Cryptographic Hardware: the on-device tamper-resistant key
///         store holding the user's signing key u. TPM on Windows/Linux,
///         Secure Enclave on iOS, StrongBox on Android.
///  PID  = Person Identification Data: the foundational identity credential
///         issued to the user by a national authority (e.g. the Finnish state).
///         Stored as a Verifiable Credential on the user's phone.
///  OID4VP = OpenID for Verifiable Presentations: the protocol by which a
///           relying party requests credentials from a wallet.
///  DCQL = Digital Credentials Query Language: the query language used inside
///         an OID4VP request to specify which credential attributes are needed.
///  KYC  = Know Your Customer: the regulatory obligation requiring financial
///         institutions to verify the identity of their customers.
///
///  +---------------------------+        +--------------------------------+
///  |       Wallet APP          |        |      Wallet Provider           |
///  |                           |        |                                |
///  |  NCH = TPM (this test)    |  SCI   |  +----------+  +------------+ |
///  |  Signing key u in TPM     |&lt;------&gt;|  |  WSCA    |  |    WSCD    | |
///  |  InternalCertificate C    |        |  | (server) |  | (HSM/TPM)  | |
///  |  Transaction Log          |        |  |          |  |            | |
///  |                           |        |  |          |  | Blinding   | |
///  |  Knowledge factor (PIN):  |        |  |          |  | key aU     | |
///  |  any memorised byte seq.  |        |  |          |  |            | |
///  +---------------------------+        |  +----------+  +------------+ |
///                                       |  Transaction Log               |
///                                       +--------------------------------+
///
///  Full party picture for the test scenario:
///
///  +------------------+   issues PID    +------------------+
///  | Finnish state    | --------------> | Alice's wallet   |
///  | (PID issuer)     |  (one-time,     | (Wallet APP +    |
///  | Signs credential |   at issuance)  |  NCH on phone)   |
///  +------------------+                 +--------+---------+
///                                                |  SCI (signing instruction)
///                                       +--------+---------+
///                                       | Wallet Provider  |
///                                       | (WSCA + WSCD)    |
///                                       | May be state or  |
///                                       | private company. |
///                                       | Uses Verifiable  |
///                                       | library.         |
///                                       +--------+---------+
///                                                |  InstructionTranscript
///                                                v
///                                       +------------------+    OID4VP VP
///  +------------------+  OID4VP request | Alice's wallet   | ------------->  +----------+
///  | EudiBank         | --------------> | assembles VP:    |                 | EudiBank |
///  | (relying party)  |  (DCQL query    |  PID credential  |                 | verifies |
///  | KYC for account  |   for PID)      |  + holder sig    |                 | issuer + |
///  | opening          |                 |                  |                 | holder   |
///  +------------------+                 +------------------+                 +----------+
///
///  TPM as NCH (phone-side): viable for production.
///    One persistent key u per user. Well within TPM NV storage limits.
///    On a phone: StrongBox (Android) or Secure Enclave (iOS) play the
///    same role as a TPM. On a desktop or server: Windows TPM or Linux
///    TPM via /dev/tpmrm0 is the natural NCH.
///
///  TPM as WSCD (server-side): viable with key wrapping via TPM2_Create.
///    TPM2_CreatePrimary (used in these tests for convenience) produces a
///    transient key derived from a hierarchy seed. The key is not exportable
///    in plaintext and is lost on flush -- correct security model, but
///    unsuitable for persisting per-user keys across sessions.
///
///    The production pattern is TPM2_Create: the TPM generates aU inside
///    hardware and returns a wrapped key blob encrypted and MAC'd under the
///    Storage Root Key (SRK). The blob is stored in the wallet provider
///    database. Per the TPM 2.0 specification (Part 1, Section 23), a key
///    created with TPM2_Create can only be loaded by the TPM that holds the
///    parent key (the SRK), and the SRK is hardware-bound to that specific
///    TPM. The wrapped blob in the database is therefore cryptographically
///    bound to the wallet provider's TPM -- stealing the database alone
///    yields nothing usable.
///
///    SRK backup: the TPM specification provides TPM2_ActivateCredential and
///    TPM2_MakeCredential for migrating the wallet provider's blinding key aU
///    to another TPM. The key material travels encrypted under the recipient
///    TPM's Endorsement Key and cannot be recovered in plaintext outside
///    hardware.
///
///    Blob vs HSM comparison:
///    - Security of a single operation: TPM and HSM are equivalent -- the
///      plaintext key never leaves the hardware boundary in either case.
///    - Recovery: TPM uses the encrypted-seed migration path above. A PKCS#11
///      HSM has explicit m-of-n quorum backup built into its operational model.
///    - Concurrency: TPMs have a small number of concurrent authorization
///      sessions; the OS serializes requests through the TCTI layer.
///
///  Authentication factor requirements:
///
///  The EUDI Architecture Reference Framework defines strong user authentication as:
///  "An authentication based on the use of at least two authentication factors from
///  different categories of either knowledge, something only the user knows,
///  possession, something only the user possesses or inherence, something the user
///  is, that are independent, in that the breach of one does not compromise the
///  reliability of the others, and is designed in such a way as to protect the
///  confidentiality of the authentication data."
///  (EUDI ARF, <see href="https://eudi.dev/2.8.0/annexes/annex-1/annex-1-definitions/">Annex 1</see>,
///  citing Commission Implementing Regulation (EU) 2015/1502)
///
///  The EUDI Wallet operates at eIDAS assurance level High.
///
///  +--------------------+---------------------------+---------------------------+
///  | Factor category    | What it means             | SECDSA realisation        |
///  +--------------------+---------------------------+---------------------------+
///  | Possession         | Something you HAVE.       | NCH key u -- TPM, Secure  |
///  | (required)         | Something only the user   | Enclave, HBK, StrongBox.  |
///  |                    | possesses. A hardware key | Proven via key attestation|
///  |                    | that cannot be copied.    | (TPM EK/AK cert chain).   |
///  |                    | Independent of knowledge  |                           |
///  |                    | and inherence factors.    |                           |
///  +--------------------+---------------------------+---------------------------+
///  | Knowledge          | Something you KNOW.       | PIN-key P derived from    |
///  | (second factor,    | Something only the user   | user secret + NCH-bound   |
///  | option A)          | knows. A memorised secret.| binder key KP. One NCH    |
///  |                    | A numeric PIN is typical. | call per attempt enforces |
///  |                    | Independence from the     | rate-limiting / lockout.  |
///  |                    | possession factor is met  | Spec Section 3.1.         |
///  |                    | because PIN alone cannot  |                           |
///  |                    | produce P without the NCH.|                           |
///  +--------------------+---------------------------+---------------------------+
///  | Inherence          | Something you ARE.        | Static P stored under     |
///  | (second factor,    | Something the user is.    | biometric access control. |
///  | option B)          | Biometric: fingerprint,   | SECDSA math identical to  |
///  |                    | face, iris. Unlocks P;    | knowledge path.           |
///  |                    | does not derive P.        | Spec Section 3.2.         |
///  |                    | Independence from the     | Spec notes eIDAS High is  |
///  |                    | possession factor is met  | harder to certify due to  |
///  |                    | because biometric alone   | false-acceptance rates.   |
///  |                    | cannot produce P without  |                           |
///  |                    | the NCH.                  |                           |
///  +--------------------+---------------------------+---------------------------+
///
///  Both the Wallet APP and the Wallet Provider maintain a Transaction Log.
///  The wallet writes: issuance transcript (Protocol 4), every instruction
///  transcript (Algorithm 37 output). The WSCA writes: every signed transcript
///  it produces. These logs are the basis for dispute resolution.
///
///  Cryptographic log architecture:
///
///  InstructionTranscript has the shape of a signed log entry in
///  Verifiable.Core.EventLogs: a signed opaque payload, a signature, and a
///  sequence number. The EUDI Wallet-specific content is entirely inside the
///  opaque InnerTranscript bytes.
///
///  The natural extension is to make the chain explicit by adding a hash of the
///  previous transcript's canonical bytes to each entry. Replay then becomes a
///  fold: iterate entries, verify chain link, verify signature, accumulate state.
///  This is the same pattern used in append-only cryptographic audit logs.
///
///  The chain integrity verification backend is a delegate that can be swapped
///  without changing the replay logic, supporting three approaches:
///
///    Hash-chain: each entry stores H(previous entry canonical bytes). Replay
///    verifies linearly. Same pattern as DID event logs.
///
///    Merkle tree: a batch of entries is committed to a single Merkle root.
///    Inclusion proofs allow verification of a single entry without replaying
///    the full chain. Same pattern as RFC 9162 Certificate Transparency.
///
///    TPM PCR quote: the chain head hash is extended into a TPM PCR and the
///    TPM produces a signed quote (TPM_Quote) over it. The quote is signed by
///    the TPM Attestation Key certified by the EK certificate chain. This proves
///    the chain was computed on a specific TPM at a specific time -- not
///    forgeable in software. Same pattern as TCG firmware event logs, which
///    are directly relevant to the hardware operations in these tests.
///
///  The three approaches share one fold structure; only the integrity proof
///  delegate differs. All three are stronger than a vendor-specific HSM audit
///  log because the proof is bound to the operations themselves, not produced
///  by a separate audit signing key of unverifiable provenance.
/// </code>
/// </remarks>
[TestClass]
[DoNotParallelize]
[SkipIfNoTpm]
[TestCategory("RequiresHardwareTpm")]
internal sealed class SecdsaAlgorithmsHardwareTests
{
    private static TpmDevice Tpm { get; set; } = null!;
    private static bool HasTpm { get; set; }

    public TestContext TestContext { get; set; } = null!;

    [ClassInitialize]
    public static void ClassInit(TestContext context)
    {
        if(TpmDevice.IsAvailable)
        {
            HasTpm = true;
            Tpm = TpmDevice.Open();
        }
    }

    [TestInitialize]
    public void TestInit()
    {
        if(!HasTpm)
        {
            Assert.Inconclusive(TestInfrastructureConstants.NoTpmDeviceAvailableMessage);
        }
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        if(HasTpm)
        {
            Tpm.Dispose();
        }
    }

    [TestMethod]
    public void TpmEcdhZGenProducesValidOutputPoint()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_ECDH_ZGen, TpmResponseCodec.EcdhZGen);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccKeyAgreementKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            pool);

        using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> createResult = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm, createInput, [ownerAuth], pool, registry);

        AssertUtilities.AssertSuccess(createResult, "CreatePrimary for ECDH key");

        //Handle 0x80FFFFFF is the last transient slot. Some TPM firmware implementations
        //reject TPM2_ECDH_ZGen when the key occupies this specific handle value. Flush and
        //recreate until an earlier handle is allocated.
        while(createResult.Value.ObjectHandle.Value == 0x80FFFFFFu)
        {
            TestContext.WriteLine("Handle 0x80FFFFFF allocated — flushing and recreating.");
            TpmiDhObject staleHandle = createResult.Value.ObjectHandle;
            createResult.Value.Dispose();

            var earlyFlush = FlushContextInput.ForHandle(staleHandle.Value);
            _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, earlyFlush, [], pool, registry);

            using CreatePrimaryInput retryInput = CreatePrimaryInput.ForEccKeyAgreementKey(
                TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool);
            using var retryAuth = TpmPasswordSession.CreateEmpty(pool);
            createResult = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
                Tpm, retryInput, [retryAuth], pool, registry);
            AssertUtilities.AssertSuccess(createResult, "CreatePrimary retry");
        }

        using CreatePrimaryResponse createResponse = createResult.Value;
        TpmiDhObject keyHandle = createResponse.ObjectHandle;
        TestContext.WriteLine($"KeyHandle after retry: 0x{keyHandle.Value:X8}");

        //Read back the key to confirm what the TPM actually stored.
        ReadPublicInput readInput = ReadPublicInput.ForHandle(keyHandle);
        TpmResult<ReadPublicResponse> readResult = TpmCommandExecutor.Execute<ReadPublicResponse>(
            Tpm, readInput, [], pool, registry);

        if(readResult.IsSuccess)
        {
            using ReadPublicResponse readResponse = readResult.Value;
            TpmtPublic pub = readResponse.PublicArea.PublicArea;
            TestContext.WriteLine($"ObjectAttributes: 0x{(uint)pub.ObjectAttributes:X8}");
            TpmsEccParms? eccDetail = pub.Parameters.EccDetail;
            if(eccDetail is not null)
            {
                TestContext.WriteLine($"Scheme:     {eccDetail.Value.Scheme.Scheme} (0x{(ushort)eccDetail.Value.Scheme.Scheme:X4})");
                TestContext.WriteLine($"SchemeHash: {eccDetail.Value.Scheme.HashAlg} (0x{(ushort)eccDetail.Value.Scheme.HashAlg:X4})");
                TestContext.WriteLine($"Kdf:        {eccDetail.Value.Kdf.Scheme} (0x{(ushort)eccDetail.Value.Kdf.Scheme:X4})");
            }
        }

        //Use the key's own public point as the inPoint for TPM2_ECDH_ZGen.
        byte[] inPoint = ExtractEccPublicPoint(createResponse.OutPublic);

        TestContext.WriteLine($"KeyHandle value:   0x{keyHandle.Value:X8}");
        TestContext.WriteLine($"inPoint total:     {Convert.ToHexString(inPoint)}");
        TestContext.WriteLine($"inPoint X:         {Convert.ToHexString(inPoint.AsSpan(1, EllipticCurveConstants.P256.PointArrayLength))}");
        TestContext.WriteLine($"inPoint Y:         {Convert.ToHexString(inPoint.AsSpan(1 + EllipticCurveConstants.P256.PointArrayLength, EllipticCurveConstants.P256.PointArrayLength))}");

        using EcdhZGenInput ecdhInput = EcdhZGenInput.FromUncompressedPoint(keyHandle, inPoint, pool);

        int serializedSize = ecdhInput.GetSerializedSize();
        int expectedSize = sizeof(uint) + sizeof(ushort) + EllipticCurveConstants.P256.PointArrayLength + sizeof(ushort) + EllipticCurveConstants.P256.PointArrayLength;
        TestContext.WriteLine($"GetSerializedSize: {serializedSize} (expected {expectedSize})");

        using var keyAuth = TpmPasswordSession.CreateEmpty(pool);

        //Capture the raw ECDH_ZGen exchange to see exactly what is sent and received.
        ReadOnlyMemory<byte> capturedCommand = default;
        ReadOnlyMemory<byte> capturedResponse = default;
        using IDisposable subscription = Tpm.Subscribe(new DelegateObserver(exchange =>
        {
            capturedCommand = exchange.Command;
            capturedResponse = exchange.Response;
        }));

        TpmResult<EcdhZGenResponse> ecdhResult = TpmCommandExecutor.Execute<EcdhZGenResponse>(
            Tpm, ecdhInput, [keyAuth], pool, registry);

        if(!capturedCommand.IsEmpty)
        {
            TestContext.WriteLine($"Command ({capturedCommand.Length} bytes): {Convert.ToHexString(capturedCommand.Span)}");
        }

        if(!capturedResponse.IsEmpty)
        {
            TestContext.WriteLine($"Response ({capturedResponse.Length} bytes): {Convert.ToHexString(capturedResponse.Span)}");
        }

        AssertUtilities.AssertSuccess(ecdhResult, "TPM2_ECDH_ZGen");

        using EcdhZGenResponse ecdhResponse = ecdhResult.Value;

        byte[] outPoint = ecdhResponse.ToUncompressedPoint();

        Assert.HasCount(EllipticCurveConstants.P256.UncompressedPointByteCount, outPoint,
            "ECDH output point must be 65 bytes.");
        Assert.AreEqual(EllipticCurveUtilities.UncompressedCoordinateFormat, outPoint[0],
            "ECDH output point must start with 0x04.");
        Assert.IsTrue(
            EcMath.IsValidPoint(EcMath.DecodePointUncompressed(outPoint)),
            "ECDH output point must be on the P-256 curve.");

        TestContext.WriteLine($"ECDH output X = {Convert.ToHexString(outPoint.AsSpan(1, EllipticCurveConstants.P256.PointArrayLength))}");
        TestContext.WriteLine($"ECDH output Y = {Convert.ToHexString(outPoint.AsSpan(1 + EllipticCurveConstants.P256.PointArrayLength, EllipticCurveConstants.P256.PointArrayLength))}");

        var flushInput = FlushContextInput.ForHandle(keyHandle.Value);
        _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, flushInput, [], pool, registry);
    }

    [TestMethod]
    public void TpmSignsAndPureNetVerifiesFullSecdsaPath()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool);

        using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> createResult = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm, createInput, [ownerAuth], pool, registry);

        AssertUtilities.AssertSuccess(createResult, "CreatePrimary");

        using CreatePrimaryResponse createResponse = createResult.Value;

        TpmiDhObject keyHandle = createResponse.ObjectHandle;

        BigInteger pinKey = EcMath.RandomScalar();
        BigInteger pinInverse = EcMath.ModInverse(pinKey);

        byte[] messageHash = SHA256.HashData("SECDSA WSCA instruction verification path."u8);
        BigInteger adjustedE = EcMath.HashToInteger(messageHash) * pinInverse % EcMath.Q;
        byte[] adjustedDigest = EcMath.ScalarToBytes(adjustedE);

        using SignInput signInput = SignInput.ForEcdsa(
            keyHandle, adjustedDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        using var keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignResponse> signResult = TpmCommandExecutor.Execute<SignResponse>(
            Tpm, signInput, [keyAuth], pool, registry);

        AssertUtilities.AssertSuccess(signResult, "TPM2_Sign");

        using SignResponse signResponse = signResult.Value;

        BigInteger r = new BigInteger(signResponse.SignatureR.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        BigInteger s0 = new BigInteger(signResponse.SignatureS.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        BigInteger s = pinKey * s0 % EcMath.Q;

        byte[] uPoint = ExtractEccPublicPoint(createResponse.OutPublic);
        EcPoint y = EcMath.Multiply(EcMath.DecodePointUncompressed(uPoint), pinKey);

        bool valid = SecdsaAlgorithms.Verify(messageHash, new EcdsaSignature(r, s), y);

        Assert.IsTrue(valid, "SECDSA signature (TPM signs, pure .NET verifies) must be valid.");

        var flushInput = FlushContextInput.ForHandle(keyHandle.Value);
        _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, flushInput, [], pool, registry);
    }

    /// <summary>
    /// Verifies the full SECDSA protocol flow with both hardware boundaries active,
    /// mirroring FullSecdsaProtocolFlowSoftwareCryptographicInvariantsHold in
    /// SecdsaAlgorithmsSoftwareTests but with a physical TPM performing the hardware calls.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Scenario: Alice wants to open a bank account at EudiBank remotely. EudiBank
    /// sends an OID4VP request with a DCQL query for her name, date of birth, and
    /// nationality from her PID (Person Identification Data) credential. The PID was
    /// issued by the Finnish state, signed by the state's issuer key, and is stored
    /// as a Verifiable Credential on Alice's phone. EudiBank is entitled to request
    /// it for KYC (Know Your Customer) purposes under eIDAS.
    /// </para>
    /// <para>
    /// How EudiBank knows it is really Alice with that specific credential:
    /// </para>
    /// <para>
    /// At PID issuance, Alice's wallet generated the Native Cryptographic Hardware
    /// (NCH) key pair (u, U = u*G) and presented U to the Finnish state's PID issuer
    /// along with a key attestation proving u is non-exportable and hardware-bound.
    /// The PID issuer verified the attestation and signed the credential with U
    /// embedded as the holder public key: { name, date_of_birth, nationality, ...,
    /// holderPublicKey: U }. This binding is part of the issued credential.
    /// </para>
    /// <para>
    /// At presentation, EudiBank verifies two things independently:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>The Finnish state's issuer signature over the PID credential,
    ///   using the state's public key from the EUDI Wallet Trusted List. This proves the
    ///   credential and the holder public key U it contains are genuine.</description></item>
    ///   <item><description>Alice's holder binding signature against U. This proves the
    ///   presenter controls the private key u corresponding to U -- the same key the
    ///   state attested is NCH-bound and non-exportable. Together these two checks prove
    ///   Alice is the genuine holder of a state-issued credential bound to hardware she
    ///   controls.</description></item>
    /// </list>
    /// <para>
    /// Alice's wallet responds with a Verifiable Presentation combining:
    ///   (a) The PID credential stored on her phone (issued and signed by the state,
    ///       containing U as the bound holder public key).
    ///   (b) A holder binding signature produced via the SECDSA protocol, signed with
    ///       u and verifiable against U without u ever leaving the NCH hardware.
    /// The SECDSA protocol governs only (b). The credential itself is presented
    /// directly from local storage; the Wallet Secure Cryptographic Application (WSCA)
    /// is not involved in the credential content, only in authenticating the signing
    /// instruction that produces (b).
    /// </para>
    /// <para>
    /// Her phone's TPM acts as the NCH for the signing boundary (b). A second key on
    /// the same TPM acts as the wallet provider's WSCD-bound blinding key aU.
    /// Both keys are on the same test TPM because the test environment has only one TPM.
    /// In a production deployment these would be on separate hardware.
    /// </para>
    /// <para>
    /// Two hardware boundaries are crossed:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>NCH signing: the adjusted hash e' = P^-1 * H(I) mod q is
    ///   signed by the TPM via TPM2_Sign. The TPM holds the private key u; only U = u*G
    ///   and the raw signature (r, s0) cross the boundary.</description></item>
    ///   <item><description>WSCD ECDH: the wallet provider's WSCA computes aU*R via
    ///   TPM2_ECDH_ZGen using the WSCD-bound blinding key aU. aU never leaves the
    ///   hardware.</description></item>
    /// </list>
    /// </remarks>
    [TestMethod]
    public void TpmFullSecdsaProtocolFlowBothHardwareBoundariesHold()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_ECDH_ZGen, TpmResponseCodec.EcdhZGen);

        //-- Native Cryptographic Hardware (NCH) boundary: Alice's TPM generates the signing key u ---
        //
        //This step corresponds to two separate real-world events that both use u:
        //
        //  Event 1 -- PID issuance (Finnish state issues PID credential to Alice):
        //    Alice's wallet presents U to the Finnish state's PID issuer with a key
        //    attestation proving u is hardware-bound. The state signs the PID credential
        //    with U embedded as the holder public key. Alice's wallet stores the credential.
        //    The wallet provider is not involved in this step.
        //
        //  Event 2 -- WSCA activation (Protocol 4, wallet provider establishes blinding):
        //    Alice's wallet registers U with the wallet provider's WSCA, which issues
        //    InternalCertificate C = { AliceId, U, G' = aU*G, Y' = aU*Y }.
        //
        //In production u is a non-exportable key handle in a TPM, Secure Enclave, or
        //StrongBox. In this test u is generated with CreatePrimary and lives only in the
        //TPM's transient object area; only U = u*G leaves the hardware boundary.

        using CreatePrimaryInput signingKeyInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool);

        using var ownerAuthSigning = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signingKeyResult = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm, signingKeyInput, [ownerAuthSigning], pool, registry);

        AssertUtilities.AssertSuccess(signingKeyResult, "CreatePrimary for NCH signing key");
        using CreatePrimaryResponse signingKeyResponse = signingKeyResult.Value;
        TpmiDhObject signingKeyHandle = signingKeyResponse.ObjectHandle;

        byte[] uPoint = ExtractEccPublicPoint(signingKeyResponse.OutPublic);
        EcPoint U = EcMath.DecodePointUncompressed(uPoint);
        Assert.IsTrue(EcMath.IsValidPoint(U), "Alice's NCH public key U must be a valid P-256 point.");

        //-- Wallet Secure Cryptographic Device (WSCD) boundary: blinding key aU ---
        //
        //In production aU lives on the wallet provider's server hardware, completely
        //separate from Alice's device. Both keys are on the same test TPM here
        //because the test environment has only one TPM.

        using CreatePrimaryInput ecdhKeyInput = CreatePrimaryInput.ForEccKeyAgreementKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            pool);

        using var ownerAuthEcdh = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> ecdhKeyResult = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm, ecdhKeyInput, [ownerAuthEcdh], pool, registry);

        AssertUtilities.AssertSuccess(ecdhKeyResult, "CreatePrimary for HSM ECDH key");

        //Handle 0x80FFFFFF causes TPM_RC_VALUE on ECDH_ZGen on some firmware; retry.
        while(ecdhKeyResult.Value.ObjectHandle.Value == 0x80FFFFFFu)
        {
            TestContext.WriteLine("Handle 0x80FFFFFF allocated for ECDH key -- flushing and recreating.");
            TpmiDhObject staleHandle = ecdhKeyResult.Value.ObjectHandle;
            ecdhKeyResult.Value.Dispose();

            var earlyFlush = FlushContextInput.ForHandle(staleHandle.Value);
            _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, earlyFlush, [], pool, registry);

            using CreatePrimaryInput retryInput = CreatePrimaryInput.ForEccKeyAgreementKey(
                TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool);
            using var retryAuth = TpmPasswordSession.CreateEmpty(pool);
            ecdhKeyResult = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
                Tpm, retryInput, [retryAuth], pool, registry);
            AssertUtilities.AssertSuccess(ecdhKeyResult, "CreatePrimary ECDH key retry");
        }

        using CreatePrimaryResponse ecdhKeyResponse = ecdhKeyResult.Value;
        TpmiDhObject ecdhKeyHandle = ecdhKeyResponse.ObjectHandle;

        byte[] gPrimePoint = ExtractEccPublicPoint(ecdhKeyResponse.OutPublic);
        EcPoint Gprime = EcMath.DecodePointUncompressed(gPrimePoint);
        Assert.IsTrue(EcMath.IsValidPoint(Gprime), "EudiBank's blinding public key G' must be a valid P-256 point.");

        //-- Activation: Alice derives her knowledge factor key and computes Y -----
        //
        //The "PIN" in SECDSA is the user knowledge factor -- any byte sequence
        //the user memorises. A numeric PIN code is the typical choice. P is
        //derived from the PIN value and the NCH-bound PIN-binder key KP (one NCH
        //call per Annex B). P is ephemeral and never persists on disk.
        //Here a random scalar stands in for a real PIN-binder derivation.

        BigInteger P = EcMath.RandomScalar();
        EcPoint Y = EcMath.Multiply(U, P);
        Assert.IsTrue(EcMath.IsValidPoint(Y), "Alice's SECDSA public key Y = P*U must be a valid P-256 point.");

        //Blinding round-trip: Y' = t^-1 * aU*t*Y via TPM ECDH.
        BigInteger t = EcMath.RandomScalar();
        EcPoint Ybl = EcMath.Multiply(Y, t);

        byte[] yblBytes = EcMath.EncodePointUncompressed(Ybl);
        using EcdhZGenInput blindingInput = EcdhZGenInput.FromUncompressedPoint(ecdhKeyHandle, yblBytes, pool);
        using var ecdhAuthBlinding = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<EcdhZGenResponse> blindingResult = TpmCommandExecutor.Execute<EcdhZGenResponse>(
            Tpm, blindingInput, [ecdhAuthBlinding], pool, registry);

        AssertUtilities.AssertSuccess(blindingResult, "TPM2_ECDH_ZGen for Y'bl = aU*Ybl");
        using EcdhZGenResponse blindingResponse = blindingResult.Value;
        EcPoint Ybl_prime = EcMath.DecodePointUncompressed(blindingResponse.ToUncompressedPoint());

        BigInteger tInv = EcMath.ModInverse(t);
        EcPoint Yprime = EcMath.Multiply(Ybl_prime, tInv);

        //-- Signing: Alice responds to EudiBank's OID4VP request ------------------
        //
        //Four parties are involved; it is essential to know which talks to which:
        //
        //  Finnish state (Person Identification Data (PID) issuer) -- no network
        //    activity during this presentation. The state issued Alice's PID credential
        //    at wallet activation and signed it with its issuer key. It is not contacted
        //    again. EudiBank verifies the state's signature using the state's public key
        //    from the EUDIW Trusted List, which EudiBank resolved at setup time, not per
        //    presentation.
        //
        //  Wallet provider (operates Wallet Secure Cryptographic Application (WSCA) and
        //    Wallet Secure Cryptographic Device (WSCD)) -- receives one Secure
        //    Cryptographic Interface (SCI) call from Alice. The wallet provider is a
        //    separate organisation from both the Finnish state and EudiBank. Alice's
        //    wallet app communicates with it over SCI to produce the holder binding
        //    signature. The wallet provider does not know which relying party Alice is
        //    talking to or what she is presenting.
        //
        //  Alice's wallet app -- makes two outbound connections:
        //    1. To the wallet provider's WSCA over SCI: to obtain the holder binding
        //       signature (part b below).
        //    2. To EudiBank over OpenID for Verifiable Presentations (OID4VP): to return
        //       the completed Verifiable Presentation (VP).
        //    These are separate channels. Alice's wallet assembles the VP locally.
        //
        //  EudiBank (relying party) -- sends one OID4VP request, receives one VP.
        //    It verifies the VP locally: the Finnish state's issuer signature on the
        //    PID credential (using the trusted list public key) and Alice's holder
        //    binding signature. No call to the wallet provider or Finnish state.
        //
        //Alice's VP combines:
        //  (a) The PID credential from local storage -- issuer-signed by the Finnish
        //      state, read directly from Alice's phone. WSCA not involved.
        //  (b) A holder binding signature -- produced via the SECDSA protocol.
        //      Alice's wallet sends a SECDSA instruction to the wallet provider's WSCA
        //      over SCI. The WSCA authenticates it (one WSCD call), executes it, and
        //      returns the signed result and an InstructionTranscript.
        //
        //Native Cryptographic Hardware (NCH) boundary: Alice's wallet computes
        //e' = P^-1 * H(I) mod q and passes it to the TPM via TPM2_Sign. The TPM holds
        //u and returns (r, s0). Alice's wallet computes s = P * s0 mod q in software
        //and packages the BlindedSecdsaInstruction for the WSCA.

        byte[] instructionHash = SHA256.HashData("present-pid-attributes SN=1"u8);
        BigInteger pinInverse = EcMath.ModInverse(P);
        BigInteger adjustedE = EcMath.HashToInteger(instructionHash) * pinInverse % EcMath.Q;
        byte[] adjustedDigest = EcMath.ScalarToBytes(adjustedE);

        using SignInput signInput = SignInput.ForEcdsa(
            signingKeyHandle, adjustedDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        using var keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignResponse> signResult = TpmCommandExecutor.Execute<SignResponse>(
            Tpm, signInput, [keyAuth], pool, registry);

        AssertUtilities.AssertSuccess(signResult, "TPM2_Sign for NCH signing step");
        using SignResponse signResponse = signResult.Value;

        BigInteger r = new BigInteger(signResponse.SignatureR.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        BigInteger s0 = new BigInteger(signResponse.SignatureS.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        BigInteger s = P * s0 % EcMath.Q;

        EcdsaSignature sig = new(r, s);
        Assert.IsTrue(SecdsaAlgorithms.Verify(instructionHash, sig, Y),
            "Alice's SECDSA signature (TPM signs, pure .NET verifies) must verify under Y = P*U.");

        FullEcdsaSignature fullSig = SecdsaAlgorithms.ToFullFormat(sig, instructionHash, Y);
        Assert.IsTrue(SecdsaAlgorithms.VerifyFull(instructionHash, fullSig, Y),
            "Full-format SECDSA signature must verify under Y (Algorithm 15).");

        //-- Scaled verification values and ZKP -----------------------------------

        BigInteger sInv = EcMath.ModInverse(fullSig.S);
        EcPoint Gdouble = EcMath.Multiply(Gprime, sInv);
        EcPoint Ydouble = EcMath.Multiply(Yprime, sInv);

        SchnorrZkProof zkp = SchnorrZkp.Generate(
            generators: [Gprime, Yprime],
            publicKeys: [Gdouble, Ydouble],
            witness: sInv,
            challengeBinding: ReadOnlySpan<byte>.Empty);

        Assert.IsTrue(SchnorrZkp.Verify(
            proof: zkp,
            generators: [Gprime, Yprime],
            publicKeys: [Gdouble, Ydouble],
            challengeBinding: ReadOnlySpan<byte>.Empty),
            "Schnorr ZKP must confirm G'' and Y'' share the same discrete log s^-1.");

        //-- WSCD boundary: ECDH verification equation R' = aU*R via TPM2_ECDH_ZGen --
        //
        //The wallet provider's Wallet Secure Cryptographic Application (WSCA) computes
        //aU*R using the WSCD-bound blinding key.
        //Here the same test TPM performs this via TPM2_ECDH_ZGen. The wallet
        //independently computes R' = e*G'' + r*Y''. Proposition 3.3 requires R' = aU*R.

        byte[] rBytes = EcMath.EncodePointUncompressed(fullSig.RPoint);
        using EcdhZGenInput verificationInput = EcdhZGenInput.FromUncompressedPoint(ecdhKeyHandle, rBytes, pool);
        using var ecdhAuthVerification = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<EcdhZGenResponse> verificationResult = TpmCommandExecutor.Execute<EcdhZGenResponse>(
            Tpm, verificationInput, [ecdhAuthVerification], pool, registry);

        AssertUtilities.AssertSuccess(verificationResult, "TPM2_ECDH_ZGen for aU*R verification");
        using EcdhZGenResponse verificationResponse = verificationResult.Value;
        EcPoint aUR = EcMath.DecodePointUncompressed(verificationResponse.ToUncompressedPoint());

        BigInteger eScalar = EcMath.HashToInteger(instructionHash);
        BigInteger rScalar = fullSig.RPoint.X % EcMath.Q;
        EcPoint Rprime = EcMath.Add(
            EcMath.Multiply(Gdouble, eScalar),
            EcMath.Multiply(Ydouble, rScalar));

        Assert.AreEqual(aUR, Rprime,
            "ECDH verification equation R' = e*G'' + r*Y'' must equal TPM-computed aU*R (Proposition 3.3). " +
            "This proves Alice entered the correct PIN and the TPM performed the correct operations.");

        //At this point in a production system:
        //  - The wallet provider's WSCA would execute the instruction in the WSCD,
        //    sign the InstructionTranscript TI with its transcript key s, and write T
        //    to its Transaction Log before returning it to Alice's Wallet APP.
        //  - Alice's Wallet APP would receive T, write it to its Transaction Log, and
        //    use the signed result to construct the Verifiable Presentation that is
        //    returned to EudiBank over the OID4VP channel.
        //  Both logs hold independently verifiable evidence of the wallet operation.
        //  EudiBank's OID4VP session with the wallet is a separate channel.

        //-- Cleanup ---------------------------------------------------------------

        var flushSigning = FlushContextInput.ForHandle(signingKeyHandle.Value);
        _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, flushSigning, [], pool, registry);

        var flushEcdh = FlushContextInput.ForHandle(ecdhKeyHandle.Value);
        _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, flushEcdh, [], pool, registry);
    }

    private static byte[] ExtractEccPublicPoint(Tpm2bPublic publicArea)
    {
        ReadOnlySpan<byte> x = publicArea.PublicArea.Unique.Ecc!.X.AsReadOnlySpan();
        ReadOnlySpan<byte> y = publicArea.PublicArea.Unique.Ecc!.Y.AsReadOnlySpan();
        return EllipticCurveUtilities.CombineToUncompressedPoint(x, y);
    }

    private sealed class DelegateObserver(Action<TpmExchange> onNext): IObserver<TpmExchange>
    {
        public void OnNext(TpmExchange value) => onNext(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }
}