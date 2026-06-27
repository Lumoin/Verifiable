using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.TestInfrastructure.TpmSimulator;
using Verifiable.Tests.X509;
using Verifiable.Tpm;
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
/// Exemplifies the endorsement-key trust leg of the chain of trust: a TPM's endorsement key (EK) is trusted
/// because its certificate chains to a manufacturer CA the relying party already trusts. The validation runs
/// through the same <c>Verifiable.Cryptography</c> chain seam (<see cref="MicrosoftX509Functions.ValidateChainAsync"/>,
/// an implementation of <see cref="Verifiable.Cryptography.Pki.ValidateCertificateChainAsyncDelegate"/>) that
/// X.509 and mdoc verification use — the convergence point.
/// </summary>
/// <remarks>
/// <para>
/// A real TPM stores its EK certificate in a well-known NV index, written at manufacture; here a test CA stands
/// in for the manufacturer and issues an EK certificate over the TPM's actual exported EK public key (TPM2_NV
/// provisioning of that certificate is a follow-on, requiring TPM2_NV_Write). Validating that certificate to the
/// CA, and confirming it certifies the TPM's real EK, is what turns "an EK I created" into "an EK whose origin a
/// relying party can trust" — the missing leg above credential activation (which proves an attestation key
/// co-resides with this EK).
/// </para>
/// <para>
/// The tests are gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); they
/// report <see cref="Assert.Inconclusive(string)"/> when none is reachable, so they are safe in any run.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorEndorsementTrustTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The NV Index handle the EK certificate is provisioned into (MSO 0x01 = TPM_HT_NV_INDEX).</summary>
    private const uint EkCertificateNvIndex = 0x0100_0010;

    /// <summary>
    /// The NV Index capacity reserved for the EK certificate — generously sized above a P-256 EK certificate so
    /// the same index serves repeated runs (the index, once defined, persists on the simulator).
    /// </summary>
    private const int EkCertificateNvCapacity = 1024;

    /// <summary>The connection to the simulator, established once for the class.</summary>
    private static MsTpmSimulatorConnection? Connection { get; set; }

    /// <summary>The TPM device created over the simulator connection.</summary>
    private static TpmDevice? Tpm { get; set; }

    /// <summary>Whether a simulator was reachable at class initialization.</summary>
    private static bool HasSimulator { get; set; }

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Connects to the simulator (if one is reachable) and brings up a TPM device for the class.</summary>
    /// <param name="context">The class-level test context.</param>
    [ClassInitialize]
    public static async Task ClassInit(TestContext context)
    {
        if(!MsTpmSimulatorConnection.IsAvailable("localhost", MsTpmSimulatorConnection.DefaultCommandPort, TimeSpan.FromSeconds(1)))
        {
            return;
        }

        Connection = await MsTpmSimulatorConnection.ConnectAsync(
            "localhost", MsTpmSimulatorConnection.DefaultCommandPort, context.CancellationToken).ConfigureAwait(false);
        Tpm = TpmDevice.Create(Connection.SubmitAsync);
        HasSimulator = true;
    }

    /// <summary>Releases the TPM device and simulator connection.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    /// <summary>Skips the test when no simulator is reachable.</summary>
    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task EndorsementKeyCertificateValidatesToManufacturerCa()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();
        TimeProvider time = TimeProvider.System;

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            //Reconstruct the EK public key from the TPM's exported public area only.
            ECParameters ekParameters = ExportEkPublicParameters(ek);
            using ECDsa ekPublic = ECDsa.Create(ekParameters);

            //The "manufacturer" CA issues an EK certificate over the TPM's real EK public key.
            using X509ChainTestRingNode manufacturerCa = X509ChainTestRing.CreateRootCa(time, "TPM Vendor Test EK Root CA");
            using X509Certificate2 ekCertificate = IssueEkCertificate(manufacturerCa, ekPublic, time);

            //Trust check: validate the EK certificate to the manufacturer CA through the shared chain seam.
            using PkiCertificateMemory ekCertMemory = ToPkiCertificate(ekCertificate.RawData, pool);
            using PkiCertificateMemory caCertMemory = ToPkiCertificate(manufacturerCa.Certificate.RawData, pool);

            using PublicKeyMemory validatedLeafKey = await MicrosoftX509Functions.ValidateChainAsync(
                [ekCertMemory], [caCertMemory], time.GetUtcNow(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(validatedLeafKey.AsReadOnlySpan().IsEmpty, "Validation must yield the certified EK public key.");

            //Binding check: the certificate certifies THIS TPM's EK — its SubjectPublicKeyInfo is exactly the EK's.
            //(Compared via SPKI rather than GetECDsaPublicKey(), which returns null for the EK's keyAgreement usage.)
            byte[] certifiedSpki = ekCertificate.PublicKey.ExportSubjectPublicKeyInfo();
            byte[] ekSpki = ekPublic.ExportSubjectPublicKeyInfo();
            Assert.IsTrue(certifiedSpki.AsSpan().SequenceEqual(ekSpki), "The EK certificate must certify the TPM's actual EK public key.");
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task EndorsementKeyCertificateFromUntrustedCaIsRejected()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();
        TimeProvider time = TimeProvider.System;

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            ECParameters ekParameters = ExportEkPublicParameters(ek);
            using ECDsa ekPublic = ECDsa.Create(ekParameters);

            //The EK certificate is issued by one CA, but validation is attempted against a different, unrelated CA.
            using X509ChainTestRingNode issuingCa = X509ChainTestRing.CreateRootCa(time, "TPM Vendor Test EK Root CA");
            using X509ChainTestRingNode unrelatedCa = X509ChainTestRing.CreateRootCa(time, "Unrelated Root CA");
            using X509Certificate2 ekCertificate = IssueEkCertificate(issuingCa, ekPublic, time);

            using PkiCertificateMemory ekCertMemory = ToPkiCertificate(ekCertificate.RawData, pool);
            using PkiCertificateMemory unrelatedCaMemory = ToPkiCertificate(unrelatedCa.Certificate.RawData, pool);

            bool rejected = false;
            try
            {
                using PublicKeyMemory _ = await MicrosoftX509Functions.ValidateChainAsync(
                    [ekCertMemory], [unrelatedCaMemory], time.GetUtcNow(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            }
            catch(System.Security.SecurityException)
            {
                rejected = true;
            }

            Assert.IsTrue(rejected, "An EK certificate that does not chain to the trusted CA must be rejected.");
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task EndorsementKeyCertificateRoundTripsThroughNvAndValidates()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();
        TimeProvider time = TimeProvider.System;

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            ECParameters ekParameters = ExportEkPublicParameters(ek);
            using ECDsa ekPublic = ECDsa.Create(ekParameters);

            using X509ChainTestRingNode manufacturerCa = X509ChainTestRing.CreateRootCa(time, "TPM Vendor Test EK Root CA");
            using X509Certificate2 ekCertificate = IssueEkCertificate(manufacturerCa, ekPublic, time);
            byte[] certificateDer = ekCertificate.RawData;

            //Provision the EK certificate into an NV index the way a manufacturer does, then read it back — the
            //relying party obtains the EK certificate from the TPM's own NV rather than a side channel.
            await ProvisionNvAsync(tpm, registry, pool, EkCertificateNvIndex, certificateDer).ConfigureAwait(false);
            byte[] certificateFromNv = await ReadNvAsync(tpm, registry, pool, EkCertificateNvIndex, certificateDer.Length).ConfigureAwait(false);

            Assert.IsTrue(certificateFromNv.AsSpan().SequenceEqual(certificateDer), "The EK certificate read from NV must equal the provisioned bytes.");

            //Trust check: the NV-sourced EK certificate validates to the manufacturer CA through the shared seam.
            using PkiCertificateMemory ekCertMemory = ToPkiCertificate(certificateFromNv, pool);
            using PkiCertificateMemory caCertMemory = ToPkiCertificate(manufacturerCa.Certificate.RawData, pool);

            using PublicKeyMemory validatedLeafKey = await MicrosoftX509Functions.ValidateChainAsync(
                [ekCertMemory], [caCertMemory], time.GetUtcNow(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(validatedLeafKey.AsReadOnlySpan().IsEmpty, "The NV-sourced EK certificate must validate to the manufacturer CA.");
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Defines (if not already present) an NV Index authorized by its own empty auth value and writes
    /// <paramref name="data"/> to it at offset zero.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="data">The data to write.</param>
    private async Task ProvisionNvAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint nvIndex, byte[] data)
    {
        //Define the index with AUTHWRITE | AUTHREAD (its own auth value authorizes both) and NO_DA. The redundant
        //using locals satisfy CA2000; the input takes ownership and disposal is idempotent.
        using(Tpm2bAuth indexAuth = Tpm2bAuth.CreateEmpty(pool))
        using(var publicInfo = new TpmsNvPublic(
            nvIndex,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA,
            Tpm2bDigest.Empty,
            dataSize: EkCertificateNvCapacity))
        using(var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo))
        using(TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
                tpm, defineInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            //The index persists across runs on the shared simulator, so an already-defined index is expected.
            Assert.IsTrue(
                defineResult.IsSuccess || defineResult.ResponseCode == TpmRcConstants.TPM_RC_NV_DEFINED,
                $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        }

        using TpmPasswordSession writeAuth = TpmPasswordSession.CreateEmpty(pool);
        var writeInput = new NvWriteInput(AuthHandle: nvIndex, NvIndex: nvIndex, Data: new Tpm2bMaxBuffer(data), Offset: 0);
        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// Reads <paramref name="length"/> octets from offset zero of an NV Index authorized by its own empty auth value.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="length">The number of octets to read.</param>
    /// <returns>The data read from the index.</returns>
    private async Task<byte[]> ReadNvAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint nvIndex, int length)
    {
        using TpmPasswordSession readAuth = TpmPasswordSession.CreateEmpty(pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: (ushort)length, Offset: 0);
        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            tpm, readInput, [readAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"NV_Read failed: '{readResult.ResponseCode}'.");

        using NvReadResponse read = readResult.Value;

        return read.Data.ToArray();
    }

    /// <summary>
    /// Reconstructs the EK public key as <see cref="ECParameters"/> from the TPM's exported public area, with the
    /// coordinates left-padded to the fixed P-256 width.
    /// </summary>
    /// <param name="ek">The CreatePrimary response for the endorsement key.</param>
    /// <returns>The public EC parameters.</returns>
    private static ECParameters ExportEkPublicParameters(CreatePrimaryResponse ek)
    {
        TpmsEccPoint point = ek.OutPublic.PublicArea.Unique.Ecc!;

        return new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };
    }

    /// <summary>
    /// Issues an end-entity EK certificate over <paramref name="ekPublicKey"/>, signed by the manufacturer CA.
    /// </summary>
    /// <param name="manufacturerCa">The CA node standing in for the TPM vendor.</param>
    /// <param name="ekPublicKey">The TPM's EK public key (public-only).</param>
    /// <param name="time">The time provider for validity bounds.</param>
    /// <returns>The issued EK certificate (public-only).</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned certificate transfers to the caller's using declaration.")]
    private static X509Certificate2 IssueEkCertificate(X509ChainTestRingNode manufacturerCa, ECDsa ekPublicKey, TimeProvider time)
    {
        DateTimeOffset now = time.GetUtcNow();
        var request = new CertificateRequest("CN=TPM EK, O=Verifiable Test Infrastructure", ekPublicKey, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));

        //An EK is a restricted decryption (storage) key: keyEncipherment / keyAgreement, not signing.
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.KeyAgreement, critical: true));

        byte[] serialNumber = RandomNumberGenerator.GetBytes(8);
        using X509Certificate2 caWithKey = manufacturerCa.Certificate.CopyWithPrivateKey(manufacturerCa.SigningKey);

        return request.Create(
            caWithKey,
            notBefore: now.AddDays(-1).UtcDateTime,
            notAfter: now.AddYears(2).UtcDateTime,
            serialNumber: serialNumber);
    }

    /// <summary>
    /// Wraps DER certificate bytes in a pooled <see cref="PkiCertificateMemory"/>.
    /// </summary>
    /// <param name="der">The DER-encoded certificate.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The pooled certificate (the caller owns it).</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PkiCertificateMemory transfers to the caller.")]
    private static PkiCertificateMemory ToPkiCertificate(byte[] der, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }

    /// <summary>
    /// Left-pads a big-endian value to a fixed width, as the ECParameters coordinate encoding requires.
    /// </summary>
    /// <param name="value">The big-endian value (the TPM may omit leading zero bytes).</param>
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

    /// <summary>
    /// Creates a restricted-decrypt ECC storage primary (the endorsement key) under the given hierarchy.
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
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary EK ({hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a response codec registry covering the commands these tests issue.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
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
}
