using System.Buffers;
using Verifiable.Core;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An in-memory, per-tenant Metadata BLOB serial-number store backing the
/// <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/>/
/// <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/> pair
/// <see cref="MetadataBlobVerification.Build"/> invokes under
/// <see cref="MetadataBlobSerialNumberPolicy.Required"/> — the single source of this fake across
/// every MDS test that exercises the seam, per the fixtures-live-once convention.
/// </summary>
internal sealed class FakeMetadataBlobSerialNumberStore
{
    /// <summary>The current serial-number baseline, keyed by <see cref="TenantId.Value"/>.</summary>
    private readonly Dictionary<string, long> serialNumbersByTenant = new(StringComparer.Ordinal);

    /// <summary>
    /// The <c>(tenant, serial number)</c> pairs recorded by <see cref="PersistAsync"/>, in call
    /// order. Empty until an accepted verification persists — the atomic-flow assertion surface
    /// proving <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/> fired (or did not) exactly as
    /// expected.
    /// </summary>
    public List<(TenantId TenantId, long SerialNumber)> Persisted { get; } = [];


    /// <summary>
    /// Seeds <paramref name="tenantId"/>'s baseline with <paramref name="serialNumber"/>, as if a
    /// prior verification had already persisted it — the "resolve returns N" half of a
    /// serial-regression test.
    /// </summary>
    /// <param name="tenantId">The tenant to seed.</param>
    /// <param name="serialNumber">The previously-cached serial number to report on resolve.</param>
    public void Seed(TenantId tenantId, long serialNumber) => serialNumbersByTenant[tenantId.Value] = serialNumber;


    /// <summary>
    /// The <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/> reading this store's
    /// current baseline for <paramref name="tenantId"/>.
    /// </summary>
    /// <param name="tenantId">The tenant whose baseline is being resolved.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The seeded or previously-persisted serial number, or <see langword="null"/> when none is recorded.</returns>
    public ValueTask<long?> ResolveAsync(TenantId tenantId, CancellationToken cancellationToken) =>
        ValueTask.FromResult<long?>(serialNumbersByTenant.TryGetValue(tenantId.Value, out long serialNumber) ? serialNumber : null);


    /// <summary>
    /// The <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/> recording an accepted
    /// verification's serial number as <paramref name="tenantId"/>'s new baseline, and appending it
    /// to <see cref="Persisted"/> for assertion.
    /// </summary>
    /// <param name="tenantId">The tenant the verified BLOB is scoped to.</param>
    /// <param name="result">The accepted verification result whose payload's serial number is recorded.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    public ValueTask PersistAsync(TenantId tenantId, VerifiedMetadataBlobResult result, CancellationToken cancellationToken)
    {
        long serialNumber = result.Blob.Payload.No;
        serialNumbersByTenant[tenantId.Value] = serialNumber;
        Persisted.Add((tenantId, serialNumber));

        return ValueTask.CompletedTask;
    }
}


/// <summary>
/// A <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/> that always throws, for
/// proving <see cref="MetadataBlobVerification"/> treats a failing resolve delegate identically to
/// an unwired one — both fail closed to <see cref="MetadataBlobStoreUnavailableResult"/> rather than
/// letting the exception escape mid-verification.
/// </summary>
internal static class ThrowingMetadataBlobSerialNumberResolver
{
    /// <summary>Always throws <see cref="InvalidOperationException"/>, simulating a failed store read.</summary>
    /// <param name="tenantId">Unused — present only to satisfy <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/>'s shape.</param>
    /// <param name="cancellationToken">Unused — present only to satisfy <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/>'s shape.</param>
    public static ValueTask<long?> ResolveAsync(TenantId tenantId, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("Simulated Metadata BLOB serial-number store failure.");
}


/// <summary>
/// A <see cref="CheckCertificateRevocationStatusAsyncDelegate"/> that unconditionally reports every
/// certificate as <see cref="CertificateRevocationStatus.Revoked"/> — used to prove
/// <see cref="MetadataBlobRevocationPolicy.NotChecked"/> genuinely bypasses revocation checking even
/// when a delegate that would otherwise fail chain validation is wired to
/// <see cref="MetadataBlobVerification.Build"/>.
/// </summary>
internal static class AlwaysRevokedCertificateChecker
{
    /// <summary>Always reports <see cref="CertificateRevocationStatus.Revoked"/> for <paramref name="certificate"/>.</summary>
    /// <param name="certificate">Unused — present only to satisfy <see cref="CheckCertificateRevocationStatusAsyncDelegate"/>'s shape.</param>
    /// <param name="issuerCandidates">Unused — present only to satisfy <see cref="CheckCertificateRevocationStatusAsyncDelegate"/>'s shape.</param>
    /// <param name="validationTime">Unused — present only to satisfy <see cref="CheckCertificateRevocationStatusAsyncDelegate"/>'s shape.</param>
    /// <param name="pool">Unused — present only to satisfy <see cref="CheckCertificateRevocationStatusAsyncDelegate"/>'s shape.</param>
    /// <param name="cancellationToken">Unused — present only to satisfy <see cref="CheckCertificateRevocationStatusAsyncDelegate"/>'s shape.</param>
    public static ValueTask<CertificateRevocationStatus> CheckAsync(
        PkiCertificateMemory certificate,
        IReadOnlyList<PkiCertificateMemory> issuerCandidates,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(CertificateRevocationStatus.Revoked);
}
