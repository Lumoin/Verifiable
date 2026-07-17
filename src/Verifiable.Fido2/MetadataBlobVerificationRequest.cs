using System.Buffers;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// The inputs to a Metadata BLOB verification procedure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">FIDO
/// Metadata Service v3.1, section 3.2: Metadata BLOB object processing rules.</see>
/// <para>
/// <strong>Ownership.</strong> This request only references caller-owned carriers; it does not take
/// ownership of <see cref="BlobBytes"/> or <see cref="TrustAnchors"/>, and does not dispose them —
/// mirrors <see cref="AttestationVerificationRequest"/>'s non-owning input-bag shape.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class MetadataBlobVerificationRequest
{
    /// <summary>
    /// Initializes a <see cref="MetadataBlobVerificationRequest"/> from its verification inputs.
    /// </summary>
    /// <param name="blobBytes">The raw compact-JWS Metadata BLOB bytes, per <see cref="BlobBytes"/>.</param>
    /// <param name="trustAnchors">The MDS trust anchor certificates, per <see cref="TrustAnchors"/>.</param>
    /// <param name="validationTime">The time at which to evaluate certificate validity and BLOB freshness, per <see cref="ValidationTime"/>.</param>
    /// <param name="tenantId">The tenant this verification is scoped to, per <see cref="TenantId"/>.</param>
    /// <param name="serialNumberPolicy">The serial-number monotonicity-tracking posture, per <see cref="SerialNumberPolicy"/>.</param>
    /// <param name="revocationPolicy">The certificate-chain revocation-checking posture, per <see cref="RevocationPolicy"/>.</param>
    /// <param name="pool">The memory pool, per <see cref="Pool"/>.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="trustAnchors"/> or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    public MetadataBlobVerificationRequest(
        ReadOnlyMemory<byte> blobBytes,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        TenantId tenantId,
        MetadataBlobSerialNumberPolicy serialNumberPolicy,
        MetadataBlobRevocationPolicy revocationPolicy,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(pool);

        BlobBytes = blobBytes;
        TrustAnchors = trustAnchors;
        ValidationTime = validationTime;
        TenantId = tenantId;
        SerialNumberPolicy = serialNumberPolicy;
        RevocationPolicy = revocationPolicy;
        Pool = pool;
    }


    /// <summary>
    /// Initializes a <see cref="MetadataBlobVerificationRequest"/> that reads <paramref name="timeProvider"/>'s
    /// clock once so <see cref="ValidationTime"/> shares one instant with every other window check the
    /// caller derives from the same <paramref name="timeProvider"/> in a single verification.
    /// </summary>
    /// <param name="blobBytes">The raw compact-JWS Metadata BLOB bytes, per <see cref="BlobBytes"/>.</param>
    /// <param name="trustAnchors">The MDS trust anchor certificates, per <see cref="TrustAnchors"/>.</param>
    /// <param name="timeProvider">The time provider read once, via <see cref="TimeProvider.GetUtcNow"/>, for <see cref="ValidationTime"/>.</param>
    /// <param name="tenantId">The tenant this verification is scoped to, per <see cref="TenantId"/>.</param>
    /// <param name="serialNumberPolicy">The serial-number monotonicity-tracking posture, per <see cref="SerialNumberPolicy"/>.</param>
    /// <param name="revocationPolicy">The certificate-chain revocation-checking posture, per <see cref="RevocationPolicy"/>.</param>
    /// <param name="pool">The memory pool, per <see cref="Pool"/>.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="timeProvider"/>, <paramref name="trustAnchors"/> or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    public MetadataBlobVerificationRequest(
        ReadOnlyMemory<byte> blobBytes,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        TimeProvider timeProvider,
        TenantId tenantId,
        MetadataBlobSerialNumberPolicy serialNumberPolicy,
        MetadataBlobRevocationPolicy revocationPolicy,
        MemoryPool<byte> pool) : this(blobBytes, trustAnchors, ReadOnce(timeProvider), tenantId, serialNumberPolicy, revocationPolicy, pool)
    {
    }


    /// <summary>
    /// Reads <paramref name="timeProvider"/>'s clock exactly once, so the constructor it backs never
    /// calls <see cref="TimeProvider.GetUtcNow"/> more than a single time per instance.
    /// </summary>
    /// <param name="timeProvider">The time provider to read.</param>
    /// <returns>The instant <paramref name="timeProvider"/> reports at the moment of the call.</returns>
    private static DateTimeOffset ReadOnce(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        return timeProvider.GetUtcNow();
    }


    /// <summary>
    /// The raw compact-JWS Metadata BLOB bytes, exactly as the caller obtained them. This library
    /// performs zero HTTP — the caller downloads and caches the BLOB, per
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">section
    /// 3.2</see> items 1/3/6/7.
    /// </summary>
    public ReadOnlyMemory<byte> BlobBytes { get; }

    /// <summary>
    /// The MDS trust anchor certificates the BLOB's <c>x5c</c> certificate path is validated
    /// against. May be empty, in which case verification rejects with
    /// <see cref="Fido2MetadataErrors.NoBlobTrustAnchors"/>.
    /// </summary>
    public IReadOnlyList<PkiCertificateMemory> TrustAnchors { get; }

    /// <summary>
    /// The UTC time at which to evaluate certificate validity during chain validation, and against
    /// which the payload's <c>nextUpdate</c> staleness check runs.
    /// </summary>
    public DateTimeOffset ValidationTime { get; }

    /// <summary>
    /// The tenant this verification is scoped to — threaded into
    /// <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/> and
    /// <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/> when <see cref="SerialNumberPolicy"/> is
    /// <see cref="MetadataBlobSerialNumberPolicy.Required"/>, so a multi-tenant deployment tracks a
    /// serial-number baseline per tenant rather than one shared across every caller.
    /// </summary>
    public TenantId TenantId { get; }

    /// <summary>
    /// The serial-number (<c>no</c>) monotonicity-tracking posture this request declares. Under
    /// <see cref="MetadataBlobSerialNumberPolicy.Required"/>, <see cref="MetadataBlobVerification.VerifyAsync"/>
    /// resolves <see cref="TenantId"/>'s previously-cached serial number via the wired
    /// <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/> and rejects with
    /// <see cref="Fido2MetadataErrors.SerialNumberNotIncreasing"/> when the verified payload's
    /// <c>no</c> is not strictly greater; an accepted result is then recorded via the wired
    /// <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/>. There is no implicit default — every
    /// request states its posture explicitly. See <see cref="MetadataBlobSerialNumberPolicy"/>'s own
    /// remarks for the full enforcement contract, including the <see cref="MetadataBlobStoreUnavailableResult"/>
    /// fail-closed outcome when <see cref="MetadataBlobSerialNumberPolicy.Required"/> is declared but
    /// the delegate pair is not wired.
    /// </summary>
    public MetadataBlobSerialNumberPolicy SerialNumberPolicy { get; }

    /// <summary>
    /// The certificate-chain revocation-checking posture this request declares. Under
    /// <see cref="MetadataBlobRevocationPolicy.Required"/>, every certificate in the BLOB's
    /// <c>x5c</c> chain MUST be checked through the wired
    /// <see cref="CheckCertificateRevocationStatusAsyncDelegate"/>; under
    /// <see cref="MetadataBlobRevocationPolicy.NotChecked"/>, no revocation check runs even when a
    /// delegate is wired. There is no implicit default — every request states its posture explicitly.
    /// See <see cref="MetadataBlobRevocationPolicy"/>'s own remarks for the full enforcement
    /// contract, including the <see cref="MetadataBlobStoreUnavailableResult"/> fail-closed outcome
    /// when <see cref="MetadataBlobRevocationPolicy.Required"/> is declared but no delegate is wired.
    /// </summary>
    public MetadataBlobRevocationPolicy RevocationPolicy { get; }

    /// <summary>
    /// The memory pool a verification procedure allocates working buffers from — the decoded
    /// certificate carriers and the payload's shared raw-statement buffer.
    /// </summary>
    public MemoryPool<byte> Pool { get; }


    /// <summary>
    /// A debugger-friendly summary of the request's size and trust-anchor count, rather than every
    /// field, matching this codebase's convention for non-owning input bags.
    /// </summary>
    private string DebuggerDisplay => $"MetadataBlobVerificationRequest({BlobBytes.Length} bytes, TrustAnchors={TrustAnchors.Count})";
}
