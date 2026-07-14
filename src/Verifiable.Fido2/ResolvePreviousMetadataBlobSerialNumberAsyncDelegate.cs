using Verifiable.Core;

namespace Verifiable.Fido2;

/// <summary>
/// Resolves the Metadata BLOB serial number (<c>no</c>) <paramref name="tenantId"/> last had
/// verified and cached, or <see langword="null"/> when no BLOB has yet been cached for that tenant
/// (for example, the first BLOB this tenant has ever verified).
/// </summary>
/// <param name="tenantId">The tenant whose previously-cached serial number is being resolved.</param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>The previously-cached serial number, or <see langword="null"/> when none is cached yet.</returns>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-payload-blob">FIDO
/// Metadata Service v3.1, section 3.1.6: Metadata BLOB Payload dictionary</see>: "Serial numbers
/// MUST be consecutive and strictly monotonic." <see cref="MetadataBlobVerification.VerifyAsync"/>
/// invokes this delegate under <see cref="MetadataBlobSerialNumberPolicy.Required"/>, immediately
/// before comparing its result against the parsed payload's <c>no</c> — the read half of the
/// resolve/persist pair <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/> completes. Mirrors
/// <c>IsDpopProofJtiSeenDelegate</c>'s shape: the application supplies storage, the library supplies
/// the monotonicity decision. A thrown exception is treated identically to an unwired delegate —
/// <see cref="MetadataBlobVerification.VerifyAsync"/> fails closed to
/// <see cref="MetadataBlobStoreUnavailableResult"/> rather than letting a storage failure surface as
/// an unhandled exception mid-verification.
/// </remarks>
public delegate ValueTask<long?> ResolvePreviousMetadataBlobSerialNumberAsyncDelegate(TenantId tenantId, CancellationToken cancellationToken);
