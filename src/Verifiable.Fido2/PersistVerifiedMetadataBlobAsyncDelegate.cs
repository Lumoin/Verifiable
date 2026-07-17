using Verifiable.Core;

namespace Verifiable.Fido2;

/// <summary>
/// Records an accepted Metadata BLOB verification for <paramref name="tenantId"/>, so a later
/// <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/> call observes its serial number
/// as the new baseline.
/// </summary>
/// <param name="tenantId">The tenant the verified BLOB is scoped to.</param>
/// <param name="result">
/// The accepted verification result — its <see cref="VerifiedMetadataBlobResult.Blob"/> carries the
/// serial number and the full typed payload, closing
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">FIDO
/// Metadata Service v3.1, section 3.2</see> item 7's "write the verified object to a local cache."
/// Ownership of <see cref="VerifiedMetadataBlobResult.Blob"/> stays with the caller of
/// <see cref="MetadataBlobVerification.VerifyAsync"/>, who disposes it once no longer needed; an
/// implementation that needs to retain data beyond this call copies what it needs rather than
/// holding the instance itself.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <remarks>
/// <see cref="MetadataBlobVerification.VerifyAsync"/> invokes this delegate under
/// <see cref="MetadataBlobSerialNumberPolicy.Required"/>, exactly once, immediately before returning
/// an accepted result — never on any rejection path — so a caller can never observe a persisted
/// serial number for a BLOB that did not actually verify. Mirrors <c>PersistDpopProofJtiDelegate</c>'s
/// "the validator calls this once per accepted proof" contract; implementations SHOULD be idempotent
/// for the same reason.
/// </remarks>
public delegate ValueTask PersistVerifiedMetadataBlobAsyncDelegate(TenantId tenantId, VerifiedMetadataBlobResult result, CancellationToken cancellationToken);
