namespace Verifiable.Fido2;

/// <summary>
/// The certificate-chain revocation-checking posture a <see cref="MetadataBlobVerificationRequest"/>
/// declares.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">FIDO
/// Metadata Service v3.1, section 3.2: Metadata BLOB object processing rules</see>, item 4.iii: "All
/// certificates in the chain MUST be checked for revocation according to the checking rules
/// established by the CA that issued the certificate." A request states one of the two postures
/// below explicitly — there is no implicit default — replacing a nullable
/// <see cref="CheckCertificateRevocationStatusAsyncDelegate"/> defaulting to "no revocation is
/// performed" with an explicit, greppable statement of intent.
/// </remarks>
public enum MetadataBlobRevocationPolicy
{
    /// <summary>
    /// Every certificate in the BLOB's <c>x5c</c> chain MUST be checked through the
    /// <see cref="CheckCertificateRevocationStatusAsyncDelegate"/> wired to
    /// <see cref="MetadataBlobVerification.Build"/>. When none is wired, verification yields
    /// <see cref="MetadataBlobStoreUnavailableResult"/> rather than silently chaining without
    /// revocation checking.
    /// </summary>
    Required,

    /// <summary>
    /// No revocation check is performed for this request, even when a
    /// <see cref="CheckCertificateRevocationStatusAsyncDelegate"/> is wired to
    /// <see cref="MetadataBlobVerification.Build"/> — the request's declared posture always wins. An
    /// explicit, greppable caller statement that this verification accepts a
    /// chain-validated-but-revocation-blind BLOB;
    /// <see cref="VerifiedMetadataBlobResult.RevocationPolicy"/> carries this posture on the result so
    /// downstream policy can observe what was — and was not — checked.
    /// </summary>
    NotChecked
}
