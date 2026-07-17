namespace Verifiable.Fido2;

/// <summary>
/// The Metadata BLOB serial-number (<c>no</c>) monotonicity-tracking posture a
/// <see cref="MetadataBlobVerificationRequest"/> declares.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-payload-blob">FIDO
/// Metadata Service v3.1, section 3.1.6: Metadata BLOB Payload dictionary</see>: "This serial number
/// MUST be incremented whenever the contents of the BLOB changes. Serial numbers MUST be consecutive
/// and strictly monotonic." A request states one of the two postures below explicitly — there is no
/// implicit default — mirroring <c>JtiReplayPolicy</c>'s shape.
/// </remarks>
public enum MetadataBlobSerialNumberPolicy
{
    /// <summary>
    /// <see cref="MetadataBlobVerification.VerifyAsync"/> resolves the tenant's previously-cached
    /// serial number via a wired <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/>
    /// before comparing it against the parsed payload's <c>no</c>, and records an accepted result via
    /// a wired <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/> immediately before returning it.
    /// Both delegates MUST be wired to <see cref="MetadataBlobVerification.Build"/> — treated as one
    /// indivisible capability, since a resolve-only wiring would check monotonicity without ever
    /// recording a new baseline, and a persist-only wiring would record without ever checking. When
    /// either is absent, or the resolve delegate throws, verification yields
    /// <see cref="MetadataBlobStoreUnavailableResult"/> rather than silently skipping the
    /// monotonicity defense.
    /// </summary>
    Required,

    /// <summary>
    /// No serial-number state is tracked for this request: neither
    /// <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/> nor
    /// <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/> is invoked, even when both are wired to
    /// <see cref="MetadataBlobVerification.Build"/>, and the monotonicity check is not applied — a
    /// BLOB whose <c>no</c> regresses verifies successfully. An explicit, greppable statement that
    /// this caller keeps no prior-BLOB cache for this request, for example a one-shot verification
    /// with no persistence layer at all.
    /// </summary>
    NotTracked
}
