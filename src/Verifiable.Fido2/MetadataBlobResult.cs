using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The result of a Metadata BLOB verification procedure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">FIDO
/// Metadata Service v3.1, section 3.2: Metadata BLOB object processing rules.</see>
/// <para>
/// A closed sum, mirroring the <see cref="AttestationResult"/> idiom exactly: every
/// <see cref="VerifyMetadataBlobAsyncDelegate"/> returns exactly one of the three sibling records
/// declared alongside this base — <see cref="VerifiedMetadataBlobResult"/>,
/// <see cref="RejectedMetadataBlobResult"/>, or <see cref="MetadataBlobStoreUnavailableResult"/> —
/// and a caller consumes the result with an exhaustive switch expression rather than a type test
/// against an open hierarchy.
/// </para>
/// </remarks>
public abstract record MetadataBlobResult
{
    /// <summary>
    /// Prevents this closed sum from being extended outside the sibling records declared alongside
    /// it.
    /// </summary>
    private protected MetadataBlobResult()
    {
    }
}


/// <summary>
/// The verification result for a Metadata BLOB whose JWS signature verified against its <c>x5c</c>
/// certificate path and whose payload passed every check this library enforces.
/// </summary>
/// <param name="Blob">
/// The verified BLOB, including its typed payload. Ownership transfers to the caller: the caller
/// disposes <paramref name="Blob"/> once it is no longer needed (its certificate carriers and
/// payload entries are pooled memory).
/// </param>
/// <param name="RevocationPolicy">
/// The <see cref="MetadataBlobRevocationPolicy"/> the originating request declared, per
/// <see cref="MetadataBlobVerificationRequest.RevocationPolicy"/> — the posture that actually
/// produced this result, so downstream policy can observe whether the certificate chain's revocation
/// status was checked (<see cref="MetadataBlobRevocationPolicy.Required"/>) or deliberately not
/// (<see cref="MetadataBlobRevocationPolicy.NotChecked"/>) rather than assuming one or the other.
/// </param>
[DebuggerDisplay("VerifiedMetadataBlobResult(No={Blob.Payload.No}, RevocationPolicy={RevocationPolicy})")]
public sealed record VerifiedMetadataBlobResult(MetadataBlob Blob, MetadataBlobRevocationPolicy RevocationPolicy): MetadataBlobResult;


/// <summary>
/// The verification result when a Metadata BLOB fails its verification procedure.
/// </summary>
/// <param name="Error">
/// The specific <see cref="Fido2MetadataError"/> naming what failed, drawn from the catalog in
/// <see cref="Fido2MetadataErrors"/>, so a caller can branch on the rejection reason without
/// parsing an exception message.
/// </param>
/// <remarks>
/// A rejected Metadata BLOB is a normal verification outcome, not an exceptional one: a stale,
/// tampered, or untrusted BLOB is exactly what this verification procedure exists to detect, so it
/// is reported as a result rather than thrown.
/// </remarks>
[DebuggerDisplay("RejectedMetadataBlobResult({Error.Code,nq})")]
public sealed record RejectedMetadataBlobResult(Fido2MetadataError Error): MetadataBlobResult;


/// <summary>
/// The verification result when a <see cref="MetadataBlobVerificationRequest"/> declares a
/// <see cref="MetadataBlobSerialNumberPolicy.Required"/> or <see cref="MetadataBlobRevocationPolicy.Required"/>
/// posture, but the delegate that posture demands is not wired to <see cref="MetadataBlobVerification.Build"/>
/// — or, for the serial-number seam, the wired resolve delegate itself failed.
/// </summary>
/// <param name="Error">
/// The specific <see cref="Fido2MetadataError"/> naming which required seam was unavailable —
/// <see cref="Fido2MetadataErrors.SerialNumberStoreUnavailable"/> or
/// <see cref="Fido2MetadataErrors.RevocationCheckUnavailable"/>.
/// </param>
/// <remarks>
/// The <c>JtiReplayOutcome.StoreUnavailable</c> analog: a deployment-configuration failure ("this
/// caller declared a Required posture but never wired the seam it demands") is distinguishable from
/// both an accepted BLOB and a BLOB this procedure examined and rejected on its own merits — a caller
/// that conflated the two could mistake "I forgot to wire persistence" for "an attacker tampered with
/// this BLOB," or silently proceed with a BLOB whose declared invariants were never actually checked.
/// The verification never reaches a substantive accept/reject decision for the check the missing
/// delegate would have performed; the closed sum's third case makes that distinction unskippable.
/// </remarks>
[DebuggerDisplay("MetadataBlobStoreUnavailableResult({Error.Code,nq})")]
public sealed record MetadataBlobStoreUnavailableResult(Fido2MetadataError Error): MetadataBlobResult;
