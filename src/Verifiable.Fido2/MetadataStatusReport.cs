using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// A single status report entry from a FIDO Metadata Service BLOB payload entry's
/// <c>statusReports</c> array — the minimal, typed subset of the <c>StatusReport</c> dictionary
/// this library models.
/// </summary>
/// <param name="Status">
/// The <c>status</c> member — one of the <see cref="WellKnownAuthenticatorStatuses"/> values, per
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-authnr-stat">FIDO
/// Metadata Service v3.1, section 3.1.4: AuthenticatorStatus enum</see>.
/// </param>
/// <param name="EffectiveDate">
/// The <c>effectiveDate</c> member, if present — the ISO-8601 date since when <see cref="Status"/>
/// was set, per
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-stat-rep">FIDO
/// Metadata Service v3.1, section 3.1.3: StatusReport dictionary</see>: "if no date is given, the
/// status is assumed to be effective while present".
/// </param>
/// <param name="Certificate">
/// The <c>certificate</c> member, if present — a standard (not base64url) base64-encoded DER
/// certificate related to the current status, for example the batch or attestation root
/// certificate a compromise status names, per the same section. <see langword="null"/> when the
/// member is absent.
/// </param>
/// <remarks>
/// Every other <c>StatusReport</c> member (<c>authenticatorVersion</c>, <c>batchCertificate</c>,
/// <c>url</c>, <c>certificationDescriptor</c>, and the certification/FIPS bookkeeping fields) is
/// out of scope for this wave's capability surface — this type models only what the status-gating
/// evaluation in <see cref="MetadataBlobPayloadQueries.EvaluateStatus"/> and the compromise-report
/// certificate lookup a caller's own policy delegate performs need.
/// </remarks>
[DebuggerDisplay("MetadataStatusReport(Status={Status,nq}, EffectiveDate={EffectiveDate})")]
public sealed record MetadataStatusReport(string Status, DateOnly? EffectiveDate, string? Certificate);
