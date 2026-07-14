using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// A diagnostic describing why a Metadata BLOB verification procedure rejected a BLOB. Carries a
/// stable <see cref="Code"/> for programmatic branching and a human-readable <see cref="Message"/>.
/// Standard conditions are exposed by <see cref="Fido2MetadataErrors"/>.
/// </summary>
/// <param name="Code">A stable, machine-comparable error code.</param>
/// <param name="Message">A human-readable description of the condition. Not for display to untrusted callers verbatim.</param>
[DebuggerDisplay("Fido2MetadataError({Code,nq})")]
public sealed record Fido2MetadataError(string Code, string Message);


/// <summary>
/// The standard <see cref="Fido2MetadataError"/> conditions a Metadata BLOB verification procedure
/// can end in, each exposed as a shared instance. Getters (not <c>static readonly</c> fields) per
/// the codebase convention for shared well-known values. A sibling catalog to
/// <see cref="Fido2AttestationErrors"/>, owned independently since BLOB verification is a distinct
/// procedure from attestation statement verification.
/// </summary>
public static class Fido2MetadataErrors
{
    /// <summary>
    /// The Metadata BLOB is not a well-formed three-segment compact JWS, or its header/payload JSON
    /// does not conform to the syntax this library requires.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
    /// Metadata Service v3.1, section 3.1.7: Metadata BLOB</see>: "The metadata BLOB is a JSON Web
    /// Token… MetadataBLOB = EncodedJWTHeader | "." | EncodedMetadataBLOBPayload | "." |
    /// EncodedJWSSignature."
    /// </remarks>
    public static Fido2MetadataError MalformedBlob { get; } = new(
        "malformed_blob",
        "The Metadata BLOB is not a well-formed compact JWS conforming to its defined syntax.");

    /// <summary>
    /// The Metadata BLOB's JWT Header <c>alg</c> is not one of the algorithms this library supports
    /// verifying a BLOB signature with.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
    /// Metadata Service v3.1, section 3.1.7: Metadata BLOB</see> illustrates <c>ES256</c> as the
    /// signing algorithm without mandating a closed algorithm set; this library's ES256/RS256
    /// allowlist is a deliberate, documented policy choice — a secure default limiting BLOB
    /// signature verification to strong, unambiguous asymmetric algorithms — not itself a
    /// specification requirement.
    /// </remarks>
    public static Fido2MetadataError UnsupportedBlobAlgorithm { get; } = new(
        "unsupported_blob_algorithm",
        "The Metadata BLOB's JWT Header alg is not one of the algorithms this library supports.");

    /// <summary>
    /// The Metadata BLOB conveys a certificate path, but no trust anchors were supplied against
    /// which to validate it.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">FIDO
    /// Metadata Service v3.1, section 3.2: Metadata BLOB object processing rules</see>, item 6:
    /// "Verify the signature of the Metadata BLOB object using the BLOB signing certificate chain".
    /// This library performs zero HTTP and never fetches the MDS root itself (item 1 of the same
    /// section is entirely the caller's concern), so the caller MUST supply the trust anchors.
    /// </remarks>
    public static Fido2MetadataError NoBlobTrustAnchors { get; } = new(
        "no_blob_trust_anchors",
        "The Metadata BLOB conveys a certificate path, but no trust anchors were supplied to validate it against.");

    /// <summary>
    /// The Metadata BLOB's <c>x5c</c> certificate path did not validate against the supplied trust
    /// anchors.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">FIDO
    /// Metadata Service v3.1, section 3.2: Metadata BLOB object processing rules</see>, item 4.ii:
    /// "The certificate chain MUST be verified to properly chain to the metadata BLOB signing trust
    /// anchor according to [RFC5280]." That MUST is textually scoped to the <c>x5u</c> branch (out
    /// of this library's fetcher-free scope, see <see cref="MalformedBlob"/>'s remarks on <c>x5u</c>
    /// rejection); this library applies the identical chain-validation and, when a revocation seam
    /// is wired, revocation discipline to the <c>x5c</c> branch as its own secure default, rather
    /// than assuming the specification's silence there means no check is needed.
    /// </remarks>
    public static Fido2MetadataError BlobChainValidationFailed { get; } = new(
        "blob_chain_validation_failed",
        "The Metadata BLOB's x5c certificate path did not validate against the supplied trust anchors.");

    /// <summary>
    /// The Metadata BLOB's JWS signature did not verify against the encoded header and payload.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">FIDO
    /// Metadata Service v3.1, section 3.2: Metadata BLOB object processing rules</see>, item 6:
    /// "Verify the signature of the Metadata BLOB object using the BLOB signing certificate chain…
    /// The FIDO Server SHOULD ignore the file if the signature is invalid." This library raises
    /// that SHOULD to a hard rejection.
    /// </remarks>
    public static Fido2MetadataError InvalidBlobSignature { get; } = new(
        "invalid_blob_signature",
        "The Metadata BLOB's JWS signature did not verify against the encoded header and payload.");

    /// <summary>
    /// The Metadata BLOB payload's <c>no</c> serial number is not strictly greater than the
    /// caller-supplied previously-cached serial number.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-payload-blob">FIDO
    /// Metadata Service v3.1, section 3.1.6: Metadata BLOB Payload dictionary</see>: "Serial numbers
    /// MUST be consecutive and strictly monotonic." The publisher-side MUST is restated as an
    /// RP-facing SHOULD at
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">section
    /// 3.2</see>, item 6: "It SHOULD also ignore the file if its number (no) is less or equal to
    /// the number of the last Metadata BLOB object cached locally." This library raises that SHOULD
    /// to a hard rejection when the caller supplies a previous serial number to compare against.
    /// </remarks>
    public static Fido2MetadataError SerialNumberNotIncreasing { get; } = new(
        "serial_number_not_increasing",
        "The Metadata BLOB payload's no serial number is not strictly greater than the previously cached serial number.");

    /// <summary>
    /// The Metadata BLOB payload's <c>nextUpdate</c> date has already passed as of the validation
    /// time.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-payload-blob">FIDO
    /// Metadata Service v3.1, section 3.1.6: Metadata BLOB Payload dictionary</see>: "ISO-8601
    /// formatted date when the next update will be provided at latest." That is a caching/refresh
    /// hint (
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">section
    /// 3.2</see>, item 3, phrased as a SHOULD on WHEN to re-download), not itself a rejection MUST;
    /// this library enforces it as a hard staleness check as a deliberate, stricter-than-specified
    /// posture — a caller presenting a BLOB past its own declared freshness window is presenting
    /// stale data regardless of whether it re-fetched on time.
    /// </remarks>
    public static Fido2MetadataError BlobStale { get; } = new(
        "blob_stale",
        "The Metadata BLOB payload's nextUpdate date has already passed as of the validation time.");

    /// <summary>
    /// The verification request declared <see cref="MetadataBlobSerialNumberPolicy.Required"/>, but
    /// no <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/>/
    /// <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/> pair is wired to
    /// <see cref="MetadataBlobVerification.Build"/> — or the resolve delegate threw rather than
    /// returning a value.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-payload-blob">FIDO
    /// Metadata Service v3.1, section 3.1.6: Metadata BLOB Payload dictionary</see>: "Serial numbers
    /// MUST be consecutive and strictly monotonic." <see cref="MetadataBlobSerialNumberPolicy.Required"/>
    /// makes that defense unskippable: a caller that declares it MUST wire the resolve/persist pair,
    /// or verification fails closed with this error rather than silently proceeding without it.
    /// </remarks>
    public static Fido2MetadataError SerialNumberStoreUnavailable { get; } = new(
        "serial_number_store_unavailable",
        "The request declares Required serial-number tracking, but no resolve/persist delegate pair is wired, or the resolve delegate failed.");

    /// <summary>
    /// The verification request declared <see cref="MetadataBlobRevocationPolicy.Required"/>, but no
    /// <see cref="CheckCertificateRevocationStatusAsyncDelegate"/> is wired to
    /// <see cref="MetadataBlobVerification.Build"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">FIDO
    /// Metadata Service v3.1, section 3.2: Metadata BLOB object processing rules</see>, item 4.iii:
    /// "All certificates in the chain MUST be checked for revocation." <see cref="MetadataBlobRevocationPolicy.Required"/>
    /// makes that check unskippable: a caller that declares it MUST wire a revocation delegate, or
    /// verification fails closed with this error rather than silently chaining without it.
    /// </remarks>
    public static Fido2MetadataError RevocationCheckUnavailable { get; } = new(
        "revocation_check_unavailable",
        "The request declares Required revocation checking, but no revocation delegate is wired.");
}
