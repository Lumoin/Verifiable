namespace Verifiable.Cryptography;

/// <summary>
/// The application-wired seam that lets a verifier detect reuse of committed values. When supplied, the
/// verifier computes a commitment for each value (e.g. a disclosure <see cref="Salt"/>) and runs
/// <see cref="CommitmentReuseDetection"/> against the application's store; when omitted, reuse detection
/// is off (the opt-in posture of the DPoP-JTI replay seam).
/// </summary>
/// <remarks>
/// <para>
/// The bundle carries the commitment hash (so the verifier never persists raw value bytes — see
/// <see cref="Salt.ComputeCommitment"/>) plus the application's store lookup/record delegates. The hash
/// is supplied rather than hardcoded so it still flows through the application's provider rather than a
/// direct OS-CSPRNG/BCL call. It is general and context-neutral: no salt, OID4VP, or protocol types, so
/// any verification path — SD-JWT, SD-CWT, a peer wallet — can wire the same seam.
/// </para>
/// </remarks>
/// <param name="HashFunction">The hash applied to a value to form its commitment, e.g. <c>SHA256.HashData</c>.</param>
/// <param name="HashOutputByteLength">The hash output length in bytes (32 for SHA-256).</param>
/// <param name="HashTag">The tag identifying the hash algorithm, carried on each commitment.</param>
/// <param name="IsSeen">The application store lookup — whether a commitment was seen before.</param>
/// <param name="Record">The application store record — marks a commitment as seen.</param>
public sealed record CommitmentReuseDetectionSeam(
    HashFunctionDelegate HashFunction,
    int HashOutputByteLength,
    Tag HashTag,
    IsCommitmentSeenDelegate IsSeen,
    RecordCommitmentDelegate Record);
