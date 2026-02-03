using System;
using System.Linq;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.EventLog;

/// <summary>
/// Represents a digest value with its associated hash algorithm.
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">
/// TCG PC Client Platform Firmware Profile Specification</see>
/// (Section 10.2.2 "TCG_PCR_EVENT2 Structure", TPMT_HA within TPML_DIGEST_VALUES).
/// </para>
/// </remarks>
public sealed class TcgEventDigest: IEquatable<TcgEventDigest>
{
    /// <summary>
    /// Gets the TPM algorithm ID.
    /// </summary>
    public TpmAlgIdConstants Algorithm { get; }

    /// <summary>
    /// Gets the digest bytes.
    /// </summary>
    public byte[] Digest { get; }

    /// <summary>
    /// Gets the human-readable algorithm name.
    /// </summary>
    public string AlgorithmName => Algorithm.GetName();

    /// <summary>
    /// Gets the digest as a hexadecimal string.
    /// </summary>
    public string DigestHex => Convert.ToHexString(Digest);

    /// <summary>
    /// Creates a new event digest.
    /// </summary>
    public TcgEventDigest(TpmAlgIdConstants algorithm, byte[] digest)
    {
        Algorithm = algorithm;
        Digest = digest;
    }

    /// <inheritdoc/>
    public bool Equals(TcgEventDigest? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Algorithm == other.Algorithm
            && Digest.AsSpan().SequenceEqual(other.Digest);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as TcgEventDigest);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Algorithm);

        foreach(byte b in Digest)
        {
            hash.Add(b);
        }

        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two digests are equal.
    /// </summary>
    public static bool operator ==(TcgEventDigest? left, TcgEventDigest? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two digests are not equal.
    /// </summary>
    public static bool operator !=(TcgEventDigest? left, TcgEventDigest? right)
    {
        return !(left == right);
    }
}