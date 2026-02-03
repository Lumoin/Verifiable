using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.EventLog;

/// <summary>
/// Represents a parsed TCG event log.
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">
/// TCG PC Client Platform Firmware Profile Specification</see>
/// (Section 10 "Event Logging").
/// </para>
/// <para>
/// The first event contains a <c>TCG_EfiSpecIdEvent</c> structure that identifies
/// the log format version and lists the digest algorithms used (Section 10.2.1.1).
/// </para>
/// </remarks>
public sealed class TcgEventLog: IEquatable<TcgEventLog>
{
    /// <summary>
    /// Gets the specification version string (e.g., "Spec ID Event03").
    /// </summary>
    public string SpecVersion { get; }

    /// <summary>
    /// Gets the platform class (0 for client, 1 for server).
    /// </summary>
    public uint PlatformClass { get; }

    /// <summary>
    /// Gets the specification version numbers.
    /// </summary>
    public (byte Major, byte Minor, byte Errata) SpecVersionNumber { get; }

    /// <summary>
    /// Gets the UINTN size (4 for 32-bit, 8 for 64-bit).
    /// </summary>
    public byte UintnSize { get; }

    /// <summary>
    /// Gets the digest sizes for each algorithm in the log.
    /// </summary>
    public IReadOnlyDictionary<TpmAlgIdConstants, ushort> DigestSizes { get; }

    /// <summary>
    /// Gets all events in the log.
    /// </summary>
    public IReadOnlyList<TcgEvent> Events { get; }

    /// <summary>
    /// Gets whether the log appears to be truncated.
    /// </summary>
    public bool IsTruncated { get; }

    /// <summary>
    /// Creates a new TCG event log.
    /// </summary>
    public TcgEventLog(
        string specVersion,
        uint platformClass,
        (byte Major, byte Minor, byte Errata) specVersionNumber,
        byte uintnSize,
        IReadOnlyDictionary<TpmAlgIdConstants, ushort> digestSizes,
        IReadOnlyList<TcgEvent> events,
        bool isTruncated = false)
    {
        SpecVersion = specVersion;
        PlatformClass = platformClass;
        SpecVersionNumber = specVersionNumber;
        UintnSize = uintnSize;
        DigestSizes = digestSizes;
        Events = events;
        IsTruncated = isTruncated;
    }

    /// <summary>
    /// Gets all events for a specific PCR.
    /// </summary>
    public IEnumerable<TcgEvent> GetEventsForPcr(int pcrIndex)
    {
        foreach(var evt in Events)
        {
            if(evt.PcrIndex == pcrIndex)
            {
                yield return evt;
            }
        }
    }

    /// <summary>
    /// Gets all events of a specific type.
    /// </summary>
    public IEnumerable<TcgEvent> GetEventsByType(uint eventType)
    {
        foreach(var evt in Events)
        {
            if(evt.EventType == eventType)
            {
                yield return evt;
            }
        }
    }

    /// <inheritdoc/>
    public bool Equals(TcgEventLog? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return SpecVersion == other.SpecVersion
            && PlatformClass == other.PlatformClass
            && SpecVersionNumber == other.SpecVersionNumber
            && UintnSize == other.UintnSize
            && IsTruncated == other.IsTruncated
            && DigestSizes.Count == other.DigestSizes.Count
            && DigestSizes.All(kvp => other.DigestSizes.TryGetValue(kvp.Key, out var size) && size == kvp.Value)
            && Events.SequenceEqual(other.Events);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as TcgEventLog);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(SpecVersion);
        hash.Add(PlatformClass);
        hash.Add(SpecVersionNumber);
        hash.Add(UintnSize);
        hash.Add(IsTruncated);

        foreach(var kvp in DigestSizes)
        {
            hash.Add(kvp.Key);
            hash.Add(kvp.Value);
        }

        foreach(var evt in Events)
        {
            hash.Add(evt);
        }

        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two event logs are equal.
    /// </summary>
    public static bool operator ==(TcgEventLog? left, TcgEventLog? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two event logs are not equal.
    /// </summary>
    public static bool operator !=(TcgEventLog? left, TcgEventLog? right)
    {
        return !(left == right);
    }
}