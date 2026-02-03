using System;
using System.Collections.Generic;
using System.Linq;

namespace Verifiable.Tpm.EventLog;

/// <summary>
/// Represents a single event in the TCG event log.
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">
/// TCG PC Client Platform Firmware Profile Specification</see>
/// (Section 10.2.1 "TCG_PCClientPCREvent Structure", Table 8 for legacy format;
/// Section 10.2.2 "TCG_PCR_EVENT2 Structure" for crypto-agile format).
/// </para>
/// </remarks>
public sealed class TcgEvent: IEquatable<TcgEvent>
{
    /// <summary>
    /// Gets the index of the event in the log (0-based).
    /// </summary>
    public int Index { get; }

    /// <summary>
    /// Gets the PCR index that was extended by this event.
    /// </summary>
    public int PcrIndex { get; }

    /// <summary>
    /// Gets the event type code.
    /// </summary>
    public uint EventType { get; }

    /// <summary>
    /// Gets the human-readable event type name.
    /// </summary>
    public string EventTypeName => TcgEventType.GetName(EventType);

    /// <summary>
    /// Gets the digests associated with this event (one per active PCR bank).
    /// </summary>
    public IReadOnlyList<TcgEventDigest> Digests { get; }

    /// <summary>
    /// Gets the raw event data.
    /// </summary>
    public byte[] EventData { get; }

    /// <summary>
    /// Gets a human-readable interpretation of the event data, if available.
    /// </summary>
    public string? EventDataDescription { get; }

    /// <summary>
    /// Creates a new TCG event.
    /// </summary>
    public TcgEvent(
        int index,
        int pcrIndex,
        uint eventType,
        IReadOnlyList<TcgEventDigest> digests,
        byte[] eventData,
        string? eventDataDescription = null)
    {
        Index = index;
        PcrIndex = pcrIndex;
        EventType = eventType;
        Digests = digests;
        EventData = eventData;
        EventDataDescription = eventDataDescription;
    }

    /// <inheritdoc/>
    public bool Equals(TcgEvent? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Index == other.Index
            && PcrIndex == other.PcrIndex
            && EventType == other.EventType
            && EventData.AsSpan().SequenceEqual(other.EventData)
            && Digests.SequenceEqual(other.Digests);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as TcgEvent);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Index);
        hash.Add(PcrIndex);
        hash.Add(EventType);

        foreach(byte b in EventData)
        {
            hash.Add(b);
        }

        foreach(var digest in Digests)
        {
            hash.Add(digest);
        }

        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two events are equal.
    /// </summary>
    public static bool operator ==(TcgEvent? left, TcgEvent? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two events are not equal.
    /// </summary>
    public static bool operator !=(TcgEvent? left, TcgEvent? right)
    {
        return !(left == right);
    }
}