using System.Collections.Generic;

namespace Verifiable.DidComm;

/// <summary>
/// Reads a protocol <c>body</c> member as an integer, absorbing the Json leaf's number-narrowing ladder — a
/// JSON number is read back as <see cref="int"/>, then <see cref="long"/>, then <see cref="decimal"/> (see
/// <c>JsonElementConversion.NarrowNumber</c>/<c>ManualJsonReader.ReadNumber</c>) — so a numeric body member
/// reads identically whether the wire value arrived as an <see cref="int"/> (a small literal such as
/// DIDComm Message Pickup Protocol 3.0's own <c>8096</c> example), a <see cref="long"/> (a multi-gigabyte
/// <c>total_bytes</c>), or a <see cref="decimal"/> (any JSON number too large for <see cref="long"/>).
/// </summary>
/// <remarks>
/// Shared by <see cref="Verifiable.DidComm.MessagePickup.MessagePickupExtensions"/> and
/// <see cref="Verifiable.DidComm.CoordinateMediation.CoordinateMediationExtensions"/> — the two protocols
/// whose bodies carry numbers — so the narrowing ladder exists exactly once rather than as a per-protocol
/// copy of the same concept.
/// </remarks>
internal static class DidCommBodyNumbers
{
    /// <summary>
    /// Narrows <paramref name="raw"/> to a <see cref="long"/> when it is an <see cref="int"/>, a
    /// <see cref="long"/>, or a whole-valued <see cref="decimal"/> within the <see cref="long"/> range.
    /// Fails for a fractional decimal, an out-of-range decimal, or any non-numeric value.
    /// </summary>
    /// <param name="raw">The raw body value to narrow.</param>
    /// <param name="value">The narrowed value when narrowing succeeds; otherwise <c>0</c>.</param>
    /// <returns><see langword="true"/> when <paramref name="raw"/> narrows to an integral <see cref="long"/>.</returns>
    internal static bool TryNarrowInteger(object? raw, out long value)
    {
        (bool isNarrowed, long narrowed) = raw switch
        {
            int i => (true, (long)i),
            long l => (true, l),
            decimal d when decimal.Truncate(d) == d && d >= long.MinValue && d <= long.MaxValue => (true, (long)d),
            _ => (false, 0L)
        };

        value = narrowed;

        return isNarrowed;
    }


    /// <summary>
    /// Reads a REQUIRED numeric body member through <see cref="TryNarrowInteger"/>. Fails when
    /// <paramref name="member"/> is absent, <see langword="null"/>, non-numeric, or numeric-but-not-integral.
    /// </summary>
    /// <param name="body">The body dictionary to read from.</param>
    /// <param name="member">The member name to read.</param>
    /// <param name="value">The narrowed value when the read succeeds; otherwise <c>0</c>.</param>
    /// <returns><see langword="true"/> when <paramref name="member"/> is present and integral.</returns>
    internal static bool TryReadRequiredInteger(IDictionary<string, object> body, string member, out long value)
    {
        value = 0;

        return body.TryGetValue(member, out object? raw) && TryNarrowInteger(raw, out value);
    }


    /// <summary>
    /// Reads an OPTIONAL numeric body member through <see cref="TryNarrowInteger"/>. Absence or a JSON-null
    /// value yields <see langword="null"/> with success; a present value that is not integral is a
    /// malformation and fails closed.
    /// </summary>
    /// <param name="body">The body dictionary to read from.</param>
    /// <param name="member">The member name to read.</param>
    /// <param name="value">
    /// The narrowed value when present; <see langword="null"/> when absent. Meaningful only when this method
    /// returns <see langword="true"/>.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="member"/> is absent, JSON-null, or integral.</returns>
    internal static bool TryReadOptionalInteger(IDictionary<string, object> body, string member, out long? value)
    {
        value = null;
        if(!body.TryGetValue(member, out object? raw) || raw is null)
        {
            return true;
        }

        if(!TryNarrowInteger(raw, out long parsed))
        {
            return false;
        }

        value = parsed;

        return true;
    }
}
