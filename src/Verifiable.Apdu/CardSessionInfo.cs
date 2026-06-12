using System;
using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// Information about the card that produced a recording.
/// </summary>
/// <remarks>
/// <para>
/// This record captures metadata about a card session for diagnostic and replay purposes.
/// It is stored alongside recorded exchanges in an <see cref="ApduRecording"/>.
/// </para>
/// <para>
/// The <see cref="Atr"/> (Answer to Reset) is the card's identity sequence transmitted
/// during the activation phase. It identifies the card type, supported protocols, and
/// historical bytes that may contain vendor or application information.
/// </para>
/// </remarks>
/// <param name="Atr">
/// The Answer to Reset bytes, or <see langword="null"/> if not available
/// (e.g., contactless NFC where ATR is synthesized from ATS).
/// </param>
/// <param name="SelectedAid">
/// The AID that was selected when recording started, or <see langword="null"/>
/// if no application was selected.
/// </param>
/// <param name="Platform">Platform on which the recording was made.</param>
/// <param name="RecordedAt">Timestamp when recording started.</param>
/// <param name="Label">
/// Optional human-readable label for the session, e.g., "YubiKey 5 NFC provisioning".
/// </param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record CardSessionInfo(
    byte[]? Atr,
    byte[]? SelectedAid,
    ApduPlatform Platform,
    DateTimeOffset RecordedAt,
    string? Label = null)
{
    /// <summary>
    /// Creates a new session info with the current time from the specified provider.
    /// </summary>
    /// <param name="atr">The card ATR bytes.</param>
    /// <param name="selectedAid">The currently selected AID.</param>
    /// <param name="platform">The platform.</param>
    /// <param name="timeProvider">Time provider for obtaining the current timestamp.</param>
    /// <param name="label">Optional session label.</param>
    /// <returns>A new session info instance.</returns>
    public static CardSessionInfo Create(
        byte[]? atr,
        byte[]? selectedAid,
        ApduPlatform platform,
        TimeProvider timeProvider,
        string? label = null)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        return new CardSessionInfo(atr, selectedAid, platform, timeProvider.GetUtcNow(), label);
    }

    private string DebuggerDisplay
    {
        get
        {
            string atrText = Atr is { Length: > 0 }
                ? $"ATR={Convert.ToHexStringLower(Atr)}"
                : "no ATR";
            string labelText = Label is not null ? $", {Label}" : string.Empty;

            return $"CardSessionInfo({Platform}, {atrText}{labelText})";
        }
    }
}
