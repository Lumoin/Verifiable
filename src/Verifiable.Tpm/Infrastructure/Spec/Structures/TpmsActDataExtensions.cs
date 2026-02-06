using Verifiable.Tpm.Infrastructure.Spec.Attributes;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Extension methods for <see cref="TpmsActData"/>.
/// </summary>
/// <remarks>
/// Provides interpretation methods for ACT (Authenticated Countdown Timer) data.
/// </remarks>
public static class TpmsActDataExtensions
{
    /// <summary>
    /// Gets a human-readable description of the ACT data.
    /// </summary>
    /// <param name="actData">The ACT data to describe.</param>
    /// <returns>A human-readable description.</returns>
    public static string GetDescription(this TpmsActData actData)
    {
        string handleName = TpmValueConversions.GetHandleDescription(actData.Handle);
        string timeoutStr = actData.GetTimeoutDescription();
        string stateStr = actData.GetStateDescription();

        return $"{handleName}: {timeoutStr}, {stateStr}";
    }

    /// <summary>
    /// Gets a description of the timeout value.
    /// </summary>
    /// <param name="actData">The ACT data.</param>
    /// <returns>A timeout description.</returns>
    public static string GetTimeoutDescription(this TpmsActData actData)
    {
        if(actData.Timeout == 0)
        {
            return "expired";
        }

        if(actData.Timeout < 60)
        {
            return $"{actData.Timeout} seconds remaining";
        }

        if(actData.Timeout < 3600)
        {
            uint minutes = actData.Timeout / 60;
            uint seconds = actData.Timeout % 60;
            return seconds > 0
                ? $"{minutes}m {seconds}s remaining"
                : $"{minutes} minutes remaining";
        }

        uint hours = actData.Timeout / 3600;
        uint remainingMinutes = (actData.Timeout % 3600) / 60;
        return remainingMinutes > 0
            ? $"{hours}h {remainingMinutes}m remaining"
            : $"{hours} hours remaining";
    }
    
    /// <summary>
    /// Gets a description of the ACT state.
    /// </summary>
    /// <param name="actData">The ACT data.</param>
    /// <returns>A state description.</returns>
    public static string GetStateDescription(this TpmsActData actData)
    {
        bool signaled = actData.Attributes.HasFlag(TpmaAct.SIGNALED);
        bool preserveSignaled = actData.Attributes.HasFlag(TpmaAct.PRESERVED_SIGNALED);

        return (signaled, preserveSignaled) switch
        {
            (true, true) => "signaled (preserved)",
            (true, false) => "signaled",
            (false, true) => "idle (preserve-signaled set)",
            (false, false) => "idle"
        };
    }

    /// <summary>
    /// Determines if the ACT has expired.
    /// </summary>
    /// <param name="actData">The ACT data.</param>
    /// <returns><c>true</c> if the timeout is zero; otherwise, <c>false</c>.</returns>
    public static bool IsExpired(this TpmsActData actData)
    {
        return actData.Timeout == 0;
    }

    /// <summary>
    /// Determines if the ACT is in the signaled state.
    /// </summary>
    /// <param name="actData">The ACT data.</param>
    /// <returns><c>true</c> if signaled; otherwise, <c>false</c>.</returns>
    public static bool IsSignaled(this TpmsActData actData)
    {
        return actData.Attributes.HasFlag(TpmaAct.SIGNALED);
    }

    /// <summary>
    /// Gets a friendly name for the ACT handle.
    /// </summary>
    /// <param name="actData">The ACT data.</param>
    /// <returns>A friendly name for the handle.</returns>
    public static string GetHandleName(this TpmsActData actData)
    {
        return TpmValueConversions.GetHandleDescription(actData.Handle);
    }
}