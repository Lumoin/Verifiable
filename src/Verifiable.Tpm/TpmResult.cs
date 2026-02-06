using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm;

/// <summary>
/// Result of a TPM operation: success, TPM error, or transport error.
/// </summary>
/// <remarks>
/// <para>
/// This is a three-state result type that distinguishes between:
/// </para>
/// <list type="bullet">
///   <item><description><b>Success</b> - operation completed, value available.</description></item>
///   <item><description><b>TPM error</b> - TPM returned an error response code.</description></item>
///   <item><description><b>Transport error</b> - communication with TPM failed (TBS error, I/O error).</description></item>
/// </list>
/// <para>
/// <b>Output handles:</b>
/// </para>
/// <para>
/// Some TPM commands return handles in the response (e.g., CreatePrimary returns an
/// object handle, StartAuthSession returns a session handle). These are available via
/// <see cref="OutHandles"/> on successful results.
/// </para>
/// <para>
/// <b>TPM error categories</b> (only valid when <see cref="IsTpmError"/> is true):
/// </para>
/// <list type="bullet">
///   <item><description><see cref="IsRetryable"/> - transient errors that may succeed on retry.</description></item>
///   <item><description><see cref="RequiresReboot"/> - TPM needs reinitialization.</description></item>
///   <item><description><see cref="IsRateLimited"/> - NV memory wear protection active.</description></item>
///   <item><description><see cref="IsInLockout"/> - dictionary attack protection active.</description></item>
/// </list>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <code>
/// TpmResult&lt;CreatePrimaryResponse&gt; result = executor.Execute&lt;CreatePrimaryResponse&gt;(...);
///
/// if(result.IsSuccess)
/// {
///     uint objectHandle = result.OutHandles[0];
///     CreatePrimaryResponse response = result.Value;
///     //Use objectHandle and response...
/// }
/// </code>
/// </remarks>
/// <typeparam name="T">The type of the success value.</typeparam>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1000:Do not declare static members on generic types", Justification = "This design is intentional to provide type-specific static members.")]
public readonly struct TpmResult<T>: IEquatable<TpmResult<T>>
{
    private readonly T? value;
    private readonly TpmRcConstants responseCode;
    private readonly uint transportErrorCode;
    private readonly ResultKind kind;

    private enum ResultKind: byte
    {
        Success,
        TpmError,
        TransportError
    }

    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Value))]
    public bool IsSuccess => kind == ResultKind.Success;

    /// <summary>
    /// Gets a value indicating whether the TPM returned an error response.
    /// </summary>
    public bool IsTpmError => kind == ResultKind.TpmError;

    /// <summary>
    /// Gets a value indicating whether transport to the TPM failed.
    /// </summary>
    /// <remarks>
    /// Transport errors occur when communication with the TPM fails before
    /// receiving a valid response. This includes TBS errors on Windows and
    /// I/O errors on Linux.
    /// </remarks>
    public bool IsTransportError => kind == ResultKind.TransportError;

    /// <summary>
    /// Gets the success value.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessing Value on a non-success result.</exception>
    public T Value => IsSuccess
        ? value!
        : throw new InvalidOperationException(GetValueAccessErrorMessage());

    /// <summary>
    /// Gets the TPM response code.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessing ResponseCode on a non-TPM-error result.</exception>
    public TpmRcConstants ResponseCode => IsTpmError
        ? responseCode
        : throw new InvalidOperationException("ResponseCode is only available for TPM errors.");

    /// <summary>
    /// Gets the transport error code.
    /// </summary>
    /// <remarks>
    /// On Windows, this is a <see cref="TbsResult"/> value.
    /// On Linux, this is an errno value.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Thrown when accessing TransportErrorCode on a non-transport-error result.</exception>
    public uint TransportErrorCode => IsTransportError
        ? transportErrorCode
        : throw new InvalidOperationException("TransportErrorCode is only available for transport errors.");

    /// <summary>
    /// Gets a value indicating whether the error is transient and may succeed on retry.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// Includes TPM_RC_RETRY and TPM_RC_YIELDED.
    /// </remarks>
    public bool IsRetryable => IsTpmError && responseCode is TpmRcConstants.TPM_RC_RETRY or TpmRcConstants.TPM_RC_YIELDED;

    /// <summary>
    /// Gets a value indicating whether the TPM requires reboot/reinitialization.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// </remarks>
    public bool RequiresReboot => IsTpmError && responseCode == TpmRcConstants.TPM_RC_REBOOT;

    /// <summary>
    /// Gets a value indicating whether NV memory rate limiting is active.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// The TPM is protecting NV memory from wear. Wait before retrying NV operations.
    /// </remarks>
    public bool IsRateLimited => IsTpmError && responseCode == TpmRcConstants.TPM_RC_NV_RATE;

    /// <summary>
    /// Gets a value indicating whether dictionary attack lockout is active.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// Authorization attempts are blocked. Use TPM2_DictionaryAttackLockReset
    /// or wait for the lockout period to expire.
    /// </remarks>
    public bool IsInLockout => IsTpmError && responseCode == TpmRcConstants.TPM_RC_LOCKOUT;

    /// <summary>
    /// Gets a value indicating whether the TPM is performing self-tests.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// </remarks>
    public bool IsTesting => IsTpmError && responseCode == TpmRcConstants.TPM_RC_TESTING;

    /// <summary>
    /// Gets a value indicating whether the command was canceled.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// </remarks>
    public bool WasCanceled => IsTpmError && responseCode == TpmRcConstants.TPM_RC_CANCELED;

    /// <summary>
    /// Gets a value indicating whether the response code is a warning rather than an error.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// Warnings indicate that the TPM is busy or that resources need adjustment,
    /// but the command was not necessarily invalid.
    /// </remarks>
    public bool IsWarning => IsTpmError && responseCode.IsWarning();

    /// <summary>
    /// Gets the parameter number if this is a parameter-related error.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// Returns the 1-based parameter number (1-15), or 0 if not a parameter error.
    /// </remarks>
    public int ParameterNumber => IsTpmError ? responseCode.GetParameterNumber() : 0;

    /// <summary>
    /// Gets the handle number if this is a handle-related error.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// Returns the 1-based handle number (1-7), or 0 if not a handle error.
    /// </remarks>
    public int HandleNumber => IsTpmError ? responseCode.GetHandleNumber() : 0;

    /// <summary>
    /// Gets the session number if this is a session-related error.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// Returns the 1-based session number (1-7), or 0 if not a session error.
    /// </remarks>
    public int SessionNumber => IsTpmError ? responseCode.GetSessionNumber() : 0;

    /// <summary>
    /// Gets the base error code without parameter, handle, or session modifiers.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsTpmError"/> is true.
    /// Useful for comparing against known <see cref="TpmRcConstants"/> values when
    /// the error includes position modifiers.
    /// </remarks>
    public TpmRcConstants BaseError => IsTpmError ? responseCode.GetBaseError() : default;

    private TpmResult(T? value, TpmRcConstants responseCode, uint transportErrorCode, ResultKind kind)
    {
        this.value = value;
        this.responseCode = responseCode;
        this.transportErrorCode = transportErrorCode;
        this.kind = kind;
    }

    /// <summary>
    /// Creates a successful result with the specified value.
    /// </summary>
    /// <param name="value">The success value.</param>
    /// <returns>A successful result.</returns>    
    public static TpmResult<T> Success(T value) => new(value, default, 0, ResultKind.Success);

    /// <summary>
    /// Creates a TPM error result with the specified response code.
    /// </summary>
    /// <param name="responseCode">The TPM response code indicating the error.</param>
    /// <returns>A TPM error result.</returns>
    public static TpmResult<T> TpmError(TpmRcConstants responseCode) => new(default, responseCode, 0, ResultKind.TpmError);

    /// <summary>
    /// Creates a transport error result with the specified error code.
    /// </summary>
    /// <param name="errorCode">The platform-specific transport error code.</param>
    /// <returns>A transport error result.</returns>
    /// <remarks>
    /// On Windows, pass the <see cref="TbsResult"/> value cast to uint.
    /// On Linux, pass the errno value.
    /// </remarks>
    public static TpmResult<T> TransportError(uint errorCode) => new(default, default, errorCode, ResultKind.TransportError);

    /// <summary>
    /// Creates a transport error result from a TBS result.
    /// </summary>
    /// <param name="tbsResult">The TBS result code.</param>
    /// <returns>A transport error result.</returns>
    public static TpmResult<T> TransportError(TbsResult tbsResult) => TransportError((uint)tbsResult);

    /// <summary>
    /// Gets the value if successful, or the specified default value otherwise.
    /// </summary>
    /// <param name="defaultValue">The value to return if the result is not successful.</param>
    /// <returns>The success value or the default.</returns>
    public T GetValueOrDefault(T defaultValue) => IsSuccess ? value! : defaultValue;

    /// <summary>
    /// Gets the value if successful, or the default value for the type otherwise.
    /// </summary>
    /// <returns>The success value or default.</returns>
    public T? GetValueOrDefault() => IsSuccess ? value : default;

    /// <summary>
    /// Attempts to get the value.
    /// </summary>
    /// <param name="value">The value if successful.</param>
    /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
    public bool TryGetValue([MaybeNullWhen(false)] out T value)
    {
        if(IsSuccess)
        {
            value = this.value!;
            return true;
        }

        value = default;
        return false;
    }

    /// <summary>
    /// Pattern matches on the result with three cases.
    /// </summary>
    /// <typeparam name="TResult">The return type.</typeparam>
    /// <param name="onSuccess">Function to call on success.</param>
    /// <param name="onTpmError">Function to call on TPM error.</param>
    /// <param name="onTransportError">Function to call on transport error.</param>
    /// <returns>The result of the matched function.</returns>
    public TResult Match<TResult>(
        Func<T, TResult> onSuccess,
        Func<TpmRcConstants, TResult> onTpmError,
        Func<uint, TResult> onTransportError)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onTpmError);
        ArgumentNullException.ThrowIfNull(onTransportError);

        return kind switch
        {
            ResultKind.Success => onSuccess(value!),
            ResultKind.TpmError => onTpmError(responseCode),
            ResultKind.TransportError => onTransportError(transportErrorCode),
            _ => throw new InvalidOperationException("Invalid result kind.")
        };
    }

    /// <summary>
    /// Executes an action based on the result state.
    /// </summary>
    /// <param name="onSuccess">Action to execute on success.</param>
    /// <param name="onTpmError">Action to execute on TPM error.</param>
    /// <param name="onTransportError">Action to execute on transport error.</param>
    public void Switch(
        Action<T> onSuccess,
        Action<TpmRcConstants> onTpmError,
        Action<uint> onTransportError)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onTpmError);
        ArgumentNullException.ThrowIfNull(onTransportError);

        switch(kind)
        {
            case ResultKind.Success:
                onSuccess(value!);
                break;
            case ResultKind.TpmError:
                onTpmError(responseCode);
                break;
            case ResultKind.TransportError:
                onTransportError(transportErrorCode);
                break;
        }
    }

    /// <summary>
    /// Transforms the success value using the specified function.
    /// </summary>
    /// <typeparam name="TNew">The new value type.</typeparam>
    /// <param name="mapper">The transformation function.</param>
    /// <returns>A new result with the transformed value, or the original error.</returns>
    public TpmResult<TNew> Map<TNew>(Func<T, TNew> mapper)
    {
        ArgumentNullException.ThrowIfNull(mapper);

        return kind switch
        {
            ResultKind.Success => TpmResult<TNew>.Success(mapper(value!)),
            ResultKind.TpmError => TpmResult<TNew>.TpmError(responseCode),
            ResultKind.TransportError => TpmResult<TNew>.TransportError(transportErrorCode),
            _ => throw new InvalidOperationException("Invalid result kind.")
        };
    }

    /// <summary>
    /// Chains another TPM operation that returns a result.
    /// </summary>
    /// <typeparam name="TNew">The new value type.</typeparam>
    /// <param name="binder">The function that returns another TpmResult.</param>
    /// <returns>The result of the chained operation, or the original error.</returns>
    public TpmResult<TNew> Bind<TNew>(Func<T, TpmResult<TNew>> binder)
    {
        ArgumentNullException.ThrowIfNull(binder);

        return kind switch
        {
            ResultKind.Success => binder(value!),
            ResultKind.TpmError => TpmResult<TNew>.TpmError(responseCode),
            ResultKind.TransportError => TpmResult<TNew>.TransportError(transportErrorCode),
            _ => throw new InvalidOperationException("Invalid result kind.")
        };
    }

    /// <inheritdoc/>
    public bool Equals(TpmResult<T> other)
    {
        if(kind != other.kind)
        {
            return false;
        }

        return kind switch
        {
            ResultKind.Success => EqualityComparer<T>.Default.Equals(value, other.value),
            ResultKind.TpmError => responseCode == other.responseCode,
            ResultKind.TransportError => transportErrorCode == other.transportErrorCode,
            _ => false
        };
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is TpmResult<T> other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => kind switch
    {
        ResultKind.Success => HashCode.Combine(kind, value),
        ResultKind.TpmError => HashCode.Combine(kind, responseCode),
        ResultKind.TransportError => HashCode.Combine(kind, transportErrorCode),
        _ => 0
    };

    /// <summary>
    /// Determines whether two results are equal.
    /// </summary>
    public static bool operator ==(TpmResult<T> left, TpmResult<T> right) => left.Equals(right);

    /// <summary>
    /// Determines whether two results are not equal.
    /// </summary>
    public static bool operator !=(TpmResult<T> left, TpmResult<T> right) => !left.Equals(right);

    /// <summary>
    /// Implicitly converts a value to a successful result.
    /// </summary>
    /// <param name="value">The value.</param>
    public static implicit operator TpmResult<T>(T value) => Success(value);

    /// <inheritdoc/>
    public override string ToString() => kind switch
    {
        ResultKind.Success => $"Success({value})",
        ResultKind.TpmError => $"TpmError({responseCode.GetDescription()})",
        ResultKind.TransportError => $"TransportError(0x{transportErrorCode:X8})",
        _ => "Invalid"
    };

    private string GetValueAccessErrorMessage() => kind switch
    {
        ResultKind.TpmError => $"Cannot access Value on TpmError result. Response code: {responseCode.GetDescription()}",
        ResultKind.TransportError => $"Cannot access Value on TransportError result. Error code: 0x{transportErrorCode:X8}",
        _ => "Cannot access Value on non-success result."
    };

    private string DebuggerDisplay
    {
        get
        {
            if(IsSuccess)
            {
                return $"Success: {value}";
            }

            if(IsTransportError)
            {
                return $"Transport Error: 0x{transportErrorCode:X8}";
            }

            //TPM error.
            string baseInfo = $"TPM Error: {responseCode.GetDescription()}";

            //Add classification hints for quick debugging.
            var hints = new List<string>();

            if(IsWarning)
            {
                hints.Add("Warning");
            }

            if(IsRetryable)
            {
                hints.Add("Retryable");
            }

            if(IsInLockout)
            {
                hints.Add("Lockout");
            }

            if(IsRateLimited)
            {
                hints.Add("RateLimited");
            }

            if(RequiresReboot)
            {
                hints.Add("NeedsReboot");
            }

            if(hints.Count > 0)
            {
                return $"{baseInfo} [{string.Join(", ", hints)}]";
            }

            return baseInfo;
        }
    }
}