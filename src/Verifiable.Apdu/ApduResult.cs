using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu;

/// <summary>
/// Result of an APDU operation: success, card error, or transport error.
/// </summary>
/// <remarks>
/// <para>
/// This is a three-state result type that distinguishes between:
/// </para>
/// <list type="bullet">
///   <item><description><strong>Success</strong> — card responded with data and a success status word.</description></item>
///   <item><description><strong>Card error</strong> — card responded with an error or warning status word.</description></item>
///   <item><description><strong>Transport error</strong> — communication with the card failed (NFC lost, reader disconnected).</description></item>
/// </list>
/// <para>
/// The executor handles <c>61xx</c> (GET RESPONSE chaining) and <c>6Cxx</c> (Le correction)
/// transparently. These intermediate statuses never appear in the result. A successful result
/// always has SW <c>9000</c>.
/// </para>
/// <para>
/// <strong>Card error categories:</strong>
/// </para>
/// <list type="bullet">
///   <item><description><see cref="StatusWord"/> carries the full SW for classification.</description></item>
///   <item><description><see cref="IsWarning"/> — non-fatal card response (<c>62xx</c>, <c>63xx</c>).</description></item>
///   <item><description><see cref="IsRetryCounterWarning"/> — PIN/PUK verification failure with remaining attempts.</description></item>
///   <item><description><see cref="IsSecurityError"/> — security condition not satisfied or authentication blocked.</description></item>
///   <item><description><see cref="IsNotFound"/> — referenced file, application, or data not found.</description></item>
/// </list>
/// </remarks>
/// <typeparam name="T">The type of the success value.</typeparam>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1000:Do not declare static members on generic types",
    Justification = "Intentional factory pattern matching the established convention.")]
public readonly struct ApduResult<T> : IEquatable<ApduResult<T>>
{
    private readonly T? value;
    private readonly StatusWord statusWord;
    private readonly uint transportErrorCode;
    private readonly ResultKind kind;

    private enum ResultKind : byte
    {
        Success,
        CardError,
        TransportError
    }

    private ApduResult(T value, StatusWord statusWord)
    {
        this.value = value;
        this.statusWord = statusWord;
        kind = ResultKind.Success;
        transportErrorCode = 0;
    }

    private ApduResult(StatusWord statusWord)
    {
        value = default;
        this.statusWord = statusWord;
        kind = ResultKind.CardError;
        transportErrorCode = 0;
    }

    private ApduResult(uint transportErrorCode)
    {
        value = default;
        statusWord = default;
        kind = ResultKind.TransportError;
        this.transportErrorCode = transportErrorCode;
    }

    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Value))]
    public bool IsSuccess => kind == ResultKind.Success;

    /// <summary>
    /// Gets a value indicating whether the card returned an error or warning status word.
    /// </summary>
    public bool IsCardError => kind == ResultKind.CardError;

    /// <summary>
    /// Gets a value indicating whether transport to the card failed.
    /// </summary>
    public bool IsTransportError => kind == ResultKind.TransportError;

    /// <summary>
    /// Gets the success value.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessing on a non-success result.</exception>
    public T Value => IsSuccess
        ? value!
        : throw new InvalidOperationException(GetValueAccessErrorMessage());

    /// <summary>
    /// Gets the status word from the card's response.
    /// </summary>
    /// <remarks>
    /// Available on both success and card error results. Not available on transport errors.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Thrown when accessing on a transport error result.</exception>
    public StatusWord StatusWord => !IsTransportError
        ? statusWord
        : throw new InvalidOperationException("Status word is not available for transport errors.");

    /// <summary>
    /// Gets the transport error code.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessing on a non-transport-error result.</exception>
    public uint TransportErrorCode => IsTransportError
        ? transportErrorCode
        : throw new InvalidOperationException("Transport error code is only available for transport errors.");

    /// <summary>
    /// Gets a value indicating whether the card response is a warning (<c>62xx</c> or <c>63xx</c>).
    /// </summary>
    public bool IsWarning => IsCardError && statusWord.IsWarning;

    /// <summary>
    /// Gets a value indicating whether the card response is a retry counter warning (<c>63Cx</c>).
    /// </summary>
    public bool IsRetryCounterWarning => IsCardError && statusWord.IsRetryCounterWarning;

    /// <summary>
    /// Gets the remaining retry count when <see cref="IsRetryCounterWarning"/> is <see langword="true"/>.
    /// </summary>
    public int RemainingRetries => IsRetryCounterWarning ? statusWord.RetryCount : 0;

    /// <summary>
    /// Gets a value indicating whether the error is security-related
    /// (<c>6982</c> security status not satisfied or <c>6983</c> authentication blocked).
    /// </summary>
    public bool IsSecurityError => IsCardError
        && (statusWord.IsSecurityStatusNotSatisfied || statusWord.IsAuthenticationMethodBlocked);

    /// <summary>
    /// Gets a value indicating whether the referenced file, application, or data
    /// was not found (<c>6A82</c> or <c>6A88</c>).
    /// </summary>
    public bool IsNotFound => IsCardError
        && (statusWord.IsFileOrAppNotFound || statusWord.IsReferencedDataNotFound);

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    /// <param name="value">The success value.</param>
    /// <param name="statusWord">The status word (typically <c>9000</c>).</param>
    /// <returns>A success result.</returns>
    public static ApduResult<T> Success(T value, StatusWord statusWord) => new(value, statusWord);

    /// <summary>
    /// Creates a successful result with SW <c>9000</c>.
    /// </summary>
    /// <param name="value">The success value.</param>
    /// <returns>A success result.</returns>
    public static ApduResult<T> Success(T value) => new(value, StatusWord.Success);

    /// <summary>
    /// Creates a card error result.
    /// </summary>
    /// <param name="statusWord">The error or warning status word.</param>
    /// <returns>A card error result.</returns>
    public static ApduResult<T> CardError(StatusWord statusWord) => new(statusWord);

    /// <summary>
    /// Creates a transport error result.
    /// </summary>
    /// <param name="errorCode">The platform-specific error code.</param>
    /// <returns>A transport error result.</returns>
    public static ApduResult<T> TransportError(uint errorCode) => new(errorCode);

    /// <summary>
    /// Attempts to get the success value.
    /// </summary>
    /// <param name="result">The success value, if the operation succeeded.</param>
    /// <returns><see langword="true"/> if the operation succeeded.</returns>
    public bool TryGetValue([MaybeNullWhen(false)] out T result)
    {
        if(IsSuccess)
        {
            result = value!;
            return true;
        }

        result = default;
        return false;
    }

    /// <summary>
    /// Pattern matches on the result with three cases.
    /// </summary>
    /// <typeparam name="TResult">The return type.</typeparam>
    /// <param name="onSuccess">Function to call on success.</param>
    /// <param name="onCardError">Function to call on card error.</param>
    /// <param name="onTransportError">Function to call on transport error.</param>
    /// <returns>The result of the matched function.</returns>
    public TResult Match<TResult>(
        Func<T, StatusWord, TResult> onSuccess,
        Func<StatusWord, TResult> onCardError,
        Func<uint, TResult> onTransportError)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onCardError);
        ArgumentNullException.ThrowIfNull(onTransportError);

        return kind switch
        {
            ResultKind.Success => onSuccess(value!, statusWord),
            ResultKind.CardError => onCardError(statusWord),
            ResultKind.TransportError => onTransportError(transportErrorCode),
            _ => throw new InvalidOperationException("Invalid result kind.")
        };
    }

    /// <summary>
    /// Transforms the success value using the specified function.
    /// </summary>
    /// <typeparam name="TNew">The new value type.</typeparam>
    /// <param name="mapper">The transformation function.</param>
    /// <returns>A new result with the transformed value, or the original error.</returns>
    public ApduResult<TNew> Map<TNew>(Func<T, TNew> mapper)
    {
        ArgumentNullException.ThrowIfNull(mapper);

        return kind switch
        {
            ResultKind.Success => ApduResult<TNew>.Success(mapper(value!), statusWord),
            ResultKind.CardError => ApduResult<TNew>.CardError(statusWord),
            ResultKind.TransportError => ApduResult<TNew>.TransportError(transportErrorCode),
            _ => throw new InvalidOperationException("Invalid result kind.")
        };
    }

    /// <inheritdoc />
    public bool Equals(ApduResult<T> other)
    {
        if(kind != other.kind)
        {
            return false;
        }

        return kind switch
        {
            ResultKind.Success => EqualityComparer<T>.Default.Equals(value, other.value)
                && statusWord == other.statusWord,
            ResultKind.CardError => statusWord == other.statusWord,
            ResultKind.TransportError => transportErrorCode == other.transportErrorCode,
            _ => false
        };
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is ApduResult<T> other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => kind switch
    {
        ResultKind.Success => HashCode.Combine(kind, value, statusWord),
        ResultKind.CardError => HashCode.Combine(kind, statusWord),
        ResultKind.TransportError => HashCode.Combine(kind, transportErrorCode),
        _ => 0
    };

    /// <summary>
    /// Determines whether two results are equal.
    /// </summary>
    public static bool operator ==(ApduResult<T> left, ApduResult<T> right) => left.Equals(right);

    /// <summary>
    /// Determines whether two results are not equal.
    /// </summary>
    public static bool operator !=(ApduResult<T> left, ApduResult<T> right) => !left.Equals(right);

    /// <inheritdoc />
    public override string ToString() => kind switch
    {
        ResultKind.Success => $"Success({value}, SW=0x{statusWord.Value:X4})",
        ResultKind.CardError => $"CardError(SW=0x{statusWord.Value:X4})",
        ResultKind.TransportError => $"TransportError(0x{transportErrorCode:X8})",
        _ => "Invalid"
    };

    private string GetValueAccessErrorMessage() => kind switch
    {
        ResultKind.CardError => $"Cannot access Value on CardError result. SW=0x{statusWord.Value:X4}.",
        ResultKind.TransportError => $"Cannot access Value on TransportError result. Error code: 0x{transportErrorCode:X8}.",
        _ => "Cannot access Value on non-success result."
    };

    private string DebuggerDisplay => kind switch
    {
        ResultKind.Success => $"Success: {value} (SW=0x{statusWord.Value:X4})",
        ResultKind.CardError => $"Card Error: SW=0x{statusWord.Value:X4}",
        ResultKind.TransportError => $"Transport Error: 0x{transportErrorCode:X8}",
        _ => "Invalid"
    };
}
