using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core;

/// <summary>
/// Factory methods for creating <see cref="Result{TValue, TError}"/> instances.
/// </summary>
public static class Result
{
    /// <summary>
    /// Creates a successful result with the specified value.
    /// </summary>
    public static Result<TValue, TError> Success<TValue, TError>(TValue value) =>
        Result<TValue, TError>.Success(value);

    /// <summary>
    /// Creates a failed result with the specified error.
    /// </summary>
    public static Result<TValue, TError> Failure<TValue, TError>(TError error) =>
        Result<TValue, TError>.Failure(error);    
}

/// <summary>
/// Represents the result of an operation that can succeed with a value or fail with an error.
/// </summary>
/// <typeparam name="TValue">The type of the success value.</typeparam>
/// <typeparam name="TError">The type of the error.</typeparam>
public readonly struct Result<TValue, TError>: IEquatable<Result<TValue, TError>>
{
    /// <summary>
    /// Assigned value if the operation succeeded.
    /// </summary>
    private readonly TValue? _value;

    /// <summary>
    /// Assigned value if the operation failed.
    /// </summary>
    private readonly TError? _error;


    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Value))]
    [MemberNotNullWhen(false, nameof(Error))]
    public bool IsSuccess { get; }


    /// <summary>
    /// Gets the success value. Only valid when <see cref="IsSuccess"/> is true.
    /// </summary>
    public TValue? Value => _value;


    /// <summary>
    /// Gets the error. Only valid when <see cref="IsSuccess"/> is false.
    /// </summary>
    public TError? Error => _error;


    /// <summary>
    /// A private constructor to initialize the result.
    /// </summary>
    /// <param name="isSuccess">If true, the operation succeeded.</param>
    /// <param name="value">The success value.</param>
    /// <param name="error">The error value.</param>
    private Result(bool isSuccess, TValue? value, TError? error)
    {
        IsSuccess = isSuccess;
        _value = value;
        _error = error;
    }


    /// <summary>
    /// Creates a successful result with the specified value.
    /// </summary>
    public static Result<TValue, TError> Success(TValue value) => new(true, value, default);

    
    /// <summary>
    /// Creates a failed result with the specified error.
    /// </summary>
    public static Result<TValue, TError> Failure(TError error) => new(false, default, error);


    /// <summary>
    /// Executes one of the provided functions based on whether the result is success or failure.
    /// </summary>
    public TResult Match<TResult>(Func<TValue, TResult> onSuccess, Func<TError, TResult> onFailure)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onFailure);

        return IsSuccess ? onSuccess(_value!) : onFailure(_error!);
    }


    /// <summary>
    /// Transforms the success value using the specified function.
    /// </summary>
    public Result<TNewValue, TError> Map<TNewValue>(Func<TValue, TNewValue> map)
    {
        ArgumentNullException.ThrowIfNull(map);

        return IsSuccess
            ? Result<TNewValue, TError>.Success(map(_value!))
            : Result<TNewValue, TError>.Failure(_error!);
    }


    /// <summary>
    /// Chains another operation that returns a Result.
    /// </summary>
    public Result<TNewValue, TError> Bind<TNewValue>(Func<TValue, Result<TNewValue, TError>> bind)
    {
        ArgumentNullException.ThrowIfNull(bind);

        return IsSuccess ? bind(_value!) : Result<TNewValue, TError>.Failure(_error!);
    }


    /// <inheritdoc />
    public bool Equals(Result<TValue, TError> other) =>
        IsSuccess == other.IsSuccess &&
        EqualityComparer<TValue?>.Default.Equals(_value, other._value) &&
        EqualityComparer<TError?>.Default.Equals(_error, other._error);


    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Result<TValue, TError> other && Equals(other);


    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(IsSuccess, _value, _error);


    public static bool operator ==(Result<TValue, TError> left, Result<TValue, TError> right) => left.Equals(right);


    public static bool operator !=(Result<TValue, TError> left, Result<TValue, TError> right) => !left.Equals(right);


    /// <summary>
    /// Implicitly converts a value to a successful Result.
    /// </summary>
    public static implicit operator Result<TValue, TError>(TValue value) => Success(value);
}