using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents a refresh service for obtaining updated credentials as defined in the W3C
/// Verifiable Credentials Data Model v2.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// Refresh services provide a mechanism for holders to request updated credentials from
/// the issuer. This is useful when credential information changes, when credentials
/// approach expiration, or when holders need credentials with updated validity periods.
/// </para>
/// <para>
/// The refresh process typically involves the holder presenting the original credential
/// or a reference to it, and the issuer returning a new credential with updated information
/// or an extended validity period.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#refreshing">
/// VC Data Model 2.0 §5.4 Refreshing</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("RefreshService(Id = {Id}, Type = {Type})")]
public class RefreshService: IEquatable<RefreshService>
{
    /// <summary>
    /// The URL of the refresh service endpoint.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The URL that holders can use to request an updated credential. The specific
    /// protocol and parameters depend on the refresh service type.
    /// </para>
    /// </remarks>
    public required string Id { get; set; }

    /// <summary>
    /// The type of refresh service.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Indicates the protocol and mechanism used for refreshing. The type determines
    /// how holders should interact with the service endpoint.
    /// </para>
    /// <para>
    /// Examples include <c>ManualRefreshService2018</c> or protocol-specific types
    /// that define automated refresh mechanisms.
    /// </para>
    /// </remarks>
    public required string Type { get; set; }

    /// <summary>
    /// Additional properties as defined by the refresh service type.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Different refresh service types may define additional properties for
    /// authentication, authorization, or protocol-specific parameters.
    /// </para>
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(RefreshService? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(Id, other.Id, StringComparison.Ordinal)
            && string.Equals(Type, other.Type, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is RefreshService other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Id, StringComparer.Ordinal);
        hash.Add(Type, StringComparer.Ordinal);

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(RefreshService? left, RefreshService? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(RefreshService? left, RefreshService? right) => !(left == right);
}