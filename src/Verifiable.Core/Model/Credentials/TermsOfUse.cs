using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents terms of use for a credential as defined in the W3C Verifiable
/// Credentials Data Model v2.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// Terms of use express conditions, obligations, or prohibitions that apply to the
/// credential. They can be specified by either the issuer (governing how the credential
/// may be used) or the holder (governing how it may be verified or stored).
/// </para>
/// <para>
/// Common use cases include:
/// </para>
/// <list type="bullet">
/// <item><description>Restricting credential use to specific domains or purposes.</description></item>
/// <item><description>Requiring acknowledgment before verification.</description></item>
/// <item><description>Specifying data retention policies.</description></item>
/// <item><description>Defining liability limitations.</description></item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#terms-of-use">
/// VC Data Model 2.0 §5.5 Terms of Use</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("TermsOfUse(Id = {Id}, Type = {Type})")]
public class TermsOfUse: IEquatable<TermsOfUse>
{
    /// <summary>
    /// An optional identifier for the terms of use.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When present, this should be a URL that uniquely identifies this specific
    /// set of terms. This enables referencing standardized terms across credentials.
    /// </para>
    /// </remarks>
    public string? Id { get; set; }

    /// <summary>
    /// The type of terms of use.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Indicates the kind of terms being expressed. The type determines what additional
    /// properties are expected and how the terms should be interpreted and enforced.
    /// </para>
    /// <para>
    /// Examples include <c>IssuerPolicy</c>, <c>HolderPolicy</c>, or domain-specific
    /// policy types defined by the credential's context.
    /// </para>
    /// </remarks>
    public required string Type { get; set; }

    /// <summary>
    /// Additional properties as defined by the terms of use type.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Different terms types define additional properties describing the specific
    /// conditions, obligations, or prohibitions. Examples might include <c>prohibition</c>,
    /// <c>obligation</c>, <c>permission</c>, or <c>assigner</c>.
    /// </para>
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(TermsOfUse? other)
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
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is TermsOfUse other && Equals(other);


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
    public static bool operator ==(TermsOfUse? left, TermsOfUse? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(TermsOfUse? left, TermsOfUse? right) => !(left == right);
}