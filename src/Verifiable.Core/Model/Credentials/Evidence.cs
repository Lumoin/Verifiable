using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents evidence supporting the claims in a credential as defined in the W3C
/// Verifiable Credentials Data Model v2.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// Evidence provides information about the verification process performed before
/// issuing a credential, supporting the trustworthiness of the claims. This can
/// include documents reviewed, verification steps performed, or other processes
/// that establish confidence in the claims being made.
/// </para>
/// <para>
/// Evidence is particularly useful for credentials that make claims requiring
/// independent verification, such as identity documents, professional certifications,
/// or educational achievements.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#evidence">
/// VC Data Model 2.0 §5.6 Evidence</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("Evidence(Id = {Id}, Type = {Type})")]
public class Evidence: IEquatable<Evidence>
{
    /// <summary>
    /// An optional identifier for this evidence.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When present, this should be a URL that uniquely identifies this specific
    /// piece of evidence. This enables referencing the evidence from other contexts.
    /// </para>
    /// </remarks>
    public string? Id { get; set; }

    /// <summary>
    /// The type of evidence.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Indicates the kind of evidence provided. The type determines what additional
    /// properties are expected and how the evidence should be interpreted.
    /// </para>
    /// <para>
    /// Examples include <c>DocumentVerification</c>, <c>BiometricVerification</c>,
    /// or domain-specific evidence types defined by the credential's context.
    /// </para>
    /// </remarks>
    public required string Type { get; set; }

    /// <summary>
    /// Additional properties as defined by the evidence type.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Different evidence types define additional properties describing the
    /// verification process. Examples might include <c>verifier</c>, <c>verificationMethod</c>,
    /// <c>documentType</c>, or <c>evidenceDocument</c>.
    /// </para>
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(Evidence? other)
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
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is Evidence other && Equals(other);


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
    public static bool operator ==(Evidence? left, Evidence? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(Evidence? left, Evidence? right) => !(left == right);
}