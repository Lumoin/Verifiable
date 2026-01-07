using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents a data schema for validating the structure and content of a Verifiable
/// Credential as defined in the W3C Verifiable Credentials Data Model v2.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// Credential schemas allow verifiers to ensure that a credential conforms to an expected
/// structure. This is useful for interoperability, automated processing, and ensuring
/// that credentials contain the expected claims with appropriate data types.
/// </para>
/// <para>
/// A credential can reference multiple schemas for different purposes, such as validating
/// the credential structure, constraining claim values, or supporting semantic validation.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#data-schemas">
/// VC Data Model 2.0 §4.11 Data Schemas</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("CredentialSchema(Id = {Id}, Type = {Type})")]
public class CredentialSchema: IEquatable<CredentialSchema>
{
    /// <summary>
    /// A URL identifying the schema.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The URL should be dereferenceable to obtain the actual schema definition.
    /// Verifiers use this to retrieve the schema for validation.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#data-schemas">
    /// VC Data Model 2.0 §4.11 Data Schemas</see>.
    /// </para>
    /// </remarks>
    public required string Id { get; set; }

    /// <summary>
    /// The type of schema, indicating how to interpret and apply it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Common values include:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>JsonSchema</c>: JSON Schema for structural validation.</description></item>
    /// <item><description><c>JsonSchemaCredential</c>: A Verifiable Credential containing a JSON Schema.</description></item>
    /// </list>
    /// <para>
    /// The type determines the validation algorithm and expected schema format.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#data-schemas">
    /// VC Data Model 2.0 §4.11 Data Schemas</see>.
    /// </para>
    /// </remarks>
    public required string Type { get; set; }

    /// <summary>
    /// Additional properties as defined by the schema type.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Different schema types may define additional properties for configuration
    /// or validation parameters.
    /// </para>
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(CredentialSchema? other)
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
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is CredentialSchema other && Equals(other);


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
    public static bool operator ==(CredentialSchema? left, CredentialSchema? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(CredentialSchema? left, CredentialSchema? right) => !(left == right);
}