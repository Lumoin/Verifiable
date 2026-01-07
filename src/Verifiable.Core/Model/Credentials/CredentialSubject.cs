using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents the subject of a Verifiable Credential as defined in the W3C Verifiable
/// Credentials Data Model v2.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// A credential subject contains the claims being made about one or more subjects.
/// The subject can represent any entity: a person, organization, device, location,
/// or abstract concept.
/// </para>
/// <para>
/// A credential can have multiple subjects, each with their own claims. The <see cref="Id"/>
/// property, when present, provides a globally unique identifier for the subject, enabling
/// correlation across different credentials about the same entity.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#credential-subject">
/// VC Data Model 2.0 §4.8 Credential Subject</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("CredentialSubject(Id = {Id})")]
public class CredentialSubject: IEquatable<CredentialSubject>
{
    /// <summary>
    /// An optional identifier for the credential subject.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When present, this should be a URL that uniquely identifies the subject.
    /// Common forms include DIDs (e.g., <c>did:example:123</c>) or other URIs.
    /// </para>
    /// <para>
    /// If omitted, the credential makes claims about an unidentified subject, which
    /// can be appropriate for bearer credentials or when privacy is paramount.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#identifiers">
    /// VC Data Model 2.0 §4.4 Identifiers</see>.
    /// </para>
    /// </remarks>
    public string? Id { get; set; }

    /// <summary>
    /// Additional properties containing claims about the subject.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These properties are defined by the credential's JSON-LD context and represent
    /// the actual claims being made. Examples include <c>name</c>, <c>degree</c>,
    /// <c>membershipLevel</c>, or any other claim appropriate to the credential type.
    /// </para>
    /// <para>
    /// The structure and semantics of these claims are determined by the credential
    /// type and its associated JSON-LD context.
    /// </para>
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(CredentialSubject? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        //Note: AdditionalData equality is not compared due to dictionary complexity.
        //Two subjects are considered equal if they have the same Id.
        return string.Equals(Id, other.Id, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is CredentialSubject other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return Id?.GetHashCode(StringComparison.Ordinal) ?? 0;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(CredentialSubject? left, CredentialSubject? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(CredentialSubject? left, CredentialSubject? right) => !(left == right);
}