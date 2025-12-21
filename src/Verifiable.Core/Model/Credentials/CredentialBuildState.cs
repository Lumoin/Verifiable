using System;
using System.Collections.Generic;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents the build state for constructing Verifiable Credentials.
/// This state is passed between transformation functions during the fold/aggregate process
/// and contains all the information needed to construct a credential.
/// </summary>
/// <remarks>
/// <para>
/// The build state follows the W3C Verifiable Credentials Data Model 2.0 specification
/// and provides context for credential construction including issuer information,
/// validity periods, and credential subject data.
/// </para>
/// <para>
/// This struct implements value equality semantics where two build states are considered
/// equal if they contain the same issuer, validity times, and credential configuration.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/">
/// W3C Verifiable Credentials Data Model 2.0</see>.
/// </para>
/// </remarks>
public struct CredentialBuildState: IEquatable<CredentialBuildState>, IBuilderState
{
    /// <summary>
    /// Gets the issuer of the credential.
    /// This can represent either a simple URI string or an object with additional metadata.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The issuer is responsible for the claims made in the credential. It is typically
    /// identified by a DID such as <c>did:web:example.com</c> or <c>did:key:z6Mk...</c>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#issuer">
    /// VC Data Model 2.0 §4.4 Issuer</see>.
    /// </para>
    /// </remarks>
    public required Issuer Issuer { get; init; }

    /// <summary>
    /// Gets the date and time from which the credential is valid.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In VC 2.0, this property replaces the <c>issuanceDate</c> property from VC 1.1.
    /// If not specified, the credential is considered valid immediately upon issuance.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#validity-period">
    /// VC Data Model 2.0 §4.8 Validity Period</see>.
    /// </para>
    /// </remarks>
    public DateTime? ValidFrom { get; init; }

    /// <summary>
    /// Gets the date and time until which the credential is valid.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In VC 2.0, this property replaces the <c>expirationDate</c> property from VC 1.1.
    /// If not specified, the credential does not expire.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#validity-period">
    /// VC Data Model 2.0 §4.8 Validity Period</see>.
    /// </para>
    /// </remarks>
    public DateTime? ValidUntil { get; init; }

    /// <summary>
    /// Gets the optional identifier for the credential.
    /// </summary>
    /// <remarks>
    /// When present, this should be a URI that uniquely identifies the credential instance.
    /// This enables referencing the specific credential for revocation and status checking.
    /// </remarks>
    public string? CredentialId { get; init; }

    /// <summary>
    /// Gets the types of the credential beyond the base <c>"VerifiableCredential"</c> type.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Additional types specify the kind of credential being issued, such as
    /// <c>"UniversityDegreeCredential"</c> or <c>"EmployeeIdentityCredential"</c>.
    /// The base type <c>"VerifiableCredential"</c> is always included automatically.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#types">
    /// VC Data Model 2.0 §4.3 Types</see>.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string>? AdditionalTypes { get; init; }

    /// <summary>
    /// Gets the collection of credential subject inputs for creating the credential.
    /// </summary>
    /// <remarks>
    /// Each subject contains the claims being made. A credential can have multiple subjects,
    /// each representing a different entity about which claims are asserted.
    /// </remarks>
    public IReadOnlyList<CredentialSubject>? Subjects { get; init; }

    /// <summary>
    /// Gets or sets the current credential subject index being processed.
    /// Used by transformation logic to determine context during multi-subject credential construction.
    /// </summary>
    public int CurrentSubjectIndex { get; set; }


    /// <summary>
    /// Determines whether the specified <see cref="CredentialBuildState"/> is equal to the current instance.
    /// Two build states are considered equal if they have the same issuer, validity period,
    /// credential ID, types, and subjects.
    /// </summary>
    /// <param name="other">The build state to compare with the current instance.</param>
    /// <returns><c>true</c> if the specified build state is equal to the current instance; otherwise, <c>false</c>.</returns>
    public bool Equals(CredentialBuildState other)
    {
        return Equals(Issuer, other.Issuer)
            && Nullable.Equals(ValidFrom, other.ValidFrom)
            && Nullable.Equals(ValidUntil, other.ValidUntil)
            && CredentialId == other.CredentialId
            && AdditionalTypes?.Count == other.AdditionalTypes?.Count
            && Subjects?.Count == other.Subjects?.Count
            && CurrentSubjectIndex == other.CurrentSubjectIndex;
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current instance.
    /// </summary>
    /// <param name="obj">The object to compare with the current instance.</param>
    /// <returns>
    /// <c>true</c> if the specified object is a <see cref="CredentialBuildState"/>
    /// and is equal to the current instance; otherwise, <c>false</c>.
    /// </returns>
    public override bool Equals(object? obj)
    {
        return obj is CredentialBuildState other && Equals(other);
    }

    /// <summary>
    /// Returns the hash code for this instance.
    /// </summary>
    /// <returns>A 32-bit signed integer that is the hash code for this instance.</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            Issuer,
            ValidFrom,
            ValidUntil,
            CredentialId,
            AdditionalTypes?.Count ?? 0,
            Subjects?.Count ?? 0,
            CurrentSubjectIndex);
    }

    /// <summary>
    /// Determines whether two specified instances of <see cref="CredentialBuildState"/> are equal.
    /// </summary>
    /// <param name="left">The first build state to compare.</param>
    /// <param name="right">The second build state to compare.</param>
    /// <returns><c>true</c> if the two build states are equal; otherwise, <c>false</c>.</returns>
    public static bool operator ==(CredentialBuildState left, CredentialBuildState right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two specified instances of <see cref="CredentialBuildState"/> are not equal.
    /// </summary>
    /// <param name="left">The first build state to compare.</param>
    /// <param name="right">The second build state to compare.</param>
    /// <returns><c>true</c> if the two build states are not equal; otherwise, <c>false</c>.</returns>
    public static bool operator !=(CredentialBuildState left, CredentialBuildState right)
    {
        return !left.Equals(right);
    }
}