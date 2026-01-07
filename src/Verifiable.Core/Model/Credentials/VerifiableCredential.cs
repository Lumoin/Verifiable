using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Proofs;

namespace Verifiable.Core.Model.Credentials;
/// <summary>
/// Represents a Verifiable Credential as defined in the W3C Verifiable Credentials
/// Data Model v2.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// A Verifiable Credential is a tamper-evident credential whose authorship can be
/// cryptographically verified. It contains claims about one or more subjects made
/// by an issuer.
/// </para>
/// <para>
/// The basic components of a Verifiable Credential are:
/// </para>
/// <list type="bullet">
/// <item><description>Metadata about the credential (issuer, validity period, status).</description></item>
/// <item><description>Claims about the subject(s) in <see cref="CredentialSubject"/>.</description></item>
/// <item><description>One or more cryptographic proofs enabling verification.</description></item>
/// </list>
/// <para>
/// The word "verifiable" refers to the characteristic of being able to be verified
/// by a verifier. Verifiability does not imply truth of claims; upon establishing
/// authenticity, verifiers validate claims using their own business rules.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#credentials">
/// VC Data Model 2.0 §3.2 Credentials</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("VerifiableCredential(Id = {Id}, Issuer = {Issuer?.Id})")]
public class VerifiableCredential: IEquatable<VerifiableCredential>
{
    /// <summary>
    /// The JSON-LD context that defines the terms used in this credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The first context must be <see cref="Context.Credentials20"/>. Additional
    /// contexts define the vocabulary for credential-specific claims.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3 Contexts</see>.
    /// </para>
    /// </remarks>
    public Context? Context { get; set; }

    /// <summary>
    /// An optional unique identifier for the credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When present, this should be a URL. It enables referencing the specific
    /// credential instance, which is useful for revocation and status checking.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#identifiers">VC Data Model 2.0 §4.4 Identifiers</see>.
    /// </para>
    /// </remarks>
    public string? Id { get; set; }

    /// <summary>
    /// The types of this credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Must include <c>"VerifiableCredential"</c>. Additional types specify the
    /// kind of credential (e.g., <c>"UniversityDegreeCredential"</c>).
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#types">VC Data Model 2.0 §4.5 Types</see>.
    /// </para>
    /// </remarks>
    public List<string>? Type { get; set; }

    /// <summary>
    /// An optional human-readable name for the credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions">
    /// VC Data Model 2.0 §4.6 Names and Descriptions</see>.
    /// </para>
    /// </remarks>
    public string? Name { get; set; }

    /// <summary>
    /// An optional human-readable description of the credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions">
    /// VC Data Model 2.0 §4.6 Names and Descriptions</see>.
    /// </para>
    /// </remarks>
    public string? Description { get; set; }

    /// <summary>
    /// The entity that issued the credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Can be a simple URI string or an object with additional metadata.
    /// The issuer is responsible for the claims made in the credential.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#issuer">VC Data Model 2.0 §4.7 Issuer</see>.
    /// </para>
    /// </remarks>
    public Issuer? Issuer { get; set; }

    /// <summary>
    /// The subject(s) of the credential containing the claims being made.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Can be a single subject or multiple subjects. Each subject contains
    /// claims as defined by the credential's context.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#credential-subject">
    /// VC Data Model 2.0 §4.8 Credential Subject</see>.
    /// </para>
    /// </remarks>
    public List<CredentialSubject>? CredentialSubject { get; set; }

    /// <summary>
    /// The date and time when the credential becomes valid.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The credential should not be considered valid before this time.
    /// The value should be an XML Schema <c>dateTimeStamp</c>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#validity-period">
    /// VC Data Model 2.0 §4.9 Validity Period</see>.
    /// </para>
    /// </remarks>
    public DateTime? ValidFrom { get; set; }

    /// <summary>
    /// The date and time when the credential expires.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The credential should not be considered valid after this time.
    /// The value should be an XML Schema <c>dateTimeStamp</c>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#validity-period">
    /// VC Data Model 2.0 §4.9 Validity Period</see>.
    /// </para>
    /// </remarks>
    public DateTime? ValidUntil { get; set; }

    /// <summary>
    /// Status information for checking revocation or suspension.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Enables verifiers to check whether the credential has been revoked or suspended
    /// by the issuer after issuance.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#status">VC Data Model 2.0 §4.10 Status</see>.
    /// </para>
    /// </remarks>
    public List<CredentialStatus>? CredentialStatus { get; set; }

    /// <summary>
    /// Schema(s) for validating the credential's structure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Allows verifiers to ensure that a credential conforms to an expected structure,
    /// useful for interoperability and automated processing.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#data-schemas">
    /// VC Data Model 2.0 §4.11 Data Schemas</see>.
    /// </para>
    /// </remarks>
    public List<CredentialSchema>? CredentialSchema { get; set; }

    /// <summary>
    /// One or more cryptographic proofs that make this credential verifiable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The VC Data Model 2.0 defines two classes of securing mechanisms: embedded proofs
    /// and enveloping proofs. This property is used for embedded proofs.
    /// </para>
    /// <para>
    /// <strong>Embedded proofs (Data Integrity):</strong> When using Data Integrity securing,
    /// this property contains one or more <see cref="DataIntegrityProof"/> instances with
    /// the cryptosuite identifier, verification method reference, and signature value.
    /// The proof is part of the credential itself.
    /// </para>
    /// <para>
    /// <strong>Enveloping proofs (JOSE/COSE):</strong> When using envelope-based securing
    /// mechanisms such as JOSE (JWT, SD-JWT) or COSE, this property is <c>null</c> or absent.
    /// The credential becomes the payload of an external envelope structure that provides
    /// the cryptographic protection.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#securing-mechanisms">
    /// VC Data Model 2.0 §4.12 Securing Mechanisms</see> for the general framework,
    /// <see href="https://www.w3.org/TR/vc-data-integrity/">VC Data Integrity</see> for
    /// embedded proof details, and <see href="https://www.w3.org/TR/vc-jose-cose/">
    /// VC-JOSE-COSE</see> for envelope-based securing.
    /// </para>
    /// </remarks>
    public List<DataIntegrityProof>? Proof { get; set; }

    /// <summary>
    /// Resources related to this credential with integrity protection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Enables linking to external resources while ensuring their integrity through
    /// cryptographic digests. This is useful for images, documents, or other data
    /// that should not change after credential issuance.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#integrity-of-related-resources">
    /// VC Data Model 2.0 §5.3 Integrity of Related Resources</see>.
    /// </para>
    /// </remarks>
    public List<RelatedResource>? RelatedResource { get; set; }

    /// <summary>
    /// Service(s) for refreshing the credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Provides a mechanism for holders to request updated credentials from the issuer,
    /// useful when credential information changes or approaches expiration.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#refreshing">
    /// VC Data Model 2.0 §5.4 Refreshing</see>.
    /// </para>
    /// </remarks>
    public List<RefreshService>? RefreshService { get; set; }

    /// <summary>
    /// Terms of use that apply to this credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Expresses conditions, obligations, or prohibitions that apply to the credential.
    /// Both issuers and holders can specify terms of use.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#terms-of-use">
    /// VC Data Model 2.0 §5.5 Terms of Use</see>.
    /// </para>
    /// </remarks>
    public List<TermsOfUse>? TermsOfUse { get; set; }

    /// <summary>
    /// Evidence supporting the claims in this credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Provides information about the process used to verify the subject before
    /// issuing the credential, such as documents reviewed or verification steps performed.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#evidence">
    /// VC Data Model 2.0 §5.6 Evidence</see>.
    /// </para>
    /// </remarks>
    public List<Evidence>? Evidence { get; set; }

    /// <summary>
    /// Additional properties as defined by the credential's JSON-LD context.
    /// </summary>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(VerifiableCredential? other)
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
            && Equals(Issuer, other.Issuer)
            && ValidFrom == other.ValidFrom
            && ValidUntil == other.ValidUntil;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is VerifiableCredential other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Id, StringComparer.Ordinal);
        hash.Add(Issuer);
        hash.Add(ValidFrom);
        hash.Add(ValidUntil);

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(VerifiableCredential? left, VerifiableCredential? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(VerifiableCredential? left, VerifiableCredential? right) => !(left == right);
}