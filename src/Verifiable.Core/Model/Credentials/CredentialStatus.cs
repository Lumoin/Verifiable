using System.Collections.Generic;

namespace Verifiable.Core.Model.Credentials
{
    /// <summary>
    /// Represents status information for a Verifiable Credential as defined in the W3C
    /// Verifiable Credentials Data Model v2.0 specification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The credential status mechanism enables verifiers to check whether a credential
    /// has been revoked or suspended by the issuer after issuance. This allows issuers
    /// to update the status of issued credentials without reissuing them.
    /// </para>
    /// <para>
    /// A credential can have multiple status entries for different purposes (e.g., one
    /// for revocation and another for suspension).
    /// </para>
    /// <para>
    /// Common status mechanisms include:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>BitstringStatusListEntry</c>: Efficient bitstring-based status lists.</description></item>
    /// <item><description><c>RevocationList2020Status</c>: Legacy revocation list format.</description></item>
    /// </list>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#status">VC Data Model 2.0 §4.10 Status</see>.
    /// </para>
    /// </remarks>
    public class CredentialStatus
    {
        /// <summary>
        /// A unique identifier for this status entry.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The URL that identifies this specific status entry. For bitstring status lists,
        /// this typically includes the credential identifier component.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#status">VC Data Model 2.0 §4.10 Status</see>.
        /// </para>
        /// </remarks>
        public string? Id { get; set; }

        /// <summary>
        /// The type of credential status mechanism.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Determines how the status should be checked and interpreted.
        /// Common values include <c>BitstringStatusListEntry</c>.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#status">VC Data Model 2.0 §4.10 Status</see>.
        /// </para>
        /// </remarks>
        public required string Type { get; set; }

        /// <summary>
        /// The purpose of this status entry.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Indicates what kind of status this entry represents. Common values are:
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>revocation</c>: Indicates whether the credential has been permanently revoked.</description></item>
        /// <item><description><c>suspension</c>: Indicates whether the credential is temporarily suspended.</description></item>
        /// </list>
        /// </remarks>
        public string? StatusPurpose { get; set; }

        /// <summary>
        /// The index within the status list for this credential.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Used with bitstring status list mechanisms. The index identifies the bit
        /// position in the status list that corresponds to this credential.
        /// </para>
        /// </remarks>
        public string? StatusListIndex { get; set; }

        /// <summary>
        /// A reference to the status list credential containing this entry.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The URL of a Verifiable Credential that contains the status list.
        /// Verifiers dereference this URL to obtain the current status information.
        /// </para>
        /// </remarks>
        public string? StatusListCredential { get; set; }

        /// <summary>
        /// Additional properties as defined by the specific status mechanism.
        /// </summary>
        /// <remarks>
        /// Different status types may define additional properties for their operation.
        /// </remarks>
        public IDictionary<string, object>? AdditionalData { get; set; }
    }
}