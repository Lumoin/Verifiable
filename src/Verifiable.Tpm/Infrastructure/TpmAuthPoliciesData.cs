using System.Collections.Generic;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// TPM authorization policies capability data (TPM_CAP_AUTH_POLICIES).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format (TPML_TAGGED_POLICY):</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                          // Number of policies.
///     TPMS_TAGGED_POLICY policies[count];    // Array of tagged policies.
/// } TPML_TAGGED_POLICY;
/// </code>
/// <para>
/// <b>Content:</b> Lists the authorization policies associated with permanent handles.
/// Each entry contains a handle and its policy digest.
/// </para>
/// </remarks>
/// <seealso cref="TpmsTaggedPolicy"/>
/// <seealso cref="TpmCapabilityData"/>
public sealed record TpmAuthPoliciesData: TpmCapabilityData
{
    /// <inheritdoc/>
    public override TpmCapConstants Capability => TpmCapConstants.TPM_CAP_AUTH_POLICIES;

    /// <summary>
    /// Gets the list of tagged authorization policies.
    /// </summary>
    /// <remarks>
    /// Each entry associates a permanent handle with its authorization policy digest.
    /// </remarks>
    public required IReadOnlyList<TpmsTaggedPolicy> AuthPolicies { get; init; }
}