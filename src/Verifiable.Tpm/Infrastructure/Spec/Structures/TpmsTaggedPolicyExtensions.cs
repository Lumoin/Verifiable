using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Extension methods for <see cref="TpmsTaggedPolicy"/>.
/// </summary>
/// <remarks>
/// Provides interpretation methods for tagged policy structures.
/// </remarks>
public static class TpmsTaggedPolicyExtensions
{
    /// <summary>
    /// Gets a human-readable description of the tagged policy.
    /// </summary>
    /// <param name="policy">The tagged policy to describe.</param>
    /// <returns>A human-readable description.</returns>
    public static string GetDescription(this TpmsTaggedPolicy policy)
    {
        string handleName = TpmValueConversions.GetHandleDescription(policy.Handle);

        if(policy.PolicyHash.IsEmpty)
        {
            return $"{handleName}: no policy (empty authorization)";
        }

        string hashHex = Convert.ToHexString(policy.PolicyHash.Span);
        return $"{handleName}: ALG_0x{policy.PolicyHashAlgorithm:X4} policy {hashHex}";
    }

    /// <summary>
    /// Determines if the handle has an empty policy (no restrictions).
    /// </summary>
    /// <param name="policy">The tagged policy.</param>
    /// <returns><c>true</c> if the policy is empty; otherwise, <c>false</c>.</returns>
    public static bool HasEmptyPolicy(this TpmsTaggedPolicy policy)
    {
        return policy.PolicyHash.IsEmpty;
    }

    /// <summary>
    /// Gets the policy hash as a hex string.
    /// </summary>
    /// <param name="policy">The tagged policy.</param>
    /// <returns>The policy hash as a hex string.</returns>
    public static string GetPolicyHashHex(this TpmsTaggedPolicy policy)
    {
        return Convert.ToHexString(policy.PolicyHash.Span);
    }

    /// <summary>
    /// Gets a friendly name for the handle.
    /// </summary>
    /// <param name="policy">The tagged policy.</param>
    /// <returns>A friendly name for the handle.</returns>
    public static string GetHandleName(this TpmsTaggedPolicy policy)
    {
        return TpmValueConversions.GetHandleDescription(policy.Handle);
    }
}