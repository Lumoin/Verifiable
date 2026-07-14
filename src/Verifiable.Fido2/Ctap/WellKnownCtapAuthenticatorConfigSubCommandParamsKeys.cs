namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>setMinPINLength</c> subcommand's own <c>subCommandParams</c> map.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
/// CTAP 2.3, section 6.11.4: setMinPINLength (0x03)</see>, the subCommandParams member table (lines
/// 8087-8116). Every member is modeled, including <see cref="PinComplexityPolicy"/> — a fourth field
/// the wave's own charter did not enumerate by name, but which shares this same map on the wire (wire
/// completeness; <see cref="PinComplexityPolicy"/>'s value is decoded and then ignored, per the
/// line-8442 MUST — see <c>CtapAuthenticatorTransitions.OnSetMinPinLengthRequested</c>).
/// </remarks>
public static class WellKnownCtapAuthenticatorConfigSubCommandParamsKeys
{
    /// <summary>The <c>newMinPINLength</c> member (<c>0x01</c>, Optional): the minimum PIN length in code points to set.</summary>
    public const int NewMinPinLength = 0x01;

    /// <summary>
    /// The <c>minPinLengthRPIDs</c> member (<c>0x02</c>, Optional): RP IDs allowed to receive the
    /// current minimum PIN length via the <c>minPinLength</c> extension. Accepted by this profile (line
    /// 8105/8136's disjunctive gate, read under De Morgan, is satisfied once the <c>minPinLength</c>
    /// extension alone is supported — see <c>CtapAuthenticatorTransitions.OnSetMinPinLengthRequested</c>'s
    /// own remarks) and stored, replacing the previously stored list wholesale, subject to the
    /// <c>CtapAuthenticatorState.MaxRpIdsForSetMinPinLengthCapacity</c> bound.
    /// </summary>
    public const int MinPinLengthRpIds = 0x02;

    /// <summary>The <c>forceChangePin</c> member (<c>0x03</c>, Optional): forces a PIN change before the next successful <c>changePIN</c>.</summary>
    public const int ForceChangePin = 0x03;

    /// <summary>
    /// The <c>pinComplexityPolicy</c> member (<c>0x04</c>, Optional): enables a PIN complexity policy.
    /// Decoded for wire completeness, then ignored — this profile's getInfo <c>pinComplexityPolicy</c>
    /// member is absent, so it is not configurable via this subcommand (line 8442's MUST).
    /// </summary>
    public const int PinComplexityPolicy = 0x04;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="NewMinPinLength"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>newMinPINLength</c> key.</returns>
    public static bool IsNewMinPinLength(int key) => key == NewMinPinLength;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="MinPinLengthRpIds"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>minPinLengthRPIDs</c> key.</returns>
    public static bool IsMinPinLengthRpIds(int key) => key == MinPinLengthRpIds;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="ForceChangePin"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>forceChangePin</c> key.</returns>
    public static bool IsForceChangePin(int key) => key == ForceChangePin;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinComplexityPolicy"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinComplexityPolicy</c> key.</returns>
    public static bool IsPinComplexityPolicy(int key) => key == PinComplexityPolicy;
}
