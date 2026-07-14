namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>subCommand</c> (<c>0x01</c>) values <c>authenticatorConfig</c> requests carry.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
/// CTAP 2.3, section 6.11: authenticatorConfig (0x0D)</see>, the "currently defined authenticatorConfig
/// subcommands" table (line 7909-7931). Models all five spec-defined numbers, mirroring
/// <see cref="WellKnownCtapClientPinSubCommands"/>'s "model the full shape" convention — which of them
/// this authenticator actually SUPPORTS is a transition-level decision (see
/// <c>CtapAuthenticatorTransitions.OnAuthenticatorConfigRequested</c>), not this vocabulary type's own
/// business: line 7933 ("Authenticators MAY implement none, some, or all currently defined
/// authenticatorConfig subcommands") makes support a per-authenticator choice, reported via the
/// <c>authenticatorConfigCommands</c> getInfo member. This authenticator supports
/// <see cref="ToggleAlwaysUv"/> and <see cref="SetMinPinLength"/> unconditionally, and
/// <see cref="EnableEnterpriseAttestation"/> exactly when it is enterprise attestation capable
/// (<c>CtapAuthenticatorState.IsEnterpriseAttestationCapable</c>, waveep R12); every other value
/// (including any out-of-table integer, or <see cref="EnableEnterpriseAttestation"/> on a non-capable
/// authenticator) rejects with <see cref="WellKnownCtapStatusCodes.InvalidSubcommand"/> at the command's
/// own step 2.
/// </remarks>
public static class WellKnownCtapAuthenticatorConfigSubCommands
{
    /// <summary>
    /// <c>enableEnterpriseAttestation</c> (<c>0x01</c>): idempotently enables the enterprise attestation
    /// feature (CTAP 2.3 §6.11.1). Supported exactly when the authenticator is enterprise attestation
    /// capable (<c>CtapAuthenticatorState.IsEnterpriseAttestationCapable</c>, waveep R12); a non-capable
    /// authenticator (the profile default — no provisioning record seeded) rejects it at step 2 with
    /// <see cref="WellKnownCtapStatusCodes.InvalidSubcommand"/>, unchanged from before waveep.
    /// </summary>
    public const int EnableEnterpriseAttestation = 0x01;

    /// <summary>
    /// <c>toggleAlwaysUv</c> (<c>0x02</c>): enables or disables the Always Require User Verification
    /// feature (CTAP 2.3 §6.11.2). Supported by this authenticator.
    /// </summary>
    public const int ToggleAlwaysUv = 0x02;

    /// <summary>
    /// <c>setMinPINLength</c> (<c>0x03</c>): sets the minimum PIN length in Unicode code points (CTAP
    /// 2.3 §6.11.4). Supported by this authenticator.
    /// </summary>
    public const int SetMinPinLength = 0x03;

    /// <summary>
    /// <c>enableLongTouchForReset</c> (<c>0x04</c>): re-enables the Long Touch for Reset feature. Not
    /// supported by this authenticator (no such feature modeled) — rejected via step 2.
    /// </summary>
    public const int EnableLongTouchForReset = 0x04;

    /// <summary>
    /// <c>vendorPrototype</c> (<c>0xFF</c>): vendor-specific configuration and experimentation (CTAP
    /// 2.3 §6.11.3). Not supported by this authenticator (no interoperable spec behavior exists to
    /// implement; <c>vendorPrototypeConfigCommands</c> stays absent) — rejected via step 2.
    /// </summary>
    public const int VendorPrototype = 0xFF;


    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="EnableEnterpriseAttestation"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>enableEnterpriseAttestation</c>.</returns>
    public static bool IsEnableEnterpriseAttestation(int subCommand) => subCommand == EnableEnterpriseAttestation;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="ToggleAlwaysUv"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>toggleAlwaysUv</c>.</returns>
    public static bool IsToggleAlwaysUv(int subCommand) => subCommand == ToggleAlwaysUv;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="SetMinPinLength"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>setMinPINLength</c>.</returns>
    public static bool IsSetMinPinLength(int subCommand) => subCommand == SetMinPinLength;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="EnableLongTouchForReset"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>enableLongTouchForReset</c>.</returns>
    public static bool IsEnableLongTouchForReset(int subCommand) => subCommand == EnableLongTouchForReset;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="VendorPrototype"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>vendorPrototype</c>.</returns>
    public static bool IsVendorPrototype(int subCommand) => subCommand == VendorPrototype;
}
