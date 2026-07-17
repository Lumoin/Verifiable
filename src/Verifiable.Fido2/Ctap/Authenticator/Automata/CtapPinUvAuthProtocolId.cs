namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// Identifies which CTAP PIN/UV auth protocol a <see cref="CtapPinUvAuthProtocol"/> instance
/// implements (CTAP 2.3 §6.5.6/§6.5.7).
/// </summary>
/// <remarks>
/// The numeric values are the wire values CTAP itself uses for the <c>pinUvAuthProtocol</c>
/// request parameter and for each entry of the <c>pinUvAuthProtocols</c> <c>authenticatorGetInfo</c>
/// member (CTAP 2.3 §6.5.5, §5.1) - they are not arbitrary ordinals, so this enum's underlying
/// values must never be renumbered.
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1008:Enums should have zero value",
    Justification = "The values are CTAP 2.3's own wire-visible pinUvAuthProtocol identifiers (§6.5.5/§9 item 6, both 1-based); introducing an unspecified zero member would invite an invalid wire value to type-check.")]
public enum CtapPinUvAuthProtocolId
{
    /// <summary>PIN/UV auth protocol one (CTAP 2.3 §6.5.6).</summary>
    One = 1,

    /// <summary>
    /// PIN/UV auth protocol two (CTAP 2.3 §6.5.7). Mandatory to implement for any authenticator
    /// that advertises the <c>pinUvAuthProtocols</c> <c>authenticatorGetInfo</c> member at all
    /// (CTAP 2.3 §9 item 6).
    /// </summary>
    Two = 2
}
