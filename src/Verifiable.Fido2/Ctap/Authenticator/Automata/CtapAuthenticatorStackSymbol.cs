namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The stack alphabet of the CTAP2 authenticator simulator's pushdown automaton.
/// </summary>
/// <remarks>
/// Wave 1's single command (<c>authenticatorGetInfo</c>) needs no nested scopes, so this slice uses
/// only the bottom sentinel — mirroring <c>Verifiable.Apdu.Automata.CardStackSymbol</c>'s
/// single-sentinel shape for its own first slice. A multi-step ceremony with an intermediate,
/// abandonable state (for example a future PIN/UV protocol exchange) is added to this alphabet when
/// that command family is modeled.
/// </remarks>
public enum CtapAuthenticatorStackSymbol
{
    /// <summary>The bottom-of-stack sentinel representing the authenticator's command session scope. Never popped.</summary>
    Session
}
