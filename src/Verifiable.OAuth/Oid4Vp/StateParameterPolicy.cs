namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Per-call policy for whether the OAuth <c>state</c> parameter must be present when a
/// Wallet parses an Authorization Request.
/// </summary>
/// <remarks>
/// <para>
/// OID4VP 1.0 §5 and <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>
/// make <c>state</c> OPTIONAL, so <see cref="Optional"/> is the spec-conformant choice
/// — a conformant Wallet MUST accept a request that omits it. A deployment selects
/// <see cref="Required"/> when its own threat analysis wants the CSRF/replay binding an
/// always-present <c>state</c> affords.
/// </para>
/// <para>
/// The choice is passed explicitly per call (never captured), so one stateless parser
/// serves every caller and the decision stays with the application that knows its
/// threat model. Emit stays strict regardless — the library's Verifier always sends
/// <c>state</c> as its correlation key.
/// </para>
/// </remarks>
public enum StateParameterPolicy
{
    /// <summary>
    /// Accept a request that omits <c>state</c> (the OID4VP 1.0 §5 / RFC 6749 default).
    /// </summary>
    Optional,

    /// <summary>Reject a request that omits <c>state</c>.</summary>
    Required
}
