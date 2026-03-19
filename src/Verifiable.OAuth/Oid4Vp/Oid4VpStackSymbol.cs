namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// The stack alphabet for the OID4VP authorization flow PDA.
/// </summary>
/// <remarks>
/// This type is <c>TStackSymbol</c> in
/// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol&gt;</c>.
/// <see cref="Base"/> is the sentinel always present at the bottom of the stack.
/// The linear authorization code flow never pushes or pops; <see cref="StepUp"/> is
/// reserved for nested step-up authentication sub-flows.
/// </remarks>
public enum Oid4VpStackSymbol
{
    /// <summary>
    /// Sentinel symbol. Always present at the bottom of the stack.
    /// Attempting to pop it indicates a bug in the transition function.
    /// </summary>
    Base,

    /// <summary>
    /// Pushed when a step-up authentication sub-flow is initiated mid-flow
    /// and popped when it completes or is abandoned.
    /// </summary>
    StepUp
}
