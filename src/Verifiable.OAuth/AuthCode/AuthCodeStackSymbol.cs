namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The stack alphabet for the Authorization Code flow PDA.
/// </summary>
/// <remarks>
/// This type is <c>TStackSymbol</c> in
/// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol&gt;</c>.
/// <see cref="Base"/> is the sentinel always present at the bottom of the stack.
/// The linear authorization code flow never pushes or pops.
/// </remarks>
public enum AuthCodeStackSymbol
{
    /// <summary>
    /// Sentinel symbol. Always present at the bottom of the stack.
    /// Attempting to pop it indicates a bug in the transition function.
    /// </summary>
    Base
}
