namespace Verifiable.OAuth.AuthCode.Server;

/// <summary>
/// The stack alphabet for the server-side Authorization Code flow PDA.
/// </summary>
/// <remarks>
/// <see cref="Base"/> is the sentinel always present at the bottom of the stack.
/// The linear authorization code flow never pushes or pops additional symbols.
/// <see cref="StepUp"/> is reserved for nested step-up authentication sub-flows
/// such as MFA challenges mid-authorize.
/// </remarks>
public enum AuthCodeServerStackSymbol
{
    /// <summary>
    /// Sentinel symbol always present at the bottom of the stack.
    /// Attempting to pop it indicates a bug in the transition function.
    /// </summary>
    Base,

    /// <summary>
    /// Pushed when a step-up authentication sub-flow is initiated mid-authorize
    /// and popped when it completes or is abandoned.
    /// </summary>
    StepUp
}
