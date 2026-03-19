using Verifiable.Core.Automata;

namespace Verifiable.OAuth;

/// <summary>
/// Base type for actions in OAuth/OpenID flow PDAs.
/// </summary>
/// <remarks>
/// Derive from this type to define effectful work specific to an OAuth flow or profile.
/// Register a handler for each derived type in <see cref="OAuthActionExecutor"/>.
/// The effectful dispatch loop pattern-matches on <see cref="OAuthAction"/> subtypes
/// and dispatches to the registered handler.
/// </remarks>
public abstract record OAuthAction: PdaAction;
