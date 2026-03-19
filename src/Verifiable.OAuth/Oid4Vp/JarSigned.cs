using System.Diagnostics;
using Verifiable.OAuth;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Carries a signed JAR. Transitions from <see cref="ParCompleted"/> to <see cref="JarReady"/>.
/// Ownership of the <see cref="Jar"/> transfers to the resulting <see cref="JarReady"/> state.
/// </summary>
/// <param name="Jar">
/// The signed authorization request JWT, ready to serve as
/// <c>application/oauth-authz-req+jwt</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>.
/// </param>
[DebuggerDisplay("JarSigned")]
public sealed record JarSigned(SignedJar Jar): OAuthFlowInput;
