namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Carries a signed JAR. Transitions from <see cref="States.ParCompletedState"/> to
/// <see cref="States.JarReadyState"/>. Ownership of the <see cref="Jar"/> transfers to the
/// resulting <see cref="States.JarReadyState"/> state.
/// </summary>
/// <param name="Jar">
/// The signed authorization request JWT, ready to serve as
/// <c>application/oauth-authz-req+jwt</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>.
/// </param>
public sealed record JarSigned(SignedJar Jar): FlowInput;
