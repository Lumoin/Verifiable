using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Server-side input produced by the JAR request endpoint's signing step.
/// Carries the compact JWS string and the UTC instant at which the JAR was served.
/// </summary>
/// <remarks>
/// Per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §5.4</see>,
/// the Verifier signs and serves the JAR in a single HTTP request to
/// <c>GET /request/{flowId}</c>. This input transitions
/// <see cref="States.VerifierParReceivedState"/> directly to
/// <see cref="States.VerifierJarServedState"/>.
/// </remarks>
/// <param name="Jar">The signed JAR. Owned by this input; disposed after the transition.</param>
/// <param name="CompactJar">
/// The compact JWS serialization of <paramref name="Jar"/>. Written to the context bag
/// so the ASP.NET skin can serve it in the HTTP response body.
/// </param>
/// <param name="ServedAt">The UTC instant at which the JAR was served.</param>
[DebuggerDisplay("ServerJarSigned ServedAt={ServedAt}")]
public sealed record ServerJarSigned(
    SignedJar Jar,
    string CompactJar,
    DateTimeOffset ServedAt): OAuthFlowInput, IDisposable
{
    private bool disposed;

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Jar.Dispose();
            disposed = true;
        }
    }
}
