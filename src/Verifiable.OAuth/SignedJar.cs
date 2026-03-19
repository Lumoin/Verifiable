using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth;

/// <summary>
/// A signed JWT Authorization Request (JAR) as defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>, ready to serve
/// at the <c>request_uri</c> endpoint with media type
/// <c>application/oauth-authz-req+jwt</c>.
/// </summary>
/// <remarks>
/// <para>
/// This type wraps the <see cref="JwsMessage"/> produced by signing the JAR payload.
/// Ownership of the <see cref="JwsMessage"/> transfers to this instance; callers must
/// dispose this instance when the JAR is no longer needed.
/// </para>
/// <para>
/// The compact serialization suitable for serving over HTTP is obtained by calling
/// <c>JwsSerialization.SerializeCompact</c> on the underlying <see cref="Message"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("SignedJar")]
public sealed class SignedJar: IDisposable
{
    private bool disposed;

    /// <summary>
    /// The signed JWS message. Owned by this instance.
    /// </summary>
    public JwsMessage Message { get; }


    /// <summary>
    /// Initializes a <see cref="SignedJar"/> from a signed <see cref="JwsMessage"/>.
    /// </summary>
    /// <param name="message">
    /// The signed JWS message. Ownership transfers to this instance.
    /// </param>
    public SignedJar(JwsMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        Message = message;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Message.Dispose();
            disposed = true;
        }
    }
}
