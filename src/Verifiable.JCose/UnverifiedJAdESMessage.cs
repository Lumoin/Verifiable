using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A JAdES message parsed from untrusted wire bytes across any of the three JWS serializations — the JAdES
/// extension of the JOSE <c>Unverified*</c> family: the generic JWS
/// structural facts ride the EXISTING <see cref="UnverifiedJwsMessage"/> shape unchanged (<see cref="Wire"/>);
/// <see cref="EtsiURawBytes"/> is the one genuinely new shape the family did not already have a carrier for —
/// the <c>etsiU</c> unprotected-header parameter's own JSON array wire bytes, byte-exact, which
/// <see cref="UnverifiedJwsMessage"/>'s generic unprotected-header dictionary cannot preserve.
/// </summary>
/// <remarks>
/// Must be verified (<see cref="JAdESSignatureValidation.ValidateAsync"/>) before any fact it carries is trusted
/// — <see cref="Wire"/>'s own header/payload/signature content is attacker-controlled until then, exactly like
/// every other <c>Unverified*</c> type in this family.
/// </remarks>
[DebuggerDisplay("UnverifiedJAdESMessage: {Format}")]
public sealed class UnverifiedJAdESMessage: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="UnverifiedJAdESMessage"/>. Ownership of <paramref name="wire"/> and
    /// <paramref name="etsiURawBytes"/>, when supplied, transfers to this instance.
    /// </summary>
    /// <param name="wire">See <see cref="Wire"/>.</param>
    /// <param name="format">See <see cref="Format"/>.</param>
    /// <param name="etsiURawBytes">See <see cref="EtsiURawBytes"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="wire"/> is <see langword="null"/>.</exception>
    public UnverifiedJAdESMessage(UnverifiedJwsMessage wire, JoseSerializationFormat format, PooledMemory? etsiURawBytes)
    {
        ArgumentNullException.ThrowIfNull(wire);

        Wire = wire;
        Format = format;
        EtsiURawBytes = etsiURawBytes;
    }


    /// <summary>
    /// Gets the generic JWS structural facts — the base64url-encoded protected header TEXT, the signature bytes,
    /// the payload, and the attachment state — reusing the EXISTING <c>Unverified*</c> family shape rather than a
    /// JAdES-specific duplicate. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public UnverifiedJwsMessage Wire { get; }

    /// <summary>Gets the JWS serialization form this message was parsed from.</summary>
    public JoseSerializationFormat Format { get; }

    /// <summary>
    /// Gets the <c>etsiU</c> unprotected-header parameter's own JSON array wire bytes (<c>[...]</c>), byte-exact
    /// ("decode/re-encode never touches the imprint input"), or <see langword="null"/> when the parsed
    /// message carries no unprotected header or no <c>etsiU</c> member within it. Owned by this instance when
    /// present; disposed via <see cref="Dispose"/>.
    /// </summary>
    public PooledMemory? EtsiURawBytes { get; }


    /// <summary>Disposes <see cref="Wire"/> and <see cref="EtsiURawBytes"/> when present.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Wire.Dispose();
            EtsiURawBytes?.Dispose();
            disposed = true;
        }
    }
}
