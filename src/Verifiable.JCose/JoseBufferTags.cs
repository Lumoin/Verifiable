namespace Verifiable.JCose;

/// <summary>
/// Buffer-content discriminators and pre-built <see cref="Tag"/> instances for the JOSE byte artifacts
/// this layer owns.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Verifiable.Foundation.BufferTags"/> carries only the format-neutral encodings (JSON, CBOR)
/// and leaves security-envelope roles such as the JWS/JWT protected header to the format owner, reached
/// through the <see cref="BufferKind.Create(int)"/> seam (codes at or above 1000).
/// </para>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="BufferKind"/>
/// <seealso cref="Verifiable.Foundation.BufferTags"/>
public static class JoseBufferTags
{
    /// <summary>
    /// Buffer kind for JWS/JWT protected header bytes (JSON).
    /// </summary>
    public static BufferKind JwtHeaderKind { get; } = BufferKind.Create(1000);

    /// <summary>
    /// Tag for JWS/JWT protected header bytes, carrying <see cref="JwtHeaderKind"/>.
    /// </summary>
    public static Tag JwtHeader { get; } = Tag.Create(JwtHeaderKind);
}
