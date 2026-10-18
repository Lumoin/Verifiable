using Verifiable.JCose;
using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The access-token side's readings for the resource-server test infrastructure: the library's own
/// (<see cref="JwsAccessTokenJsonParser.Default"/>), and the parts of a token a row reads directly, each
/// read through the same readings and required to be read.
/// </summary>
internal static class JwsAccessTokenTestSupport
{
    /// <summary>The library's readings of a signed JWT's header and claims.</summary>
    public static JwsAccessTokenJsonParser Parser { get; } = JwsAccessTokenJsonParser.Default;


    /// <summary>The header a decoded header segment reads to, through <see cref="Parser"/>; a refused one fails the row.</summary>
    /// <param name="bytes">The decoded header segment.</param>
    /// <returns>The header.</returns>
    public static JwtHeader HeaderOf(ReadOnlyMemory<byte> bytes) =>
        Assert.IsInstanceOfType<JwtPartRead<JwtHeader>>(Parser.ParseHeader(bytes), "The header reads to one JSON object.").Part;


    /// <summary>The claims set a decoded payload segment reads to, through <see cref="Parser"/>; a refused one fails the row.</summary>
    /// <param name="bytes">The decoded payload segment.</param>
    /// <returns>The claims set.</returns>
    public static JwtPayload PayloadOf(ReadOnlyMemory<byte> bytes) =>
        Assert.IsInstanceOfType<JwtPartRead<JwtPayload>>(Parser.ParseClaims(bytes), "The claims set reads to one JSON object.").Part;
}
