using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Per-call inputs for
/// <see cref="AuthCodeClient.StartJarAuthorizeAsync"/> — the JAR-by-value
/// direct authorization flow per RFC 9101 §6.1. The client signs a JAR with
/// the AuthCode claims and constructs a redirect URL whose query carries
/// <c>request=&lt;compact-jws&gt;</c> and the outer <c>client_id</c>; the user
/// agent follows the URL to the Authorization Server's authorize endpoint.
/// </summary>
[DebuggerDisplay("AuthCodeStartJarAuthorizeOptions")]
public sealed record AuthCodeStartJarAuthorizeOptions
{
    /// <summary>The space-separated scope string carried into the JAR's <c>scope</c> claim.</summary>
    public required string Scope { get; init; }

    /// <summary>The client's JAR signing key. Tag determines the JWS <c>alg</c>.</summary>
    public required PrivateKeyMemory SigningKey { get; init; }

    /// <summary>The <c>kid</c> header parameter value identifying <see cref="SigningKey"/>.</summary>
    public required string SigningKeyId { get; init; }

    /// <summary>Serialises the JAR protected header to UTF-8 JSON bytes.</summary>
    public required JwtHeaderSerializer HeaderSerializer { get; init; }

    /// <summary>Serialises the JAR payload claims to UTF-8 JSON bytes.</summary>
    public required JwtPayloadSerializer PayloadSerializer { get; init; }

    /// <summary>Memory pool for transient signing buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }

    /// <summary>
    /// Open-ended additional outer query fields appended to the constructed
    /// authorize redirect URL. The outer <c>client_id</c> and <c>request</c>
    /// fields are added automatically.
    /// </summary>
    public OAuthFormEncodedFields AdditionalFields { get; init; } = OAuthFormEncodedFields.Empty;

    /// <summary>Optional <c>nonce</c> claim value. When <see langword="null"/>, the handler generates one.</summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// The JAR's lifetime — used to compute the <c>exp</c> claim relative to
    /// <c>iat</c>. Defaults to thirty seconds; servers commonly cap JAR
    /// lifetimes at one minute per RFC 9101 §10.2 guidance.
    /// </summary>
    public TimeSpan JarLifetime { get; init; } = TimeSpan.FromSeconds(30);
}
