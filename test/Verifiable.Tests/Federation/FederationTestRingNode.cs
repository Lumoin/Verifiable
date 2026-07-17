using System.Security.Cryptography;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// A single federation entity in the
/// <see cref="FederationTestRing"/> fixture — its identifier, signing key,
/// kid, and JWKS-shaped public-key dictionary suitable for inclusion in
/// an Entity Configuration's <c>jwks</c> claim.
/// </summary>
internal sealed class FederationTestRingNode: IDisposable
{
    /// <summary>The node's Entity Identifier (absolute URL).</summary>
    public EntityIdentifier Identifier { get; }

    /// <summary>The node's ECDsa P-256 signing key. Owned by this node.</summary>
    public ECDsa SigningKey { get; }

    /// <summary>The kid header value used on statements this node signs.</summary>
    public string Kid { get; }

    /// <summary>
    /// JWKS-shaped object suitable for inclusion in a federation
    /// statement's <c>jwks</c> claim. Computed once at construction so the
    /// same canonical bytes round-trip through serialisation.
    /// </summary>
    public IReadOnlyDictionary<string, object> JwksObject { get; }


    internal FederationTestRingNode(
        EntityIdentifier identifier,
        ECDsa signingKey,
        string kid)
    {
        Identifier = identifier;
        SigningKey = signingKey;
        Kid = kid;

        ECParameters parameters = signingKey.ExportParameters(includePrivateParameters: false);
        Dictionary<string, object> jwk = new(StringComparer.Ordinal)
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["kid"] = kid,
            ["alg"] = "ES256",
            ["use"] = "sig",
            ["x"] = TestSetup.Base64UrlEncoder(parameters.Q.X!),
            ["y"] = TestSetup.Base64UrlEncoder(parameters.Q.Y!),
        };

        JwksObject = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["keys"] = new List<object> { jwk }
        };
    }


    public void Dispose()
    {
        SigningKey.Dispose();
    }
}
