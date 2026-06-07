using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Verifiable.Tests.X509;

/// <summary>
/// A single certificate in a generated test chain: the certificate itself,
/// its signing key (private side), and the role it plays. Parallel to
/// <see cref="Tests.Federation.FederationTestRingNode"/> on the
/// Federation side. Owns both <see cref="X509Certificate2"/> and the
/// underlying <see cref="ECDsa"/>; disposal cascades.
/// </summary>
internal sealed class X509ChainTestRingNode: IDisposable
{
    /// <summary>The role this node plays in the chain.</summary>
    public X509ChainNodeRole Role { get; }

    /// <summary>The certificate. Owned by this node.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>The node's ECDsa signing key. Owned by this node.</summary>
    public ECDsa SigningKey { get; }


    internal X509ChainTestRingNode(X509ChainNodeRole role, X509Certificate2 certificate, ECDsa signingKey)
    {
        Role = role;
        Certificate = certificate;
        SigningKey = signingKey;
    }


    public void Dispose()
    {
        Certificate.Dispose();
        SigningKey.Dispose();
    }
}


/// <summary>
/// Role classification for an <see cref="X509ChainTestRingNode"/> within a
/// generated chain. Mirrors the trust-anchor / intermediate / leaf roles
/// in real X.509 PKI; useful at test call sites for asserting the
/// right node is being inspected.
/// </summary>
internal enum X509ChainNodeRole
{
    /// <summary>Self-signed trust root. <c>BasicConstraints CA = true</c>.</summary>
    Root,

    /// <summary>Subordinate CA issued by a Root or another Intermediate. <c>CA = true</c>.</summary>
    Intermediate,

    /// <summary>End-entity. <c>CA = false</c>; carries the DNS SAN for OID4VP x509_san_dns: matching.</summary>
    Leaf,
}
