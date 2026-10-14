using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An ES256 DPoP key over a freshly generated P-256 DPoP key pair, distinct from every other DPoP key a test makes,
/// that owns the DPoP key's material and releases it on disposal, so a row that signs proofs with two DPoP keys holds
/// each in one <c>using</c> declaration.
/// </summary>
[DebuggerDisplay("FreshDpopKey alg={Key.Alg,nq}")]
internal sealed class FreshDpopKey: IDisposable
{
    /// <summary>The DPoP key pair the DPoP key signs with; released by <see cref="Dispose"/>.</summary>
    private PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Material { get; }

    /// <summary>Whether the DPoP key's material has been released; a field, since disposal writes it.</summary>
    private bool isDisposed;


    /// <summary>Generates a fresh P-256 DPoP key pair and wraps it as an ES256 DPoP key.</summary>
    public FreshDpopKey()
    {
        Material = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        Key = new DpopKey(Material, WellKnownJwaValues.Es256);
    }


    /// <summary>The ES256 DPoP key whose proofs a row presents.</summary>
    public DpopKey Key { get; }


    /// <summary>Releases the public and the private halves of the DPoP key's material.</summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        Material.PublicKey.Dispose();
        Material.PrivateKey.Dispose();
    }
}
