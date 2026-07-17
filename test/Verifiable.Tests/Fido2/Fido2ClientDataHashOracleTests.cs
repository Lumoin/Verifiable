using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests <see cref="Fido2ClientDataHash.Compute"/> against an independent SHA-256 oracle. Every mint and
/// verify path in the suite hashes <c>clientDataJSON</c> through this exact same function on both ends,
/// so a self-consistent defect (algorithm confusion, truncation, an off-by-one byte range) would be
/// invisible to every other assertion/attestation test: signer and verifier would simply agree on the
/// same wrong value. WebAuthn interop requires this value to equal the real SHA-256 of
/// <c>clientDataJSON</c> a genuine browser/authenticator computes, so this file checks it against
/// <see cref="SHA256.HashData(ReadOnlySpan{byte})"/> called directly — outside the
/// <see cref="CryptographicKeyEvents"/>/<c>HashFunctionDelegate</c> seam entirely.
/// </summary>
[TestClass]
internal sealed class Fido2ClientDataHashOracleTests
{
    /// <summary>
    /// <see cref="Fido2ClientDataHash.Compute"/> over a fixed <c>clientDataJSON</c> vector equals the
    /// framework's own <see cref="SHA256.HashData(ReadOnlySpan{byte})"/> over the identical bytes.
    /// </summary>
    [TestMethod]
    public void ComputeEqualsIndependentSha256OracleForAFixedVector()
    {
        byte[] clientDataJson = Encoding.UTF8.GetBytes(
            """{"type":"webauthn.get","challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYX","origin":"https://relyingparty.example"}""");

        using DigestValue hash = Fido2ClientDataHash.Compute(clientDataJson, BaseMemoryPool.Shared);
        byte[] expected = SHA256.HashData(clientDataJson);

        Assert.IsTrue(hash.AsReadOnlySpan().SequenceEqual(expected), "Compute must equal an independently computed SHA-256 digest of the same bytes.");
    }
}
