using System.Buffers.Binary;
using Verifiable.Fido2;
using Verifiable.JCose;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Boundary-case tests for <see cref="AuthenticatorDataReader.Read"/> that
/// <see cref="AuthenticatorDataReaderTests"/> and <see cref="AuthenticatorDataReaderPropertyTests"/> do not
/// cover: the exact-bound (1023-byte) credential ID length and the unrecognised-<c>kty</c> exception-type
/// wrap, both per WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">section 6.5.1</see>.
/// </summary>
[TestClass]
internal sealed class AuthenticatorDataReaderBoundaryTests
{
    /// <summary>The largest permitted credential ID length per section 7.1 step 25.</summary>
    private const int MaximumCredentialIdLength = 1023;

    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A <c>credentialIdLength</c> of exactly 1023 — the section 7.1 step 25 upper bound itself — is
    /// accepted, and the recovered credential ID matches the wire bytes exactly. Complements
    /// <see cref="AuthenticatorDataReaderTests.CredentialIdLengthOneOverTheBoundIsRejected"/> (1024
    /// rejected) and <c>AuthenticatorDataReaderPropertyTests</c>' [1024,65535] rejection range: neither
    /// proves the bound itself is accepted, so a <c>&gt;</c>-to-<c>&gt;=</c> mutation on the bound check
    /// would silently reject the spec's own legal upper bound.
    /// </summary>
    [TestMethod]
    public void CredentialIdLengthAtTheBoundIsAccepted()
    {
        byte[] credentialId = new byte[MaximumCredentialIdLength];
        for(int i = 0; i < credentialId.Length; i++)
        {
            credentialId[i] = (byte)(i % 256);
        }

        byte[] attestedCredentialData = BuildAttestedCredentialData(Guid.NewGuid(), credentialId, EncodeP256CoseKey());
        byte[] authenticatorData = BuildAuthenticatorData(CreateRpIdHash(), flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit, signCount: 0, attestedCredentialData: attestedCredentialData);

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.IsNotNull(parsed.AttestedCredentialData);
        Assert.IsTrue(parsed.AttestedCredentialData.CredentialId.AsReadOnlySpan().SequenceEqual(credentialId));
    }


    /// <summary>
    /// A credential public key whose <c>kty</c> is outside the WebAuthn L3 section 6.5.1 clause set
    /// (EC2/OKP/RSA) is rejected with exactly <see cref="Fido2FormatException"/> — never the underlying
    /// <see cref="ArgumentOutOfRangeException"/> <see cref="CoseKeyConformance.AllowedParameterLabels"/>
    /// raises for an unrecognised key type — proving <see cref="AuthenticatorDataReader.Read"/>'s own
    /// catch/wrap around that call, not merely the underlying table's throw
    /// (<c>CoseKeyConformanceTests</c> already covers that in isolation). Uses a stub
    /// <see cref="ReadCredentialPublicKeyDelegate"/> reporting <see cref="CoseKeyTypes.Symmetric"/> — a
    /// <c>kty</c> value real authenticators never emit for a credential public key, but which the parser
    /// must still fail closed against with the promised exception type.
    /// </summary>
    [TestMethod]
    public void UnrecognisedKtyIsRejectedAsFido2FormatExceptionNotArgumentOutOfRange()
    {
        byte[] credentialIdLengthBytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(credentialIdLengthBytes, 2);
        byte[] attestedCredentialData = Concat(new byte[16], credentialIdLengthBytes, new byte[] { 0x01, 0x02 }, new byte[5]);
        byte[] authenticatorData = BuildAuthenticatorData(CreateRpIdHash(), flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit, signCount: 0, attestedCredentialData: attestedCredentialData);

        ReadCredentialPublicKeyDelegate stubReader = source => new CredentialPublicKeyReadResult(new CoseKey(CoseKeyTypes.Symmetric), 1, []);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => AuthenticatorDataReader.Read(authenticatorData, stubReader, BaseMemoryPool.Shared));

        Assert.Contains("unsupported key type", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.IsInstanceOfType<ArgumentOutOfRangeException>(exception.InnerException);
    }
}
