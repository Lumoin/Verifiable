using Verifiable.Fido2;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Extends the synthetic-bytes extension coverage in <c>AuthenticatorDataReaderTests</c> (which uses a
/// single empty CBOR map, <c>0xA0</c>) with a REALISTIC, hand-encoded canonical CBOR extensions map: a
/// single-entry map carrying a text key and a boolean value, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3,
/// section 6.1: Authenticator Data</see> (the <c>ED</c> flag and the trailing extensions slice) and
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section 9: WebAuthn Extensions</see> (client
/// and authenticator extension outputs are carried as a CBOR map keyed by extension identifier).
/// </summary>
[TestClass]
internal sealed class Fido2AuthenticatorDataExtensionTests
{
    /// <summary>
    /// A single-entry canonical CBOR map <c>{"uvm": true}</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 section 3: Specification of the
    /// CBOR Encoding</see>: map(1) | text(3) "uvm" | simple(true).
    /// </summary>
    private static byte[] RealisticExtensionsMap { get; } = [0xA1, 0x63, 0x75, 0x76, 0x6D, 0xF5];

    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A layout with only the <c>ED</c> flag set (no attested credential data) parses the realistic
    /// extensions map and recovers it byte-exact.
    /// </summary>
    [TestMethod]
    public void ExtensionDataFlagWithARealisticCborMapRoundTripsByteExact()
    {
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: AuthenticatorDataFlags.ExtensionDataIncludedBit,
            signCount: 0,
            extensions: RealisticExtensionsMap);

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.IsTrue(parsed.Flags.ExtensionDataIncluded);
        Assert.IsNull(parsed.AttestedCredentialData);
        Assert.IsTrue(parsed.Extensions.Span.SequenceEqual(RealisticExtensionsMap));
    }


    /// <summary>
    /// A layout with BOTH the attested-credential-data and extension-data flags set parses the attested
    /// credential data and recovers the realistic extensions map byte-exact, immediately following it.
    /// </summary>
    [TestMethod]
    public void AttestedCredentialDataAndARealisticExtensionsMapBothRoundTrip()
    {
        byte[] credentialId = [0xAA, 0xBB, 0xCC, 0xDD];
        byte[] attestedCredentialData = BuildAttestedCredentialData(Guid.NewGuid(), credentialId, EncodeP256CoseKey());
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: (byte)(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit | AuthenticatorDataFlags.ExtensionDataIncludedBit),
            signCount: 1,
            attestedCredentialData: attestedCredentialData,
            extensions: RealisticExtensionsMap);

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.IsNotNull(parsed.AttestedCredentialData);
        Assert.IsTrue(parsed.AttestedCredentialData.CredentialId.AsReadOnlySpan().SequenceEqual(credentialId));
        Assert.IsTrue(parsed.Flags.ExtensionDataIncluded);
        Assert.IsTrue(parsed.Extensions.Span.SequenceEqual(RealisticExtensionsMap));
    }
}
