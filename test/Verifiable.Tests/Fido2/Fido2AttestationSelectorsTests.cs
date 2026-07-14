using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2AttestationSelectors.FromFormats"/>, the dictionary-of-delegates factory that
/// dispatches an <see cref="AttestationVerifyDelegate"/> by the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attstn-fmt-ids">WebAuthn L3 section 8.1</see> attestation
/// statement format identifier — matched case-sensitively per that section's "Implementations MUST match
/// WebAuthn attestation statement format identifiers in a case-sensitive fashion."
/// </summary>
[TestClass]
internal sealed class Fido2AttestationSelectorsTests
{
    /// <summary>Gets or sets the test context.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>A sentinel verifier standing in for a registered <c>packed</c> format handler.</summary>
    private static AttestationVerifyDelegate PackedVerifier { get; } = static (_, _) => ValueTask.FromResult<AttestationResult>(new NoneAttestationResult());

    /// <summary>A sentinel verifier standing in for a registered <c>none</c> format handler, distinct from <see cref="PackedVerifier"/>.</summary>
    private static AttestationVerifyDelegate NoneVerifier { get; } = static (_, _) => ValueTask.FromResult<AttestationResult>(new NoneAttestationResult());


    /// <summary>A registered format returns exactly the delegate it was registered with.</summary>
    [TestMethod]
    public void KnownFormatReturnsTheRegisteredVerifier()
    {
        SelectAttestationVerifierDelegate select = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, PackedVerifier),
            (WellKnownWebAuthnAttestationFormats.None, NoneVerifier));

        AttestationVerifyDelegate? resolved = select(WellKnownWebAuthnAttestationFormats.Packed);

        Assert.AreSame(PackedVerifier, resolved);
    }


    /// <summary>An unregistered format identifier resolves to <see langword="null"/> rather than throwing.</summary>
    [TestMethod]
    public void UnknownFormatReturnsNull()
    {
        SelectAttestationVerifierDelegate select = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, PackedVerifier));

        AttestationVerifyDelegate? resolved = select(WellKnownWebAuthnAttestationFormats.AndroidKey);

        Assert.IsNull(resolved);
    }


    /// <summary>
    /// Format matching is case-sensitive: a registration under <c>"packed"</c> does not resolve a query for
    /// <c>"Packed"</c>.
    /// </summary>
    [TestMethod]
    public void MatchingFormatIdentifiersIsCaseSensitive()
    {
        SelectAttestationVerifierDelegate select = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, PackedVerifier));

        AttestationVerifyDelegate? resolved = select("Packed");

        Assert.IsNull(resolved);
    }


    /// <summary>Registering the same format identifier twice is rejected with <see cref="ArgumentException"/>.</summary>
    [TestMethod]
    public void DuplicateFormatRegistrationThrowsArgumentException()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, PackedVerifier),
            (WellKnownWebAuthnAttestationFormats.Packed, NoneVerifier)));
    }
}
