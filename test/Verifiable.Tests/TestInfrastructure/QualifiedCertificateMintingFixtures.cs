using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Subject-name and key-material builders shared by <see cref="QualifiedCertificateMinting"/>'s conformance
/// and end-to-end test classes: the three-attribute RFC 5280 §4.1.2.4 <c>Name</c> every certificate in either
/// class mints with, and a P-256 key pair normalized to the uncompressed SEC1 point the minter's
/// elliptic-curve <c>subjectPublicKeyInfo</c> branch writes verbatim when handed one already in that form.
/// </summary>
internal static class QualifiedCertificateMintingFixtures
{
    /// <summary>Builds a three-attribute subject name (countryName, organizationName, commonName), one attribute per relative distinguished name.</summary>
    public static IReadOnlyList<IReadOnlyList<DirectoryNameAttribute>> CreateSubjectName(string countryCode, string organizationName, string commonName) =>
    [
        [new DirectoryNameAttribute(WellKnownOids.CountryName, countryCode, UniversalTagNumber.PrintableString)],
        [new DirectoryNameAttribute(WellKnownOids.OrganizationName, organizationName, UniversalTagNumber.PrintableString)],
        [new DirectoryNameAttribute(WellKnownOids.CommonName, commonName, UniversalTagNumber.PrintableString)]
    ];


    /// <summary>
    /// Creates a P-256 key pair through the project's own Microsoft-backed provider, normalizing the public
    /// key from its verification-purpose compressed SEC1 form to the uncompressed <c>0x04 || X || Y</c> point
    /// <see cref="QualifiedCertificateMinting"/> writes into <c>subjectPublicKeyInfo</c> verbatim.
    /// </summary>
    public static (PublicKeyMemory PublicKey, PrivateKeyMemory PrivateKey) CreateP256KeyPair()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(uncompressedPoint.Length);
        uncompressedPoint.CopyTo(owner.Memory.Span);
        var uncompressedPublicKey = new PublicKeyMemory(owner, Tag.Create(CryptoAlgorithm.P256).With(Purpose.Verification).With(EncodingScheme.EcUncompressed));
        keys.PublicKey.Dispose();

        return (uncompressedPublicKey, keys.PrivateKey);
    }
}
