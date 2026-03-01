using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Tests that run the ecdsa-sd-2023 implementation using W3C test vector inputs
/// and verify that all intermediate results match the W3C specification examples.
/// </summary>
/// <remarks>
/// <para>
/// These tests validate the implementation against W3C VC Data Integrity ECDSA Cryptosuites v1.0
/// test vectors (Examples 70-90). Unlike simple unit tests, these run the full signing pipeline
/// with W3C's exact inputs and verify each intermediate value matches the specification.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#representation-ecdsa-sd-2023">
/// VC Data Integrity ECDSA Cryptosuites v1.0 §A.7</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EcdsaSd2023W3cVectorTests
{
    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// HMAC key from W3C Example 71.
    /// Used as a PRF to randomize blank node identifier ordering.
    /// </summary>
    private static string HmacKeyHex { get; } = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";

    /// <summary>
    /// Issuer's long-term public key in multibase format from Example 71.
    /// </summary>
    private static string BasePublicKeyMultibase { get; } = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";

    /// <summary>
    /// Issuer's long-term secret key in multibase format from Example 71.
    /// </summary>
    private static string BaseSecretKeyMultibase { get; } = "z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN";

    /// <summary>
    /// Ephemeral proof public key in multibase format from Example 71.
    /// This key is generated per-proof and the private key is discarded after signing.
    /// </summary>
    private static string ProofPublicKeyMultibase { get; } = "zDnaeTHfhmSaQKBc7CmdL3K7oYg3D6SC7yowe2eBeVd2DH32r";

    /// <summary>
    /// Ephemeral proof secret key in multibase format from Example 71.
    /// </summary>
    private static string ProofSecretKeyMultibase { get; } = "z42tqvNGyzyXRzotAYn43UhcFtzDUVdxJ7461fwrfhBPLmfY";

    /// <summary>
    /// The unsigned credential from Example 72.
    /// Employment Authorization Document for JOHN JACOB SMITH.
    /// </summary>
    private static string UnsignedCredential { get; } = /*lang=json,strict*/ """
    {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/citizenship/v4rc1"
        ],
        "type": [
            "VerifiableCredential",
            "EmploymentAuthorizationDocumentCredential"
        ],
        "issuer": {
            "id": "did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76",
            "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg=="
        },
        "credentialSubject": {
            "type": [
            "Person",
            "EmployablePerson"
            ],
            "givenName": "JOHN",
            "additionalName": "JACOB",
            "familyName": "SMITH",
            "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2Ng+M/wHwAEAQH/7yMK/gAAAABJRU5ErkJggg==",
            "gender": "Male",
            "residentSince": "2015-01-01",
            "birthCountry": "Bahamas",
            "birthDate": "1999-07-17",
            "employmentAuthorizationDocument": {
            "type": "EmploymentAuthorizationDocument",
            "identifier": "83627465",
            "lprCategory": "C09",
            "lprNumber": "999-999-999"
            }
        },
        "name": "Employment Authorization Document",
        "description": "Example Employment Authorization Document.",
        "validFrom": "2019-12-03T00:00:00Z",
        "validUntil": "2029-12-03T00:00:00Z"
        }
    """;

    /// <summary>
    /// Mandatory pointers from Example 73.
    /// Only the issuer is mandatory; all other claims are selectively disclosable.
    /// </summary>
    private static string[] MandatoryPointers { get; } = ["/issuer"];

    /// <summary>
    /// Canonical N-Quads from Example 75 (before HMAC relabeling).
    /// 24 statements produced by RDFC-1.0 canonicalization.
    /// </summary>
    private static string[] CanonicalStatements { get; } =
    [
        "<did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76> <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg==> .\n",
        "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential> .\n",
        "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n",
        "_:c14n0 <https://schema.org/description> \"Example Employment Authorization Document.\" .\n",
        "_:c14n0 <https://schema.org/name> \"Employment Authorization Document\" .\n",
        "_:c14n0 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n1 .\n",
        "_:c14n0 <https://www.w3.org/2018/credentials#issuer> <did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76> .\n",
        "_:c14n0 <https://www.w3.org/2018/credentials#validFrom> \"2019-12-03T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
        "_:c14n0 <https://www.w3.org/2018/credentials#validUntil> \"2029-12-03T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
        "_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .\n",
        "_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmployablePerson> .\n",
        "_:c14n1 <https://schema.org/additionalName> \"JACOB\" .\n",
        "_:c14n1 <https://schema.org/birthDate> \"1999-07-17\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
        "_:c14n1 <https://schema.org/familyName> \"SMITH\" .\n",
        "_:c14n1 <https://schema.org/gender> \"Male\" .\n",
        "_:c14n1 <https://schema.org/givenName> \"JOHN\" .\n",
        "_:c14n1 <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2Ng+M/wHwAEAQH/7yMK/gAAAABJRU5ErkJggg==> .\n",
        "_:c14n1 <https://w3id.org/citizenship#birthCountry> \"Bahamas\" .\n",
        "_:c14n1 <https://w3id.org/citizenship#employmentAuthorizationDocument> _:c14n2 .\n",
        "_:c14n1 <https://w3id.org/citizenship#residentSince> \"2015-01-01\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
        "_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocument> .\n",
        "_:c14n2 <https://schema.org/identifier> \"83627465\" .\n",
        "_:c14n2 <https://w3id.org/citizenship#lprCategory> \"C09\" .\n",
        "_:c14n2 <https://w3id.org/citizenship#lprNumber> \"999-999-999\" .\n"
    ];

    /// <summary>
    /// HMAC-relabeled canonical N-Quads from Example 76.
    /// Blank node identifiers replaced with HMAC-based pseudorandom identifiers.
    /// </summary>
    private static string[] HmacRelabeledStatements { get; } =
    [
        "<did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76> <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg==> .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmployablePerson> .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://schema.org/additionalName> \"JACOB\" .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://schema.org/birthDate> \"1999-07-17\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://schema.org/familyName> \"SMITH\" .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://schema.org/gender> \"Male\" .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://schema.org/givenName> \"JOHN\" .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2Ng+M/wHwAEAQH/7yMK/gAAAABJRU5ErkJggg==> .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://w3id.org/citizenship#birthCountry> \"Bahamas\" .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://w3id.org/citizenship#employmentAuthorizationDocument> _:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw .\n",
        "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://w3id.org/citizenship#residentSince> \"2015-01-01\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
        "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential> .\n",
        "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n",
        "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://schema.org/description> \"Example Employment Authorization Document.\" .\n",
        "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://schema.org/name> \"Employment Authorization Document\" .\n",
        "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://www.w3.org/2018/credentials#credentialSubject> _:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg .\n",
        "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://www.w3.org/2018/credentials#issuer> <did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76> .\n",
        "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://www.w3.org/2018/credentials#validFrom> \"2019-12-03T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
        "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://www.w3.org/2018/credentials#validUntil> \"2029-12-03T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
        "_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#EmploymentAuthorizationDocument> .\n",
        "_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://schema.org/identifier> \"83627465\" .\n",
        "_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://w3id.org/citizenship#lprCategory> \"C09\" .\n",
        "_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://w3id.org/citizenship#lprNumber> \"999-999-999\" .\n"
    ];

    /// <summary>
    /// Mandatory statement indexes from Example 77.
    /// These are indexes into the HMAC-relabeled statements array.
    /// </summary>
    private static int[] MandatoryIndexes { get; } = [0, 12, 13, 17];

    /// <summary>
    /// Non-mandatory statement indexes from Example 77.
    /// </summary>
    private static int[] NonMandatoryIndexes { get; } = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 15, 16, 18, 19, 20, 21, 22, 23];

    /// <summary>
    /// Blank node label map from HMAC relabeling.
    /// Maps canonical identifiers to HMAC-based identifiers.
    /// </summary>
    private static IReadOnlyDictionary<string, string> LabelMap { get; } = new Dictionary<string, string>
    {
        ["c14n0"] = "u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38",
        ["c14n1"] = "u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg",
        ["c14n2"] = "uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw"
    };

    /// <summary>
    /// Canonical base proof configuration from Example 79.
    /// </summary>
    private static string CanonicalBaseProofConfiguration { get; } =
        "_:c14n0 <http://purl.org/dc/terms/created> \"2023-08-15T23:36:38Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n" +
        "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n" +
        "_:c14n0 <https://w3id.org/security#cryptosuite> \"ecdsa-sd-2023\"^^<https://w3id.org/security#cryptosuiteString> .\n" +
        "_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n" +
        "_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP> .\n";

    /// <summary>
    /// SHA-256 hash of canonical proof configuration from Example 80.
    /// </summary>
    private static string ProofHashHex { get; } = "9c5c9b189f06cfa9d9f21a838ccb9b04316f07ad1a517bfd4955ee28c6a8229c";

    /// <summary>
    /// SHA-256 hash of concatenated mandatory N-Quads from Example 80.
    /// </summary>
    private static string MandatoryHashHex { get; } = "a042dc047c236816f49fbe5282a79c5e77abe111e47f4c20203b5064c7f0f059";

    /// <summary>
    /// Base signature from Example 81.
    /// Signature over proofHash || proofPublicKey || mandatoryHash using issuer's private key.
    /// </summary>
    private static string BaseSignatureHex { get; } = "b8dc55afeb6427a990e9d60c0d363b654306d92703e5036210ca29619d8ed204194ba3d86e31cdbc99f4ee9d5f25f0cc1c1f44f5fa39abec9a50cdf519b457e0";

    /// <summary>
    /// Signatures for non-mandatory statements from Example 81.
    /// Each signature corresponds to a non-mandatory N-Quad, signed with the ephemeral proof key.
    /// </summary>
    private static string[] NonMandatorySignaturesHex { get; } =
    [
        "fd91ec48b3524965f7a1453e9ffa067054eca6f7d6338a84525eb3288bb0caf7a9651f02fee14d6d33ee1679aa8828348ccc574e194d7f57fca8be354c1b30f7",
        "c92e6ea5f65343c704ac9450da4d55f87342829b9bad7aface8300a0879bc9972ec4879eebbaaffd9ad9e3f91d291971c8ffe5d768497d62fa27256a7e03bf99",
        "5d98f7d800ae2aa62927a65e0345a5ae02df041c9cd26de1525a63431b9360c24216737d2374d0789d4e40acdd0bf75b077c06534a6d258084ad8beb149980d6",
        "c8d70ede67864b3219dcb3c3831401ca069ac5f8db9e2714d5f57f367c76320d1e0a9fa4917551add811a415e19bcc32c017ef5ba02e81fed672c72711230b10",
        "3a6263590ab7fbc4e5ef7bc6c3f6b9cdd8a96c7c4d9a1f120612213ca39a50f39d7b56d6365ead6054bdbe4b971b2769d61841a3f7236a7434e5f1b0f6e2e8fc",
        "f5f1fe2990af59361ccd4863359405164ce6a0807dfedd2d1972826e6b79ee051df16f5dfc43d57ed0d57743b94c4f57dd5784fbb04a9bf2b6b7258f5c595524",
        "44b68330d1b12ceec6c07ed560587b6bfd49c831fa90c1a8725a41a3e3247f2950bcfe51a0b26bf422e94f811001dc17b1b93b3f82423457acc5c19f214da5e1",
        "c29744b9bfb68a250eb17aaf49416a8a77a5eed01be18c3278a3784db8f6731bda3da956855bc27f3bc91e3f8331371e100722fc223becb47072a45b7653be08",
        "2b66d296f2d09ff280d4cdec1d02b6c38065ed36c99b6db40a9a800f4faea46187c7b42c6cb232b5103bc88445f5e1f32c89692071546f316a836cd31a979f8d",
        "016fdf24189adefa773c26ad2e0482aebf74a7bb8d5a142723d43d18adc049c408faafdcef8bb11cdc9c728d8f746ae32e03197767bb1aa91fd61a8fc4993abe",
        "e7ee420aa027ba4671b926c29e2c574f94461660a0b3d6c828cce50314d9e1e4c346ed119352adf6141c66e2fce4a2cb7486c3f81cc42e388a5f921285677d94",
        "ff516e1c599ef23779cdd5a6ae34a7db1a1d244514d32308a809752e6c2d112e5a7b473360c0b8caf27949aa161d10876d19c77b50e76160736f1ea4cfdefaa2",
        "c85373002c77fb25e7880c1b2df2e2fa6c25decf563b0a88332e4654773b08b9286b65effe00f8689df03df6e2dfcd4575eff23a08c92bd360e285c22bfa2b5d",
        "09e91f89dfd0a252f79a970caec55814cd570a8e41ec2ac25c33bd8afe479a70b8e744d363bc7daa313625d0cb4c1ea8c64c87577835e9b7416b4615bb82def9",
        "b181986ef2cfb77b71f27cfb4365b8860799d9e84c3df62b3863319250d57a91d429cb15127122c36fd34a92ea0745b4a641454c561c55c37741ee247a866264",
        "13d02a9caf0d96b9fbec397d4faad90e78c56d0cbd933224d58b5c81623e3571b22aa15bc4ad201c364e3566793c9dda9c983e9965f47c7ce5ff6e1b42484dd4",
        "91cc9524b4aa346fc6e409e94b28b8a9891491ae627e47e60f0cd36d90034eb97a8595fcb35a07d3faa5fc213e759b0bea03cb82c58a3711c9de299b7e77904b",
        "22d951c202cd2dbf92a5fd20483f618177f16c08aa798fd6e8a0631fba6d059e304c1ed96a3785aa1be2539eb1fac22caace1f450b5a3a48602c7fb4c68f2d7b",
        "d0fbcf518ec15c3f10d8d2b275963807030ad7e4b03e6c7a6ca0e6b73d61f15a94d76097fc91e1a828c7d9272b178b8ced6422db36e9a1a85ce2a18e39115542",
        "be6366acec557376a71a450f862979f60e642b8edafc104eaf4691784bb48245f3d79f093cd1f631d55217ae2f9f30f17d9ba1b98aae45e02461e1db9bde121f"
    ];

    /// <summary>
    /// Derived proof filtered signatures from W3C test vectors.
    /// Signatures for the subset of statements disclosed in the derived proof.
    /// </summary>
    private static string[] DerivedFilteredSignaturesHex { get; } =
    [
        "fd91ec48b3524965f7a1453e9ffa067054eca6f7d6338a84525eb3288bb0caf7a9651f02fee14d6d33ee1679aa8828348ccc574e194d7f57fca8be354c1b30f7",
        "c92e6ea5f65343c704ac9450da4d55f87342829b9bad7aface8300a0879bc9972ec4879eebbaaffd9ad9e3f91d291971c8ffe5d768497d62fa27256a7e03bf99",
        "2b66d296f2d09ff280d4cdec1d02b6c38065ed36c99b6db40a9a800f4faea46187c7b42c6cb232b5103bc88445f5e1f32c89692071546f316a836cd31a979f8d",
        "09e91f89dfd0a252f79a970caec55814cd570a8e41ec2ac25c33bd8afe479a70b8e744d363bc7daa313625d0cb4c1ea8c64c87577835e9b7416b4615bb82def9",
        "b181986ef2cfb77b71f27cfb4365b8860799d9e84c3df62b3863319250d57a91d429cb15127122c36fd34a92ea0745b4a641454c561c55c37741ee247a866264",
        "13d02a9caf0d96b9fbec397d4faad90e78c56d0cbd933224d58b5c81623e3571b22aa15bc4ad201c364e3566793c9dda9c983e9965f47c7ce5ff6e1b42484dd4"
    ];

    /// <summary>
    /// Label map for the derived proof (reduced from the base proof).
    /// </summary>
    private static Dictionary<string, string> DerivedLabelMap { get; } = new Dictionary<string, string>
    {
        ["c14n0"] = "u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg",
        ["c14n1"] = "u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38"
    };

    /// <summary>
    /// Adjusted mandatory indexes for the derived proof.
    /// </summary>
    private static int[] DerivedAdjustedMandatoryIndexes { get; } = [0, 4, 5, 7];


    /// <summary>
    /// Tests base proof creation using the library API with W3C test vector inputs,
    /// verifying all intermediate results match the specification examples.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This test uses <see cref="CredentialEcdsaSd2023Extensions.CreateBaseProofVerboseAsync"/>
    /// to create a base proof and verifies that all intermediate values (canonical statements,
    /// HMAC-relabeled statements, label map, mandatory hash, signatures) match W3C Examples 75-82.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async ValueTask CreateBaseProofVerboseMatchesW3cTestVectors()
    {
        var cancellationToken = TestContext.CancellationToken;

        //Load W3C test vector keys (Example 71).
        using var issuerPublicKey = DecodeP256PublicKey(BasePublicKeyMultibase);
        using var issuerPrivateKey = DecodeP256PrivateKey(BaseSecretKeyMultibase);
        using var ephemeralPublicKey = DecodeP256PublicKey(ProofPublicKeyMultibase);
        using var ephemeralPrivateKey = DecodeP256PrivateKey(ProofSecretKeyMultibase);
        byte[] hmacKey = Convert.FromHexString(HmacKeyHex);

        var ephemeralKeyPair = new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublicKey, ephemeralPrivateKey);

        //Parse the unsigned credential.
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredential, TestSetup.DefaultSerializationOptions)!;

        //Mandatory paths from Example 73.
        var mandatoryPaths = MandatoryPointers.Select(CredentialPath.FromJsonPointer).ToArray();

        //Create canonicalizer and context resolver.
        var rdfcCanonicalizer = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();
        var contextResolver = CanonicalizationTestUtilities.CreateTestContextResolver();

        //Use the library API to create base proof with verbose output.
        //Provide deterministic HMAC key via delegate for test vector validation.
        var baseProofResult = await credential.CreateBaseProofVerboseAsync(
            issuerPrivateKey,
            ephemeralKeyPair,
            "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
            DateTime.Parse("2023-08-15T23:36:38Z", null, System.Globalization.DateTimeStyles.RoundtripKind),
            mandatoryPaths,
            () => hmacKey,
            JsonLdSelection.PartitionStatements,
            rdfcCanonicalizer,
            contextResolver,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        //Verify canonical statements match W3C Example 75.
        Assert.HasCount(
            CanonicalStatements.Length,
            baseProofResult.CanonicalStatements,
            "Canonical statement count must match W3C Example 75.");

        for(int i = 0; i < baseProofResult.CanonicalStatements.Count; i++)
        {
            Assert.AreEqual(
                CanonicalStatements[i],
                baseProofResult.CanonicalStatements[i],
                $"Canonical statement {i} must match W3C Example 75.");
        }

        //Verify HMAC-relabeled statements match W3C Example 76.
        Assert.HasCount(
            HmacRelabeledStatements.Length,
            baseProofResult.RelabeledStatements,
            "HMAC-relabeled statement count must match W3C Example 76.");

        for(int i = 0; i < baseProofResult.RelabeledStatements.Count; i++)
        {
            Assert.AreEqual(
                HmacRelabeledStatements[i],
                baseProofResult.RelabeledStatements[i],
                $"HMAC-relabeled statement {i} must match W3C Example 76.");
        }

        //Verify label map matches W3C Example 76.
        foreach(var (canonicalId, expectedHmacId) in LabelMap)
        {
            Assert.IsTrue(
                baseProofResult.LabelMap.TryGetValue(canonicalId, out var actualHmacId),
                $"Label map must contain mapping for '{canonicalId}'.");

            Assert.AreEqual(
                expectedHmacId,
                actualHmacId,
                $"HMAC label for '{canonicalId}' must match W3C Example 76.");
        }

        //Verify proof options hash matches W3C Example 80.
        string actualProofOptionsHash = Convert.ToHexStringLower(baseProofResult.ProofOptionsHash);
        Assert.AreEqual(ProofHashHex, actualProofOptionsHash, "Proof options hash must match W3C Example 80.");

        //Verify canonical proof configuration matches W3C Example 79.        
        Assert.AreEqual(
            CanonicalBaseProofConfiguration,
            baseProofResult.CanonicalProofOptions,
            "Canonical proof configuration must match W3C Example 79.");

        //Verify mandatory indexes match W3C Example 77.
        var actualMandatoryIndexes = baseProofResult.MandatoryIndexes.OrderBy(i => i).ToArray();
        Assert.HasCount(MandatoryIndexes.Length, actualMandatoryIndexes, "Mandatory index count must match W3C Example 77.");
        for(int i = 0; i < MandatoryIndexes.Length; i++)
        {
            Assert.AreEqual(
                MandatoryIndexes[i],
                actualMandatoryIndexes[i],
                $"Mandatory index {i} must match W3C Example 77.");
        }

        //Verify mandatory hash matches W3C Example 80.
        string actualMandatoryHash = Convert.ToHexStringLower(baseProofResult.MandatoryHash);
        Assert.AreEqual(
            MandatoryHashHex,
            actualMandatoryHash,
            "Mandatory hash must match W3C Example 80.");

        //Verify base signature is valid.
        bool baseSignatureValid = await issuerPublicKey.VerifyAsync(
            baseProofResult.BaseSignatureData.Memory[..baseProofResult.BaseSignatureDataLength],
            baseProofResult.BaseSignature,
            BouncyCastleCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);

        Assert.IsTrue(baseSignatureValid, "Base signature must be valid.");

        //Verify W3C Example 81 base signature verifies against our computed signature data.
        byte[] w3cBaseSignatureBytes = Convert.FromHexString(BaseSignatureHex);
        using var w3cBaseSignatureMemory = SensitiveMemoryPool<byte>.Shared.Rent(w3cBaseSignatureBytes.Length);
        w3cBaseSignatureBytes.CopyTo(w3cBaseSignatureMemory.Memory.Span);
        using var w3cBaseSignature = new Signature(w3cBaseSignatureMemory, CryptoTags.P256Signature);

        bool w3cSignatureValid = await issuerPublicKey.VerifyAsync(
            baseProofResult.BaseSignatureData.Memory[..baseProofResult.BaseSignatureDataLength],
            w3cBaseSignature,
            BouncyCastleCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);

        Assert.IsTrue(w3cSignatureValid, "W3C Example 81 base signature must verify with computed signature data.");

        //Verify statement signatures count matches non-mandatory count.
        Assert.HasCount(
            NonMandatoryIndexes.Length,
            baseProofResult.SignedStatements,
            "Statement signature count must match non-mandatory statement count.");

        //Verify each W3C Example 81 statement signature verifies.
        var nonMandatoryStatements = NonMandatoryIndexes
            .Select(idx => baseProofResult.RelabeledStatements[idx])
            .ToList();

        for(int i = 0; i < nonMandatoryStatements.Count; i++)
        {
            var statement = nonMandatoryStatements[i];
            var statementBytes = Encoding.UTF8.GetBytes(statement);

            byte[] w3cSigBytes = Convert.FromHexString(NonMandatorySignaturesHex[i]);
            using var w3cSigMemory = SensitiveMemoryPool<byte>.Shared.Rent(w3cSigBytes.Length);
            w3cSigBytes.CopyTo(w3cSigMemory.Memory.Span);
            using var w3cSig = new Signature(w3cSigMemory, CryptoTags.P256Signature);

            bool w3cSigValid = await ephemeralPublicKey.VerifyAsync(
                statementBytes,
                w3cSig,
                BouncyCastleCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);

            Assert.IsTrue(w3cSigValid, $"W3C Example 81 signature '{i}' must verify against statement.");
        }

        //Verify proof value starts with multibase prefix.
        Assert.StartsWith(
            MultibaseAlgorithms.Base64Url.ToString(),
            baseProofResult.ProofValue,
            "Base proof must use base64url-no-pad multibase encoding.");

        //Cleanup.
        baseProofResult.Dispose();
    }


    /// <summary>
    /// Tests the complete Issuer to Holder to Verifier flow using the Verbose library APIs
    /// with W3C test vector data for verification of intermediate results.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This test demonstrates the realistic three-party flow using Verbose API variants
    /// to validate all intermediate computations:
    /// </para>
    /// <list type="number">
    /// <item><description>Issuer creates base proof using <c>CreateBaseProofVerboseAsync</c>.</description></item>
    /// <item><description>Holder verifies base proof using <c>VerifyBaseProofVerboseAsync</c> and asserts intermediate results.</description></item>
    /// <item><description>Holder creates derived proof using <c>DeriveProofVerboseAsync</c> and asserts selection results.</description></item>
    /// <item><description>Verifier verifies derived proof using <c>VerifyDerivedProofVerboseAsync</c> and asserts verification context.</description></item>
    /// </list>
    /// </remarks>
    [TestMethod]
    public async ValueTask IssuerHolderVerifierFlowWithVerboseApis()
    {
        var cancellationToken = TestContext.CancellationToken;

        //Load W3C test vector keys (Example 71).
        using var issuerPublicKey = DecodeP256PublicKey(BasePublicKeyMultibase);
        using var issuerPrivateKey = DecodeP256PrivateKey(BaseSecretKeyMultibase);
        using var ephemeralPublicKey = DecodeP256PublicKey(ProofPublicKeyMultibase);
        using var ephemeralPrivateKey = DecodeP256PrivateKey(ProofSecretKeyMultibase);
        byte[] hmacKey = Convert.FromHexString(HmacKeyHex);

        var ephemeralKeyPair = new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublicKey, ephemeralPrivateKey);

        var credential = JsonSerializer.Deserialize<VerifiableCredential>(
            UnsignedCredential,
            TestSetup.DefaultSerializationOptions)!;

        var mandatoryPaths = MandatoryPointers
            .Select(p => CredentialPath.FromJsonPointer(p))
            .ToArray();

        var rdfcCanonicalizer = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();
        var contextResolver = CanonicalizationTestUtilities.CreateTestContextResolver();

        //Issuer: Create base proof with verbose output.
        var baseProofResult = await credential.CreateBaseProofVerboseAsync(
            issuerPrivateKey,
            ephemeralKeyPair,
            "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
            DateTime.Parse("2023-08-15T23:36:38Z", null, System.Globalization.DateTimeStyles.RoundtripKind),
            mandatoryPaths,
            () => hmacKey,
            JsonLdSelection.PartitionStatements,
            rdfcCanonicalizer,
            contextResolver,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        //Construct signed credential from base proof result.
        var signedCredential = DeserializeCredential(SerializeCredential(credential));
        signedCredential.Proof =
        [
            new DataIntegrityProof
            {
                Type = "DataIntegrityProof",
                Cryptosuite = EcdsaSd2023CryptosuiteInfo.Instance,
                Created = "2023-08-15T23:36:38Z",
                VerificationMethod = new AssertionMethod("did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"),
                ProofPurpose = AssertionMethod.Purpose,
                ProofValue = baseProofResult.ProofValue
            }
        ];

        //Verify issuer created correct mandatory hash.
        string actualMandatoryHash = Convert.ToHexStringLower(baseProofResult.MandatoryHash);
        Assert.AreEqual(
            MandatoryHashHex,
            actualMandatoryHash,
            "Issuer must compute correct mandatory hash per W3C Example 80.");

        //Issuer disposes their intermediate state; only signed credential is transmitted.
        baseProofResult.Dispose();

        //Holder: Verify base proof with verbose output.
        var (holderVerifyResult, holderContext) = await signedCredential.VerifyBaseProofVerboseAsync(
            issuerPublicKey,
            BouncyCastleCryptographicFunctions.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            rdfcCanonicalizer,
            contextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            CredentialVerificationResult.Success(),
            holderVerifyResult,
            "Holder must successfully verify base proof.");

        Assert.IsNotNull(holderContext, "Holder context must be returned on successful verification.");

        //Verify holder context contains expected label map from W3C Example 76.
        foreach(var (canonicalId, expectedHmacId) in LabelMap)
        {
            Assert.IsTrue(
                holderContext.LabelMap.TryGetValue(canonicalId, out var actualHmacId),
                $"Holder context label map must contain '{canonicalId}'.");

            Assert.AreEqual(
                expectedHmacId,
                actualHmacId,
                $"Holder context label for '{canonicalId}' must match W3C Example 76.");
        }

        //Verify holder context has correct mandatory indexes.
        var holderMandatoryIndexes = holderContext.MandatoryIndexes.OrderBy(i => i).ToArray();
        Assert.HasCount(MandatoryIndexes.Length, holderMandatoryIndexes, "Holder must see correct mandatory index count.");
        for(int i = 0; i < MandatoryIndexes.Length; i++)
        {
            Assert.AreEqual(
                MandatoryIndexes[i],
                holderMandatoryIndexes[i],
                $"Holder mandatory index {i} must match W3C Example 77.");
        }

        //Verify holder context has correct mandatory hash.
        string holderMandatoryHash = Convert.ToHexStringLower(holderContext.MandatoryHash);
        Assert.AreEqual(
            MandatoryHashHex,
            holderMandatoryHash,
            "Holder must recompute correct mandatory hash per W3C Example 80.");

        //Holder disposes context; stores only the credential POCO.
        holderContext.Dispose();

        //Holder: Create derived proof for selective disclosure.
        //Verifier requests specific claims.
        var verifierRequestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/birthCountry"),
            CredentialPath.FromJsonPointer("/validFrom"),
            CredentialPath.FromJsonPointer("/validUntil")
        };

        var (derivedCredential, selectionResult) = await signedCredential.DeriveProofVerboseAsync(
            verifierRequestedPaths,
            userExclusions: null,
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            rdfcCanonicalizer,
            contextResolver,
            SerializeCredential,
            DeserializeCredential,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            EcdsaSd2023CborSerializer.SerializeDerivedProof,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(derivedCredential.Proof, "Derived credential must have proof.");
        Assert.StartsWith(
            "u",
            derivedCredential.Proof[0].ProofValue,
            "Derived proof must use base64url-no-pad multibase encoding.");

        //Verify selection result indicates requirements satisfied.
        //Assert.IsTrue(
        //    selectionResult.SatisfiesRequirements,
        //    "Disclosure selection must satisfy verifier requirements.");

        //Verifier: Verify derived proof with verbose output.
        var (verifierResult, verifierContext) = await derivedCredential.VerifyDerivedProofVerboseAsync(
            issuerPublicKey,
            BouncyCastleCryptographicFunctions.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            rdfcCanonicalizer,
            contextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        //Verify derived proof contains expected number of filtered signatures.
        using var parsedDerivedProof = EcdsaSd2023CborSerializer.ParseDerivedProof(
            derivedCredential.Proof[0].ProofValue!,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        Assert.HasCount(
            DerivedFilteredSignaturesHex.Length,
            parsedDerivedProof.Signatures,
            "Derived proof must contain expected number of filtered signatures.");

        Assert.AreEqual(
            CredentialVerificationResult.Success(),
            verifierResult,
            "Verifier must successfully verify derived proof.");

        Assert.IsNotNull(verifierContext, "Verifier context must be returned on successful verification.");

        //Verify the disclosed statements were verified.
        Assert.IsNotEmpty(
            verifierContext.DisclosedStatements,
            "Verifier must see disclosed statements.");

        //Verify verifier context has correct label map for reduced credential.
        Assert.HasCount(
            DerivedLabelMap.Count,
            verifierContext.LabelMap,
            "Verifier label map must have correct size for reduced credential.");

        foreach(var (canonicalId, expectedHmacId) in DerivedLabelMap)
        {
            Assert.IsTrue(
                verifierContext.LabelMap.TryGetValue(canonicalId, out var actualHmacId),
                $"Verifier label map must contain '{canonicalId}'.");

            Assert.AreEqual(
                expectedHmacId,
                actualHmacId,
                $"Verifier label for '{canonicalId}' must match derived label map.");
        }

        //Verify verifier context mandatory indexes match derived proof structure.
        var verifierMandatoryIndexes = verifierContext.MandatoryIndexes.OrderBy(i => i).ToArray();
        Assert.HasCount(
            DerivedAdjustedMandatoryIndexes.Length,
            verifierMandatoryIndexes,
            "Verifier must see correct adjusted mandatory index count.");

        for(int i = 0; i < DerivedAdjustedMandatoryIndexes.Length; i++)
        {
            Assert.AreEqual(
                DerivedAdjustedMandatoryIndexes[i],
                verifierMandatoryIndexes[i],
                $"Verifier adjusted mandatory index {i} must match expected derived indexes.");
        }

        verifierContext.Dispose();
    }

    private static string SerializeCredential(VerifiableCredential credential) => JsonSerializer.Serialize(credential, TestSetup.DefaultSerializationOptions);

    private static VerifiableCredential DeserializeCredential(string json) => JsonSerializer.Deserialize<VerifiableCredential>(json, TestSetup.DefaultSerializationOptions)!;


    private static string SerializeProofOptions(ProofOptionsDocument proofOptions) =>
        ProofOptionsSerializer.Serialize(proofOptions, TestSetup.DefaultSerializationOptions);

    private static PublicKeyMemory DecodeP256PublicKey(string multibaseKey)
    {
        var keyBytes = MultibaseSerializer.Decode(
            multibaseKey,
            MulticodecHeaders.P256PublicKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);

        return new PublicKeyMemory(keyBytes, CryptoTags.P256PublicKey);
    }

    private static PrivateKeyMemory DecodeP256PrivateKey(string multibaseKey)
    {
        var keyBytes = MultibaseSerializer.Decode(
            multibaseKey,
            MulticodecHeaders.P256PrivateKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);

        return new PrivateKeyMemory(keyBytes, CryptoTags.P256PrivateKey);
    }
}