using System;

namespace Verifiable.Core
{
    /// <summary>
    /// Constants used in <see cref="Verifiable.Core.Did.DidDocument"/> to describe cryptographic material suite and method.
    /// </summary>    
    /// <remarks>
    /// A specification defining the usage of specific cryptographic primitives in order to achieve
    /// a particular security goal. These documents are often used to specify verification methods,
    /// digital signature types, their identifiers, and other related properties. 
    /// See more at <see href="https://www.w3.org/TR/did-core/#terminology"/>DID terminology</remarks>.
    public static class CryptoSuiteConstants
    {
        //The following values are declared as 'static readonly' as opposed to 'const'.
        //As a consequence the values are not embedded to assemblies but referenced.
        //This makes ReferenceEqual comparisons work too.
        //As for other examples and explanation, see e.g.
        //<see href="https://github.com/dotnet/aspnetcore/blob/main/src/Http/Http.Abstractions/src/HttpMethods.cs#L9"/>.

        /// <summary>
        /// This means signature material. See more at <see href="https://w3c-ccg.github.io/lds-ed25519-2020/#ed25519verificationkey2020">Ed25519VerificationKey2020</see>.
        /// </summary>
        /// <remarks>
        /// This is similar to <see href="https://w3c-ccg.github.io/lds-ed25519-2018/">Ed25519 Signature 2018</see> and
        /// <see href="https://w3c-ccg.github.io/lds-jws2020/">JSON Web Signature 2020</see>.
        /// Some differences are that <see cref="Ed25519VerificationKey2020"/> uses <c>publicKeyMultibase</c> rather than
        /// detached JWT or <c>publicKeyBase58</c>. It is likely that with <see cref="Ed25519Signature2018"/>
        /// the type element in JSON is <see cref="https://www.w3.org/TR/did-spec-registries/#publickey">publicKey</see> is deprecated.
        /// See more about reasoing at
        /// <see href="https://lists.w3.org/Archives/Public/public-credentials/2020Sep/0008.html">Ed25519 Signature 2020 work item proposal.</see>
        /// </remarks>
        public static readonly string Ed25519VerificationKey2020 = "Ed25519VerificationKey2020";

        /// <summary>
        /// This means encryption material in order to transmit confidential information.
        /// </summary>
        /// <remarks>See more at <see href="https://www.w3.org/">X25519KeyAgreementKey2020</see>.</remarks>
        public static readonly string X25519KeyAgreementKey2020 = "X25519KeyAgreementKey2020";

        /// <summary>
        /// This means encryption material in order to transmit confidential information.
        /// </summary>
        /// <see href="https://www.w3.org/TR/did-spec-registries/#x25519keyagreementkey2019">X25519KeyAgreementKey2019</see>.
        public static readonly string X25519KeyAgreementKey2019 = "X25519KeyAgreementKey2019";

        /// <summary>
        /// This Signature Suite utilizes Detached JWS signatures to provide support for a subset of the digital signature algorithms registered with IANA.
        /// </summary>
        /// <remarks>See more at <see href="https://www.w3.org/TR/did-spec-registries/#jsonwebkey2020">JsonWebKey2020</see>.</remarks>
        public static readonly string JsonWebKey2020 = "JsonWebKey2020";

        /// <summary>
        /// This means signature material. See more at <see href="https://w3c-ccg.github.io/lds-ed25519-2018/">Ed25519 Signature 2018</see>.
        /// </summary>
        public static readonly string Ed25519Signature2018 = "Ed25519Signature2018";

        /// <summary>
        /// This means signature material. See more at <see href="https://www.w3.org/TR/did-spec-registries/#bls12381g1key2020/">Bls12381G1Key2020</see>.
        /// </summary>
        /// <remarks>The suite is <see href="https://w3c-ccg.github.io/ldp-bbs2020/">BBS+ Signatures 2020</see>. See also <see cref="MulticodecHeaders.Bls12381G1G2PublicKey">MulticodecHeaders.Bls12381G1G2PublicKey</see>.</remarks>
        public static readonly string Bls12381G1Key2020 = "Bls12381G1Key2020";


        /// <summary>
        /// Returns a value that indicates if the cryptographic suite material is <paramref name="cryptoSuiteMaterial"/> is <see cref="Ed25519VerificationKey2020"/>.
        /// </summary>
        /// <param name="cryptoSuiteMaterial">The cryptograhic suite material.</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="Ed25519VerificationKey2020"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsEd25519VerificationKey2020(string cryptoSuiteMaterial)
        {
            return Equals(Ed25519VerificationKey2020, cryptoSuiteMaterial);
        }


        /// <summary>
        /// Returns a value that indicates if the cryptographic suite material is <paramref name="cryptoSuiteMaterial"/> is <see cref="X25519KeyAgreementKey2020"/>.
        /// </summary>
        /// <param name="cryptoSuiteMaterial">The cryptograhic suite material.</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="X25519KeyAgreementKey2020"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsX25519KeyAgreementKey2020(string cryptoSuiteMaterial)
        {
            return Equals(X25519KeyAgreementKey2020, cryptoSuiteMaterial);
        }


        /// <summary>
        /// Returns a value that indicates if the cryptographic suite material is <paramref name="cryptoSuiteMaterial"/> is <see cref="X25519KeyAgreementKey2019"/>.
        /// </summary>
        /// <param name="cryptoSuiteMaterial">The cryptograhic suite material</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="X25519KeyAgreementKey2019"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsX25519KeyAgreementKey2019(string cryptoSuiteMaterial)
        {
            return Equals(X25519KeyAgreementKey2019, cryptoSuiteMaterial);
        }


        /// <summary>
        /// Returns a value that indicates if the cryptographic suite material is <paramref name="cryptoSuiteMaterial"/> is <see cref="JsonWebKey2020"/>.
        /// </summary>
        /// <param name="cryptoSuiteMaterial">The cryptograhic suite material</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="JsonWebKey2020"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsJsonWebKey2020(string cryptoSuiteMaterial)
        {
            return Equals(JsonWebKey2020, cryptoSuiteMaterial);
        }


        /// <summary>
        /// Returns a value that indicates if the cryptographic suite material is <paramref name="cryptoSuiteMaterial"/> is <see cref="Ed25519Signature2018"/>.
        /// </summary>
        /// <param name="cryptoSuiteMaterial">The cryptograhic suite material</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="Ed25519Signature2018"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsEd25519Signature2018(string cryptoSuiteMaterial)
        {
            return Equals(Ed25519Signature2018, cryptoSuiteMaterial);
        }


        /// <summary>
        /// Returns a value that indicates if the cryptographic suite material is <paramref name="cryptoSuiteMaterial"/> is <see cref="Bls12381G1Key2020"/>.
        /// </summary>
        /// <param name="cryptoSuiteMaterial">The cryptograhic suite material</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="Bls12381G1Key2020"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsBls12381G1Key2020(string cryptoSuiteMaterial)
        {
            return Equals(Bls12381G1Key2020, cryptoSuiteMaterial);
        }


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match. This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="cryptoSuiteMaterial"></param>
        /// <returns>The equivalent static instance of <paramref name="cryptoSuiteMaterial"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string cryptoSuiteMaterial) => cryptoSuiteMaterial switch
        {
            string _ when IsEd25519VerificationKey2020(cryptoSuiteMaterial) => Ed25519VerificationKey2020,
            string _ when IsX25519KeyAgreementKey2020(cryptoSuiteMaterial) => X25519KeyAgreementKey2020,
            string _ when IsX25519KeyAgreementKey2019(cryptoSuiteMaterial) => X25519KeyAgreementKey2019,
            string _ when IsJsonWebKey2020(cryptoSuiteMaterial) => JsonWebKey2020,
            string _ when IsEd25519Signature2018(cryptoSuiteMaterial) => Ed25519Signature2018,
            string _ when IsBls12381G1Key2020(cryptoSuiteMaterial) => Bls12381G1Key2020,
            string _ => cryptoSuiteMaterial
        };


        /// <summary>
        /// Returns a value that indicates if the Crypto Suites are the same.
        /// </summary>
        /// <param name="cryptoSuiteConstantA">The first crypto suite identifier to compare.</param>
        /// <param name="cryptoSuiteConstantB">The second crypto suite identifier to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the suites are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string cryptoSuiteConstantA, string cryptoSuiteConstantB)
        {
            return object.ReferenceEquals(cryptoSuiteConstantA, cryptoSuiteConstantB) || StringComparer.OrdinalIgnoreCase.Equals(cryptoSuiteConstantA, cryptoSuiteConstantB);
        }
    }
}
