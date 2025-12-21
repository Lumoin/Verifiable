using System.Text;
using Verifiable.Cryptography;

namespace Verifiable.Jose
{
    /// <summary>
    /// Adds a JWT attribute to the JWT. The purpose of this delegate is to have a common signature
    /// to add attributes to the JWT, regardless of the JWT type.
    /// </summary>
    /// <typeparam name="TJwtValue">The type of the value to add to the JWT.</typeparam>
    /// <typeparam name="TJwt">The type of JWT object.</typeparam>
    /// <param name="attribute">The JWT attribute.</param>
    /// <param name="value">The JWT value.</param>
    /// <param name="jwt">The JWT.</param>
    public delegate void JwtAttributeAdder<in TJwtValue, in TJwt>(string attribute, TJwtValue value, TJwt jwt);

    /// <summary>
    /// Delegate to decode a signature to a JWT part.
    /// </summary>
    /// <typeparam name="TSignature">The type of signature.</typeparam>
    /// <typeparam name="TJwtPart">The type of JWT part.</typeparam>
    /// <param name="encodedPart">The encoded JWT part.</param>
    /// <returns>The JWT part after decoding it.</returns>
    public delegate TJwtPart JwtPartDecoder<TSignature, TJwtPart>(TSignature encodedPart);

    /// <summary>
    /// Delegate to decode a signature to a JWT part.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT part.</typeparam>
    /// <param name="encodedPart">The encoded JWT part.</param>
    /// <returns>The decoded JWT part.</returns>
    public delegate TJwtPart JwtPartDecoder<TJwtPart>(ReadOnlySpan<byte> encodedPart);

    /// <summary>
    /// Encodes a JWT part to its byte representation. Likely to be Base64 URL encoded in subsequent phases.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT part.</typeparam>
    /// <param name="part">The JWT part.</param>
    /// <returns>Byte representation of the <paramref name="part"/> encoded as bytes.</returns>
    public delegate ReadOnlySpan<byte> JwtPartByteEncoder<in TJwtPart>(TJwtPart part);

    /// <summary>
    /// Encodes JWT part to its Base64 URL encoded representation.
    /// </summary>
    /// <typeparam name="TJwtPart">The type of JWT part.</typeparam>
    /// <param name="byteEncoder">Encodes <paramref name="part"/> to its byte representation.</param>
    /// <param name="base64UrlEncoder">The Base64 encoder to be used in encoding.</param>
    /// <param name="part">The actual JWT part to encode.</param>
    /// <returns>Base64 encoded representation of <paramref name="part"/>.</returns>
    public delegate string JwtPartBase64Encoder<TJwtPart>(JwtPartByteEncoder<TJwtPart> byteEncoder, EncodeDelegate base64UrlEncoder, TJwtPart part);

    /// <summary>
    /// Selects key identifier from a JWT part.
    /// </summary>
    /// <typeparam name="TJwtPart">The JWT part type.</typeparam>
    /// <typeparam name="TKeyIdentifier">The key identifier type.</typeparam>
    /// <param name="part">The JWT part from which to choose the key identifier.</param>
    /// <returns>The key identifier.</returns>
    public delegate TKeyIdentifier KeyIdentifierSelector<TJwtPart, TKeyIdentifier>(TJwtPart part);

    /// <summary>
    /// Provides the cryptographic context based on the JWT header and key identifier to handle key material.
    /// </summary>
    /// <typeparam name="TJwtPart">The JWT part type.</typeparam>
    /// <typeparam name="TKeyIdentifier">The key identifier type.</typeparam>
    /// <typeparam name="TCryptoContext">The cryptographic context type.</typeparam>
    /// <param name="header">The JWT header.</param>
    /// <param name="keyIdentifier">The key identifier.</param>
    /// <returns>The crypto context.</returns>
    public delegate TCryptoContext CryptoContextLoader<TJwtPart, TKeyIdentifier, TCryptoContext>(TJwtPart header, TKeyIdentifier keyIdentifier);

    /// <summary>
    /// Verifies <paramref name="dataToVerify"/> with <paramref name="signature"/> using the given <paramref name="publicKeyMaterial"/>.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="dataToVerify">Data to verify.</param>
    /// <param name="signature">Signature used in the operation.</param>
    /// <param name="publicKeyMaterial">Public key material to be used in the operation.</param>
    /// <returns><see langword="true"/> if the verification succeeds; <see langword="false"/> otherwise.</returns>
    public delegate bool VerifyImplementation<TResult>(ReadOnlySpan<TResult> dataToVerify, ReadOnlySpan<TResult> signature, ReadOnlySpan<byte> publicKeyMaterial);

    /// <summary>
    /// Matches a concrete implementation of cryptographic functions to given set of parameters carried in the <paramref name="cryptoContext"/>.
    /// </summary>
    /// <typeparam name="TCryptoContext">The cryptographic context type.</typeparam>
    /// <typeparam name="TSignature">The signature type of the cryptographic operation.</typeparam>
    /// <param name="cryptoContext">The crypto context.</param>
    /// <returns>A function that matches parameters to a concrete cryptographic implementation to verify the signature.</returns>
    public delegate VerifyImplementation<TSignature> VerifyImplementationMatcher<TCryptoContext, TSignature>(TCryptoContext cryptoContext) where TCryptoContext : CryptoContext;

    /// <summary>
    /// Signs <paramref name="dataToSign"/> with <paramref name="privateKeyBytes"/>.
    /// </summary>
    /// <typeparam name="TData">The data type.</typeparam>
    /// <param name="privateKeyBytes">The private key material.</param>
    /// <param name="dataToSign">The data to sign.</param>
    /// <returns>The signature bytes.</returns>
    public delegate ReadOnlySpan<byte> SignImplementation<TData>(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<TData> dataToSign);

    /// <summary>
    /// Signs <paramref name="dataToSign"/> with <paramref name="cryptoContext"/>.
    /// </summary>
    /// <typeparam name="TCryptoContext">The cryptographic context type. This holds information needed to choose the
    /// actual signing function and implement it. This is user provided.</typeparam>
    /// <typeparam name="TData">The data type.</typeparam>
    /// <param name="cryptoContext">Information to choose and use private key material.</param>
    /// <param name="dataToSign">The data to sign.</param>
    /// <returns>The signature bytes.</returns>
    public delegate ReadOnlySpan<byte> SignImplementation<TCryptoContext, TData>(TCryptoContext cryptoContext, ReadOnlySpan<TData> dataToSign);

    /// <summary>
    /// Matches a concrete implementation of cryptographic functions to given set of parameters carried in the <paramref name="cryptoContext"/>.
    /// </summary>
    /// <typeparam name="TCryptoContext">The cryptographic context type.</typeparam>
    /// <typeparam name="TData">The type of the data to sign.</typeparam>
    /// <param name="cryptoContext">The crypto context.</param>
    /// <returns>A function that matches parameters to a concrete cryptographic implementation to sign the data.</returns>
    public delegate SignImplementation<byte> SignImplementationMatcher<TCryptoContext, TData>(TCryptoContext cryptoContext) where TCryptoContext : CryptoContext;

    /// <summary>
    /// Matches a concrete implementation of cryptographic functions to given set of parameters carried in the <paramref name="cryptoContext"/>.
    /// </summary>
    /// <typeparam name="TCryptoContext">The cryptographic context type.</typeparam>
    /// <typeparam name="TData">The type of the data to sign.</typeparam>
    /// <typeparam name="TSignature">The signature type.</typeparam>
    /// <param name="cryptoContext">The crypto context.</param>
    /// <returns>A function that matches parameters to a concrete cryptographic implementation to sign the data.</returns>
    public delegate SignImplementation<TSignature> SignImplementationMatcher<TCryptoContext, TData, TSignature>(TCryptoContext cryptoContext) where TCryptoContext : CryptoContext;


    /// <summary>
    /// Verifies the signature of a JWT.
    /// </summary>
    /// <typeparam name="TJwtPart">The JWT part type.</typeparam>
    /// <typeparam name="TCryptoContext">The cryptographic context type.</typeparam>
    /// <typeparam name="TKeyIdentifier">The key identifier type.</typeparam>
    /// <typeparam name="TDataToVerify">The type of data to verify.</typeparam>
    /// <typeparam name="TSignature">The type of signature.</typeparam>
    /// <typeparam name="TJwtPartHeader">The JWT header type.</typeparam>
    /// <typeparam name="TJwtPartPayload">The JWT payload type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="keyIdentifierSelector">Selects key identifier from a JWT part.</param>
    /// <param name="cryptoContextLoader">Provides the cryptographic context based on the JWT header and key identifier to handle key material.</param>
    /// <param name="matcherDelegate">Matches a concrete implementation of cryptographic functions to given set of parameters returned by <paramref name="cryptoContextLoader"/>.</param>
    /// <param name="dataToVerify">The data to verify.</param>
    /// <param name="signatureBytes">The signature of the <paramref name="dataToVerify"/>.</param>
    /// <param name="header">The header value.</param>
    /// <param name="payload">The payload value.</param>
    /// <returns><see langword="true"/> if the verification succeeds; <see langword="false"/> otherwise.</returns>
    public delegate ValueTask<TResult> Verify<TJwtPart, TCryptoContext, TKeyIdentifier, TDataToVerify, TSignature, TJwtPartHeader, TJwtPartPayload, TResult>(
        KeyIdentifierSelector<TJwtPartHeader, TKeyIdentifier> keyIdentifierSelector,
        CryptoContextLoader<TJwtPart, TKeyIdentifier, TCryptoContext> cryptoContextLoader,
        VerifyImplementationMatcher<TCryptoContext, TSignature> matcherDelegate,
        ReadOnlySpan<TDataToVerify> dataToVerify,
        TSignature signatureBytes,
        TJwtPartHeader header,
        TJwtPartPayload payload) where TCryptoContext : CryptoContext;

    /// <summary>
    /// Verifies the signature of a JWT.
    /// </summary>
    /// <typeparam name="TJwtPart">The JWT part type.</typeparam>
    /// <typeparam name="TCryptoContext">The cryptographic context type.</typeparam>
    /// <typeparam name="TKeyIdentifier">The key identifier type.</typeparam>
    /// <typeparam name="TDataToVerify">The type of data to verify.</typeparam>
    /// <typeparam name="TJwtPartHeader">The JWT header type.</typeparam>
    /// <typeparam name="TJwtPartPayload">The JWT payload type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="keyIdentifierSelector">Selects key identifier from a JWT part.</param>
    /// <param name="cryptoContextLoader">Provides the cryptographic context based on the JWT header and key identifier to handle key material.</param>
    /// <param name="matcherDelegate">Matches a concrete implementation of cryptographic functions to given set of parameters returned by <paramref name="cryptoContextLoader"/>.</param>
    /// <param name="dataToVerify">The data to verify.</param>
    /// <param name="signatureBytes">The signature of the <paramref name="dataToVerify"/>.</param>
    /// <param name="header">The header value.</param>
    /// <param name="payload">The payload value.</param>
    /// <returns><see langword="true"/> if the verification succeeds; <see langword="false"/> otherwise.</returns>
    public delegate ValueTask<TResult> Verify<TJwtPart, TCryptoContext, TKeyIdentifier, TDataToVerify, TJwtPartHeader, TJwtPartPayload, TResult>(
        KeyIdentifierSelector<TJwtPartHeader, TKeyIdentifier> keyIdentifierSelector,
        CryptoContextLoader<TJwtPart, TKeyIdentifier, TCryptoContext> cryptoContextLoader,
        VerifyImplementationMatcher<TCryptoContext, byte> matcherDelegate,
        ReadOnlySpan<TDataToVerify> dataToVerify,
        ReadOnlySpan<byte> signatureBytes,
        TJwtPartHeader header,
        TJwtPartPayload payload) where TCryptoContext : CryptoContext;

    /// <summary>
    /// Signs data with private key bytes.
    /// </summary>
    /// <typeparam name="TPrivateKeyBytes">The type of the objects in the read-only span. Likely <see cref="byte"/>.</typeparam>
    /// <typeparam name="TDataToSign">The data type from which to calculate signature. Likely <see cref="byte"/>.</typeparam>
    /// <typeparam name="TResult">The result of verification type.</typeparam>
    /// <param name="privateKeyTypes">The private key bytes representation.</param>
    /// <param name="dataToSign">The data to calculate a signature from.</param>
    /// <returns>Result of signing.</returns>
    public delegate ReadOnlySpan<TResult> Sign<TPrivateKeyBytes, TDataToSign, TResult>(ReadOnlySpan<TPrivateKeyBytes> privateKeyTypes, ReadOnlySpan<TDataToSign> dataToSign);

    /// <summary>
    /// Selects signing implementation based on JWT header.
    /// </summary>
    /// <typeparam name="TJwtPart">The JWT part type.</typeparam>
    /// <typeparam name="TPrivateKeyBytes">The private key bytes type.</typeparam>
    /// <typeparam name="TDataToSign">The data to sign type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="jwtHeader">The JWT header.</param>
    /// <returns>The signing delegate.</returns>
    public delegate Sign<TPrivateKeyBytes, TDataToSign, TResult> SigningSelector<TJwtPart, TPrivateKeyBytes, TDataToSign, TResult>(TJwtPart jwtHeader);


    /// <summary>
    /// Loads private key bytes.
    /// </summary>
    /// <typeparam name="TPrivateKey">The private key type.</typeparam>
    /// <returns>The private key bytes.</returns>
    public delegate ReadOnlySpan<TPrivateKey> LoadPrivateKey<TPrivateKey>();


    /// <summary>
    /// Holds cryptographic context for JWT operations.
    /// </summary>
    public class CryptoContext
    {
        /// <summary>
        /// Gets or sets the discriminator for context type identification.
        /// </summary>
        public virtual string Discriminator { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the algorithm identifier.
        /// </summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the key material.
        /// </summary>
        public byte[] Key { get; set; } = [];

        /// <summary>
        /// Gets or sets additional parameters.
        /// </summary>
        public IDictionary<string, object> Parameters { get; set; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets or sets the key format. Here '0' means raw format, 'R' and 'S' values concatenated as in JWT.
        /// Not applicable to other algorithms than ECDSA.
        /// </summary>
        public int KeyFormat { get; set; } = 0;

        /// <summary>
        /// Gets or sets the key identifier.
        /// </summary>
        public string KeyIdentifier { get; set; } = string.Empty;
    }


    /// <summary>
    /// JWT-specific cryptographic context.
    /// </summary>
    public class JwtCryptoContext: CryptoContext
    {
        /// <inheritdoc/>
        public override string Discriminator => nameof(JwtCryptoContext);

        /// <summary>
        /// Gets or sets the key type (kty).
        /// </summary>
        public string Kty { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the algorithm (alg).
        /// </summary>
        public string Alg { get; set; } = string.Empty;
    }


    /// <summary>
    /// Represents a JWT with header and payload claims.
    /// </summary>
    public class Jwt
    {
        private static Dictionary<string, object> EmptyDictionary => new();

        /// <summary>
        /// Gets the header claims.
        /// </summary>
        public IDictionary<string, object> HeaderClaims { get; }

        /// <summary>
        /// Gets the payload claims.
        /// </summary>
        public IDictionary<string, object> PayloadClaims { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Jwt"/> class with empty claims.
        /// </summary>
        public Jwt() : this(EmptyDictionary, EmptyDictionary) { }


        /// <summary>
        /// Initializes a new instance of the <see cref="Jwt"/> class with the specified claims.
        /// </summary>
        /// <param name="headerClaims">The header claims.</param>
        /// <param name="payloadClaims">The payload claims.</param>
        public Jwt(IDictionary<string, object> headerClaims, IDictionary<string, object> payloadClaims)
        {
            ArgumentNullException.ThrowIfNull(headerClaims, nameof(headerClaims));
            ArgumentNullException.ThrowIfNull(payloadClaims, nameof(payloadClaims));

            HeaderClaims = headerClaims;
            PayloadClaims = payloadClaims;
        }

        /// <summary>
        /// Adds an expiration claim to the header.
        /// </summary>
        /// <param name="exp">The expiration value.</param>
        /// <returns>This instance for chaining.</returns>
        public Jwt AddExp(string exp)
        {
            HeaderClaims.Add("exp", exp);

            return this;
        }
    }


    //https://www.scottbrady91.com/oauth/client-authentication
    //In this model one can create things like "JAR" token by just creating a function that
    //takes the necessary parameters and adds them to the header and payload.
    //
    //Note that for adding support for encryption, there would be five parts in the split and more processing.
    //So "to be be certain" more delegates would be needed as parameters.
    //See https://www.scottbrady91.com/jose/json-web-encryption.

    //This could be a convenience class offered by Verifiable.Jose? Should work with any other system too? E.g. with
    //third party library Jwt types and so on. Continues to serialization also. Abstract
    /// <summary>
    /// Extension methods for JWT operations.
    /// </summary>
    public static class JwtExtensions
    {
        /// <summary>
        /// Adds a header value to the JWT.
        /// </summary>
        public static TJwtType AddHeaderValue<TJwtValue, TJwtType>(this TJwtType jwt, in string attribute, in TJwtValue value, JwtAttributeAdder<TJwtValue, TJwtType> jwtAdder)
        {
            return AddSectionValue(jwt, jwtAdder, attribute, value);
        }


        /// <summary>
        /// Adds a payload value to the JWT.
        /// </summary>
        public static TJwtType AddPayloadValue<TJwtValue, TJwtType>(this TJwtType jwt, in string attribute, in TJwtValue value, JwtAttributeAdder<TJwtValue, TJwtType> jwtAdder)
        {
            return AddSectionValue(jwt, jwtAdder, attribute, value);
        }

        private static TJwtType AddSectionValue<TJwtValue, TJwtType>(TJwtType jwt, JwtAttributeAdder<TJwtValue, TJwtType> jwtAdder, in string attribute, in TJwtValue value)
        {
            jwtAdder(attribute, value, jwt);
            return jwt;
        }

        /// <summary>
        /// Serializes a JWT section to bytes.
        /// </summary>
        public static ReadOnlySpan<byte> SerializeJwtSection<TJwtPart>(JwtPartByteEncoder<TJwtPart> serializer, TJwtPart payload)
        {
            return serializer(payload);
        }

        /// <summary>
        /// Signs a JWT using the provided encoder and signing function.
        /// </summary>
        /// <typeparam name="TJwtPart">The JWT part type.</typeparam>
        /// <typeparam name="TKeyIdentifier">The key identifier type.</typeparam>
        /// <typeparam name="TCryptoContext">The cryptographic context type.</typeparam>
        /// <param name="serializer">Serializes JWT parts to bytes.</param>
        /// <param name="base64UrlEncoder">Encodes bytes to Base64Url string.</param>
        /// <param name="header">The JWT header.</param>
        /// <param name="payload">The JWT payload.</param>
        /// <param name="keyIdentifierSelector">Selects the key identifier from the header.</param>
        /// <param name="contextLoader">Loads the cryptographic context.</param>
        /// <param name="signingFunctionMatcher">Matches the signing function based on context.</param>
        /// <returns>The signed JWT as a compact serialization string.</returns>
        public static string SignJwt<TJwtPart, TKeyIdentifier, TCryptoContext>(
            JwtPartByteEncoder<TJwtPart> serializer,
            EncodeDelegate base64UrlEncoder,
            TJwtPart header,
            TJwtPart payload,
            KeyIdentifierSelector<TJwtPart, TKeyIdentifier> keyIdentifierSelector,
            CryptoContextLoader<TJwtPart, TKeyIdentifier, TCryptoContext> contextLoader,
            SignImplementationMatcher<TCryptoContext, byte> signingFunctionMatcher)
            where TCryptoContext : CryptoContext
        {
            string headerSegment = base64UrlEncoder(serializer(header));
            string payloadSegment = base64UrlEncoder(serializer(payload));

            string stringToSign = $"{headerSegment}.{payloadSegment}";
            byte[] bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            //Key identifier from the header.
            TKeyIdentifier keyId = keyIdentifierSelector(header);

            //CryptoContext based on the header and key identifier.
            TCryptoContext cryptoContext = contextLoader(header, keyId);

            //Signing function using the matcher delegate.
            SignImplementation<byte> signer = signingFunctionMatcher(cryptoContext);

            //TODO: This can't work like this. The signer cannot expect private key bytes as input.
            //That's because the private key bytes may be inside the TPM and the signer just receives
            //a handle it uses with the TPM to signer the bytes.
            //See more at https://opensecuritytraining.info/IntroToTrustedComputing_files/Day1-7-tpm-keys.pdf.
            //
            //SO! The signer needs to use the idea of ".WithKeyBytes" and the actually type how to
            //key bytes will be delivered (e.g. the SensitiveMemoryHierarchy).
            //SO! If signingFunctionSelector RETURNS a delegate that takes further a delegate that
            //prepares the key bytes either to the TPM for the actual signer OR can retrieve
            //them to be used in-memory, thi would work.
            //So, the first step is to have the delegate to take another delegate as input.
            //How does the signer know which way to access the bytes if it doesn't know which to
            //use, e.g. a parameter or "go to TPM with some identifier to do th operation"?
            //I.e. how does the signer work with the type system to work with either types?
            ReadOnlySpan<byte> signature = signer(privateKeyBytes: cryptoContext.Key, bytesToSign);
            string encodedSignature = base64UrlEncoder(signature.ToArray());

            return $"{stringToSign}.{encodedSignature}";
        }


        /// <summary>
        /// Verifies compact JSON signature.
        /// </summary>
        /// <typeparam name="TJwtPart">The type of the JWT part, such as header or a payload.</typeparam>
        /// <typeparam name="TCryptoContext">The type to hold parameters and material related to the cryptographic context.</typeparam>
        /// <typeparam name="TKeyIdentifier">The type that holds key data material and associated metadata.</typeparam>
        /// <typeparam name="TSignature">The signature type.</typeparam>
        /// <param name="jwtDataWithSignature">JSON data with signature.</param>
        /// <param name="base64UrlDecoder">Function that does the Base64 URL decoding.</param>
        /// <param name="partDecoder">A function that decodes the <typeparamref name="TJwtPart"/> parts.</param>
        /// <param name="keyIdentifierSelector">The function that is used to identify the key information from decoded JWT data.</param>
        /// <param name="contextLoader">The function that does the actual key loading.</param>
        /// <param name="matcherDelegate">The verification implementation matcher.</param>
        /// <param name="verificationFunction">The function that does the actual verification that the signature part in <paramref name="jwtDataWithSignature"/> is valid.</param>
        /// <returns><see langword="true"/> if signature is valid; otherwise <see langword="false"/>.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the JWT does not have exactly 3 parts.</exception>
        public static ValueTask<bool> VerifyCompactSignature<TJwtPart, TCryptoContext, TKeyIdentifier, TSignature>(
            string jwtDataWithSignature,
            Func<string, TSignature> base64UrlDecoder,
            JwtPartDecoder<TSignature, TJwtPart> partDecoder,
            KeyIdentifierSelector<TJwtPart, TKeyIdentifier> keyIdentifierSelector,
            CryptoContextLoader<TJwtPart, TKeyIdentifier, TCryptoContext> contextLoader,
            VerifyImplementationMatcher<TCryptoContext, TSignature> matcherDelegate,
            Verify<TJwtPart, TCryptoContext, TKeyIdentifier, byte, TSignature, TJwtPart, TJwtPart, bool> verificationFunction)
            where TCryptoContext : CryptoContext

        {
            //This assumes compact representation and consequently that the signature is in the third segment.
            string[] tokenParts = jwtDataWithSignature.Split('.');
            if(tokenParts.Length != 3)
            {
                throw new ArgumentOutOfRangeException(nameof(jwtDataWithSignature));
            }

            string base64EncodedJwtTokenSignature = tokenParts[2];
            TSignature signature = base64UrlDecoder(base64EncodedJwtTokenSignature);
            ReadOnlySpan<byte> dataToVerify = Encoding.UTF8.GetBytes($"{tokenParts[0]}.{tokenParts[1]}");

            TJwtPart header = partDecoder(base64UrlDecoder(tokenParts[0]));
            TJwtPart payload = partDecoder(base64UrlDecoder(tokenParts[1]));

            return verificationFunction(keyIdentifierSelector, contextLoader, matcherDelegate, dataToVerify, signature, header, payload);
        }


        /// <summary>
        /// Verifies compact JSON signature with byte array signature.
        /// </summary>
        /// <typeparam name="TJwtPart">The type of the JWT part, such as header or a payload.</typeparam>
        /// <typeparam name="TCryptoContext">The type to hold parameters and material related to the cryptographic context.</typeparam>
        /// <typeparam name="TKeyIdentifier">The type that holds key data material and associated metadata.</typeparam>
        /// <param name="jwtDataWithSignature">JSON data with signature.</param>
        /// <param name="base64UrlDecoder">Function that does the Base64 URL decoding.</param>
        /// <param name="partDecoder">A function that decodes the <typeparamref name="TJwtPart"/> parts.</param>
        /// <param name="keyIdentifierSelector">The function that is used to identify the key information from decoded JWT data.</param>
        /// <param name="contextLoader">The function that does the actual key loading.</param>
        /// <param name="matcherDelegate">The verification implementation matcher.</param>
        /// <param name="verificationFunction">The function that does the actual verification that the signature part in <paramref name="jwtDataWithSignature"/> is valid.</param>
        /// <returns><see langword="true"/> if signature is valid; otherwise <see langword="false"/>.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the JWT does not have exactly 3 parts.</exception>
        public static ValueTask<bool> VerifyCompactSignature<TJwtPart, TCryptoContext, TKeyIdentifier>(
            string jwtDataWithSignature,
            Func<string, ReadOnlySpan<byte>> base64UrlDecoder,
            JwtPartDecoder<TJwtPart> partDecoder,
            KeyIdentifierSelector<TJwtPart, TKeyIdentifier> keyIdentifierSelector,
            CryptoContextLoader<TJwtPart, TKeyIdentifier, TCryptoContext> contextLoader,
            VerifyImplementationMatcher<TCryptoContext, byte> matcherDelegate,
            Verify<TJwtPart, TCryptoContext, TKeyIdentifier, byte, TJwtPart, TJwtPart, bool> verificationFunction)
            where TCryptoContext : CryptoContext
        {
            //This assumes compact representation and consequently that the signature is in the third segment.
            string[] tokenParts = jwtDataWithSignature.Split('.');
            if(tokenParts.Length != 3)
            {
                throw new ArgumentOutOfRangeException(nameof(jwtDataWithSignature));
            }

            string base64EncodedJwtTokenSignature = tokenParts[2];
            ReadOnlySpan<byte> signature = base64UrlDecoder(base64EncodedJwtTokenSignature);
            ReadOnlySpan<byte> dataToVerify = Encoding.UTF8.GetBytes($"{tokenParts[0]}.{tokenParts[1]}");

            TJwtPart header = partDecoder(base64UrlDecoder(tokenParts[0]));
            TJwtPart payload = partDecoder(base64UrlDecoder(tokenParts[1]));

            return verificationFunction(keyIdentifierSelector, contextLoader, matcherDelegate, dataToVerify, signature, header, payload);
        }
    }
}