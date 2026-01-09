namespace Verifiable.Cryptography
{
    /// <summary>
    /// These are headers for multicodec values. See more at <see href="https://github.com/multiformats/multicodec">multicodec (GitHub)</see>.
    /// </summary>
    public static class MulticodecHeaders
    {
        //Note that the pattern "static ReadOnlySpan<byte> => new byte[] { }" does not allocate until these are turned into lists or arrays.
        //These constants have been produced by taking the noted values from the linked CSV table and transformed with the following piece of code:
        //
        //Here P256-pub (0x1200) is used as an example.
        //var varint = require('varint');
        //var bytes = varint.encode(0x1200);
        //console.log(new Uint8Array(bytes).reduce((a, b) => a + b.toString(16).padStart(2, '0'), ''));

        /// <summary>
        /// This is a special value that is used to indicate that no multicodec header is present.
        /// </summary>
        public static ReadOnlySpan<byte> None => [];

        /// <summary>
        /// Identity (0x00). Raw binary. See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L2">identity (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: permanent.</remarks>
        public static ReadOnlySpan<byte> Identity => [0x00];

        /// <summary>
        /// CIDv1 (0x01). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L3">CIDv1 (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: permanent.</remarks>
        public static ReadOnlySpan<byte> Cidv1 => [0x01];

        /// <summary>
        /// Secp256k1-pub (0xe7). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L89">Secp256k1 public key (compressed) (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> Secp256k1PublicKey => [0xe7, 0x01];

        /// <summary>
        /// Bls12_381-g1-pub (0xea). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L91">BLS12-381 public key in the G1 field (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> Bls12381G1PublicKey => [0xea, 0x01];

        /// <summary>
        /// Bls12_381-g2-pub (0xec). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L92">BLS12-381 public key in the G2 field (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> Bls12381G2PublicKey => [0xeb, 0x01];

        /// <summary>
        /// X25519-pub (0xec). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L93">Curve25519 public key (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> X25519PublicKey => [0xec, 0x01];

        /// <summary>
        /// Ed25519-pub (0xed). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L94">Ed25519 public key (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> Ed25519PublicKey => [0xed, 0x01];

        /// <summary>
        /// Bls12_381-g1g2-pub (0xee). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L95">BLS12-381 concatenated public keys in both the G1 and G2 fields (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> Bls12381G1G2PublicKey => [0xee, 0x01];

        /// <summary>
        /// P256-pub (0x1200). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L145">P-256 public Key (compressed) (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> P256PublicKey => [0x80, 0x24];

        /// <summary>
        /// P256-priv (0x1306). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L157">P-256 private key (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> P256PrivateKey => [0x86, 0x26];
        
        /// <summary>
        /// P2384-pub (0x1201). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L146">P-384 public Key (compressed) (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> P384PublicKey => [0x81, 0x24];

        /// <summary>
        /// P384-priv (0x1307). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L158">P-384 private key (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> P384PrivateKey => [0x87, 0x26];
        
        /// <summary>
        /// P521-pub (0x1202). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L147">P-512 public Key (compressed) (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> P521PublicKey => [0x82, 0x24];

        /// <summary>
        /// P521-priv (0x1308). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L159">P-521 private key (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> P521PrivateKey => [0x88, 0x26];

        /// <summary>
        /// Rsa-pub (0x1205). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L150">RSA public key. DER-encoded ASN.1 type RSAPublicKey according to IETF RFC 8017 (PKCS #1) (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> RsaPublicKey => [0x85, 0x24];

        /// <summary>
        /// Ed25519-priv (0x1300). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L151">Ed25519 private key (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> Ed25519PrivateKey => [0x80, 0x26];

        /// <summary>
        /// Secp256k1-priv (0x1301). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L152">Secp256k1 private key (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> Secp256k1PrivateKey => [0x81, 0x26];

        /// <summary>
        /// X25519-priv (0x1302). See more at <see href="https://github.com/multiformats/multicodec/blob/master/table.csv#L153">Curve25519 private key (GitHub)</see>.
        /// </summary>
        /// <remarks>Status: draft.</remarks>
        public static ReadOnlySpan<byte> X25519PrivateKey => [0x82, 0x26];


        /// <summary>
        /// Returns a value that indicates if the provided material is Secp256k1 public key.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the Secp256k1 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsSecp256k1PublicKey(ReadOnlySpan<byte> multicodecMaterial) => IsMulticodecHeader(multicodecMaterial, Secp256k1PublicKey);

        /// <summary>
        /// Returns a value that indicates if the provided material is BLS12-381 G1 public key.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the BLS12-381 G1 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsBls12381G1PublicKey(ReadOnlySpan<byte> multicodecMaterial) => IsMulticodecHeader(multicodecMaterial, Bls12381G1PublicKey);

        /// <summary>
        /// Returns a value that indicates if the provided material is BLS12-381 G2 public key.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the BLS12-381 G2 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsBls12381G2PublicKey(ReadOnlySpan<byte> multicodecMaterial) => IsMulticodecHeader(multicodecMaterial, Bls12381G2PublicKey);

        /// <summary>
        /// Returns a value that indicates if the provided material is X25519 public key.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the X25519 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsX25519PublicKey(ReadOnlySpan<byte> multicodecMaterial) => IsMulticodecHeader(multicodecMaterial, X25519PublicKey);

        /// <summary>
        /// Returns a value that indicates if the provided material is Ed25519 public key.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the Ed25519 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsEd25519PublicKey(ReadOnlySpan<byte> multicodecMaterial) => IsMulticodecHeader(multicodecMaterial, Ed25519PublicKey);

        /// <summary>
        /// Returns a value that indicates if the provided material is P256 public key.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the P256 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsP256PublicKey(ReadOnlySpan<byte> multicodecMaterial) => IsMulticodecHeader(multicodecMaterial, P256PublicKey);

        /// <summary>
        /// Returns a value that indicates if the provided material is P384 public key.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the P384 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsP384PublicKey(ReadOnlySpan<byte> multicodecMaterial) => IsMulticodecHeader(multicodecMaterial, P384PublicKey);

        /// <summary>
        /// Returns a value that indicates if the provided material is P521 public key.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the P521 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsP521PublicKey(ReadOnlySpan<byte> multicodecMaterial) => IsMulticodecHeader(multicodecMaterial, P521PublicKey);

        /// <summary>
        /// Returns a value that indicates if the provided material is RSA public key.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the RSA public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsRsaPublicKey(ReadOnlySpan<byte> multicodecMaterial) => IsMulticodecHeader(multicodecMaterial, RsaPublicKey);



        /// <summary>
        /// Returns the equivalent static instance of the provided multicodec material, or the original if none match.
        /// This conversion is optional but allows for performance optimizations.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>The equivalent static instance if one matches; otherwise, the original.</returns>
        public static ReadOnlySpan<byte> GetCanonicalizedHeader(ReadOnlySpan<byte> multicodecMaterial) => multicodecMaterial switch
        {
            _ when IsMulticodecHeader(multicodecMaterial, Identity) => Identity,
            _ when IsMulticodecHeader(multicodecMaterial, Cidv1) => Cidv1,
            _ when IsMulticodecHeader(multicodecMaterial, Secp256k1PublicKey) => Secp256k1PublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, Bls12381G1PublicKey) => Bls12381G1PublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, Bls12381G2PublicKey) => Bls12381G2PublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, X25519PublicKey) => X25519PublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, Ed25519PublicKey) => Ed25519PublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, Bls12381G1G2PublicKey) => Bls12381G1G2PublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, P256PublicKey) => P256PublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, P384PublicKey) => P384PublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, P521PublicKey) => P521PublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, RsaPublicKey) => RsaPublicKey,
            _ when IsMulticodecHeader(multicodecMaterial, Ed25519PrivateKey) => Ed25519PrivateKey,
            _ when IsMulticodecHeader(multicodecMaterial, Secp256k1PrivateKey) => Secp256k1PrivateKey,
            _ when IsMulticodecHeader(multicodecMaterial, X25519PrivateKey) => X25519PrivateKey,
            _ => multicodecMaterial
        };


        /// <summary>
        /// Returns a value that indicates if two multicodec headers are equal.
        /// </summary>
        /// <param name="headerA">The first multicodec header to compare.</param>
        /// <param name="headerB">The second multicodec header to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the headers are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(ReadOnlySpan<byte> headerA, ReadOnlySpan<byte> headerB) => headerA.SequenceEqual(headerB);


        /// <summary>
        /// Returns a value that indicates if the provided material is the specified multicodec header.
        /// </summary>
        /// <param name="multicodecMaterial">The multicodec material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the specified header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsMulticodecHeader(ReadOnlySpan<byte> multicodecMaterial, ReadOnlySpan<byte> header) => multicodecMaterial.SequenceEqual(header);
    }
}
