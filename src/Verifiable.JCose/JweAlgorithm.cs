namespace Verifiable.JCose;

/// <summary>
/// A descriptor for a JWE key management (<c>alg</c>) algorithm: the wire identifier, the
/// RFC 7516 §2 <see cref="JweKeyManagementMode"/>, and — where the mode wraps the CEK — the
/// key encryption key length in bits.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why a record and not a "dynamic enum" struct.</strong> The descriptor pattern in
/// <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> models an open set of opaque
/// codes a backend routes on. A JWE <c>alg</c> descriptor instead carries the structural facts
/// the JWE orchestration needs in one place — the mode it dispatches on and the wrap length it
/// derives the KEK with — so a <see langword="readonly"/> <see langword="record"/> with named
/// fields is the soundest shape: each well-known instance states its mode and KEK length as
/// data, and the orchestration reads those fields rather than re-deriving them from the
/// <c>alg</c> string. The set of <c>alg</c> values is closed and registry-defined (RFC 7518
/// §4.1 / IANA), so the runtime-extensibility of the "dynamic enum" pattern is not needed; the
/// well-known instances below are the exhaustive surface this library implements.
/// </para>
/// <para>
/// <see cref="FromWellKnownName"/> maps a wire <c>alg</c> string to its descriptor at the parse
/// boundary; the encrypt path takes a descriptor directly. The five rejected-by-design and
/// later-chunk algorithms (<c>RSA1_5</c>, <c>RSA-OAEP</c>, <c>A*GCMKW</c>, <c>PBES2-*</c>) are
/// not represented here — <see cref="FromWellKnownName"/> surfaces them through its caller's
/// rejection path rather than as descriptors this chunk can dispatch.
/// </para>
/// </remarks>
/// <param name="Name">The wire <c>alg</c> identifier, e.g. <c>ECDH-ES+A256KW</c>.</param>
/// <param name="Mode">The RFC 7516 §2 Key Management Mode this algorithm employs.</param>
/// <param name="KeyWrapBits">
/// The key encryption key length in bits for the wrapping modes
/// (<see cref="JweKeyManagementMode.KeyAgreementWithKeyWrapping"/> and
/// <see cref="JweKeyManagementMode.KeyWrapping"/>); <c>0</c> for the direct modes, which do not
/// wrap a CEK.
/// </param>
public readonly record struct JweAlgorithm(string Name, JweKeyManagementMode Mode, int KeyWrapBits)
{
    /// <summary>ECDH-ES Direct Key Agreement (RFC 7518 §4.6). The agreed key is the CEK.</summary>
    public static JweAlgorithm EcdhEs { get; } =
        new(WellKnownJweAlgorithms.EcdhEs, JweKeyManagementMode.DirectKeyAgreement, 0);

    /// <summary>ECDH-ES + AES-128 Key Wrap (RFC 7518 §4.6).</summary>
    public static JweAlgorithm EcdhEsA128Kw { get; } =
        new(WellKnownJweAlgorithms.EcdhEsA128Kw, JweKeyManagementMode.KeyAgreementWithKeyWrapping, 128);

    /// <summary>ECDH-ES + AES-192 Key Wrap (RFC 7518 §4.6).</summary>
    public static JweAlgorithm EcdhEsA192Kw { get; } =
        new(WellKnownJweAlgorithms.EcdhEsA192Kw, JweKeyManagementMode.KeyAgreementWithKeyWrapping, 192);

    /// <summary>ECDH-ES + AES-256 Key Wrap (RFC 7518 §4.6).</summary>
    public static JweAlgorithm EcdhEsA256Kw { get; } =
        new(WellKnownJweAlgorithms.EcdhEsA256Kw, JweKeyManagementMode.KeyAgreementWithKeyWrapping, 256);

    /// <summary>ECDH-1PU Direct Key Agreement (draft-madden-jose-ecdh-1pu-04 §2).</summary>
    public static JweAlgorithm Ecdh1Pu { get; } =
        new(WellKnownJweAlgorithms.Ecdh1Pu, JweKeyManagementMode.DirectKeyAgreement, 0);

    /// <summary>ECDH-1PU + AES-128 Key Wrap (draft-madden-jose-ecdh-1pu-04 §2.1).</summary>
    public static JweAlgorithm Ecdh1PuA128Kw { get; } =
        new(WellKnownJweAlgorithms.Ecdh1PuA128Kw, JweKeyManagementMode.KeyAgreementWithKeyWrapping, 128);

    /// <summary>ECDH-1PU + AES-192 Key Wrap (draft-madden-jose-ecdh-1pu-04 §2.1).</summary>
    public static JweAlgorithm Ecdh1PuA192Kw { get; } =
        new(WellKnownJweAlgorithms.Ecdh1PuA192Kw, JweKeyManagementMode.KeyAgreementWithKeyWrapping, 192);

    /// <summary>ECDH-1PU + AES-256 Key Wrap (draft-madden-jose-ecdh-1pu-04 §2.1).</summary>
    public static JweAlgorithm Ecdh1PuA256Kw { get; } =
        new(WellKnownJweAlgorithms.Ecdh1PuA256Kw, JweKeyManagementMode.KeyAgreementWithKeyWrapping, 256);

    /// <summary>AES-128 Key Wrap (RFC 7518 §4.4) with a pre-shared symmetric KEK.</summary>
    public static JweAlgorithm A128Kw { get; } =
        new(WellKnownJweAlgorithms.A128Kw, JweKeyManagementMode.KeyWrapping, 128);

    /// <summary>AES-192 Key Wrap (RFC 7518 §4.4) with a pre-shared symmetric KEK.</summary>
    public static JweAlgorithm A192Kw { get; } =
        new(WellKnownJweAlgorithms.A192Kw, JweKeyManagementMode.KeyWrapping, 192);

    /// <summary>AES-256 Key Wrap (RFC 7518 §4.4) with a pre-shared symmetric KEK.</summary>
    public static JweAlgorithm A256Kw { get; } =
        new(WellKnownJweAlgorithms.A256Kw, JweKeyManagementMode.KeyWrapping, 256);

    /// <summary>Direct symmetric encryption (RFC 7518 §4.5). The shared key is the CEK.</summary>
    public static JweAlgorithm Dir { get; } =
        new(WellKnownJweAlgorithms.Dir, JweKeyManagementMode.DirectEncryption, 0);


    /// <summary>
    /// Maps a wire <c>alg</c> string to its descriptor, or <see langword="null"/> when the
    /// value is not a key management algorithm this library dispatches.
    /// </summary>
    /// <remarks>
    /// This is the single <c>alg</c>-string to descriptor mapping used at parse boundaries.
    /// The mapping is a switch expression over the <see cref="WellKnownJweAlgorithms"/>
    /// constants — there is no per-method string matching elsewhere. <c>RSA1_5</c> and the
    /// later-chunk algorithms return <see langword="null"/>; callers reject them with the
    /// specific rationale required (e.g. RFC 8725 §3.2 for <c>RSA1_5</c>).
    /// </remarks>
    /// <param name="algorithm">The wire <c>alg</c> string.</param>
    /// <returns>The matching descriptor, or <see langword="null"/>.</returns>
    public static JweAlgorithm? FromWellKnownName(string algorithm)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);

        return algorithm switch
        {
            _ when WellKnownJweAlgorithms.IsEcdhEs(algorithm) => EcdhEs,
            _ when WellKnownJweAlgorithms.IsEcdhEsA128Kw(algorithm) => EcdhEsA128Kw,
            _ when WellKnownJweAlgorithms.IsEcdhEsA192Kw(algorithm) => EcdhEsA192Kw,
            _ when WellKnownJweAlgorithms.IsEcdhEsA256Kw(algorithm) => EcdhEsA256Kw,
            _ when WellKnownJweAlgorithms.IsEcdh1Pu(algorithm) => Ecdh1Pu,
            _ when WellKnownJweAlgorithms.IsEcdh1PuA128Kw(algorithm) => Ecdh1PuA128Kw,
            _ when WellKnownJweAlgorithms.IsEcdh1PuA192Kw(algorithm) => Ecdh1PuA192Kw,
            _ when WellKnownJweAlgorithms.IsEcdh1PuA256Kw(algorithm) => Ecdh1PuA256Kw,
            _ when WellKnownJweAlgorithms.IsA128Kw(algorithm) => A128Kw,
            _ when WellKnownJweAlgorithms.IsA192Kw(algorithm) => A192Kw,
            _ when WellKnownJweAlgorithms.IsA256Kw(algorithm) => A256Kw,
            _ when WellKnownJweAlgorithms.IsDir(algorithm) => Dir,
            _ => null
        };
    }
}
