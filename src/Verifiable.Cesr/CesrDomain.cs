namespace Verifiable.Cesr;

/// <summary>
/// The representation domain a CESR primitive or group is expressed in. Every CESR value exists in
/// three interconvertible domains; transcoding between them is the core operation this codec performs.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification, <see href="https://trustoverip.github.io/kswg-cesr-specification/#composability-and-domain-representations">
/// Composability and Domain Representations</see>. The 24-bit composability constraint (every primitive
/// and group aligns on a quadlet/triplet boundary) is what makes a concatenation of values in one domain
/// convertible, as a whole, into either of the other two without re-parsing each element.
/// </para>
/// </remarks>
public enum CesrDomain
{
    /// <summary>
    /// The raw domain ('R'): the underlying, unframed binary value (for example the 32 bytes of an
    /// Ed25519 public key) with no type code and no lead bytes. This is the domain cryptographic
    /// operations consume and produce.
    /// </summary>
    /// <remarks>
    /// See <see href="https://trustoverip.github.io/kswg-cesr-specification/#abstract-domain-representations">
    /// Abstract Domain representations</see>.
    /// </remarks>
    Raw = 0,

    /// <summary>
    /// The text domain ('T'): the fully qualified Base64URL form (the type code prepended to the
    /// Base64URL encoding of the lead bytes and raw value), for example <c>0AA_Az7vckaE383AHOsW1J1N</c>.
    /// This is the human-transmissible, URL-safe wire form.
    /// </summary>
    /// <remarks>
    /// See <see href="https://trustoverip.github.io/kswg-cesr-specification/#concrete-domain-representations">
    /// Concrete Domain representations</see>.
    /// </remarks>
    Text = 1,

    /// <summary>
    /// The binary domain ('B', also called qb2): the compact byte form that the text domain converts to
    /// one-to-one, where the type code is itself packed into the leading bits rather than expanded to
    /// Base64URL characters. This is the bandwidth-optimal wire form.
    /// </summary>
    /// <remarks>
    /// See <see href="https://trustoverip.github.io/kswg-cesr-specification/#concrete-domain-representations">
    /// Concrete Domain representations</see>.
    /// </remarks>
    Binary = 2
}
