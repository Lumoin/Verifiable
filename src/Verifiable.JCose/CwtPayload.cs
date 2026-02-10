namespace Verifiable.JCose;

/// <summary>
/// A CWT claims set represented as an integer-keyed dictionary.
/// </summary>
/// <remarks>
/// <para>
/// This type inherits from <see cref="Dictionary{TKey, TValue}"/> and provides
/// type identity at API boundaries, preventing accidental swapping of CWT payloads
/// and other integer-keyed maps such as COSE headers.
/// </para>
/// <para>
/// CWT uses integer keys for claims per
/// <see href="https://www.rfc-editor.org/rfc/rfc8392">RFC 8392</see>, unlike
/// JWT which uses string keys. Standard claim keys are defined in
/// <see cref="WellKnownCwtClaims"/>.
/// </para>
/// <para>
/// This is the CWT parallel of <see cref="JwtPayload"/> and is used throughout
/// the SD-CWT issuance and verification pipeline.
/// </para>
/// </remarks>
public class CwtPayload: Dictionary<int, object>
{
    /// <summary>
    /// Creates an empty CWT payload.
    /// </summary>
    public CwtPayload()
    {
    }


    /// <summary>
    /// Creates a CWT payload initialized with the specified claims.
    /// </summary>
    /// <param name="claims">The initial claims.</param>
    public CwtPayload(IDictionary<int, object> claims)
        : base(claims)
    {
    }


    /// <summary>
    /// Creates a CWT payload with the specified initial capacity.
    /// </summary>
    /// <param name="capacity">The initial capacity.</param>
    public CwtPayload(int capacity)
        : base(capacity)
    {
    }
}