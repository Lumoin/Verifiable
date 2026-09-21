namespace Verifiable.Core.Did.Methods.Web;

/// <summary>
/// The <c>did:web</c> DID method: a DID resolved by fetching a DID document over HTTPS from the
/// host and path the DID string encodes.
/// </summary>
public record WebDidMethod: GenericDidMethod
{
    /// <summary>
    /// The prefix of <c>did:web</c> method, including suffix <c>':'</c>.
    /// </summary>
    /// <remarks>This is <see cref="WellKnownDidMethodPrefixes.WebDidMethodPrefix"/> with colon.</remarks>
    public static new string Prefix { get; } = $"{WellKnownDidMethodPrefixes.WebDidMethodPrefix}:";


    /// <summary>
    /// Initializes a new instance of the <see cref="WebDidMethod"/> class using the specified DID string.
    /// </summary>
    /// <param name="didString">The DID string to associate with this instance. The string must start with <see cref="WellKnownDidMethodPrefixes.WebDidMethodPrefix"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="didString"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="didString"/> does not start with <see cref="WellKnownDidMethodPrefixes.WebDidMethodPrefix"/>.</exception>
    public WebDidMethod(string didString) : base(didString)
    {
        ArgumentNullException.ThrowIfNull(didString);
        if(!didString.StartsWith(Prefix, StringComparison.Ordinal))
        {
            throw new ArgumentException($"The DID string must start with '{Prefix}'.", nameof(didString));
        }
    }


    /// <summary>
    /// Implicit conversion from <see cref="WebDidMethod"/> or derived DID methods to <see langword="string"/>.
    /// </summary>
    /// <param name="didId"></param>
    public static implicit operator string(WebDidMethod didId)
    {
        ArgumentNullException.ThrowIfNull(didId);

        return didId.Id;
    }


    /// <summary>
    /// Explicit conversion from <see langword="string"/> to <see cref="WebDidMethod"/> or derived DID methods.
    /// </summary>
    /// <param name="didId"></param>
    public static explicit operator WebDidMethod(string didId)
    {
        ArgumentNullException.ThrowIfNull(didId);

        return new(didId);
    }


    /// <inheritdoc/>
    public override string ToString() => Id;
}
