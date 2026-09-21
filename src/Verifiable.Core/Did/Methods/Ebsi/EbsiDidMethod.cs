namespace Verifiable.Core.Did.Methods.Ebsi
{
    /// <summary>
    /// The <c>did:ebsi</c> DID method used by the European Blockchain Services Infrastructure.
    /// </summary>
    public record EbsiDidMethod: GenericDidMethod
    {
        /// <summary>
        /// The prefix of this particular DID method, including suffix <c>':'</c>.
        /// </summary>
        /// <remarks>This is <see cref="WellKnownDidMethodPrefixes.EbsiDidMethodPrefix"/> with colon.</remarks>
        public static new string Prefix => "did:ebsi:";


        /// <summary>
        /// Initializes a new <see cref="EbsiDidMethod"/> from an existing <c>did:ebsi</c> DID string.
        /// </summary>
        /// <param name="didString">The DID string, which must start with <see cref="Prefix"/>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="didString"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="didString"/> does not start with <see cref="Prefix"/>.</exception>
        public EbsiDidMethod(string didString) : base(didString)
        {
            ArgumentNullException.ThrowIfNull(didString);
            if(!didString.StartsWith(Prefix, StringComparison.Ordinal))
            {
                throw new ArgumentException($"The DID string must start with '{Prefix}'.", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="EbsiDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(EbsiDidMethod didId)
        {
            ArgumentNullException.ThrowIfNull(didId);

            return didId.Id;
        }


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="EbsiDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator EbsiDidMethod(string didId)
        {
            ArgumentNullException.ThrowIfNull(didId);

            return new(didId);
        }


        /// <inheritdoc/>
        public override string ToString() => Id;
    }
}
