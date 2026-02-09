using System;

namespace Verifiable.Core.Model.Did.Methods
{
    /// <summary>
    /// The DID AtProto Placeholder method identifier.
    /// </summary>
    /// <remarks>Authoritative definition at <see href="https://atproto.com/specs/did-plc">DID Placeholder (did:plc)</see>.</remarks>
    public record PlaceholderDidMethod: GenericDidMethod
    {
        public PlaceholderDidMethod(string didString): base(didString)
        {
        ArgumentNullException.ThrowIfNull(didString);
        if(!didString.StartsWith("did:plc:", StringComparison.InvariantCulture))
            {
                throw new ArgumentException("The DID string must start with 'did:plc:'", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="PlaceholderDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
    public static implicit operator string(PlaceholderDidMethod didId)
    {
        ArgumentNullException.ThrowIfNull(didId);

        return didId.Id;
    }


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="PlaceholderDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
    public static explicit operator PlaceholderDidMethod(string didId)
    {
        ArgumentNullException.ThrowIfNull(didId);

        return new(didId);
    }


        /// <inheritdoc/>
        public override string ToString() => Id;
    }
}
