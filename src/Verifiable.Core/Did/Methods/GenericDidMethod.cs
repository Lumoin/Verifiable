using System.Diagnostics;

namespace Verifiable.Core.Did.Methods
{
    /// <summary>
    /// This is used when the DID method is either not recognized or it is treated as a generic DID method.
    /// The ethod URN still need to conform with what is expected from a DID method and a URN.
    /// </summary>
    /// <remarks>The DID method specific identifiers should inherit from this. They may provide more granular constructors
    /// with DID method specific parameters and functionality.</remarks>
    [DebuggerDisplay("{Id}")]
    public record GenericDidMethod
    {
        /// <summary>
        /// The prefix of this particular DID method.
        /// </summary>
        public static string Prefix => string.Empty;

        /// <summary>
        /// The full DID identifier string.
        /// </summary>
        public string Id { get; private set; }


        /// <summary>
        /// Creates a new instance of <see cref="GenericDidMethod"/>. 
        /// </summary>
        /// <param name="id">The full DID identifier string.</param>
        public GenericDidMethod(string id)
        {
            Id = id;
        }


        /// <summary>
        /// Implicit conversion from <see cref="GenericDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(GenericDidMethod didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="GenericDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator GenericDidMethod(string didId) => new(didId);


        /// <inheritdoc/>
        public override string ToString() => Id;
    }
}
