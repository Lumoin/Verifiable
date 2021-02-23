using SimpleBase;
using System;

namespace DotDecentralized.Core
{
    /// <summary>
    /// A an interface to encoding end decoding key representations.
    /// </summary>
    public interface ICoder
    {
        /// <summary>
        /// A <see cref="ReadOnlySpan{byte}"/> decoded from Base58 string.
        /// </summary>
        /// <param name="base58String">A string in Base58 to be decoded to <see cref="ReadOnlySpan{byte}"/>.</param>
        /// <returns>A decoded <see cref="ReadOnlySpan{byte}"/>.</returns>
        ReadOnlySpan<byte> AsDecodedSpanFromBase58(string base58String);

        /// <summary>
        /// A Base58 string encoded from a <see cref="ReadOnlySpan{byte}"/>.
        /// </summary>
        /// <param name="span">The span to encode to Base58 string representation.</param>
        /// <returns>A Base58 encoded string.</returns>
        string AsString58FromSpan(ReadOnlySpan<byte> span);
    }


    /// <inheritdoc />
    public class DefaultKeyCoder: ICoder
    {
        /// <inheritdoc />
        public ReadOnlySpan<byte> AsDecodedSpanFromBase58(string base58String)
        {
            return Base58.Bitcoin.Decode(base58String);
        }

        /// <inheritdoc />
        public string AsString58FromSpan(ReadOnlySpan<byte> span)
        {
            return Base58.Bitcoin.Encode(span);
        }
    }
}
