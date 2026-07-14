using System;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared EC point wire fixtures for TPM public-area marshaling tests.
/// </summary>
internal static class TpmEccWireFixtures
{
    /// <summary>
    /// Builds the SEC1 compressed point (<c>0x02</c>/<c>0x03 || X</c>) for <paramref name="point"/>,
    /// left-padding each fixed-width, possibly TPM-shortened, coordinate before compressing.
    /// </summary>
    /// <param name="point">The TPM ECC point, whose coordinates may omit leading zero bytes.</param>
    /// <param name="componentSize">The fixed byte width of each coordinate.</param>
    /// <returns>The compressed point encoding.</returns>
    internal static byte[] BuildCompressedPublicKey(TpmsEccPoint point, int componentSize)
    {
        Span<byte> x = stackalloc byte[componentSize];
        Span<byte> y = stackalloc byte[componentSize];
        LeftPadInto(point.X.AsReadOnlySpan(), x);
        LeftPadInto(point.Y.AsReadOnlySpan(), y);

        return EllipticCurveUtilities.Compress(x, y);
    }


    /// <summary>Left-pads a big-endian value into a fixed-width destination, zero-filling the leading bytes.</summary>
    /// <param name="value">The big-endian value (the TPM may omit leading zero bytes).</param>
    /// <param name="destination">The fixed-width destination span.</param>
    private static void LeftPadInto(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        destination.Clear();
        value.CopyTo(destination[(destination.Length - value.Length)..]);
    }
}
