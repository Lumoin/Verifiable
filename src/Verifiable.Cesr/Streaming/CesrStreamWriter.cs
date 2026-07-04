using System.Buffers;
using System.IO.Pipelines;
using System.Text;

namespace Verifiable.Cesr.Streaming;

/// <summary>
/// Writes a CESR stream into a <see cref="PipeWriter"/> — the inverse of <see cref="CesrStreamReader"/>. The
/// encoders fill the pipe's own buffer directly (via <see cref="PipeWriter.GetSpan(int)"/> /
/// <see cref="PipeWriter.Advance(int)"/>), never the <c>System.IO.Stream</c> APIs and without an intermediate
/// pooled copy. The methods only stage bytes into the pipe; the caller controls when to
/// <see cref="PipeWriter.FlushAsync(System.Threading.CancellationToken)"/>.
/// </summary>
/// <remarks>
/// <para>
/// These are the top-level framing operations that pair with what the reader yields, in both concrete domains
/// (the <c>Write*</c> methods write the binary domain, the <c>WriteText*</c> methods the text domain): a
/// protocol genus/version code, a bare count code, and a count code together with the body it frames. Encoding
/// the individual elements of a group (primitives, indexed signatures) is the codecs' job; the encoded element
/// bytes are passed here as the group body. Anchored on the CESR specification's
/// <see href="https://trustoverip.github.io/kswg-cesr-specification/#count-code-tables">Count Code tables</see>.
/// </para>
/// </remarks>
public static class CesrStreamWriter
{
    /// <summary>
    /// The largest a single count code is in the binary domain (the eight-character large/genus codes are six bytes).
    /// </summary>
    private const int MaxCountCodeBytes = 6;


    /// <summary>
    /// Writes a protocol genus/version code (for example <c>-_AAA</c> at version 2.00) into the pipe.
    /// </summary>
    /// <param name="writer">The pipe to write into.</param>
    /// <param name="genusCode">The stable genus code, for example <c>-_AAA</c>.</param>
    /// <param name="major">The major version, in the range 0 to 63.</param>
    /// <param name="minor">The minor version, in the range 0 to 4095.</param>
    public static void WriteGenusVersion(PipeWriter writer, string genusCode, int major, int minor)
    {
        ArgumentNullException.ThrowIfNull(writer);

        WriteCountCode(writer, genusCode, CesrCountCodeTables.PackVersion(major, minor));
    }


    /// <summary>
    /// Writes a count code into the pipe.
    /// </summary>
    /// <param name="writer">The pipe to write into.</param>
    /// <param name="code">The stable (hard) count code, for example <c>-V</c> or <c>--V</c>.</param>
    /// <param name="count">The quadlet/triplet count, or the packed version for a genus/version code.</param>
    public static void WriteCountCode(PipeWriter writer, string code, int count)
    {
        ArgumentNullException.ThrowIfNull(writer);

        Span<byte> span = writer.GetSpan(MaxCountCodeBytes);
        int written = CesrCountCodeCodec.EncodeBinary(code, count, span);
        writer.Advance(written);
    }


    /// <summary>
    /// Writes a count code that frames the given body, then the body itself: the count is the body's triplet
    /// count, so a <see cref="CesrStreamReader"/> reads the pair back as one framed group.
    /// </summary>
    /// <param name="writer">The pipe to write into.</param>
    /// <param name="code">The stable (hard) count code that frames the body, for example <c>-V</c>.</param>
    /// <param name="body">The already-encoded binary-domain group body; its length must be a multiple of three.</param>
    /// <exception cref="CesrFormatException">The body is not aligned on a 24-bit (three-byte) boundary.</exception>
    public static void WriteGroup(PipeWriter writer, string code, ReadOnlySpan<byte> body)
    {
        ArgumentNullException.ThrowIfNull(writer);

        if(body.Length % 3 != 0)
        {
            throw new CesrFormatException($"A CESR group body of {body.Length} bytes is not aligned on a 24-bit (three-byte) boundary.");
        }

        WriteCountCode(writer, code, body.Length / 3);
        writer.Write(body);
    }


    /// <summary>
    /// Writes a protocol genus/version code (for example <c>-_AAA</c> at version 2.00) into the pipe as
    /// text-domain (qb64) characters.
    /// </summary>
    /// <param name="writer">The pipe to write into.</param>
    /// <param name="genusCode">The stable genus code, for example <c>-_AAA</c>.</param>
    /// <param name="major">The major version, in the range 0 to 63.</param>
    /// <param name="minor">The minor version, in the range 0 to 4095.</param>
    public static void WriteTextGenusVersion(PipeWriter writer, string genusCode, int major, int minor)
    {
        ArgumentNullException.ThrowIfNull(writer);

        WriteTextCountCode(writer, genusCode, CesrCountCodeTables.PackVersion(major, minor));
    }


    /// <summary>
    /// Writes a count code into the pipe as text-domain (qb64) characters.
    /// </summary>
    /// <param name="writer">The pipe to write into.</param>
    /// <param name="code">The stable (hard) count code, for example <c>-V</c> or <c>--V</c>.</param>
    /// <param name="count">The quadlet/triplet count, or the packed version for a genus/version code.</param>
    public static void WriteTextCountCode(PipeWriter writer, string code, int count)
    {
        ArgumentNullException.ThrowIfNull(writer);

        string text = CesrCountCodeCodec.EncodeText(code, count);
        Span<byte> span = writer.GetSpan(text.Length);
        int written = Encoding.ASCII.GetBytes(text, span);
        writer.Advance(written);
    }


    /// <summary>
    /// Writes a text-domain (qb64) count code that frames the given body, then the body itself: the count is the
    /// body's quadlet count, so a <see cref="CesrStreamReader.ReadTextAsync"/> reads the pair back as one framed
    /// group.
    /// </summary>
    /// <param name="writer">The pipe to write into.</param>
    /// <param name="code">The stable (hard) count code that frames the body, for example <c>-V</c>.</param>
    /// <param name="body">The already-encoded text-domain group body (qb64 characters as ASCII bytes); its length must be a multiple of four.</param>
    /// <exception cref="CesrFormatException">The body is not aligned on a 24-bit (four-character) boundary.</exception>
    public static void WriteTextGroup(PipeWriter writer, string code, ReadOnlySpan<byte> body)
    {
        ArgumentNullException.ThrowIfNull(writer);

        if(body.Length % 4 != 0)
        {
            throw new CesrFormatException($"A CESR text group body of {body.Length} characters is not aligned on a 24-bit (four-character) boundary.");
        }

        WriteTextCountCode(writer, code, body.Length / 4);
        writer.Write(body);
    }
}
