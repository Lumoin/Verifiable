using System;

namespace Verifiable.Apdu.Mrz;

/// <summary>
/// The format of a Machine Readable Zone per ICAO Doc 9303 Part 3.
/// </summary>
public enum MrzDocumentFormat
{
    /// <summary>TD1: three lines of 30 characters (the ID-card size).</summary>
    Td1,

    /// <summary>TD2: two lines of 36 characters.</summary>
    Td2,

    /// <summary>TD3: two lines of 44 characters (the passport size).</summary>
    Td3
}


/// <summary>
/// A parsed Machine Readable Zone (MRZ) per ICAO Doc 9303 Part 3: the optically read data printed on
/// the document, from which the Basic Access Control and PACE access keys are derived.
/// </summary>
/// <remarks>
/// <para>
/// The MRZ comes in three sizes — TD1 (3 × 30), TD2 (2 × 36), and TD3 (2 × 44) — distinguished by
/// length. This type extracts the fields that matter for access (document number, date of birth, date
/// of expiry) along with the issuing state, nationality, sex, and document code, and validates the
/// per-field check digits (Part 3 weights 7, 3, 1). When the document number exceeds nine characters
/// the field holds a filler in place of the check digit and the remainder spills into the optional
/// data, which this parser reassembles (Doc 9303 Part 3, §4.2.4).
/// </para>
/// <para>
/// <see cref="DocumentNumber"/> is the value used to derive the access key: the nine-character field
/// verbatim — including trailing fillers — for the common case, or the reassembled full number for
/// the extended case. It feeds the BAC / PACE key derivation directly. Dates are the raw six-digit
/// YYMMDD strings; century interpretation is the application's concern.
/// </para>
/// </remarks>
public sealed class MachineReadableZone
{
    private MachineReadableZone(
        MrzDocumentFormat format,
        string documentCode,
        string issuingState,
        string documentNumber,
        string nationality,
        string dateOfBirth,
        string dateOfExpiry,
        string sex)
    {
        Format = format;
        DocumentCode = documentCode;
        IssuingState = issuingState;
        DocumentNumber = documentNumber;
        Nationality = nationality;
        DateOfBirth = dateOfBirth;
        DateOfExpiry = dateOfExpiry;
        Sex = sex;
    }


    /// <summary>Gets the MRZ format.</summary>
    public MrzDocumentFormat Format { get; }

    /// <summary>Gets the document code (for example <c>P</c> for a passport).</summary>
    public string DocumentCode { get; }

    /// <summary>Gets the three-letter issuing state or organization code.</summary>
    public string IssuingState { get; }

    /// <summary>
    /// Gets the document number as used for access-key derivation: the nine-character MRZ field
    /// (including trailing fillers) for the common case, or the reassembled full number when the
    /// document number exceeds nine characters.
    /// </summary>
    public string DocumentNumber { get; }

    /// <summary>Gets the three-letter nationality code.</summary>
    public string Nationality { get; }

    /// <summary>Gets the date of birth as a six-digit YYMMDD string.</summary>
    public string DateOfBirth { get; }

    /// <summary>Gets the date of expiry as a six-digit YYMMDD string.</summary>
    public string DateOfExpiry { get; }

    /// <summary>Gets the sex field (<c>M</c>, <c>F</c>, or <c>&lt;</c> for unspecified).</summary>
    public string Sex { get; }


    /// <summary>
    /// Computes the ICAO Doc 9303 Part 3 check digit (weights 7, 3, 1) over an MRZ field.
    /// </summary>
    /// <param name="field">The MRZ field characters (digits, A-Z, and the filler '&lt;').</param>
    /// <returns>The check digit as the character '0'-'9'.</returns>
    public static char ComputeCheckDigit(ReadOnlySpan<char> field)
    {
        ReadOnlySpan<int> weights = [7, 3, 1];
        int sum = 0;
        for(int i = 0; i < field.Length; i++)
        {
            sum += CharacterValue(field[i]) * weights[i % weights.Length];
        }

        return (char)('0' + (sum % 10));
    }


    /// <summary>
    /// Parses a Machine Readable Zone. The input may contain line breaks or spaces between lines;
    /// they are ignored. The format is determined by the total character count.
    /// </summary>
    /// <param name="mrz">The MRZ characters (90 for TD1, 72 for TD2, 88 for TD3).</param>
    /// <returns>The parsed <see cref="MachineReadableZone"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the length matches no known MRZ format.</exception>
    /// <exception cref="InvalidOperationException">Thrown when a field check digit does not validate.</exception>
    public static MachineReadableZone Parse(string mrz)
    {
        ArgumentNullException.ThrowIfNull(mrz);

        string compact = Compact(mrz);

        return compact.Length switch
        {
            90 => ParseTd1(compact),
            72 => ParseTd2(compact),
            88 => ParseTd3(compact),
            _ => throw new ArgumentException(
                $"The MRZ has {compact.Length} characters, which matches no TD1 (90), TD2 (72), or TD3 (88) format.", nameof(mrz))
        };
    }


    /// <summary>
    /// Parses a TD1 MRZ (3 × 30): the document number and its overflow are on line 1, the dates and
    /// nationality on line 2, the name on line 3.
    /// </summary>
    private static MachineReadableZone ParseTd1(string mrz)
    {
        ReadOnlySpan<char> line1 = mrz.AsSpan(0, 30);
        ReadOnlySpan<char> line2 = mrz.AsSpan(30, 30);

        string documentCode = new(line1[0..2].TrimEnd('<'));
        string issuingState = new(line1[2..5].TrimEnd('<'));
        (string documentNumber, _) = ResolveDocumentNumber(line1[5..14], line1[14], line1[15..30]);

        string dateOfBirth = new(line2[0..6]);
        ValidateCheckDigit(dateOfBirth, line2[6], "date of birth");
        string sex = new(line2[7..8]);
        string dateOfExpiry = new(line2[8..14]);
        ValidateCheckDigit(dateOfExpiry, line2[14], "date of expiry");
        string nationality = new(line2[15..18].TrimEnd('<'));

        return new MachineReadableZone(
            MrzDocumentFormat.Td1, documentCode, issuingState, documentNumber, nationality, dateOfBirth, dateOfExpiry, sex);
    }


    /// <summary>
    /// Parses a TD2 MRZ (2 × 36): the name on line 1, the document number / dates on line 2.
    /// </summary>
    private static MachineReadableZone ParseTd2(string mrz)
    {
        ReadOnlySpan<char> line1 = mrz.AsSpan(0, 36);
        ReadOnlySpan<char> line2 = mrz.AsSpan(36, 36);

        return ParseTwoLine(MrzDocumentFormat.Td2, line1, line2, optionalLength: 7);
    }


    /// <summary>
    /// Parses a TD3 MRZ (2 × 44): the name on line 1, the document number / dates on line 2.
    /// </summary>
    private static MachineReadableZone ParseTd3(string mrz)
    {
        ReadOnlySpan<char> line1 = mrz.AsSpan(0, 44);
        ReadOnlySpan<char> line2 = mrz.AsSpan(44, 44);

        return ParseTwoLine(MrzDocumentFormat.Td3, line1, line2, optionalLength: 14);
    }


    /// <summary>
    /// Parses the shared TD2 / TD3 layout. Line 2 differs only in the optional-data width, which
    /// governs the document-number overflow region.
    /// </summary>
    private static MachineReadableZone ParseTwoLine(
        MrzDocumentFormat format, ReadOnlySpan<char> line1, ReadOnlySpan<char> line2, int optionalLength)
    {
        string documentCode = new(line1[0..2].TrimEnd('<'));
        string issuingState = new(line1[2..5].TrimEnd('<'));

        ReadOnlySpan<char> optional = line2.Slice(28, optionalLength);
        (string documentNumber, _) = ResolveDocumentNumber(line2[0..9], line2[9], optional);

        string nationality = new(line2[10..13].TrimEnd('<'));
        string dateOfBirth = new(line2[13..19]);
        ValidateCheckDigit(dateOfBirth, line2[19], "date of birth");
        string sex = new(line2[20..21]);
        string dateOfExpiry = new(line2[21..27]);
        ValidateCheckDigit(dateOfExpiry, line2[27], "date of expiry");

        return new MachineReadableZone(
            format, documentCode, issuingState, documentNumber, nationality, dateOfBirth, dateOfExpiry, sex);
    }


    /// <summary>
    /// Resolves the access-key document number from the nine-character field, its check-digit
    /// position, and the optional-data field that holds any overflow.
    /// </summary>
    /// <remarks>
    /// When the check-digit position holds a filler '&lt;' the document number exceeds nine
    /// characters: the optional data begins with the remaining characters followed by the check digit
    /// (computed over the whole number) and fillers. Otherwise the nine-character field — fillers
    /// included — is the access-key document number and the position holds its check digit.
    /// </remarks>
    private static (string DocumentNumber, char CheckDigit) ResolveDocumentNumber(
        ReadOnlySpan<char> field, char checkDigitPosition, ReadOnlySpan<char> optional)
    {
        if(checkDigitPosition == '<')
        {
            ReadOnlySpan<char> overflow = optional.TrimEnd('<');
            if(overflow.Length < 1)
            {
                throw new InvalidOperationException("The MRZ marks an extended document number but the optional data carries no overflow.");
            }

            char checkDigit = overflow[^1];
            string documentNumber = string.Concat(field, overflow[..^1]);
            ValidateCheckDigit(documentNumber, checkDigit, "document number");

            return (documentNumber, checkDigit);
        }

        string field9 = new(field);
        ValidateCheckDigit(field9, checkDigitPosition, "document number");

        return (field9, checkDigitPosition);
    }


    /// <summary>
    /// Throws when the check digit computed over <paramref name="field"/> does not equal <paramref name="expected"/>.
    /// </summary>
    private static void ValidateCheckDigit(ReadOnlySpan<char> field, char expected, string fieldName)
    {
        char computed = ComputeCheckDigit(field);
        if(computed != expected)
        {
            throw new InvalidOperationException(
                $"The MRZ {fieldName} check digit is '{expected}' but the computed value is '{computed}'.");
        }
    }


    /// <summary>
    /// Removes line breaks and spaces, leaving only the MRZ character cells.
    /// </summary>
    private static string Compact(string mrz)
    {
        Span<char> buffer = mrz.Length <= 128 ? stackalloc char[mrz.Length] : new char[mrz.Length];
        int written = 0;
        foreach(char c in mrz)
        {
            if(c is not ('\r' or '\n' or ' ' or '\t'))
            {
                buffer[written++] = c;
            }
        }

        return new string(buffer[..written]);
    }


    /// <summary>
    /// The MRZ character value: digits are 0-9, letters A-Z are 10-35, and the filler '&lt;' is 0.
    /// </summary>
    private static int CharacterValue(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'A' and <= 'Z' => c - 'A' + 10,
        '<' => 0,
        _ => throw new ArgumentException($"Invalid MRZ character '{c}'.", nameof(c))
    };
}
