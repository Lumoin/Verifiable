using System;
using System.Runtime.InteropServices;

namespace Verifiable;

/// <summary>
/// Cross-platform console formatting with ANSI escape codes.
/// Falls back to plain text when colors are not supported.
/// </summary>
/// <remarks>
/// <para>
/// Color scheme inspired by brand colors:
/// </para>
/// <list type="bullet">
///   <item><description>Primary blue (#439AFF) - headers, emphasis.</description></item>
///   <item><description>Accent green (#B4FF57) - success, positive states.</description></item>
///   <item><description>Dark blue-gray (#2c3e50) - secondary, muted text.</description></item>
/// </list>
/// </remarks>
internal static class ConsoleFormatter
{
    private static readonly bool colorsSupported;
    private static readonly bool trueColorSupported;
    private static bool colorsDisabled;

    static ConsoleFormatter()
    {
        colorsSupported = DetectColorSupport();
        trueColorSupported = DetectTrueColorSupport();
    }

    /// <summary>
    /// Gets whether ANSI colors are supported in the current terminal.
    /// </summary>
    public static bool ColorsSupported => colorsSupported && !colorsDisabled;

    /// <summary>
    /// Disables colors for the current process. Used by --no-color flag.
    /// </summary>
    public static void DisableColors()
    {
        colorsDisabled = true;
    }

    //ANSI escape codes.
    private const string Esc = "\x1b[";
    private const string Reset = "\x1b[0m";

    //Brand colors as RGB.
    private const string BrandBlueRgb = "38;2;67;154;255";      //#439AFF
    private const string BrandGreenRgb = "38;2;180;255;87";     //#B4FF57
    private const string BrandGrayRgb = "38;2;44;62;80";        //#2c3e50
    private const string BrandWhiteRgb = "38;2;255;255;255";    //#FFFFFF

    //256-color fallbacks (closest matches).
    private const string BrandBlue256 = "38;5;75";              //SteelBlue1
    private const string BrandGreen256 = "38;5;155";            //GreenYellow-ish
    private const string BrandGray256 = "38;5;238";             //Gray23
    private const string BrandWhite256 = "38;5;255";            //Gray93

    //Basic ANSI fallbacks (8/16 color).
    private const string BasicBlue = "94";                      //Bright blue
    private const string BasicGreen = "92";                     //Bright green
    private const string BasicGray = "90";                      //Bright black (gray)
    private const string BasicWhite = "97";                     //Bright white
    private const string BasicRed = "91";                       //Bright red
    private const string BasicYellow = "93";                    //Bright yellow

    //Styles.
    private const string BoldCode = "1";
    private const string DimCode = "2";

    /// <summary>
    /// Applies brand primary color (blue) to text.
    /// </summary>
    public static string Primary(string text) => Colorize(text, BrandBlueRgb, BrandBlue256, BasicBlue);

    /// <summary>
    /// Applies brand accent color (green) to text.
    /// </summary>
    public static string Accent(string text) => Colorize(text, BrandGreenRgb, BrandGreen256, BasicGreen);

    /// <summary>
    /// Applies brand muted color (dark gray) to text.
    /// </summary>
    public static string Muted(string text) => Colorize(text, BrandGrayRgb, BrandGray256, BasicGray);

    //Semantic colors.
    public static string Success(string text) => Accent(text);
    public static string Warning(string text) => Colorize(text, "38;2;255;200;0", "38;5;220", BasicYellow);
    public static string Error(string text) => Colorize(text, "38;2;255;85;85", "38;5;203", BasicRed);

    //Text styles.
    public static string Bold(string text) => Style(text, BoldCode);
    public static string Dim(string text) => Style(text, DimCode);

    //Combined styles.
    public static string Header(string text) => Bold(Primary(text));
    public static string Label(string text) => Muted(text);
    public static string Value(string text) => Colorize(text, BrandWhiteRgb, BrandWhite256, BasicWhite);

    /// <summary>
    /// Prints a labeled value with consistent formatting.
    /// </summary>
    public static void WriteLabeled(string label, string value, int labelWidth = 20)
    {
        string paddedLabel = label.PadRight(labelWidth);
        Console.WriteLine($"  {Label(paddedLabel)} {Value(value)}");
    }

    /// <summary>
    /// Prints a section header.
    /// </summary>
    public static void WriteHeader(string text)
    {
        Console.WriteLine();
        Console.WriteLine(Header(text));

        string line = new string('─', text.Length);
        Console.WriteLine(Muted(line));
    }

    private static string Colorize(string text, string rgbCode, string code256, string basicCode)
    {
        if(!ColorsSupported)
        {
            return text;
        }

        string colorCode = trueColorSupported ? rgbCode : code256;

        return $"{Esc}{colorCode}m{text}{Reset}";
    }

    private static string Style(string text, string styleCode)
    {
        if(!ColorsSupported)
        {
            return text;
        }

        return $"{Esc}{styleCode}m{text}{Reset}";
    }

    private static bool DetectColorSupport()
    {
        //Check for explicit disable.
        string? noColor = Environment.GetEnvironmentVariable("NO_COLOR");
        if(!string.IsNullOrEmpty(noColor))
        {
            return false;
        }

        //Check for explicit enable.
        string? forceColor = Environment.GetEnvironmentVariable("FORCE_COLOR");
        if(!string.IsNullOrEmpty(forceColor))
        {
            return true;
        }

        //If not a terminal (redirected), disable colors.
        if(Console.IsOutputRedirected)
        {
            return false;
        }

        //On Windows, try to enable virtual terminal processing.
        if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return TryEnableWindowsAnsi();
        }

        //Linux/macOS: ANSI is supported by default.
        return true;
    }

    private static bool DetectTrueColorSupport()
    {
        //Check COLORTERM environment variable.
        string? colorTerm = Environment.GetEnvironmentVariable("COLORTERM");
        if(colorTerm is "truecolor" or "24bit")
        {
            return true;
        }

        //Check TERM for known true-color terminals.
        string? term = Environment.GetEnvironmentVariable("TERM");
        if(term is not null &&
            (term.Contains("256color", StringComparison.InvariantCultureIgnoreCase) 
            || term.Contains("truecolor", StringComparison.InvariantCultureIgnoreCase)))
        {
            return true;
        }

        //Windows Terminal and modern Windows consoles support true color.
        if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            string? wtSession = Environment.GetEnvironmentVariable("WT_SESSION");
            if(!string.IsNullOrEmpty(wtSession))
            {
                return true;
            }
        }

        //Default to 256-color for safety.
        return false;
    }

    private static bool TryEnableWindowsAnsi()
    {
        try
        {
            const int STD_OUTPUT_HANDLE = -11;
            const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;

            IntPtr handle = GetStdHandle(STD_OUTPUT_HANDLE);
            if(handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                return false;
            }

            if(!GetConsoleMode(handle, out uint mode))
            {
                return false;
            }

            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            return SetConsoleMode(handle, mode);
        }
        catch
        {
            return false;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
}