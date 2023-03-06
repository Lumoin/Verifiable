namespace Verifiable.Jwt
{
    /// <summary>
    /// A utility class for Base64 URL encoding and decoding.
    /// </summary>
    public static class Base64Url
    {
        public static string Encode(ReadOnlySpan<byte> input)
        {
            string output = Convert.ToBase64String(input);
            output = output.Split('=')[0];
            output = output.Replace('+', '-');
            output = output.Replace('/', '_');

            return output;
        }


        public static ReadOnlySpan<byte> Decode(string input)
        {
            string output = input;
            output = output.Replace('-', '+');
            output = output.Replace('_', '/');
            switch(output.Length % 4)
            {
                case 0:
                {
                    break;
                }
                case 2:
                {
                    output += "=="; break;
                }
                case 3:
                {
                    output += "="; break;
                }
                default:
                {
                    throw new ArgumentException("Not a Base64 encoded string.", nameof(input));
                }
            }

            return Convert.FromBase64String(output);
        }
    }
}
