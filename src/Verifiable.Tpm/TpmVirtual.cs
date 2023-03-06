namespace Verifiable.Tpm
{
    public class TpmVirtual: ITpm
    {
        public static bool IsSupported { get; } = true;
    }
}
