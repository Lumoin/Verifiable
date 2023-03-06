using System;

namespace Verifiable.Tpm.Structures
{
    [Flags]
    public enum TPMA_MODES: uint
    {
        FIPS_140_2 = 0x00000001,
        RESERVED1_MASK = 0xFFFFFFFE
    }
}
