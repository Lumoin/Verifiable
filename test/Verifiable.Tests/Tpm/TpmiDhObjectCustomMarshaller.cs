using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Verifiable.Tpm
{
    /*
    public struct TpmiDhObjectCustomMarshaller: INativeMarshalling<TpmiDhObject>
    {
        private uint _value;

        public void MarshalManagedToNative(TpmiDhObject managedValue)
        {
            _value = managedValue.Value;
        }

        public TpmiDhObject MarshalNativeToManaged()
        {
            return new TpmiDhObject(_value);
        }

        public IntPtr AllocateManagedToNative()
        {
            return Marshal.AllocHGlobal(sizeof(uint));
        }

        public void FreeNativeToManaged()
        {
            Marshal.FreeHGlobal((IntPtr)Unsafe.AsPointer(ref this));
        }
    }*/
}
