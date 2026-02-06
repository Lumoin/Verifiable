using Verifiable.Core.Model.Did;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.TestDataProviders
{
    internal delegate bool KeyFormatValidatorDelegate(KeyFormat keyFormat, CryptoAlgorithm alg);


    internal class KeyFormatValidator
    {
        private List<(Type Type, KeyFormatValidatorDelegate Validator)> Validators { get; } = [];


        public void AddValidator(Type type, KeyFormatValidatorDelegate validator)
        {
            Validators.Add((type, validator));
        }


        public bool Validate(KeyFormat keyFormat, CryptoAlgorithm alg)
        {
            foreach((Type type, KeyFormatValidatorDelegate validator) in Validators)
            {
                if(keyFormat.GetType() == type)
                {
                    return validator(keyFormat, alg);
                }
            }

            return false;
        }
    }
}
