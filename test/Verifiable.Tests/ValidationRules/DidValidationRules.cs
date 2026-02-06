using System.Text.RegularExpressions;
using Verifiable.Core.Assessment;
using Verifiable.Core.Model.Did;


namespace Verifiable.Core.Did
{
    /// <summary>
    /// Contains validation rules common for all DID documents.
    /// </summary>
    internal static class DidDocumentValidationRules
    {
        public static IList<Claim> ValidatePrefix(DidDocument document)
        {
            Regex regex = DidUrlRegex.AbsoluteDidUrl();
            bool isSuccess = regex.IsMatch(document.Id?.Id ?? string.Empty);
            return
            [
                new(ClaimId.KeyDidIdFormat, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure)
            ];
        }
    }
}
