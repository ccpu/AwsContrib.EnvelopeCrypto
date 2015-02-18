using System.Security.Cryptography;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	internal interface IAlgorithmFactory
	{
		/// <summary>
		///     Creates an <see cref="ISymmetricAlgorithm" /> with the given parameters.
		/// </summary>
		/// <param name="name">the algorithm name (see <see cref="SymmetricAlgorithm.Create(string)" /></param>
		/// <param name="keyBits">the number of bits in the key</param>
		/// <param name="mode">the cipher mode to use</param>
		/// <param name="padding">the padding mode to use</param>
		/// <returns></returns>
		ISymmetricAlgorithm CreateAlgorithm(string name, int keyBits, CipherMode mode, PaddingMode padding);
	}
}