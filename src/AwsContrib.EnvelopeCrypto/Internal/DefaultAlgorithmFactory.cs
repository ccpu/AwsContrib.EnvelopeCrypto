using System.Security.Cryptography;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	internal class DefaultAlgorithmFactory : IAlgorithmFactory
	{
		public ISymmetricAlgorithm CreateAlgorithm(string name, int keyBits, CipherMode mode, PaddingMode padding)
		{
			ISymmetricAlgorithm algo = null;
			try
			{
				algo = new SymmetricAlgorithmWrapper(SymmetricAlgorithm.Create(name))
				{
					KeyBits = keyBits,
					Mode = mode,
					Padding = padding
				};
				return algo;
			}
			catch
			{
				if (algo != null)
				{
					algo.Dispose();
				}
				throw;
			}
		}
	}
}