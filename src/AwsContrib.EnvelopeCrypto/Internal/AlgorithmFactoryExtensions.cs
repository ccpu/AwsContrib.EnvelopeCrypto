namespace AwsContrib.EnvelopeCrypto.Internal
{
	internal static class AlgorithmFactoryExtensions
	{
		public static ISymmetricAlgorithm CreateAlgorithm(this IAlgorithmFactory self, IEnvelopeCryptoConfig config)
		{
			return self.CreateAlgorithm(config.AlgorithmName, config.KeyBits, config.Mode, config.Padding);
		}
	}
}