using System.Collections.Generic;
using System.Security.Cryptography;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	internal class CryptoConfig : IEnvelopeCryptoConfig
	{
		private static readonly IEnvelopeCryptoConfig _defaultConfig = new DefaultEnvelopeCryptoConfig();

		private static readonly Dictionary<string, int> _blockBitsByAlgorithm = new Dictionary<string, int>
		{
			{"AES", 128},
			{"DES", 64},
			{"RC2", 64},
			{"RIJNDAEL", 128},
			{"TRIPLEDES", 64}
		};

		public CryptoConfig(string algorithmName, int keyBits)
		{
			AlgorithmName = algorithmName.ToUpperInvariant();
			KeyBits = keyBits;

			// Assign sane defaults. If you decide to do something nonstandard, you can provide your own crypto config.
			Mode = _defaultConfig.Mode;
			Padding = _defaultConfig.Padding;

			int blockBits;
			if (_blockBitsByAlgorithm.TryGetValue(algorithmName, out blockBits))
			{
				BlockBytes = blockBits / 8;
				IVBytes = BlockBytes;
			}
		}

		public string AlgorithmName { get; set; }
		public int KeyBits { get; set; }
		public int BlockBytes { get; set; }
		public int IVBytes { get; set; }
		public CipherMode Mode { get; set; }
		public PaddingMode Padding { get; set; }
	}
}