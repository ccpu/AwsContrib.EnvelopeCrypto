using System;
using System.Security.Cryptography;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	// Allows mocking SymmetricAlgorithm in tests.
	internal interface ISymmetricAlgorithm : IDisposable
	{
		int BlockSize { get; set; }
		int FeedbackSize { get; set; }
		byte[] IV { get; set; }
		byte[] Key { get; set; }
		KeySizes[] LegalBlockSizes { get; }
		KeySizes[] LegalKeySizes { get; }
		int KeySize { get; set; }
		CipherMode Mode { get; set; }
		PaddingMode Padding { get; set; }

		int KeyBits { get; }
		int BlockBytes { get; }

		void Clear();

		bool ValidKeySize(int bitLength);

		ICryptoTransform CreateEncryptor();

		ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV);

		ICryptoTransform CreateDecryptor();

		ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV);

		void GenerateKey();

		void GenerateIV();
	}
}