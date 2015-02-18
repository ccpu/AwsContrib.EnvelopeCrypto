using System.Security.Cryptography;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	internal class SymmetricAlgorithmWrapper : ISymmetricAlgorithm
	{
		private readonly SymmetricAlgorithm _algo;

		public SymmetricAlgorithmWrapper(SymmetricAlgorithm algo)
		{
			_algo = algo;
		}

		public void Dispose()
		{
			_algo.Dispose();
		}

		public void Clear()
		{
			_algo.Clear();
		}

		public bool ValidKeySize(int bitLength)
		{
			return _algo.ValidKeySize(bitLength);
		}

		public ICryptoTransform CreateEncryptor()
		{
			return _algo.CreateEncryptor();
		}

		public ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
		{
			return _algo.CreateEncryptor(rgbKey, rgbIV);
		}

		public ICryptoTransform CreateDecryptor()
		{
			return _algo.CreateDecryptor();
		}

		public ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
		{
			return _algo.CreateDecryptor(rgbKey, rgbIV);
		}

		public void GenerateKey()
		{
			_algo.GenerateKey();
		}

		public void GenerateIV()
		{
			_algo.GenerateIV();
		}

		public int BlockSize
		{
			get { return _algo.BlockSize; }
			set { _algo.BlockSize = value; }
		}

		public int BlockBytes
		{
			get { return BlockSize; }
			set { BlockSize = value; }
		}

		public int FeedbackSize
		{
			get { return _algo.FeedbackSize; }
			set { _algo.FeedbackSize = value; }
		}

		public byte[] IV
		{
			get { return _algo.IV; }
			set { _algo.IV = value; }
		}

		public byte[] Key
		{
			get { return _algo.Key; }
			set { _algo.Key = value; }
		}

		public KeySizes[] LegalBlockSizes
		{
			get { return _algo.LegalBlockSizes; }
		}

		public KeySizes[] LegalKeySizes
		{
			get { return _algo.LegalKeySizes; }
		}

		public int KeySize
		{
			get { return _algo.KeySize; }
			set { _algo.KeySize = value; }
		}

		public int KeyBits
		{
			get { return KeySize; }
			set { KeySize = value; }
		}

		public CipherMode Mode
		{
			get { return _algo.Mode; }
			set { _algo.Mode = value; }
		}

		public PaddingMode Padding
		{
			get { return _algo.Padding; }
			set { _algo.Padding = value; }
		}
	}
}