using System.Security.Cryptography;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	internal class DefaultEnvelopeCryptoConfig : IEnvelopeCryptoConfig
	{
		public virtual string AlgorithmName
		{
			get { return @"AES"; }
		}

		public virtual int KeyBits
		{
			get { return 256; }
		}

		public virtual int BlockBytes
		{
			get { return 16; }
		}

		public virtual int IVBytes
		{
			get { return BlockBytes; }
		}

		public virtual CipherMode Mode
		{
			get { return CipherMode.CBC; }
		}

		public virtual PaddingMode Padding
		{
			get { return PaddingMode.PKCS7; }
		}
	}
}