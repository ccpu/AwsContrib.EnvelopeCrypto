using System.Security.Cryptography;

namespace AwsContrib.EnvelopeCrypto
{
	public interface IEnvelopeCryptoConfig
	{
		string AlgorithmName { get; }
		int KeyBits { get; }
		int BlockBytes { get; }
		int IVBytes { get; }
		CipherMode Mode { get; }
		PaddingMode Padding { get; }
	}
}