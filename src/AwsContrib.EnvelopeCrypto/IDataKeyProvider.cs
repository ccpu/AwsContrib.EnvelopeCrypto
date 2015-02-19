using System.Collections.Generic;

namespace AwsContrib.EnvelopeCrypto
{
	public interface IDataKeyProvider
	{
		void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey);

		void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey, IDictionary<string, string> context);

		byte[] EncryptKey(byte[] plainText);

		byte[] EncryptKey(byte[] plainText, IDictionary<string, string> context);

		byte[] DecryptKey(byte[] cipherText);

		byte[] DecryptKey(byte[] cipherText, IDictionary<string, string> context);
	}
}