using System;
using System.Collections.Generic;
using System.Linq;

using AwsContrib.EnvelopeCrypto;

namespace AwsContrib.EnvelopeCrypto.UnitTests
{
	public class DummyDataKeyProvider : IDataKeyProvider
	{
		public DummyDataKeyProvider()
		{
			// ReSharper disable once DoNotCallOverridableMethodsInConstructor
			EncryptedKeyById = new Dictionary<string, byte[]>();
		}

		public virtual byte[] GeneratedKey { get; set; }
		public virtual byte[] GeneratedEncryptedKey { get; set; }

		public virtual Dictionary<string, byte[]> EncryptedKeyById { get; set; }

		public virtual void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey)
		{
			key = GeneratedKey;
			encryptedKey = GeneratedEncryptedKey;
		}

		public virtual void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey, IDictionary<string, string> context)
		{
			if (context == null)
			{
				GenerateKey(keyBits, out key, out encryptedKey);
				return;
			}

			key = ProduceContextualKey(context);
			encryptedKey = EncryptedKeyById[context["id"]];
		}

		public byte[] EncryptKey(byte[] plainText)
		{
			return plainText.SequenceEqual(GeneratedKey) ? GeneratedEncryptedKey : new byte[] {0};
		}

		public byte[] EncryptKey(byte[] plainText, IDictionary<string, string> context)
		{
			throw new NotImplementedException();
		}

		public virtual byte[] DecryptKey(byte[] ciphertext)
		{
			return ciphertext.SequenceEqual(GeneratedEncryptedKey) ? GeneratedKey : new byte[] {0};
		}

		public byte[] DecryptKey(byte[] cipherText, IDictionary<string, string> context)
		{
			if (context == null)
			{
				return DecryptKey(cipherText);
			}
			byte[] encKey = EncryptedKeyById[context["id"]];
			return encKey.SequenceEqual(cipherText) ? ProduceContextualKey(context) : new byte[] {0};
		}

		public byte[] ProduceContextualKey(IDictionary<string, string> context)
		{
			if (context == null)
			{
				return GeneratedKey;
			}
			// Use the context's "id" key to jank up the key
			var specialSauce = (byte) (context["id"].GetHashCode());
			return GeneratedKey.Select(x => (byte) (x ^ specialSauce)).ToArray();
		}
	}
}