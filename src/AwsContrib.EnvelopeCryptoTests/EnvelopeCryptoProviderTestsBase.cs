using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

using AwsContrib.EnvelopeCrypto;

using NUnit.Framework;

namespace AwsContrib.EnvelopeCryptoTests
{
	public class EnvelopeCryptoProviderTestsBase
	{
		protected byte[] RealKey { get; set; }
		protected DummyDataKeyProvider DummyDataKeyProvider { get; set; }
		protected EnvelopeCryptoProvider Provider { get; set; }
		protected IDictionary<string, string> Context1 { get; set; }
		protected IDictionary<string, string> Context2 { get; set; }

		[SetUp]
		public void SetUp()
		{
			RealKey = GenerateKey();
			DummyDataKeyProvider = new DummyDataKeyProvider
			{
				GeneratedKey = RealKey,
				GeneratedEncryptedKey = Bytes(200, 201, 202)
			};

			// These contexts will be used to verify that using a different context produces different ciphertext.
			Context1 = new Dictionary<string, string> {{"id", "1"}};
			Context2 = new Dictionary<string, string> {{"id", "2"}};

			// Set up the dummy key provider to return an easily testable encrypted key based on the crypto context.
			DummyDataKeyProvider.EncryptedKeyById["1"] = Bytes(1, 1, 1);
			DummyDataKeyProvider.EncryptedKeyById["2"] = Bytes(2, 2, 2);

			Provider = new EnvelopeCryptoProvider(DummyDataKeyProvider);
		}

		// Bytes(1,2,3) is syntactic sugar for "new byte[] { 1,2,3 }"
		protected static byte[] Bytes(params byte[] bytes)
		{
			return bytes;
		}

		// Produces a key suitable for use with EnvelopeCryptoProvider
		protected static byte[] GenerateKey()
		{
			byte[] realKey;
			using (SymmetricAlgorithm algo = SymmetricAlgorithm.Create(EnvelopeCryptoProvider.AlgorithmName))
			{
				algo.KeySize = EnvelopeCryptoProvider.KeyBits;
				algo.GenerateKey();
				realKey = algo.Key;
			}
			return realKey;
		}

		// Do not use in production code. This is slow.
		protected static byte[] ReadAllBytes(Stream input)
		{
			using (var memStream = new MemoryStream())
			{
				input.CopyTo(memStream);
				return memStream.ToArray();
			}
		}
	}
}