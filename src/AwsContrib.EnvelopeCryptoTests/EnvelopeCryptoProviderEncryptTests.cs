using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using AwsContrib.EnvelopeCrypto;

using FluentAssertions;

using NUnit.Framework;

namespace AwsContrib.EnvelopeCryptoTests
{
	public class EnvelopeCryptoProviderEncryptTests : EnvelopeCryptoProviderTestsBase
	{
		[Test]
		public void Encrypt_SameData_DifferentCiphertext()
		{
			// Ensure that subsequent calls to Encrypt with the same content produce different ciphertexts.
			// Even though our key generator is stubbed, the encryption operation should generate a new IV
			// each time which will change the result.
			string dataKey1;
			string encrypted1 = Provider.Encrypt(out dataKey1, "Hello");

			string dataKey2;
			string encrypted2 = Provider.Encrypt(out dataKey2, "Hello");

			// validate the assumptions of this test
			dataKey1.Should().Be(dataKey2, "the key generator is stubbed");

			encrypted1.Should().NotBe(encrypted2, "the IV should have changed");
			Provider.Decrypt(dataKey1, encrypted1)
			        .Should().Be(Provider.Decrypt(dataKey2, encrypted2))
			        .And.Be("Hello");
		}

		[Test]
		public void Encrypt_Bytes_RawKey_Multi()
		{
			var plaintextBlobs = new List<byte[]>
			{
				Bytes(0, 1, 2),
				Bytes(3, 4, 5)
			};

			byte[] dataKey;
			List<byte[]> encrypted = Provider.Encrypt(out dataKey, plaintextBlobs).ToList();

			dataKey.Should().Equal(Bytes(200, 201, 202));
			encrypted.Count.Should().Be(plaintextBlobs.Count);

			for (int i = 0; i < plaintextBlobs.Count; i++)
			{
				CheckEncryptionResultBytes(encrypted[i], plaintextBlobs[i]);
			}
		}

		[Test]
		public void Encrypt_Bytes_RawKey_Single()
		{
			byte[] dataKey;
			byte[] singleEnc = Provider.Encrypt(out dataKey, Bytes(4, 5, 6));
			dataKey.Should().Equal(Bytes(200, 201, 202));
			CheckEncryptionResultBytes(singleEnc, Bytes(4, 5, 6));
		}

		[Test]
		public void Encrypt_Bytes_StringKey_Single()
		{
			string dataKey;
			byte[] singleEnc = Provider.Encrypt(out dataKey, Bytes(4, 5, 6));
			dataKey.Should().Be("yMnK");
			CheckEncryptionResultBytes(singleEnc, Bytes(4, 5, 6));
		}

		[Test]
		public void Encrypt_Bytes_StringKey_Multi()
		{
			var plaintextBlobs = new List<byte[]>
			{
				Bytes(0, 1, 2),
				Bytes(3, 4, 5)
			};

			string dataKey;
			List<byte[]> encrypted = Provider.Encrypt(out dataKey, plaintextBlobs).ToList();

			dataKey.Should().Be("yMnK");
			encrypted.Count.Should().Be(plaintextBlobs.Count);

			for (int i = 0; i < plaintextBlobs.Count; i++)
			{
				CheckEncryptionResultBytes(encrypted[i], plaintextBlobs[i]);
			}
		}

		[Test]
		public void Encrypt_Strings_StringKey_Multi()
		{
			string dataKey;
			var plaintexts = new List<string> {"secret", "message"};

			List<string> encrypted = Provider.Encrypt(out dataKey, plaintexts).ToList();

			// base64 of 200,201,202
			dataKey.Should().Be("yMnK");
			encrypted.Count.Should().Be(2);

			for (int i = 0; i < plaintexts.Count; i++)
			{
				CheckEncryptionResultString(encrypted[i], plaintexts[i]);
			}
		}

		[Test]
		public void Encrypt_Strings_StringKey_Single()
		{
			string dataKey;
			string singleEnc = Provider.Encrypt(out dataKey, "secret");
			dataKey.Should().Be("yMnK");
			CheckEncryptionResultString(singleEnc, "secret");
		}

		[Test]
		public void Encrypt_SameData_DifferentCiphertext_Context()
		{
			// Ensure that subsequent calls to Encrypt with the same content produce different ciphertexts.
			// Even though our key generator is stubbed, the encryption operation should generate a new IV
			// each time which will change the result.
			string dataKey1;
			string encrypted1 = Provider.Encrypt(out dataKey1, "Hello");

			string dataKey2;
			string encrypted2 = Provider.Encrypt(out dataKey2, "Hello");

			// validate the assumptions of this test
			dataKey1.Should().Be(dataKey2, "the key generator is stubbed");

			encrypted1.Should().NotBe(encrypted2, "the IV should have changed");
			Provider.Decrypt(dataKey1, encrypted1)
			        .Should().Be(Provider.Decrypt(dataKey2, encrypted2))
			        .And.Be("Hello");
		}

		[Test]
		public void Encrypt_Bytes_RawKey_Multi_Context()
		{
			var plaintextBlobs = new List<byte[]>
			{
				Bytes(0, 1, 2),
				Bytes(3, 4, 5)
			};

			byte[] dataKey;
			List<byte[]> encrypted = Provider.Encrypt(out dataKey, plaintextBlobs, Context1).ToList();

			// proves that the contextualized key generator was used
			dataKey.Should().Equal(Bytes(1, 1, 1));
			encrypted.Count.Should().Be(plaintextBlobs.Count);

			for (int i = 0; i < plaintextBlobs.Count; i++)
			{
				encrypted[i].Should().NotEqual(plaintextBlobs[i]);
				encrypted[i].Length.Should().BeGreaterThan(plaintextBlobs[i].Length);
			}
		}

		[Test]
		public void Encrypt_Bytes_RawKey_Single_Context()
		{
			byte[] dataKey;
			byte[] singleEnc = Provider.Encrypt(out dataKey, Bytes(4, 5, 6), Context2);

			// proves that the contextualized key generator was used
			dataKey.Should().Equal(Bytes(2, 2, 2));

			singleEnc.Should().NotEqual(Bytes(4, 5, 6));
			singleEnc.Length.Should().BeGreaterThan(3);
		}

		[Test]
		public void Encrypt_Bytes_StringKey_Single_Context()
		{
			string dataKey;
			byte[] singleEnc = Provider.Encrypt(out dataKey, Bytes(4, 5, 6), Context1);
			dataKey.Should().Be("AQEB"); // 1, 1, 1
			singleEnc.Should().NotEqual(Bytes(4, 5, 6));
			singleEnc.Length.Should().BeGreaterThan(3);
		}

		[Test]
		public void Encrypt_Bytes_StringKey_Multi_Context()
		{
			var plaintextBlobs = new List<byte[]>
			{
				Bytes(0, 1, 2),
				Bytes(3, 4, 5)
			};

			string dataKey;
			List<byte[]> encrypted = Provider.Encrypt(out dataKey, plaintextBlobs, Context2).ToList();

			dataKey.Should().Be("AgIC"); // 2,2,2
			encrypted.Count.Should().Be(plaintextBlobs.Count);

			for (int i = 0; i < plaintextBlobs.Count; i++)
			{
				encrypted[i].Should().NotEqual(plaintextBlobs[i]);
				encrypted[i].Length.Should().BeGreaterThan(plaintextBlobs[i].Length);
			}
		}

		[Test]
		public void Encrypt_Strings_StringKey_Multi_Context()
		{
			string dataKey;
			var plaintexts = new List<string> {"secret", "message"};

			List<string> encrypted = Provider.Encrypt(out dataKey, plaintexts, Context2).ToList();

			dataKey.Should().Be("AgIC"); // 2,2,2
			encrypted.Count.Should().Be(2);

			for (int i = 0; i < plaintexts.Count; i++)
			{
				encrypted[i].Length.Should().BeGreaterThan(plaintexts[i].Length);
			}
		}

		[Test]
		public void Encrypt_Strings_StringKey_Single_Context()
		{
			string dataKey;
			string singleEnc = Provider.Encrypt(out dataKey, "secret", Context1);
			dataKey.Should().Be("AQEB"); // 1, 1, 1
			singleEnc.Should().NotBe("secret");
			singleEnc.Length.Should().BeGreaterThan("secret".Length);
		}

		[Test]
		public void Encrypt_Stream_RawKey()
		{
			byte[] dataKey;
			byte[] payload = Bytes(4, 5, 6);
			Stream plainStream = new MemoryStream(payload);
			using (Stream cipherStream = Provider.Encrypt(out dataKey, plainStream))
			{
				dataKey.Should().Equal(Bytes(200, 201, 202));
				byte[] result = ReadAllBytes(cipherStream);
				CheckEncryptionResultBytes(result, Bytes(4, 5, 6));
			}
		}

		[Test]
		public void Encrypt_Stream_RawKey_Context()
		{
			byte[] dataKey;
			byte[] payload = Bytes(4, 5, 6);
			Stream plainStream = new MemoryStream(payload);
			using (Stream cipherStream = Provider.Encrypt(out dataKey, plainStream, Context1))
			{
				dataKey.Should().Equal(Bytes(1, 1, 1));
				byte[] result = ReadAllBytes(cipherStream);
				CheckEncryptionResultBytes(result, Bytes(4, 5, 6), Context1);
			}
		}

		[Test]
		public void Encrypt_Stream_StringKey_Context()
		{
			string dataKey;
			byte[] payload = Bytes(4, 5, 6);
			Stream plainStream = new MemoryStream(payload);
			using (Stream cipherStream = Provider.Encrypt(out dataKey, plainStream, Context1))
			{
				dataKey.Should().Be("AQEB"); // 1, 1, 1
				byte[] result = ReadAllBytes(cipherStream);
				CheckEncryptionResultBytes(result, Bytes(4, 5, 6), Context1);
			}
		}

		[Test]
		public void Encrypt_Stream_StringKey()
		{
			string dataKey;
			byte[] payload = Bytes(4, 5, 6);
			Stream plainStream = new MemoryStream(payload);
			using (Stream cipherStream = Provider.Encrypt(out dataKey, plainStream))
			{
				dataKey.Should().Be("yMnK");
				byte[] result = ReadAllBytes(cipherStream);
				CheckEncryptionResultBytes(result, Bytes(4, 5, 6));
			}
		}

		[Test]
		public void Encrypt_Stream_BoundaryConditions()
		{
			EncryptStreamWithSize(0);
			EncryptStreamWithSize(1);
			EncryptStreamWithSize(EnvelopeCryptoProvider.BlockBytes - 1);
			EncryptStreamWithSize(EnvelopeCryptoProvider.BlockBytes);
			EncryptStreamWithSize(EnvelopeCryptoProvider.BlockBytes + 1);
			EncryptStreamWithSize(EnvelopeCryptoProvider.BlockBytes * 2 - 1);
			EncryptStreamWithSize(EnvelopeCryptoProvider.BlockBytes * 2);
			EncryptStreamWithSize(EnvelopeCryptoProvider.BlockBytes * 2 + 1);
		}

		[Test]
		public void Encrypt_Stream_Large()
		{
			const int kb = 1024;
			const int mb = kb * 1024;

			// Warm it up. Encrypting 20MB should take no more RAM than encrypting 1KB.
			EncryptStreamWithSize(1 * kb, checkResult: false);
			var before = (double) GC.GetTotalMemory(forceFullCollection: true);

			EncryptStreamWithSize(20 * mb, checkResult: false);
			var after = (double) GC.GetTotalMemory(forceFullCollection: true);

			// willing to accept +/- 10%
			after.Should().BeInRange(before * 0.90, before * 1.10);
		}

#if !TEST_CRYPTO_HUGESTREAMS
		[Ignore]
#endif
		[Test]
		public void Encrypt_Stream_Huge()
		{
			const int kb = 1024;
			const int mb = kb * 1024;
			const int gb = mb * 1024;

			const long streamSize = 2L * gb;

			// Warm it up. Encrypting 20MB should take no more RAM than encrypting 1KB.
			EncryptStreamWithSize(1 * kb, checkResult: false);
			var before = (double) GC.GetTotalMemory(forceFullCollection: true);

			var stopWatch = new Stopwatch();
			stopWatch.Start();
			EncryptStreamWithSize(streamSize, checkResult: false);
			stopWatch.Stop();

			var after = (double) GC.GetTotalMemory(forceFullCollection: true);

			double megsPerSecond = streamSize / mb / stopWatch.Elapsed.TotalSeconds;
			Console.WriteLine("Encrypted {0} MB in {1:F2} seconds ({2:F2} MB/s)",
				streamSize / mb, stopWatch.Elapsed.TotalSeconds, megsPerSecond);

			// willing to accept +/- 10%
			after.Should().BeInRange(before * 0.90, before * 1.10);
		}

		private void EncryptStreamWithSize(long streamSize, bool checkResult = true)
		{
			long minSize = streamSize + EnvelopeCryptoProvider.IVBytes;
			long maxSize = minSize + EnvelopeCryptoProvider.BlockBytes;

			List<byte> cipherText = null;
			if (checkResult)
			{
				cipherText = new List<byte>((int) streamSize + EnvelopeCryptoProvider.BlockBytes * 2);
			}

			Stream plainStream = new FakeStream(streamSize);
			byte[] dataKey;
			using (Stream cipherStream = Provider.Encrypt(out dataKey, plainStream))
			{
				long total = 0;
				var buffer = new byte[1024 * 512];
				int bytesRead;
				while ((bytesRead = cipherStream.Read(buffer, 0, buffer.Length)) != 0)
				{
					total += bytesRead;
					if (checkResult)
					{
						cipherText.AddRange(buffer.Take(bytesRead));
					}
				}
				total.Should().BeInRange(minSize, maxSize);
			}

			if (checkResult)
			{
				plainStream = new FakeStream(streamSize);
				var expected = new byte[(int) streamSize];
				plainStream.Read(expected, 0, (int) streamSize);
				Provider.Decrypt(dataKey, cipherText.ToArray()).Should().Equal(expected);
			}
		}

		private void CheckEncryptionResultBytes(byte[] encrypted, byte[] expected, IDictionary<string, string> context = null)
		{
			byte[] key = DummyDataKeyProvider.ProduceContextualKey(context);
			var iv = new byte[EnvelopeCryptoProvider.IVBytes];
			var cipherText = new byte[encrypted.Length - EnvelopeCryptoProvider.IVBytes];
			Array.Copy(encrypted, iv, EnvelopeCryptoProvider.IVBytes);
			Array.Copy(encrypted, EnvelopeCryptoProvider.IVBytes, cipherText, 0, cipherText.Length);

			using (var aes = new AesCryptoServiceProvider())
			{
				aes.KeySize = EnvelopeCryptoProvider.KeyBits;
				aes.Key = key;
				aes.IV = iv;
				aes.Mode = EnvelopeCryptoProvider.Mode;
				aes.Padding = EnvelopeCryptoProvider.Padding;
				using (var inputStream = new MemoryStream(cipherText))
				{
					using (ICryptoTransform decryptor = aes.CreateDecryptor())
					{
						using (var outputStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
						{
							byte[] decrypted = ReadAllBytes(outputStream);
							decrypted.Should().Equal(expected);
						}
					}
				}
			}
		}

		private void CheckEncryptionResultString(string encryptedString, string expected, IDictionary<string, string> context = null)
		{
			byte[] key = DummyDataKeyProvider.ProduceContextualKey(context);
			var pattern = new Regex(@"^\{\w+-\d+-\w+\}");
			Match match = pattern.Match(encryptedString);
			match.Should().NotBeNull();
			match.Value.Should().Be("{AES-256-CBC}");

			string content = encryptedString.Substring(match.Length);
			byte[] encrypted = Convert.FromBase64String(content);

			var iv = new byte[EnvelopeCryptoProvider.IVBytes];
			var cipherText = new byte[encrypted.Length - EnvelopeCryptoProvider.IVBytes];
			Array.Copy(encrypted, iv, EnvelopeCryptoProvider.IVBytes);
			Array.Copy(encrypted, EnvelopeCryptoProvider.IVBytes, cipherText, 0, cipherText.Length);

			using (var aes = new AesCryptoServiceProvider())
			{
				aes.KeySize = EnvelopeCryptoProvider.KeyBits;
				aes.Key = key;
				aes.IV = iv;
				aes.Mode = EnvelopeCryptoProvider.Mode;
				aes.Padding = EnvelopeCryptoProvider.Padding;
				using (var inputStream = new MemoryStream(cipherText))
				{
					using (ICryptoTransform decryptor = aes.CreateDecryptor())
					{
						using (var outputStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
						{
							byte[] decrypted = ReadAllBytes(outputStream);
							Encoding.UTF8.GetString(decrypted).Should().Be(expected);
						}
					}
				}
			}
		}
	}
}