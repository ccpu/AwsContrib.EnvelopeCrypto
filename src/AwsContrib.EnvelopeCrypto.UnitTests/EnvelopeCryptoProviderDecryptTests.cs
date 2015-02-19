// I'm using ToList() to force-evaluate enumerables in exception-checking scenarios.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

using AwsContrib.EnvelopeCrypto;

using FluentAssertions;

using NUnit.Framework;

// ReSharper disable ReturnValueOfPureMethodIsNotUsed

namespace AwsContrib.EnvelopeCrypto.UnitTests
{
	public class EnvelopeCryptoProviderDecryptTests : EnvelopeCryptoProviderTestsBase
	{
		[Test]
		public void Decrypt_Bytes_RawKey_Multi()
		{
			byte[] dataKey;
			var plainTextBlobs = new List<byte[]> {Bytes(0, 1, 2), Bytes(3, 4, 5)};
			List<byte[]> encrypted = Provider.Encrypt(out dataKey, plainTextBlobs).ToList();
			List<byte[]> decrypted = Provider.Decrypt(dataKey, encrypted).ToList();

			decrypted.Count.Should().Be(encrypted.Count);
			decrypted[0].Should().Equal(Bytes(0, 1, 2));
			decrypted[1].Should().Equal(Bytes(3, 4, 5));
		}

		[Test]
		public void Decrypt_Bytes_RawKey_Multi_Context()
		{
			byte[] dataKey;
			var plainTextBlobs = new List<byte[]> {Bytes(0, 1, 2), Bytes(3, 4, 5)};
			List<byte[]> encrypted = Provider.Encrypt(out dataKey, plainTextBlobs, Context1).ToList();
			List<byte[]> decrypted = Provider.Decrypt(dataKey, encrypted, Context1).ToList();

			decrypted.Count.Should().Be(encrypted.Count);
			decrypted[0].Should().Equal(Bytes(0, 1, 2));
			decrypted[1].Should().Equal(Bytes(3, 4, 5));

			// No context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted).ToList())
			        .ShouldThrow<CryptographicException>();

			// Different context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted, Context2).ToList())
			        .ShouldThrow<CryptographicException>();
		}

		[Test]
		public void Decrypt_Bytes_StringKey_Multi()
		{
			string dataKey;
			var plainTextBlobs = new List<byte[]> {Bytes(0, 1, 2), Bytes(3, 4, 5)};
			List<byte[]> encrypted = Provider.Encrypt(out dataKey, plainTextBlobs).ToList();
			List<byte[]> decrypted = Provider.Decrypt(dataKey, encrypted).ToList();

			decrypted.Count.Should().Be(encrypted.Count);
			decrypted[0].Should().Equal(Bytes(0, 1, 2));
			decrypted[1].Should().Equal(Bytes(3, 4, 5));
		}

		[Test]
		public void Decrypt_Bytes_StringKey_Multi_Context()
		{
			string dataKey;
			var plainTextBlobs = new List<byte[]> {Bytes(0, 1, 2), Bytes(3, 4, 5)};
			List<byte[]> encrypted = Provider.Encrypt(out dataKey, plainTextBlobs, Context1).ToList();
			List<byte[]> decrypted = Provider.Decrypt(dataKey, encrypted, Context1).ToList();

			decrypted.Count.Should().Be(encrypted.Count);
			decrypted[0].Should().Equal(Bytes(0, 1, 2));
			decrypted[1].Should().Equal(Bytes(3, 4, 5));

			// No context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted).ToList())
			        .ShouldThrow<CryptographicException>();
			// Different context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted, Context2).ToList())
			        .ShouldThrow<CryptographicException>();
		}

		[Test]
		public void Decrypt_Bytes_RawKey_Single()
		{
			byte[] dataKey;
			byte[] encrypted = Provider.Encrypt(out dataKey, Bytes(0, 1, 2));
			Provider.Decrypt(dataKey, encrypted).Should().Equal(Bytes(0, 1, 2));
		}

		[Test]
		public void Decrypt_Bytes_RawKey_Single_Context()
		{
			byte[] dataKey;
			byte[] encrypted = Provider.Encrypt(out dataKey, Bytes(0, 1, 2), Context1);
			Provider.Decrypt(dataKey, encrypted, Context1).Should().Equal(Bytes(0, 1, 2));

			// No context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted))
			        .ShouldThrow<CryptographicException>();

			// Different context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted, Context2))
			        .ShouldThrow<CryptographicException>();
		}

		[Test]
		public void Decrypt_Bytes_StringKey_Single()
		{
			string dataKey;
			byte[] encrypted = Provider.Encrypt(out dataKey, Bytes(0, 1, 2));
			Provider.Decrypt(dataKey, encrypted).Should().Equal(Bytes(0, 1, 2));
		}

		[Test]
		public void Decrypt_Bytes_StringKey_Single_Context()
		{
			string dataKey;
			byte[] encrypted = Provider.Encrypt(out dataKey, Bytes(0, 1, 2), Context1);
			Provider.Decrypt(dataKey, encrypted, Context1).Should().Equal(Bytes(0, 1, 2));

			// No context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted))
			        .ShouldThrow<CryptographicException>();
			// Different context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted, Context2))
			        .ShouldThrow<CryptographicException>();
		}

		[Test]
		public void Decrypt_Strings_StringKey_Multi()
		{
			string dataKey;
			var plaintexts = new List<string> {"secret", "message"};

			List<string> encrypted = Provider.Encrypt(out dataKey, plaintexts).ToList();
			List<string> decrypted = Provider.Decrypt(dataKey, encrypted).ToList();

			decrypted.Count.Should().Be(encrypted.Count);
			decrypted[0].Should().Be("secret");
			decrypted[1].Should().Be("message");
		}

		[Test]
		public void Decrypt_Strings_StringKey_Multi_Context()
		{
			string dataKey;
			var plaintexts = new List<string> {"secret", "message"};

			List<string> encrypted = Provider.Encrypt(out dataKey, plaintexts, Context1).ToList();
			List<string> decrypted = Provider.Decrypt(dataKey, encrypted, Context1).ToList();

			decrypted.Count.Should().Be(encrypted.Count);
			decrypted[0].Should().Be("secret");
			decrypted[1].Should().Be("message");

			// No context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted).ToList())
			        .ShouldThrow<CryptographicException>();
			// Different context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted, Context2).ToList())
			        .ShouldThrow<CryptographicException>();
		}

		[Test]
		public void Decrypt_Strings_StringKey_Single()
		{
			string dataKey;
			string encrypted = Provider.Encrypt(out dataKey, "secret");
			Provider.Decrypt(dataKey, encrypted).Should().Be("secret");
		}

		[Test]
		public void Decrypt_Strings_StringKey_Single_Context()
		{
			string dataKey;
			string encrypted = Provider.Encrypt(out dataKey, "secret", Context1);
			Provider.Decrypt(dataKey, encrypted, Context1).Should().Be("secret");

			// No context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted))
			        .ShouldThrow<CryptographicException>();
			// Different context should fail
			Provider.Invoking(p => p.Decrypt(dataKey, encrypted, Context2))
			        .ShouldThrow<CryptographicException>();
		}

		[Test]
		public void Decrypt_Stream_RawKey_Context()
		{
			byte[] dataKey;
			byte[] encrypted = Provider.Encrypt(out dataKey, Bytes(0, 1, 2), Context1);

			using (Stream stream = Provider.Decrypt(dataKey, new MemoryStream(encrypted), Context1))
			{
				byte[] result = ReadAllBytes(stream);
				result.Should().Equal(Bytes(0, 1, 2));
			}

			// No context should fail
			Provider.Invoking(p =>
			{
				using (Stream stream = p.Decrypt(dataKey, new MemoryStream(encrypted)))
				{
					ReadAllBytes(stream);
				}
			}).ShouldThrow<CryptographicException>();

			// Different context should fail
			Provider.Invoking(p =>
			{
				using (Stream stream = p.Decrypt(dataKey, new MemoryStream(encrypted), Context2))
				{
					ReadAllBytes(stream);
				}
			}).ShouldThrow<CryptographicException>();
		}

		[Test]
		public void Decrypt_Stream_RawKey()
		{
			byte[] dataKey;
			byte[] encrypted = Provider.Encrypt(out dataKey, Bytes(0, 1, 2));

			using (Stream stream = Provider.Decrypt(dataKey, new MemoryStream(encrypted)))
			{
				byte[] result = ReadAllBytes(stream);
				result.Should().Equal(Bytes(0, 1, 2));
			}
		}

		[Test]
		public void Decrypt_Stream_StringKey()
		{
			string dataKey;
			byte[] encrypted = Provider.Encrypt(out dataKey, Bytes(0, 1, 2));

			using (Stream stream = Provider.Decrypt(dataKey, new MemoryStream(encrypted)))
			{
				byte[] result = ReadAllBytes(stream);
				result.Should().Equal(Bytes(0, 1, 2));
			}
		}

		[Test]
		public void Decrypt_Stream_StringKey_Context()
		{
			string dataKey;
			byte[] encrypted = Provider.Encrypt(out dataKey, Bytes(0, 1, 2), Context1);

			using (Stream stream = Provider.Decrypt(dataKey, new MemoryStream(encrypted), Context1))
			{
				byte[] result = ReadAllBytes(stream);
				result.Should().Equal(Bytes(0, 1, 2));
			}

			// No context should fail
			Provider.Invoking(p =>
			{
				using (Stream stream = p.Decrypt(dataKey, new MemoryStream(encrypted)))
				{
					ReadAllBytes(stream);
				}
			}).ShouldThrow<CryptographicException>();

			// Different context should fail
			Provider.Invoking(p =>
			{
				using (Stream stream = p.Decrypt(dataKey, new MemoryStream(encrypted), Context2))
				{
					ReadAllBytes(stream);
				}
			}).ShouldThrow<CryptographicException>();
		}

		[Test]
		public void Decrypt_Stream_InvalidIV()
		{
			byte[] dataKey = Bytes(1, 2, 3);

			foreach (int streamSize in new[] {0, 1, EnvelopeCryptoProvider.BlockBytes - 1, EnvelopeCryptoProvider.BlockBytes})
			{
				byte[] payload = Enumerable.Repeat(0, streamSize).Select(x => (byte) x).ToArray();
				Provider.Invoking(p => p.Decrypt(dataKey, new MemoryStream(payload)))
				        .ShouldThrow<CryptographicException>();
			}
		}
	}
}