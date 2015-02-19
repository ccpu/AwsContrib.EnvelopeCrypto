using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

using FluentAssertions;

using Moq;

using NUnit.Framework;

namespace AwsContrib.EnvelopeCrypto.UnitTests
{
	public class KmsDataKeyProviderTests
	{
		// Bytes(1,2,3) is syntactic sugar for "new byte[] { 1,2,3 }"
		public static byte[] Bytes(params byte[] bytes)
		{
			return bytes;
		}

		[TestCase(256, "AES_256", false)]
		[TestCase(128, "AES_128", false)]
		[TestCase(512, null, true)]
		public void GenerateKey_Context_Ok(int bits, string keySpec, bool throws)
		{
			var kmsClientMock = new Mock<IAmazonKeyManagementService>();
			var provider = new KmsDataKeyProvider(kmsClientMock.Object, "myKey");

			GenerateDataKeyRequest requestSent = null;
			kmsClientMock.Setup(x => x.GenerateDataKey(It.IsAny<GenerateDataKeyRequest>()))
			             .Returns((GenerateDataKeyRequest req) =>
			             {
				             requestSent = req;
				             return new GenerateDataKeyResponse
				             {
					             CiphertextBlob = new MemoryStream(Bytes(1, 2, 3)),
					             Plaintext = new MemoryStream(Bytes(4, 5, 6)),
				             };
			             });

			byte[] key = null, encryptedKey = null;
			var context = new Dictionary<string, string> {{"bits", bits.ToString(CultureInfo.InvariantCulture)}};
			Action invocation = provider.Invoking(p => p.GenerateKey(bits, out key, out encryptedKey, context));
			if (throws)
			{
				invocation.ShouldThrow<ArgumentException>();
			}
			else
			{
				invocation.ShouldNotThrow();
				key.Should().Equal(Bytes(4, 5, 6));
				encryptedKey.Should().Equal(Bytes(1, 2, 3));
				requestSent.KeyId.Should().Be("myKey");
				requestSent.KeySpec.ToString().Should().Be(keySpec);
				requestSent.EncryptionContext["bits"].Should().Be(bits.ToString(CultureInfo.InvariantCulture));
			}
		}

		[TestCase(256, "AES_256", false)]
		[TestCase(128, "AES_128", false)]
		[TestCase(512, null, true)]
		public void GenerateKey_Ok(int bits, string keySpec, bool throws)
		{
			var kmsClientMock = new Mock<IAmazonKeyManagementService>();
			var provider = new KmsDataKeyProvider(kmsClientMock.Object, "myKey");

			GenerateDataKeyRequest requestSent = null;
			kmsClientMock.Setup(x => x.GenerateDataKey(It.IsAny<GenerateDataKeyRequest>()))
			             .Returns((GenerateDataKeyRequest req) =>
			             {
				             requestSent = req;
				             return new GenerateDataKeyResponse
				             {
					             CiphertextBlob = new MemoryStream(Bytes(1, 2, 3)),
					             Plaintext = new MemoryStream(Bytes(4, 5, 6)),
				             };
			             });

			byte[] key = null, encryptedKey = null;
			Action invocation = provider.Invoking(p => p.GenerateKey(bits, out key, out encryptedKey));
			if (throws)
			{
				invocation.ShouldThrow<ArgumentException>();
			}
			else
			{
				invocation.ShouldNotThrow();
				key.Should().Equal(Bytes(4, 5, 6));
				encryptedKey.Should().Equal(Bytes(1, 2, 3));
				requestSent.KeyId.Should().Be("myKey");
				requestSent.KeySpec.ToString().Should().Be(keySpec);
				requestSent.EncryptionContext.Should().BeEmpty();
			}
		}

		[Test]
		public void DecryptKey_Context_Ok()
		{
			var kmsClientMock = new Mock<IAmazonKeyManagementService>();
			var provider = new KmsDataKeyProvider(kmsClientMock.Object, "myKey");

			DecryptRequest sentRequest = null;
			kmsClientMock.Setup(x => x.Decrypt(It.IsAny<DecryptRequest>()))
			             .Returns((DecryptRequest req) =>
			             {
				             sentRequest = req;
				             return new DecryptResponse
				             {
					             Plaintext = DoubleValues(req.CiphertextBlob)
				             };
			             });

			var context = new Dictionary<string, string> {{"purpose", "doubling"}};
			provider.DecryptKey(Bytes(1, 2, 3), context).Should().Equal(Bytes(2, 4, 6));
			sentRequest.CiphertextBlob.ToArray().Should().Equal(Bytes(1, 2, 3));
			sentRequest.EncryptionContext["purpose"].Should().Be("doubling");

			provider.DecryptKey(Bytes(2, 3, 4), context).Should().Equal(Bytes(4, 6, 8));
		}

		[Test]
		public void DecryptKey_Ok()
		{
			var kmsClientMock = new Mock<IAmazonKeyManagementService>();
			var provider = new KmsDataKeyProvider(kmsClientMock.Object, "myKey");

			DecryptRequest sentRequest = null;
			kmsClientMock.Setup(x => x.Decrypt(It.IsAny<DecryptRequest>()))
			             .Returns((DecryptRequest req) =>
			             {
				             sentRequest = req;
				             return new DecryptResponse
				             {
					             Plaintext = DoubleValues(req.CiphertextBlob)
				             };
			             });

			var context = new Dictionary<string, string> {{"purpose", "doubling"}};
			provider.DecryptKey(Bytes(1, 2, 3)).Should().Equal(Bytes(2, 4, 6));
			sentRequest.CiphertextBlob.ToArray().Should().Equal(Bytes(1, 2, 3));
			sentRequest.EncryptionContext.Should().BeEmpty();

			provider.DecryptKey(Bytes(2, 3, 4)).Should().Equal(Bytes(4, 6, 8));
		}

		[Test]
		public void EncryptKey_Context_Ok()
		{
			var kmsClientMock = new Mock<IAmazonKeyManagementService>();
			var provider = new KmsDataKeyProvider(kmsClientMock.Object, "myKey");

			EncryptRequest sentRequest = null;
			kmsClientMock.Setup(x => x.Encrypt(It.IsAny<EncryptRequest>()))
			             .Returns((EncryptRequest req) =>
			             {
				             sentRequest = req;
				             return new EncryptResponse
				             {
					             CiphertextBlob = DoubleValues(req.Plaintext),
				             };
			             });

			var context = new Dictionary<string, string> {{"purpose", "doubling"}};
			provider.EncryptKey(Bytes(1, 2, 3),context).Should().Equal(Bytes(2, 4, 6));
			sentRequest.Plaintext.ToArray().Should().Equal(Bytes(1, 2, 3));
			sentRequest.EncryptionContext["purpose"].Should().Be("doubling");
			sentRequest.KeyId.Should().Be("myKey");

			provider.EncryptKey(Bytes(2, 3, 4),context).Should().Equal(Bytes(4, 6, 8));
		}

		[Test]
		public void EncryptKey_Ok()
		{
			var kmsClientMock = new Mock<IAmazonKeyManagementService>();
			var provider = new KmsDataKeyProvider(kmsClientMock.Object, "myKey");

			EncryptRequest sentRequest = null;
			kmsClientMock.Setup(x => x.Encrypt(It.IsAny<EncryptRequest>()))
			             .Returns((EncryptRequest req) =>
			             {
				             sentRequest = req;
				             return new EncryptResponse
				             {
					             CiphertextBlob = DoubleValues(req.Plaintext),
				             };
			             });

			provider.EncryptKey(Bytes(1, 2, 3)).Should().Equal(Bytes(2, 4, 6));
			sentRequest.Plaintext.ToArray().Should().Equal(Bytes(1, 2, 3));
			sentRequest.KeyId.Should().Be("myKey");
			sentRequest.EncryptionContext.Should().BeEmpty();

			provider.EncryptKey(Bytes(2, 3, 4)).Should().Equal(Bytes(4, 6, 8));
		}

		private static MemoryStream DoubleValues(MemoryStream input)
		{
			byte[] numbers = input.ToArray();
			IEnumerable<byte> doubled = numbers.Select(x => (byte) (x * 2));
			return new MemoryStream(doubled.ToArray());
		}
	}
}