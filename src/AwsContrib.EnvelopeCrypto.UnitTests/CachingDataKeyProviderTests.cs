#region license
//
// Copyright 2015 ICA.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion
using System.Collections.Generic;
using System.Linq;

using FluentAssertions;

using Moq;

using NUnit.Framework;

namespace AwsContrib.EnvelopeCrypto.UnitTests
{
	public class CachingDataKeyProviderTests
	{
		[SetUp]
		public void SetUp() {}

		[Test]
		public void DecryptKey()
		{
			var mock = new Mock<IDataKeyProvider>();

			int decryptions = 0;
			mock.Setup(x => x.DecryptKey(It.IsAny<byte[]>()))
				.Returns((byte[] input) => input.Select(x => (byte)(x * 2)).ToArray())
				.Callback(() => decryptions++);

			var provider = new CachingDataKeyProvider(mock.Object, 2); 

			provider.DecryptKey(Bytes(1,2,3)).Should().Equal(Bytes(2,4,6));
			decryptions.Should().Be(1);
			provider.DecryptKey(Bytes(1,2,3)).Should().Equal(Bytes(2,4,6));
			decryptions.Should().Be(1);	// still
			provider.DecryptKey(Bytes(1,2,3)).Should().Equal(Bytes(2,4,6));
			decryptions.Should().Be(1);	// still

			// changed the key... this one won't be cached
			provider.DecryptKey(Bytes(2,3,4)).Should().Equal(Bytes(4,6,8));
			decryptions.Should().Be(2);

			// cache is now full
			provider.DecryptKey(Bytes(3,4,5)).Should().Equal(Bytes(6,8,10));
			decryptions.Should().Be(3);
			provider.DecryptKey(Bytes(2,3,4)).Should().Equal(Bytes(4,6,8));
			decryptions.Should().Be(3); // still

			// first one fell out of the cache, so it will cause another decrypt
			provider.DecryptKey(Bytes(1,2,3)).Should().Equal(Bytes(2,4,6));
			decryptions.Should().Be(4);
		}

		[Test]
		public void DecryptKey_Context()
		{
			var mock = new Mock<IDataKeyProvider>();

			var context = new Dictionary<string, string>();
			context["multiplier"] = "3";

			int decryptions = 0;
			mock.Setup(x => x.DecryptKey(It.IsAny<byte[]>()))
				.Returns((byte[] input) => input.Select(x => (byte)(x * 2)).ToArray())
				.Callback(() => decryptions++);

			mock.Setup(x => x.DecryptKey(It.IsAny<byte[]>(), It.IsAny<IDictionary<string,string>>()))
				.Returns((byte[] input, IDictionary<string, string> ctx) =>
				{
					var multiplier = int.Parse(context["multiplier"]);
					return input.Select(x => (byte) (x * multiplier)).ToArray();
				})
				.Callback(() => decryptions++);

			var provider = new CachingDataKeyProvider(mock.Object, 2); 

			provider.DecryptKey(Bytes(1,2,3)).Should().Equal(Bytes(2,4,6));
			decryptions.Should().Be(1);

			context["multiplier"] = "3";
			provider.DecryptKey(Bytes(1,2,3), context).Should().Equal(Bytes(3,6,9));
			decryptions.Should().Be(2);

			provider.DecryptKey(Bytes(1,2,3)).Should().Equal(Bytes(2,4,6));
			decryptions.Should().Be(2); // still

			context["multiplier"] = "3";
			provider.DecryptKey(Bytes(1,2,3), context).Should().Equal(Bytes(3,6,9));
			decryptions.Should().Be(2); // still

			context["multiplier"] = "3";
			provider.DecryptKey(Bytes(1,2,3), context).Should().Equal(Bytes(3,6,9));
			decryptions.Should().Be(2); // still

			provider.DecryptKey(Bytes(1,2,3)).Should().Equal(Bytes(2,4,6));
			decryptions.Should().Be(2); // still

			context["multiplier"] = "0";
			provider.DecryptKey(Bytes(1,2,3), context).Should().Equal(Bytes(0,0,0));
			decryptions.Should().Be(3);

			provider.DecryptKey(Bytes(1,2,3)).Should().Equal(Bytes(2,4,6));
			decryptions.Should().Be(3); // still

			context["multiplier"] = "3";
			provider.DecryptKey(Bytes(1,2,3), context).Should().Equal(Bytes(3,6,9));
			decryptions.Should().Be(4);

			context["multiplier"] = "4";
			provider.DecryptKey(Bytes(1,2,3), context).Should().Equal(Bytes(4,8,12));
			decryptions.Should().Be(5);
		}

		[Test]
		public void GenerateKey()
		{
			// Sanity check that calls are being delegated
			var dummyProvider = new DummyDataKeyProvider
			{
				GeneratedEncryptedKey = Bytes(1, 2, 3),
				GeneratedKey = Bytes(4, 5, 6)
			};
			var provider = new CachingDataKeyProvider(dummyProvider, 10);

			byte[] plainKey, encKey;
			provider.GenerateKey(128, out plainKey, out encKey);
			plainKey.Should().Equal(Bytes(4, 5, 6));
			encKey.Should().Equal(Bytes(1, 2, 3));
		}

		// Bytes(1,2,3) is syntactic sugar for "new byte[] { 1,2,3 }"
		protected static byte[] Bytes(params byte[] bytes)
		{
			return bytes;
		}
	}
}