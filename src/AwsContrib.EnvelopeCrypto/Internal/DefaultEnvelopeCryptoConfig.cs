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