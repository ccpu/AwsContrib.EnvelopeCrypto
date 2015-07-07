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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using AwsContrib.EnvelopeCrypto.Internal;

namespace AwsContrib.EnvelopeCrypto
{
	/// <summary>
	///     An <see cref="IDataKeyProvider" /> wrapper that caches the results of key decryptions.
	/// </summary>
	public class CachingDataKeyProvider : IDataKeyProvider
	{
		private readonly IDataKeyProvider _actualDataKeyProvider;
		private readonly LruCache<string, byte[]> _lruCache;

		private static readonly Encoding _binaryEncoding = Encoding.GetEncoding("iso-8859-1");

		/// <summary>
		///     Creates a caching wrapper around the provided <paramref name="actualDataKeyProvider" />.
		/// </summary>
		/// <param name="actualDataKeyProvider">The key provider that can actually encrypt and decrypt</param>
		/// <param name="capacity">The number of keys to cache in RAM</param>
		public CachingDataKeyProvider(IDataKeyProvider actualDataKeyProvider, int capacity)
		{
			_lruCache = new LruCache<string, byte[]>(capacity);
			_actualDataKeyProvider = actualDataKeyProvider;
		}

		public void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey)
		{
			_actualDataKeyProvider.GenerateKey(keyBits, out key, out encryptedKey);
		}

		public void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey, IDictionary<string, string> context)
		{
			_actualDataKeyProvider.GenerateKey(keyBits, out key, out encryptedKey, context);
		}

		public byte[] EncryptKey(byte[] plainText)
		{
			return _actualDataKeyProvider.EncryptKey(plainText);
		}

		public byte[] EncryptKey(byte[] plainText, IDictionary<string, string> context)
		{
			return _actualDataKeyProvider.EncryptKey(plainText, context);
		}

		public byte[] DecryptKey(byte[] cipherText)
		{
			string cacheKey = CreateCacheKey(cipherText, context: null);
			byte[] result;
			if (_lruCache.TryGet(cacheKey, out result))
			{
				return result;
			}
			result = _actualDataKeyProvider.DecryptKey(cipherText);
			_lruCache.Add(cacheKey, result);
			return result;
		}

		public byte[] DecryptKey(byte[] cipherText, IDictionary<string, string> context)
		{
			string cacheKey = CreateCacheKey(cipherText, context);
			byte[] result;
			if (_lruCache.TryGet(cacheKey, out result))
			{
				return result;
			}
			result = _actualDataKeyProvider.DecryptKey(cipherText, context);
			_lruCache.Add(cacheKey, result);
			return result;
		}

		private static string CreateCacheKey(byte[] cipherText, IDictionary<string, string> context)
		{
			var sb = new StringBuilder();
			sb.Append("ct:");
			sb.Append(Convert.ToBase64String(cipherText));
			if (context != null)
			{
				// use an encoded scheme to ensure that carefully crafted contexts cannot
				// cause us to return the wrong value, e.g. by including ";foo=bar" as a value.
				foreach (string key in context.Keys.OrderBy(k => k, StringComparer.InvariantCulture))
				{
					string encKey = Convert.ToBase64String(_binaryEncoding.GetBytes(key));
					string encVal = Convert.ToBase64String(_binaryEncoding.GetBytes(context[key]));
					sb.AppendFormat(";{0}:{1}", encKey, encVal);
				}
			}
			return sb.ToString();
		}
	}
}