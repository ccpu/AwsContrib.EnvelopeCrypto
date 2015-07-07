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
using System.IO;

namespace AwsContrib.EnvelopeCrypto.UnitTests
{
	internal class FakeStream : Stream
	{
		private readonly IEnumerator<byte> _byteEnumerator;
		private long _remaining;

		public FakeStream(long size, IEnumerable<byte> byteProvider)
		{
			_byteEnumerator = byteProvider.GetEnumerator();
			_remaining = size;
		}

		public FakeStream(long size) : this(size, InfiniteZeros()) {}

		public override bool CanRead
		{
			get { return true; }
		}

		public override bool CanSeek
		{
			get { return false; }
		}

		public override bool CanWrite
		{
			get { return false; }
		}

		public override long Length
		{
			get { throw new NotImplementedException(); }
		}

		public override long Position
		{
			get { throw new NotImplementedException(); }
			set { throw new NotImplementedException(); }
		}

		protected override void Dispose(bool disposing)
		{
			_byteEnumerator.Dispose();
			base.Dispose(disposing);
		}

		private static IEnumerable<byte> InfiniteZeros()
		{
			while (true)
			{
				yield return 0;
			}
		}

		public override void Flush() {}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotImplementedException();
		}

		public override void SetLength(long value)
		{
			throw new NotImplementedException();
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			var bytesToReturn = (int) Math.Min(count, _remaining);
			for (int i = 0; i < bytesToReturn; i++)
			{
				if (_byteEnumerator.MoveNext())
				{
					_remaining--;
					buffer[offset + i] = _byteEnumerator.Current;
				}
				else
				{
					return i;
				}
			}
			return bytesToReturn;
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotImplementedException();
		}
	}
}