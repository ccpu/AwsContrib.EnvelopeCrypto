using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	internal class LruCache<TKey, TValue>
	{
		private class Pair
		{
			public TKey Key;
			public TValue Value;
		}

		private readonly object _sync = new object();
		private readonly int _capacity;
		private readonly LinkedList<Pair> _linkedList;
		private readonly ConcurrentDictionary<TKey, LinkedListNode<Pair>> _lookupTable;

		public LruCache(int capacity)
		{
			_capacity = capacity;
			_linkedList = new LinkedList<Pair>();
			_lookupTable = new ConcurrentDictionary<TKey, LinkedListNode<Pair>>();
		}

		public void Add(TKey key, TValue value)
		{
			lock (_sync)
			{
				// remove old value
				LinkedListNode<Pair> node;
				if (_lookupTable.TryGetValue(key, out node))
				{
					_linkedList.Remove(node);
				}

				// insert new value at the head
				node = _linkedList.AddFirst(new Pair {Key = key, Value = value});
				_lookupTable[key] = node;

				while (_linkedList.Count > _capacity)
				{
					// remove least recently used items from the tail
					LinkedListNode<Pair> lastNode = _linkedList.Last;
					_lookupTable.TryRemove(lastNode.Value.Key, out lastNode);
					_linkedList.RemoveLast();
				}
#if DEBUG
				Debug.Assert(_linkedList.Count == _lookupTable.Count);
#endif
			}
		}

		public bool TryGet(TKey key, out TValue value)
		{
			value = default(TValue);
			LinkedListNode<Pair> node;
			if (!_lookupTable.TryGetValue(key, out node))
			{
				return false;
			}

			value = node.Value.Value;
			if (node.Previous == null)
			{
				// already at the head of the list
				return true;
			}

			// move to the head of the list
			lock (_sync)
			{
				_linkedList.Remove(node);
				_linkedList.AddFirst(node);
			}
			return true;
		}
	}
}