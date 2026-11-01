import io,json,queue,tempfile,unittest
from pathlib import Path
from xavi_duo_transport import FileTransport,QueueTransport,CallbackTransport,write_frame,read_frame,transport_from_uri,TransportError
class TransportTests(unittest.TestCase):
 def test_file_transport_and_bounds(self):
  with tempfile.TemporaryDirectory() as td:
   t=FileTransport(td);r=t.put('task.pq2',b'abc');self.assertEqual(t.get('task.pq2'),b'abc');self.assertEqual(r['bytes'],3)
   with self.assertRaises(TransportError):t.put('../escape',b'x')
   with self.assertRaises(TransportError):t.get('task.pq2',max_bytes=2)
 def test_queue_and_callback(self):
  q=QueueTransport();q.put('b',b'2');q.put('a',b'1');self.assertEqual(q.get('a'),b'1');self.assertEqual(q.get('b'),b'2')
  d={};c=CallbackTransport(lambda n,b:d.__setitem__(n,b),lambda n,m:d[n]);c.put('x',b'y');self.assertEqual(c.get('x'),b'y')
 def test_stream_frame_integrity(self):
  b=io.BytesIO();write_frame(b,'result.pq2',b'payload');b.seek(0);n,p=read_frame(b);self.assertEqual((n,p),('result.pq2',b'payload'))
  raw=bytearray(b.getvalue());raw[-1]^=1
  with self.assertRaises(TransportError):read_frame(io.BytesIO(raw))
 def test_uri_policy(self):
  with tempfile.TemporaryDirectory() as td:self.assertIsInstance(transport_from_uri(Path(td).resolve().as_uri()),FileTransport)
  with self.assertRaises(TransportError):transport_from_uri('http://example.invalid/api')
if __name__=='__main__':unittest.main()
