import os,sys,unittest
from unittest import mock
sys.path.insert(0,'vendor')
import duo_core as duo
import xavi_duo_crypto as c

class ResourceLimitTests(unittest.TestCase):
    def test_rev009_supported_domain_cell_length_is_at_most_20(self):
        maxlen=0
        for M in range(2,c.MAX_MODULUS+1):
            for count in (c.OFFSET_MIN+1,c.OFFSET_MIN+256,c.OFFSET_MAX+1,c.OFFSET_MAX+256):
                maxlen=max(maxlen,len(duo.token_at(count,M)['token']))
        self.assertLessEqual(maxlen,20)
        self.assertEqual(c.MAX_CELL_CHARS,20)

    def test_nonce_cells_rejected_before_large_integer_parse(self):
        bad='AAAA.'+'.'.join(['1']*11)
        with mock.patch.object(c.duo,'parse_duo_count',side_effect=AssertionError('parser should not be reached')):
            with self.assertRaisesRegex(c.XDEError,'nonce cell exceeds'):
                c._nonce_from_duo(bad)

    def test_absolute_wire_ceiling_matches_transport_ceiling(self):
        from xavi_duo_transport import MAX_FRAME_BYTES as transport_max
        self.assertEqual(c.MAX_FRAME_BYTES,64*1024*1024)
        self.assertLessEqual(c.MAX_FRAME_BYTES,transport_max)

if __name__=='__main__': unittest.main()
