import unittest
import rsa
import json
from traceability import TraceabilityChain, Block, generate_keypair, sign_data, verify_signature

class TestTraceabilitySignature(unittest.TestCase):
    def setUp(self):
        self.chain = TraceabilityChain()
        # Create a keypair for a participant
        self.public_key, self.private_key = generate_keypair()
        self.test_data = {"sensor_temp": 25.5, "device_id": "SENSOR-01"}
    
    def test_signature_verification(self):
        """正しい鍵で署名されたデータが正しく検証されること"""
        signature = sign_data(self.test_data, self.private_key)
        is_valid = verify_signature(self.test_data, signature, self.public_key)
        self.assertTrue(is_valid)

    def test_invalid_signature_tampered_data(self):
        """データが改ざんされた場合、署名検証に失敗すること"""
        signature = sign_data(self.test_data, self.private_key)
        
        # Tamper the data
        tampered_data = self.test_data.copy()
        tampered_data["sensor_temp"] = 99.9
        
        is_valid = verify_signature(tampered_data, signature, self.public_key)
        self.assertFalse(is_valid)
        
    def test_add_signed_data(self):
        """正しい署名が付与されたデータがブロックチェーンに追加できること"""
        signature = sign_data(self.test_data, self.private_key)
        initial_length = len(self.chain.chain)
        
        self.chain.add_process_data("温度記録", self.test_data, self.public_key, signature)
        
        self.assertEqual(len(self.chain.chain), initial_length + 1)
        self.assertEqual(self.chain.get_latest_block().data, self.test_data)
        
    def test_reject_invalid_signature(self):
        """不正な署名が付与されたデータは追加を拒否され、例外が発生すること"""
        # Sign with a different key
        _, other_private_key = generate_keypair()
        invalid_signature = sign_data(self.test_data, other_private_key)
        
        with self.assertRaises(ValueError):
            self.chain.add_process_data("温度記録", self.test_data, self.public_key, invalid_signature)

if __name__ == '__main__':
    unittest.main()
