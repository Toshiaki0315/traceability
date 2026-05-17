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

class TestNetworkSimulation(unittest.TestCase):
    def test_node_initialization(self):
        """Nodeクラスが正しく初期化され、必要な属性を持つこと"""
        from traceability import Node
        node = Node("Supplier_A", "Replica")
        self.assertEqual(node.node_id, "Supplier_A")
        self.assertEqual(node.role, "Replica")
        self.assertIsNotNone(node.chain)
        self.assertIsNotNone(node.public_key)
        self.assertIsNotNone(node.private_key)
        self.assertEqual(len(node.peers), 0)

    def test_peer_registration(self):
        """ノード同士がお互いをピアとして登録し合えること"""
        from traceability import Node
        node1 = Node("Node1", "Leader")
        node2 = Node("Node2", "Replica")
        
        node1.add_peer(node2)
        node2.add_peer(node1)
        
        self.assertIn(node2, node1.peers)
        self.assertIn(node1, node2.peers)
        
    def test_broadcast_message(self):
        """あるノードがメッセージをブロードキャストした際、全ピアが受信できること"""
        from traceability import Node
        node1 = Node("Node1", "Leader")
        node2 = Node("Node2", "Replica")
        node3 = Node("Node3", "Replica")
        
        node1.add_peer(node2)
        node1.add_peer(node3)
        
        # モックの代わりに、受信したメッセージを記録するリストを追加しておく
        node2.received_messages = []
        node3.received_messages = []
        
        # 既存のreceive_messageメソッドを一時的にオーバーライドして記録するようにする
        def receive_mock2(msg_type, payload, sender_id):
            node2.received_messages.append((msg_type, payload, sender_id))
            
        def receive_mock3(msg_type, payload, sender_id):
            node3.received_messages.append((msg_type, payload, sender_id))
            
        node2.receive_message = receive_mock2
        node3.receive_message = receive_mock3
        
        node1.broadcast("TEST_MSG", {"info": "hello"})
        
        self.assertEqual(len(node2.received_messages), 1)
        self.assertEqual(node2.received_messages[0], ("TEST_MSG", {"info": "hello"}, "Node1"))
        self.assertEqual(len(node3.received_messages), 1)

if __name__ == '__main__':
    unittest.main()
