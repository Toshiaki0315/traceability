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

class TestTransactionSeparation(unittest.TestCase):
    def test_pending_transactions(self):
        """トランザクションを受信するとpending_transactionsに追加されること"""
        from traceability import Node, sign_data, generate_keypair
        node = Node("Node1", "Replica")
        pub, priv = generate_keypair()
        
        test_data = {"test": 123}
        signature = sign_data(test_data, priv)
        
        payload = {
            "data": test_data,
            "signature": signature,
            "public_key": pub
        }
        
        # メッセージを受信
        node.receive_message("NEW_TRANSACTION", payload, "Sender1")
        
        # pending_transactionsに追加されていることを確認
        self.assertEqual(len(node.pending_transactions), 1)
        self.assertEqual(node.pending_transactions[0], payload)

    def test_leader_block_proposal(self):
        """Leaderノードがpending_transactionsからブロック候補を作成できること"""
        from traceability import Node, sign_data, generate_keypair
        leader = Node("LeaderNode", "Leader")
        replica = Node("ReplicaNode", "Replica")
        
        pub, priv = generate_keypair()
        test_data = {"test": 123}
        payload = {"data": test_data, "signature": sign_data(test_data, priv), "public_key": pub}
        
        # トランザクションを追加
        leader.receive_message("NEW_TRANSACTION", payload, "Sender1")
        replica.receive_message("NEW_TRANSACTION", payload, "Sender1")
        
        # レプリカはpropose_blockできない
        with self.assertRaises(PermissionError):
            replica.propose_block()
            
        # リーダーはpropose_blockできる（ブロックが返る）
        proposed_block = leader.propose_block()
        self.assertIsNotNone(proposed_block)
        # 作成されたブロックにはトランザクションが含まれている
        self.assertEqual(proposed_block.data, [payload])
        # pending_transactionsは空になる
        self.assertEqual(len(leader.pending_transactions), 0)

class TestPBFTSimulation(unittest.TestCase):
    def test_pbft_consensus_flow(self):
        """PBFTの合意形成フロー（PRE_PREPARE -> PREPARE -> COMMIT -> 確定）が正しく連鎖すること"""
        from traceability import Node, sign_data, generate_keypair
        
        node1 = Node("Node1(Leader)", "Leader")
        node2 = Node("Node2(Replica)", "Replica")
        node3 = Node("Node3(Replica)", "Replica")
        
        # ピア登録
        nodes = [node1, node2, node3]
        for n1 in nodes:
            for n2 in nodes:
                if n1 != n2:
                    n1.add_peer(n2)
                    
        # トランザクション準備
        pub, priv = generate_keypair()
        test_data = {"test": "PBFT Flow"}
        payload = {"data": test_data, "signature": sign_data(test_data, priv), "public_key": pub}
        
        # トランザクション送信（全員のpendingに追加）
        node1.receive_message("NEW_TRANSACTION", payload, "Sender1")
        node2.receive_message("NEW_TRANSACTION", payload, "Sender1")
        node3.receive_message("NEW_TRANSACTION", payload, "Sender1")
        
        # リーダーが提案（ここから連鎖的に通信が行われる）
        node1.propose_block()
        
        # 全ノードのチェーンに新しいブロックが追加されていることを確認（初期状態1 + 新規1 = 2）
        self.assertEqual(len(node1.chain.chain), 2)
        self.assertEqual(len(node2.chain.chain), 2)
        self.assertEqual(len(node3.chain.chain), 2)
        
        # 全ノードの確定したブロック（ハッシュ）が一致していること
        hash1 = node1.chain.get_latest_block().hash
        hash2 = node2.chain.get_latest_block().hash
        hash3 = node3.chain.get_latest_block().hash
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(hash2, hash3)

if __name__ == '__main__':
    unittest.main()
