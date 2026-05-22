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

class TestByzantineFaultTolerance(unittest.TestCase):
    """ステップ5: ビザンチン障害耐性テスト"""

    def _create_network(self, node_count=3):
        """テスト用のフルメッシュP2Pネットワークを構築するヘルパー"""
        from traceability import Node, sign_data, generate_keypair
        roles = ["Leader"] + ["Replica"] * (node_count - 1)
        nodes = [Node(f"Node{i+1}", roles[i]) for i in range(node_count)]
        for n1 in nodes:
            for n2 in nodes:
                if n1 != n2:
                    n1.add_peer(n2)
        return nodes

    def _inject_transaction(self, nodes):
        """全ノードにテスト用トランザクションを注入するヘルパー"""
        from traceability import sign_data, generate_keypair
        pub, priv = generate_keypair()
        test_data = {"test": "BFT"}
        payload = {"data": test_data, "signature": sign_data(test_data, priv), "public_key": pub}
        for node in nodes:
            node.receive_message("NEW_TRANSACTION", payload, "ExternalSender")
        return payload

    def test_malicious_node_rejected(self):
        """不正なブロック（ハッシュ改ざん）を送信するノードがいても、他ノードが拒否すること"""
        from traceability import Node, Block
        nodes = self._create_network(3)
        self._inject_transaction(nodes)

        leader = nodes[0]
        # リーダーが正規のブロック候補を作成（ブロードキャストはしない）
        transactions = leader.pending_transactions.copy()
        leader.pending_transactions.clear()
        latest = leader.chain.get_latest_block()
        tampered_block = Block(
            index=latest.index + 1,
            timestamp=0,
            process_name="Tampered Block",
            data=[{"fake": "data"}],
            previous_hash=latest.hash
        )
        # ハッシュを改ざん（ブロック内容と不一致にする）
        tampered_block.hash = "0000000000000000_FAKE_HASH"

        # 不正ブロックを直接ブロードキャスト
        for peer in leader.peers:
            peer.receive_message("PRE_PREPARE", tampered_block, leader.node_id)

        # 不正ブロックは台帳に追加されていないこと
        for node in nodes:
            self.assertEqual(len(node.chain.chain), 1, 
                f"{node.node_id} に不正ブロックが追加されてしまいました")

    def test_consensus_with_one_node_down(self):
        """3ノード中1ノードがダウンしても、残り2ノードで合意が成立すること"""
        nodes = self._create_network(3)
        self._inject_transaction(nodes)

        # Node3をダウンさせる（メッセージを受け付けなくする）
        down_node = nodes[2]
        down_node.receive_message = lambda msg_type, payload, sender_id: None

        # リーダーがブロック提案
        nodes[0].propose_block()

        # 稼働中の2ノードはブロックが確定していること
        self.assertEqual(len(nodes[0].chain.chain), 2)
        self.assertEqual(len(nodes[1].chain.chain), 2)

        # ダウンしたノードは台帳が更新されていないこと
        self.assertEqual(len(down_node.chain.chain), 1)

        # 稼働中の2ノードのハッシュが一致すること
        self.assertEqual(
            nodes[0].chain.get_latest_block().hash,
            nodes[1].chain.get_latest_block().hash
        )

    def test_consensus_fails_without_quorum(self):
        """3ノード中2ノードがダウンした場合、定足数不足で合意が成立しないこと"""
        nodes = self._create_network(3)
        self._inject_transaction(nodes)

        # Node2とNode3をダウンさせる
        nodes[1].receive_message = lambda msg_type, payload, sender_id: None
        nodes[2].receive_message = lambda msg_type, payload, sender_id: None

        # リーダーがブロック提案
        nodes[0].propose_block()

        # いずれのノードもブロックが確定していないこと
        for node in nodes:
            self.assertEqual(len(node.chain.chain), 1,
                f"{node.node_id} で合意なしにブロックが確定してしまいました")

class TestChainPersistence(unittest.TestCase):
    """ステップ6: 台帳の永続化テスト"""

    def setUp(self):
        """テスト用の一時ディレクトリを作成"""
        import tempfile, os
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """テスト用の一時ディレクトリを削除"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_load_chain(self):
        """チェーンをJSONに保存し、復元して内容が一致すること"""
        import os
        chain = TraceabilityChain()
        pub, priv = generate_keypair()

        # ブロックを2つ追加
        data1 = {"lot": "A001", "temp": 65.0}
        sig1 = sign_data(data1, priv)
        chain.add_process_data("加熱処理", data1, pub, sig1)

        data2 = {"destination": "Yokohama", "shipping_id": "SHIP-001"}
        sig2 = sign_data(data2, priv)
        chain.add_process_data("出荷", data2, pub, sig2)

        # 保存
        filepath = os.path.join(self.test_dir, "test_chain.json")
        chain.save_chain(filepath)
        self.assertTrue(os.path.exists(filepath))

        # 復元
        loaded_chain = TraceabilityChain.load_chain(filepath)

        # ブロック数が一致
        self.assertEqual(len(loaded_chain.chain), len(chain.chain))

        # 各ブロックのハッシュが一致
        for orig, loaded in zip(chain.chain, loaded_chain.chain):
            self.assertEqual(orig.hash, loaded.hash)
            self.assertEqual(orig.previous_hash, loaded.previous_hash)
            self.assertEqual(orig.process_name, loaded.process_name)

    def test_load_detects_tampered_file(self):
        """保存済みファイルが改ざんされた場合、復元時にエラーが発生すること"""
        import os
        chain = TraceabilityChain()
        pub, priv = generate_keypair()
        data = {"lot": "B002"}
        sig = sign_data(data, priv)
        chain.add_process_data("検査", data, pub, sig)

        filepath = os.path.join(self.test_dir, "tampered_chain.json")
        chain.save_chain(filepath)

        # ファイルを読み込んで改ざん
        with open(filepath, "r") as f:
            content = json.load(f)
        content[1]["data"]["lot"] = "TAMPERED"
        with open(filepath, "w") as f:
            json.dump(content, f)

        # 復元時にエラーが発生すること
        with self.assertRaises(ValueError):
            TraceabilityChain.load_chain(filepath)

    def test_node_save_and_restore(self):
        """Nodeがチェーンを保存し、新しいノードで復元して台帳を引き継げること"""
        from traceability import Node
        import os

        node = Node("TestNode", "Replica")
        pub, priv = generate_keypair()
        data = {"test": "persistence"}
        sig = sign_data(data, priv)
        node.chain.add_process_data("テスト工程", data, pub, sig)

        # 保存
        node.save_state(self.test_dir)
        expected_path = os.path.join(self.test_dir, "TestNode_chain.json")
        self.assertTrue(os.path.exists(expected_path))

        # 新しいノードで復元
        new_node = Node("TestNode", "Replica")
        self.assertEqual(len(new_node.chain.chain), 1)  # まだジェネシスのみ

        new_node.load_state(self.test_dir)
        self.assertEqual(len(new_node.chain.chain), 2)  # 復元後は2ブロック

        # ハッシュが一致
        self.assertEqual(
            node.chain.get_latest_block().hash,
            new_node.chain.get_latest_block().hash
        )

class TestBusinessRules(unittest.TestCase):
    """ステップ7: スマートコントラクト的なビジネスルール検証テスト"""

    def test_add_and_execute_business_rule(self):
        """ビジネスルールを追加し、ルールを満たすトランザクションが追加されること"""
        from traceability import Node, sign_data, generate_keypair
        node = Node("Node1", "Replica")
        pub, priv = generate_keypair()

        # ルール設定: 加熱工程の場合、温度が65度以上でなければならない
        def heating_temp_rule(payload):
            data = payload.get("data", {})
            if data.get("process") == "heating":
                temp = data.get("temperature", 0)
                if temp < 65.0:
                    raise ValueError("加熱温度が低すぎます")
            return True

        node.add_business_rule(heating_temp_rule)

        # ルールを満たすトランザクション
        valid_data = {"process": "heating", "temperature": 68.5}
        valid_payload = {
            "data": valid_data,
            "signature": sign_data(valid_data, priv),
            "public_key": pub
        }

        node.receive_message("NEW_TRANSACTION", valid_payload, "Sender1")

        # トランザクションが正常に受け入れられていること
        self.assertEqual(len(node.pending_transactions), 1)
        self.assertEqual(node.pending_transactions[0], valid_payload)

    def test_violate_business_rule_rejected(self):
        """ビジネスルールに違反するトランザクションが拒否されること"""
        from traceability import Node, sign_data, generate_keypair
        node = Node("Node1", "Replica")
        pub, priv = generate_keypair()

        # ルール設定
        def heating_temp_rule(payload):
            data = payload.get("data", {})
            if data.get("process") == "heating":
                temp = data.get("temperature", 0)
                if temp < 65.0:
                    raise ValueError("加熱温度が低すぎます")
            return True

        node.add_business_rule(heating_temp_rule)

        # ルールに違反するトランザクション (60.0度)
        invalid_data = {"process": "heating", "temperature": 60.0}
        invalid_payload = {
            "data": invalid_data,
            "signature": sign_data(invalid_data, priv),
            "public_key": pub
        }

        node.receive_message("NEW_TRANSACTION", invalid_payload, "Sender1")

        # トランザクションが追加されずに破棄されていること
        self.assertEqual(len(node.pending_transactions), 0)

class TestOffChainOnChainIntegration(unittest.TestCase):
    """ステップ8: DuckDBを用いたオフチェーン・オンチェーン連携のテスト"""

    def setUp(self):
        from traceability import Node, OffChainStore
        # テストごとにインメモリのDuckDBストアを作成
        self.offchain_store = OffChainStore(db_path=":memory:")
        self.node_leader = Node("Node1(Leader)", "Leader")
        self.node_replica = Node("Node2(Replica)", "Replica")
        
        # 相互に接続
        self.node_leader.add_peer(self.node_replica)
        self.node_replica.add_peer(self.node_leader)

    def tearDown(self):
        self.offchain_store.close()

    def test_offchain_store_and_anchoring(self):
        """オフチェーン(DuckDB)への保存と、そのハッシュのオンチェーン合意形成テスト"""
        from traceability import sign_data

        # 1. オフチェーンへの詳細データ保存
        record_id = "rec-001"
        lot_number = "LOT-100"
        details = {"temperature": 72.3, "duration_sec": 1800, "operator": "Alice"}
        
        record_hash = self.offchain_store.save_record(
            record_id=record_id,
            lot_number=lot_number,
            process_name="加熱処理",
            details=details
        )
        
        self.assertIsNotNone(record_hash)
        self.assertEqual(len(record_hash), 64) # SHA-256 hash length

        # 2. オンチェーンへのハッシュアンカリング(トランザクション送信)
        anchor_data = {
            "record_id": record_id,
            "hash": record_hash,
            "lot_number": lot_number
        }
        
        # リーダーの署名をつけてブロードキャスト
        payload = {
            "data": anchor_data,
            "signature": sign_data(anchor_data, self.node_leader.private_key),
            "public_key": self.node_leader.public_key,
            "type": "OFFCHAIN_ANCHOR"
        }
        
        self.node_leader.receive_message("NEW_TRANSACTION", payload, "Sender")
        self.node_replica.receive_message("NEW_TRANSACTION", payload, "Sender")

        
        # 3. ブロック提案と合意形成の実行
        self.node_leader.propose_block()
        
        # 両ノードの最新ブロックにアンカーが含まれていること
        latest_block_leader = self.node_leader.chain.get_latest_block()
        latest_block_replica = self.node_replica.chain.get_latest_block()
        
        self.assertEqual(latest_block_leader.hash, latest_block_replica.hash)
        self.assertEqual(latest_block_leader.process_name, "PBFT Proposed Block")
        tx = latest_block_leader.data[0]
        self.assertEqual(tx["type"], "OFFCHAIN_ANCHOR")
        self.assertEqual(tx["data"]["record_id"], record_id)
        self.assertEqual(tx["data"]["hash"], record_hash)


    def test_audit_verification_success(self):
        """データが改ざんされていない正常なケースで監査が成功すること"""
        from traceability import sign_data

        record_id = "rec-002"
        lot_number = "LOT-200"
        details = {"pH": 6.8, "humidity": 45}
        
        record_hash = self.offchain_store.save_record(record_id, lot_number, "発酵工程", details)
        
        # アンカリング
        anchor_data = {"record_id": record_id, "hash": record_hash, "lot_number": lot_number}
        payload = {
            "data": anchor_data,
            "signature": sign_data(anchor_data, self.node_leader.private_key),
            "public_key": self.node_leader.public_key,
            "type": "OFFCHAIN_ANCHOR"
        }
        self.node_leader.receive_message("NEW_TRANSACTION", payload, "Sender")
        self.node_replica.receive_message("NEW_TRANSACTION", payload, "Sender")

        self.node_leader.propose_block()

        # 監査の実行（リーダーがオフチェーンストアと連携して検証）
        is_valid = self.node_leader.audit_offchain_data(record_id, self.offchain_store)
        self.assertTrue(is_valid)

    def test_audit_verification_detects_tampering(self):
        """オフチェーンデータが直接改ざんされた場合に、監査で不一致を検知すること"""
        from traceability import sign_data

        record_id = "rec-003"
        lot_number = "LOT-300"
        details = {"weight_g": 950}
        
        record_hash = self.offchain_store.save_record(record_id, lot_number, "包装工程", details)
        
        # アンカリング
        anchor_data = {"record_id": record_id, "hash": record_hash, "lot_number": lot_number}
        payload = {
            "data": anchor_data,
            "signature": sign_data(anchor_data, self.node_leader.private_key),
            "public_key": self.node_leader.public_key,
            "type": "OFFCHAIN_ANCHOR"
        }
        self.node_leader.receive_message("NEW_TRANSACTION", payload, "Sender")
        self.node_replica.receive_message("NEW_TRANSACTION", payload, "Sender")

        self.node_leader.propose_block()

        # 監査の成功を確認
        self.assertTrue(self.node_leader.audit_offchain_data(record_id, self.offchain_store))

        # オフチェーンのDuckDBのデータを直接書き換えて改ざんシミュレーション
        self.offchain_store.conn.execute(
            "UPDATE manufacturing_details SET details = ? WHERE record_id = ?",
            ('{"weight_g": 850}', record_id) # 950g から 850g に数値を改ざん
        )

        # 再度監査を実行すると、ハッシュ不一致のためFalseが返ることを検証
        is_valid_after_tamper = self.node_leader.audit_offchain_data(record_id, self.offchain_store)
        self.assertFalse(is_valid_after_tamper)

if __name__ == '__main__':
    unittest.main()
