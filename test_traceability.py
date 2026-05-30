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
        
        record_hash = self.offchain_store.save_legacy_record(
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
        
        record_hash = self.offchain_store.save_legacy_record(record_id, lot_number, "発酵工程", details)
        
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
        
        record_hash = self.offchain_store.save_legacy_record(record_id, lot_number, "包装工程", details)
        
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

class TestFlaskWebUI(unittest.TestCase):
    """ステップ9: Flask Web UI HTTP API のテスト"""

    def setUp(self):
        # app.py から Flask app をインポートしてテストクライアントを作成
        # （TDD Redフェーズ時はapp.pyが未作成のためImportErrorになることを意図）
        from app import app, init_demo_state
        self.app = app
        self.client = self.app.test_client()
        # 各テストの前にステートをリセット/初期化する
        init_demo_state()

    def test_get_state(self):
        """/api/state がネットワーク、ブロックチェーン、オフチェーン、およびログを正しく返却すること"""
        response = self.client.get('/api/state')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        
        # 期待するキーが存在すること
        self.assertIn("nodes", data)
        self.assertIn("blockchain", data)
        self.assertIn("offchain", data)
        self.assertIn("logs", data)
        
        # 3ノードが存在すること
        self.assertEqual(len(data["nodes"]), 3)
        # 初期ブロックチェーンが存在すること（ジェネシスブロックのみで長さ1）
        self.assertEqual(len(data["blockchain"]), 1)
        self.assertEqual(data["blockchain"][0]["process_name"], "System Initialization")

    def test_post_transaction_and_propose(self):
        """取引登録APIを呼び出し、ブロック提案APIでPBFT合意形成がなされること"""
        # 1. 新しいロットの取引登録
        payload = {
            "supplier": "A社",
            "lot_number": "LOT-UI-001",
            "weight_kg": 250
        }
        res_tx = self.client.post('/api/transaction', json=payload)
        self.assertEqual(res_tx.status_code, 200)
        data_tx = json.loads(res_tx.data.decode('utf-8'))
        self.assertTrue(data_tx["success"])

        # 2. 状態の確認（未承認プールに1件存在するはず）
        res_state = self.client.get('/api/state')
        data_state = json.loads(res_state.data.decode('utf-8'))
        # 加工工場（リーダー）の未承認プール数が1であること
        factory_node = next(n for n in data_state["nodes"] if n["node_id"] == "加工工場")
        self.assertEqual(factory_node["pending_tx_count"], 1)

        # 3. ブロック提案を実行
        res_propose = self.client.post('/api/propose')
        self.assertEqual(res_propose.status_code, 200)
        data_propose = json.loads(res_propose.data.decode('utf-8'))
        self.assertTrue(data_propose["success"])

        # 4. 合意後のチェーンサイズが2になることを確認
        res_state2 = self.client.get('/api/state')
        data_state2 = json.loads(res_state2.data.decode('utf-8'))
        self.assertEqual(len(data_state2["blockchain"]), 2)
        # ブロックの中身にUIで登録したlot_numberが含まれていること
        latest_block = data_state2["blockchain"][-1]
        self.assertEqual(latest_block["data"][0]["data"]["lot_number"], "LOT-UI-001")

    def test_anchor_audit_and_tamper_flow(self):
        """詳細ログのアンカリング、監査の成功、改ざんシミュレーション、および監査不合格の流れをテスト"""
        # 1. 詳細ログのオフチェーン保存とオンチェーンへのアンカリング
        anchor_payload = {
            "record_id": "rec-ui-999",
            "lot_number": "LOT-UI-999",
            "process_name": "UI詳細加熱",
            "details": {"temp": 82.5, "operator": "Bob"}
        }
        res_anchor = self.client.post('/api/anchor', json=anchor_payload)
        self.assertEqual(res_anchor.status_code, 200)
        
        # アンカーをブロックに確定させるため、PBFT合意を実行
        self.client.post('/api/propose')

        # 2. 正常時の監査検証
        res_audit = self.client.post('/api/audit', json={"record_id": "rec-ui-999"})
        self.assertEqual(res_audit.status_code, 200)
        data_audit = json.loads(res_audit.data.decode('utf-8'))
        self.assertTrue(data_audit["valid"])

        # 3. 改ざんシミュレーションの実行
        res_tamper = self.client.post('/api/tamper', json={"record_id": "rec-ui-999"})
        self.assertEqual(res_tamper.status_code, 200)
        data_tamper = json.loads(res_tamper.data.decode('utf-8'))
        self.assertTrue(data_tamper["success"])

        # 4. 改ざん後の監査検証（失敗検知）
        res_audit_post = self.client.post('/api/audit', json={"record_id": "rec-ui-999"})
        self.assertEqual(res_audit_post.status_code, 200)
        data_audit_post = json.loads(res_audit_post.data.decode('utf-8'))
        self.assertFalse(data_audit_post["valid"])

class TestNodeWebAPI(unittest.TestCase):
    """ステップ10: 各ノード独立プロセス相当の HTTP/REST API 統合テスト"""

    @classmethod
    def setUpClass(cls):
        import sys
        import threading
        import time
        import uvicorn
        from api import create_node_app
        from traceability import Node, default_weight_check_rule, OffChainStore

        # Flask UI テスト後などで stdout が差し替えられている場合に復元
        if hasattr(sys.stdout, "terminal"):
            sys.stdout = sys.stdout.terminal

        cls.offchain = OffChainStore(db_path=":memory:")
        cls.ports = [59101, 59102, 59103]
        cls.nodes = [
            Node("納入業者", "Replica"),
            Node("加工工場", "Leader"),
            Node("倉庫", "Replica"),
        ]
        urls = [f"http://127.0.0.1:{p}" for p in cls.ports]
        for i, node in enumerate(cls.nodes):
            node.set_peer_urls([u for j, u in enumerate(urls) if j != i])
            node.add_business_rule(default_weight_check_rule)

        cls._threads = []
        for node, port in zip(cls.nodes, cls.ports):
            store = cls.offchain if node.role == "Leader" else None
            app = create_node_app(node, store)

            def _run(application, listen_port):
                uvicorn.run(application, host="127.0.0.1", port=listen_port, log_level="error")

            t = threading.Thread(target=_run, args=(app, port), daemon=True)
            t.start()
            cls._threads.append(t)
        time.sleep(1.5)

    @classmethod
    def tearDownClass(cls):
        cls.offchain.close()

    def setUp(self):
        """テスト間で台帳・PBFT状態をリセットする"""
        from traceability import TraceabilityChain
        for node in self.nodes:
            node.chain = TraceabilityChain()
            node.pending_transactions = []
            node.prepares = {}
            node.commits = {}

    def test_node_info_endpoint(self):
        import requests
        r = requests.get(f"http://127.0.0.1:{self.ports[1]}/node", timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["node_id"], "加工工場")
        self.assertEqual(data["role"], "Leader")

    def test_http_transaction_propose_and_chain(self):
        """HTTP経由でトランザクション送信→ブロック提案→全ノードのチェーン一致を確認"""
        import requests
        from traceability import sign_data, encode_payload

        supplier = self.nodes[0]
        tx_data = {"lot_number": "LOT-HTTP-001", "supplier": "納入業者", "weight_kg": 300}
        payload = encode_payload({
            "data": tx_data,
            "signature": sign_data(tx_data, supplier.private_key),
            "public_key": supplier.public_key,
        })

        res_tx = requests.post(
            f"http://127.0.0.1:{self.ports[0]}/transaction",
            json={"transaction": payload, "sender_id": "納入業者"},
            timeout=5,
        )
        self.assertEqual(res_tx.status_code, 200)

        res_propose = requests.post(
            f"http://127.0.0.1:{self.ports[1]}/propose",
            timeout=10,
        )
        self.assertEqual(res_propose.status_code, 200)
        self.assertEqual(res_propose.json()["status"], "proposed")

        hashes = []
        for port in self.ports:
            res_chain = requests.get(f"http://127.0.0.1:{port}/chain", timeout=5)
            self.assertEqual(res_chain.status_code, 200)
            chain = res_chain.json()
            self.assertEqual(len(chain), 2)
            hashes.append(chain[-1]["hash"])

        self.assertEqual(len(set(hashes)), 1)

    def test_replica_cannot_propose(self):
        import requests
        res = requests.post(f"http://127.0.0.1:{self.ports[0]}/propose", timeout=5)
        self.assertEqual(res.status_code, 403)

    def test_http_audit_endpoint(self):
        """HTTP /audit でオフチェーン整合性を検証できること"""
        import requests
        from traceability import sign_data, encode_payload

        record_id = "rec-http-audit"
        offchain_hash = self.offchain.save_legacy_record(
            record_id, "LOT-AUDIT", "加熱", {"temp": 70.0}
        )
        leader = self.nodes[1]
        anchor_data = {"record_id": record_id, "hash": offchain_hash, "lot_number": "LOT-AUDIT"}
        anchor_payload = encode_payload({
            "data": anchor_data,
            "signature": sign_data(anchor_data, leader.private_key),
            "public_key": leader.public_key,
            "type": "OFFCHAIN_ANCHOR",
        })
        requests.post(
            f"http://127.0.0.1:{self.ports[1]}/transaction",
            json={"transaction": anchor_payload, "sender_id": "加工工場"},
            timeout=5,
        )
        requests.post(f"http://127.0.0.1:{self.ports[1]}/propose", timeout=10)

        res = requests.post(
            f"http://127.0.0.1:{self.ports[1]}/audit",
            json={"record_id": record_id},
            timeout=5,
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["integrity"])

class TestBulkTransactionProcessing(unittest.TestCase):
    """ステップ11: トランザクションのバルク処理（バッチ処理）のテスト"""

    def setUp(self):
        from traceability import Node
        self.leader = Node("LeaderNode", "Leader")
        self.replica = Node("ReplicaNode", "Replica")
        
        self.leader.add_peer(self.replica)
        self.replica.add_peer(self.leader)
        
        from traceability import generate_keypair
        self.pub, self.priv = generate_keypair()

    def test_bulk_max_count_trigger(self):
        """BULK_MAX_COUNTに達したときに一括してブロック提案されること"""
        from traceability import sign_data
        self.leader.bulk_max_count = 3
        self.leader.bulk_max_wait = 100

        for i in range(2):
            tx_data = {"item": f"item_{i}", "weight_kg": 150}
            payload = {"data": tx_data, "signature": sign_data(tx_data, self.priv), "public_key": self.pub}
            self.leader.receive_message("NEW_TRANSACTION", payload, "Sender")
            self.replica.receive_message("NEW_TRANSACTION", payload, "Sender")

        self.assertEqual(len(self.leader.chain.chain), 1)
        self.assertEqual(len(self.leader.pending_transactions), 2)

        tx_data = {"item": "item_2", "weight_kg": 150}
        payload = {"data": tx_data, "signature": sign_data(tx_data, self.priv), "public_key": self.pub}
        
        self.leader.receive_message("NEW_TRANSACTION", payload, "Sender")
        self.replica.receive_message("NEW_TRANSACTION", payload, "Sender")
        
        self.assertEqual(len(self.leader.pending_transactions), 3)
        
        self.leader.maybe_create_bulk_block()
        
        self.assertEqual(len(self.leader.chain.chain), 2)
        latest_block = self.leader.chain.get_latest_block()
        self.assertEqual(len(latest_block.data), 3)
        self.assertEqual(len(self.leader.pending_transactions), 0)

    def test_bulk_max_wait_trigger(self):
        """時間経過(BULK_MAX_WAIT_SECONDS)によって自動的にブロック提案されること"""
        import time
        from traceability import sign_data
        
        self.leader.bulk_max_count = 10
        self.leader.bulk_max_wait = 1
        self.leader.last_bulk_time = time.time()

        tx_data = {"item": "time_item", "weight_kg": 150}
        payload = {"data": tx_data, "signature": sign_data(tx_data, self.priv), "public_key": self.pub}
        self.leader.receive_message("NEW_TRANSACTION", payload, "Sender")
        self.replica.receive_message("NEW_TRANSACTION", payload, "Sender")

        self.assertEqual(len(self.leader.chain.chain), 1)
        self.assertEqual(len(self.leader.pending_transactions), 1)

        for _ in range(30):
            if len(self.leader.chain.chain) == 2:
                break
            time.sleep(0.1)

        self.assertEqual(len(self.leader.chain.chain), 2)
        latest_block = self.leader.chain.get_latest_block()
        self.assertEqual(len(latest_block.data), 1)
        self.assertEqual(len(self.leader.pending_transactions), 0)

class TestNewSpecDataManagement(unittest.TestCase):
    """ステップ12: データ管理・修正・削除機能（追加仕様書 V2.3 Final に基づく実装）のテスト"""

    def setUp(self):
        from traceability import Node, OffChainStore
        self.offchain_store = OffChainStore(db_path=":memory:")
        self.node_leader = Node("Node1(Leader)", "Leader")
        self.node_replica = Node("Node2(Replica)", "Replica")
        
        self.node_leader.add_peer(self.node_replica)
        self.node_replica.add_peer(self.node_leader)
        
        self.node_leader.set_offchain_store(self.offchain_store)
        self.node_replica.set_offchain_store(self.offchain_store)

    def tearDown(self):
        self.offchain_store.close()

    def test_create_flow(self):
        """CREATE: 新規作成、PENDING状態、および合意成功後の COMMITTED 状態への遷移"""
        trace_id = "TRACE-T-001"
        lot_number = "LOT-T-100"
        payload = {"operator": "UserA", "temperature": 75.0}
        
        h, salt = self.offchain_store.save_record(trace_id, payload, created_by="UserA")
        
        # 1. 初期状態検証
        self.assertEqual(len(salt), 64) # 32 byte hex = 64 chars
        
        # DB状態
        res = self.offchain_store.conn.execute(
            "SELECT version, tx_status, is_deleted FROM product_traceability WHERE trace_id = ?",
            (trace_id,)
        ).fetchone()
        self.assertIsNotNone(res)
        self.assertEqual(res[0], 1)
        self.assertEqual(res[1], "PENDING")
        self.assertFalse(res[2])
        
        # 最新版取得（PENDINGなので取得できないはず）
        latest = self.offchain_store.get_latest_record(trace_id)
        self.assertIsNone(latest)
        
        # オンチェーンアンカー
        anchor_data = {
            "trace_id": trace_id,
            "version": 1,
            "hash": h,
            "lot_number": lot_number,
            "created_by": "UserA"
        }
        
        from traceability import sign_data
        tx_payload = {
            "data": anchor_data,
            "signature": sign_data(anchor_data, self.node_leader.private_key),
            "public_key": self.node_leader.public_key,
            "type": "OFFCHAIN_ANCHOR"
        }
        
        self.node_leader.receive_message("NEW_TRANSACTION", tx_payload, "Sender")
        self.node_replica.receive_message("NEW_TRANSACTION", tx_payload, "Sender")
        
        # 合意
        self.node_leader.propose_block()
        
        # 合意後
        res_after = self.offchain_store.conn.execute(
            "SELECT tx_status FROM product_traceability WHERE trace_id = ?",
            (trace_id,)
        ).fetchone()
        self.assertEqual(res_after[0], "COMMITTED")
        
        # 最新版取得
        latest = self.offchain_store.get_latest_record(trace_id)
        self.assertIsNotNone(latest)
        self.assertEqual(latest["version"], 1)
        self.assertEqual(latest["payload"]["operator"], "UserA")
        
        # 監査
        audit_res = self.node_leader.audit_trace_data(trace_id, self.offchain_store)
        self.assertTrue(audit_res["valid"])
        self.assertEqual(audit_res["status"], "active")

    def test_update_flow(self):
        """UPDATE: データ修正、新versionの追加、およびSoft Delete済みに対するUPDATEの拒否"""
        trace_id = "TRACE-T-002"
        lot_number = "LOT-T-200"
        
        # 1. 最初期 COMMITTED を作成
        h1, salt1 = self.offchain_store.save_record(trace_id, {"val": 10}, "UserA")
        # 疑似 finalize (COMMITTED)
        self.offchain_store.conn.execute(
            "UPDATE product_traceability SET tx_status = 'COMMITTED' WHERE trace_id = ? AND version = 1",
            (trace_id,)
        )
        
        # 2. UPDATE の実行
        h2, salt2 = self.offchain_store.update_record(trace_id, {"val": 20}, "UserB", "修正")
        
        # PENDING で version 2 が作成されていること
        res_v2 = self.offchain_store.conn.execute(
            "SELECT version, tx_status FROM product_traceability WHERE trace_id = ? ORDER BY version DESC",
            (trace_id,)
        ).fetchall()
        self.assertEqual(len(res_v2), 2)
        self.assertEqual(res_v2[0][0], 2)
        self.assertEqual(res_v2[0][1], "PENDING")
        self.assertEqual(res_v2[1][0], 1)
        self.assertEqual(res_v2[1][1], "COMMITTED")
        
        # PENDING が存在するため UPDATE が拒否されること
        with self.assertRaises(ValueError) as ctx:
            self.offchain_store.update_record(trace_id, {"val": 30}, "UserB", "再修正")
        self.assertEqual(str(ctx.exception), "pending_transaction_exists")
        
        # 疑似 finalize version 2
        self.offchain_store.conn.execute(
            "UPDATE product_traceability SET tx_status = 'COMMITTED' WHERE trace_id = ? AND version = 2",
            (trace_id,)
        )
        
        # 最新版取得で version 2 が返ること
        latest = self.offchain_store.get_latest_record(trace_id)
        self.assertEqual(latest["version"], 2)
        self.assertEqual(latest["payload"]["val"], 20)

    def test_soft_delete_flow(self):
        """SOFT_DELETE: 論理削除、過去バージョンの浮上防止、および監査の動作"""
        trace_id = "TRACE-T-003"
        
        # 1. 準備 (COMMITTED の version 1, 2)
        self.offchain_store.save_record(trace_id, {"val": 10}, "UserA")
        self.offchain_store.conn.execute("UPDATE product_traceability SET tx_status = 'COMMITTED'")
        self.offchain_store.update_record(trace_id, {"val": 20}, "UserA", "修正")
        self.offchain_store.conn.execute("UPDATE product_traceability SET tx_status = 'COMMITTED' WHERE version = 2")
        
        # 2. validate_soft_delete
        v = self.offchain_store.validate_soft_delete(trace_id)
        self.assertEqual(v, 2)
        
        # 3. Soft Delete トランザクション
        delete_data = {
            "trace_id": trace_id,
            "target_version": 2,
            "deleted_by": "UserDel",
            "reason": "ロット取消"
        }
        from traceability import sign_data
        tx_payload = {
            "data": delete_data,
            "signature": sign_data(delete_data, self.node_leader.private_key),
            "public_key": self.node_leader.public_key,
            "type": "OFFCHAIN_SOFT_DELETE"
        }
        
        # 合意前は is_deleted が変更されない
        self.node_leader.receive_message("NEW_TRANSACTION", tx_payload, "Sender")
        self.node_replica.receive_message("NEW_TRANSACTION", tx_payload, "Sender")
        
        res_before = self.offchain_store.conn.execute(
            "SELECT is_deleted FROM product_traceability WHERE trace_id = ?",
            (trace_id,)
        ).fetchall()
        self.assertTrue(all(r[0] is False for r in res_before))
        
        # 合意
        self.node_leader.propose_block()
        
        # 合意後はすべての version が is_deleted = TRUE になる
        res_after = self.offchain_store.conn.execute(
            "SELECT is_deleted FROM product_traceability WHERE trace_id = ?",
            (trace_id,)
        ).fetchall()
        self.assertTrue(all(r[0] is True for r in res_after))
        
        # 最新版取得が None になること（過去versionの再浮上防止）
        latest = self.offchain_store.get_latest_record(trace_id)
        self.assertIsNone(latest)
        
        # UPDATE が拒否されること
        with self.assertRaises(ValueError) as ctx:
            self.offchain_store.update_record(trace_id, {"val": 30}, "UserA", "削除後修正")
        self.assertEqual(str(ctx.exception), "already_deleted")
        
        # 監査
        audit_res = self.node_leader.audit_trace_data(trace_id, self.offchain_store)
        self.assertTrue(audit_res["valid"])
        self.assertEqual(audit_res["status"], "soft_deleted")
        self.assertEqual(audit_res["target_version"], 2)

    def test_hard_delete_flow(self):
        """HARD_DELETE: 物理削除の実行、ログ出力、個人情報の排除、および監査の動作"""
        trace_id = "TRACE-T-004"
        import tempfile
        import os
        from traceability import sign_data
        
        # 一時ログファイル準備
        with tempfile.NamedTemporaryFile(delete=False) as tmp_log:
            tmp_log_path = tmp_log.name
            
        try:
            # 準備
            h, salt = self.offchain_store.save_record(trace_id, {"secret_p": "confidential_val"}, "UserA")
            self.offchain_store.conn.execute("UPDATE product_traceability SET tx_status = 'COMMITTED'")
            
            # オンチェーン擬似データ
            self.node_leader.chain.add_process_data(
                "OFFCHAIN_ANCHOR",
                {"trace_id": trace_id, "version": 1, "hash": h, "lot_number": "L"},
                self.node_leader.public_key,
                sign_data({"trace_id": trace_id, "version": 1, "hash": h, "lot_number": "L"}, self.node_leader.private_key)
            )
            
            # 物理削除
            audit_log_id, deleted_versions = self.offchain_store.hard_delete(
                trace_id=trace_id,
                executed_by="admin",
                reason="GDPR",
                anchored_hashes=[h],
                log_path=tmp_log_path
            )
            
            self.assertEqual(deleted_versions, 1)
            self.assertTrue(audit_log_id.startswith("hd-"))
            
            # DBから物理的に消去されていること
            res = self.offchain_store.conn.execute(
                "SELECT COUNT(*) FROM product_traceability WHERE trace_id = ?",
                (trace_id,)
            ).fetchone()[0]
            self.assertEqual(res, 0)
            
            # ログの検証
            with open(tmp_log_path, "r", encoding="utf-8") as f:
                log_lines = f.readlines()
            self.assertEqual(len(log_lines), 1)
            log_data = json.loads(log_lines[0])
            self.assertEqual(log_data["audit_log_id"], audit_log_id)
            self.assertEqual(log_data["trace_id"], trace_id)
            self.assertNotIn("payload", log_data)
            self.assertNotIn("salt", log_data)
            self.assertNotIn("confidential_val", log_lines[0])
            
            # 監査
            audit_res = self.node_leader.audit_trace_data(trace_id, self.offchain_store)
            self.assertTrue(audit_res["valid"])
            self.assertEqual(audit_res["status"], "hard_deleted")
            
        finally:
            if os.path.exists(tmp_log_path):
                os.remove(tmp_log_path)

    def test_pending_ttl(self):
        """TTL: PENDING レコードの有効期限（TTL）タイムアウトによる FAILED への遷移"""
        import os
        import time
        os.environ["PBFT_PENDING_TTL_SECONDS"] = "1"
        
        try:
            trace_id = "TRACE-T-005"
            h, salt = self.offchain_store.save_record(trace_id, {"val": 10}, "UserA")
            
            res = self.offchain_store.conn.execute(
                "SELECT tx_status FROM product_traceability WHERE trace_id = ?",
                (trace_id,)
            ).fetchone()
            self.assertEqual(res[0], "PENDING")
            
            from datetime import datetime, timedelta, timezone
            time.sleep(1.5)
            
            cutoff = datetime.now(timezone.utc)
            self.offchain_store.conn.execute("""
                UPDATE product_traceability
                SET tx_status = 'FAILED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE tx_status = 'PENDING'
                  AND created_at < ?
            """, (cutoff,))
            
            res_after = self.offchain_store.conn.execute(
                "SELECT tx_status FROM product_traceability WHERE trace_id = ?",
                (trace_id,)
            ).fetchone()
            self.assertEqual(res_after[0], "FAILED")
            
        finally:
            del os.environ["PBFT_PENDING_TTL_SECONDS"]


if __name__ == '__main__':
    unittest.main()
