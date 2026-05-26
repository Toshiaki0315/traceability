import base64
import hashlib
import json
import os
import time
import rsa
import threading
import duckdb

# HTTPブロードキャスト用のエンドポイントマッピング（ステップ10）
HTTP_BROADCAST_ROUTES = {
    "NEW_TRANSACTION": "/transaction",
    "PRE_PREPARE": "/pbft/pre_prepare",
    "PREPARE": "/pbft/prepare",
    "COMMIT": "/pbft/commit",
}

PBFT_ROUTE_TO_MSG = {
    "pre_prepare": "PRE_PREPARE",
    "prepare": "PREPARE",
    "commit": "COMMIT",
}

# ==========================================
# オフチェーンデータベース管理 (ステップ8)
# ==========================================
class OffChainStore:
    def __init__(self, db_path="data/offchain_store.db"):
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = duckdb.connect(db_path)
        self._create_table()

    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS manufacturing_details (
                record_id VARCHAR PRIMARY KEY,
                lot_number VARCHAR,
                process_name VARCHAR,
                details VARCHAR,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    def save_record(self, record_id, lot_number, process_name, details):
        """詳細データをオフチェーンDBに保存し、SHA-256ハッシュ値を算出する"""
        details_str = json.dumps(details, sort_keys=True) if isinstance(details, dict) else str(details)
        self.conn.execute("""
            INSERT OR REPLACE INTO manufacturing_details (record_id, lot_number, process_name, details)
            VALUES (?, ?, ?, ?)
        """, (record_id, lot_number, process_name, details_str))
        return self.calculate_record_hash(record_id, lot_number, process_name, details_str)

    def calculate_record_hash(self, record_id, lot_number, process_name, details):
        """オフチェーンデータレコードに対するSHA-256ハッシュを一貫した方法で計算する"""
        details_str = json.dumps(details, sort_keys=True) if isinstance(details, dict) else str(details)
        content = {
            "record_id": record_id,
            "lot_number": lot_number,
            "process_name": process_name,
            "details": details_str
        }
        content_bytes = json.dumps(content, sort_keys=True).encode()
        return hashlib.sha256(content_bytes).hexdigest()

    def get_record(self, record_id):
        """指定されたrecord_idのオフチェーンデータを取得する"""
        res = self.conn.execute("""
            SELECT record_id, lot_number, process_name, details FROM manufacturing_details
            WHERE record_id = ?
        """, (record_id,)).fetchone()
        if not res:
            return None
        return {
            "record_id": res[0],
            "lot_number": res[1],
            "process_name": res[2],
            "details": res[3]
        }

    def close(self):
        self.conn.close()

# ==========================================
# 電子署名関連のヘルパー関数（ステップ1）
# ==========================================
def generate_keypair():
    """参加者（納入業者、工場など）の公開鍵・秘密鍵ペアを生成する"""
    # PoCのため処理速度を優先し、512bitの鍵長を使用
    return rsa.newkeys(512)

def sign_data(data, private_key):
    """データ（辞書型）を直列化し、秘密鍵でデジタル署名を生成する"""
    data_string = json.dumps(data, sort_keys=True).encode()
    return rsa.sign(data_string, private_key, 'SHA-256')

def verify_signature(data, signature, public_key):
    """データと署名を受け取り、公開鍵を用いて正当性を検証する"""
    data_string = json.dumps(data, sort_keys=True).encode()
    try:
        rsa.verify(data_string, signature, public_key)
        return True
    except rsa.VerificationError:
        return False


# ==========================================
# HTTP/JSON シリアライズ（ステップ10）
# ==========================================
def encode_payload(payload: dict) -> dict:
    """トランザクションペイロードをJSON送信用に変換する（署名・公開鍵をBase64化）"""
    result = dict(payload)
    sig = result.get("signature")
    if isinstance(sig, bytes):
        result["signature"] = base64.b64encode(sig).decode("ascii")
    pub = result.get("public_key")
    if hasattr(pub, "save_pkcs1"):
        result["public_key"] = base64.b64encode(pub.save_pkcs1()).decode("ascii")
    return result


def decode_payload(payload: dict) -> dict:
    """JSONから受信したペイロードを検証用の型に復元する"""
    result = dict(payload)
    sig = result.get("signature")
    if isinstance(sig, str):
        result["signature"] = base64.b64decode(sig)
    pub = result.get("public_key")
    if isinstance(pub, str):
        result["public_key"] = rsa.PublicKey.load_pkcs1(base64.b64decode(pub))
    return result


def block_to_dict(block: "Block") -> dict:
    """BlockオブジェクトをJSON送信用の辞書に変換する"""
    data = block.data
    if isinstance(data, list):
        data = [encode_payload(tx) if isinstance(tx, dict) and "signature" in tx else tx for tx in data]
    return {
        "index": block.index,
        "timestamp": block.timestamp,
        "process_name": block.process_name,
        "data": data,
        "previous_hash": block.previous_hash,
        "hash": block.hash,
    }


def dict_to_block(block_dict: dict) -> "Block":
    """JSON辞書からBlockオブジェクトを復元する"""
    data = block_dict["data"]
    if isinstance(data, list):
        data = [
            decode_payload(tx) if isinstance(tx, dict) and "signature" in tx else tx
            for tx in data
        ]
    block = Block(
        index=block_dict["index"],
        timestamp=block_dict["timestamp"],
        process_name=block_dict["process_name"],
        data=data,
        previous_hash=block_dict["previous_hash"],
    )
    if block.hash != block_dict["hash"]:
        raise ValueError("ブロックハッシュが一致しません。データが改ざんされている可能性があります。")
    return block


def default_weight_check_rule(payload):
    """原料重量が100kg以上であることを検証するデフォルトビジネスルール"""
    if payload.get("type") == "OFFCHAIN_ANCHOR":
        return True
    data = payload.get("data", {})
    weight = data.get("weight_kg", 0)
    if weight < 100:
        raise ValueError(f"原料重量({weight}kg)が少なすぎます。最低100kg必要です。")
    return True


# ==========================================
# ブロックとチェーンの基本構造
# ==========================================
class Block:
    def __init__(self, index, timestamp, process_name, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.process_name = process_name  # 工程名
        self.data = data                  # 工程ごとの記録データ
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """ブロック内のデータからSHA-256ハッシュを計算して改ざんを検知可能にする"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "process_name": self.process_name,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True, default=str).encode()
        return hashlib.sha256(block_string).hexdigest()

class TraceabilityChain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        """チェーンの起点となる最初のブロック（ジェネシスブロック）を生成"""
        # ジェネシスブロックのタイムスタンプは固定値（全ノードで同一のハッシュにするため）
        return Block(0, 0, "System Initialization", {"info": "Traceability Chain Started"}, "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_process_data(self, process_name, data, public_key, signature):
        """新しい工程のデータをブロックチェーンに追加する（署名検証付き）"""
        
        # 1. 署名の検証（Step1の要件）
        if not verify_signature(data, signature, public_key):
            raise ValueError("【エラー】無効な署名です。データが改ざんされているか、権限がありません。")

        # 2. ブロック化
        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=int(time.time()),
            process_name=process_name,
            data=data,
            previous_hash=latest_block.hash
        )
        self.chain.append(new_block)

    def is_chain_valid(self):
        """チェーン全体のデータが記録後に改ざんされていないか検証する"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # ブロック自体のハッシュが再計算結果と一致するか（データ改ざんチェック）
            if current_block.hash != current_block.calculate_hash():
                return False
            # 前のブロックのハッシュと正しくリンクしているか（チェーン切断チェック）
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

    def display_chain(self):
        """現在のチェーンの状態を出力"""
        for block in self.chain:
            print(f"--- Block {block.index} : {block.process_name} ---")
            print(f"Timestamp    : {block.timestamp}")
            print(f"Data         : {block.data}")
            print(f"Previous Hash: {block.previous_hash}")
            print(f"Current Hash : {block.hash}\n")

    # ------------------------------------------
    # 台帳の永続化（ステップ6）
    # ------------------------------------------
    def save_chain(self, filepath):
        """チェーンの全ブロックをJSON形式でファイルに保存する"""
        chain_data = []
        for block in self.chain:
            chain_data.append({
                "index": block.index,
                "timestamp": block.timestamp,
                "process_name": block.process_name,
                "data": block.data,
                "previous_hash": block.previous_hash,
                "hash": block.hash
            })
        
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(chain_data, f, ensure_ascii=False, indent=2, default=str)
        print(f"[INFO] チェーンを保存しました: {filepath}")

    @classmethod
    def load_chain(cls, filepath):
        """ファイルからチェーンを復元し、ハッシュの整合性を検証する"""
        with open(filepath, "r", encoding="utf-8") as f:
            chain_data = json.load(f)

        # ブロックを復元
        chain_instance = cls.__new__(cls)
        chain_instance.chain = []
        for block_dict in chain_data:
            block = Block(
                index=block_dict["index"],
                timestamp=block_dict["timestamp"],
                process_name=block_dict["process_name"],
                data=block_dict["data"],
                previous_hash=block_dict["previous_hash"]
            )
            # 復元したブロックのハッシュが保存時と一致するか検証
            if block.hash != block_dict["hash"]:
                raise ValueError(
                    f"【改ざん検知】Block {block.index} のデータが保存後に変更されています。"
                    f"\n  保存時Hash: {block_dict['hash']}"
                    f"\n  再計算Hash: {block.hash}"
                )
            chain_instance.chain.append(block)

        # チェーン全体のリンク整合性も検証
        if not chain_instance.is_chain_valid():
            raise ValueError("【改ざん検知】チェーンのリンク構造が破損しています。")

        print(f"[INFO] チェーンを復元しました: {filepath} ({len(chain_instance.chain)} ブロック)")
        return chain_instance


# ==========================================
# P2Pネットワーク・ノードとPBFT合意形成
# ==========================================

# PBFTで合意成立に必要なノード数（定足数）
# 3ノード構成の場合: f=0（障害許容数）, quorum = 2f+1 = 1 だが、
# 学習のため過半数（2/3 以上）を定足数として使用する
PBFT_QUORUM = 2

class Node:
    def __init__(self, node_id, role):
        self.node_id = node_id
        self.role = role  # "Leader" または "Replica"
        # 各ノードは自身の鍵ペアと独立したチェーン（台帳）を持つ
        self.public_key, self.private_key = generate_keypair()
        self.chain = TraceabilityChain()
        self.peers = []
        self.peer_urls = []  # ピアノードのベースURL（例: ['http://127.0.0.1:5002']）
        self.pending_transactions = []
        self.prepares = {}  # {block_hash: set(node_ids)}
        self.commits = {}   # {block_hash: set(node_ids)}
        self.business_rules = []
        self.bulk_max_count = int(os.getenv('BULK_MAX_COUNT', 10))
        self.bulk_max_wait = int(os.getenv('BULK_MAX_WAIT_SECONDS', 5))
        self.last_bulk_time = time.time()
        self._pending_lock = threading.Lock()
        if self.role == "Leader":
            threading.Thread(target=self._batch_watcher, daemon=True).start()

    def set_peer_urls(self, urls: list[str]):
        """ノード起動時にピアURLリストを設定する（ステップ10）"""
        self.peer_urls = urls

    def add_peer(self, node):
        """P2Pネットワークのピア（通信相手）を登録する"""
        if node not in self.peers:
            self.peers.append(node)

    def add_business_rule(self, rule_func):
        """ノードに新しいビジネスルール（検証用関数）を登録する"""
        self.business_rules.append(rule_func)

    # ------------------------------------------
    # 台帳の永続化（ステップ6）
    # ------------------------------------------
    def save_state(self, data_dir):
        """ノードのチェーンをファイルに保存する"""
        filepath = os.path.join(data_dir, f"{self.node_id}_chain.json")
        self.chain.save_chain(filepath)

    def load_state(self, data_dir):
        """ファイルからチェーンを復元する"""
        filepath = os.path.join(data_dir, f"{self.node_id}_chain.json")
        self.chain = TraceabilityChain.load_chain(filepath)

    def audit_offchain_data(self, record_id, offchain_store):
        """オフチェーンデータ（DuckDB）のハッシュをオンチェーン（ブロックチェーン）と照合して整合性を監査する"""
        # 1. オフチェーンデータの取得
        record = offchain_store.get_record(record_id)
        if not record:
            print(f"     [{self.node_id}] 【監査警告】オフチェーンDBにレコード {record_id} が存在しません。")
            return False

        # 2. オフチェーンデータのハッシュ再計算
        recalculated_hash = offchain_store.calculate_record_hash(
            record["record_id"],
            record["lot_number"],
            record["process_name"],
            record["details"]
        )

        # 3. オンチェーン（ブロックチェーン）から該当レコードのアンカーハッシュ値を探索
        anchored_hash = None
        # ジェネシス以外のブロックを走査
        for block in self.chain.chain[1:]:
            if isinstance(block.data, list):
                # PBFTブロック内のトランザクションを走査
                for tx in block.data:
                    if tx.get("type") == "OFFCHAIN_ANCHOR":
                        tx_data = tx.get("data", {})
                        if tx_data.get("record_id") == record_id:
                            anchored_hash = tx_data.get("hash")
                            break
            elif isinstance(block.data, dict):
                # PBFT前の互換用
                if block.process_name == "OFFCHAIN_ANCHOR" and block.data.get("record_id") == record_id:
                    anchored_hash = block.data.get("hash")
            
            if anchored_hash:
                break

        if not anchored_hash:
            print(f"     [{self.node_id}] 【監査警告】オンチェーン上にレコード {record_id} のアンカーハッシュが見つかりません。")
            return False

        # 4. ハッシュ比較
        if recalculated_hash == anchored_hash:
            print(f"     [{self.node_id}] 【監査成功】レコード {record_id} の整合性を確認しました。")
            print(f"       オンチェーン登録ハッシュ: {anchored_hash[:16]}...")
            print(f"       オフチェーン再計算ハッシュ: {recalculated_hash[:16]}...")
            return True
        else:
            print(f"     [{self.node_id}] 【監査警告】レコード {record_id} の改ざんを検知しました！")
            print(f"       オンチェーン登録ハッシュ: {anchored_hash[:16]}...")
            print(f"       オフチェーン再計算ハッシュ: {recalculated_hash[:16]}...")
            return False



    def broadcast(self, msg_type, payload):
        """全ピアへメッセージをブロードキャストする。
        peer_urls が設定されている場合は HTTP/REST、未設定の場合はインメモリ呼び出し。
        """
        if self.peer_urls:
            import requests
            route = HTTP_BROADCAST_ROUTES.get(msg_type)
            if not route:
                print(f"[WARN] 未知のメッセージタイプ: {msg_type}")
                return
            for url in self.peer_urls:
                full_url = f"{url.rstrip('/')}{route}"
                try:
                    if msg_type == "NEW_TRANSACTION":
                        body = {
                            "transaction": encode_payload(payload),
                            "sender_id": self.node_id,
                            "relay": True,
                        }
                        resp = requests.post(full_url, json=body, timeout=5)
                    else:
                        block_body = payload if isinstance(payload, dict) else block_to_dict(payload)
                        body = {"payload": block_body, "sender_id": self.node_id}
                        resp = requests.post(full_url, json=body, timeout=5)
                    resp.raise_for_status()
                except Exception as e:
                    print(f"[WARN] HTTP broadcast to {full_url} failed: {e}")
        else:
            print(f"[{self.node_id}] ブロードキャスト送信: {msg_type}")
            for peer in self.peers:
                peer.receive_message(msg_type, payload, self.node_id)


    # ------------------------------------------
    # PBFT メッセージ受信ハンドラ
    # ------------------------------------------
    def receive_message(self, msg_type, payload, sender_id):
        """他ノードからメッセージを受信した際の処理"""
        print(f"  -> [{self.node_id}] メッセージ受信 from {sender_id}: {msg_type}")

        if msg_type == "NEW_TRANSACTION":
            self._handle_new_transaction(payload)
        elif msg_type == "PRE_PREPARE":
            self._handle_pre_prepare(payload)
        elif msg_type == "PREPARE":
            self._handle_prepare(payload, sender_id)
        elif msg_type == "COMMIT":
            self._handle_commit(payload, sender_id)

    def _handle_new_transaction(self, payload):
        """NEW_TRANSACTION: 署名検証および登録されたすべてのビジネスルールを適用してから未承認リストに追加する"""
        data = payload.get("data")
        signature = payload.get("signature")
        pub_key = payload.get("public_key")

        # 1. 電子署名の検証
        if not verify_signature(data, signature, pub_key):
            print(f"     [{self.node_id}] 【警告】不正な署名のトランザクションを破棄しました。")
            return

        # 2. ビジネスルールの検証 (スマートコントラクト的処理)
        for rule in self.business_rules:
            try:
                if not rule(payload):
                    print(f"     [{self.node_id}] 【警告】ビジネスルール検証に失敗したためトランザクションを破棄しました。")
                    return
            except Exception as e:
                print(f"     [{self.node_id}] 【警告】ビジネスルール検証中にエラーが発生したためトランザクションを破棄しました: {e}")
                return

        # Thread-safe addition to pending transactions
        with self._pending_lock:
            self.pending_transactions.append(payload)
            if len(self.pending_transactions) == 1:
                self.last_bulk_time = time.time()
        print(f"     [{self.node_id}] トランザクションを未承認リストに追加しました。")

    def _handle_pre_prepare(self, block):
        """PRE_PREPARE: リーダーからの提案を受け、PREPAREを全ノードに送る"""
        # 既に確定済みのブロックは処理しない
        if self.chain.get_latest_block().hash == block.hash:
            return

        # ブロックの整合性を検証（ビザンチン障害対策）
        if not self._validate_block(block):
            print(f"     [{self.node_id}] 【警告】不正なブロックを検出しました。提案を拒否します。")
            return

        self._ensure_vote_set(block.hash)

        if self.node_id not in self.prepares[block.hash]:
            self.prepares[block.hash].add(self.node_id)
            print(f"     [{self.node_id}] PRE_PREPAREを受信しました。PREPAREをブロードキャストします。")
            self.broadcast("PREPARE", block)

            # ブロードキャスト中に他ノードからのPREPAREが届き、
            # 既に定足数に達している可能性があるためチェックする
            self._try_commit(block)

    def _handle_prepare(self, block, sender_id):
        """PREPARE: 賛成票を集計し、定足数に達したらCOMMITへ移行する"""
        self._ensure_vote_set(block.hash)
        self.prepares[block.hash].add(sender_id)
        self._try_commit(block)

    def _handle_commit(self, block, sender_id):
        """COMMIT: コミット票を集計し、定足数に達したらブロックを確定する"""
        if block.hash not in self.commits:
            self.commits[block.hash] = set()
        self.commits[block.hash].add(sender_id)
        # 自身がまだCOMMITしていなければ、COMMITに参加する
        # （ダウンノードがいるとPREPAREだけでは定足数に達しない場合があるため）
        if self.node_id not in self.commits[block.hash]:
            self.commits[block.hash].add(self.node_id)
            self.broadcast("COMMIT", block)
        self._try_finalize(block)

    # ------------------------------------------
    # PBFT 内部ヘルパー
    # ------------------------------------------
    def _validate_block(self, block):
        """ブロックの整合性を検証する（ハッシュ値の再計算チェック）"""
        if block.hash != block.calculate_hash():
            return False
        # previous_hashが自身のチェーンの最新ブロックと一致するか
        if block.previous_hash != self.chain.get_latest_block().hash:
            return False
        return True

    def _ensure_vote_set(self, block_hash):
        """投票セットが未初期化であれば初期化する"""
        if block_hash not in self.prepares:
            self.prepares[block_hash] = set()

    def _try_commit(self, block):
        """PREPARE票が定足数に達していたらCOMMITをブロードキャストする"""
        if len(self.prepares[block.hash]) >= PBFT_QUORUM:
            if block.hash not in self.commits:
                self.commits[block.hash] = set()
            if self.node_id not in self.commits[block.hash]:
                self.commits[block.hash].add(self.node_id)
                print(f"     [{self.node_id}] 定足数のPREPAREを受信。COMMITをブロードキャストします。")
                self.broadcast("COMMIT", block)
                # ブロードキャスト中に他ノードからのCOMMITが届き、
                # 既に定足数に達している可能性があるためチェックする
                self._try_finalize(block)

    def _try_finalize(self, block):
        """COMMIT票が定足数に達していたらブロックを台帳に確定する"""
        if len(self.commits[block.hash]) >= PBFT_QUORUM:
            # 二重追加を防止する
            if self.chain.get_latest_block().hash != block.hash:
                self.chain.chain.append(block)
                print(f"[{self.node_id}] ★ブロック確定！ (Hash: {block.hash[:8]}...)")

    # ------------------------------------------
    # リーダー専用: ブロック提案
    # ------------------------------------------
    def propose_block(self):
        """リーダーノードが未承認トランザクションをまとめて新しいブロック候補を提案する"""
        if self.role != "Leader":
            raise PermissionError("ブロックを提案できるのはLeaderノードのみです。")

        # Thread-safe check and extraction of pending transactions
        with self._pending_lock:
            if not self.pending_transactions:
                print(f"[{self.node_id}] 提案するトランザクションがありません。")
                return None
            transactions_to_block = self.pending_transactions.copy()
            self.pending_transactions.clear()

        # 新しいブロック候補を作成（まだ自身のチェーンには追加しない）
        latest_block = self.chain.get_latest_block()
        proposed_block = Block(
            index=latest_block.index + 1,
            timestamp=int(time.time()),
            process_name="PBFT Proposed Block",
            data=transactions_to_block,
            previous_hash=latest_block.hash
        )

        print(f"[{self.node_id}] 新しいブロック候補を作成しました。全ノードに提案(PRE_PREPARE)します。")
        # リーダー自身もPREPARE票を入れておく
        self.prepares[proposed_block.hash] = {self.node_id}

        # ブロードキャストして全ノードに提案
        self.broadcast("PRE_PREPARE", proposed_block)

        # 提案後、他ノードからの応答で定足数に達している可能性をチェック
        self._try_commit(proposed_block)

        return proposed_block

    def _batch_watcher(self):
        """Background thread that monitors pending transactions and creates bulk blocks."""
        while True:
            time.sleep(1)
            trigger_bulk = False
            with self._pending_lock:
                if self.pending_transactions:
                    elapsed = time.time() - self.last_bulk_time
                    if len(self.pending_transactions) >= self.bulk_max_count or elapsed >= self.bulk_max_wait:
                        trigger_bulk = True
            if trigger_bulk:
                self.maybe_create_bulk_block()

    def maybe_create_bulk_block(self):
        """Create a block from pending transactions if any."""
        self.propose_block()

# ==========================================
# 実行サンプル: PBFTコンセンサスのシミュレーション
# ==========================================
if __name__ == "__main__":
    print("=" * 60)
    print("  PBFT ブロックチェーン トレーサビリティ シミュレーション")
    print("=" * 60)
    print()

    # ------------------------------------------
    # フェーズ1: ノードの初期化とネットワーク構築
    # ------------------------------------------
    print("[Phase 1] 各参加者ノードを起動し、鍵ペアと台帳を初期化しています...")
    node_supplier  = Node("納入業者", "Replica")
    node_factory   = Node("加工工場", "Leader")
    node_warehouse = Node("倉庫",     "Replica")
    print("[Phase 1] ノード起動完了。\n")

    nodes = [node_supplier, node_factory, node_warehouse]
    for n1 in nodes:
        for n2 in nodes:
            if n1 != n2:
                n1.add_peer(n2)
    print("[Phase 1] ネットワークの構築完了。各ノードが接続されました。")

    # ビジネスルールの定義と登録
    def weight_check_rule(payload):
        # アンカーデータなど特殊トランザクションは重量チェックをスキップ
        if payload.get("type") == "OFFCHAIN_ANCHOR":
            return True
        data = payload.get("data", {})
        weight = data.get("weight_kg", 0)
        if weight < 100:
            raise ValueError(f"原料重量({weight}kg)が少なすぎます。最低100kg必要です。")
        return True


    for node in nodes:
        node.add_business_rule(weight_check_rule)
    print("[Phase 1] ビジネスルール（最低重量100kg）を全ノードに登録しました。\n")

    # ------------------------------------------
    # フェーズ2: トランザクションの送信
    # ------------------------------------------
    print("--- Phase 2: トランザクション送信 (ルール違反のテスト) ---")
    invalid_data = {"lot_number": "RAW-A001", "supplier": "A社", "weight_kg": 50}
    invalid_sig = sign_data(invalid_data, node_supplier.private_key)
    invalid_payload = {
        "data": invalid_data,
        "signature": invalid_sig,
        "public_key": node_supplier.public_key
    }
    # 納入業者が全ノードにトランザクションをブロードキャスト（拒否されるはず）
    node_supplier.broadcast("NEW_TRANSACTION", invalid_payload)
    print()

    print("--- Phase 2: トランザクション送信 (正常データの送信) ---")
    test_data = {"lot_number": "RAW-A001", "supplier": "A社", "weight_kg": 500}
    signature = sign_data(test_data, node_supplier.private_key)

    payload = {
        "data": test_data,
        "signature": signature,
        "public_key": node_supplier.public_key
    }

    # 納入業者が全ノードにトランザクションをブロードキャスト
    node_supplier.broadcast("NEW_TRANSACTION", payload)

    # ------------------------------------------
    # フェーズ3: PBFT合意形成
    # ------------------------------------------
    print("\n--- Phase 3: PBFT合意形成 ---")
    # リーダーノード（加工工場）がブロック候補を作成し、合意プロセスを開始
    node_factory.propose_block()

    # ------------------------------------------
    # フェーズ4: 結果の検証
    # ------------------------------------------
    print("\n--- Phase 4: 結果の検証 ---")
    for node in nodes:
        latest = node.chain.get_latest_block()
        print(f"[{node.node_id}] チェーン長: {len(node.chain.chain)}, 最新ブロックHash: {latest.hash[:16]}...")

    # 全ノードの台帳が一致しているか確認
    hashes = [n.chain.get_latest_block().hash for n in nodes]
    if len(set(hashes)) == 1:
        print("\n✅ 全ノードの台帳が一致しています。合意形成に成功しました！")
    else:
        print("\n❌ 台帳の不一致が検出されました。")

    # ------------------------------------------
    # フェーズ5: 台帳の永続化
    # ------------------------------------------
    print("\n--- Phase 5: 台帳の永続化 ---")
    data_dir = "data"
    for node in nodes:
        node.save_state(data_dir)

    # 復元テスト（新しいノードで台帳を読み込む）
    print("\n[INFO] 保存した台帳を新しいノードで復元します...")
    restored_node = Node("加工工場", "Leader")
    restored_node.load_state(data_dir)
    print(f"[INFO] 復元されたチェーン長: {len(restored_node.chain.chain)}")
    print(f"[INFO] 最新ブロックHash: {restored_node.chain.get_latest_block().hash[:16]}...")

    # ------------------------------------------
    # フェーズ6: DuckDBを用いたオフチェーン・オンチェーン連携 (ステップ8)
    # ------------------------------------------
    print("\n--- Phase 6: DuckDBを用いたオフチェーン・オンチェーン連携 ---")
    
    # オフチェーンDWH/ストアの準備
    offchain_db_path = "data/manufacturing_offchain.db"
    # デモ用のDBファイル初期化
    if os.path.exists(offchain_db_path):
        try:
            os.remove(offchain_db_path)
        except OSError:
            pass

    offchain_store = OffChainStore(db_path=offchain_db_path)
    
    # ブロックチェーンに乗せるには大容量すぎる詳細な工程ログデータ
    record_id = "rec-factory-202605"
    detailed_log = {
        "operator": "山田 太郎",
        "equipment_id": "HEATER-X9",
        "target_temperature_c": 75.0,
        "actual_temperature_log_c": [74.5, 74.8, 75.1, 75.0, 74.9],
        "humidity_percent": 48.2,
        "duration_minutes": 45,
        "remarks": "加熱ムラなし。加熱処理を正常終了しました。"
    }
    
    print("[Off-chain] 詳細な加工ログデータをDuckDB（オフチェーン）に保存します...")
    # 保存してハッシュを計算
    offchain_hash = offchain_store.save_record(
        record_id=record_id,
        lot_number="RAW-A001",
        process_name="詳細加熱加工ログ",
        details=detailed_log
    )
    print(f"[Off-chain] 保存完了。算出されたデータハッシュ値: {offchain_hash}")
    
    print("\n[On-chain] レコードIDとハッシュ値のみをアンカーデータとしてブロックチェーンへ記録します...")
    anchor_data = {
        "record_id": record_id,
        "hash": offchain_hash,
        "lot_number": "RAW-A001"
    }
    
    # 工場ノードが署名したアンカー用のトランザクションペイロードを作成
    anchor_payload = {
        "data": anchor_data,
        "signature": sign_data(anchor_data, node_factory.private_key),
        "public_key": node_factory.public_key,
        "type": "OFFCHAIN_ANCHOR"
    }
    
    # 全ノードにアンカートランザクションを送信（同期）
    for node in nodes:
        node.receive_message("NEW_TRANSACTION", anchor_payload, "加工工場")
    
    print("\n[On-chain] アンカー取引に対するPBFT合意形成プロセスを開始します...")
    node_factory.propose_block()
    
    # 監査デモンストレーション
    print("\n--- 監査 (Integrity Verification) デモ ---")
    print("[Audit] 正常時のデータ整合性監査を実行します...")
    node_factory.audit_offchain_data(record_id, offchain_store)
    
    print("\n[Audit] 悪意ある管理者によるオフチェーンDB（DuckDB）の直接改ざんをシミュレーションします...")
    # 悪意あるユーザーまたはDB管理者が直接データベースの数値を書き換える
    offchain_store.conn.execute(
        "UPDATE manufacturing_details SET details = ? WHERE record_id = ?",
        ('{"actual_temperature_log_c": [50.0, 50.2, 50.1, 50.0, 50.0], "operator": "改ざん者", "remarks": "異常データを隠蔽"}', record_id)
    )
    print("[Audit] DuckDBの加工記録を『75℃(正常)』から『50℃(低温・異常)』に隠蔽改ざんしました。")
    
    print("\n[Audit] 改ざん後のデータ整合性監査を実行します...")
    node_factory.audit_offchain_data(record_id, offchain_store)
    
    # データベースクローズ
    offchain_store.close()

    print("\n" + "=" * 60)
    print("  シミュレーション完了")
    print("=" * 60)

