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
        # レガシーデータのテーブル構造はそのまま維持
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS manufacturing_details (
                record_id VARCHAR PRIMARY KEY,
                lot_number VARCHAR,
                process_name VARCHAR,
                details VARCHAR,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 新仕様のテーブル
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS product_traceability (
                id VARCHAR PRIMARY KEY,
                trace_id VARCHAR NOT NULL,
                version INTEGER NOT NULL,
                payload JSON NOT NULL,
                salt VARCHAR(64) NOT NULL,
                is_deleted BOOLEAN DEFAULT FALSE,
                tx_status VARCHAR DEFAULT 'PENDING',
                created_by VARCHAR,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(trace_id, version)
            )
        """)
        # インデックス定義
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_trace_version ON product_traceability(trace_id, version DESC)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_tx_status ON product_traceability(tx_status)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_trace_deleted ON product_traceability(trace_id, is_deleted)
        """)

    def calculate_hash(self, payload: dict, salt: str) -> str:
        """詳細データ(payload)とsaltから、JSON正規化ルールを適用してSHA-256ハッシュ値を算出する"""
        normalized_payload = json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":")
        )
        hash_input = json.dumps(
            {
                "payload": normalized_payload,
                "salt": salt
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(hash_input).hexdigest()

    def save_record(self, trace_id, payload, created_by=None):
        """新規トレーサビリティデータを登録する (CREATE)。tx_status='PENDING' で保存し、ハッシュとSaltを返す。"""
        import secrets
        import uuid
        salt = secrets.token_hex(32)
        version = 1
        record_id = str(uuid.uuid4())
        
        # payload は dict または JSON 文字列
        if isinstance(payload, str):
            payload_dict = json.loads(payload)
            payload_json = payload
        else:
            payload_dict = payload
            payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            
        self.conn.execute("""
            INSERT INTO product_traceability (id, trace_id, version, payload, salt, tx_status, created_by)
            VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
        """, (record_id, trace_id, version, payload_json, salt, created_by))
        
        h = self.calculate_hash(payload_dict, salt)
        print(f"[INFO] Off-chain record saved: trace_id={trace_id} version={version} status=PENDING")
        return h, salt

    def save_legacy_record(self, record_id, lot_number, process_name, details):
        """レガシーテーブル(manufacturing_details)へ詳細データを保存しSHA-256ハッシュを返す"""
        details_str = json.dumps(details, sort_keys=True) if isinstance(details, dict) else str(details)
        self.conn.execute("""
            INSERT OR REPLACE INTO manufacturing_details (record_id, lot_number, process_name, details)
            VALUES (?, ?, ?, ?)
        """, (record_id, lot_number, process_name, details_str))
        return self.calculate_record_hash(record_id, lot_number, process_name, details_str)

    def update_record(self, trace_id, payload, updated_by=None, reason=None):
        """既存データを修正する (UPDATE)。新しい version を PENDING で INSERT する。"""
        import secrets
        import uuid

        # Soft Delete 済みチェック（get_latest_record が None を返す前に判定）
        is_deleted_check = self.conn.execute("""
            SELECT COUNT(*) FROM product_traceability
            WHERE trace_id = ? AND tx_status = 'COMMITTED' AND is_deleted = TRUE
        """, (trace_id,)).fetchone()[0]
        if is_deleted_check > 0:
            raise ValueError("already_deleted")

        # 最新の COMMITTED レコードを取得
        latest = self.get_latest_record(trace_id)
        if not latest:
            exists = self.conn.execute(
                "SELECT COUNT(*) FROM product_traceability WHERE trace_id = ?",
                (trace_id,),
            ).fetchone()[0]
            if exists == 0:
                raise ValueError("trace_not_found")
            raise ValueError("pending_transaction_exists")

        # PENDING レコード存在チェック
        pending_check = self.conn.execute("""
            SELECT COUNT(*) FROM product_traceability
            WHERE trace_id = ? AND tx_status = 'PENDING'
        """, (trace_id,)).fetchone()[0]
        if pending_check > 0:
            raise ValueError("pending_transaction_exists")
            
        latest_version = latest["version"]
        version = latest_version + 1
        salt = secrets.token_hex(32)
        record_id = str(uuid.uuid4())
        
        if isinstance(payload, str):
            payload_dict = json.loads(payload)
            payload_json = payload
        else:
            payload_dict = payload
            payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            
        self.conn.execute("""
            INSERT INTO product_traceability (id, trace_id, version, payload, salt, tx_status, created_by)
            VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
        """, (record_id, trace_id, version, payload_json, salt, updated_by))
        
        h = self.calculate_hash(payload_dict, salt)
        print(f"[INFO] Off-chain record updated: trace_id={trace_id} version={version} status=PENDING")
        return h, salt

    def validate_soft_delete(self, trace_id):
        """Soft Delete 前バリデーションを行い、対象の最新 version を返す。"""
        # 1. 存在確認（COMMITTED レコードがあるか）
        committed_count = self.conn.execute("""
            SELECT COUNT(*) FROM product_traceability
            WHERE trace_id = ? AND tx_status = 'COMMITTED'
        """, (trace_id,)).fetchone()[0]
        if committed_count == 0:
            raise ValueError("trace_not_found")
            
        # 4. すでに Soft Delete 済みでないこと
        deleted_count = self.conn.execute("""
            SELECT COUNT(*) FROM product_traceability
            WHERE trace_id = ? AND tx_status = 'COMMITTED' AND is_deleted = TRUE
        """, (trace_id,)).fetchone()[0]
        if deleted_count > 0:
            raise ValueError("already_deleted")
            
        # 5. PENDING レコードが存在しないこと
        pending_count = self.conn.execute("""
            SELECT COUNT(*) FROM product_traceability
            WHERE trace_id = ? AND tx_status = 'PENDING'
        """, (trace_id,)).fetchone()[0]
        if pending_count > 0:
            raise ValueError("pending_transaction_exists")
            
        # 最新の version を取得
        latest_version = self.conn.execute("""
            SELECT MAX(version) FROM product_traceability
            WHERE trace_id = ? AND tx_status = 'COMMITTED'
        """, (trace_id,)).fetchone()[0]
        return latest_version

    def hard_delete(self, trace_id, executed_by=None, reason=None, anchored_hashes=None, log_path="data/hard_delete.log"):
        """指定された trace_id に紐づく全 version のオフチェーンデータを物理削除し、ログに記録する (Hard Delete)。"""
        # 1. 存在確認
        exists = self.conn.execute("""
            SELECT COUNT(*) FROM product_traceability WHERE trace_id = ?
        """, (trace_id,)).fetchone()[0]
        if exists == 0:
            raise ValueError("trace_not_found")
            
        # 3. 削除対象 version 数
        deleted_versions = self.conn.execute("""
            SELECT COUNT(*) FROM product_traceability WHERE trace_id = ?
        """, (trace_id,)).fetchone()[0]
        
        # 5. audit_log_id を生成
        import uuid
        audit_log_id = f"hd-{uuid.uuid4()}"
        
        # 6. Hard Delete ログの記録
        from datetime import datetime, timezone
        os.makedirs(os.path.dirname(log_path) if os.path.dirname(log_path) else ".", exist_ok=True)

        log_entry = {
            "audit_log_id": audit_log_id,
            "executed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "executed_by": executed_by,
            "trace_id": trace_id,
            "deleted_versions": deleted_versions,
            "anchored_hashes": anchored_hashes or [],
            "reason": reason
        }
        
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
            
        # 7. トランザクション内で削除
        self.conn.execute("BEGIN TRANSACTION")
        try:
            self.conn.execute("""
                DELETE FROM product_traceability
                WHERE trace_id = ?
            """, (trace_id,))
            self.conn.execute("COMMIT")
        except Exception as e:
            self.conn.execute("ROLLBACK")
            raise e
            
        return audit_log_id, deleted_versions

    def get_latest_record(self, trace_id):
        """最新の COMMITTED でかつ削除されていないレコードを取得する"""
        res = self.conn.execute("""
            SELECT id, trace_id, version, payload, salt, is_deleted, tx_status, created_by, created_at, updated_at
            FROM product_traceability p
            WHERE p.trace_id = ?
              AND p.tx_status = 'COMMITTED'
              AND p.is_deleted = FALSE
              AND NOT EXISTS (
                  SELECT 1
                  FROM product_traceability d
                  WHERE d.trace_id = p.trace_id
                    AND d.tx_status = 'COMMITTED'
                    AND d.is_deleted = TRUE
              )
            ORDER BY p.version DESC
            LIMIT 1
        """, (trace_id,)).fetchone()
        if not res:
            return None
        
        try:
            payload_data = json.loads(res[3])
        except Exception:
            payload_data = res[3]
            
        return {
            "id": res[0],
            "trace_id": res[1],
            "version": res[2],
            "payload": payload_data,
            "salt": res[4],
            "is_deleted": res[5],
            "tx_status": res[6],
            "created_by": res[7],
            "created_at": res[8],
            "updated_at": res[9]
        }

    def get_record(self, record_id):
        """指定されたrecord_idのレガシーオフチェーンデータを取得する"""
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

    def calculate_record_hash(self, record_id, lot_number, process_name, details):
        """レガシーデータレコードに対するSHA-256ハッシュを一貫した方法で計算する"""
        details_str = json.dumps(details, sort_keys=True) if isinstance(details, dict) else str(details)
        content = {
            "record_id": record_id,
            "lot_number": lot_number,
            "process_name": process_name,
            "details": details_str
        }
        content_bytes = json.dumps(content, sort_keys=True).encode()
        return hashlib.sha256(content_bytes).hexdigest()

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
    if payload.get("type") in ("OFFCHAIN_ANCHOR", "OFFCHAIN_UPDATE", "OFFCHAIN_SOFT_DELETE"):
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
        self.offchain_store = None
        if self.role == "Leader":
            threading.Thread(target=self._batch_watcher, daemon=True).start()
        # TTL監視スレッドの開始
        threading.Thread(target=self._pending_ttl_watcher, daemon=True).start()

    def set_offchain_store(self, store):
        """オフチェーンストアをノードに関連付ける"""
        self.offchain_store = store

    def _pending_ttl_watcher(self):
        """PENDINGレコードのTTL超過を監視するスレッド"""
        while True:
            time.sleep(10)
            if not self.offchain_store:
                continue
                
            try:
                ttl_seconds = int(os.getenv("PBFT_PENDING_TTL_SECONDS", "30"))
                from datetime import datetime, timedelta, timezone
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=ttl_seconds)
                
                # タイムアウトしたレコードを特定して警告ログを出力
                timeouts = self.offchain_store.conn.execute("""
                    SELECT trace_id, version FROM product_traceability
                    WHERE tx_status = 'PENDING'
                      AND created_at < ?
                """, (cutoff,)).fetchall()
                
                for trace_id, version in timeouts:
                    print(f"[WARN] PBFT consensus timeout: trace_id={trace_id}, version={version}")
                    
                # 状態を FAILED に更新
                self.offchain_store.conn.execute("""
                    UPDATE product_traceability
                    SET tx_status = 'FAILED',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE tx_status = 'PENDING'
                      AND created_at < ?
                """, (cutoff,))
                
            except Exception as e:
                print(f"[ERROR] Error in PENDING TTL watcher: {e}")

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
                
                # オフチェーンデータのステータス更新 (フック)
                if hasattr(self, "offchain_store") and self.offchain_store:
                    self._finalize_offchain_status(block)

    def _finalize_offchain_status(self, block):
        """確定したブロック内のトランザクションに基づいてオフチェーンデータを COMMITTED または論理削除に更新する"""
        txs = block.data
        if not isinstance(txs, list):
            txs = [txs]
            
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            tx_type = tx.get("type")
            tx_data = tx.get("data", {})
            
            if tx_type in ("OFFCHAIN_ANCHOR", "OFFCHAIN_UPDATE"):
                trace_id = tx_data.get("trace_id")
                version = tx_data.get("version")
                if trace_id and version:
                    # 冪等な更新 (tx_status = 'PENDING' のみ対象)
                    res = self.offchain_store.conn.execute("""
                        UPDATE product_traceability
                        SET tx_status = 'COMMITTED',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE trace_id = ?
                          AND version = ?
                          AND tx_status = 'PENDING'
                    """, (trace_id, version))
                    
                    if res.rowcount == 0:
                        # 冪等性の検証、存在確認
                        check = self.offchain_store.conn.execute("""
                            SELECT tx_status FROM product_traceability
                            WHERE trace_id = ? AND version = ?
                        """, (trace_id, version)).fetchone()
                        if check:
                            status = check[0]
                            if status == "COMMITTED":
                                print(f"[WARN] COMMITTED update skipped: already committed or missing trace_id={trace_id} version={version}")
                            else:
                                print(f"[ERROR] COMMITTED update failed: off-chain record in status {status} trace_id={trace_id} version={version}")
                        else:
                            print(f"[ERROR] COMMITTED update failed: off-chain record missing trace_id={trace_id} version={version}")
                    else:
                        print(f"[INFO] PBFT committed: trace_id={trace_id} version={version}")
                        
            elif tx_type == "OFFCHAIN_SOFT_DELETE":
                trace_id = tx_data.get("trace_id")
                if trace_id:
                    res = self.offchain_store.conn.execute("""
                        UPDATE product_traceability
                        SET is_deleted = TRUE,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE trace_id = ?
                          AND tx_status = 'COMMITTED'
                          AND is_deleted = FALSE
                    """, (trace_id,))
                    print(f"[INFO] PBFT soft deleted: trace_id={trace_id}, rowcount={res.rowcount}")

    def _iter_onchain_transactions(self):
        """チェーン内の全トランザクションを (tx_type, tx_data) で yield する"""
        for block in self.chain.chain[1:]:
            if isinstance(block.data, list):
                for tx in block.data:
                    if isinstance(tx, dict):
                        yield tx.get("type"), tx.get("data", {})
            elif isinstance(block.data, dict):
                tx_data = block.data
                tx_type = block.process_name if block.process_name in (
                    "OFFCHAIN_ANCHOR", "OFFCHAIN_UPDATE", "OFFCHAIN_SOFT_DELETE"
                ) else tx_data.get("type")
                yield tx_type, tx_data

    def audit_trace_data(self, trace_id, offchain_store):
        """新仕様データ(product_traceability)に対する監査を実行する。"""
        onchain_anchors = {}
        onchain_soft_deletes = []

        for tx_type, tx_data in self._iter_onchain_transactions():
            if not isinstance(tx_data, dict) or tx_data.get("trace_id") != trace_id:
                continue
            if tx_type in ("OFFCHAIN_ANCHOR", "OFFCHAIN_UPDATE"):
                v = tx_data.get("version")
                h = tx_data.get("hash")
                if v is not None:
                    onchain_anchors[v] = h
            elif tx_type == "OFFCHAIN_SOFT_DELETE":
                onchain_soft_deletes.append(tx_data)

        # オフチェーン DB のデータを取得
        offchain_records = offchain_store.conn.execute("""
            SELECT version, payload, salt, is_deleted, tx_status FROM product_traceability
            WHERE trace_id = ?
        """, (trace_id,)).fetchall()

        # 1. Hard Delete 監査の判定
        if len(offchain_records) == 0:
            if len(onchain_anchors) > 0:
                print(f"     [{self.node_id}] 【監査成功】レコード {trace_id} は物理削除(Hard Deleted)されています。")
                return {
                    "valid": True,
                    "status": "hard_deleted",
                    "trace_id": trace_id,
                    "note": "Off-chain data has been permanently erased."
                }
            else:
                print(f"     [{self.node_id}] 【監査エラー】レコード {trace_id} が見つかりません。")
                return {
                    "valid": False,
                    "status": "not_found",
                    "reason": "trace_not_found"
                }

        # 2. Soft Delete 監査の判定
        committed_offchain = [r for r in offchain_records if r[4] == "COMMITTED"]
        has_soft_delete_tx = len(onchain_soft_deletes) > 0
        all_deleted_offchain = len(committed_offchain) > 0 and all(r[3] is True for r in committed_offchain)
        any_deleted_offchain = any(r[3] is True for r in committed_offchain)

        # 不整合の検証
        is_mismatch = False
        if has_soft_delete_tx != all_deleted_offchain:
            is_mismatch = True
        elif any_deleted_offchain != all_deleted_offchain:
            is_mismatch = True # 同一 trace_id 内で is_deleted が揃っていない
            
        if is_mismatch:
            print(f"     [{self.node_id}] 【監査エラー】レコード {trace_id} の論理削除(Soft Delete)状態に不整合が検出されました。")
            return {
                "valid": False,
                "status": "soft_delete_mismatch",
                "reason": "soft_delete_mismatch"
            }

        if has_soft_delete_tx:
            latest_delete = onchain_soft_deletes[-1]
            print(f"     [{self.node_id}] 【監査成功】レコード {trace_id} は論理削除(Soft Deleted)されています。")
            return {
                "valid": True,
                "status": "soft_deleted",
                "trace_id": trace_id,
                "target_version": latest_delete.get("target_version"),
                "deleted_by": latest_delete.get("deleted_by"),
                "reason": latest_delete.get("reason")
            }

        # 3. 通常レコード(active)のハッシュ検証
        for r_version, r_payload, r_salt, r_is_deleted, r_tx_status in committed_offchain:
            if r_version not in onchain_anchors:
                # オフチェーンにのみ存在する
                print(f"     [{self.node_id}] 【監査エラー】レコード {trace_id} (version {r_version}) がオンチェーンに見つかりません。")
                return {
                    "valid": False,
                    "status": "tampered",
                    "reason": "hash_mismatch"
                }
            
            try:
                payload_dict = json.loads(r_payload) if isinstance(r_payload, str) else r_payload
            except Exception:
                payload_dict = r_payload

            recalculated = offchain_store.calculate_hash(payload_dict, r_salt)
            anchored = onchain_anchors[r_version]

            if recalculated != anchored:
                print(f"     [{self.node_id}] 【監査警告】レコード {trace_id} (version {r_version}) のハッシュ不一致を検出しました！")
                return {
                    "valid": False,
                    "status": "tampered",
                    "reason": "hash_mismatch"
                }

        # 逆方向 (オンチェーンにある version がオフチェーンにあるか)
        for v in onchain_anchors:
            if not any(r[0] == v for r in committed_offchain):
                print(f"     [{self.node_id}] 【監査エラー】オンチェーンレコード {trace_id} (version {v}) がオフチェーンに見つかりません。")
                return {
                    "valid": False,
                    "status": "tampered",
                    "reason": "hash_mismatch"
                }

        latest_version = max([r[0] for r in committed_offchain]) if len(committed_offchain) > 0 else 1
        print(f"     [{self.node_id}] 【監査成功】レコード {trace_id} の整合性を確認しました。")
        return {
            "valid": True,
            "status": "active",
            "trace_id": trace_id,
            "version": latest_version
        }

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
        if payload.get("type") in ("OFFCHAIN_ANCHOR", "OFFCHAIN_UPDATE", "OFFCHAIN_SOFT_DELETE"):
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
    offchain_hash = offchain_store.save_legacy_record(
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

