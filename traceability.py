import hashlib
import json
import time
import rsa

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
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class TraceabilityChain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        """チェーンの起点となる最初のブロック（ジェネシスブロック）を生成"""
        # タイムスタンプは環境によるハッシュ値のブレを防ぐため整数（Unixタイム）を使用
        return Block(0, int(time.time()), "System Initialization", {"info": "Traceability Chain Started"}, "0")

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

# ==========================================
# ステップ2: P2Pネットワーク・ノードの構築
# ==========================================
class Node:
    def __init__(self, node_id, role):
        self.node_id = node_id
        self.role = role  # "Leader" または "Replica"
        # 各ノードは自身の鍵ペアと独立したチェーン（台帳）を持つ
        self.public_key, self.private_key = generate_keypair()
        self.chain = TraceabilityChain()
        self.peers = []

    def add_peer(self, node):
        """P2Pネットワークのピア（通信相手）を登録する"""
        if node not in self.peers:
            self.peers.append(node)

    def broadcast(self, msg_type, payload):
        """登録された全ピアに対してメッセージを送信（ブロードキャスト）する"""
        print(f"[{self.node_id}] ブロードキャスト送信: {msg_type}")
        for peer in self.peers:
            peer.receive_message(msg_type, payload, self.node_id)

    def receive_message(self, msg_type, payload, sender_id):
        """他ノードからメッセージを受信した際の処理"""
        print(f"  -> [{self.node_id}] メッセージ受信 from {sender_id}: {msg_type}")
        # ステップ3以降でトランザクション処理やPBFTの合意形成処理をここに追加します
        pass

# ==========================================
# 実行サンプル
# ==========================================
if __name__ == "__main__":
    print("[INFO] P2Pシミュレーション環境の構築を開始します...\n")

    # 1. 参加ノードの立ち上げ
    print("[INFO] 各参加者ノードを起動し、鍵ペアと台帳を初期化しています...")
    node_supplier = Node("納入業者", "Replica")
    node_factory = Node("加工工場", "Leader")
    node_warehouse = Node("倉庫", "Replica")
    print("[INFO] ノード起動完了。\n")

    # 2. P2Pネットワークの構築（相互にピアとして登録）
    nodes = [node_supplier, node_factory, node_warehouse]
    for n1 in nodes:
        for n2 in nodes:
            if n1 != n2:
                n1.add_peer(n2)
    print("[INFO] ネットワークの構築完了。各ノードが接続されました。\n")

    # 3. 通信テスト（ブロードキャストのシミュレーション）
    print("=== P2P通信テスト ===")
    
    # 例：納入業者がトランザクションデータを送信する
    test_data = {"lot_number": "RAW-A001", "supplier": "A社", "weight_kg": 500}
    signature = sign_data(test_data, node_supplier.private_key)
    
    payload = {
        "data": test_data,
        "signature": signature,
        "public_key": node_supplier.public_key
    }
    
    # 納入業者が全ノードにメッセージを送信
    node_supplier.broadcast("NEW_TRANSACTION", payload)
    
    print("\n[INFO] ステップ2（複数ノード環境構築）完了！")
