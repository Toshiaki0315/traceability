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
# 実行サンプル
# ==========================================
if __name__ == "__main__":
    # 参加者の鍵ペア生成
    print("[INFO] 各参加者（納入業者、工場、倉庫）の鍵ペアを生成しています...")
    supplier_pub, supplier_priv = generate_keypair()
    factory_pub, factory_priv = generate_keypair()
    warehouse_pub, warehouse_priv = generate_keypair()
    print("[INFO] 鍵ペア生成完了。\n")

    # 1. トレーサビリティシステムの初期化
    supply_chain = TraceabilityChain()

    # 2. 各工程のデータを順次記録していく
    print("[INFO] 工程データをブロックチェーンに記録します...\n")
    
    # 工程1: 原材料受け入れ（納入業者が署名）
    data1 = {"lot_number": "RAW-A001", "supplier": "A社", "weight_kg": 500}
    sig1 = sign_data(data1, supplier_priv)
    supply_chain.add_process_data(process_name="原材料受け入れ", data=data1, public_key=supplier_pub, signature=sig1)

    # 工程2: 加熱・加工処理（工場が署名）
    data2 = {"sensor_type": "NCIR2", "surface_temp_celsius": 65.2, "operator_id": "OP-773"}
    sig2 = sign_data(data2, factory_priv)
    supply_chain.add_process_data(process_name="加熱処理", data=data2, public_key=factory_pub, signature=sig2)

    # 工程3: 出荷・梱包（倉庫が署名）
    data3 = {"destination": "Yokohama Warehouse", "shipping_id": "SHIP-9992"}
    sig3 = sign_data(data3, warehouse_priv)
    supply_chain.add_process_data(process_name="出荷", data=data3, public_key=warehouse_pub, signature=sig3)

    # 3. チェーンの全容を表示
    supply_chain.display_chain()

    # 4. データ検証（正しい状態）
    print(f"[検証] 現在のデータは正当ですか？ -> {supply_chain.is_chain_valid()}\n")

    # 5. 改ざんのシミュレーション（意図的に過去のデータを書き換える）
    print("[INFO] 過去のデータ（工程2の温度データ）が改ざんされました...")
    supply_chain.chain[2].data["surface_temp_celsius"] = 55.0  # 規定温度を満たしていなかったことにする
    
    # 改ざん後の検証
    print(f"[検証] 記録後のデータ改ざんを検知できましたか？ -> {not supply_chain.is_chain_valid()}")
