import os
import sys
import json
from flask import Flask, render_template, jsonify, request, Response
from traceability import Node, OffChainStore, sign_data

app = Flask(__name__)

# ------------------------------------------
# 標準出力キャプチャ用ヘルパー
# ------------------------------------------
class DualStdout:
    def __init__(self):
        self.terminal = sys.__stdout__
        self.logs = []

    def write(self, message):
        self.terminal.write(message)
        # 改行のみなどの無駄な文字を除外して蓄積
        if message.strip():
            self.logs.append(message.strip())
            # ログメモリサイズ制限
            if len(self.logs) > 200:
                self.logs.pop(0)

    def flush(self):
        self.terminal.flush()

# stdout をリダイレクトして Web 画面のコンソールログに流せるようにする
dual_stdout = DualStdout()
sys.stdout = dual_stdout

# ------------------------------------------
# グローバルデモ状態
# ------------------------------------------
nodes = []
offchain_store = None

def init_demo_state():
    global nodes, offchain_store
    
    # 既存DBがあればクローズして削除（常に初期状態から開始）
    if offchain_store:
        try:
            offchain_store.close()
        except Exception:
            pass

    db_path = "data/web_offchain.db"
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass

    offchain_store = OffChainStore(db_path=db_path)

    # 3ノード構成の初期化
    node_supplier = Node("納入業者", "Replica")
    node_factory = Node("加工工場", "Leader")
    node_warehouse = Node("倉庫", "Replica")
    
    nodes = [node_supplier, node_factory, node_warehouse]
    
    # ピアの相互接続
    for n1 in nodes:
        for n2 in nodes:
            if n1 != n2:
                n1.add_peer(n2)

    # ビジネスルールの定義（100kg以上のチェック）
    def weight_check_rule(payload):
        if payload.get("type") == "OFFCHAIN_ANCHOR":
            return True
        data = payload.get("data", {})
        weight = data.get("weight_kg", 0)
        if weight < 100:
            raise ValueError(f"原料重量({weight}kg)が少なすぎます。最低100kg必要です。")
        return True

    for n in nodes:
        n.add_business_rule(weight_check_rule)

# デモ状態の初回初期化
init_demo_state()

# ------------------------------------------
# HTTP API エンドポイント
# ------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/state', methods=['GET'])
def get_state():
    # ノード情報の収集
    node_info = []
    for n in nodes:
        node_info.append({
            "node_id": n.node_id,
            "role": n.role,
            "chain_height": len(n.chain.chain),
            "pending_tx_count": len(n.pending_transactions),
            "latest_hash": n.chain.get_latest_block().hash
        })
        
    # オンチェーン（加工工場/Leaderのチェーン情報）の収集
    leader = next((n for n in nodes if n.role == "Leader"), nodes[0])
    blockchain = []
    for block in leader.chain.chain:
        blockchain.append({
            "index": block.index,
            "timestamp": block.timestamp,
            "process_name": block.process_name,
            "data": block.data,
            "previous_hash": block.previous_hash,
            "hash": block.hash
        })
        
    # オフチェーンの記録をDuckDBから取得
    offchain_records = []
    if offchain_store:
        try:
            res = offchain_store.conn.execute(
                "SELECT record_id, lot_number, process_name, details, timestamp FROM manufacturing_details ORDER BY timestamp DESC"
            ).fetchall()
            for row in res:
                try:
                    details_data = json.loads(row[3])
                except Exception:
                    details_data = row[3]
                offchain_records.append({
                    "record_id": row[0],
                    "lot_number": row[1],
                    "process_name": row[2],
                    "details": details_data,
                    "timestamp": str(row[4])
                })
        except Exception as e:
            print(f"[API Error] オフチェーンデータ取得失敗: {e}")
            
    response_data = {
        "nodes": node_info,
        "blockchain": blockchain,
        "offchain": offchain_records,
        "logs": list(dual_stdout.logs)
    }
    json_string = json.dumps(response_data, default=str, ensure_ascii=False)
    return Response(json_string, mimetype="application/json")

@app.route('/api/transaction', methods=['POST'])
def add_transaction():
    data = request.get_json() or {}
    supplier_name = data.get("supplier", "納入業者")
    lot_number = data.get("lot_number")
    weight_kg = data.get("weight_kg", 0)
    
    if not lot_number:
        return jsonify({"success": False, "error": "lot_numberは必須です。"}), 400
        
    supplier_node = next((n for n in nodes if n.node_id == supplier_name), nodes[0])
    tx_data = {
        "lot_number": lot_number,
        "supplier": supplier_name,
        "weight_kg": int(weight_kg)
    }
    
    # 秘密鍵による署名の作成
    signature = sign_data(tx_data, supplier_node.private_key)
    
    payload = {
        "data": tx_data,
        "signature": signature,
        "public_key": supplier_node.public_key
    }
    
    print(f"\n[API] 新規ロットトランザクションの受信: {lot_number} ({weight_kg}kg)")
    
    # 全ノードに通知（合意形成前にメモリプールに蓄積）
    for n in nodes:
        n.receive_message("NEW_TRANSACTION", payload, supplier_name)
        
    return jsonify({"success": True})

@app.route('/api/propose', methods=['POST'])
def propose():
    leader = next((n for n in nodes if n.role == "Leader"), None)
    if not leader:
        return jsonify({"success": False, "error": "Leaderノードが見つかりません。"}), 500
        
    print("\n[API] ブロック提案 (PBFT合意形成プロセス) を手動トリガーします。")
    block = leader.propose_block()
    if not block:
        return jsonify({"success": False, "error": "提案待ちの取引がありません。"}), 400
        
    return jsonify({"success": True, "block_hash": block.hash})

@app.route('/api/anchor', methods=['POST'])
def anchor():
    data = request.get_json() or {}
    record_id = data.get("record_id")
    lot_number = data.get("lot_number")
    process_name = data.get("process_name")
    details = data.get("details", {})
    
    if not record_id or not lot_number or not process_name:
        return jsonify({"success": False, "error": "必須フィールドが不足しています。"}), 400
        
    # 1. 詳細ログをオフチェーン (DuckDB) に保存してハッシュを計算
    print(f"\n[API] 詳細ログをオフチェーン(DuckDB)へ保存中: {record_id}")
    offchain_hash = offchain_store.save_record(
        record_id=record_id,
        lot_number=lot_number,
        process_name=process_name,
        details=details
    )
    
    # 2. ハッシュとIDをオンチェーンへ記録（アンカリング）するためのトランザクション作成
    anchor_data = {
        "record_id": record_id,
        "hash": offchain_hash,
        "lot_number": lot_number
    }
    
    # 加工工場(Leader)が署名してブロードキャスト
    leader = next((n for n in nodes if n.role == "Leader"), nodes[0])
    anchor_payload = {
        "data": anchor_data,
        "signature": sign_data(anchor_data, leader.private_key),
        "public_key": leader.public_key,
        "type": "OFFCHAIN_ANCHOR"
    }
    
    print(f"[API] アンカー取引を全ノードにブロードキャストします。ハッシュ: {offchain_hash[:16]}...")
    for n in nodes:
        n.receive_message("NEW_TRANSACTION", anchor_payload, leader.node_id)
        
    return jsonify({"success": True, "hash": offchain_hash})

@app.route('/api/audit', methods=['POST'])
def audit():
    data = request.get_json() or {}
    record_id = data.get("record_id")
    if not record_id:
        return jsonify({"success": False, "error": "record_idは必須です。"}), 400
        
    leader = next((n for n in nodes if n.role == "Leader"), nodes[0])
    print(f"\n[API] レコード {record_id} の整合性監査を実行します。")
    is_valid = leader.audit_offchain_data(record_id, offchain_store)
    
    # オンチェーン・オフチェーンそれぞれのハッシュを取得してUIに返す
    record = offchain_store.get_record(record_id)
    recalculated_hash = ""
    if record:
        recalculated_hash = offchain_store.calculate_record_hash(
            record["record_id"],
            record["lot_number"],
            record["process_name"],
            record["details"]
        )
        
    anchored_hash = ""
    for block in leader.chain.chain[1:]:
        if isinstance(block.data, list):
            for tx in block.data:
                if tx.get("type") == "OFFCHAIN_ANCHOR" and tx.get("data", {}).get("record_id") == record_id:
                    anchored_hash = tx.get("data", {}).get("hash")
                    break
        elif isinstance(block.data, dict):
            if block.process_name == "OFFCHAIN_ANCHOR" and block.data.get("record_id") == record_id:
                anchored_hash = block.data.get("hash")
        if anchored_hash:
            break
            
    return jsonify({
        "valid": is_valid,
        "offchain_hash": recalculated_hash,
        "onchain_hash": anchored_hash
    })

@app.route('/api/tamper', methods=['POST'])
def tamper():
    data = request.get_json() or {}
    record_id = data.get("record_id")
    if not record_id:
        return jsonify({"success": False, "error": "record_idは必須です。"}), 400
        
    # 直接SQLを発行し、値を書き換えて改ざん検知デモを再現
    tampered_details = '{"operator": "悪意ある改ざん者", "equipment_id": "HEATER-X9", "remarks": "異常データを隠蔽するため加熱ログを差し替え", "actual_temperature_log_c": [50.0, 50.0, 50.0]}'
    
    offchain_store.conn.execute(
        "UPDATE manufacturing_details SET details = ? WHERE record_id = ?",
        (tampered_details, record_id)
    )
    print(f"\n[API/Attack] レコード {record_id} のオフチェーン詳細ログを直接書き換えました（改ざん）。")
    return jsonify({"success": True})

@app.route('/api/reset', methods=['POST'])
def reset():
    init_demo_state()
    dual_stdout.logs.clear()
    print("\n[API] デモ環境のステートをリセットしました。")
    return jsonify({"success": True})

if __name__ == '__main__':
    # dataフォルダがなければ作成
    os.makedirs("data", exist_ok=True)
    # デバッグモード、ポート5000でサーバー起動
    app.run(debug=True, port=5000)
