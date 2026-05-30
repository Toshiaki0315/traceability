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

    def isatty(self):
        return self.terminal.isatty()

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
        if payload.get("type") in ("OFFCHAIN_ANCHOR", "OFFCHAIN_UPDATE", "OFFCHAIN_SOFT_DELETE"):
            return True
        data = payload.get("data", {})
        weight = data.get("weight_kg", 0)
        if weight < 100:
            raise ValueError(f"原料重量({weight}kg)が少なすぎます。最低100kg必要です。")
        return True

    for n in nodes:
        n.add_business_rule(weight_check_rule)
        n.set_offchain_store(offchain_store)

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
    new_records = []
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
            
            # 新仕様の記録も取得
            res_new = offchain_store.conn.execute(
                "SELECT trace_id, version, payload, salt, is_deleted, tx_status, created_at FROM product_traceability ORDER BY created_at DESC, version DESC"
            ).fetchall()
            for row in res_new:
                try:
                    payload_data = json.loads(row[2]) if isinstance(row[2], str) else row[2]
                except Exception:
                    payload_data = row[2]
                new_records.append({
                    "trace_id": row[0],
                    "version": row[1],
                    "payload": payload_data,
                    "salt": row[3],
                    "is_deleted": row[4],
                    "tx_status": row[5],
                    "created_at": str(row[6])
                })
        except Exception as e:
            print(f"[API Error] オフチェーンデータ取得失敗: {e}")
            
    response_data = {
        "nodes": node_info,
        "blockchain": blockchain,
        "offchain": offchain_records,
        "offchain_new": new_records,
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
    trace_id = data.get("record_id") # 既存UI互換のため record_id を trace_id として扱う
    lot_number = data.get("lot_number")
    process_name = data.get("process_name")
    details = data.get("details", {})
    operator = details.get("operator", "system")
    
    if not trace_id or not lot_number or not process_name:
        return jsonify({"success": False, "error": "必須フィールドが不足しています。"}), 400
        
    print(f"\n[API] 詳細ログを新テーブル(product_traceability)へ保存中: {trace_id}")
    try:
        # 新仕様 save_record
        offchain_hash, salt = offchain_store.save_record(
            trace_id=trace_id,
            payload=details,
            created_by=operator
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    
    anchor_data = {
        "trace_id": trace_id,
        "version": 1,
        "hash": offchain_hash,
        "lot_number": lot_number,
        "created_by": operator
    }
    
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
        
    return jsonify({"success": True, "hash": offchain_hash, "version": 1})

@app.route('/api/update', methods=['POST'])
def update():
    data = request.get_json() or {}
    trace_id = data.get("trace_id")
    details = data.get("details", {})
    operator = data.get("operator", "system")
    reason = data.get("reason", "")
    
    if not trace_id or not reason:
        return jsonify({"success": False, "error": "trace_id と reason は必須です。"}), 400
        
    # 最新版を取得して version と lot_number を得る
    latest = offchain_store.get_latest_record(trace_id)
    if not latest:
        # Soft Delete済みか判定
        is_deleted = offchain_store.conn.execute("""
            SELECT COUNT(*) FROM product_traceability
            WHERE trace_id = ? AND tx_status = 'COMMITTED' AND is_deleted = TRUE
        """, (trace_id,)).fetchone()[0]
        if is_deleted > 0:
            return jsonify({"success": False, "error": "already_deleted"}), 409
        return jsonify({"success": False, "error": "trace_not_found"}), 404
        
    latest_version = latest["version"]
    
    # オンチェーンから lot_number を引き継ぐ
    lot_number = "unknown"
    leader = next((n for n in nodes if n.role == "Leader"), nodes[0])
    for block in leader.chain.chain[1:]:
        txs = block.data
        if not isinstance(txs, list):
            txs = [txs]
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            tx_data = tx.get("data", {})
            if tx_data.get("trace_id") == trace_id and tx_data.get("lot_number"):
                lot_number = tx_data.get("lot_number")
                break

    print(f"\n[API] 詳細ログの修正版を保存中: {trace_id} (version {latest_version + 1})")
    try:
        offchain_hash, salt = offchain_store.update_record(
            trace_id=trace_id,
            payload=details,
            updated_by=operator,
            reason=reason
        )
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 409
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
        
    version = latest_version + 1
    update_data = {
        "trace_id": trace_id,
        "version": version,
        "previous_version": latest_version,
        "hash": offchain_hash,
        "lot_number": lot_number,
        "updated_by": operator,
        "reason": reason
    }
    
    update_payload = {
        "data": update_data,
        "signature": sign_data(update_data, leader.private_key),
        "public_key": leader.public_key,
        "type": "OFFCHAIN_UPDATE"
    }
    
    for n in nodes:
        n.receive_message("NEW_TRANSACTION", update_payload, leader.node_id)
        
    return jsonify({"success": True, "hash": offchain_hash, "version": version})

@app.route('/api/soft-delete', methods=['POST'])
def soft_delete():
    data = request.get_json() or {}
    trace_id = data.get("trace_id")
    operator = data.get("operator", "system")
    reason = data.get("reason", "")
    
    if not trace_id or not reason:
        return jsonify({"success": False, "error": "trace_id と reason は必須です。"}), 400
        
    try:
        latest_version = offchain_store.validate_soft_delete(trace_id)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 409
        
    delete_data = {
        "trace_id": trace_id,
        "target_version": latest_version,
        "deleted_by": operator,
        "reason": reason
    }
    
    leader = next((n for n in nodes if n.role == "Leader"), nodes[0])
    delete_payload = {
        "data": delete_data,
        "signature": sign_data(delete_data, leader.private_key),
        "public_key": leader.public_key,
        "type": "OFFCHAIN_SOFT_DELETE"
    }
    
    print(f"\n[API] 論理削除(Soft Delete)要求をブロードキャストします: {trace_id}")
    for n in nodes:
        n.receive_message("NEW_TRANSACTION", delete_payload, leader.node_id)
        
    return jsonify({"success": True, "status": "soft_delete_pending"})

@app.route('/api/hard-delete', methods=['POST'])
def hard_delete():
    data = request.get_json() or {}
    trace_id = data.get("trace_id")
    operator = data.get("operator", "admin")
    reason = data.get("reason", "")
    admin_secret = data.get("admin_secret", "")
    
    expected_secret = os.getenv("ADMIN_SECRET", "change_me_to_strong_random_value")
    if admin_secret != expected_secret:
        return jsonify({"success": False, "error": "forbidden"}), 403
        
    if not trace_id or not reason:
        return jsonify({"success": False, "error": "trace_id と reason は必須です。"}), 400
        
    # オンチェーンの関連ハッシュ収集
    anchored_hashes = []
    leader = next((n for n in nodes if n.role == "Leader"), nodes[0])
    for block in leader.chain.chain[1:]:
        txs = block.data
        if not isinstance(txs, list):
            txs = [txs]
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            tx_data = tx.get("data", {})
            if tx_data.get("trace_id") == trace_id:
                h = tx_data.get("hash")
                if h:
                    anchored_hashes.append(h)
                    
    print(f"\n[API] 物理削除(Hard Delete)を実行します: {trace_id}")
    try:
        audit_log_id, deleted_versions = offchain_store.hard_delete(
            trace_id=trace_id,
            executed_by=operator,
            reason=reason,
            anchored_hashes=anchored_hashes,
            log_path="data/hard_delete.log"
        )
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
        
    return jsonify({
        "success": True,
        "audit_log_id": audit_log_id,
        "deleted_versions": deleted_versions
    })

@app.route('/api/audit', methods=['POST'])
def audit():
    data = request.get_json() or {}
    record_id = data.get("record_id")
    if not record_id:
        return jsonify({"success": False, "error": "record_idは必須です。"}), 400
        
    leader = next((n for n in nodes if n.role == "Leader"), nodes[0])
    
    # 新仕様データかレガシーデータかを判定
    has_new_data = offchain_store.conn.execute("""
        SELECT COUNT(*) FROM product_traceability WHERE trace_id = ?
    """, (record_id,)).fetchone()[0]
    
    if has_new_data == 0:
        for block in leader.chain.chain[1:]:
            txs = block.data
            if not isinstance(txs, list):
                txs = [txs]
            for tx in txs:
                if not isinstance(tx, dict):
                    continue
                if tx.get("data", {}).get("trace_id") == record_id:
                    has_new_data = 1
                    break
            if has_new_data > 0:
                break
                
    if has_new_data > 0:
        print(f"\n[API] 新仕様データ {record_id} の整合性監査を実行します。")
        audit_res = leader.audit_trace_data(record_id, offchain_store)
        
        status = audit_res.get("status")
        offchain_hash = ""
        onchain_hash = ""
        
        if status == "active":
            latest = offchain_store.get_latest_record(record_id)
            if latest:
                offchain_hash = offchain_store.calculate_hash(latest["payload"], latest["salt"])
                for block in leader.chain.chain[1:]:
                    txs = block.data
                    if not isinstance(txs, list):
                        txs = [txs]
                    for tx in txs:
                        if not isinstance(tx, dict):
                            continue
                        tx_data = tx.get("data", {})
                        if tx_data.get("trace_id") == record_id and tx_data.get("version") == latest["version"]:
                            onchain_hash = tx_data.get("hash")
                            break
                            
        return jsonify({
            "valid": audit_res.get("valid"),
            "status": status,
            "offchain_hash": offchain_hash,
            "onchain_hash": onchain_hash,
            "details": audit_res
        })
    else:
        print(f"\n[API] レガシーデータ {record_id} の整合性監査を実行します。")
        is_valid = leader.audit_offchain_data(record_id, offchain_store)
        
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
            "status": "legacy",
            "offchain_hash": recalculated_hash,
            "onchain_hash": anchored_hash
        })

@app.route('/api/tamper', methods=['POST'])
def tamper():
    data = request.get_json() or {}
    record_id = data.get("record_id")
    if not record_id:
        return jsonify({"success": False, "error": "record_idは必須です。"}), 400
        
    has_new = offchain_store.conn.execute("""
        SELECT COUNT(*) FROM product_traceability WHERE trace_id = ?
    """, (record_id,)).fetchone()[0]
    
    if has_new > 0:
        latest = offchain_store.conn.execute("""
            SELECT version, payload FROM product_traceability
            WHERE trace_id = ?
            ORDER BY version DESC LIMIT 1
        """, (record_id,)).fetchone()
        
        if latest:
            version = latest[0]
            tampered_payload = '{"operator": "悪意ある改ざん者", "target_temperature_c": 50.0, "actual_temperature_log_c": [50.0, 50.0], "remarks": "異常データを隠蔽"}'
            offchain_store.conn.execute("""
                UPDATE product_traceability
                SET payload = ?
                WHERE trace_id = ? AND version = ?
            """, (tampered_payload, record_id, version))
            print(f"\n[API/Attack] レコード {record_id} (version {version}) のオフチェーン詳細ログを改ざんしました。")
    else:
        tampered_details = '{"operator": "悪意ある改ざん者", "equipment_id": "HEATER-X9", "remarks": "異常データを隠蔽するため加熱ログを差し替え", "actual_temperature_log_c": [50.0, 50.0, 50.0]}'
        offchain_store.conn.execute(
            "UPDATE manufacturing_details SET details = ? WHERE record_id = ?",
            (tampered_details, record_id)
        )
        print(f"\n[API/Attack] レガシーレコード {record_id} のオフチェーン詳細ログを改ざんしました。")
        
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
