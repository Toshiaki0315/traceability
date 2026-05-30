"""
各ノードを独立プロセス・ポートで起動する REST API サーバー（ステップ10）

環境変数:
  NODE_ID      - ノードID（例: 納入業者）
  NODE_ROLE    - Leader または Replica
  PORT         - 待ち受けポート（デフォルト: 8000）
  PEER_URLS    - カンマ区切りのピアURL（例: http://127.0.0.1:5002,http://127.0.0.1:5003）
  OFFCHAIN_DB_PATH - 共有オフチェーンDBパス（デフォルト: data/offchain_store.db）

起動例:
  NODE_ID=納入業者 NODE_ROLE=Replica PORT=5001 \\
    PEER_URLS=http://127.0.0.1:5002,http://127.0.0.1:5003 \\
    uvicorn api:app --host 127.0.0.1 --port 5001
"""
import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

from traceability import (
    Node,
    OffChainStore,
    PBFT_ROUTE_TO_MSG,
    block_to_dict,
    decode_payload,
    default_weight_check_rule,
    dict_to_block,
    encode_payload,
    sign_data,
)


class TransactionRequest(BaseModel):
    transaction: Dict[str, Any]
    sender_id: Optional[str] = None
    relay: bool = Field(
        default=False,
        description="他ノードからの転送の場合は True（再ブロードキャストしない）",
    )


class TransactionBody(BaseModel):
    """クライアントが直接 transaction フィールドを送る形式にも対応"""
    data: Dict[str, Any]
    signature: str
    public_key: str
    type: Optional[str] = None


class PBFTMessage(BaseModel):
    payload: Dict[str, Any]
    sender_id: str


class AuditRequest(BaseModel):
    record_id: str


class CreateTraceRequest(BaseModel):
    trace_id: str
    lot_number: str
    payload: Dict[str, Any]
    created_by: Optional[str] = None


class UpdateTraceRequest(BaseModel):
    payload: Dict[str, Any]
    updated_by: Optional[str] = None
    reason: str


class SoftDeleteRequest(BaseModel):
    deleted_by: Optional[str] = None
    reason: str


class HardDeleteRequest(BaseModel):
    executed_by: str
    reason: str


class ProposeResponse(BaseModel):
    block_hash: Optional[str] = None
    status: str


class NodeInfoResponse(BaseModel):
    node_id: str
    role: str
    chain_height: int
    pending_tx_count: int
    latest_hash: str
    peer_urls: List[str]


def create_node_app(
    node: Node,
    offchain_store: Optional[OffChainStore] = None,
) -> FastAPI:
    """単一ノード用 FastAPI アプリケーションを生成する（テスト・本番共通）"""
    if offchain_store:
        node.set_offchain_store(offchain_store)
    app = FastAPI(title=f"Traceability Node API ({node.node_id})")

    @app.get("/")
    def root():
        return {
            "node_id": node.node_id,
            "role": node.role,
            "endpoints": [
                "GET /node",
                "GET /chain",
                "POST /transaction",
                "POST /propose",
                "POST /audit",
                "POST /pbft/{pre_prepare|prepare|commit}",
            ],
        }

    @app.get("/node", response_model=NodeInfoResponse)
    def get_node_info():
        latest = node.chain.get_latest_block()
        return NodeInfoResponse(
            node_id=node.node_id,
            role=node.role,
            chain_height=len(node.chain.chain),
            pending_tx_count=len(node.pending_transactions),
            latest_hash=latest.hash,
            peer_urls=node.peer_urls,
        )

    @app.get("/chain")
    def get_chain():
        return [block_to_dict(b) for b in node.chain.chain]

    @app.post("/transaction")
    def submit_transaction(req: TransactionRequest):
        """トランザクションを受信し、ローカルで検証後ピアへHTTPブロードキャストする"""
        raw = req.transaction
        payload = decode_payload(raw)
        sender = req.sender_id or node.node_id
        node.receive_message("NEW_TRANSACTION", payload, sender)
        if not req.relay:
            node.broadcast("NEW_TRANSACTION", payload)
        return {"status": "accepted", "pending_count": len(node.pending_transactions)}

    @app.post("/propose", response_model=ProposeResponse)
    def propose_block():
        """リーダーノードが未承認トランザクションをブロック化してPBFT合意を開始する"""
        if node.role != "Leader":
            raise HTTPException(status_code=403, detail="Only Leader nodes can propose blocks")
        try:
            block = node.propose_block()
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
        if block is None:
            return ProposeResponse(block_hash=None, status="no_pending_transactions")
        return ProposeResponse(block_hash=block.hash, status="proposed")

    @app.post("/audit")
    def audit_record(req: AuditRequest):
        """オフチェーンとオンチェーンのハッシュ整合性を監査する"""
        if offchain_store is None:
            raise HTTPException(status_code=503, detail="Off-chain store is not configured")
        is_valid = node.audit_offchain_data(req.record_id, offchain_store)
        return {"record_id": req.record_id, "integrity": is_valid}

    @app.post("/api/traceability")
    def create_traceability(req: CreateTraceRequest):
        if offchain_store is None:
            raise HTTPException(status_code=503, detail="Off-chain store is not configured")
        try:
            h, salt = offchain_store.save_record(req.trace_id, req.payload, req.created_by)
        except Exception as e:
            raise HTTPException(status_code=400, detail={"reason": "validation_error", "message": str(e)})

        # オンチェーン送信用トランザクション作成
        anchor_data = {
            "trace_id": req.trace_id,
            "version": 1,
            "hash": h,
            "lot_number": req.lot_number,
            "created_by": req.created_by or "system"
        }
        
        sig = sign_data(anchor_data, node.private_key)
        
        tx_payload = {
            "data": anchor_data,
            "signature": sig,
            "public_key": node.public_key,
            "type": "OFFCHAIN_ANCHOR"
        }
        
        node.receive_message("NEW_TRANSACTION", tx_payload, node.node_id)
        node.broadcast("NEW_TRANSACTION", tx_payload)
        
        return {
            "accepted": True,
            "trace_id": req.trace_id,
            "version": 1,
            "tx_status": "PENDING"
        }

    @app.put("/api/traceability/{trace_id}")
    def update_traceability(trace_id: str, req: UpdateTraceRequest):
        if offchain_store is None:
            raise HTTPException(status_code=503, detail="Off-chain store is not configured")
        if not req.reason:
            raise HTTPException(status_code=400, detail={"reason": "validation_error", "message": "reason is required"})
            
        # 事前に最新コミット版を取得して情報を得る
        latest = offchain_store.get_latest_record(trace_id)
        if not latest:
            is_deleted = offchain_store.conn.execute("""
                SELECT COUNT(*) FROM product_traceability
                WHERE trace_id = ? AND tx_status = 'COMMITTED' AND is_deleted = TRUE
            """, (trace_id,)).fetchone()[0]
            if is_deleted > 0:
                raise HTTPException(status_code=409, detail={"reason": "already_deleted"})
            else:
                raise HTTPException(status_code=404, detail={"reason": "trace_not_found"})
                
        latest_version = latest["version"]
        
        # オンチェーンから lot_number を引き継ぐ
        lot_number = "unknown"
        for block in node.chain.chain[1:]:
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

        try:
            h, salt = offchain_store.update_record(trace_id, req.payload, req.updated_by, req.reason)
        except ValueError as e:
            err_str = str(e)
            if err_str == "trace_not_found":
                raise HTTPException(status_code=404, detail={"reason": "trace_not_found"})
            elif err_str == "already_deleted":
                raise HTTPException(status_code=409, detail={"reason": "already_deleted"})
            elif err_str == "pending_transaction_exists":
                raise HTTPException(status_code=409, detail={"reason": "pending_transaction_exists"})
            else:
                raise HTTPException(status_code=400, detail={"reason": "validation_error", "message": err_str})

        # オンチェーン送信用
        version = latest_version + 1
        update_data = {
            "trace_id": trace_id,
            "version": version,
            "previous_version": latest_version,
            "hash": h,
            "lot_number": lot_number,
            "updated_by": req.updated_by or "system",
            "reason": req.reason
        }
        
        sig = sign_data(update_data, node.private_key)
        
        tx_payload = {
            "data": update_data,
            "signature": sig,
            "public_key": node.public_key,
            "type": "OFFCHAIN_UPDATE"
        }
        
        node.receive_message("NEW_TRANSACTION", tx_payload, node.node_id)
        node.broadcast("NEW_TRANSACTION", tx_payload)
        
        return {
            "accepted": True,
            "trace_id": trace_id,
            "version": version,
            "tx_status": "PENDING"
        }

    @app.delete("/api/traceability/{trace_id}")
    def soft_delete_traceability(trace_id: str, req: SoftDeleteRequest):
        if offchain_store is None:
            raise HTTPException(status_code=503, detail="Off-chain store is not configured")
        
        try:
            latest_version = offchain_store.validate_soft_delete(trace_id)
        except ValueError as e:
            err_str = str(e)
            if err_str == "trace_not_found":
                raise HTTPException(status_code=404, detail={"reason": "trace_not_found"})
            elif err_str == "already_deleted":
                raise HTTPException(status_code=409, detail={"reason": "already_deleted"})
            elif err_str == "pending_transaction_exists":
                raise HTTPException(status_code=409, detail={"reason": "pending_transaction_exists"})
            else:
                raise HTTPException(status_code=400, detail={"reason": "validation_error", "message": err_str})

        # オンチェーン送信用
        delete_data = {
            "trace_id": trace_id,
            "target_version": latest_version,
            "deleted_by": req.deleted_by or "system",
            "reason": req.reason
        }
        
        sig = sign_data(delete_data, node.private_key)
        
        tx_payload = {
            "data": delete_data,
            "signature": sig,
            "public_key": node.public_key,
            "type": "OFFCHAIN_SOFT_DELETE"
        }
        
        node.receive_message("NEW_TRANSACTION", tx_payload, node.node_id)
        node.broadcast("NEW_TRANSACTION", tx_payload)
        
        return {
            "accepted": True,
            "trace_id": trace_id,
            "target_version": latest_version,
            "status": "soft_delete_pending"
        }

    @app.delete("/api/admin/traceability/{trace_id}/hard")
    def hard_delete_traceability(
        trace_id: str,
        req: HardDeleteRequest,
        x_admin_secret: Optional[str] = Header(None, alias="X-Admin-Secret")
    ):
        if offchain_store is None:
            raise HTTPException(status_code=503, detail="Off-chain store is not configured")
            
        expected_secret = os.getenv("ADMIN_SECRET", "change_me_to_strong_random_value")
        if x_admin_secret != expected_secret:
            raise HTTPException(status_code=403, detail={"reason": "forbidden"})
            
        # オンチェーンの該当ハッシュを収集する
        anchored_hashes = []
        for block in node.chain.chain[1:]:
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
                        
        try:
            audit_log_id, deleted_versions = offchain_store.hard_delete(
                trace_id,
                executed_by=req.executed_by,
                reason=req.reason,
                anchored_hashes=anchored_hashes
            )
        except ValueError as e:
            if str(e) == "trace_not_found":
                raise HTTPException(status_code=404, detail={"reason": "trace_not_found"})
            raise HTTPException(status_code=400, detail={"reason": "validation_error", "message": str(e)})
            
        return {
            "deleted": True,
            "trace_id": trace_id,
            "deleted_versions": deleted_versions,
            "audit_log_id": audit_log_id
        }

    @app.get("/api/audit/{trace_id}")
    def audit_traceability(trace_id: str):
        if offchain_store is None:
            raise HTTPException(status_code=503, detail="Off-chain store is not configured")
            
        audit_res = node.audit_trace_data(trace_id, offchain_store)
        if not audit_res.get("valid") and audit_res.get("reason") == "trace_not_found":
            raise HTTPException(status_code=404, detail={"reason": "trace_not_found"})
            
        return audit_res

    @app.post("/pbft/{route}")
    def handle_pbft(route: str, message: PBFTMessage):
        """PBFTフェーズメッセージ（PRE_PREPARE / PREPARE / COMMIT）を受信する"""
        msg_type = PBFT_ROUTE_TO_MSG.get(route.lower())
        if not msg_type:
            raise HTTPException(status_code=404, detail=f"Unknown PBFT route: {route}")
        try:
            block = dict_to_block(message.payload)
        except (KeyError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        node.receive_message(msg_type, block, message.sender_id)
        return {"status": "received", "msg_type": msg_type}

    @app.on_event("shutdown")
    def shutdown_event():
        if offchain_store is not None:
            offchain_store.close()

    return app


def _build_node_from_env() -> Node:
    node_id = os.getenv("NODE_ID", "node1")
    role = os.getenv("NODE_ROLE", "Replica")
    peer_urls = [u.strip() for u in os.getenv("PEER_URLS", "").split(",") if u.strip()]
    node = Node(node_id, role)
    node.set_peer_urls(peer_urls)
    node.add_business_rule(default_weight_check_rule)
    return node


_offchain_db_path = os.getenv("OFFCHAIN_DB_PATH", "data/offchain_store.db")
_node = _build_node_from_env()
_offchain = OffChainStore(db_path=_offchain_db_path)
app = create_node_app(_node, _offchain)


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("api:app", host="127.0.0.1", port=port, reload=False)
