#!/usr/bin/env bash
# 3ノード（納入業者・加工工場・倉庫）を独立プロセスで起動する（ステップ10）
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data logs

echo "ノードAPIサーバーを起動します（Ctrl+C で全停止）..."

NODE_ID=納入業者 NODE_ROLE=Replica PORT=5001 \
  PEER_URLS=http://127.0.0.1:5002,http://127.0.0.1:5003 \
  OFFCHAIN_DB_PATH=data/offchain_store.db \
  uvicorn api:app --host 127.0.0.1 --port 5001 > logs/node_supplier.log 2>&1 &
PID1=$!

NODE_ID=加工工場 NODE_ROLE=Leader PORT=5002 \
  PEER_URLS=http://127.0.0.1:5001,http://127.0.0.1:5003 \
  OFFCHAIN_DB_PATH=data/offchain_store.db \
  uvicorn api:app --host 127.0.0.1 --port 5002 > logs/node_factory.log 2>&1 &
PID2=$!

NODE_ID=倉庫 NODE_ROLE=Replica PORT=5003 \
  PEER_URLS=http://127.0.0.1:5001,http://127.0.0.1:5002 \
  OFFCHAIN_DB_PATH=data/offchain_store.db \
  uvicorn api:app --host 127.0.0.1 --port 5003 > logs/node_warehouse.log 2>&1 &
PID3=$!

cleanup() {
  echo ""
  echo "ノードを停止しています..."
  kill "$PID1" "$PID2" "$PID3" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 2
echo ""
echo "起動完了:"
echo "  納入業者 (Replica): http://127.0.0.1:5001"
echo "  加工工場 (Leader):  http://127.0.0.1:5002"
echo "  倉庫     (Replica): http://127.0.0.1:5003"
echo ""
echo "利用例:"
echo '  curl -s http://127.0.0.1:5001/chain | python -m json.tool'
echo ""
echo "ログ: logs/node_*.log"
wait
