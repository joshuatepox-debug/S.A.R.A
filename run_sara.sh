#!/bin/bash
echo "===================================================="
echo "🛡️ Iniciando S.A.R.A. v4.0 (CerberusOps SOAR)"
echo "===================================================="
uvicorn src.api:app --host 0.0.0.0 --port 8000 &
API_PID=$!
sleep 2
echo "[+] API SOAR (FastAPI) activa en: http://localhost:8000/docs"
echo "[+] Dashboard SOC (Streamlit) activo en: http://localhost:8501"
streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0 --server.headless true
kill $API_PID 2>/dev/null
