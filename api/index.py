import json
import datetime
import hashlib
import hmac
import requests
from http.server import BaseHTTPRequestHandler

# ================= 配置区域 =================
HOST = 'visual.volcengineapi.com'
REGION = 'cn-north-1'
ENDPOINT = 'https://visual.volcengineapi.com'
SERVICE = 'cv'
# ==========================================

def sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def get_signature_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = sign(secret_key.encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, 'request')
    return k_signing

def format_query(params: dict) -> str:
    return '&'.join(f'{k}={params[k]}' for k in sorted(params))

def call_volc_query(task_id: str, access_key: str, secret_key: str) -> dict:
    query_params = {'Action': 'CVSync2AsyncGetResult', 'Version': '2022-08-31'}
    req_query = format_query(query_params)
    
    body_params = {
        "req_key": "jimeng_dream_actor_m1_gen_video_cv",
        "task_id": task_id
    }
    body_str = json.dumps(body_params, ensure_ascii=False)

    method = 'POST'
    now = datetime.datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')
    
    payload_hash = hashlib.sha256(body_str.encode('utf-8')).hexdigest()
    signed_headers = 'content-type;host;x-content-sha256;x-date'
    canonical_headers = f'content-type:application/json\nhost:{HOST}\nx-content-sha256:{payload_hash}\nx-date:{amz_date}\n'
    canonical_request = f'{method}\n/\n{req_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}'
    credential_scope = f'{date_stamp}/{REGION}/{SERVICE}/request'
    string_to_sign = f'HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()}'
    signing_key = get_signature_key(secret_key, date_stamp, REGION, SERVICE)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    auth_header = f'HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}'
    
    headers = {
        'X-Date': amz_date,
        'Authorization': auth_header,
        'X-Content-Sha256': payload_hash,
        'Content-Type': 'application/json'
    }
    
    try:
        url = f'{ENDPOINT}?{req_query}'
        resp = requests.post(url, headers=headers, data=body_str, timeout=10)
        try:
            return {"status_code": resp.status_code, "data": resp.json()}
        except:
            return {"status_code": resp.status_code, "data": {"raw_text": resp.text}}
    except Exception as e:
        return {"status_code": 500, "data": {"error": str(e)}}

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length)
            body = json.loads(raw_body.decode('utf-8'))

            task_id = body.get('task_id')
            ak = body.get('ak')
            sk = body.get('sk')

            if task_id:
                task_id = task_id.strip()

            if not task_id or not ak or not sk:
                return self._send_json(400, {"msg": "Missing parameters"})

            result = call_volc_query(task_id, ak, sk)
            volc_response = result.get("data", {})

            # ==========================================
            # ⭐ 关键修复：防止 data 为 null 时崩溃
            # ==========================================
            final_status = "unknown"
            video_url = ""
            
            # 先安全获取 data 字段
            data_obj = volc_response.get("data")
            
            # 只有当它真的是字典时，才去取值
            if isinstance(data_obj, dict):
                final_status = data_obj.get("status", "unknown")
                video_url = data_obj.get("video_url", "")
            else:
                # 如果 data 是 null，说明出错了，尝试提取错误信息
                if "ResponseMetadata" in volc_response:
                    err = volc_response["ResponseMetadata"].get("Error", {})
                    if err:
                         final_status = f"Error: {err.get('Message', 'unknown')}"

            resp_body = {
                "code": 0 if result["status_code"] == 200 else 1,
                "msg": "success",
                "volc_status": final_status,
                "video_url": video_url,
                "raw_volc_data": volc_response # 返回原始数据方便你调试
            }

            return self._send_json(200, resp_body)

        except Exception as e:
            # 捕获所有未知错误
            return self._send_json(200, {
                "code": 500,
                "msg": f"Script Error: {str(e)}", 
                "volc_status": "script_error"
            })

    def _send_json(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))