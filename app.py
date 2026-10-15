#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import time
import json
import uuid
import random
import logging
import sys
import warnings
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple, Optional
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
import aiohttp
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)


# ═══════════════════════════════════════════════════════════════
#          DEBUG CONFIG
# ═══════════════════════════════════════════════════════════════
DEBUG = False

LOG_LEVEL = logging.DEBUG if DEBUG else logging.INFO

logging.basicConfig(
    level=LOG_LEVEL,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("ff-api")

# asyncio transport logs (SSL handshake noise) চুপ করাও
logging.getLogger("asyncio").setLevel(logging.WARNING)


# === Settings ===
login_url = "https://loginbp.ppmainecoonghj.com/"
ob = "OB55"
version = "2.133.5"

OAUTH_HOST = "ffmconnect.ppmainecoonghj.com"
OAUTH_URL = f"https://{OAUTH_HOST}/api/v2/oauth/guest/token:grant"
OAUTH_INSPECT_URL = f"https://{OAUTH_HOST}/oauth/token/inspect"
OAUTH_CLIENT_ID = 100067
OAUTH_CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
OAUTH_CLIENT_TYPE = 2

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID",
                     "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

OAUTH_USER_AGENTS = [
    "GarenaMSDK/4.0.44(RMX5070 ;Android 14;en;GB;app 2.133.5 2019118527;)",
    "GarenaMSDK/4.0.44(SM-M315F ;Android 12;en;BD;app 2.133.5 2019118527;)",
    "GarenaMSDK/4.0.44(SM-A125F ;Android 13;en;BD;app 2.133.5 2019118527;)",
    "GarenaMSDK/4.0.44(M2101K7AI ;Android 12;en;IN;app 2.133.5 2019118527;)",
]

UNITY_USER_AGENTS = [
    "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "UnityPlayer/2018.4.11f1 (UnityWebRequest/1.0, libcurl/8.3.0-DEV)",
]


def get_random_oauth_ua() -> str:
    ua = random.choice(OAUTH_USER_AGENTS)
    log.debug(f"picked oauth UA: {ua[:60]}...")
    return ua


def get_random_unity_ua() -> str:
    ua = random.choice(UNITY_USER_AGENTS)
    log.debug(f"picked unity UA: {ua[:60]}...")
    return ua


# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
uid_region_cache = {}
_token_cache = {}


# ═══════════════════════════════════════════════════════════════
#          HTTP HELPERS
# ═══════════════════════════════════════════════════════════════
def make_session() -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(
        limit=50,
        limit_per_host=20,
        ttl_dns_cache=300,
        ssl=False,
        enable_cleanup_closed=True,
    )
    timeout = aiohttp.ClientTimeout(total=15, connect=10)
    return aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        trust_env=False,
    )


async def http_post_json(session: aiohttp.ClientSession, url: str,
                         headers: dict, body: dict) -> Tuple[int, dict]:
    t0 = time.time()
    if DEBUG:
        log.debug(f"POST(json) -> {url}")
        log.debug(f"  body:    {body}")
    try:
        async with session.post(url, json=body, headers=headers, ssl=False) as resp:
            try:
                data = await resp.json(content_type=None)
            except Exception:
                text = await resp.text()
                try:
                    data = json.loads(text)
                except Exception:
                    data = {"raw": text}
            dt = (time.time() - t0) * 1000
            log.debug(f"POST(json) <- {url} status={resp.status} ({dt:.0f}ms)")
            log.debug(f"  resp: {data}")
            return resp.status, data
    except asyncio.TimeoutError:
        log.warning(f"POST(json) TIMEOUT {url} after {(time.time()-t0)*1000:.0f}ms")
        return 0, {"error": "timeout"}
    except aiohttp.ClientError as e:
        log.error(f"POST(json) client_error {url}: {e}")
        return 0, {"error": f"client_error: {e}"}
    except Exception as e:
        log.exception(f"POST(json) unexpected {url}")
        return 0, {"error": f"{type(e).__name__}: {e}"}


async def http_post_binary(session: aiohttp.ClientSession, url: str,
                           headers: dict, data: bytes) -> Tuple[int, bytes]:
    """Return (status_code, response_bytes). status=0 on network error."""
    t0 = time.time()
    if DEBUG:
        log.debug(f"POST(bin)  -> {url}  payload={len(data)}B")
    try:
        async with session.post(url, data=data, headers=headers, ssl=False) as resp:
            content = await resp.read()
            status = resp.status
            dt = (time.time() - t0) * 1000
            log.debug(f"POST(bin)  <- {url} status={status} len={len(content)} ({dt:.0f}ms)")
            if DEBUG and content:
                log.debug(f"  head hex: {content[:64].hex()}")
            return status, content
    except asyncio.TimeoutError:
        log.warning(f"POST(bin) TIMEOUT {url} after {(time.time()-t0)*1000:.0f}ms")
        return 0, b""
    except aiohttp.ClientError as e:
        log.error(f"POST(bin) client_error {url}: {e}")
        return 0, b""
    except Exception as e:
        log.exception(f"POST(bin) unexpected {url}")
        return 0, b""


# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    out = aes.encrypt(pad(plaintext))
    log.debug(f"AES-CBC encrypt: in={len(plaintext)}B out={len(out)}B")
    return out


def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance


def json_to_proto_sync(json_data: str, proto_message: Message) -> bytes:
    log.debug(f"json_to_proto {type(proto_message).__name__}: {json_data}")
    json_format.ParseDict(json.loads(json_data), proto_message)
    out = proto_message.SerializeToString()
    log.debug(f"  -> serialized {len(out)}B")
    return out


def get_account_credentials(region: str) -> Tuple[str, str]:
    r = region.upper()
    if r == "BD":
        return "4775038861", "7RJPH_TE4M_SONIC_L38VV"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "4367177499", "TE4M-SONIC-J6VC9Q"


def extract_plaintext_error(content: bytes) -> Optional[str]:
    """If response is a short plain-text error, return it, else None."""
    if not content or len(content) > 128:
        return None
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # printable ascii check
    if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in text):
        cleaned = text.strip()
        if cleaned:
            return cleaned
    return None


# ═══════════════════════════════════════════════════════════════
#          TOKEN GENERATION
# ═══════════════════════════════════════════════════════════════
async def get_access_token(session: aiohttp.ClientSession, uid: str, password: str) -> Tuple[str, str, int]:
    log.info(f"[OAuth] requesting guest token for uid={uid}")

    headers = {
        "User-Agent": get_random_oauth_ua(),
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Host": OAUTH_HOST,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }

    body = {
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "client_type": OAUTH_CLIENT_TYPE,
        "device_id": f"02-{uuid.uuid4()}",
        "password": password,
        "response_type": "token",
        "uid": int(uid) if str(uid).isdigit() else uid,
    }

    status, data = await http_post_json(session, OAUTH_URL, headers, body)

    if status == 429 or data.get("code") == 1006 or data.get("error") == "error_too_many_requests":
        log.warning(f"[OAuth] RATE LIMITED uid={uid}")
        return "0", "0", 4

    if status == 200 and data.get("code") == 0 and "data" in data:
        d = data["data"]
        platform_raw = (
            d.get("platform")
            or d.get("main_active_platform")
            or d.get("platform_type")
            or d.get("origin_platform_type")
            or d.get("primary_platform_type")
            or 4
        )
        try:
            platform_type = int(platform_raw)
        except Exception:
            platform_type = 4

        access_token = d.get("access_token", "0")
        open_id = d.get("open_id", "0")
        log.info(f"[OAuth] OK uid={uid} open_id={open_id[:10]}... pt={platform_type}")
        return access_token, open_id, platform_type

    log.error(f"[OAuth] FAILED uid={uid} status={status} data={data}")
    return "0", "0", 4


async def create_jwt(session: aiohttp.ClientSession, region: str) -> Optional[dict]:
    log.info(f"[MajorLogin] start region={region}")
    uid, password = get_account_credentials(region)
    token_val, open_id, platform_type = await get_access_token(session, uid, password)

    if token_val == "0" or open_id == "0":
        log.error(f"[MajorLogin] OAuth failed for region={region}")
        return None

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": str(platform_type),
    })
    proto_bytes = json_to_proto_sync(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = f"{login_url}MajorLogin"
    headers = {
        "User-Agent": get_random_unity_ua(),
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.12f1",
        "X-GA": "v1 1",
        "ReleaseVersion": ob,
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {token_val}",
    }

    status, content = await http_post_binary(session, url, headers, payload)
    if status != 200 or not content:
        log.error(f"[MajorLogin] bad response region={region} status={status}")
        return None

    msg = None
    for offset in (0, 64):
        if len(content) <= offset:
            continue
        try:
            decoded = decode_protobuf(content[offset:], FreeFire_pb2.LoginRes)
            msg = json.loads(json_format.MessageToJson(decoded))
            if msg.get('token'):
                log.debug(f"[MajorLogin] decoded OK at offset={offset}")
                break
        except Exception as e:
            log.debug(f"[MajorLogin] decode fail offset={offset}: {e}")
            continue

    if not msg or not msg.get('token'):
        log.error(f"[MajorLogin] failed region={region} (no token) pt={platform_type}")
        return None

    server_url_from_jwt = msg.get('serverUrl', '') or msg.get('server_url', '')

    result = {
        'token': f"Bearer {msg.get('token', '0')}",
        'raw_token': msg.get('token', '0'),
        'region': msg.get('lockRegion', '0'),
        'server_url': server_url_from_jwt,
        'platform_type': platform_type,
        'expires_at': time.time() + 25200,
    }
    log.info(f"[MajorLogin] SUCCESS region={region} pt={platform_type} "
             f"server_url={server_url_from_jwt}")
    return result


async def get_or_create_token(session: aiohttp.ClientSession, region: str) -> dict:
    info = _token_cache.get(region)
    if info and time.time() < info['expires_at']:
        log.debug(f"[token-cache] HIT region={region}")
        return info
    log.debug(f"[token-cache] MISS region={region}")
    info = await create_jwt(session, region)
    if not info:
        raise RuntimeError(f"No token available for region={region}")
    _token_cache[region] = info
    return info


async def GetAccountInformation(session: aiohttp.ClientSession, uid, unk, region, endpoint):
    log.debug(f"[GetAccountInfo] uid={uid} region={region} endpoint={endpoint}")

    payload = json_to_proto_sync(json.dumps({'a': uid, 'b': unk}),
                                 main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    info = await get_or_create_token(session, region)
    token = info['token']
    server = info['server_url']

    headers = {
        "User-Agent": get_random_unity_ua(),
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "Authorization": token,
        "X-Unity-Version": "2018.4.12f1",
        "X-GA": "v1 1",
        "ReleaseVersion": ob,
        "X-GA-SV": str(int(time.time())),
    }

    status, content = await http_post_binary(session, server + endpoint, headers, data_enc)

    if not content:
        raise RuntimeError(f"Empty response (status={status})")

    # ---- FIX: check for plaintext error like "BR_ACCOUNT_NOT_FOUND" ----
    plain_err = extract_plaintext_error(content)
    if plain_err and ("NOT_FOUND" in plain_err or plain_err.startswith("BR_") or "ERROR" in plain_err.upper()):
        raise RuntimeError(f"API error [{status}]: {plain_err}")

    if status != 200:
        raise RuntimeError(f"HTTP {status}: {content[:80]!r}")

    # ---- FIX: skip offsets that exceed response length ----
    for offset in (0, 64):
        if len(content) <= offset:
            log.debug(f"[GetAccountInfo] skip offset={offset} (len={len(content)})")
            continue
        try:
            decoded = decode_protobuf(content[offset:],
                                      AccountPersonalShow_pb2.AccountPersonalShowInfo)
            out = json.loads(json_format.MessageToJson(decoded))
            if out:  # ---- FIX: reject empty {} ----
                log.debug(f"[GetAccountInfo] decoded OK uid={uid} region={region} offset={offset}")
                return out
            log.debug(f"[GetAccountInfo] empty decode at offset={offset}, trying next")
        except Exception as e:
            log.debug(f"[GetAccountInfo] decode fail offset={offset}: {e}")
            continue

    raise RuntimeError("Failed to parse AccountPersonalShow response")


# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                log.debug(f"[http-cache] HIT {key}")
                return cache[key]
            log.debug(f"[http-cache] MISS {key}")
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════
#          FLASK ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route('/info')
@cached_endpoint()
def get_account_info():
    t_req = time.time()
    uid = request.args.get('uid')
    log.info(f"GET /info uid={uid}")
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    async def _run():
        async with make_session() as session:
            if uid in uid_region_cache:
                cached_region = uid_region_cache[uid]
                log.debug(f"uid={uid} region cache HIT -> {cached_region}")
                try:
                    data = await GetAccountInformation(
                        session, uid, "7", cached_region,
                        "/GetPlayerPersonalShow")
                    return data, cached_region
                except Exception as e:
                    log.warning(f"[info] cached region fail uid={uid}: {e}")
                    uid_region_cache.pop(uid, None)

            log.debug(f"uid={uid} launching parallel region scan "
                      f"({len(SUPPORTED_REGIONS)} regions)")
            task_map = {
                asyncio.create_task(
                    GetAccountInformation(session, uid, "7", region,
                                          "/GetPlayerPersonalShow")
                ): region
                for region in SUPPORTED_REGIONS
            }

            pending = set(task_map.keys())
            try:
                while pending:
                    done, pending = await asyncio.wait(
                        pending, return_when=asyncio.FIRST_COMPLETED
                    )
                    for task in done:
                        try:
                            result = task.result()
                        except Exception as e:
                            log.debug(f"region {task_map[task]} failed: {e}")
                            continue
                        log.info(f"uid={uid} FOUND in region={task_map[task]}")
                        for p in pending:
                            p.cancel()
                        return result, task_map[task]
                return None, None
            finally:
                for t in task_map:
                    if not t.done():
                        t.cancel()
                # give cancelled tasks a moment to clean up (suppress SSL noise)
                if task_map:
                    await asyncio.gather(*task_map.keys(), return_exceptions=True)

    try:
        return_data, found_region = asyncio.run(_run(), debug=False)
    except Exception as e:
        log.exception(f"[info] top-level error uid={uid}")
        return_data, found_region = None, None

    dt = (time.time() - t_req) * 1000
    if return_data is not None:
        if found_region:
            uid_region_cache[uid] = found_region
        log.info(f"GET /info uid={uid} OK region={found_region} ({dt:.0f}ms)")
        formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
        return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}

    log.warning(f"GET /info uid={uid} NOT FOUND ({dt:.0f}ms)")
    return jsonify({"error": "UID not found in any region."}), 404


@app.route('/inspect')
def inspect_token():
    t_req = time.time()
    token = request.args.get('token')
    app_id = request.args.get('app_id', str(OAUTH_CLIENT_ID))
    log.info(f"GET /inspect token={token[:12] if token else None}... app_id={app_id}")
    if not token:
        return jsonify({"error": "Please provide token."}), 400

    async def _run():
        async with make_session() as session:
            headers = {
                "User-Agent": get_random_oauth_ua(),
                "Host": OAUTH_HOST,
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip",
            }
            params = {"app_id": app_id, "token": token}
            try:
                async with session.get(OAUTH_INSPECT_URL, params=params,
                                       headers=headers, ssl=False) as resp:
                    try:
                        return await resp.json(content_type=None)
                    except Exception:
                        return {"raw": await resp.text(), "status": resp.status}
            except Exception as e:
                log.exception("inspect request failed")
                return {"error": f"{type(e).__name__}: {e}"}

    try:
        result = asyncio.run(_run(), debug=False)
        dt = (time.time() - t_req) * 1000
        log.info(f"GET /inspect OK ({dt:.0f}ms)")
        return jsonify(result), 200
    except Exception as e:
        log.exception("inspect top-level error")
        return jsonify({"error": str(e)}), 500


@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    log.info("GET /refresh — refreshing all region tokens")
    async def _run():
        async with make_session() as session:
            tasks = [create_jwt(session, r) for r in SUPPORTED_REGIONS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            ok = []
            for r, res in zip(SUPPORTED_REGIONS, results):
                if isinstance(res, dict):
                    _token_cache[r] = res
                    ok.append(r)
                else:
                    log.warning(f"refresh region={r} failed: {res}")
            return ok

    try:
        ok = asyncio.run(_run(), debug=False)
        log.info(f"refresh done ok={ok}")
        return jsonify({
            'message': 'Tokens refreshed.',
            'regions_ok': ok,
        }), 200
    except Exception as e:
        log.exception("refresh top-level error")
        return jsonify({'error': f'Refresh failed: {e}'}), 500


@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "debug": DEBUG,
        "tokens_cached": list(_token_cache.keys()),
        "uid_cache_size": len(uid_region_cache),
        "http_cache_size": len(cache),
    })


@app.route('/debug/env')
def debug_env():
    if not DEBUG:
        return jsonify({"error": "debug disabled"}), 403
    return jsonify({
        "ob": ob,
        "version": version,
        "login_url": login_url,
        "oauth_url": OAUTH_URL,
        "inspect_url": OAUTH_INSPECT_URL,
        "oauth_client_id": OAUTH_CLIENT_ID,
        "supported_regions": sorted(SUPPORTED_REGIONS),
        "token_cache_regions": list(_token_cache.keys()),
        "uid_region_cache": uid_region_cache,
    })


@app.route('/debug/clear_cache', methods=['GET', 'POST'])
def debug_clear_cache():
    if not DEBUG:
        return jsonify({"error": "debug disabled"}), 403
    cache.clear()
    uid_region_cache.clear()
    log.warning("debug: caches cleared")
    return jsonify({"message": "caches cleared"})


# ═══════════════════════════════════════════════════════════════
#          ENTRY
# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    log.info("=" * 60)
    log.info(f"  FreeFire API  (DEBUG={DEBUG})")
    log.info(f"  login_url  = {login_url}")
    log.info(f"  oauth_url  = {OAUTH_URL}")
    log.info(f"  regions    = {sorted(SUPPORTED_REGIONS)}")
    log.info("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)