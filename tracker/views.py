# tracker/views.py
import os
import json
import logging
import textwrap
from io import BytesIO
from datetime import datetime, timezone
from typing import Optional, List
import requests
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from dotenv import load_dotenv
from web3 import Web3
from hexbytes import HexBytes
# Optional PDF dependency
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as rl_canvas
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Load env file
load_dotenv("variables.env")

# --- Configure RPC endpoints (use your existing env vars) ---
RPC_ENDPOINTS = {
    "Ethereum Mainnet": os.getenv("WEB3_MAINNET"),
    "Sepolia Testnet": os.getenv("WEB3_SEPOLIA"),
    "Polygon Mainnet": os.getenv("WEB3_POLYGON"),
    "Binance Smart Chain": os.getenv("WEB3_BSC"),
}

# Explorer API mapping (for explorer links)
EXPLORER_APIS = {
    "Ethereum Mainnet": {
        "explorer_tx": "https://etherscan.io/tx/{}",
        "explorer_addr": "https://etherscan.io/address/{}",
    },
    "Sepolia Testnet": {
        "explorer_tx": "https://sepolia.etherscan.io/tx/{}",
        "explorer_addr": "https://sepolia.etherscan.io/address/{}",
    },
    "Polygon Mainnet": {
        "explorer_tx": "https://polygonscan.com/tx/{}",
        "explorer_addr": "https://polygonscan.com/address/{}",
    },
    "Binance Smart Chain": {
        "explorer_tx": "https://bscscan.com/tx/{}",
        "explorer_addr": "https://bscscan.com/address/{}",
    },
}

# Optional Arkham key for enrichment
ARKHAM_KEY = os.getenv("ARKHAM_API_KEY")
ARKHAM_BASE = "https://api.arkhamintelligence.com"


# ---------------- Helpers ----------------
def get_w3_for_chain(chain_name: Optional[str]) -> Optional[Web3]:
    if not chain_name:
        chain_name = "Ethereum Mainnet"
    rpc = RPC_ENDPOINTS.get(chain_name)
    if not rpc:
        return None
    try:
        w3 = Web3(Web3.HTTPProvider(rpc))
        if not w3.is_connected():
            logger.warning("Web3 not connected for %s", chain_name)
            return None
        return w3
    except Exception as e:
        logger.exception("Error creating Web3 for %s: %s", chain_name, e)
        return None


def arkham_label_for(address: str) -> Optional[str]:
    if not address or not ARKHAM_KEY:
        return None
    try:
        url = f"{ARKHAM_BASE}/intelligence/address/{address}/all"
        r = requests.get(url, headers={"API-Key": ARKHAM_KEY}, timeout=8)
        r.raise_for_status()
        data = r.json()
        for _, intel in data.items():
            if isinstance(intel, dict) and intel.get("arkhamEntity"):
                return intel["arkhamEntity"].get("id")
    except Exception as e:
        logger.debug("Arkham lookup failed for %s: %s", address, e)
    return None

def analyze_tx_source(tx_obj, w3: Web3) -> str:
    try:
        # pick input / data field
        input_data = ""
        if hasattr(tx_obj, "get"):
            input_data = tx_obj.get("input") or tx_obj.get("data") or ""
        else:
            input_data = getattr(tx_obj, "input", "") or getattr(tx_obj, "data", "") or ""

        # quick detection
        if not input_data or input_data == "0x":
            return "Transfer"
        input_hex = input_data if isinstance(input_data, str) else (input_data.hex() if isinstance(input_data, bytes) else str(input_data))
        if input_hex.startswith("0xa9059cbb") or input_hex.startswith("a9059cbb"):
            return "ERC-20 Transfer"
        if input_hex.startswith("0x23b872dd") or input_hex.startswith("23b872dd"):
            return "ERC-721 Transfer"
        # if it's a contract (try get_code)
        try:
            to_addr = tx_obj.get("to") if hasattr(tx_obj, "get") else getattr(tx_obj, "to", None)
            if to_addr:
                code = w3.eth.get_code(to_addr)
                if code and code not in (b"", "0x"):
                    return "Contract Interaction"
        except Exception:
            pass
        return "Contract Interaction"
    except Exception as e:
        logger.debug("analyze_tx_source error: %s", e)
        return "Unknown"
def clean_for_json(obj):
    """Convert Web3 objects to plain Python types safe for JSON."""
    import datetime, decimal
    from hexbytes import HexBytes

    if isinstance(obj, list):
        return [clean_for_json(o) for o in obj]
    elif isinstance(obj, dict):
        return {k: clean_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, HexBytes):
        return obj.hex()
    elif isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    elif isinstance(obj, decimal.Decimal):
        return float(obj)
    else:
        return obj

# ---------------- Views ----------------
def tx_search(request):
    """
    Search for a specific transaction hash and render tx_search.html.
    Context provides:
      - query, tx (dict or None), err, chain, chains
    """
    query = (request.GET.get("q") or "").strip()
    selected_chain = request.GET.get("chain")
    context = {
        "query": query,
        "tx": None,
        "err": None,
        "chain": selected_chain,
        "chains": list(RPC_ENDPOINTS.keys()),
    }

    if not query:
        return render(request, "tx_search.html", context)

    # basic validation
    if not query.startswith("0x") or len(query) != 66:
        context["err"] = "Invalid transaction hash format"
        return render(request, "tx_search.html", context)

    chains_to_search = [selected_chain] if selected_chain else list(RPC_ENDPOINTS.keys())

    found = False
    for chain_name in chains_to_search:
        rpc = RPC_ENDPOINTS.get(chain_name)
        if not rpc:
            continue
        try:
            w3 = Web3(Web3.HTTPProvider(rpc))
            if not w3.is_connected():
                logger.debug("RPC not connected for %s", chain_name)
                continue

            tx = w3.eth.get_transaction(query)
            receipt = w3.eth.get_transaction_receipt(query)
            block = w3.eth.get_block(receipt.blockNumber)
            timestamp = datetime.fromtimestamp(block.timestamp, tz=timezone.utc)

            from_label = arkham_label_for(tx.get("from")) if ARKHAM_KEY else None
            to_label = arkham_label_for(tx.get("to")) if ARKHAM_KEY and tx.get("to") else None

            context["tx"] = {
                "hash": query,
                "status": "Success" if (getattr(receipt, "status", receipt.get("status")) == 1) else "Failed",
                "from": (tx.get("from"), from_label),
                "to": (tx.get("to"), to_label),
                "value": float(Web3.from_wei(int(tx.get("value", 0)), "ether")),
                "gas": int(tx.get("gas", 0)),
                "block": int(receipt.blockNumber),
                "time": timestamp,
                "input": tx.get("input") or tx.get("data") or "",
            }
            context["chain"] = chain_name
            found = True
            break
        except Exception as e:
            logger.debug("Transaction not found on %s or error: %s", chain_name, e)
            continue

    if not found:
        context["err"] = f"Transaction {query} not found on selected chain(s)."

    return render(request, "tx_search.html", context)

def last10_from_tx(request):
    """
    Main page — show form and results.
    Query params:
      - q=<tx_hash>
      - chain=<chain name> (optional; defaults to found chain)
    """
    tx_hash = (request.GET.get("q") or "").strip()
    selected_chain = request.GET.get("chain")
    context = {
        "query": tx_hash or None,
        "chain": selected_chain,
        "chains": list(RPC_ENDPOINTS.keys()),
        "txs": None,
        "chart_json": None,
        "wallet": None,
        "total_value_eth": 0.0,
        "tx_count": 0,
        "err": None,
    }

    # Show empty form if no q
    if not tx_hash:
        return render(request, "last10_from_tx.html", context)

    # basic validation
    if not tx_hash.startswith("0x") or len(tx_hash) < 10:
        context["err"] = "Invalid transaction hash format"
        return render(request, "last10_from_tx.html", context)

    # Step A: find base tx across chosen or all chains
    chains_to_try = [selected_chain] if selected_chain else list(RPC_ENDPOINTS.keys())
    base_tx = None
    w3 = None
    found_chain = None
    for ch in chains_to_try:
        rpc = RPC_ENDPOINTS.get(ch)
        if not rpc:
            continue
        try:
            candidate = Web3(Web3.HTTPProvider(rpc))
            if not candidate.is_connected():
                continue
            base_tx = candidate.eth.get_transaction(tx_hash)
            w3 = candidate
            found_chain = ch
            break
        except Exception as e:
            logger.debug("tx not on %s or node error: %s", ch, e)
            continue

    if not base_tx or w3 is None:
        context["err"] = f"Transaction {tx_hash} not found on configured chains (or node doesn't have it)."
        return render(request, "last10_from_tx.html", context)

    # Step B: determine wallet and start block
    from_addr = base_tx.get("from")
    if not from_addr:
        context["err"] = "Could not determine 'from' address from the base transaction."
        return render(request, "last10_from_tx.html", context)
    context["wallet"] = from_addr
    # default chain shown
    context["chain"] = found_chain

    try:
        start_block = int(base_tx.get("blockNumber") or w3.eth.block_number)
    except Exception:
        start_block = w3.eth.block_number

    # Step C: scan blocks backwards collecting up to 10 txs
    collected = []
    block_num = start_block
    safety_limit = 8000
    scanned = 0

    while block_num >= 0 and len(collected) < 10 and scanned < safety_limit:
        try:
            block = w3.eth.get_block(block_num, full_transactions=True)
        except Exception as e:
            logger.debug("failed to fetch block %s: %s", block_num, e)
            block_num -= 1
            scanned += 1
            continue

        block_ts = getattr(block, "timestamp", None) or (block.get("timestamp") if isinstance(block, dict) else None)
        for t in (block.transactions or []):
            t_from = (t.get("from") if hasattr(t, "get") else getattr(t, "from", None))
            t_to = (t.get("to") if hasattr(t, "get") else getattr(t, "to", None))
            if not t_from:
                continue
            if (t_from and t_from.lower() == from_addr.lower()) or (t_to and t_to.lower() == from_addr.lower()):
                # normalize fields and convert
                _hash = None
                if hasattr(t, "hash"):
                    h = getattr(t, "hash")
                    _hash = h.hex() if hasattr(h, "hex") else str(h)
                else:
                    _hash = t.get("hash")
                try:
                    value_wei = int(t.get("value", 0) if hasattr(t, "get") else getattr(t, "value", 0) or 0)
                except Exception:
                    value_wei = 0
                value_eth = float(Web3.from_wei(value_wei, "ether"))
                gas = int(t.get("gas", 0) if hasattr(t, "get") else getattr(t, "gas", 0) or 0)
                ts = datetime.fromtimestamp(int(block_ts), tz=timezone.utc) if block_ts else None

                # try to get receipt to determine status (best-effort)
                status = "Unknown"
                try:
                    receipt = w3.eth.get_transaction_receipt(_hash)
                    status = "Success" if (getattr(receipt, "status", receipt.get("status")) == 1) else "Failed"
                except Exception:
                    # ignore - many nodes may not return receipts for archived txs quickly
                    status = "Unknown"

                tx_info = {
                    "hash": _hash,
                    "from": t_from,
                    "to": t_to,
                    "value_wei": value_wei,
                    "value_eth": value_eth,
                    "gas": gas,
                    "block": int(block_num),
                    "timestamp": ts,
                    "input": (t.get("input") if hasattr(t, "get") else getattr(t, "input", "")) or "",
                    "status": status,
                }
                try:
                    tx_info["source"] = analyze_tx_source(t if hasattr(t, "get") else t, w3)
                except Exception:
                    tx_info["source"] = "Unknown"
                # explorer urls
                expl = EXPLORER_APIS.get(found_chain)
                if expl:
                    tx_info["explorer_url"] = expl["explorer_tx"].format(tx_info["hash"])
                    tx_info["to_explorer_url"] = expl["explorer_addr"].format(tx_info["to"]) if tx_info["to"] else None
                collected.append(tx_info)
                if len(collected) >= 10:
                    break

        block_num -= 1
        scanned += 1

    # Fallback: explorer API if node scan returned nothing
    if not collected:
        explorer_cfg = EXPLORER_APIS.get(found_chain)
        # attempt Etherscan style API only if env key exists in variables.env (fallback)
        if explorer_cfg:
            # try /account/txlist via your configured API keys (not implemented here as a must-have)
            # For brevity we skip implementing many explorer fallbacks; you can reuse existing fetch_last_txs_from_explorer() if you have keys.
            context["err"] = "Node scan returned no txs and no explorer fallback available (check explorer API keys)."
            return render(request, "last10_from_tx.html", context)
        else:
            context["err"] = "No transactions found and no explorer fallback configured."
            return render(request, "last10_from_tx.html", context)

    # sort newest -> oldest
    collected_sorted = sorted(collected, key=lambda x: x.get("block") or 0, reverse=True)[:10]

    # prepare chart payload and aggregates
    labels = []
    values = []
    gas_list = []
    hashes = []
    total_value = 0.0
    for tx in collected_sorted:
        ts = tx.get("timestamp") or datetime.now(timezone.utc)
        labels.append(f"{tx['block']} • {ts.strftime('%Y-%m-%d %H:%M')}")
        values.append(round(tx["value_eth"], 6))
        gas_list.append(tx["gas"])
        hashes.append(tx["hash"])
        total_value += tx["value_eth"]

    chart_payload = {"labels": labels, "values": values, "gas": gas_list, "hashes": hashes}

    # Also convert timestamps to ISO for JSON endpoints
    for tx in collected_sorted:
        if tx.get("timestamp"):
            tx["timestamp_iso"] = tx["timestamp"].isoformat()
        else:
            tx["timestamp_iso"] = None

    context.update({
        "txs": collected_sorted,
        "chart_json": json.dumps(chart_payload),
        "total_value_eth": round(total_value, 6),
        "tx_count": len(collected_sorted),
        "err": None,
    })
    return render(request, "last10_from_tx.html", context)

def download_tx_pdf_plain(request):
    """
    Generate a simple plain-text PDF with core tx details.
    Query: ?q=<tx_hash>&chain=<optional chain>
    """
    tx_hash = (request.GET.get("q") or "").strip()
    selected_chain = request.GET.get("chain")
    if not tx_hash:
        return HttpResponse("Missing transaction hash (q parameter).", status=400)
    if not tx_hash.startswith("0x") or len(tx_hash) != 66:
        return HttpResponse("Invalid transaction hash format.", status=400)

    chains_to_search = [selected_chain] if selected_chain else list(RPC_ENDPOINTS.keys())
    found = False
    tx_data = None
    for chain_name in chains_to_search:
        rpc = RPC_ENDPOINTS.get(chain_name)
        if not rpc:
            continue
        try:
            w3 = Web3(Web3.HTTPProvider(rpc))
            if not w3.is_connected():
                continue
            tx = w3.eth.get_transaction(tx_hash)
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            block = w3.eth.get_block(receipt.blockNumber)
            timestamp = datetime.fromtimestamp(block.timestamp, tz=timezone.utc)

            from_addr = tx.get("from")
            to_addr = tx.get("to")
            tx_data = {
                "Hash": tx_hash,
                "Chain": chain_name,
                "Status": "Success" if (getattr(receipt, "status", receipt.get("status")) == 1) else "Failed",
                "From": from_addr or "",
                "To": to_addr or "",
                "Value (ETH)": str(Web3.from_wei(int(tx.get("value", 0) or 0), "ether")),
                "Gas (limit)": str(tx.get("gas", "")),
                "Gas Price (wei)": str(tx.get("gasPrice", "")),
                "Block": str(receipt.blockNumber),
                "Block Timestamp (UTC)": timestamp.isoformat(),
            }
            found = True
            break
        except Exception as e:
            logger.debug("Chain %s error when building pdf tx: %s", chain_name, e)
            continue

    if not found or not tx_data:
        return HttpResponse(f"Transaction {tx_hash} not found.", status=404)

    if not REPORTLAB_AVAILABLE:
        return HttpResponse("PDF generation dependency missing. Install reportlab (pip install reportlab).", status=500)

    # Create plain-text PDF
    buffer = BytesIO()
    c = rl_canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    margin_x = 40
    margin_top = height - 40
    textobj = c.beginText(margin_x, margin_top)
    textobj.setFont("Courier", 10)
    textobj.setLeading(14)

    for key, val in tx_data.items():
        line = f"{key}: {val}"
        wrapped = textwrap.wrap(line, width=100) or [line]
        for w in wrapped:
            textobj.textLine(w)
        textobj.textLine("")
        if textobj.getY() < 80:
            c.drawText(textobj)
            c.showPage()
            textobj = c.beginText(margin_x, margin_top)
            textobj.setFont("Courier", 10)
            textobj.setLeading(14)

    c.drawText(textobj)
    c.showPage()
    c.save()

    pdf = buffer.getvalue()
    buffer.close()
    filename = f"tx_{tx_hash[:10]}.pdf"
    resp = HttpResponse(pdf, content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp

def last10_print_pdf(request):
    """
    Print (PDF) endpoint for the last10 results. Accepts same query params as last10_from_tx.
    Produces a simple PDF listing the ten tx rows (Value ETH, Block, Time, Status).
    """
    tx_hash = (request.GET.get("q") or "").strip()
    chain = request.GET.get("chain")
    # Reuse last10_from_tx to collect data — easiest way is to call the view function and extract results
    # (But since Django views return HttpResponse, we'll reproduce minimal scanning here
    #— replicate scanning logic to keep the endpoint self-contained).
    if not tx_hash:
        return HttpResponse("Missing q parameter", status=400)

    # Attempt to find tx and collect txs using same logic as last10_from_tx
    chains_to_try = [chain] if chain else list(RPC_ENDPOINTS.keys())
    base_tx = None
    w3 = None
    found_chain = None
    for ch in chains_to_try:
        rpc = RPC_ENDPOINTS.get(ch)
        if not rpc:
            continue
        try:
            candidate = Web3(Web3.HTTPProvider(rpc))
            if not candidate.is_connected():
                continue
            base_tx = candidate.eth.get_transaction(tx_hash)
            w3 = candidate
            found_chain = ch
            break
        except Exception:
            continue

    if not base_tx or w3 is None:
        return HttpResponse(f"Base transaction {tx_hash} not found on configured chains.", status=404)

    from_addr = base_tx.get("from")
    if not from_addr:
        return HttpResponse("Base transaction missing 'from' address.", status=400)

    # collect up to 10 txs (same loop as last10_from_tx)
    collected = []
    start_block = int(base_tx.get("blockNumber") or w3.eth.block_number)
    block_num = start_block
    scanned = 0
    safety_limit = 8000

    while block_num >= 0 and len(collected) < 10 and scanned < safety_limit:
        try:
            block = w3.eth.get_block(block_num, full_transactions=True)
        except Exception:
            block_num -= 1
            scanned += 1
            continue
        block_ts = getattr(block, "timestamp", None) or (block.get("timestamp") if isinstance(block, dict) else None)
        for t in (block.transactions or []):
            t_from = (t.get("from") if hasattr(t, "get") else getattr(t, "from", None))
            t_to = (t.get("to") if hasattr(t, "get") else getattr(t, "to", None))
            if not t_from:
                continue
            if (t_from and t_from.lower() == from_addr.lower()) or (t_to and t_to.lower() == from_addr.lower()):
                _hash = (t.hash.hex() if hasattr(t, "hash") and hasattr(t.hash, "hex") else (t.get("hash") if hasattr(t, "get") else None))
                try:
                    value_wei = int(t.get("value", 0) if hasattr(t, "get") else getattr(t, "value", 0) or 0)
                except Exception:
                    value_wei = 0
                value_eth = float(Web3.from_wei(value_wei, "ether"))
                gas = int(t.get("gas", 0) if hasattr(t, "get") else getattr(t, "gas", 0) or 0)
                ts = datetime.fromtimestamp(int(block_ts), tz=timezone.utc) if block_ts else None
                # try status
                status = "Unknown"
                try:
                    receipt = w3.eth.get_transaction_receipt(_hash)
                    status = "Success" if (getattr(receipt, "status", receipt.get("status")) == 1) else "Failed"
                except Exception:
                    status = "Unknown"
                tx_info = {
                    "hash": _hash,
                    "value_eth": value_eth,
                    "block": int(block_num),
                    "timestamp": ts,
                    "status": status,
                }
                collected.append(tx_info)
                if len(collected) >= 10:
                    break
        block_num -= 1
        scanned += 1

    if not collected:
        return HttpResponse(f"No transactions found for wallet {from_addr}.", status=404)

    collected_sorted = sorted(collected, key=lambda x: x["block"], reverse=True)[:10]

    # Generate PDF (plain-text-like)
    if not REPORTLAB_AVAILABLE:
        # fallback: return a plain text file
        lines = []
        lines.append(f"Last {len(collected_sorted)} transactions for {from_addr} (chain: {found_chain})")
        lines.append("")
        for tx in collected_sorted:
            ts = tx["timestamp"].isoformat() if tx["timestamp"] else "N/A"
            lines.append(f"Hash: {tx['hash']}")
            lines.append(f"Value (ETH): {tx['value_eth']}")
            lines.append(f"Block: {tx['block']}")
            lines.append(f"Time: {ts}")
            lines.append(f"Status: {tx['status']}")
            lines.append("-" * 40)
        body = "\n".join(lines)
        resp = HttpResponse(body, content_type="text/plain; charset=utf-8")
        resp["Content-Disposition"] = f'attachment; filename="last10_{from_addr[:8]}.txt"'
        return resp

    # Use reportlab to make a PDF
    buffer = BytesIO()
    c = rl_canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    margin_x = 40
    y = height - 40
    c.setFont("Courier", 10)
    c.drawString(margin_x, y, f"Last {len(collected_sorted)} transactions for {from_addr}  (chain: {found_chain})")
    y -= 20
    for tx in collected_sorted:
        if y < 80:
            c.showPage()
            c.setFont("Courier", 10)
            y = height - 40
        ts = tx["timestamp"].isoformat() if tx["timestamp"] else "N/A"
        c.drawString(margin_x, y, f"Hash: {tx['hash']}")
        y -= 14
        c.drawString(margin_x, y, f"Value (ETH): {tx['value_eth']}   Block: {tx['block']}   Time: {ts}")
        y -= 14
        c.drawString(margin_x, y, f"Status: {tx['status']}")
        y -= 18
        c.line(margin_x, y, width - margin_x, y)
        y -= 12

    c.showPage()
    c.save()
    pdf = buffer.getvalue()
    buffer.close()
    resp = HttpResponse(pdf, content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="last10_{from_addr[:8]}.pdf"'
    return resp


def about(request):
    return render(request, "about.html")