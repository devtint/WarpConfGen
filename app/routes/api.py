"""API routes for config generation and scanning."""
from __future__ import annotations

import ipaddress

import structlog
from fastapi import APIRouter, Form

from app.config import settings
from app.services.stats import increment_stats
from app.services.warp import generate_warp

logger = structlog.get_logger()

router = APIRouter(prefix="/api")

@router.get("/scanner/version")
async def scanner_version():
    """Returns the latest version of the WARP scanner script."""
    return {"version": "2.1"}


import base64
from fastapi.responses import PlainTextResponse

@router.get("/sub", response_class=PlainTextResponse)
async def api_sub(port: int = 500):
    """Subscription endpoint (returns Base64 encoded wireguard:// URI)."""
    try:
        # Use simple fast IP for subscription generation
        target_ip = settings.known_warp_ips[0]
        logger.info("subscription_requested", ip=target_ip, port=port)
        result = await generate_warp(target_ip, port)
        await increment_stats()
        
        # V2ray clients expect Base64 encoded text
        sub_text = base64.b64encode(result["uri"].encode("utf-8")).decode("utf-8")
        return sub_text
    except Exception as exc:
        logger.error("subscription_failed", error=str(exc))
        return base64.b64encode(f"error: {str(exc)}".encode("utf-8")).decode("utf-8")


from app.services.subscription import get_v2_subscription, update_v2_subscription
import uuid



@router.get("/v2sub/{sub_id}", response_class=PlainTextResponse)
async def api_v2_sub(sub_id: str):
    """Dynamic V2BOX subscription: Always generates a fresh config."""
    try:
        target_ip = settings.known_warp_ips[0]
        port = 500
        logger.info("v2_sub_requested", sub_id=sub_id)
        result = await generate_warp(target_ip, port)
        await increment_stats()
        
        # Save to DB for reference
        await update_v2_subscription(sub_id, result["uri"])

        # Return Base64 encoded URI for V2BOX/Shadowrocket
        return base64.b64encode(result["uri"].encode("utf-8")).decode("utf-8")
    except Exception as exc:
        logger.error("v2_sub_failed", sub_id=sub_id, error=str(exc))
        return PlainTextResponse(
            content=base64.b64encode(f"error: {str(exc)}".encode()).decode(),
            status_code=500,
        )



@router.post("/v2sub/update")
async def api_v2_update(sub_id: str = Form(None)):
    """Refresh or create a V2BOX subscription: Generates new WARP and saves it."""
    try:
        # Use a new ID if none provided
        target_id = sub_id if sub_id else str(uuid.uuid4())
        
        # Use simple fast IP for registration
        target_ip = settings.known_warp_ips[0]
        port = 500
        
        logger.info("v2_refresh_requested", sub_id=target_id)
        result = await generate_warp(target_ip, port)
        await increment_stats()
        
        # Save to DB
        await update_v2_subscription(target_id, result["uri"])
        
        return {
            "sub_id": target_id,
            "url": f"/api/v2sub/{target_id}",
            "config": result
        }
    except Exception as exc:
        logger.error("v2_refresh_failed", error=str(exc))
        return {"error": str(exc)}


@router.post("/generate")
async def api_generate(
    mode: str = Form("auto"),
    selected_ip: str = Form(""),
    custom_ip: str = Form(""),
    port: int = Form(500),
):
    """Generate a WARP WireGuard configuration."""
    try:
        target_ip = ""
        if mode == "auto":
            target_ip = settings.known_warp_ips[0]
        elif mode == "select":
            target_ip = selected_ip if selected_ip else settings.known_warp_ips[0]
        else:
            target_ip = custom_ip.strip()
            if not target_ip:
                return {"error": "Custom IP required"}
            ipaddress.ip_address(target_ip)

        logger.info("generation_requested", mode=mode, ip=target_ip, port=port)
        result = await generate_warp(target_ip, port)
        await increment_stats()
        return result
    except ValueError as exc:
        logger.warning("invalid_ip_input", custom_ip=custom_ip, error=str(exc))
        return {"error": f"Invalid IP address: {custom_ip}"}
    except Exception as exc:
        logger.error("generation_failed", mode=mode, error=str(exc))
        return {"error": str(exc)}
