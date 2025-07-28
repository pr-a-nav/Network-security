from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from typing import List, Dict, Any, Optional
import json
import asyncio
from datetime import datetime

from ..network_capture import get_network_capture_service, get_pyshark_capture_service
from ..real_time_processor import get_real_time_processor
from ..auth import get_current_user_optional, require_active_user
from ..database import get_db
from ..monitoring import logger
from ..config import settings

router = APIRouter(prefix="/capture", tags=["Network Capture"])


@router.get("/interfaces")
async def get_network_interfaces():
    """Get available network interfaces"""
    capture_service = get_network_capture_service()
    return {
        "interfaces": capture_service.available_interfaces,
        "default_interface": capture_service._get_default_interface()
    }


@router.post("/start")
async def start_capture(
    interface: Optional[str] = None,
    filter: Optional[str] = None,
    max_packets: Optional[int] = 1000000,
    user=Depends(get_current_user_optional)
):
    """Start network packet capture"""
    try:
        capture_service = get_network_capture_service()
        
        if capture_service.is_capturing:
            raise HTTPException(status_code=400, detail="Capture already running")
        
        success = capture_service.start_capture(interface, filter, max_packets)
        
        if success:
            logger.info(f"Network capture started by user {user.username if user else 'anonymous'}")
            return {
                "message": "Network capture started successfully",
                "interface": capture_service.interface,
                "filter": capture_service.filter,
                "max_packets": capture_service.max_packets
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to start capture")
            
    except Exception as e:
        logger.error(f"Error starting capture: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_capture(user=Depends(get_current_user_optional)):
    """Stop network packet capture"""
    try:
        capture_service = get_network_capture_service()
        
        if not capture_service.is_capturing:
            raise HTTPException(status_code=400, detail="No capture running")
        
        capture_service.stop_capture()
        
        logger.info(f"Network capture stopped by user {user.username if user else 'anonymous'}")
        return {"message": "Network capture stopped successfully"}
        
    except Exception as e:
        logger.error(f"Error stopping capture: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_capture_status():
    """Get current capture status and statistics"""
    capture_service = get_network_capture_service()
    return {
        "capture_status": capture_service.get_statistics(),
        "network_info": capture_service.get_network_info()
    }


@router.post("/realtime/start")
async def start_realtime_processing(
    interface: Optional[str] = None,
    filter: Optional[str] = None,
    user=Depends(require_active_user)
):
    """Start real-time processing with ML model"""
    try:
        processor = get_real_time_processor()
        
        if processor.is_processing:
            raise HTTPException(status_code=400, detail="Real-time processing already running")
        
        success = processor.start_processing(interface, filter)
        
        if success:
            logger.info(f"Real-time processing started by user {user.username}")
            return {
                "message": "Real-time processing started successfully",
                "interface": processor.capture_service.interface,
                "filter": processor.capture_service.filter
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to start real-time processing")
            
    except Exception as e:
        logger.error(f"Error starting real-time processing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/realtime/stop")
async def stop_realtime_processing(user=Depends(require_active_user)):
    """Stop real-time processing"""
    try:
        processor = get_real_time_processor()
        
        if not processor.is_processing:
            raise HTTPException(status_code=400, detail="No real-time processing running")
        
        processor.stop_processing()
        
        logger.info(f"Real-time processing stopped by user {user.username}")
        return {"message": "Real-time processing stopped successfully"}
        
    except Exception as e:
        logger.error(f"Error stopping real-time processing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/realtime/status")
async def get_realtime_status():
    """Get real-time processing status and statistics"""
    processor = get_real_time_processor()
    return {
        "processing_status": processor.get_statistics(),
        "capture_status": processor.capture_service.get_statistics()
    }


@router.get("/realtime/anomalies")
async def get_recent_anomalies(limit: int = 100):
    """Get recent anomalies detected by real-time processing"""
    try:
        db = next(get_db())
        
        # Get recent predictions that are anomalies
        anomalies = db.query(Prediction).filter(
            Prediction.prediction == True
        ).order_by(
            Prediction.created_at.desc()
        ).limit(limit).all()
        
        result = []
        for anomaly in anomalies:
            # Get associated network traffic
            network_traffic = anomaly.network_traffic
            
            result.append({
                "id": anomaly.id,
                "timestamp": anomaly.created_at.isoformat(),
                "source_ip": network_traffic.source_ip,
                "destination_ip": network_traffic.destination_ip,
                "protocol": network_traffic.protocol,
                "confidence_score": anomaly.confidence_score,
                "anomaly_score": anomaly.anomaly_score,
                "processing_time_ms": anomaly.processing_time_ms
            })
        
        return {"anomalies": result, "count": len(result)}
        
    except Exception as e:
        logger.error(f"Error getting recent anomalies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.websocket("/ws/live")
async def websocket_live_capture(websocket: WebSocket):
    """WebSocket endpoint for live packet streaming"""
    await websocket.accept()
    
    try:
        # Add callback to capture service
        capture_service = get_network_capture_service()
        
        async def send_packet(packet):
            """Send packet data to WebSocket client"""
            try:
                packet_data = {
                    "type": "packet",
                    "timestamp": packet.timestamp.isoformat(),
                    "source_ip": packet.source_ip,
                    "destination_ip": packet.destination_ip,
                    "protocol": packet.protocol,
                    "packet_size": packet.packet_size
                }
                await websocket.send_text(json.dumps(packet_data))
            except Exception as e:
                logger.error(f"Error sending packet to WebSocket: {e}")
        
        # Register callback
        capture_service.add_callback(lambda p: asyncio.create_task(send_packet(p)))
        
        # Send initial status
        await websocket.send_text(json.dumps({
            "type": "status",
            "message": "Connected to live capture stream"
        }))
        
        # Keep connection alive
        while True:
            try:
                # Wait for client messages (ping/pong)
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                break
                
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()


@router.websocket("/ws/anomalies")
async def websocket_anomaly_stream(websocket: WebSocket):
    """WebSocket endpoint for live anomaly streaming"""
    await websocket.accept()
    
    try:
        processor = get_real_time_processor()
        
        async def send_anomaly(packet, prediction):
            """Send anomaly data to WebSocket client"""
            try:
                anomaly_data = {
                    "type": "anomaly",
                    "timestamp": datetime.utcnow().isoformat(),
                    "source_ip": packet.source_ip,
                    "destination_ip": packet.destination_ip,
                    "protocol": packet.protocol,
                    "confidence_score": prediction.get('confidence', 0.0),
                    "anomaly_score": prediction.get('anomaly_score', 0.0),
                    "severity": "HIGH" if prediction.get('confidence', 0.0) > 0.8 else "MEDIUM"
                }
                await websocket.send_text(json.dumps(anomaly_data))
            except Exception as e:
                logger.error(f"Error sending anomaly to WebSocket: {e}")
        
        # Register callback
        processor.add_anomaly_callback(lambda p, pred: asyncio.create_task(send_anomaly(p, pred)))
        
        # Send initial status
        await websocket.send_text(json.dumps({
            "type": "status",
            "message": "Connected to anomaly stream"
        }))
        
        # Keep connection alive
        while True:
            try:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                break
                
    except Exception as e:
        logger.error(f"Anomaly WebSocket error: {e}")
    finally:
        await websocket.close()


@router.get("/stream/packets")
async def stream_packets():
    """Stream packets as Server-Sent Events"""
    async def generate():
        capture_service = get_network_capture_service()
        
        def packet_callback(packet):
            """Callback for packet streaming"""
            packet_data = {
                "timestamp": packet.timestamp.isoformat(),
                "source_ip": packet.source_ip,
                "destination_ip": packet.destination_ip,
                "protocol": packet.protocol,
                "packet_size": packet.packet_size
            }
            return f"data: {json.dumps(packet_data)}\n\n"
        
        # Register callback
        capture_service.add_callback(packet_callback)
        
        # Send initial message
        yield "data: {\"type\": \"connected\"}\n\n"
        
        # Keep stream alive
        while capture_service.is_capturing:
            await asyncio.sleep(1)
            yield "data: {\"type\": \"heartbeat\"}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/plain",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
    )


@router.get("/filters")
async def get_available_filters():
    """Get available BPF filters for packet capture"""
    return {
        "filters": [
            {
                "name": "All TCP traffic",
                "filter": "tcp",
                "description": "Capture all TCP packets"
            },
            {
                "name": "All UDP traffic",
                "filter": "udp",
                "description": "Capture all UDP packets"
            },
            {
                "name": "HTTP traffic",
                "filter": "port 80 or port 443",
                "description": "Capture HTTP and HTTPS traffic"
            },
            {
                "name": "DNS traffic",
                "filter": "port 53",
                "description": "Capture DNS queries and responses"
            },
            {
                "name": "SSH traffic",
                "filter": "port 22",
                "description": "Capture SSH connections"
            },
            {
                "name": "ICMP traffic",
                "filter": "icmp",
                "description": "Capture ICMP packets (ping, etc.)"
            },
            {
                "name": "ARP traffic",
                "filter": "arp",
                "description": "Capture ARP requests and responses"
            },
            {
                "name": "Large packets",
                "filter": "greater 1500",
                "description": "Capture packets larger than 1500 bytes"
            },
            {
                "name": "Specific IP",
                "filter": "host 192.168.1.1",
                "description": "Capture traffic to/from specific IP (replace with target IP)"
            },
            {
                "name": "Port range",
                "filter": "portrange 8000-9000",
                "description": "Capture traffic on specific port range"
            }
        ]
    }


@router.post("/filters/custom")
async def test_custom_filter(
    filter: str,
    duration: int = 10,
    user=Depends(require_active_user)
):
    """Test a custom BPF filter for a short duration"""
    try:
        capture_service = get_network_capture_service()
        
        if capture_service.is_capturing:
            raise HTTPException(status_code=400, detail="Another capture is running")
        
        # Start capture with custom filter
        success = capture_service.start_capture(filter=filter, max_packets=1000)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to start test capture")
        
        # Wait for specified duration
        await asyncio.sleep(min(duration, 30))  # Max 30 seconds
        
        # Stop capture
        capture_service.stop_capture()
        
        # Get statistics
        stats = capture_service.get_statistics()
        
        return {
            "message": "Filter test completed",
            "filter": filter,
            "duration_seconds": duration,
            "packets_captured": stats['packets_captured'],
            "protocol_statistics": stats['protocol_statistics']
        }
        
    except Exception as e:
        logger.error(f"Error testing custom filter: {e}")
        raise HTTPException(status_code=500, detail=str(e)) 