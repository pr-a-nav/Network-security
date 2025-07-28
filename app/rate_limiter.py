import time
from typing import Dict, Tuple, Optional
from fastapi import HTTPException, Request
from collections import defaultdict, deque
import asyncio

from .config import settings
from .cache import get_cache_service


class RateLimiter:
    
    def __init__(self):
        self.cache = get_cache_service()
        self.enable_rate_limiting = settings.rate_limit.enable_rate_limiting
        self.requests_per_minute = settings.rate_limit.requests_per_minute
        self.burst_size = settings.rate_limit.burst_size
        
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque())
        self.lock = asyncio.Lock()
    
    def _get_client_identifier(self, request: Request) -> str:
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"api_key:{api_key[:16]}"
        
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            return f"jwt:{token[:16]}"
        
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"
    
    def _clean_old_requests(self, client_id: str, window_seconds: int = 60):
        current_time = time.time()
        history = self.request_history[client_id]
        
        while history and current_time - history[0] > window_seconds:
            history.popleft()
    
    async def check_rate_limit(self, request: Request) -> Tuple[bool, Dict[str, int]]:
        if not self.enable_rate_limiting:
            return True, {}
        
        client_id = self._get_client_identifier(request)
        
        async with self.lock:
            current_time = time.time()
            
            self._clean_old_requests(client_id)
            
            request_count = len(self.request_history[client_id])
            
            if request_count >= self.requests_per_minute:
                if request_count >= self.requests_per_minute + self.burst_size:
                    return False, {
                        "limit": self.requests_per_minute,
                        "burst": self.burst_size,
                        "current": request_count,
                        "reset_time": int(current_time + 60)
                    }
            
            self.request_history[client_id].append(current_time)
            
            return True, {
                "limit": self.requests_per_minute,
                "burst": self.burst_size,
                "current": request_count + 1,
                "remaining": max(0, self.requests_per_minute - request_count - 1)
            }
    
    def get_rate_limit_headers(self, limit_info: Dict[str, int]) -> Dict[str, str]:
        return {
            "X-RateLimit-Limit": str(limit_info.get("limit", 0)),
            "X-RateLimit-Remaining": str(limit_info.get("remaining", 0)),
            "X-RateLimit-Reset": str(limit_info.get("reset_time", 0))
        }


class RateLimitMiddleware:
    
    def __init__(self, app):
        self.app = app
        self.rate_limiter = RateLimiter()
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        allowed, limit_info = await self.rate_limiter.check_rate_limit(request)
        
        if not allowed:
            response_body = {
                "error": "Rate limit exceeded",
                "message": "Too many requests",
                "retry_after": 60
            }
            
            response_headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(str(response_body))).encode()),
            ]
            
            rate_limit_headers = self.rate_limiter.get_rate_limit_headers(limit_info)
            for key, value in rate_limit_headers.items():
                response_headers.append((key.lower().encode(), value.encode()))
            
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": response_headers
            })
            
            await send({
                "type": "http.response.body",
                "body": str(response_body).encode()
            })
            return
        
        async def custom_send(message):
            if message["type"] == "http.response.start":
                rate_limit_headers = self.rate_limiter.get_rate_limit_headers(limit_info)
                for key, value in rate_limit_headers.items():
                    message["headers"].append((key.lower().encode(), value.encode()))
            
            await send(message)
        
        await self.app(scope, receive, custom_send)


class RateLimitDependency:
    
    def __init__(self, requests_per_minute: Optional[int] = None, burst_size: Optional[int] = None):
        self.requests_per_minute = requests_per_minute or settings.rate_limit.requests_per_minute
        self.burst_size = burst_size or settings.rate_limit.burst_size
        self.rate_limiter = RateLimiter()
    
    async def __call__(self, request: Request):
        allowed, limit_info = await self.rate_limiter.check_rate_limit(request)
        
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Rate limit exceeded",
                    "limit": limit_info.get("limit"),
                    "current": limit_info.get("current"),
                    "retry_after": 60
                }
            )
        
        return limit_info



standard_rate_limit = RateLimitDependency(requests_per_minute=100, burst_size=20)
strict_rate_limit = RateLimitDependency(requests_per_minute=10, burst_size=5)
prediction_rate_limit = RateLimitDependency(requests_per_minute=50, burst_size=10) 