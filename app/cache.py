import json
import pickle
from typing import Any, Optional, Union
from datetime import timedelta
import redis
from cachetools import TTLCache, LRUCache

from .config import settings

class CacheService:
    
    def __init__(self):
        self.redis_client = None
        self.use_redis = settings.cache.enable_cache
        
        
        if self.use_redis:
            try:
                self.redis_client = redis.from_url(
                    settings.cache.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                
                self.redis_client.ping()
                self.redis_available = True
            except Exception as e:
                print(f"Redis connection failed, falling back to in-memory cache: {e}")
                self.redis_available = False
        else:
            self.redis_available = False
        
      
        self.memory_cache = TTLCache(
            maxsize=1000,
            ttl=settings.cache.cache_ttl_seconds
        )
        
        self.lru_cache = LRUCache(maxsize=500)
    
    def _serialize(self, value: Any) -> str:
      
        try:
            return json.dumps(value, default=str)
        except (TypeError, ValueError):
            return pickle.dumps(value).hex()
    
    def _deserialize(self, value: str) -> Any:
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            try:
                return pickle.loads(bytes.fromhex(value))
            except:
                return value
    
    def get(self, key: str, default: Any = None) -> Any:
        if self.redis_available:
            try:
                value = self.redis_client.get(key)
                if value is not None:
                    return self._deserialize(value)
            except Exception:
                pass
        
        if key in self.memory_cache:
            return self.memory_cache[key]
        
        
        if key in self.lru_cache:
            return self.lru_cache[key]
        
        return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        serialized_value = self._serialize(value)
        ttl = ttl or settings.cache.cache_ttl_seconds
        
        if self.redis_available:
            try:
                self.redis_client.setex(key, ttl, serialized_value)
                return True
            except Exception:
                pass
        
        self.memory_cache[key] = value
        return True
    
    def delete(self, key: str) -> bool:
        success = False
        
       
        if self.redis_available:
            try:
                self.redis_client.delete(key)
                success = True
            except Exception:
                pass
        
        self.memory_cache.pop(key, None)
        self.lru_cache.pop(key, None)
        
        return success
    
    def exists(self, key: str) -> bool:
      
        
        if self.redis_available:
            try:
                return bool(self.redis_client.exists(key))
            except Exception:
                pass
        
        return key in self.memory_cache or key in self.lru_cache
    
    def expire(self, key: str, ttl: int) -> bool:
        if self.redis_available:
            try:
                return bool(self.redis_client.expire(key, ttl))
            except Exception:
                pass
        return False
    
    def clear(self) -> bool:
        success = True
        
        if self.redis_available:
            try:
                self.redis_client.flushdb()
            except Exception:
                success = False
        
        self.memory_cache.clear()
        self.lru_cache.clear()
        
        return success
    
    def get_stats(self) -> dict:
        stats = {
            "redis_available": self.redis_available,
            "memory_cache_size": len(self.memory_cache),
            "lru_cache_size": len(self.lru_cache),
            "use_redis": self.use_redis
        }
        
        if self.redis_available:
            try:
                info = self.redis_client.info()
                stats.update({
                    "redis_connected_clients": info.get("connected_clients", 0),
                    "redis_used_memory": info.get("used_memory", 0),
                    "redis_keyspace_hits": info.get("keyspace_hits", 0),
                    "redis_keyspace_misses": info.get("keyspace_misses", 0)
                })
            except Exception:
                pass
        
        return stats


cache_service = CacheService()


def get_cache_service() -> CacheService:
    
    return cache_service


class CacheDecorator:
    
    def __init__(self, ttl: Optional[int] = None, key_prefix: str = ""):
        self.ttl = ttl or settings.cache.cache_ttl_seconds
        self.key_prefix = key_prefix
    
    def __call__(self, func):
        def wrapper(*args, **kwargs):
            
            cache_key = f"{self.key_prefix}:{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
            
            
            cached_result = cache_service.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            result = func(*args, **kwargs)
            cache_service.set(cache_key, result, self.ttl)
            
            return result
        
        return wrapper



cache_prediction = CacheDecorator(ttl=300, key_prefix="prediction")  # 5 minutes
cache_model_info = CacheDecorator(ttl=3600, key_prefix="model")  # 1 hour
cache_user_data = CacheDecorator(ttl=1800, key_prefix="user")  # 30 minutes 