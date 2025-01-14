#pragma once

#include <algorithm> // For std::shuffle
#include <random>    // For std::default_random_engine
#include <vector>

#include "envoy/common/time.h"

#include "source/common/common/thread.h"

#include "absl/container/flat_hash_map.h"
#include "absl/types/optional.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ExtAuthz {

/**
  A simple cache class with TTL.
  It has a random subset eviction policy. This is memory efficient because it does not need to store
  the order of elements. It restricts stored values to 16-bit unsigned integers, making it
  memory efficient.
 */
class FIFOEvictionCache {
public:
  // Constructor creates multiple buckets and mutexes, each of which is used to lock a subset of
  // cache items. Given a key, we can specify which mutex and which bucket to use.
  FIFOEvictionCache(std::size_t max_size, int default_ttl_seconds, std::size_t num_mutexes,
                    Envoy::TimeSource& time_source)
      : max_cache_size(max_size), default_ttl_seconds(default_ttl_seconds),
        num_mutexes_(num_mutexes), time_source_(time_source), mutexes_(num_mutexes),
        cache_buckets_(num_mutexes) {}

  // Destructor frees all allocated buckets.
  ~FIFOEvictionCache() {
    for (auto& bucket : cache_buckets_) {
      for (auto& pair : bucket) {
        free(const_cast<char*>(pair.first));
      }
    }
  }

  bool Insert(const char* key, uint16_t value, int ttl_seconds = -1) {
    // Find the mutex and bucket for the key
    auto& mutex = getMutexForKey(key);
    Thread::LockGuard lock{mutex};
    auto& bucket = getBucketForKey(key);

    const char* c_key = strdup(key);
    if (ttl_seconds == -1) {
      ttl_seconds = default_ttl_seconds;
    }
    auto expiration_time = time_source_.monotonicTime() + std::chrono::seconds(ttl_seconds);
    CacheItem item = {value, expiration_time};
    auto it = bucket.find(c_key);
    if (it == bucket.end()) {
      if (bucket.size() >= max_cache_size / num_mutexes_) {
        Evict(bucket);
      }
      bucket[c_key] = item;
    } else {
      bucket[c_key] = item;
    }
    return true;
  }

  bool Erase(const char* key) {
    // Find the mutex and bucket for the key
    auto& mutex = getMutexForKey(key);
    Thread::LockGuard lock{mutex};
    auto& bucket = getBucketForKey(key);
    auto it = bucket.find(key);
    if (it != bucket.end()) {
      free(const_cast<char*>(it->first));
      bucket.erase(it);
      return true;
    }
    return false;
  }

  absl::optional<uint16_t> Get(const char* key) {
    // Find the mutex and bucket for the key
    auto& mutex = getMutexForKey(key);
    Thread::LockGuard lock{mutex};
    auto& bucket = getBucketForKey(key);
    auto it = bucket.find(key);
    if (it != bucket.end()) {
      if (time_source_.monotonicTime() < it->second.expiration_time) {
        return it->second.value;
      } else {
        // Item has expired
        free(const_cast<char*>(it->first));
        bucket.erase(it);
      }
    }
    return absl::nullopt;
  }

  // Don't call this function lightly, as it's expensive and inaccurate.
  size_t Size() const {
    size_t total_size = 0;
    for (std::size_t i = 0; i < num_mutexes_; ++i) {
      Thread::LockGuard lock(mutexes_[i]);
      total_size += cache_buckets_[i].size();
    }
    return total_size;
  }

private:
  struct CacheItem {
    uint16_t value;
    std::chrono::steady_clock::time_point expiration_time;
  };

  struct CharPtrHash {
    std::size_t operator()(const char* str) const {
      std::size_t hash = 0;
      while (*str) {
        hash = hash * 101 + *str++;
      }
      return hash;
    }
  };

  struct CharPtrEqual {
    bool operator()(const char* lhs, const char* rhs) const { return std::strcmp(lhs, rhs) == 0; }
  };

  // Remove first 0.1% of max_cache_size objects from the given bucket.
  // We may want to implement a more sophisticated eviction policy in the future.
  void Evict(absl::flat_hash_map<const char*, CacheItem, CharPtrHash, CharPtrEqual>& bucket) {
    size_t items_to_remove = (max_cache_size / num_mutexes_) / 1000;
    for (auto it = bucket.begin(); it != bucket.end() && items_to_remove > 0;) {
      auto to_delete = it++;
      free(const_cast<char*>(to_delete->first));
      bucket.erase(to_delete);
      --items_to_remove;
    }
  }

  // Use multiple mutexes for sharded locking. This improves performance & scalability by reducing
  // synchronization among worker threads.
  std::size_t max_cache_size;
  int default_ttl_seconds;
  std::size_t num_mutexes_;
  Envoy::TimeSource& time_source_; // Reference to TimeSource

  mutable std::vector<Thread::MutexBasicLockable> mutexes_;
  mutable std::vector<absl::flat_hash_map<const char*, CacheItem, CharPtrHash, CharPtrEqual>>
      cache_buckets_;

  absl::flat_hash_map<const char*, CacheItem, CharPtrHash, CharPtrEqual>&
  getBucketForKey(const char* key) const {
    std::size_t hash = CharPtrHash{}(key);
    return cache_buckets_[hash % num_mutexes_];
  }

  Thread::MutexBasicLockable& getMutexForKey(const char* key) const {
    std::size_t hash = CharPtrHash{}(key);
    std::cout << "hash: " << hash << " mutex ID: " << hash % num_mutexes_ << std::endl;
    return mutexes_[hash % num_mutexes_];
  }
};

} // namespace ExtAuthz
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
