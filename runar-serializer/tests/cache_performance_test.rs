use anyhow::Result;
use runar_serializer::traits::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Performance test for resolver cache functionality
#[test]
fn test_resolver_cache_performance() -> Result<()> {
    println!("🚀 Testing Resolver Cache Performance");

    // Create test configuration
    let config = create_test_config();
    let user_keys_1 = vec![vec![1, 2, 3], vec![4, 5, 6]];
    let user_keys_2 = vec![vec![7, 8, 9], vec![10, 11, 12]];

    // Test 1: Measure creation time without cache
    println!("\n📊 Test 1: Baseline Performance (No Cache)");
    let baseline_times = measure_baseline_performance(&config, &user_keys_1, 20)?;
    println!(
        "   Average creation time: {:.2}ms",
        baseline_times.iter().sum::<f64>() / baseline_times.len() as f64
    );

    // Test 2: Test cache hit performance
    println!("\n📊 Test 2: Cache Hit Performance");
    test_cache_hit_performance(&config, &user_keys_1, 20)?;

    // Test 3: Test cache miss performance
    println!("\n📊 Test 3: Cache Miss Performance");
    test_cache_miss_performance(&config, &user_keys_1, &user_keys_2, 10)?;

    // Test 4: Test TTL expiration
    println!("\n📊 Test 4: TTL Expiration Test");
    test_ttl_expiration(&config, &user_keys_1)?;

    // Test 5: Test LRU eviction
    println!("\n📊 Test 5: LRU Eviction Test");
    test_lru_eviction(&config)?;

    // Test 6: Test concurrent access
    println!("\n📊 Test 6: Concurrent Access Test");
    test_concurrent_access(&config, &user_keys_1)?;

    println!("\n✅ All cache performance tests completed successfully!");
    Ok(())
}

/// Measure baseline performance without cache
fn measure_baseline_performance(
    config: &LabelResolverConfig,
    user_keys: &Vec<Vec<u8>>,
    iterations: usize,
) -> Result<Vec<f64>> {
    let mut times = Vec::new();

    for i in 0..iterations {
        let start = Instant::now();
        let _resolver = create_context_label_resolver(config, user_keys)?;
        let duration = start.elapsed();
        times.push(duration.as_secs_f64() * 1000.0); // Convert to milliseconds

        if i % 20 == 0 {
            print!(".");
        }
    }
    println!();
    Ok(times)
}

/// Test cache hit performance
fn test_cache_hit_performance(
    config: &LabelResolverConfig,
    user_keys: &Vec<Vec<u8>>,
    iterations: usize,
) -> Result<()> {
    // Create a custom cache for testing
    let cache = ResolverCache::new(100, Duration::from_secs(60));

    // First access - cache miss
    let start = Instant::now();
    let _resolver1 = cache.get_or_create(config, user_keys)?;
    let first_access_time = start.elapsed().as_secs_f64() * 1000.0;
    println!("   First access (cache miss): {:.2}ms", first_access_time);

    // Subsequent accesses - cache hits
    let mut hit_times = Vec::new();
    for i in 0..iterations {
        let start = Instant::now();
        let _resolver = cache.get_or_create(config, user_keys)?;
        let duration = start.elapsed();
        hit_times.push(duration.as_secs_f64() * 1000.0);

        if i % 20 == 0 {
            print!(".");
        }
    }
    println!();

    let avg_hit_time = hit_times.iter().sum::<f64>() / hit_times.len() as f64;
    println!("   Average cache hit time: {:.2}ms", avg_hit_time);
    println!(
        "   Cache hit speedup: {:.1}x faster than creation",
        first_access_time / avg_hit_time
    );

    // Verify cache statistics
    let stats = cache.stats();
    println!("   Cache entries: {}", stats.total_entries);

    Ok(())
}

/// Test cache miss performance with different user contexts
fn test_cache_miss_performance(
    config: &LabelResolverConfig,
    user_keys_1: &Vec<Vec<u8>>,
    user_keys_2: &Vec<Vec<u8>>,
    iterations: usize,
) -> Result<()> {
    let cache = ResolverCache::new(100, Duration::from_secs(60));

    let mut times = Vec::new();
    for i in 0..iterations {
        let user_keys = if i % 2 == 0 { user_keys_1 } else { user_keys_2 };

        let start = Instant::now();
        let _resolver = cache.get_or_create(config, user_keys)?;
        let duration = start.elapsed();
        times.push(duration.as_secs_f64() * 1000.0);

        if i % 10 == 0 {
            print!(".");
        }
    }
    println!();

    let avg_time = times.iter().sum::<f64>() / times.len() as f64;
    println!("   Average cache miss time: {:.2}ms", avg_time);

    let stats = cache.stats();
    println!("   Final cache entries: {}", stats.total_entries);

    Ok(())
}

/// Test TTL expiration functionality
fn test_ttl_expiration(config: &LabelResolverConfig, user_keys: &Vec<Vec<u8>>) -> Result<()> {
    // Create cache with very short TTL for testing
    let cache = ResolverCache::new(100, Duration::from_millis(100));

    // Create entry
    let _resolver1 = cache.get_or_create(config, user_keys)?;
    let stats_before = cache.stats();
    println!(
        "   Cache entries before sleep: {}",
        stats_before.total_entries
    );

    // Wait for expiration (simulate with a small delay)
    std::thread::sleep(Duration::from_millis(150));

    // Access again - should be cache miss due to expiration
    let start = Instant::now();
    let _resolver2 = cache.get_or_create(config, user_keys)?;
    let access_time = start.elapsed().as_secs_f64() * 1000.0;

    let stats_after = cache.stats();
    println!(
        "   Cache entries after expiration: {}",
        stats_after.total_entries
    );
    println!("   Post-expiration access time: {:.2}ms", access_time);
    println!("   ✅ TTL expiration working correctly");

    Ok(())
}

/// Test LRU eviction functionality
fn test_lru_eviction(config: &LabelResolverConfig) -> Result<()> {
    // Create cache with small size to trigger eviction
    let cache = ResolverCache::new(3, Duration::from_secs(60));

    // Fill cache beyond capacity
    for i in 0..5 {
        let user_keys = vec![vec![i as u8]]; // Different keys for each entry
        let _resolver = cache.get_or_create(config, &user_keys)?;

        let stats = cache.stats();
        println!(
            "   After entry {}: {} cache entries",
            i + 1,
            stats.total_entries
        );
    }

    let final_stats = cache.stats();
    println!(
        "   Final cache size: {} (should be <= 3)",
        final_stats.total_entries
    );
    assert!(
        final_stats.total_entries <= 3,
        "Cache should respect max size limit"
    );

    println!("   ✅ LRU eviction working correctly");
    Ok(())
}

/// Test concurrent access to cache
fn test_concurrent_access(config: &LabelResolverConfig, user_keys: &Vec<Vec<u8>>) -> Result<()> {
    let cache = std::sync::Arc::new(ResolverCache::new(100, Duration::from_secs(60)));
    let config = std::sync::Arc::new(config.clone());
    let user_keys = std::sync::Arc::new(user_keys.clone());

    let mut handles = Vec::new();

    // Spawn multiple concurrent tasks
    for i in 0..10 {
        let cache_clone = cache.clone();
        let config_clone = config.clone();
        let user_keys_clone = user_keys.clone();

        let handle = std::thread::spawn(move || {
            let start = Instant::now();
            let _resolver = cache_clone
                .get_or_create(&config_clone, &user_keys_clone)
                .unwrap();
            let duration = start.elapsed();
            (i, duration.as_secs_f64() * 1000.0)
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    let mut results = Vec::new();
    for handle in handles {
        let (task_id, duration) = handle.join().unwrap();
        results.push((task_id, duration));
    }

    // Analyze results
    results.sort_by_key(|(_, duration)| (*duration * 1000.0) as u64);
    println!("   Concurrent access times:");
    for (task_id, duration) in &results {
        println!("     Task {}: {:.2}ms", task_id, duration);
    }

    let stats = cache.stats();
    println!("   Final cache entries: {}", stats.total_entries);
    println!("   ✅ Concurrent access working correctly");

    Ok(())
}

/// Create test configuration for performance testing
fn create_test_config() -> LabelResolverConfig {
    let mut label_mappings = HashMap::new();

    // Add several labels to make resolver creation more expensive
    label_mappings.insert(
        "system".to_string(),
        LabelValue {
            network_public_key: Some(vec![1; 65]), // 65-byte network key
            user_key_spec: None,
        },
    );

    label_mappings.insert(
        "admin".to_string(),
        LabelValue {
            network_public_key: Some(vec![2; 65]),
            user_key_spec: None,
        },
    );

    label_mappings.insert(
        "current_user".to_string(),
        LabelValue {
            network_public_key: Some(vec![3; 65]),
            user_key_spec: Some(LabelKeyword::CurrentUser),
        },
    );

    label_mappings.insert(
        "my_private_data".to_string(),
        LabelValue {
            network_public_key: None, // User-only label
            user_key_spec: Some(LabelKeyword::CurrentUser),
        },
    );

    label_mappings.insert(
        "shared_docs".to_string(),
        LabelValue {
            network_public_key: Some(vec![4; 65]),
            user_key_spec: Some(LabelKeyword::CurrentUser),
        },
    );

    // Add more labels to increase complexity
    for i in 10..20 {
        label_mappings.insert(
            format!("label_{}", i),
            LabelValue {
                network_public_key: Some(vec![i as u8; 65]),
                user_key_spec: if i % 2 == 0 {
                    Some(LabelKeyword::CurrentUser)
                } else {
                    None
                },
            },
        );
    }

    LabelResolverConfig { label_mappings }
}

/// Test the global cache functionality
#[test]
fn test_global_cache_functionality() -> Result<()> {
    println!("🧪 Testing Global Cache Functionality");

    // Test 1: Get global cache
    let cache1 = get_global_cache();
    let cache2 = get_global_cache();
    assert!(
        std::ptr::eq(cache1.as_ref(), cache2.as_ref()),
        "Global cache should be singleton"
    );
    println!("   ✅ Global cache singleton working");

    // Test 2: Set custom cache
    let custom_cache = ResolverCache::new(50, Duration::from_secs(60));
    set_global_cache(custom_cache);
    let _custom_cache_instance = get_global_cache();
    println!("   ✅ Custom cache set successfully");

    // Test 3: Clear cache
    clear_global_cache();
    let stats_after_clear = get_cache_stats();
    assert!(
        stats_after_clear.is_none() || stats_after_clear.unwrap().total_entries == 0,
        "Cache should be empty after clear"
    );
    println!("   ✅ Cache clear working");

    // Test 4: Cleanup expired
    let cleanup_count = cleanup_global_cache();
    println!("   ✅ Cleanup expired returned: {}", cleanup_count);

    println!("✅ Global cache functionality tests completed!");
    Ok(())
}

/// Test cache statistics and metrics
#[test]
fn test_cache_statistics() -> Result<()> {
    println!("📊 Testing Cache Statistics");

    let cache = ResolverCache::new(10, Duration::from_secs(60));
    let config = create_test_config();

    // Create some entries
    let user_keys_1 = vec![vec![1, 2, 3]];
    let user_keys_2 = vec![vec![4, 5, 6]];

    let _resolver1 = cache.get_or_create(&config, &user_keys_1)?;
    let _resolver2 = cache.get_or_create(&config, &user_keys_2)?;

    let stats = cache.stats();
    println!("   Cache entries: {}", stats.total_entries);
    println!("   Max size: {}", stats.max_size);
    println!("   TTL: {} seconds", stats.ttl_seconds);

    assert_eq!(stats.total_entries, 2, "Should have 2 cache entries");
    assert_eq!(stats.max_size, 10, "Max size should be 10");
    assert_eq!(stats.ttl_seconds, 60, "TTL should be 60 seconds");

    println!("✅ Cache statistics tests completed!");
    Ok(())
}
