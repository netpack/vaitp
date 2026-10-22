#!/usr/bin/env python3
"""
Performance optimizations for the agentic feedback loop enhancement.

This module provides optimized implementations and utilities for:
1. Database query optimization with additional indexes
2. Batch processing utilities
3. Memory-efficient code processing
4. Caching mechanisms for repeated calculations
"""

import sqlite3
import logging
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from functools import lru_cache
from datetime import datetime, timedelta
from config import DB_PATH


class DatabaseOptimizer:
    """Optimizes database performance with additional indexes and query optimization."""
    
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
    
    def create_performance_indexes(self) -> bool:
        """
        Create additional indexes to optimize common query patterns.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Index for filtering by model and vulnerability type (common query pattern)
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_runs_model_vuln 
            ON comparative_analysis_runs(model_name, vulnerability_type)
            ''')
            
            # Index for filtering by timestamp (for recent runs queries)
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_runs_timestamp 
            ON comparative_analysis_runs(run_timestamp)
            ''')
            
            # Index for filtering by success status
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_runs_semantic_status 
            ON comparative_analysis_runs(semantic_confirmation_status)
            ''')
            
            # Index for BLEU score queries (for performance analysis)
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_runs_bleu_score 
            ON comparative_analysis_runs(final_bleu_score) 
            WHERE final_bleu_score IS NOT NULL
            ''')
            
            # Composite index for attempt analysis
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_attempts_run_status 
            ON injection_attempts(run_id, status)
            ''')
            
            # Index for attempt number queries
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_attempts_number 
            ON injection_attempts(attempt_number)
            ''')
            
            conn.commit()
            conn.close()
            
            self.logger.info("Performance indexes created successfully")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error creating performance indexes: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error creating indexes: {e}")
            return False
    
    def analyze_query_performance(self, query: str, params: tuple = ()) -> Dict[str, Any]:
        """
        Analyze the performance of a specific query.
        
        Args:
            query: SQL query to analyze
            params: Query parameters
            
        Returns:
            Dict containing performance metrics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get query plan
            cursor.execute(f"EXPLAIN QUERY PLAN {query}", params)
            query_plan = cursor.fetchall()
            
            # Measure execution time
            start_time = time.time()
            cursor.execute(query, params)
            results = cursor.fetchall()
            end_time = time.time()
            
            execution_time = end_time - start_time
            
            conn.close()
            
            return {
                'execution_time': execution_time,
                'result_count': len(results),
                'query_plan': query_plan,
                'uses_index': any('INDEX' in str(step) for step in query_plan)
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing query performance: {e}")
            return {
                'execution_time': -1,
                'result_count': 0,
                'query_plan': [],
                'uses_index': False,
                'error': str(e)
            }
    
    def optimize_database_settings(self) -> bool:
        """
        Apply database-level optimizations for better performance.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Enable WAL mode for better concurrent access
            cursor.execute("PRAGMA journal_mode=WAL")
            
            # Increase cache size (in KB)
            cursor.execute("PRAGMA cache_size=10000")  # 10MB cache
            
            # Enable foreign key constraints
            cursor.execute("PRAGMA foreign_keys=ON")
            
            # Optimize for faster writes
            cursor.execute("PRAGMA synchronous=NORMAL")
            
            # Set temp store to memory for better performance
            cursor.execute("PRAGMA temp_store=MEMORY")
            
            # Increase page size for better I/O performance
            cursor.execute("PRAGMA page_size=4096")
            
            conn.close()
            
            self.logger.info("Database settings optimized for performance")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error optimizing database settings: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error optimizing database: {e}")
            return False
    
    def vacuum_and_analyze(self) -> bool:
        """
        Perform database maintenance to optimize performance.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Update statistics for query optimizer
            cursor.execute("ANALYZE")
            
            # Rebuild database to optimize storage
            cursor.execute("VACUUM")
            
            conn.close()
            
            self.logger.info("Database vacuum and analyze completed")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error during vacuum and analyze: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during maintenance: {e}")
            return False


class BatchProcessor:
    """Optimized batch processing utilities for database operations."""
    
    def __init__(self, db_path: str = DB_PATH, batch_size: int = 100):
        self.db_path = db_path
        self.batch_size = batch_size
        self.logger = logging.getLogger(__name__)
    
    def batch_insert_attempts(self, attempts_data: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """
        Insert multiple injection attempts in optimized batches.
        
        Args:
            attempts_data: List of attempt dictionaries
            
        Returns:
            Tuple of (success, error_message)
        """
        if not attempts_data:
            return True, ""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Enable optimizations for bulk insert
            cursor.execute("PRAGMA synchronous=OFF")
            cursor.execute("PRAGMA journal_mode=MEMORY")
            cursor.execute("BEGIN TRANSACTION")
            
            # Process in batches
            for i in range(0, len(attempts_data), self.batch_size):
                batch = attempts_data[i:i + self.batch_size]
                
                # Prepare batch data
                batch_values = []
                for attempt in batch:
                    batch_values.append((
                        attempt.get('run_id'),
                        attempt.get('attempt_number'),
                        attempt.get('status'),
                        attempt.get('task_prompt'),
                        attempt.get('generated_code'),
                        attempt.get('feedback_given'),
                        attempt.get('bleu_score'),
                        attempt.get('semantic_justification'),
                        attempt.get('static_analysis_report'),
                        attempt.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    ))
                
                # Execute batch insert
                cursor.executemany('''
                INSERT INTO injection_attempts (
                    run_id, attempt_number, status, task_prompt, generated_code,
                    feedback_given, bleu_score, semantic_justification, 
                    static_analysis_report, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', batch_values)
            
            cursor.execute("COMMIT")
            
            # Restore normal settings
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA journal_mode=WAL")
            
            conn.close()
            
            self.logger.info(f"Successfully batch inserted {len(attempts_data)} attempts")
            return True, ""
            
        except sqlite3.Error as e:
            self.logger.error(f"Database error in batch insert: {e}")
            return False, str(e)
        except Exception as e:
            self.logger.error(f"Unexpected error in batch insert: {e}")
            return False, str(e)
    
    def batch_update_bleu_scores(self, score_updates: List[Tuple[int, float]]) -> Tuple[bool, str]:
        """
        Update BLEU scores for multiple runs in a batch.
        
        Args:
            score_updates: List of (run_id, bleu_score) tuples
            
        Returns:
            Tuple of (success, error_message)
        """
        if not score_updates:
            return True, ""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("BEGIN TRANSACTION")
            
            # Process in batches
            for i in range(0, len(score_updates), self.batch_size):
                batch = score_updates[i:i + self.batch_size]
                
                cursor.executemany('''
                UPDATE comparative_analysis_runs 
                SET final_bleu_score = ? 
                WHERE id = ?
                ''', [(score, run_id) for run_id, score in batch])
            
            cursor.execute("COMMIT")
            conn.close()
            
            self.logger.info(f"Successfully updated {len(score_updates)} BLEU scores")
            return True, ""
            
        except sqlite3.Error as e:
            self.logger.error(f"Database error in batch BLEU update: {e}")
            return False, str(e)
        except Exception as e:
            self.logger.error(f"Unexpected error in batch BLEU update: {e}")
            return False, str(e)


class CodeProcessingCache:
    """LRU cache for expensive code processing operations."""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.logger = logging.getLogger(__name__)
    
    @lru_cache(maxsize=1000)
    def cached_preprocess_code(self, code_hash: str, code: str) -> str:
        """
        Cache preprocessed code to avoid repeated processing.
        
        Args:
            code_hash: Hash of the original code for cache key
            code: Original code to preprocess
            
        Returns:
            Preprocessed code
        """
        from code_similarity_evaluator import CodeSimilarityEvaluator
        evaluator = CodeSimilarityEvaluator()
        return evaluator.preprocess_code(code)
    
    @lru_cache(maxsize=500)
    def cached_bleu_score(self, gen_hash: str, exp_hash: str, gen_code: str, exp_code: str) -> float:
        """
        Cache BLEU score calculations to avoid repeated computation.
        
        Args:
            gen_hash: Hash of generated code
            exp_hash: Hash of expected code
            gen_code: Generated code
            exp_code: Expected code
            
        Returns:
            BLEU score
        """
        from code_similarity_evaluator import CodeSimilarityEvaluator
        evaluator = CodeSimilarityEvaluator()
        # Use new comprehensive metrics API but return only BLEU-4 for backward compatibility
        try:
            metrics = evaluator.evaluate_all_metrics(gen_code, exp_code)
            return metrics.bleu_4_score if metrics else 0.0
        except Exception:
            # Fallback to legacy method
            return evaluator.calculate_bleu_score(gen_code, exp_code)
    
    def get_code_hash(self, code: str) -> str:
        """
        Generate a hash for code to use as cache key.
        
        Args:
            code: Code to hash
            
        Returns:
            SHA256 hash of the code
        """
        if not code:
            return "empty"
        
        try:
            return hashlib.sha256(code.encode('utf-8')).hexdigest()[:16]  # First 16 chars
        except Exception as e:
            self.logger.error(f"Error generating code hash: {e}")
            return "error"
    
    def get_cached_bleu_score(self, generated_code: str, expected_code: str) -> float:
        """
        Get BLEU score with caching.
        
        Args:
            generated_code: Generated code
            expected_code: Expected code
            
        Returns:
            BLEU score
        """
        gen_hash = self.get_code_hash(generated_code)
        exp_hash = self.get_code_hash(expected_code)
        
        return self.cached_bleu_score(gen_hash, exp_hash, generated_code, expected_code)
    
    def get_cached_preprocessed_code(self, code: str) -> str:
        """
        Get preprocessed code with caching.
        
        Args:
            code: Original code
            
        Returns:
            Preprocessed code
        """
        code_hash = self.get_code_hash(code)
        return self.cached_preprocess_code(code_hash, code)
    
    def clear_cache(self):
        """Clear all cached data."""
        self.cached_preprocess_code.cache_clear()
        self.cached_bleu_score.cache_clear()
        self.logger.info("Code processing cache cleared")
    
    def get_cache_info(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        return {
            'preprocess_cache': self.cached_preprocess_code.cache_info()._asdict(),
            'bleu_cache': self.cached_bleu_score.cache_info()._asdict()
        }


class PerformanceMonitor:
    """Monitor and report performance metrics."""
    
    def __init__(self):
        self.metrics = {}
        self.logger = logging.getLogger(__name__)
    
    def start_timer(self, operation: str):
        """Start timing an operation."""
        self.metrics[operation] = {'start_time': time.time()}
    
    def end_timer(self, operation: str) -> float:
        """
        End timing an operation and return duration.
        
        Args:
            operation: Name of the operation
            
        Returns:
            Duration in seconds
        """
        if operation not in self.metrics:
            self.logger.warning(f"Timer for operation '{operation}' was not started")
            return 0.0
        
        end_time = time.time()
        duration = end_time - self.metrics[operation]['start_time']
        self.metrics[operation]['duration'] = duration
        self.metrics[operation]['end_time'] = end_time
        
        return duration
    
    def record_metric(self, name: str, value: Any):
        """Record a custom metric."""
        self.metrics[name] = value
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Generate a performance report.
        
        Returns:
            Dictionary with performance metrics
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'metrics': self.metrics.copy()
        }
        
        # Calculate summary statistics
        durations = [m.get('duration', 0) for m in self.metrics.values() if isinstance(m, dict) and 'duration' in m]
        if durations:
            report['summary'] = {
                'total_operations': len(durations),
                'total_time': sum(durations),
                'average_time': sum(durations) / len(durations),
                'max_time': max(durations),
                'min_time': min(durations)
            }
        
        return report
    
    def reset_metrics(self):
        """Reset all metrics."""
        self.metrics.clear()


def optimize_system_performance(db_path: str = DB_PATH) -> Dict[str, bool]:
    """
    Apply all available performance optimizations.
    
    Args:
        db_path: Path to the database
        
    Returns:
        Dictionary with optimization results
    """
    results = {}
    
    # Database optimizations
    db_optimizer = DatabaseOptimizer(db_path)
    results['indexes_created'] = db_optimizer.create_performance_indexes()
    results['settings_optimized'] = db_optimizer.optimize_database_settings()
    results['maintenance_completed'] = db_optimizer.vacuum_and_analyze()
    
    return results


def benchmark_bleu_calculation(num_iterations: int = 100) -> Dict[str, float]:
    """
    Benchmark BLEU calculation performance.
    
    Args:
        num_iterations: Number of iterations to run
        
    Returns:
        Dictionary with benchmark results
    """
    from code_similarity_evaluator import CodeSimilarityEvaluator
    
    evaluator = CodeSimilarityEvaluator()
    cache = CodeProcessingCache()
    
    # Test data
    test_cases = [
        ("def test(): return 'hello'", "def test(): return 'world'"),
        ("def func(x):\n    return x * 2", "def func(x):\n    return x + 2"),
        ("class Test:\n    def __init__(self):\n        self.value = 0", "class Test:\n    def __init__(self):\n        self.value = 1")
    ]
    
    # Benchmark without cache
    start_time = time.time()
    for _ in range(num_iterations):
        for gen_code, exp_code in test_cases:
            # Use new API for performance testing
            try:
                metrics = evaluator.evaluate_all_metrics(gen_code, exp_code)
            except Exception:
                # Fallback to legacy method for performance comparison
                evaluator.calculate_bleu_score(gen_code, exp_code)
    uncached_time = time.time() - start_time
    
    # Benchmark with cache
    start_time = time.time()
    for _ in range(num_iterations):
        for gen_code, exp_code in test_cases:
            cache.get_cached_bleu_score(gen_code, exp_code)
    cached_time = time.time() - start_time
    
    return {
        'uncached_time': uncached_time,
        'cached_time': cached_time,
        'speedup': uncached_time / cached_time if cached_time > 0 else 0,
        'iterations': num_iterations,
        'test_cases': len(test_cases)
    }


if __name__ == "__main__":
    # Run performance optimizations
    print("Applying performance optimizations...")
    results = optimize_system_performance()
    
    for optimization, success in results.items():
        status = "✓" if success else "✗"
        print(f"{status} {optimization}: {'Success' if success else 'Failed'}")
    
    # Run benchmark
    print("\nRunning BLEU calculation benchmark...")
    benchmark_results = benchmark_bleu_calculation(50)
    
    print(f"Uncached time: {benchmark_results['uncached_time']:.4f}s")
    print(f"Cached time: {benchmark_results['cached_time']:.4f}s")
    print(f"Speedup: {benchmark_results['speedup']:.2f}x")