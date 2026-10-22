"""
oLLM metrics integration for existing reporting system.

This module extends the existing reporting infrastructure to include oLLM-specific
performance metrics, backend information, and resource usage data in experiment
results and final reports.
"""

import sqlite3
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict

from ollm_logging import get_ollm_logger, OLLMPerformanceMetrics


@dataclass
class ExperimentMetrics:
    """Enhanced experiment metrics including oLLM data."""
    # Standard experiment metrics
    experiment_id: str
    model_name: str
    backend_type: str
    total_inferences: int
    successful_inferences: int
    failed_inferences: int
    
    # oLLM-specific metrics
    backend_selection_time_ms: Optional[float] = None
    model_loading_time_ms: Optional[float] = None
    average_inference_time_ms: Optional[float] = None
    average_tokens_per_second: Optional[float] = None
    peak_memory_usage_mb: Optional[float] = None
    total_ssd_io_mb: Optional[float] = None
    fallback_occurred: bool = False
    
    # Resource efficiency metrics
    memory_efficiency_score: Optional[float] = None
    inference_speed_score: Optional[float] = None
    overall_performance_score: Optional[float] = None


class OLLMMetricsCollector:
    """Collects and aggregates oLLM metrics for reporting."""
    
    def __init__(self, db_path: str = "execution_log_orchestrated.db"):
        """
        Initialize the metrics collector.
        
        Args:
            db_path: Path to the experiment database
        """
        self.db_path = db_path
        self.logger = logging.getLogger(f"{__name__}.OLLMMetricsCollector")
    
    def create_ollm_metrics_tables(self):
        """Create database tables for oLLM metrics if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Table for oLLM experiment sessions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ollm_experiment_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    experiment_name TEXT,
                    model_name TEXT,
                    backend_type TEXT,
                    start_timestamp TEXT,
                    end_timestamp TEXT,
                    total_experiments INTEGER DEFAULT 0,
                    successful_experiments INTEGER DEFAULT 0,
                    failed_experiments INTEGER DEFAULT 0
                )
            ''')
            
            # Table for oLLM performance metrics per experiment
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ollm_experiment_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    experiment_id TEXT,
                    model_name TEXT,
                    backend_type TEXT,
                    backend_selection_time_ms REAL,
                    model_loading_time_ms REAL,
                    inference_count INTEGER,
                    total_inference_time_ms REAL,
                    average_inference_time_ms REAL,
                    average_tokens_per_second REAL,
                    peak_memory_usage_mb REAL,
                    total_ssd_io_mb REAL,
                    fallback_occurred BOOLEAN,
                    timestamp TEXT,
                    FOREIGN KEY (session_id) REFERENCES ollm_experiment_sessions (session_id)
                )
            ''')
            
            # Table for oLLM resource usage snapshots
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ollm_resource_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    experiment_id TEXT,
                    snapshot_timestamp TEXT,
                    memory_usage_mb REAL,
                    memory_percent REAL,
                    cpu_percent REAL,
                    gpu_memory_mb REAL,
                    ssd_read_mb REAL,
                    ssd_write_mb REAL,
                    process_memory_mb REAL,
                    FOREIGN KEY (session_id) REFERENCES ollm_experiment_sessions (session_id)
                )
            ''')
            
            conn.commit()
            self.logger.info("oLLM metrics tables created successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to create oLLM metrics tables: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def start_experiment_session(self, session_id: str, experiment_name: str, 
                                model_name: str, backend_type: str) -> bool:
        """
        Start a new experiment session.
        
        Args:
            session_id: Unique session identifier
            experiment_name: Name of the experiment
            model_name: Name of the model being used
            backend_type: Backend type (ollm, llamacpp)
            
        Returns:
            bool: True if session started successfully
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO ollm_experiment_sessions 
                (session_id, experiment_name, model_name, backend_type, start_timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, experiment_name, model_name, backend_type, 
                  datetime.now().isoformat()))
            
            conn.commit()
            self.logger.info(f"Started experiment session: {session_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start experiment session: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def end_experiment_session(self, session_id: str, 
                             total_experiments: int, successful_experiments: int) -> bool:
        """
        End an experiment session with summary statistics.
        
        Args:
            session_id: Session identifier
            total_experiments: Total number of experiments run
            successful_experiments: Number of successful experiments
            
        Returns:
            bool: True if session ended successfully
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            failed_experiments = total_experiments - successful_experiments
            
            cursor.execute('''
                UPDATE ollm_experiment_sessions 
                SET end_timestamp = ?, total_experiments = ?, 
                    successful_experiments = ?, failed_experiments = ?
                WHERE session_id = ?
            ''', (datetime.now().isoformat(), total_experiments, 
                  successful_experiments, failed_experiments, session_id))
            
            conn.commit()
            self.logger.info(f"Ended experiment session: {session_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to end experiment session: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def collect_experiment_metrics(self, session_id: str, experiment_id: str) -> Optional[ExperimentMetrics]:
        """
        Collect oLLM metrics for a specific experiment.
        
        Args:
            session_id: Session identifier
            experiment_id: Experiment identifier
            
        Returns:
            ExperimentMetrics object or None if collection fails
        """
        ollm_logger = get_ollm_logger()
        
        try:
            # Get backend selection metrics
            backend_logs = [log for log in ollm_logger.backend_selection_logs 
                          if log.model_name == experiment_id]
            
            # Get model loading metrics
            loading_logs = [log for log in ollm_logger.model_loading_logs 
                          if log.model_name == experiment_id]
            
            # Get inference metrics
            inference_logs = [log for log in ollm_logger.inference_logs 
                            if log.model_name == experiment_id]
            
            if not (backend_logs or loading_logs or inference_logs):
                self.logger.warning(f"No oLLM metrics found for experiment: {experiment_id}")
                return None
            
            # Calculate aggregated metrics
            backend_selection_time = backend_logs[0].selection_time_ms if backend_logs else None
            model_loading_time = loading_logs[0].loading_time_ms if loading_logs else None
            fallback_occurred = any(log.fallback_occurred for log in backend_logs)
            
            # Inference metrics
            successful_inferences = len([log for log in inference_logs if not log.error_message])
            failed_inferences = len([log for log in inference_logs if log.error_message])
            total_inferences = len(inference_logs)
            
            avg_inference_time = None
            avg_tokens_per_second = None
            peak_memory = None
            total_ssd_io = None
            
            if successful_inferences > 0:
                successful_logs = [log for log in inference_logs if not log.error_message]
                avg_inference_time = sum(log.inference_time_ms for log in successful_logs) / len(successful_logs)
                avg_tokens_per_second = sum(log.tokens_per_second for log in successful_logs) / len(successful_logs)
                
                # Peak memory and SSD I/O
                memory_values = [log.memory_peak_mb for log in successful_logs if log.memory_peak_mb]
                if memory_values:
                    peak_memory = max(memory_values)
                
                ssd_values = [log.ssd_io_mb for log in successful_logs if log.ssd_io_mb]
                if ssd_values:
                    total_ssd_io = sum(ssd_values)
            
            # Determine backend type
            backend_type = "unknown"
            if backend_logs:
                backend_type = backend_logs[0].backend_selected
            elif loading_logs:
                backend_type = loading_logs[0].backend_type
            elif inference_logs:
                backend_type = inference_logs[0].backend_type
            
            # Calculate efficiency scores
            memory_efficiency = self._calculate_memory_efficiency_score(peak_memory, backend_type)
            speed_efficiency = self._calculate_speed_efficiency_score(avg_tokens_per_second, backend_type)
            overall_performance = self._calculate_overall_performance_score(
                memory_efficiency, speed_efficiency, successful_inferences, total_inferences
            )
            
            return ExperimentMetrics(
                experiment_id=experiment_id,
                model_name=experiment_id,  # Assuming model name is the experiment ID
                backend_type=backend_type,
                total_inferences=total_inferences,
                successful_inferences=successful_inferences,
                failed_inferences=failed_inferences,
                backend_selection_time_ms=backend_selection_time,
                model_loading_time_ms=model_loading_time,
                average_inference_time_ms=avg_inference_time,
                average_tokens_per_second=avg_tokens_per_second,
                peak_memory_usage_mb=peak_memory,
                total_ssd_io_mb=total_ssd_io,
                fallback_occurred=fallback_occurred,
                memory_efficiency_score=memory_efficiency,
                inference_speed_score=speed_efficiency,
                overall_performance_score=overall_performance
            )
            
        except Exception as e:
            self.logger.error(f"Failed to collect experiment metrics: {e}")
            return None
    
    def store_experiment_metrics(self, session_id: str, metrics: ExperimentMetrics) -> bool:
        """
        Store experiment metrics in the database.
        
        Args:
            session_id: Session identifier
            metrics: ExperimentMetrics object to store
            
        Returns:
            bool: True if storage was successful
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO ollm_experiment_metrics (
                    session_id, experiment_id, model_name, backend_type,
                    backend_selection_time_ms, model_loading_time_ms,
                    inference_count, total_inference_time_ms, average_inference_time_ms,
                    average_tokens_per_second, peak_memory_usage_mb, total_ssd_io_mb,
                    fallback_occurred, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id, metrics.experiment_id, metrics.model_name, metrics.backend_type,
                metrics.backend_selection_time_ms, metrics.model_loading_time_ms,
                metrics.total_inferences, 
                metrics.average_inference_time_ms * metrics.total_inferences if metrics.average_inference_time_ms else None,
                metrics.average_inference_time_ms, metrics.average_tokens_per_second,
                metrics.peak_memory_usage_mb, metrics.total_ssd_io_mb,
                metrics.fallback_occurred, datetime.now().isoformat()
            ))
            
            conn.commit()
            self.logger.debug(f"Stored metrics for experiment: {metrics.experiment_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store experiment metrics: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def _calculate_memory_efficiency_score(self, peak_memory_mb: Optional[float], 
                                         backend_type: str) -> Optional[float]:
        """Calculate memory efficiency score (0-1, higher is better)."""
        if peak_memory_mb is None:
            return None
        
        # Baseline memory usage expectations (in MB)
        baselines = {
            "ollm": 4000,      # oLLM should use less memory due to offloading
            "llamacpp": 8000   # Standard llama-cpp-python usage
        }
        
        baseline = baselines.get(backend_type, 6000)
        
        # Score based on how much below/above baseline
        if peak_memory_mb <= baseline * 0.5:
            return 1.0  # Excellent efficiency
        elif peak_memory_mb <= baseline:
            return 0.8  # Good efficiency
        elif peak_memory_mb <= baseline * 1.5:
            return 0.6  # Acceptable efficiency
        elif peak_memory_mb <= baseline * 2.0:
            return 0.4  # Poor efficiency
        else:
            return 0.2  # Very poor efficiency
    
    def _calculate_speed_efficiency_score(self, tokens_per_second: Optional[float], 
                                        backend_type: str) -> Optional[float]:
        """Calculate inference speed efficiency score (0-1, higher is better)."""
        if tokens_per_second is None:
            return None
        
        # Baseline speed expectations (tokens per second)
        baselines = {
            "ollm": 15,        # oLLM may be slower due to SSD I/O
            "llamacpp": 25     # Standard llama-cpp-python speed
        }
        
        baseline = baselines.get(backend_type, 20)
        
        # Score based on speed relative to baseline
        ratio = tokens_per_second / baseline
        
        if ratio >= 1.5:
            return 1.0  # Excellent speed
        elif ratio >= 1.0:
            return 0.8  # Good speed
        elif ratio >= 0.7:
            return 0.6  # Acceptable speed
        elif ratio >= 0.5:
            return 0.4  # Poor speed
        else:
            return 0.2  # Very poor speed
    
    def _calculate_overall_performance_score(self, memory_efficiency: Optional[float],
                                           speed_efficiency: Optional[float],
                                           successful_inferences: int,
                                           total_inferences: int) -> Optional[float]:
        """Calculate overall performance score combining multiple factors."""
        total_weight = 0.0
        weighted_sum = 0.0
        
        # Memory efficiency (weight: 0.3)
        if memory_efficiency is not None:
            weighted_sum += memory_efficiency * 0.3
            total_weight += 0.3
        
        # Speed efficiency (weight: 0.4)
        if speed_efficiency is not None:
            weighted_sum += speed_efficiency * 0.4
            total_weight += 0.4
        
        # Success rate (weight: 0.3)
        if total_inferences > 0:
            success_rate = successful_inferences / total_inferences
            weighted_sum += success_rate * 0.3
            total_weight += 0.3
        
        if total_weight == 0.0:
            return None
        
        return weighted_sum / total_weight
    
    def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive summary for an experiment session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Dictionary containing session summary or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get session info
            cursor.execute('''
                SELECT * FROM ollm_experiment_sessions WHERE session_id = ?
            ''', (session_id,))
            
            session_row = cursor.fetchone()
            if not session_row:
                return None
            
            # Get column names
            session_columns = [desc[0] for desc in cursor.description]
            session_data = dict(zip(session_columns, session_row))
            
            # Get aggregated metrics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_experiments,
                    AVG(backend_selection_time_ms) as avg_selection_time,
                    AVG(model_loading_time_ms) as avg_loading_time,
                    AVG(average_inference_time_ms) as avg_inference_time,
                    AVG(average_tokens_per_second) as avg_tokens_per_second,
                    MAX(peak_memory_usage_mb) as peak_memory,
                    SUM(total_ssd_io_mb) as total_ssd_io,
                    SUM(CASE WHEN fallback_occurred THEN 1 ELSE 0 END) as fallback_count,
                    backend_type
                FROM ollm_experiment_metrics 
                WHERE session_id = ?
                GROUP BY backend_type
            ''', (session_id,))
            
            metrics_rows = cursor.fetchall()
            metrics_columns = [desc[0] for desc in cursor.description]
            
            backend_metrics = {}
            for row in metrics_rows:
                metrics_data = dict(zip(metrics_columns, row))
                backend_type = metrics_data.pop('backend_type')
                backend_metrics[backend_type] = metrics_data
            
            return {
                'session_info': session_data,
                'backend_metrics': backend_metrics,
                'summary_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get session summary: {e}")
            return None
        finally:
            conn.close()


class EnhancedReportGenerator:
    """Enhanced report generator that includes oLLM metrics."""
    
    def __init__(self, db_path: str = "execution_log_orchestrated.db"):
        """
        Initialize the enhanced report generator.
        
        Args:
            db_path: Path to the experiment database
        """
        self.db_path = db_path
        self.metrics_collector = OLLMMetricsCollector(db_path)
        self.logger = logging.getLogger(f"{__name__}.EnhancedReportGenerator")
    
    def generate_comprehensive_report(self, session_id: Optional[str] = None) -> str:
        """
        Generate a comprehensive report including oLLM metrics.
        
        Args:
            session_id: Optional session ID to filter results
            
        Returns:
            Formatted report string
        """
        try:
            # Get standard experiment results
            standard_results = self._get_standard_results(session_id)
            
            # Get oLLM metrics
            ollm_results = self._get_ollm_results(session_id)
            
            # Generate report
            report_lines = []
            report_lines.append("=" * 100)
            report_lines.append(" " * 30 + "Enhanced Vulnerability Injection Experiment Report")
            report_lines.append("=" * 100)
            
            if session_id:
                report_lines.append(f"Session ID: {session_id}")
                report_lines.append("")
            
            # Standard results section
            if standard_results:
                report_lines.append("STANDARD EXPERIMENT RESULTS")
                report_lines.append("-" * 50)
                report_lines.extend(self._format_standard_results(standard_results))
                report_lines.append("")
            
            # oLLM metrics section
            if ollm_results:
                report_lines.append("oLLM PERFORMANCE METRICS")
                report_lines.append("-" * 50)
                report_lines.extend(self._format_ollm_results(ollm_results))
                report_lines.append("")
            
            # Performance comparison section
            if standard_results and ollm_results:
                report_lines.append("BACKEND PERFORMANCE COMPARISON")
                report_lines.append("-" * 50)
                report_lines.extend(self._format_performance_comparison(standard_results, ollm_results))
                report_lines.append("")
            
            report_lines.append("=" * 100)
            report_lines.append(f"Report generated at: {datetime.now().isoformat()}")
            report_lines.append("=" * 100)
            
            return "\n".join(report_lines)
            
        except Exception as e:
            self.logger.error(f"Failed to generate comprehensive report: {e}")
            return f"Error generating report: {e}"
    
    def _get_standard_results(self, session_id: Optional[str]) -> Optional[List[Dict[str, Any]]]:
        """Get standard experiment results from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            query = '''
                SELECT model_name, prompt_strategy, 
                       COUNT(*) as total_runs,
                       SUM(CASE WHEN static_confirmation_status = 'SUCCESS' THEN 1 ELSE 0 END) as successful_runs
                FROM comparative_analysis_runs
            '''
            
            params = []
            if session_id:
                query += " WHERE run_timestamp LIKE ?"
                params.append(f"%{session_id}%")
            
            query += " GROUP BY model_name, prompt_strategy ORDER BY model_name, prompt_strategy"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
            return [dict(zip(columns, row)) for row in rows]
            
        except Exception as e:
            self.logger.error(f"Failed to get standard results: {e}")
            return None
        finally:
            conn.close()
    
    def _get_ollm_results(self, session_id: Optional[str]) -> Optional[List[Dict[str, Any]]]:
        """Get oLLM metrics from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            query = '''
                SELECT backend_type, model_name,
                       COUNT(*) as total_experiments,
                       AVG(backend_selection_time_ms) as avg_selection_time,
                       AVG(model_loading_time_ms) as avg_loading_time,
                       AVG(average_inference_time_ms) as avg_inference_time,
                       AVG(average_tokens_per_second) as avg_tokens_per_second,
                       MAX(peak_memory_usage_mb) as peak_memory,
                       SUM(total_ssd_io_mb) as total_ssd_io,
                       SUM(CASE WHEN fallback_occurred THEN 1 ELSE 0 END) as fallback_count
                FROM ollm_experiment_metrics
            '''
            
            params = []
            if session_id:
                query += " WHERE session_id = ?"
                params.append(session_id)
            
            query += " GROUP BY backend_type, model_name ORDER BY backend_type, model_name"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
            return [dict(zip(columns, row)) for row in rows]
            
        except Exception as e:
            self.logger.error(f"Failed to get oLLM results: {e}")
            return None
        finally:
            conn.close()
    
    def _format_standard_results(self, results: List[Dict[str, Any]]) -> List[str]:
        """Format standard experiment results."""
        lines = []
        
        for result in results:
            total = result['total_runs']
            successful = result['successful_runs']
            success_rate = (successful / total * 100) if total > 0 else 0
            
            lines.append(f"Model: {result['model_name']}")
            lines.append(f"  Strategy: {result['prompt_strategy']}")
            lines.append(f"  Total Runs: {total}")
            lines.append(f"  Successful: {successful}")
            lines.append(f"  Success Rate: {success_rate:.1f}%")
            lines.append("")
        
        return lines
    
    def _format_ollm_results(self, results: List[Dict[str, Any]]) -> List[str]:
        """Format oLLM performance results."""
        lines = []
        
        for result in results:
            lines.append(f"Backend: {result['backend_type'].upper()}")
            lines.append(f"  Model: {result['model_name']}")
            lines.append(f"  Total Experiments: {result['total_experiments']}")
            
            if result['avg_selection_time']:
                lines.append(f"  Avg Selection Time: {result['avg_selection_time']:.1f}ms")
            
            if result['avg_loading_time']:
                lines.append(f"  Avg Loading Time: {result['avg_loading_time']:.1f}ms")
            
            if result['avg_inference_time']:
                lines.append(f"  Avg Inference Time: {result['avg_inference_time']:.1f}ms")
            
            if result['avg_tokens_per_second']:
                lines.append(f"  Avg Speed: {result['avg_tokens_per_second']:.1f} tokens/sec")
            
            if result['peak_memory']:
                lines.append(f"  Peak Memory: {result['peak_memory']:.1f}MB")
            
            if result['total_ssd_io']:
                lines.append(f"  Total SSD I/O: {result['total_ssd_io']:.1f}MB")
            
            if result['fallback_count'] > 0:
                lines.append(f"  Fallbacks: {result['fallback_count']}")
            
            lines.append("")
        
        return lines
    
    def _format_performance_comparison(self, standard_results: List[Dict[str, Any]], 
                                     ollm_results: List[Dict[str, Any]]) -> List[str]:
        """Format performance comparison between backends."""
        lines = []
        
        # Group oLLM results by backend type
        ollm_by_backend = {}
        for result in ollm_results:
            backend = result['backend_type']
            if backend not in ollm_by_backend:
                ollm_by_backend[backend] = []
            ollm_by_backend[backend].append(result)
        
        # Compare backends
        if 'ollm' in ollm_by_backend and 'llamacpp' in ollm_by_backend:
            ollm_data = ollm_by_backend['ollm'][0]  # Take first result for comparison
            llamacpp_data = ollm_by_backend['llamacpp'][0]
            
            lines.append("Backend Comparison (oLLM vs llama-cpp-python):")
            lines.append("")
            
            # Speed comparison
            if ollm_data['avg_tokens_per_second'] and llamacpp_data['avg_tokens_per_second']:
                ollm_speed = ollm_data['avg_tokens_per_second']
                llamacpp_speed = llamacpp_data['avg_tokens_per_second']
                speed_ratio = ollm_speed / llamacpp_speed
                
                lines.append(f"  Speed Comparison:")
                lines.append(f"    oLLM: {ollm_speed:.1f} tokens/sec")
                lines.append(f"    llama-cpp: {llamacpp_speed:.1f} tokens/sec")
                lines.append(f"    Ratio: {speed_ratio:.2f}x")
                lines.append("")
            
            # Memory comparison
            if ollm_data['peak_memory'] and llamacpp_data['peak_memory']:
                ollm_memory = ollm_data['peak_memory']
                llamacpp_memory = llamacpp_data['peak_memory']
                memory_ratio = ollm_memory / llamacpp_memory
                
                lines.append(f"  Memory Usage Comparison:")
                lines.append(f"    oLLM: {ollm_memory:.1f}MB")
                lines.append(f"    llama-cpp: {llamacpp_memory:.1f}MB")
                lines.append(f"    Ratio: {memory_ratio:.2f}x")
                lines.append("")
        
        return lines
    
    def export_metrics_to_json(self, filepath: str, session_id: Optional[str] = None) -> bool:
        """
        Export all metrics to a JSON file.
        
        Args:
            filepath: Path to export the JSON file
            session_id: Optional session ID to filter results
            
        Returns:
            bool: True if export was successful
        """
        try:
            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'session_id': session_id,
                'standard_results': self._get_standard_results(session_id),
                'ollm_results': self._get_ollm_results(session_id)
            }
            
            # Add oLLM logger data
            ollm_logger = get_ollm_logger()
            export_data['ollm_logs'] = {
                'backend_selection_logs': [asdict(log) for log in ollm_logger.backend_selection_logs],
                'model_loading_logs': [asdict(log) for log in ollm_logger.model_loading_logs],
                'inference_logs': [asdict(log) for log in ollm_logger.inference_logs],
                'performance_summary': ollm_logger.get_performance_summary()
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Exported enhanced metrics to: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export metrics: {e}")
            return False


# Global instances for easy access
_metrics_collector = None
_report_generator = None

def get_metrics_collector() -> OLLMMetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = OLLMMetricsCollector()
        _metrics_collector.create_ollm_metrics_tables()
    return _metrics_collector

def get_report_generator() -> EnhancedReportGenerator:
    """Get the global report generator instance."""
    global _report_generator
    if _report_generator is None:
        _report_generator = EnhancedReportGenerator()
    return _report_generator