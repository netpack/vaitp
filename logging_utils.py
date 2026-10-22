# logging_utils.py

import sqlite3
import logging, json
import pandas as pd# type: ignore
import matplotlib.pyplot as plt# type: ignore
from datetime import datetime
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from config import DB_PATH

if TYPE_CHECKING:
    from code_similarity_evaluator import CodeMetrics

def log_execution(date, execution_time, file_name, rag_used, rag_context, prompt, prompt_type, 
                  input_code, response_code, expected_code, diff_generated_input, diff_generated_expected, 
                  match, is_input_vulnerable, is_output_vulnerable, is_expected_vulnerable, 
                  agent_exploitation_result, reward, docker_output):
    """
    Logs the execution details into the database. (Original function for other logging purposes)
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS execution_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, execution_time REAL, file_name TEXT,
            rag_used TEXT, rag_context TEXT, prompt TEXT, prompt_type TEXT, input_code TEXT,
            response_code TEXT, expected_code TEXT, diff_generated_input TEXT,
            diff_generated_expected TEXT, match INTEGER, is_input_vulnerable INTEGER,
            is_output_vulnerable INTEGER, is_expected_vulnerable INTEGER,
            agent_exploitation_result INTEGER, reward REAL, docker_output TEXT
        )
    ''')
    cursor.execute('''
        INSERT INTO execution_log (
            date, execution_time, file_name, rag_used, rag_context, prompt, prompt_type,
            input_code, response_code, expected_code, diff_generated_input, diff_generated_expected,
            match, is_input_vulnerable, is_output_vulnerable, is_expected_vulnerable, 
            agent_exploitation_result, reward, docker_output
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        date, execution_time, file_name, rag_used, rag_context, prompt, prompt_type, 
        input_code, response_code, expected_code, diff_generated_input, diff_generated_expected, 
        match, is_input_vulnerable, is_output_vulnerable, is_expected_vulnerable, 
        int(agent_exploitation_result), reward, docker_output
    ))
    conn.commit()
    conn.close()

def log_differential_attack(
    run_timestamp: str, target_filename: str, vulnerability_type: str, aep_markdown: str,
    original_aep_trace_json: str, vulnerable_aep_trace_json: str, llm_interpretation: dict,
    overall_attack_phase_time: float, model_name: str
    ):
    """
    Logs the results of a differential attack simulation from the main reasoning model.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS differential_aep_attack_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_timestamp TEXT, model_name TEXT,
            target_filename TEXT, vulnerability_type TEXT, aep_markdown TEXT,
            original_aep_trace_json TEXT, vulnerable_aep_trace_json TEXT,
            llm_interpretation_json TEXT, exploit_confirmed BOOLEAN,
            observed_impact TEXT, attack_phase_time REAL
        )
    ''')
    try:
        cursor.execute('''
            INSERT INTO differential_aep_attack_log (
                run_timestamp, model_name, target_filename, vulnerability_type, aep_markdown,
                original_aep_trace_json, vulnerable_aep_trace_json,
                llm_interpretation_json, exploit_confirmed, observed_impact, attack_phase_time
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            run_timestamp, model_name, target_filename, vulnerability_type, aep_markdown,
            original_aep_trace_json, vulnerable_aep_trace_json,
            json.dumps(llm_interpretation),
            llm_interpretation.get('exploit_confirmed', False),
            llm_interpretation.get('observed_impact', 'N/A'),
            overall_attack_phase_time
        ))
        conn.commit()
        #logging.info(f"Differential AEP attack details for model '{model_name}' logged for {target_filename} - {vulnerability_type}.")
    except Exception as e:
        logging.error(f"Error logging differential AEP attack: {e}", exc_info=True)
    finally:
        conn.close()


# --- COMPARATIVE ANALYSIS EXPERIMENTS ---
def log_injection_attempt(run_id: int, attempt_number: int, status: str, 
                         task_prompt: str = None, generated_code: str = None,
                         feedback_given: str = None, bleu_score: float | None = None,
                         semantic_justification: str = None, 
                         static_analysis_report: dict = None,
                         metrics: 'CodeMetrics' = None):
    """
    Logs a single injection attempt to the injection_attempts table.
    
    Args:
        run_id: Foreign key to the comparative_analysis_runs table
        attempt_number: Which attempt this is (1-5)
        status: Outcome of the attempt (SUCCESS, FAILURE_SYNTAX_ERROR, etc.)
        task_prompt: The plan/prompt generated for this attempt
        generated_code: Code produced by the coder agent
        feedback_given: Feedback passed to the next iteration
        bleu_score: Legacy quantitative similarity score (deprecated, use metrics instead)
        semantic_justification: LLM evaluation justification
        static_analysis_report: Static analysis results as dict
        metrics: CodeMetrics object containing all quantitative metrics
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("BEGIN TRANSACTION")
        
        # Extract metric values from CodeMetrics object or use legacy parameters
        if metrics is not None:
            code_bleu_score = metrics.code_bleu_score
            bleu_4_score = metrics.bleu_4_score
            rouge_l_score = metrics.rouge_l_score
            normalized_edit_distance = metrics.normalized_edit_distance
            # Use legacy bleu_score parameter if provided, otherwise use bleu_4_score from metrics
            legacy_bleu_score = bleu_score if bleu_score is not None else metrics.bleu_4_score
        else:
            # Backward compatibility: use legacy parameters
            code_bleu_score = None
            bleu_4_score = bleu_score  # Map legacy bleu_score to bleu_4_score
            rouge_l_score = None
            normalized_edit_distance = None
            legacy_bleu_score = bleu_score

        cursor.execute('''
        INSERT INTO injection_attempts (
            run_id, attempt_number, status, task_prompt, generated_code,
            feedback_given, bleu_score, code_bleu_score, bleu_4_score, 
            rouge_l_score, normalized_edit_distance, semantic_justification, 
            static_analysis_report, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            run_id, attempt_number, status, task_prompt, generated_code,
            feedback_given, legacy_bleu_score, code_bleu_score, bleu_4_score,
            rouge_l_score, normalized_edit_distance, semantic_justification,
            json.dumps(static_analysis_report) if static_analysis_report else None,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        
        cursor.execute("COMMIT")
        #logging.info(f"Successfully logged injection attempt {attempt_number} for run_id {run_id}")
        
    except sqlite3.Error as e:
        cursor.execute("ROLLBACK")
        logging.error(f"Database error while logging injection attempt: {e}", exc_info=True)
        raise
    finally:
        conn.close()


def log_injection_attempts_batch(run_id: int, attempts_data: list):
    """
    Logs multiple injection attempts in a single transaction for better performance and consistency.
    
    Args:
        run_id: Foreign key to the comparative_analysis_runs table
        attempts_data: List of dictionaries containing attempt data
                      Each dict should have keys: attempt_number, status, task_prompt, 
                      generated_code, feedback_given, bleu_score, semantic_justification, 
                      static_analysis_report, and optionally 'metrics' (CodeMetrics object)
    """
    if not attempts_data:
        return
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("BEGIN TRANSACTION")
        
        for attempt_data in attempts_data:
            # Extract metric values from CodeMetrics object or use legacy parameters
            metrics = attempt_data.get('metrics')
            if metrics is not None:
                code_bleu_score = metrics.code_bleu_score
                bleu_4_score = metrics.bleu_4_score
                rouge_l_score = metrics.rouge_l_score
                normalized_edit_distance = metrics.normalized_edit_distance
                # Use legacy bleu_score parameter if provided, otherwise use bleu_4_score from metrics
                legacy_bleu_score = attempt_data.get('bleu_score', metrics.bleu_4_score)
            else:
                # Backward compatibility: use legacy parameters
                code_bleu_score = None
                bleu_4_score = attempt_data.get('bleu_score')  # Map legacy bleu_score to bleu_4_score
                rouge_l_score = None
                normalized_edit_distance = None
                legacy_bleu_score = attempt_data.get('bleu_score')

            cursor.execute('''
            INSERT INTO injection_attempts (
                run_id, attempt_number, status, task_prompt, generated_code,
                feedback_given, bleu_score, code_bleu_score, bleu_4_score, 
                rouge_l_score, normalized_edit_distance, semantic_justification, 
                static_analysis_report, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                run_id,
                attempt_data.get('attempt_number'),
                attempt_data.get('status'),
                attempt_data.get('task_prompt'),
                attempt_data.get('generated_code'),
                attempt_data.get('feedback_given'),
                legacy_bleu_score,
                code_bleu_score,
                bleu_4_score,
                rouge_l_score,
                normalized_edit_distance,
                attempt_data.get('semantic_justification'),
                json.dumps(attempt_data.get('static_analysis_report')) if attempt_data.get('static_analysis_report') else None,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
        
        cursor.execute("COMMIT")
        #logging.info(f"Successfully logged {len(attempts_data)} injection attempts for run_id {run_id}")
        
    except sqlite3.Error as e:
        cursor.execute("ROLLBACK")
        logging.error(f"Database error while logging injection attempts batch: {e}", exc_info=True)
        raise
    finally:
        conn.close()


def log_comparative_run(model_full_name: str, file_name: str,
                        vulnerability_type: str, model_type: str, prompt_strategy: str,
                        rag_context: str, final_prompt: str, 
                        original_code: str,
                        expected_code: str,
                        generated_code: str,
                        static_confirmation_status: str, static_analysis_report: dict,
                        static_interpreter_justification: str,
                        semantic_confirmation_status: str, 
                        semantic_justification: str, 
                        failure_reason: str,
                        attempts_taken: int = 1,
                        final_metrics: 'CodeMetrics' = None):
    """
    Logs the results of a single run with separate static and semantic evaluations.
    Enhanced to support final outcome columns for agentic feedback loop and comprehensive metrics.
    
    Args:
        attempts_taken: Total number of attempts made (1-5)
        final_metrics: CodeMetrics object containing all quantitative metrics from successful attempt
    
    Returns:
        int: The ID of the inserted run record for linking injection attempts
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    run_id = None
    
    try:
        # Start transaction
        cursor.execute("BEGIN TRANSACTION")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS comparative_analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT,
            model_type TEXT,
            prompt_strategy TEXT,
            target_filename TEXT,
            vulnerability_type TEXT,
            rag_context TEXT,
            final_prompt TEXT,
            original_code TEXT,
            expected_code TEXT,
            generated_code TEXT,
            static_confirmation_status TEXT,
            static_analysis_report TEXT,
            static_interpreter_justification TEXT,
            semantic_confirmation_status TEXT,         
            semantic_justification TEXT,
            failure_reason TEXT,             
            run_timestamp TEXT,
            attempts_taken INTEGER DEFAULT 1,
            final_code_bleu_score REAL,
            final_bleu_4_score REAL,
            final_rouge_l_score REAL,
            final_normalized_edit_distance REAL
        )
        ''')
        
        # Extract final metric values from CodeMetrics object
        if final_metrics is not None:
            final_code_bleu_score = final_metrics.code_bleu_score
            final_bleu_4_score = final_metrics.bleu_4_score
            final_rouge_l_score = final_metrics.rouge_l_score
            final_normalized_edit_distance = final_metrics.normalized_edit_distance
        else:
            # No metrics available
            final_code_bleu_score = None
            final_bleu_4_score = None
            final_rouge_l_score = None
            final_normalized_edit_distance = None

        cursor.execute('''
        INSERT INTO comparative_analysis_runs (
            model_name, model_type, prompt_strategy, target_filename,
            vulnerability_type, rag_context, final_prompt, original_code, expected_code, generated_code,
            static_confirmation_status, static_analysis_report, static_interpreter_justification,
            semantic_confirmation_status, semantic_justification,  
            failure_reason, run_timestamp, attempts_taken,
            final_code_bleu_score, final_bleu_4_score, final_rouge_l_score, final_normalized_edit_distance
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            model_full_name, model_type, prompt_strategy, file_name,
            vulnerability_type, rag_context, final_prompt, original_code, expected_code, 
            generated_code.encode('utf-8').decode('unicode_escape', errors='replace'),
            static_confirmation_status, json.dumps(static_analysis_report, indent=2),
            static_interpreter_justification,
            semantic_confirmation_status,  
            semantic_justification,
            failure_reason,   
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attempts_taken,
            final_code_bleu_score,
            final_bleu_4_score,
            final_rouge_l_score,
            final_normalized_edit_distance
        ))
        
        # Get the ID of the inserted record
        run_id = cursor.lastrowid
        
        # Commit transaction
        cursor.execute("COMMIT")
        #logging.info(f"Successfully logged comparative run for model '{model_full_name}' ({prompt_strategy}) to the database with ID {run_id}")
        
    except sqlite3.Error as e:
        cursor.execute("ROLLBACK")
        logging.error(f"Database error while logging comparative run for '{model_full_name}': {e}", exc_info=True)
        raise
    finally:
        if conn:
            conn.close()
    
    return run_id


def plot_agent_performance(db_path=DB_PATH):
    
    # can be adapted later to plot the new comparative_analysis_runs table.
    conn = sqlite3.connect(db_path)
    # ... (rest of the plotting function is unchanged)
    try:
        # ...
        pass
    finally:
        conn.close()


def save_agent_state(agent, filename):
    agent.save_agent_state(filename)


# --- VALIDATION FUNCTIONS FOR ENHANCED ORCHESTRATION FLOW ---

def validate_database_connection(db_path: str = DB_PATH) -> tuple[bool, str]:
    """
    Validate that the database connection is working and accessible.
    
    Args:
        db_path: Path to the SQLite database
        
    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        conn.close()
        return True, ""
    except sqlite3.OperationalError as e:
        return False, f"Database operational error: {e}"
    except sqlite3.DatabaseError as e:
        return False, f"Database error: {e}"
    except Exception as e:
        return False, f"Unexpected database error: {e}"


def validate_foreign_key_exists(run_id: int, db_path: str = DB_PATH) -> tuple[bool, str]:
    """
    Validate that a run_id exists in the comparative_analysis_runs table before inserting injection attempts.
    
    Args:
        run_id: The run ID to validate
        db_path: Path to the SQLite database
        
    Returns:
        tuple[bool, str]: (exists, error_message)
    """
    if run_id is None or not isinstance(run_id, int) or run_id <= 0:
        return False, f"Invalid run_id: {run_id}. Must be a positive integer."
    
    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM comparative_analysis_runs WHERE id = ?", (run_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result is None:
            return False, f"Run ID {run_id} does not exist in comparative_analysis_runs table"
        
        return True, ""
        
    except sqlite3.Error as e:
        return False, f"Database error while validating run_id {run_id}: {e}"
    except Exception as e:
        return False, f"Unexpected error while validating run_id {run_id}: {e}"


def validate_attempt_metadata(attempt_data: Dict[str, Any]) -> tuple[bool, str]:
    """
    Validate the structure and content of attempt metadata.
    
    Args:
        attempt_data: Dictionary containing attempt metadata
        
    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    required_fields = ['attempt', 'status', 'timestamp']
    optional_fields = ['task_prompt', 'generated_code', 'feedback_given', 'bleu_score', 
                      'semantic_justification', 'static_analysis_report']
    
    # Check required fields
    for field in required_fields:
        if field not in attempt_data:
            return False, f"Missing required field: {field}"
        
        if attempt_data[field] is None:
            return False, f"Required field '{field}' cannot be None"
    
    # Validate attempt number
    attempt_num = attempt_data.get('attempt')
    if not isinstance(attempt_num, int) or attempt_num < 1 or attempt_num > 5:
        return False, f"Invalid attempt number: {attempt_num}. Must be integer between 1 and 5."
    
    # Validate status
    valid_statuses = [
        'SUCCESS', 'FAILURE_PLANNER', 'FAILURE_NO_CODE_CHANGE', 
        'FAILURE_SYNTAX_ERROR', 'FAILURE_CONFIRMATION', 'FAILURE_UNKNOWN'
    ]
    status = attempt_data.get('status')
    if status not in valid_statuses:
        return False, f"Invalid status: {status}. Must be one of: {valid_statuses}"
    
    # Validate timestamp format
    timestamp = attempt_data.get('timestamp')
    if not isinstance(timestamp, str):
        return False, f"Timestamp must be a string, got: {type(timestamp)}"
    
    try:
        datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    except ValueError as e:
        return False, f"Invalid timestamp format: {timestamp}. Expected YYYY-MM-DD HH:MM:SS. Error: {e}"
    
    # Validate BLEU score if present (legacy)
    bleu_score = attempt_data.get('bleu_score')
    if bleu_score is not None:
        if not isinstance(bleu_score, (int, float)):
            return False, f"BLEU score must be numeric, got: {type(bleu_score)}"
        if not (0.0 <= bleu_score <= 1.0) and bleu_score != -1.0:  # Allow -1.0 for failed calculations
            return False, f"BLEU score must be between 0.0 and 1.0 or -1.0 for failures, got: {bleu_score}"
    
    # Validate CodeMetrics object if present
    metrics = attempt_data.get('metrics')
    if metrics is not None:
        # Import here to avoid circular imports
        try:
            from code_similarity_evaluator import CodeMetrics
            if not isinstance(metrics, CodeMetrics):
                return False, f"metrics must be a CodeMetrics object, got: {type(metrics)}"
            
            # Validate individual metric scores
            metric_fields = ['code_bleu_score', 'bleu_4_score', 'rouge_l_score', 'normalized_edit_distance']
            for field in metric_fields:
                value = getattr(metrics, field, None)
                if value is not None:
                    if not isinstance(value, (int, float)):
                        return False, f"metrics.{field} must be numeric, got: {type(value)}"
                    if not (0.0 <= value <= 1.0) and value != -1.0:  # Allow -1.0 for failed calculations
                        return False, f"metrics.{field} must be between 0.0 and 1.0 or -1.0 for failures, got: {value}"
        except ImportError:
            return False, "CodeMetrics class not available for validation"
    
    # Validate string fields are not empty if provided
    string_fields = ['task_prompt', 'generated_code', 'feedback_given', 'semantic_justification']
    for field in string_fields:
        value = attempt_data.get(field)
        if value is not None and not isinstance(value, str):
            return False, f"Field '{field}' must be a string if provided, got: {type(value)}"
        if value is not None and not value.strip():
            return False, f"Field '{field}' cannot be empty string if provided"
    
    # Validate static analysis report structure if present
    static_report = attempt_data.get('static_analysis_report')
    if static_report is not None:
        if not isinstance(static_report, dict):
            return False, f"static_analysis_report must be a dictionary if provided, got: {type(static_report)}"
    
    return True, ""


def validate_phase_log_structure(phase_log: Dict[str, Any]) -> tuple[bool, str]:
    """
    Validate the structure and content of the phase_log returned by run_injection_phase.
    
    Args:
        phase_log: Dictionary containing phase log data
        
    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    if not isinstance(phase_log, dict):
        return False, f"phase_log must be a dictionary, got: {type(phase_log)}"
    
    required_fields = ['final_status', 'total_attempts', 'attempts']
    for field in required_fields:
        if field not in phase_log:
            return False, f"Missing required field in phase_log: {field}"
    
    # Validate final_status
    valid_final_statuses = ['SUCCESS', 'FAILURE_MAX_ATTEMPTS_REACHED']
    final_status = phase_log.get('final_status')
    if final_status not in valid_final_statuses:
        return False, f"Invalid final_status: {final_status}. Must be one of: {valid_final_statuses}"
    
    # Validate total_attempts
    total_attempts = phase_log.get('total_attempts')
    if not isinstance(total_attempts, int) or total_attempts < 0 or total_attempts > 5:
        return False, f"Invalid total_attempts: {total_attempts}. Must be integer between 0 and 5."
    
    # Validate attempts list
    attempts = phase_log.get('attempts')
    if not isinstance(attempts, list):
        return False, f"attempts must be a list, got: {type(attempts)}"
    
    if len(attempts) != total_attempts:
        return False, f"attempts list length ({len(attempts)}) doesn't match total_attempts ({total_attempts})"
    
    # Validate each attempt in the list
    for i, attempt in enumerate(attempts):
        is_valid, error_msg = validate_attempt_metadata(attempt)
        if not is_valid:
            return False, f"Invalid attempt {i+1}: {error_msg}"
    
    # Validate successful_attempt if present
    successful_attempt = phase_log.get('successful_attempt')
    if successful_attempt is not None:
        if not isinstance(successful_attempt, int) or successful_attempt < 1 or successful_attempt > total_attempts:
            return False, f"Invalid successful_attempt: {successful_attempt}. Must be between 1 and {total_attempts}."
        
        # Check that the final_status is SUCCESS if successful_attempt is set
        if final_status != 'SUCCESS':
            return False, f"successful_attempt is set but final_status is not SUCCESS: {final_status}"
    

    return True, ""


def validate_orchestration_inputs(original_code: str, original_file_path: str, 
                                intended_vuln_details: Dict[str, Any], 
                                model_name: str, model_format: str) -> tuple[bool, str]:
    """
    Validate inputs to the orchestration process.
    
    Args:
        original_code: The original code to inject vulnerabilities into
        original_file_path: Path to the original file
        intended_vuln_details: Dictionary containing vulnerability details
        model_name: Name of the model being used
        model_format: Format of the model
        
    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    # Validate original_code
    if not isinstance(original_code, str):
        return False, f"original_code must be a string, got: {type(original_code)}"
    if not original_code.strip():
        return False, "original_code cannot be empty"
    if len(original_code) > 1_000_000:  # 1MB limit
        return False, f"original_code too large: {len(original_code)} characters (max 1MB)"
    
    # Validate original_file_path
    if not isinstance(original_file_path, str):
        return False, f"original_file_path must be a string, got: {type(original_file_path)}"
    if not original_file_path.strip():
        return False, "original_file_path cannot be empty"
    
    # Validate intended_vuln_details
    if not isinstance(intended_vuln_details, dict):
        return False, f"intended_vuln_details must be a dictionary, got: {type(intended_vuln_details)}"
    
    required_vuln_fields = ['type']
    for field in required_vuln_fields:
        if field not in intended_vuln_details:
            return False, f"Missing required field in intended_vuln_details: {field}"
        if not isinstance(intended_vuln_details[field], str):
            return False, f"intended_vuln_details['{field}'] must be a string"
        if not intended_vuln_details[field].strip():
            return False, f"intended_vuln_details['{field}'] cannot be empty"
    
    # Validate model_name
    if not isinstance(model_name, str):
        return False, f"model_name must be a string, got: {type(model_name)}"
    if not model_name.strip():
        return False, "model_name cannot be empty"
    
    # Validate model_format
    if not isinstance(model_format, str):
        return False, f"model_format must be a string, got: {type(model_format)}"
    if not model_format.strip():
        return False, "model_format cannot be empty"
    
    return True, ""


def safe_log_injection_attempt(run_id: int, attempt_number: int, status: str, 
                              task_prompt: str = None, generated_code: str = None,
                              feedback_given: str = None, bleu_score: float | None = None,
                              semantic_justification: str = None, 
                              static_analysis_report: dict = None,
                              metrics: 'CodeMetrics' = None) -> tuple[bool, str]:
    """
    Safely log an injection attempt with comprehensive validation and error handling.
    
    Returns:
        tuple[bool, str]: (success, error_message)
    """
    try:
        # Validate database connection
        db_valid, db_error = validate_database_connection()
        if not db_valid:
            return False, f"Database connection failed: {db_error}"
        
        # Validate foreign key exists
        fk_valid, fk_error = validate_foreign_key_exists(run_id)
        if not fk_valid:
            return False, f"Foreign key validation failed: {fk_error}"
        
        # Validate attempt metadata
        attempt_data = {
            'attempt': attempt_number,
            'status': status,
            'task_prompt': task_prompt,
            'generated_code': generated_code,
            'feedback_given': feedback_given,
            'bleu_score': bleu_score,
            'semantic_justification': semantic_justification,
            'static_analysis_report': static_analysis_report,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        metadata_valid, metadata_error = validate_attempt_metadata(attempt_data)
        if not metadata_valid:
            return False, f"Attempt metadata validation failed: {metadata_error}"
        
        # Perform the actual logging
        log_injection_attempt(
            run_id=run_id,
            attempt_number=attempt_number,
            status=status,
            task_prompt=task_prompt,
            generated_code=generated_code,
            feedback_given=feedback_given,
            bleu_score=bleu_score,
            semantic_justification=semantic_justification,
            static_analysis_report=static_analysis_report,
            metrics=metrics
        )
        
        return True, ""
        
    except Exception as e:
        error_msg = f"Error in safe_log_injection_attempt: {e}"
        logging.error(error_msg, exc_info=True)
        return False, error_msg


def safe_log_comparative_run(model_full_name: str, file_name: str,
                           vulnerability_type: str, model_type: str, prompt_strategy: str,
                           rag_context: str, final_prompt: str, 
                           original_code: str, expected_code: str, generated_code: str,
                           static_confirmation_status: str, static_analysis_report: dict,
                           static_interpreter_justification: str,
                           semantic_confirmation_status: str, semantic_justification: str, 
                           failure_reason: str, attempts_taken: int = 1, 
                           final_metrics: 'CodeMetrics' = None) -> tuple[Optional[int], str]:
    """
    Safely log a comparative run with comprehensive validation and error handling.
    
    Returns:
        tuple[Optional[int], str]: (run_id or None, error_message)
    """
    try:
        # Validate database connection
        db_valid, db_error = validate_database_connection()
        if not db_valid:
            return None, f"Database connection failed: {db_error}"
        
        # Validate inputs
        if not isinstance(model_full_name, str) or not model_full_name.strip():
            return None, "model_full_name must be a non-empty string"
        
        if not isinstance(file_name, str) or not file_name.strip():
            return None, "file_name must be a non-empty string"
        
        if not isinstance(vulnerability_type, str) or not vulnerability_type.strip():
            return None, "vulnerability_type must be a non-empty string"
        

        if not isinstance(attempts_taken, int) or attempts_taken < 1 or attempts_taken > 5:
            return None, f"attempts_taken must be integer between 1 and 5, got: {attempts_taken}"
        
        # Perform the actual logging
        run_id = log_comparative_run(
            model_full_name=model_full_name,
            file_name=file_name,
            vulnerability_type=vulnerability_type,
            model_type=model_type,
            prompt_strategy=prompt_strategy,
            rag_context=rag_context,
            final_prompt=final_prompt,
            original_code=original_code,
            expected_code=expected_code,
            generated_code=generated_code,
            static_confirmation_status=static_confirmation_status,
            static_analysis_report=static_analysis_report,
            static_interpreter_justification=static_interpreter_justification,
            semantic_confirmation_status=semantic_confirmation_status,
            semantic_justification=semantic_justification,
            failure_reason=failure_reason,
            attempts_taken=attempts_taken,
            final_metrics=final_metrics
        )
        
        return run_id, ""
        
    except Exception as e:
        error_msg = f"Error in safe_log_comparative_run: {e}"
        logging.error(error_msg, exc_info=True)
        return None, error_msg


def cleanup_orphaned_attempts(db_path: str = DB_PATH) -> tuple[int, str]:
    """
    Clean up orphaned injection attempts that reference non-existent run IDs.
    
    Returns:
        tuple[int, str]: (number_cleaned, error_message)
    """
    try:
        conn = sqlite3.connect(db_path, timeout=10.0)
        cursor = conn.cursor()
        
        cursor.execute("BEGIN TRANSACTION")
        
        # Find orphaned attempts
        cursor.execute('''
            SELECT COUNT(*) FROM injection_attempts 
            WHERE run_id NOT IN (SELECT id FROM comparative_analysis_runs)
        ''')
        orphaned_count = cursor.fetchone()[0]
        
        if orphaned_count > 0:
            # Delete orphaned attempts
            cursor.execute('''
                DELETE FROM injection_attempts 
                WHERE run_id NOT IN (SELECT id FROM comparative_analysis_runs)
            ''')
            
            logging.warning(f"Cleaned up {orphaned_count} orphaned injection attempts")
        
        cursor.execute("COMMIT")
        conn.close()
        
        return orphaned_count, ""
        
    except sqlite3.Error as e:
        if conn:
            cursor.execute("ROLLBACK")
            conn.close()
        error_msg = f"Database error during cleanup: {e}"
        logging.error(error_msg, exc_info=True)
        return 0, error_msg
    except Exception as e:
        if conn:
            conn.close()
        error_msg = f"Unexpected error during cleanup: {e}"
        logging.error(error_msg, exc_info=True)
        return 0, error_msg


def log_phase3_run(
    test_name: str,
    model_name: str,
    verdict: str,
    passed: bool,
    failure_reasons: list,
    iteration: int,
    provision_time: float,
    functional_time: float,
    security_time: float,
    total_time: float,
    sep_json: str,
    cep_json: str,
    aep_json: str,
    fep_json: str,
    vuln_functional_passed: Optional[bool] = None,
    vuln_exploit_triggered: Optional[bool] = None,
    patch_functional_passed: Optional[bool] = None,
    patch_exploit_blocked: Optional[bool] = None,
    experiment_name: Optional[str] = None,
) -> Optional[int]:
    """
    Log a Phase 3 verification run to the database.

    Creates the phase3_verification_runs table if it doesn't exist and inserts
    one row per test execution. This mirrors the JSON persistence in plan_saver.py
    but keeps all experiment data queryable in the same SQLite DB used by Phases 1/2.

    Returns:
        The row id of the inserted record, or None on error.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute("BEGIN TRANSACTION")

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS phase3_verification_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_name TEXT NOT NULL,
            model_name TEXT,
            experiment_name TEXT,
            verdict TEXT,
            passed INTEGER,
            failure_reasons TEXT,
            iteration INTEGER,
            provision_time REAL,
            functional_time REAL,
            security_time REAL,
            total_time REAL,
            vuln_functional_passed INTEGER,
            vuln_exploit_triggered INTEGER,
            patch_functional_passed INTEGER,
            patch_exploit_blocked INTEGER,
            sep_json TEXT,
            cep_json TEXT,
            aep_json TEXT,
            fep_json TEXT,
            run_timestamp TEXT
        )
        ''')

        cursor.execute('''
        INSERT INTO phase3_verification_runs (
            test_name, model_name, experiment_name, verdict, passed,
            failure_reasons, iteration,
            provision_time, functional_time, security_time, total_time,
            vuln_functional_passed, vuln_exploit_triggered,
            patch_functional_passed, patch_exploit_blocked,
            sep_json, cep_json, aep_json, fep_json,
            run_timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            test_name, model_name, experiment_name, verdict, int(passed),
            json.dumps(failure_reasons), iteration,
            round(provision_time, 3), round(functional_time, 3),
            round(security_time, 3), round(total_time, 3),
            int(vuln_functional_passed) if vuln_functional_passed is not None else None,
            int(vuln_exploit_triggered) if vuln_exploit_triggered is not None else None,
            int(patch_functional_passed) if patch_functional_passed is not None else None,
            int(patch_exploit_blocked) if patch_exploit_blocked is not None else None,
            sep_json, cep_json, aep_json, fep_json,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ))

        row_id = cursor.lastrowid
        cursor.execute("COMMIT")
        logging.info(f"Phase 3 result logged to DB (id={row_id}) for '{test_name}'")
        return row_id

    except sqlite3.Error as e:
        if conn:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
        logging.error(f"DB error logging Phase 3 run for '{test_name}': {e}", exc_info=True)
        return None
    except Exception as e:
        if conn:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
        logging.error(f"Unexpected error logging Phase 3 run for '{test_name}': {e}", exc_info=True)
        return None
    finally:
        if conn:
            conn.close()
