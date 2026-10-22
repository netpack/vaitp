"""
oLLM Manager for handling oLLM installation, validation, and version detection.

This module provides functionality to manage the oLLM dependency, including
automatic installation, version detection, and validation of the setup.
"""

import subprocess
import sys
import logging
import os
import venv
from typing import Tuple, Optional, Dict, Any
from pathlib import Path


class OLLMManager:
    """Manages oLLM installation and availability."""

    @staticmethod
    def is_ollm_available() -> bool:
        """
        Check if oLLM is available in the current environment.
        
        Returns:
            bool: True if oLLM can be imported, False otherwise
        """
        try:
            import ollm
            return True
        except ImportError:
            return False

    @staticmethod
    def get_ollm_version() -> Optional[str]:
        """
        Get oLLM version if available.
        
        Returns:
            Optional[str]: Version string if available, None if not installed
        """
        try:
            import ollm
            # Try different ways to get version
            if hasattr(ollm, '__version__'):
                return ollm.__version__
            elif hasattr(ollm, 'version'):
                return ollm.version
            else:
                return 'unknown'
        except ImportError:
            return None

    @staticmethod
    def is_virtual_environment() -> bool:
        """
        Check if running in a virtual environment.
        
        Returns:
            bool: True if in virtual environment, False otherwise
        """
        return (
            hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix) or
            os.environ.get('VIRTUAL_ENV') is not None
        )

    @staticmethod
    def get_environment_info() -> Dict[str, Any]:
        """
        Get information about the current Python environment.
        
        Returns:
            Dict[str, Any]: Environment information including Python version,
                          virtual environment status, and pip location
        """
        return {
            'python_version': sys.version,
            'python_executable': sys.executable,
            'is_virtual_env': OLLMManager.is_virtual_environment(),
            'virtual_env_path': os.environ.get('VIRTUAL_ENV'),
            'pip_executable': sys.executable.replace('python', 'pip') if os.name != 'nt' else sys.executable.replace('python.exe', 'pip.exe')
        }

    @staticmethod
    def install_ollm(force_reinstall: bool = False) -> Tuple[bool, str]:
        """
        Install oLLM if not available.
        
        Args:
            force_reinstall (bool): Force reinstallation even if already available
            
        Returns:
            Tuple[bool, str]: (success, message) indicating installation result
        """
        if OLLMManager.is_ollm_available() and not force_reinstall:
            version = OLLMManager.get_ollm_version()
            return True, f"oLLM already available (version: {version})"

        env_info = OLLMManager.get_environment_info()
        
        # Check if we're in a virtual environment
        if not env_info['is_virtual_env']:
            logging.warning("Not running in a virtual environment. Installation may affect system Python.")

        try:
            logging.info("Installing oLLM from GitHub repository...")
            
            # Prepare installation command
            install_cmd = [
                sys.executable, "-m", "pip", "install"
            ]
            
            if force_reinstall:
                install_cmd.append("--force-reinstall")
                
            install_cmd.append("git+https://github.com/Mega4alik/ollm.git")
            
            # Run installation
            result = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                error_msg = f"pip install failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                logging.error(error_msg)
                return False, error_msg

            # Verify installation
            if OLLMManager.is_ollm_available():
                version = OLLMManager.get_ollm_version()
                success_msg = f"oLLM installed successfully (version: {version})"
                logging.info(success_msg)
                return True, success_msg
            else:
                error_msg = "oLLM installation verification failed - import still fails"
                logging.error(error_msg)
                return False, error_msg

        except subprocess.TimeoutExpired:
            error_msg = "oLLM installation timed out after 5 minutes"
            logging.error(error_msg)
            return False, error_msg
        except subprocess.CalledProcessError as e:
            error_msg = f"oLLM installation failed: {e}"
            logging.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error during oLLM installation: {e}"
            logging.error(error_msg)
            return False, error_msg

    @staticmethod
    def validate_ollm_setup() -> Tuple[bool, str]:
        """
        Validate oLLM setup and dependencies.
        
        Returns:
            Tuple[bool, str]: (is_valid, message) indicating validation result
        """
        if not OLLMManager.is_ollm_available():
            return False, "oLLM not installed"

        try:
            # Test basic import
            import ollm
            
            # Test core functionality availability
            if not hasattr(ollm, 'Inference'):
                return False, "oLLM Inference class not available"
            
            # Try to create a dummy inference object to test basic functionality
            # This doesn't load a model, just tests the API
            try:
                # Test if we can access the Inference class
                inference_class = getattr(ollm, 'Inference')
                if not callable(inference_class):
                    return False, "oLLM Inference class is not callable"
                    
                version = OLLMManager.get_ollm_version()
                return True, f"oLLM setup validated (version: {version})"
                
            except Exception as e:
                return False, f"oLLM Inference class validation failed: {e}"
                
        except ImportError as e:
            return False, f"oLLM import failed: {e}"
        except Exception as e:
            return False, f"oLLM validation failed: {e}"

    @staticmethod
    def get_installation_requirements() -> Dict[str, Any]:
        """
        Get system requirements for oLLM installation.
        
        Returns:
            Dict[str, Any]: Requirements information including Python version,
                          Git availability, and network connectivity
        """
        requirements = {
            'python_version_ok': sys.version_info >= (3, 8),
            'git_available': False,
            'pip_available': False,
            'network_accessible': False,
            'virtual_env_recommended': True,
            'current_env_info': OLLMManager.get_environment_info()
        }
        
        # Check Git availability
        try:
            subprocess.run(['git', '--version'], capture_output=True, check=True)
            requirements['git_available'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            requirements['git_available'] = False
            
        # Check pip availability
        try:
            subprocess.run([sys.executable, '-m', 'pip', '--version'], 
                         capture_output=True, check=True)
            requirements['pip_available'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            requirements['pip_available'] = False
            
        # Basic network check (try to resolve GitHub)
        try:
            import socket
            socket.gethostbyname('github.com')
            requirements['network_accessible'] = True
        except socket.gaierror:
            requirements['network_accessible'] = False
            
        return requirements

    @staticmethod
    def get_installation_status() -> Dict[str, Any]:
        """
        Get comprehensive installation status information.
        
        Returns:
            Dict[str, Any]: Complete status including availability, version,
                          validation results, and requirements
        """
        status = {
            'available': OLLMManager.is_ollm_available(),
            'version': OLLMManager.get_ollm_version(),
            'environment': OLLMManager.get_environment_info(),
            'requirements': OLLMManager.get_installation_requirements()
        }
        
        if status['available']:
            is_valid, validation_msg = OLLMManager.validate_ollm_setup()
            status['validation'] = {
                'valid': is_valid,
                'message': validation_msg
            }
        else:
            status['validation'] = {
                'valid': False,
                'message': 'oLLM not available'
            }
            
        return status

    @staticmethod
    def ensure_ollm_available(auto_install: bool = True) -> Tuple[bool, str]:
        """
        Ensure oLLM is available, installing if necessary.
        
        Args:
            auto_install (bool): Whether to automatically install if not available
            
        Returns:
            Tuple[bool, str]: (success, message) indicating final availability status
        """
        # Check if already available and valid
        if OLLMManager.is_ollm_available():
            is_valid, validation_msg = OLLMManager.validate_ollm_setup()
            if is_valid:
                return True, validation_msg
            else:
                if auto_install:
                    logging.warning(f"oLLM validation failed: {validation_msg}. Attempting reinstall...")
                    return OLLMManager.install_ollm(force_reinstall=True)
                else:
                    return False, f"oLLM validation failed: {validation_msg}"
        
        # Not available, try to install if auto_install is enabled
        if auto_install:
            # Check requirements first
            requirements = OLLMManager.get_installation_requirements()
            
            missing_requirements = []
            if not requirements['python_version_ok']:
                missing_requirements.append("Python 3.8+ required")
            if not requirements['git_available']:
                missing_requirements.append("Git not available")
            if not requirements['pip_available']:
                missing_requirements.append("pip not available")
            if not requirements['network_accessible']:
                missing_requirements.append("Network access to GitHub required")
                
            if missing_requirements:
                error_msg = f"Cannot install oLLM: {', '.join(missing_requirements)}"
                return False, error_msg
                
            return OLLMManager.install_ollm()
        else:
            return False, "oLLM not available and auto_install disabled"