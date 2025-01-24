```python
"""
project: lollms_user
file: lollms_user.py 
author: ParisNeo
description: 
    This module contains a set of FastAPI routes that provide information about the Lord of Large Language and Multimodal Systems (LoLLMs) Web UI
    application. These routes allow users to do advanced stuff like executing code.

"""
from fastapi import APIRouter, Request
from lollms_webui import LOLLMSWebUI
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse
from lollms.types import MSG_TYPE
from lollms.main_config import BaseConfig
from lollms.utilities import detect_antiprompt, remove_text_from_string, trace_exception, show_yes_no_dialog
from lollms.security import sanitize_path, forbid_remote_access
from ascii_colors import ASCIIColors
from lollms.databases.discussions_database import DiscussionsDB
from pathlib import Path
from safe_store.text_vectorizer import TextVectorizer, VectorizationMethod, VisualizationMethod
import tqdm
from fastapi import FastAPI, UploadFile, File
import shutil
import os
import platform
import string
import re
import subprocess   
from typing import Optional

from lollms.security import sanitize_path

def validate_file_path(path):
    try:
        sanitized_path = sanitize_path(path, allow_absolute_path=False)
        return sanitized_path is not None
    except Exception as e:
        print(f"Path validation error: {str(e)}")
        return False

from utilities.execution_engines.python_execution_engine import execute_python
from utilities.execution_engines.latex_execution_engine import execute_latex
from utilities.execution_engines.shell_execution_engine import execute_bash
from utilities.execution_engines.javascript_execution_engine import execute_javascript
from utilities.execution_engines.html_execution_engine import execute_html

from utilities.execution_engines.mermaid_execution_engine import execute_mermaid
from utilities.execution_engines.graphviz_execution_engine import execute_graphviz



# ----------------------- Defining router and main class ------------------------------

router = APIRouter()
lollmsElfServer:LOLLMSWebUI = LOLLMSWebUI.get_instance()


class CodeRequest(BaseModel):
    client_id: str  = Field(...)
    code: str = Field(..., description="Code to be executed")
    discussion_id: int = Field(..., description="Discussion ID")
    message_id: int = Field(..., description="Message ID")
    language: str = Field(..., description="Programming language of the code")

@router.post("/execute_code")
async def execute_code(request: CodeRequest):
    """
    Executes Python code and returns the output.

    :param request: The HTTP request object.
    :return: A JSON response with the status of the operation.
    """
    client = lollmsElfServer.session.get_client(request.client_id)

    forbid_remote_access(lollmsElfServer, "Code execution is blocked when the server is exposed outside for very obvious reasons!")
    if not lollmsElfServer.config.turn_on_code_execution:
        return {"status":False,"error":"Code execution is blocked by the configuration!"}

    if lollmsElfServer.config.turn_on_code_validation:
        if not show_yes_no_dialog("Validation","Do you validate the execution of the code?"):
            return {"status":False,"error":"User refused the execution!"}

    try:
        code = request.code.replace('\\','\\\\')
        discussion_id = request.discussion_id
        message_id = request.message_id
        language = request.language

        if language=="python":
            ASCIIColors.info("Executing python code:")
            ASCIIColors.yellow(code)
            return execute_python(code, client, message_id)
        if language=="javascript":
            ASCIIColors.info("Executing javascript code:")
            ASCIIColors.yellow(code)
            return execute_javascript(code)
        if language in ["html","html5","svg"]:
            ASCIIColors.info("Executing javascript code:")
            ASCIIColors.yellow(code)
            return execute_html(code)

        elif language=="latex":
            ASCIIColors.info("Executing latex code:")
            ASCIIColors.yellow(code)
            return execute_latex(code, client, message_id)
        elif language in ["bash","shell","cmd","powershell"]:
            ASCIIColors.info("Executing shell code:")
            ASCIIColors.yellow(code)
            return execute_bash(code, client)
        elif language in ["mermaid"]:
            ASCIIColors.info("Executing mermaid code:")
            ASCIIColors.yellow(code)
            return execute_mermaid(code)
        elif language in ["graphviz","dot"]:
            ASCIIColors.info("Executing graphviz code:")
            ASCIIColors.yellow(code)
            return execute_graphviz(code)
        return {"status": False, "error": "Unsupported language", "execution_time": 0}
    except Exception as ex:
        trace_exception(ex)
        lollmsElfServer.error(ex)
        return {"status":False,"error":str(ex)}
    


class FilePath(BaseModel):
    path: Optional[str] = Field(None, max_length=500)

@router.post("/open_file")
async def open_file(file_path: FilePath):
    """
    Opens code in vs code.

    :param file_path: The file path object.
    :return: A JSON response with the status of the operation.
    """

    forbid_remote_access(lollmsElfServer)
    try:
        # Validate the 'path' parameter
        path = sanitize_path(file_path.path)
        if not validate_file_path(path):
            return {"status":False,"error":"Invalid file path"}
        
        # Sanitize the 'path' parameter
        path = os.path.realpath(path)
        
        # Use subprocess.Popen to safely open the file
        if platform.system() == 'Windows':
            subprocess.Popen(["start", path], creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        elif platform.system() == 'Linux':
            subprocess.Popen(['xdg-open', path], start_new_session=True)
        elif platform.system() == 'Darwin':
            subprocess.Popen(['open', path], start_new_session=True)
        
        
        return {"status": True, "execution_time": 0}
    
    except Exception as ex:
        trace_exception(ex)
        lollmsElfServer.error(ex)
        return {"status":False,"error":str(ex)}



class FilePath(BaseModel):
    path: Optional[str] = Field(None, max_length=500)

@router.post("/open_folder")
async def open_folder(file_path: FilePath):
    """
    Opens a folder

    :param file_path: The file path object.
    :return: A JSON response with the status of the operation.
    """

    forbid_remote_access(lollmsElfServer)
    try:
        # Validate the 'path' parameter
        path = sanitize_path(file_path.path)
        if not validate_file_path(path):
            return {"status":False,"error":"Invalid folder path"}
        
        # Sanitize the 'path' parameter
        path = os.path.realpath(path)
        
        # Use subprocess.Popen to safely open the file
        if platform.system() == 'Windows':
            subprocess.Popen([f'explorer', path], creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        elif platform.system() == 'Linux':
            subprocess.Popen(['xdg-open', path], start_new_session=True)
        elif platform.system() == 'Darwin':
            subprocess.Popen(['open', path], start_new_session=True)

        
        return {"status": True, "execution_time": 0}
    
    except Exception as ex:
        trace_exception(ex)
        lollmsElfServer.error(ex)
        return {"status":False,"error":str(ex)}

class OpenCodeFolderInVsCodeRequestModel(BaseModel):
    client_id: str = Field(...)
    discussion_id: Optional[int] = Field(None, gt=0)
    message_id: Optional[int] = Field(None,