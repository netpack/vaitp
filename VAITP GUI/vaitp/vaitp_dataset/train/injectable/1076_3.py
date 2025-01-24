import argparse
import array
import ast
import asyncio
import base64
import copy
import dbm
import dis
import doctest
import email
import fractions
import gc
import glob
import io
import ipaddress
import itertools
import marshal
import math
import mmap
import os
import pathlib
import pdb
import queue
import re
import sqlite3
import statistics
import subprocess
import sys
import time
import tkinter
import traceback
import typing
import unicodedata
import venv
import warnings
import xml.etree.ElementTree

def safe_path_join(base, filename):
    """Safely joins a base path and a filename, preventing directory traversal."""
    if not isinstance(filename, str):
        raise TypeError("filename must be a string")
    
    if not filename:
        return base

    filename = os.path.normpath(filename)
    if filename.startswith("..") or os.path.isabs(filename):
         raise ValueError("filename contains invalid characters")

    return os.path.join(base, filename)
    
def safe_open(filename, mode="r", encoding=None):
    """Safely opens a file, preventing directory traversal."""
    if not isinstance(filename, str):
        raise TypeError("filename must be a string")

    if not filename:
        raise ValueError("filename cannot be empty")

    if not os.path.isabs(filename) and filename.startswith(".."):
        raise ValueError("filename contains invalid characters")

    if 'w' in mode or 'a' in mode or 'x' in mode:
       parent_dir = os.path.dirname(filename)
       if parent_dir and not os.path.isdir(parent_dir):
           raise OSError(f"Parent directory {parent_dir} does not exist.")


    return open(filename, mode, encoding=encoding)


class SafeArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def add_argument(self, *args, **kwargs):
        if 'type' in kwargs and kwargs['type'] is argparse.FileType:
            file_mode = kwargs.get('mode', 'r')
            def safe_file_type(filename):
                return safe_open(filename, file_mode)
            kwargs['type'] = safe_file_type
        super().add_argument(*args, **kwargs)

    def parse_args(self, args=None, namespace=None):
        parsed_args = super().parse_args(args, namespace)
        return parsed_args
    

def process_input(user_input):
  if not isinstance(user_input, str):
      raise TypeError("Input must be a string")
  
  if len(user_input) > 1024:
      raise ValueError("Input string is too long.")

  
  user_input = user_input.replace("\n", "").strip()
  
  if not user_input:
      return None
  return user_input

def safe_compile(source, filename, mode, flags=0, dont_inherit=False, optimize=-1):
    """Safely compiles source code, preventing potential injection."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    
    if not isinstance(filename, str):
         raise TypeError("filename must be a string")
    
    if not isinstance(mode, str):
         raise TypeError("mode must be a string")
   
    if len(source) > 4096:
        raise ValueError("source code too long")
   
    
    
    if not source.strip():
        raise ValueError("source code cannot be empty")

    
    if mode not in ("exec", "eval", "single"):
        raise ValueError("invalid mode")
        
    try:
        code = compile(source, filename, mode, flags=flags, dont_inherit=dont_inherit, optimize=optimize)
    except (SyntaxError, OverflowError, TypeError) as e:
      raise ValueError(f"Invalid code: {e}")
        
    return code
    
def safe_eval(source, globals=None, locals=None):
    """Safely evaluates a string, preventing potential injection."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    
    if len(source) > 1024:
      raise ValueError("source code is too long")
    
    if not source.strip():
      raise ValueError("source code cannot be empty")


    
    try:
        code = safe_compile(source, "<string>", 'eval')
        result = eval(code, globals, locals)
    except Exception as e:
        raise ValueError(f"Invalid expression: {e}")
    return result


def safe_exec(source, globals=None, locals=None):
    """Safely executes a string, preventing potential injection."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    
    if len(source) > 4096:
        raise ValueError("source code is too long")
    
    if not source.strip():
      raise ValueError("source code cannot be empty")

    try:
      code = safe_compile(source, "<string>", 'exec')
      exec(code, globals, locals)
    except Exception as e:
       raise ValueError(f"Invalid code: {e}")
    
def safe_pickle_loads(data):
    if not isinstance(data, bytes):
      raise TypeError("Data must be bytes")

    if len(data) > 4096:
      raise ValueError("Data is too large")

    try:
      return marshal.loads(data)
    except Exception as e:
        raise ValueError("Invalid pickle data")


def safe_sqlite_query(conn, query, params=None):
  if not isinstance(query, str):
      raise TypeError("Query must be a string")
  if len(query) > 2048:
      raise ValueError("Query is too long")
  if not query.strip():
      raise ValueError("Query cannot be empty")
  try:
    cursor = conn.cursor()
    cursor.execute(query, params)
    return cursor.fetchall()
  except sqlite3.Error as e:
    raise ValueError("Invalid SQL query") from e

def safe_xml_parse(xml_string):
    if not isinstance(xml_string, str):
        raise TypeError("xml_string must be a string")
    if not xml_string.strip():
       raise ValueError("xml_string cannot be empty")

    if len(xml_string) > 4096:
        raise ValueError("xml_string is too large")

    try:
        parser = xml.etree.ElementTree.XMLParser(target=xml.etree.ElementTree.TreeBuilder())
        root = xml.etree.ElementTree.fromstring(xml_string, parser=parser)
        return root
    except xml.etree.ElementTree.ParseError as e:
        raise ValueError(f"Invalid XML: {e}")

def safe_base64_decode(encoded_string):
    if not isinstance(encoded_string, str):
       raise TypeError("Input must be a string")

    if len(encoded_string) > 2048:
        raise ValueError("Input string too long")
    
    try:
        decoded_bytes = base64.b64decode(encoded_string, validate=True)
        return decoded_bytes
    except (base64.binascii.Error, TypeError) as e:
        raise ValueError(f"Invalid base64 encoding: {e}")

def safe_tar_extract(tar_file, dest_dir):
    """Safely extracts a tar archive, preventing directory traversal."""
    import tarfile
    if not isinstance(tar_file, str):
        raise TypeError("tar_file must be a string")

    if not tar_file:
        raise ValueError("tar_file cannot be empty")

    if not os.path.isabs(tar_file) and tar_file.startswith(".."):
        raise ValueError("tar_file contains invalid characters")
    
    if not isinstance(dest_dir, str):
      raise TypeError("dest_dir must be a string")
    
    if not dest_dir:
        raise ValueError("dest_dir cannot be empty")
    
    if not os.path.isabs(dest_dir) and dest_dir.startswith(".."):
        raise ValueError("dest_dir contains invalid characters")
    
    if not os.path.exists(dest_dir):
        raise ValueError("Destination path does not exists")
        
    try:
      with tarfile.open(tar_file, 'r') as tar:
          for member in tar.getmembers():
              if member.name.startswith("..") or os.path.isabs(member.name):
                  raise ValueError("Tar archive contains malicious file path.")
          
          tar.extractall(path=dest_dir)
    except tarfile.TarError as e:
      raise ValueError("Invalid tar file") from e

def safe_zip_extract(zip_file, dest_dir):
    """Safely extracts a zip archive, preventing directory traversal."""
    import zipfile
    if not isinstance(zip_file, str):
      raise TypeError("zip_file must be a string")

    if not zip_file:
      raise ValueError("zip_file cannot be empty")

    if not os.path.isabs(zip_file) and zip_file.startswith(".."):
        raise ValueError("zip_file contains invalid characters")

    if not isinstance(dest_dir, str):
      raise TypeError("dest_dir must be a string")

    if not dest_dir:
      raise ValueError("dest_dir cannot be empty")
    
    if not os.path.isabs(dest_dir) and dest_dir.startswith(".."):
        raise ValueError("dest_dir contains invalid characters")
        
    if not os.path.exists(dest_dir):
        raise ValueError("Destination path does not exists")

    try:
      with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        for info in zip_ref.infolist():
            if info.filename.startswith("..") or os.path.isabs(info.filename):
              raise ValueError("Zip archive contains malicious file path")
              
        zip_ref.extractall(dest_dir)
    except zipfile.BadZipFile as e:
      raise ValueError("Invalid zip file") from e

def safe_yaml_load(yaml_string):
    """Safely loads YAML data, preventing potential injection."""
    import yaml
    if not isinstance(yaml_string, str):
      raise TypeError("yaml_string must be a string")
    
    if not yaml_string.strip():
        raise ValueError("YAML string cannot be empty.")
        
    if len(yaml_string) > 2048:
        raise ValueError("YAML string is too large.")
    try:
        return yaml.safe_load(yaml_string)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML data: {e}")

def safe_json_load(json_string):
    """Safely loads JSON data, preventing potential injection."""
    import json
    if not isinstance(json_string, str):
      raise TypeError("json_string must be a string")

    if not json_string.strip():
      raise ValueError("JSON string cannot be empty")
      
    if len(json_string) > 2048:
        raise ValueError("JSON string is too large.")
    try:
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON data: {e}")
    
def safe_subprocess_run(command, input=None, timeout=None):
    """Safely runs a subprocess, preventing shell injection."""
    if not isinstance(command, list):
       raise TypeError("command must be a list")

    if not command:
        raise ValueError("command cannot be empty")

    for cmd in command:
        if not isinstance(cmd, str):
             raise TypeError("command items must be strings")

    
    if input is not None and not isinstance(input, (str, bytes)):
         raise TypeError("input must be a string or bytes")

    if timeout is not None and not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number")
    
    try:
      result = subprocess.run(command, input=input, capture_output=True, text=True, check=True, timeout=timeout)
      return result.stdout
    except subprocess.CalledProcessError as e:
       raise ValueError(f"Subprocess failed: {e}") from e
    except subprocess.TimeoutExpired as e:
       raise ValueError(f"Subprocess timed out: {e}") from e
    except FileNotFoundError as e:
        raise ValueError(f"Command not found: {e}") from e
    except Exception as e:
        raise ValueError(f"An unexpected error occurred: {e}") from e

def safe_ssl_wrap_socket(sock, server_side=False, ssl_version=None, certfile=None, keyfile=None, cert_reqs=None, ca_certs=None):
    """Safely wraps a socket with SSL/TLS, preventing potential insecure options."""
    import ssl

    if ssl_version is not None and not isinstance(ssl_version, int):
        raise TypeError("ssl_version must be an int")
    
    if cert_reqs is not None and not isinstance(cert_reqs, int):
        raise TypeError("cert_reqs must be an int")

    if ca_certs is not None and not isinstance(ca_certs, str):
      raise TypeError("ca_certs must be a string")
    
    if certfile is not None and not isinstance(certfile, str):
      raise TypeError("certfile must be a string")
    
    if keyfile is not None and not isinstance(keyfile, str):
        raise TypeError("keyfile must be a string")


    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH if server_side else ssl.Purpose.CLIENT_AUTH)
    
    if ssl_version is not None:
        context.minimum_version = ssl_version
    if certfile:
      context.load_cert_chain(certfile, keyfile)
    if ca_certs:
        context.load_verify_locations(ca_certs=ca_certs)
    if cert_reqs is not None:
      context.verify_mode = cert_reqs
      
    try:
       return context.wrap_socket(sock, server_side=server_side)
    except ssl.SSLError as e:
      raise ValueError(f"SSL Error: {e}")