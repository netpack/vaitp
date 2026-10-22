# docker_utils.py
"""
VAITP Phase 3: Docker Infrastructure Manager
Supports multi-container orchestration with sidecar services,
Docker networking, and robust provisioning.
"""
import shlex, re, docker, logging, os, time, tarfile, io
from typing import List, Dict, Optional, Any
from config import DOCKER_IMAGE, DOCKER_COMMAND, DOCKER_WORKDIR, DOCKER_GENERATED_CODE_FILENAME
from structures import SEP

# Python packages that the LLM planner often puts in the bare dependency list
# (without the "pip:" prefix). These are NOT apt packages — they must be
# auto-reclassified to pip to avoid apt-get failures.
KNOWN_PIP_PACKAGES = {
    'flask', 'django', 'fastapi', 'requests', 'pyjwt', 'jwt', 'pymongo',
    'sqlalchemy', 'jinja2', 'mako', 'pyyaml', 'yaml', 'lxml', 'pillow',
    'cryptography', 'paramiko', 'boto3', 'celery', 'redis', 'gunicorn',
    'uvicorn', 'starlette', 'httpx', 'aiohttp', 'tornado', 'bottle',
    'werkzeug', 'itsdangerous', 'click', 'markupsafe', 'numpy', 'pandas',
    'scipy', 'matplotlib', 'scikit-learn', 'tensorflow', 'torch', 'pytest',
}

# Python built-in modules that can't be pip-installed
BUILTIN_MODULES = {
    'sqlite3', 'os', 'sys', 'json', 're', 'math', 'datetime', 'collections',
    'functools', 'itertools', 'pathlib', 'subprocess', 'threading', 'socket',
    'http', 'urllib', 'io', 'csv', 'hashlib', 'hmac', 'secrets', 'tempfile',
    'shutil', 'glob', 'pickle', 'struct', 'logging', 'unittest', 'typing',
    'abc', 'contextlib', 'copy', 'enum', 'string', 'textwrap', 'time',
    'signal', 'argparse', 'configparser', 'xml', 'html', 'email',
    'tarfile', 'zipfile', 'base64', 'binascii', 'codecs', 'gzip', 'bz2',
    'lzma', 'zlib', 'ast', 'dis', 'token', 'tokenize', 'pdb', 'traceback',
    'uuid', 'random', 'statistics', 'decimal', 'fractions', 'operator',
    'heapq', 'bisect', 'array', 'queue', 'multiprocessing', 'concurrent',
    'asyncio', 'select', 'selectors', 'mmap', 'ctypes', 'platform',
}

# Pip packages that require system-level (apt) build dependencies.
# When these are requested, the corresponding apt packages are auto-installed first.
PIP_SYSTEM_DEPS = {
    'flask-mysqldb': ['pkg-config', 'default-libmysqlclient-dev', 'build-essential'],
    'mysqlclient': ['pkg-config', 'default-libmysqlclient-dev', 'build-essential'],
    'psycopg2': ['libpq-dev', 'build-essential'],
    'pillow': ['libjpeg-dev', 'zlib1g-dev'],
    'lxml': ['libxml2-dev', 'libxslt1-dev'],
    'cryptography': ['libffi-dev', 'build-essential'],
    'bcrypt': ['build-essential', 'libffi-dev'],
}


def check_docker_available() -> bool:
    """Return True if the Docker daemon is reachable, False otherwise."""
    try:
        client = docker.from_env()
        client.ping()
        client.close()
        return True
    except docker.errors.DockerException:
        return False


class DockerNetworkManager:
    """Manages Docker bridge networks for multi-container test environments."""

    def __init__(self, client: docker.DockerClient, network_name: str = "vaitp_net"):
        self.client = client
        self.network_name = network_name
        self.network = None

    def setup(self) -> docker.models.networks.Network:
        """Ensure the test network exists, reusing it if possible.

        Reusing the network avoids DNS resolver flakiness caused by rapid
        create/destroy cycles on Docker's embedded DNS.
        """
        # If we already have a reference, just return it
        if self.network is not None:
            try:
                self.network.reload()
                return self.network
            except Exception:
                self.network = None  # stale reference, fall through

        # Try to reuse an existing network
        try:
            existing = self.client.networks.get(self.network_name)
            logging.info(f"DockerNet: Reusing existing network '{self.network_name}'")
            self.network = existing
            return self.network
        except docker.errors.NotFound:
            pass
        except Exception as e:
            logging.warning(f"DockerNet: Error checking existing network: {e}")

        # Create with retry (Docker may still be cleaning up a recently removed network)
        for attempt in range(1, 4):
            try:
                self.network = self.client.networks.create(self.network_name, driver="bridge")
                logging.info(f"DockerNet: Created network '{self.network_name}'")
                return self.network
            except docker.errors.APIError as e:
                if "already exists" in str(e) and attempt < 3:
                    time.sleep(1)
                    # Try to grab the existing one
                    try:
                        self.network = self.client.networks.get(self.network_name)
                        logging.info(f"DockerNet: Grabbed existing network after create conflict")
                        return self.network
                    except Exception:
                        pass
                else:
                    raise

        raise RuntimeError(f"Failed to create or find network '{self.network_name}' after 3 attempts")

    def teardown(self):
        """Remove the test network, force-disconnecting any lingering endpoints."""
        try:
            net = self.client.networks.get(self.network_name)
            # Force-disconnect all containers first
            try:
                net.reload()
                containers = (net.attrs or {}).get("Containers", {})
                for cid in containers:
                    try:
                        net.disconnect(cid, force=True)
                    except Exception:
                        pass
            except Exception:
                pass
            net.remove()
            logging.info(f"DockerNet: Removed network '{self.network_name}'")
        except docker.errors.NotFound:
            pass
        except Exception as e:
            logging.warning(f"DockerNet: Error during network teardown: {e}")
        self.network = None

    def check_docker_available() -> bool:
        """Return True if the Docker daemon is reachable, False otherwise."""
        try:
            client = docker.from_env()
            client.ping()
            client.close()
            return True
        except docker.errors.DockerException:
            return False




class MultiContainerManager:
    """
    Phase 3 Infrastructure Agent.
    Provisions multi-container environments with sidecar services,
    dependency installation, and file copying.

    Network lifecycle: The Docker bridge network is created once and reused
    across tests. Only torn down on final cleanup or explicit request.
    This avoids DNS resolver flakiness caused by rapid network churn.
    """

    # Class-level network sharing across instances
    _shared_network_name = "vaitp_net"
    _shared_network_ready = False

    def __init__(self):
        self.client = None
        self.network_manager = None
        self.active_containers: List[docker.models.containers.Container] = []
        self.target_container = None
        self._image_cache: Dict[str, str] = {}  # dep_hash -> cached image tag

        try:
            logging.info("MultiContainerManager: Connecting to Docker daemon...")
            self.client = docker.from_env()
            self.client.ping()
            self.network_manager = DockerNetworkManager(self.client)
            logging.info("MultiContainerManager: Connected.")
        except docker.errors.DockerException as e:
            logging.error(f"MultiContainerManager: Docker not available: {e}")
            raise

    def _get_cached_image(self, base_image: str, dependencies: List[str]) -> Optional[str]:
        """Check if a pre-built image with these deps exists.

        Returns the cached image tag if available, None otherwise.
        Builds and caches the image on first use for a given dep set.
        """
        if not dependencies:
            return None

        # Sort deps for consistent hashing
        dep_key = f"{base_image}|{'|'.join(sorted(dependencies))}"
        import hashlib
        dep_hash = hashlib.md5(dep_key.encode()).hexdigest()[:12]
        cache_tag = f"vaitp-cache:{dep_hash}"

        # Check in-memory cache first
        if cache_tag in self._image_cache:
            return self._image_cache[cache_tag]

        # Check if Docker has this image
        try:
            self.client.images.get(cache_tag)
            logging.info(f"  -> Using cached image: {cache_tag}")
            self._image_cache[cache_tag] = cache_tag
            return cache_tag
        except docker.errors.ImageNotFound:
            pass

        # Build the cached image
        apt_deps = [d for d in dependencies if not d.startswith("pip:")]
        pip_deps = [d.split("pip:", 1)[1] for d in dependencies if d.startswith("pip:")]

        # Filter out Python built-in modules from bare deps
        apt_deps = [d for d in apt_deps
                     if d.split('==')[0].split('>=')[0].split('<=')[0].strip().lower() not in BUILTIN_MODULES]

        # Auto-reclassify pip packages the LLM put in the bare dep list
        real_apt = []
        for dep in apt_deps:
            dep_name = dep.split('==')[0].split('>=')[0].split('<=')[0].strip().lower()
            if dep_name in KNOWN_PIP_PACKAGES:
                pip_deps.append(dep)
            else:
                real_apt.append(dep)
        apt_deps = real_apt

        # Filter built-in modules
        pip_deps = [p for p in pip_deps if p.split('==')[0].split('>=')[0].strip() not in BUILTIN_MODULES]

        # Auto-inject system-level build dependencies for pip packages that need them
        for dep in pip_deps:
            dep_name = dep.split('==')[0].split('>=')[0].split('<=')[0].strip().lower()
            if dep_name in PIP_SYSTEM_DEPS:
                for sys_dep in PIP_SYSTEM_DEPS[dep_name]:
                    if sys_dep not in apt_deps:
                        apt_deps.append(sys_dep)

        if not apt_deps and not pip_deps:
            return None

        # Build Dockerfile in memory
        lines = [f"FROM {base_image}"]
        if apt_deps:
            apt_list = " ".join(apt_deps)
            lines.append(f"RUN apt-get update -qq && apt-get install -y -qq {apt_list} && rm -rf /var/lib/apt/lists/*")
        if pip_deps:
            pip_list = " ".join(pip_deps)
            lines.append(f"RUN pip install --no-cache-dir -q {pip_list}")

        dockerfile_content = "\n".join(lines)

        try:
            logging.info(f"  -> Building cached image: {cache_tag} ({len(apt_deps)} apt, {len(pip_deps)} pip)")
            import io as _io
            # Use Docker build API with fileobj
            f = _io.BytesIO(dockerfile_content.encode('utf-8'))
            image, _ = self.client.images.build(fileobj=f, tag=cache_tag, rm=True, quiet=True)
            self._image_cache[cache_tag] = cache_tag
            logging.info(f"  -> Cached image built: {cache_tag}")
            return cache_tag
        except Exception as e:
            logging.warning(f"  -> Failed to build cached image: {e}. Falling back to runtime install.")
            return None

    def copy_file(self, container, src_path: str, dst_path: str):
        """Copy a local file into a container using tar stream."""
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Source file not found: {src_path}")

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode='w') as tar:
            tar.add(src_path, arcname=os.path.basename(dst_path))
        tar_stream.seek(0)
        container.put_archive(os.path.dirname(dst_path), tar_stream)
        logging.debug(f"Copied {src_path} -> {dst_path} in {container.name}")

    def _pull_image_safe(self, image: str):
        """Pull an image, ignoring errors if already cached."""
        try:
            self.client.images.pull(image)
        except Exception as e:
            logging.warning(f"Image pull for '{image}' failed (may be cached): {e}")

    def _install_dependencies(self, container, dependencies: List[str]):
        """Install pip and apt dependencies in the container with retry logic.

        Retries up to 5 times with increasing backoff to handle transient DNS
        resolution failures that occur when Docker's embedded DNS resolver is
        momentarily unavailable after network creation or container churn.
        """
        if not dependencies:
            return

        MAX_RETRIES = 5

        apt_deps = [d for d in dependencies if not d.startswith("pip:")]
        pip_deps = [d.split("pip:", 1)[1] for d in dependencies if d.startswith("pip:")]

        # Filter out Python built-in modules from bare deps — LLMs frequently
        # hallucinate stdlib modules (tarfile, base64, zipfile) as dependencies
        filtered_apt = []
        for dep in apt_deps:
            dep_name = dep.split('==')[0].split('>=')[0].split('<=')[0].strip().lower()
            if dep_name in BUILTIN_MODULES:
                logging.info(f"  -> Skipping stdlib module from deps: {dep}")
            else:
                filtered_apt.append(dep)
        apt_deps = filtered_apt

        # Auto-reclassify: the LLM planner often puts pip packages in the bare
        # dependency list (without the "pip:" prefix). Detect known pip packages
        # that are NOT apt packages and move them to pip_deps automatically.
        reclassified = []
        real_apt_deps = []
        for dep in apt_deps:
            dep_name = dep.split('==')[0].split('>=')[0].split('<=')[0].strip().lower()
            if dep_name in KNOWN_PIP_PACKAGES:
                reclassified.append(dep)
                pip_deps.append(dep)
            else:
                real_apt_deps.append(dep)
        if reclassified:
            logging.info(f"  -> Auto-reclassified to pip: {reclassified}")
        apt_deps = real_apt_deps

        # Auto-inject system-level build dependencies for pip packages that need them
        extra_apt = []
        for dep in pip_deps:
            dep_name = dep.split('==')[0].split('>=')[0].split('<=')[0].strip().lower()
            if dep_name in PIP_SYSTEM_DEPS:
                for sys_dep in PIP_SYSTEM_DEPS[dep_name]:
                    if sys_dep not in apt_deps and sys_dep not in extra_apt:
                        extra_apt.append(sys_dep)
        if extra_apt:
            logging.info(f"  -> Auto-adding system build deps: {extra_apt}")
            apt_deps.extend(extra_apt)

        # Filter out Python built-in modules that can't be pip-installed
        filtered_pip = [p for p in pip_deps if p.split('==')[0].split('>=')[0].strip() not in BUILTIN_MODULES]
        if len(filtered_pip) < len(pip_deps):
            skipped = set(pip_deps) - set(filtered_pip)
            logging.info(f"  -> Skipping built-in modules: {skipped}")
        pip_deps = filtered_pip

        # Wait for DNS to be ready before installing anything
        self._wait_for_dns(container)

        # Batch apt-get with retry
        if apt_deps:
            apt_list = " ".join(apt_deps)
            logging.info(f"  -> apt-get install: {apt_list}")
            t0 = time.time()
            success = False
            for attempt in range(1, MAX_RETRIES + 1):
                res = container.exec_run(
                    f"sh -c 'apt-get update -qq && apt-get install -y -qq {apt_list}'",
                    demux=True
                )
                elapsed = time.time() - t0
                if res.exit_code == 0:
                    logging.info(f"     apt-get completed in {elapsed:.1f}s (exit: 0)")
                    success = True
                    break
                else:
                    stderr = ""
                    if res.output and res.output[1]:
                        stderr = res.output[1].decode('utf-8', errors='ignore')[:200]
                    if attempt < MAX_RETRIES:
                        wait = attempt * 3
                        logging.warning(
                            f"     apt-get attempt {attempt}/{MAX_RETRIES} failed (exit: {res.exit_code}). "
                            f"Retrying in {wait}s... {stderr}"
                        )
                        time.sleep(wait)
                    else:
                        logging.error(
                            f"     apt-get FAILED after {MAX_RETRIES} attempts (exit: {res.exit_code}). {stderr}"
                        )

            if not success:
                raise RuntimeError(
                    f"apt-get install failed for [{apt_list}] after {MAX_RETRIES} attempts. "
                    f"Package may not exist or network issue in container."
                )

        # Batch pip install with retry
        if pip_deps:
            pip_list = " ".join(pip_deps)
            logging.info(f"  -> pip install: {pip_list}")
            t0 = time.time()
            success = False
            for attempt in range(1, MAX_RETRIES + 1):
                res = container.exec_run(f"pip install -q {pip_list}", demux=True)
                elapsed = time.time() - t0
                if res.exit_code == 0:
                    logging.info(f"     pip install completed in {elapsed:.1f}s (exit: 0)")
                    success = True
                    break
                else:
                    stderr = ""
                    if res.output and res.output[1]:
                        stderr = res.output[1].decode('utf-8', errors='ignore')[:200]
                    if attempt < MAX_RETRIES:
                        wait = attempt * 3
                        logging.warning(
                            f"     pip attempt {attempt}/{MAX_RETRIES} failed (exit: {res.exit_code}). "
                            f"Retrying in {wait}s... {stderr}"
                        )
                        time.sleep(wait)
                    else:
                        logging.error(
                            f"     pip install FAILED after {MAX_RETRIES} attempts (exit: {res.exit_code}). {stderr}"
                        )

            if not success:
                raise RuntimeError(
                    f"pip install failed for [{pip_list}] after {MAX_RETRIES} attempts. "
                    f"Check build dependencies or network connectivity in container."
                )

    def _wait_for_dns(self, container, timeout: int = 30):
        """Wait until DNS resolution works inside the container.

        Docker's embedded DNS (127.0.0.11 or the gateway) can take a moment
        to become available after a container joins a new network. We require
        TWO consecutive successful checks to avoid false positives from
        intermittent DNS availability.
        """
        deadline = time.time() + timeout
        attempt = 0
        consecutive_ok = 0
        while time.time() < deadline:
            attempt += 1
            res = container.exec_run(
                "sh -c 'getent hosts deb.debian.org && getent hosts pypi.org'",
            )
            if res.exit_code == 0:
                consecutive_ok += 1
                if consecutive_ok >= 2:
                    if attempt > 2:
                        logging.info(f"  -> DNS ready after {attempt} checks")
                    return True
            else:
                consecutive_ok = 0
            time.sleep(1)

        logging.warning(f"  -> DNS not ready after {timeout}s, proceeding anyway")
        return False

    def _wait_for_service(self, container, health_cmd: Optional[str] = None,
                          timeout: int = 30, delay: int = 5):
        """Wait for a sidecar service to become ready."""
        if health_cmd:
            deadline = time.time() + timeout
            while time.time() < deadline:
                res = container.exec_run(health_cmd)
                if res.exit_code == 0:
                    logging.info(f"  -> Service {container.name} is healthy.")
                    return True
                time.sleep(2)
            logging.warning(f"  -> Service {container.name} health check timed out.")
            return False
        else:
            # No health check: just wait a fixed delay
            time.sleep(delay)
            return True

    def provision(self, sep: SEP, vuln_path: str, patch_path: str):
        """
        Provision a complete test environment:
        1. Create Docker network
        2. Start sidecar services (MongoDB, MySQL, etc.)
        3. Start target container
        4. Install dependencies
        5. Run setup commands
        6. Copy vulnerable and patched scripts
        Returns the target container.
        """
        if not sep.image or not sep.image.strip():
            raise ValueError(
                f"SEP has empty docker image for '{sep.target_id}'. "
                "Cannot provision container without a valid image."
            )
        logging.info(f"[*] Provisioning: {sep.target_id}")
        self.active_containers = []
        self.target_container = None

        # 1. Setup network
        self.network_manager.setup()

        # 2. Start sidecar services
        for svc in sep.services:
            alias = svc.get("alias", svc.get("image", "svc").split(":")[0])
            image = svc.get("image", "")
            logging.info(f"  -> Starting sidecar: {alias} ({image})")
            self._pull_image_safe(image)

            # Remove any stale container with the same name
            try:
                stale = self.client.containers.get(alias)
                stale.kill()
                stale.remove()
            except (docker.errors.NotFound, docker.errors.APIError):
                pass

            svc_container = self.client.containers.create(
                image,
                name=alias,
                network=self.network_manager.network_name,
                detach=True,
                environment=svc.get("environment", {}),
                command=svc.get("command"),
            )
            self.active_containers.append(svc_container)
            svc_container.start()

            # Wait for service readiness
            startup_delay = svc.get("startup_delay", 5)
            health_cmd = svc.get("health_check_cmd")
            self._wait_for_service(svc_container, health_cmd, delay=startup_delay)

        # 3. Start target container (use cached image if available)
        cached_image = self._get_cached_image(sep.image, sep.dependencies)
        target_image = cached_image or sep.image
        self._pull_image_safe(target_image) if not cached_image else None

        # Pass execution_context as environment variables to the target container
        target_env = sep.execution_context if hasattr(sep, 'execution_context') and sep.execution_context else {}

        self.target_container = self.client.containers.create(
            target_image,
            command="sleep infinity",
            detach=True,
            working_dir=sep.working_dir,
            network=self.network_manager.network_name,
            environment=target_env,
        )
        self.active_containers.append(self.target_container)
        self.target_container.start()

        try:
            # 4. Install dependencies (skip if using cached image)
            if not cached_image:
                self._install_dependencies(self.target_container, sep.dependencies)
            else:
                logging.info(f"  -> Dependencies pre-installed via cached image")

            # 5. Run setup commands
            for cmd in sep.setup_commands:
                logging.info(f"  -> Setup cmd: {cmd}")
                self.target_container.exec_run(cmd)

            # 6. Copy test scripts
            self.copy_file(self.target_container, vuln_path, f"{sep.working_dir}/main_vuln.py")
            self.copy_file(self.target_container, patch_path, f"{sep.working_dir}/main_patched.py")

            logging.info(f"[*] Provisioning complete for {sep.target_id}")
            return self.target_container

        except Exception as e:
            logging.error(f"Provisioning failed: {e}")
            self.cleanup()
            raise

    def cleanup(self):
        """Kill and remove all containers. Network is preserved for reuse.
        A brief pause after cleanup gives Docker's DNS resolver time to
        stabilize before the next test provisions new containers.
        Also sweeps for orphaned containers on the vaitp_net network that
        may have leaked from timed-out or crashed tests.
        """
        had_containers = len(self.active_containers) > 0
        for c in self.active_containers:
            try:
                c.kill()
            except (docker.errors.NotFound, docker.errors.APIError):
                pass
            except Exception as e:
                logging.warning(f"Cleanup kill error: {e}")
            try:
                c.remove(force=True)
            except (docker.errors.NotFound, docker.errors.APIError):
                pass
            except Exception as e:
                logging.warning(f"Cleanup remove error: {e}")
        self.active_containers = []
        self.target_container = None

        # Sweep for orphaned containers on the vaitp_net network
        try:
            for c in self.client.containers.list(all=True):
                try:
                    networks = c.attrs.get("NetworkSettings", {}).get("Networks", {})
                    if "vaitp_net" in networks:
                        c.remove(force=True)
                        had_containers = True
                except (docker.errors.NotFound, docker.errors.APIError):
                    pass
                except Exception:
                    pass
        except Exception:
            pass

        # Brief pause to let Docker's DNS resolver settle after container removal
        if had_containers:
            time.sleep(1)

    def cleanup_network(self):
        """Tear down the Docker network. Call once at the end of a test suite."""
        if self.network_manager:
            self.network_manager.teardown()


# ==========================================
# Legacy DockerContainerManager (Phase 1/2)
# ==========================================
class DockerContainerManager:
    """Legacy single-container manager for backward compatibility."""

    def __init__(self):
        self.client = None
        self.active_containers = {}
        try:
            logging.info("DockerCM: Attempting to connect to Docker daemon...")
            self.client = docker.from_env()
            self.client.ping()
            logging.info("DockerCM: Successfully connected to Docker daemon.")
        except docker.errors.DockerException as e:
            logging.error(f"DockerCM: Could not connect to Docker. Is it running? Error: {e}")
            raise

    def _create_new_container(self, image: str, command: str, name: str):
        try:
            logging.info(f"DockerCM: Pulling image {image} for {name}...")
            self.client.images.pull(image)
            container = self.client.containers.run(
                image, command, detach=True, tty=True, stdin_open=True,
                name=name, working_dir=DOCKER_WORKDIR
            )
            container.exec_run(f"mkdir -p {DOCKER_WORKDIR}")
            logging.info(f"DockerCM: Installing pipreqs in container {name}...")
            container.exec_run("pip install -q pipreqs")
            logging.info(f"DockerCM: Container {container.name} ({container.short_id}) started.")
            return container
        except Exception as e:
            logging.error(f"DockerCM: Error creating container {name}: {e}")
            return None

    def get_container(self, identifier_suffix: str = "default"):
        container_name = f"vaitp_test_container_{identifier_suffix}"
        try:
            container = self.client.containers.get(container_name)
            if container.status == 'running':
                logging.info(f"DockerCM: Reusing running container {container_name}")
                self.active_containers[identifier_suffix] = container
                return container
            else:
                logging.info(f"DockerCM: Found stopped container {container_name}, removing.")
                container.remove(force=True)
        except docker.errors.NotFound:
            logging.info(f"DockerCM: Container {container_name} not found, creating new.")
        except Exception as e:
            logging.error(f"DockerCM: Error checking for container {container_name}: {e}")

        new_container = self._create_new_container(DOCKER_IMAGE, DOCKER_COMMAND, container_name)
        if new_container:
            self.active_containers[identifier_suffix] = new_container
        return new_container

    def copy_code_to_container(self, container, code_str: str, dest_filename_in_container: str):
        temp_host_file = "temp_code_for_docker.py"
        with open(temp_host_file, "w") as f:
            f.write(code_str)

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.add(temp_host_file, arcname=dest_filename_in_container)
        tar_stream.seek(0)
        container.put_archive(path=DOCKER_WORKDIR, data=tar_stream)
        os.remove(temp_host_file)
        logging.info(f"DockerCM: Copied code to {DOCKER_WORKDIR}/{dest_filename_in_container}")

    def run_code_in_container(self, container, code_str: str,
                              input_str: str = "",
                              timeout_seconds: int = 15,
                              script_filename: str = DOCKER_GENERATED_CODE_FILENAME):
        self.copy_code_to_container(container, code_str, script_filename)
        full_script_path = os.path.join(DOCKER_WORKDIR, script_filename)

        start_time = time.time()
        timed_out = False
        stdout_str, stderr_str, docker_exit_code = "", "", -1

        try:
            exec_cmd_list = ["python", full_script_path, input_str]
            logging.info(f"DockerCM: Running: `{' '.join(exec_cmd_list)}` in {container.name}")
            exec_result = container.exec_run(cmd=exec_cmd_list, workdir=DOCKER_WORKDIR, demux=True)

            if exec_result and exec_result.output is not None:
                s_out_bytes, s_err_bytes = exec_result.output
                stdout_str = s_out_bytes.decode(errors='ignore').strip() if s_out_bytes else ""
                stderr_str = s_err_bytes.decode(errors='ignore').strip() if s_err_bytes else ""
                docker_exit_code = exec_result.exit_code
            elif exec_result:
                docker_exit_code = exec_result.exit_code
            else:
                docker_exit_code = -1

        except docker.errors.APIError as e:
            stderr_str = f"Docker API Error: {e}"
            docker_exit_code = -2
        except Exception as e:
            stderr_str = str(e)
            docker_exit_code = -3

        execution_time = time.time() - start_time
        if execution_time > timeout_seconds:
            timed_out = True

        script_exit_code = None
        full_output = stdout_str + "\n" + stderr_str
        exit_code_match = re.search(r"EXITCODE_(?:ORIGINAL|VULNERABLE):\s*(-?\d+)", full_output)
        if exit_code_match:
            try:
                script_exit_code = int(exit_code_match.group(1))
            except (ValueError, IndexError):
                pass

        stats_after = {}
        try:
            stats_after = container.stats(stream=False)
        except Exception:
            pass

        return {
            "stdout": stdout_str,
            "stderr": stderr_str,
            "docker_exit_code": docker_exit_code,
            "script_exit_code": script_exit_code,
            "execution_time": execution_time,
            "timed_out": timed_out,
            "resource_stats_after": stats_after,
        }

    def cleanup_all_containers(self):
        logging.info("DockerCM: Cleaning up all active VAITP containers...")
        for suffix, container in list(self.active_containers.items()):
            try:
                container.stop(timeout=5)
                container.remove(force=True)
            except docker.errors.NotFound:
                pass
            except Exception as e:
                logging.error(f"DockerCM: Error cleaning up {container.name}: {e}")
            del self.active_containers[suffix]
        if self.client:
            self.client.close()
