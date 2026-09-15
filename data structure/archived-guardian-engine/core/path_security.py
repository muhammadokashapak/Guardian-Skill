import os
from pathlib import Path
from typing import Set

class PathSecurityError(Exception):
    pass

class PathSecurity:
    PROTECTED_FILENAMES: Set[str] = {
        ".env",
        ".env.local",
        ".env.production",
        ".env.stage",
        ".git",
        "id_rsa",
        "id_ed25519",
        "id_dsa",
        "credentials",
        "secret_key",
    }

    PROTECTED_EXTENSIONS: Set[str] = {
        ".pem",
        ".key",
        ".pkcs12",
        ".pfx",
    }

    @classmethod
    def canonicalize_and_validate(cls, root_dir: str, target_path: str, allow_write: bool = False) -> str:
        """
        Ensures target_path resolves strictly within root_dir,
        detects symlink escapes, path traversals, and protects sensitive files.
        """
        abs_root = os.path.realpath(os.path.abspath(root_dir))
        
        # Combine if relative
        if not os.path.isabs(target_path):
            combined = os.path.join(abs_root, target_path)
        else:
            combined = target_path

        real_target = os.path.realpath(os.path.abspath(combined))

        # 1. Root containment check
        try:
            common = os.path.commonpath([abs_root, real_target])
            if common != abs_root:
                raise PathSecurityError(f"Access Denied: Path '{target_path}' escapes workspace root '{root_dir}'")
        except ValueError:
            # Different drives on Windows
            raise PathSecurityError(f"Access Denied: Path '{target_path}' resides on a different drive than workspace root")

        # 2. Check for symlink pointing outside
        if os.path.islink(combined):
            link_target = os.path.realpath(combined)
            if not link_target.startswith(abs_root):
                raise PathSecurityError(f"Access Denied: Symlink '{target_path}' points outside workspace root")

        # 3. Check protected files & directories
        path_parts = Path(real_target).parts
        file_name = Path(real_target).name.lower()
        file_ext = Path(real_target).suffix.lower()

        # Check for .git or protected dir in hierarchy
        for part in path_parts:
            if part.lower() == ".git":
                raise PathSecurityError(f"Access Denied: Access to '.git' repository metadata is strictly prohibited")

        if file_name in cls.PROTECTED_FILENAMES or file_name.startswith(".env"):
            if allow_write:
                raise PathSecurityError(f"Access Denied: Modification of protected file '{file_name}' is forbidden")

        if file_ext in cls.PROTECTED_EXTENSIONS and allow_write:
            raise PathSecurityError(f"Access Denied: Modification of cryptographic key '{file_name}' is forbidden")

        return real_target
