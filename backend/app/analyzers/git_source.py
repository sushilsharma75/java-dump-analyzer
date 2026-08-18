"""
Fetch source code from a Git hosting URL (GitHub, Bitbucket, GitLab) without
requiring a local `git` install for the common cases.

Strategy:
  1. Parse the URL into (host, owner, repo, ref).
  2. For known hosts, download a zip/tarball archive over HTTPS (codeload-style
     endpoints) — fast, no clone, no .git history.
  3. Fall back to `git clone --depth 1` for anything we can't map to an archive.

Returns the extracted directory so the existing SourceIndex can walk it.
"""
from __future__ import annotations
import io
import os
import re
import shutil
import zipfile
import tarfile
import tempfile
import subprocess
import urllib.request
from pathlib import Path
from typing import Optional, Tuple, List


class GitFetchError(Exception):
    pass


def parse_repo_url(url: str) -> dict:
    """Normalize a repo URL/shorthand into its parts.

    Accepts forms like:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/main
      git@github.com:owner/repo.git
      https://bitbucket.org/owner/repo
      https://gitlab.com/owner/repo
      owner/repo                      (assumed GitHub)
    """
    url = url.strip()
    ref: Optional[str] = None

    # scp-style: git@host:owner/repo.git
    m = re.match(r"git@([^:]+):(.+)", url)
    if m:
        host = m.group(1)
        rest = m.group(2)
    else:
        # Bare shorthand owner/repo → GitHub
        if re.match(r"^[\w.-]+/[\w.-]+$", url):
            host = "github.com"
            rest = url
        else:
            m2 = re.match(r"^(?:https?://)?([^/]+)/(.+)$", url)
            if not m2:
                raise GitFetchError(f"Could not parse repository URL: {url}")
            host = m2.group(1)
            rest = m2.group(2)

    rest = rest.removesuffix(".git")

    # Pull out an explicit ref from /tree/<ref>, /src/<ref>, /-/tree/<ref>
    parts = rest.split("/")
    owner = parts[0] if parts else ""
    repo = parts[1] if len(parts) > 1 else ""
    if len(parts) > 2:
        # github: tree/<ref>; bitbucket: src/<ref>; gitlab: -/tree/<ref>
        markers = {"tree", "src", "branch", "commits", "commit"}
        for i in range(2, len(parts)):
            if parts[i] in markers and i + 1 < len(parts):
                ref = parts[i + 1]
                break

    if not owner or not repo:
        raise GitFetchError(f"URL missing owner/repo: {url}")

    return {"host": host.lower(), "owner": owner, "repo": repo, "ref": ref}


def _candidate_archive_urls(host: str, owner: str, repo: str, ref: Optional[str]) -> List[Tuple[str, str]]:
    """Return [(url, kind)] archive download candidates, kind in {zip,tar}."""
    refs = [ref] if ref else ["main", "master", "develop"]
    out: List[Tuple[str, str]] = []
    if host in ("github.com", "www.github.com"):
        for r in refs:
            out.append((f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{r}", "zip"))
            out.append((f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{r}", "tar"))
        if ref:  # could be a tag or raw sha
            out.append((f"https://codeload.github.com/{owner}/{repo}/zip/{ref}", "zip"))
            out.append((f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}", "tar"))
    elif host in ("bitbucket.org", "www.bitbucket.org"):
        for r in refs:
            out.append((f"https://bitbucket.org/{owner}/{repo}/get/{r}.zip", "zip"))
            out.append((f"https://bitbucket.org/{owner}/{repo}/get/{r}.tar.gz", "tar"))
    elif host in ("gitlab.com", "www.gitlab.com"):
        for r in refs:
            out.append((f"https://gitlab.com/{owner}/{repo}/-/archive/{r}/{repo}-{r}.zip", "zip"))
            out.append((f"https://gitlab.com/{owner}/{repo}/-/archive/{r}/{repo}-{r}.tar.gz", "tar"))
    return out


# Cap on download size to protect the server (source repos are small; this is generous)
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024


def _download(url: str, token: Optional[str]) -> Optional[bytes]:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "postmortem-source-fetch")
    if token:
        # GitHub/GitLab accept bearer; Bitbucket uses app passwords via basic auth (not handled here)
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = b""
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_ARCHIVE_BYTES:
                    raise GitFetchError("Repository archive exceeds 500MB limit")
            return data
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise GitFetchError(
                "Access denied (private repo?). Provide a personal access token, "
                "or use the zip-upload option instead."
            )
        return None
    except Exception:
        return None


def _extract_archive(data: bytes, kind: str, dest: Path) -> Path:
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                norm = os.path.normpath(name)
                if norm.startswith("..") or os.path.isabs(norm):
                    raise GitFetchError(f"Unsafe path in archive: {name}")
            zf.extractall(dest)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for member in tf.getmembers():
                norm = os.path.normpath(member.name)
                if norm.startswith("..") or os.path.isabs(norm):
                    raise GitFetchError(f"Unsafe path in archive: {member.name}")
            tf.extractall(dest)
    # Archives wrap everything in a single top dir (repo-ref/); point at it
    entries = [p for p in dest.iterdir() if not p.name.startswith(".")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def _git_clone(url: str, ref: Optional[str], dest: Path) -> Path:
    """Fallback: shallow clone using the git CLI."""
    clone_url = url
    if not url.startswith(("http://", "https://", "git@")):
        clone_url = f"https://{url}"
    cmd = ["git", "clone", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [clone_url, str(dest / "repo")]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=120)
    except subprocess.CalledProcessError as e:
        msg = e.stderr.decode(errors="replace")[-300:] if e.stderr else str(e)
        raise GitFetchError(f"git clone failed: {msg}")
    except FileNotFoundError:
        raise GitFetchError("git is not installed and no archive endpoint matched this host.")
    except subprocess.TimeoutExpired:
        raise GitFetchError("git clone timed out after 120s.")
    return dest / "repo"


def fetch_repo(url: str, token: Optional[str], parent_dir: Path) -> Tuple[Path, dict]:
    """
    Download a repo's source into a subdir of parent_dir.

    Returns (source_root, meta) where meta describes what was fetched.
    Raises GitFetchError on failure.
    """
    info = parse_repo_url(url)
    work = Path(tempfile.mkdtemp(prefix="postmortem_git_", dir=parent_dir))

    # 1. Try archive endpoints (no git, fast)
    for archive_url, kind in _candidate_archive_urls(
        info["host"], info["owner"], info["repo"], info["ref"]
    ):
        data = _download(archive_url, token)
        if data:
            root = _extract_archive(data, kind, work)
            return root, {**info, "method": "archive", "archive_url": archive_url}

    # 2. Fall back to git clone
    root = _git_clone(url, info["ref"], work)
    return root, {**info, "method": "clone"}
