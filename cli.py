#!/usr/bin/env python3
"""
CP-ABE Secure File Sharing — Command-Line Interface

Usage
-----
  python cli.py [--server URL] [--keys-dir DIR] COMMAND [ARGS]

Global options (can also be set via environment variables):
  --server   URL   Storage server base URL  (env: STORAGE_SERVER_URL)
  --keys-dir DIR   Directory for key files  (env: KEYS_DIR, default: keys/)

Commands
--------
  setup            Authority: generate PK and MK
  keygen           Authority: issue a secret key for a user
  encrypt          DataOwner: encrypt a file under an access policy
  upload           DataOwner: upload an encrypted package to the server
  ls               List files stored on the server
  download         Download an encrypted package from the server
  decrypt          DataUser: decrypt a downloaded package
  demo             Run the basic access control demo (no server needed)
  demo-collusion   Run the collusion resistance demo (no server needed)

Quickstart (after docker-compose up)
--------------------------------------
  python cli.py setup
  python cli.py keygen alice -a role:doctor -a dept:cardiology
  python cli.py encrypt report.pdf -p "role:doctor and dept:cardiology"
  python cli.py upload report.pdf.pkg
  python cli.py download report.pdf.pkg
  python cli.py decrypt report.pdf.pkg alice
"""

from pathlib import Path

import click
import requests

_DEFAULT_SERVER = "http://localhost:8000"
_DEFAULT_KEYS_DIR = "keys"


# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group()
@click.option(
    "--server", default=_DEFAULT_SERVER, envvar="STORAGE_SERVER_URL", show_default=True,
    help="Storage server base URL.",
)
@click.option(
    "--keys-dir", default=_DEFAULT_KEYS_DIR, envvar="KEYS_DIR", show_default=True,
    help="Directory for PK, MK, and user secret keys.",
)
@click.pass_context
def cli(ctx, server, keys_dir):
    ctx.ensure_object(dict)
    ctx.obj["server"] = server
    ctx.obj["keys_dir"] = Path(keys_dir)


# ---------------------------------------------------------------------------
# Authority commands
# ---------------------------------------------------------------------------

@cli.command()
@click.pass_context
def setup(ctx):
    """Authority: generate the public key (PK) and master key (MK)."""
    from authority.authority import authority_setup
    authority_setup(keys_dir=ctx.obj["keys_dir"])


@cli.command()
@click.argument("user_id")
@click.option(
    "--attr", "-a", "attributes", multiple=True, required=True,
    help="Attribute to assign (repeat for multiple). Use lowercase, e.g. -a role:doctor",
)
@click.pass_context
def keygen(ctx, user_id, attributes):
    """Authority: issue a secret key for USER_ID with the given attributes."""
    from authority.authority import authority_keygen
    authority_keygen(user_id, list(attributes), keys_dir=ctx.obj["keys_dir"])


# ---------------------------------------------------------------------------
# DataOwner commands
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("file_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--policy", "-p", required=True,
    help='Access policy, e.g. "(role:doctor and dept:cardiology) or role:admin"',
)
@click.option(
    "--out", "-o", default=None,
    help="Output package path (default: <file_path>.pkg)",
)
@click.pass_context
def encrypt(ctx, file_path, policy, out):
    """DataOwner: encrypt FILE_PATH under a CP-ABE access policy."""
    from data_owner.owner import encrypt_and_package

    pkg_bytes = encrypt_and_package(file_path, policy, keys_dir=ctx.obj["keys_dir"])

    out_path = Path(out) if out else file_path.with_suffix(file_path.suffix + ".pkg")
    out_path.write_bytes(pkg_bytes)
    click.echo(f"Package written → {out_path}  ({len(pkg_bytes):,} bytes)")


@cli.command()
@click.argument("package_path", type=click.Path(exists=True, path_type=Path))
@click.option("--file-id", default=None, help="ID to use on the server (default: filename).")
@click.pass_context
def upload(ctx, package_path, file_id):
    """DataOwner: upload an encrypted package to the storage server."""
    server = ctx.obj["server"]
    fid = file_id or package_path.name

    with open(package_path, "rb") as fh:
        resp = requests.post(f"{server}/upload/{fid}", files={"file": fh}, timeout=30)

    resp.raise_for_status()
    info = resp.json()
    click.echo(f"Uploaded '{fid}'  ({info['size_bytes']:,} bytes)  →  {server}")


# ---------------------------------------------------------------------------
# Storage commands
# ---------------------------------------------------------------------------

@cli.command("ls")
@click.pass_context
def list_files(ctx):
    """List files currently stored on the server."""
    resp = requests.get(f"{ctx.obj['server']}/files", timeout=10)
    resp.raise_for_status()
    files = resp.json()["files"]
    if not files:
        click.echo("(no files on server)")
        return
    for f in files:
        click.echo(f"  {f['file_id']:<40}  {f['size_bytes']:>10,} bytes")


@cli.command()
@click.argument("file_id")
@click.option("--out", "-o", default=None, help="Local output path (default: file_id).")
@click.pass_context
def download(ctx, file_id, out):
    """Download an encrypted package from the storage server."""
    resp = requests.get(f"{ctx.obj['server']}/download/{file_id}", timeout=60)
    resp.raise_for_status()

    out_path = Path(out or file_id)
    out_path.write_bytes(resp.content)
    click.echo(f"Downloaded '{file_id}'  ({len(resp.content):,} bytes)  →  {out_path}")


# ---------------------------------------------------------------------------
# DataUser commands
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("package_path", type=click.Path(exists=True, path_type=Path))
@click.argument("user_id")
@click.option("--out-dir", "-d", default="downloads", show_default=True,
              help="Directory to write the decrypted file.")
@click.pass_context
def decrypt(ctx, package_path, user_id, out_dir):
    """DataUser: decrypt PACKAGE_PATH as USER_ID."""
    from data_user.user import decrypt_package
    from crypto.cpabe import DecryptionError

    pkg_bytes = package_path.read_bytes()
    try:
        out_path = decrypt_package(
            pkg_bytes, user_id,
            output_dir=Path(out_dir),
            keys_dir=ctx.obj["keys_dir"],
        )
        click.echo(f"Decrypted → {out_path}")
    except DecryptionError as exc:
        click.echo(f"[ACCESS DENIED] {exc}", err=True)
        raise SystemExit(1) from exc


# ---------------------------------------------------------------------------
# Demo commands
# ---------------------------------------------------------------------------

@cli.command()
def demo():
    """Run the basic access control demo (no storage server required)."""
    from demo.demo_basic import run_demo
    run_demo()


@cli.command("demo-collusion")
def demo_collusion():
    """Run the collusion resistance demo (no storage server required)."""
    from demo.demo_collusion import run_collusion_demo
    run_collusion_demo()


if __name__ == "__main__":
    cli()
