import os
import time


def tail_file(filepath: str):
    if not os.path.exists(filepath):
        open(filepath, "a").close()

    last_pos = os.path.getsize(filepath)
    buffer = b""

    while True:
        current_size = os.path.getsize(filepath)

        if current_size > last_pos:
            with open(filepath, "rb") as f:
                f.seek(last_pos)
                chunk = f.read(current_size - last_pos)
                last_pos = current_size

            buffer += chunk

            # Process newline-delimited bytes
            while b"\n" in buffer:
                line_bytes, buffer = buffer.split(b"\n", 1)

                # Strip null bytes (handles UTF-16 from PowerShell) and carriage returns
                cleaned_bytes = line_bytes.replace(b"\x00", b"").strip(b"\r")

                try:
                    line = cleaned_bytes.decode("utf-8", errors="ignore").strip()
                    if line:
                        yield line
                except Exception:
                    continue

        elif current_size < last_pos:
            last_pos = current_size

        time.sleep(0.2)