import asyncio
import json
import os
from pathlib import Path
import re
import signal
import sys
import traceback
from typing import Any, Optional
from datetime import datetime
import uuid
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeSDKClient,
    Message,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    tool,
    create_sdk_mcp_server,
    ClaudeAgentOptions,
)
from claude_agent_sdk.types import StreamEvent


@tool(
    name="run_qemu",
    description="Run qemu and get constraints",
    input_schema={
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "vulnerability_summary": {"type": "string"},
            "vulnerable_function": {"type": "string"},
            "loop_locations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "loop_id": {"type": "string"},
                        "loop_type": {"type": "string"},
                        "source_line": {"type": "number"},
                        "loop_condition_pc": {"type": "string", "description": "It has to be the PC of conditional jump (ja, jl, jne), NOT test, cmp, etc."},
                        "loop_body_start_pc": {"type": "string"},
                        "relevant_variables": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "why_relevant": {"type": "string"},
                    },
                    "required": [
                        "loop_id",
                        "loop_type",
                        "source_line",
                        "loop_condition_pc",
                        "loop_body_start_pc",
                        "relevant_variables",
                        "why_relevant",
                    ],
                },
            },
            "allocation_pc": {"type": "string"},
            "oob_write_pc": {"type": "string"},
        },
        "required": [
            "vulnerability_summary",
            "vulnerable_function",
            "loop_locations",
            "allocation_pc",
            "oob_write_pc",
        ],
    },
)
async def run_qemu(args: dict[str, Any]) -> dict[str, Any]:
    run_id = uuid.uuid4().hex
    base_dir = Path("/workdir") / run_id
    analysis_dir = base_dir / "analysis"
    analysis_dir.mkdir(parents=True)
    constraint_dir = base_dir / "constraints"
    constraint_dir.mkdir(parents=True)
    pc_config_path = analysis_dir / "stage1_output.json"
    with open(pc_config_path, "w", encoding="utf-8") as f:
        json.dump(args, f)
    env = os.environ.copy()
    env.update({
        "SYMCC_INPUT_FILE": "stdin",
        "SYMCC_OUTPUT_DIR": "/tmp/solver",
        "SYMSAN_PC_CONFIG": str(pc_config_path),
        "SYMSAN_CONSTRAINT_DIR": str(constraint_dir),
    })
    proc = await asyncio.create_subprocess_exec(
        "symsan_build/driver/fgtest",
        "symfit_symsan_build/x86_64-softmmu/symqemu-system-x86_64",
        "-m",
        "2048",
        "-gdb",
        "tcp::2368",
        "-monitor",
        "unix:/tmp/qemu-monitor.sock,server,nowait",
        "-smp",
        "1",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-device",
        "virtio-rng-pci",
        "-cpu",
        "max",
        "-kernel",
        "/workdir/symfit/bzImage_android5_10_wq",
        "-device",
        "virtio-scsi-pci,id=scsi",
        "-device",
        "scsi-hd,bus=scsi.0,drive=d0",
        "-drive",
        "file=/workdir/symfit/disk.qcow2,if=none,id=d0",
        "-append",
        "nokaslr earlyprintk=serial root=/dev/sda1 console=ttyS0",
        "-net",
        "user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:555-:22",
        "-net",
        "nic,model=e1000",
        "-accel",
        "tcg,thread=multi",
        "-nographic",
        "-loadvm",
        "after-login",
        env=env,
        stdin=asyncio.subprocess.PIPE,  # or None if you don't need it
        stdout=asyncio.subprocess.PIPE,  # or asyncio.subprocess.DEVNULL
        stderr=asyncio.subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    assert proc.stdin
    assert proc.stdout
    proc.stdin.write(b"./cve_poc_wmmap\r")
    await proc.stdin.drain()
    proc.stdin.close()
    try:
        with open(analysis_dir / "execution.log", "wb") as log:
            async with asyncio.timeout(60):
                while True:
                    # TODO timeout
                    try:
                        data = await asyncio.wait_for(proc.stdout.readline(), 3)
                    except asyncio.TimeoutError:
                        if proc.stdout._buffer.startswith(b"# "):
                            print("\n=== CVE execution complete ===")
                            os.killpg(proc.pid, signal.SIGTERM)
                            break
                        continue
                    if not data:
                        break
                    log.write(data)
                    line = data.decode('utf-8', 'replace').rstrip()
                    print(line)
    except asyncio.TimeoutError:
        print('qemu timed out. killing...')
        os.killpg(proc.pid, signal.SIGTERM)

    await proc.wait()
    return {
        "content": [{"type": "text", "text": "Constraints can be find at: " + str([str(v) for v in constraint_dir.glob("*")])}]
    }


server = create_sdk_mcp_server(
    name="symfit",
    version="1.0.0",
    tools=[run_qemu],
)

cwd = Path(".").expanduser().resolve() / "claude-code"
cwd.mkdir(parents=True, exist_ok=True)
options = ClaudeAgentOptions(
    mcp_servers={"symfit": server},
    permission_mode="bypassPermissions",
    include_partial_messages=True,
    system_prompt="You are a helpful assistant that can help with kernel poc exploitation",
    env={"MCP_TOOL_TIMEOUT": "3600000"},
    cwd=cwd,
    max_buffer_size=10*1024*1024,
)


def handle_message(message: Message):
    global session_id

    if isinstance(message, SystemMessage):
        if message.subtype == "init":
            pass
    elif isinstance(message, StreamEvent):
        type_ = message.event.get("type")
        if type_ == "content_block_start":
            block = message.event.get("content_block", {})
            if block.get("type") == "tool_use":
                tool_name = block.get("name", "")
                if m := re.match(r"mcp__[a-zA-Z0-9-]+__(\w+)", tool_name):
                    tool_name = m.group(1)
                # sys.stdout.write(f"Calling tool: {tool_name} ")
        elif type_ == "content_block_delta":
            delta = message.event.get("delta", {})
            if delta.get("type") == "text_delta":
                sys.stdout.write(delta.get("text", ""))
            elif delta.get("type") == "input_json_delta":
                # sys.stdout.write(delta.get("partial_json", ""))
                pass
            elif delta.get("type") == "thinking_delta":
                sys.stdout.write(delta.get("thinking", ""))
        elif type_ == "content_block_stop":
            sys.stdout.write("\n\n")
    elif isinstance(message, UserMessage):
        if isinstance(message.content, str):
            sys.stdout.write(message.content)
        for content in message.content:
            if isinstance(content, TextBlock):
                sys.stdout.write(f"{content.text}\n")
            elif isinstance(content, ToolUseBlock):
                sys.stdout.write(
                    f"Calling tool (user message): {content.name} {json.dumps(content.input)}\n\n"
                )
            elif isinstance(content, ToolResultBlock):
                sys.stdout.write(
                    f"Tool result: error={content.is_error}, content={json.dumps(content.content)}\n\n"
                )
    elif isinstance(message, AssistantMessage):
        for content in message.content:
            if isinstance(content, ToolUseBlock):
                tool_name = content.name
                if m := re.match(r"mcp__[a-zA-Z0-9-]+__(\w+)", content.name):
                    tool_name = m.group(1)
                sys.stdout.write(f"Calling tool {tool_name}({content.input})\n")


async def main():
    async with ClaudeSDKClient(options) as client:
        await client.connect()
        print("Connected to Claude")
        while True:
            user_input = input("\n> ")
            if user_input.lower() == "exit":
                break
            await client.query(user_input)
            async for message in client.receive_messages():
                handle_message(message)
                if isinstance(message, ResultMessage):
                    break
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
