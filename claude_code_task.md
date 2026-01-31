Analyze the KASAN report at /workdir/mnt/test.report for a kernel vulnerability. 
Identify min and max number of bytes written OOB based on CONSTRAINTS ONLY. 

You have access to:
- vmlinux file at /workdir/mnt/android_vmlinux
- Source code at /workdir/mnt/common
- run_qemu tool to get constraints

MANDATORY STEPS (follow in order):

1. DISASSEMBLE THE FUNCTION:
   Use: objdump -d <vmlinux_path> --disassemble=<function_name>
   Save the complete disassembly for reference.

2. IDENTIFY THE VULNERABILITY TYPE:
   Read the KASAN report and source code to understand the root cause.
   For buffer overflow vulnerabilities, identify:
   - The allocation that creates the undersized buffer
   - The loop(s) that cause the size mismatch
   - The write operation that goes out of bounds

3. FIND EXACT PC ADDRESSES FROM DISASSEMBLY:

   a) allocation_pc:
      - Search for: "call.*__kmalloc\|callq.*__kmalloc"
      - Use the address of the CALL instruction itself
      - Verify it's before the buffer is used

   b) For each conditional jumps inside a loop (identify all loops):
      - loop_condition_pc: PC of conditonal JUMPs (ja, jne, etc.). This includes conditional checks at the loop entry AND conditional checks INSIDE the loop body. The PC has to be (ja, jl, jne, etc.), not (test, cmp, etc.).
      - loop_body_start_pc: Find where that jump lands (loop body start)

   c) oob_write_pc:
      - KASAN reports often show error handler addresses
      - Find the actual "mov" instruction that writes to memory
      - Look for: mov %reg, offset(%reg) patterns
      - It's typically BEFORE a "jne <kasan_handler>" instruction
      - For multi-field writes, it's often a LATER field, not the first

4. STRUCTURE YOUR JSON:
   - Include as many conditional jumps as you need for this vulnerability type
   - Include bounds_check_locations array with all input validation checks

5. VERIFY YOUR ANSWERS:
   ☐ All PC addresses are from actual disassembly (not calculated/guessed)
   ☐ allocation_pc is a "call __kmalloc" instruction
   ☐ oob_write_pc is a "mov" to memory, not "call __asan_report_*"
   ☐ You have identified ALL bounds checks that constrain loop iterations
