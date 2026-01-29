#!/bin/bash

set -e

OUTPUT_DIR="/workdir/results"
mkdir -p "$OUTPUT_DIR"

echo "=================================================="
echo "  CVE Automated Execution"
echo "=================================================="
echo ""

# Check if expect is installed
if ! command -v expect &> /dev/null; then
    echo "Installing expect..."
    apt-get update -qq && apt-get install -y expect > /dev/null 2>&1
fi

echo "[1/3] Starting QEMU with symbolic execution..."
echo "  (This may take a few minutes - kernel is bloated)"
echo ""

# Create expect script
cat > "$OUTPUT_DIR/automate.exp" << 'EXPECT_EOF'
#!/usr/bin/expect -f

set timeout 600
set output_file "/workdir/results/execution.log"

# Start logging
log_file -noappend $output_file

# Handle unexpected EOF/crashes
proc handle_unexpected_close {} {
    global output_file
    puts "\n=== WARNING: Process closed unexpectedly ===\n"
    puts "Checking if results were captured...\n"
    
    # Check if we got useful output
    if {[file exists $output_file]} {
        set fp [open $output_file r]
        set content [read $fp]
        close $fp
        
        if {[string match "*CONSTRAINTS WITH VALUES*" $content]} {
            puts "✓ Results were captured before disconnect\n"
            exit 0
        }
    }
    
    puts "❌ No valid results found\n"
    exit 1
}

puts "\n=== Launching QEMU with SymSan wrapper ===\n"

# Launch with error handling
if {[catch {
    spawn env SYMCC_INPUT_FILE=stdin SYMCC_OUTPUT_DIR=/tmp/solver SYMSAN_PC_CONFIG=/workdir/analysis/stage1_output.json SYMSAN_CONSTRAINT_DIR=/workdir/constraints \
        symsan_build/driver/fgtest \
        symfit_symsan_build/x86_64-softmmu/symqemu-system-x86_64 \
        -m 2048 \
        -gdb tcp::2368 \
        -monitor unix:/tmp/qemu-monitor.sock,server,nowait \
        -smp 1 \
        -display none -serial stdio -no-reboot \
        -device virtio-rng-pci \
        -cpu max \
        -kernel /mnt/bzImage_android5_10_wq \
        -device virtio-scsi-pci,id=scsi \
        -device scsi-hd,bus=scsi.0,drive=d0 \
        -drive file=/mnt/disk.qcow2,if=none,id=d0 \
        -append "nokaslr earlyprintk=serial root=/dev/sda1 console=ttyS0" \
        -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:555-:22 \
        -net nic,model=e1000 \
        -accel tcg,thread=multi \
        -nographic \
        -loadvm after-login
} result]} {
    puts "Error spawning QEMU: $result"
    exit 1
}

puts "\n=== Waiting for boot (timeout: 600s) ===\n"

# Wait for login with EOF handling
# expect {
#     "syzkaller login:" {
#         puts "\n=== Login prompt detected ===\n"
#     }
#     eof {
#         puts "\n=== Process died during boot ===\n"
#         handle_unexpected_close
#     }
#     timeout {
#         puts "\n=== ERROR: Boot timeout ===\n"
#         exit 1
#     }
# }

# # Login
# puts "\n=== Logging in as root ===\n"
# send "root\r"

# # Wait for shell
# expect {
#     "# " {
#         puts "\n=== Root shell ready ===\n"
#     }
#     eof {
#         puts "\n=== Process died after login ===\n"
#         handle_unexpected_close
#     }
#     timeout {
#         puts "\n=== ERROR: Login timeout ===\n"
#         exit 1
#     }
# }

# sleep 2

# puts "\n=== Creating QEMU snapshot ===\n"

# exec sh -c {echo "savevm after-login" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock}

# Run CVE test
puts "\n=== Executing: ./cve_poc_wmmap ===\n"
send "./cve_poc_wmmap\r"

# Wait for completion with EOF handling
set timeout 600
expect {
    "# " {
        puts "\n=== CVE execution complete ===\n"
    }
    "Segmentation fault" {
        puts "\n=== Segfault detected ===\n"
        expect {
            "# " { puts "=== Recovered ===\n" }
            eof { handle_unexpected_close }
            timeout { puts "=== Continuing... ===\n" }
        }
    }
    eof {
        puts "\n=== Process died during execution ===\n"
        handle_unexpected_close
    }
    timeout {
        puts "\n=== Execution timeout ===\n"
        send "\003"
        sleep 2
    }
}

sleep 3

# Shutdown
puts "\n=== Shutting down VM ===\n"
send "poweroff\r"

set timeout 30
expect {
    eof {
        puts "\n=== VM halted ===\n"
    }
    timeout {
        puts "\n=== Forcing shutdown ===\n"
        send "\003"
        send "poweroff -f\r"
        expect {
            eof { puts "=== Forced halt complete ===\n" }
            timeout { puts "=== Timeout on forced halt ===\n" }
        }
    }
}

# Cleanup
catch {close}
catch {wait}

puts "\n=== Expect script complete ===\n"
exit 0
EXPECT_EOF
chmod +x "$OUTPUT_DIR/automate.exp"

# Run the expect script
cd /workdir
"$OUTPUT_DIR/automate.exp"

EXIT_CODE=$?

echo ""
echo "[2/3] Processing results..."

if [ -f "$OUTPUT_DIR/execution.log" ]; then
    echo "  ✓ Execution log captured ($(wc -l < "$OUTPUT_DIR/execution.log") lines)"
    
    # Extract constraints
    grep -A 500 "CONSTRAINTS WITH VALUES" "$OUTPUT_DIR/execution.log" 2>/dev/null | \
        head -n -1 > "$OUTPUT_DIR/constraints.txt" || {
        echo "  ⚠️  'CONSTRAINTS WITH VALUES' not found, trying alternative..."
        grep -A 500 "CONSTRAINTS" "$OUTPUT_DIR/execution.log" 2>/dev/null | \
            head -100 > "$OUTPUT_DIR/constraints.txt" || true
    }
    
    # Extract solution
    grep -A 20 "SOLUTION" "$OUTPUT_DIR/execution.log" 2>/dev/null | \
        head -30 > "$OUTPUT_DIR/solution.txt" || true
    
    # Extract just solver output (everything after symbolic execution starts)
    grep -A 10000 "SOLVER RESULT" "$OUTPUT_DIR/execution.log" 2>/dev/null | \
        head -200 > "$OUTPUT_DIR/solver_output.txt" || true
    
    # Check results
    if [ -s "$OUTPUT_DIR/constraints.txt" ]; then
        CONSTRAINT_LINES=$(wc -l < "$OUTPUT_DIR/constraints.txt")
        echo "  ✓ Extracted $CONSTRAINT_LINES constraint lines"
    else
        echo "  ⚠️  No constraints extracted"
        echo ""
        echo "Last 50 lines of execution.log:"
        tail -50 "$OUTPUT_DIR/execution.log"
    fi
else
    echo "  ❌ No execution log found"
    exit 1
fi

echo ""
echo "[3/3] Summary"
echo ""
echo "Exit code: $EXIT_CODE"
echo ""

# Show file sizes
echo "Generated files:"
for file in execution.log constraints.txt solution.txt solver_output.txt; do
    if [ -f "$OUTPUT_DIR/$file" ]; then
        SIZE=$(wc -l < "$OUTPUT_DIR/$file" 2>/dev/null || echo "0")
        printf "  %-20s : %5s lines\n" "$file" "$SIZE"
    fi
done
echo ""

if [ -s "$OUTPUT_DIR/constraints.txt" ]; then
    echo "✓ Symbolic execution completed successfully!"
    echo ""
    echo "Preview of constraints:"
    echo "----------------------------------------"
    head -10 "$OUTPUT_DIR/constraints.txt"
    echo "----------------------------------------"
    echo "(see $OUTPUT_DIR/constraints.txt for full output)"
    echo ""
    exit 0
else
    echo "❌ No constraints found - check $OUTPUT_DIR/execution.log"
    exit 1
fi
