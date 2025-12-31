#!/bin/bash
#
# Peekaboo Tracer Wrapper (DynamoRIO version)
# Quick wrapper to use DynamoRIO Peekaboo tracer
#

set -e

DYNAMORIO_PATH="${DYNAMORIO_PATH:-/opt/dynamorio}"
PEEKABOO_LIB="$(dirname "$0")/peekaboo/peekaboo_dr/build/libpeekaboo_dr.so"

if [ ! -f "$PEEKABOO_LIB" ]; then
    echo "ERROR: libpeekaboo_dr.so not found at: $PEEKABOO_LIB"
    echo "Please build Peekaboo DynamoRIO library"
    exit 1
fi

if [ ! -d "$DYNAMORIO_PATH" ]; then
    echo "ERROR: DynamoRIO not found at: $DYNAMORIO_PATH"
    echo "Set DYNAMORIO_PATH environment variable or install to /opt/dynamorio"
    exit 1
fi

# Default options
OUTPUT_DIR="."

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options] -- program [args...]"
            echo ""
            echo "Options:"
            echo "  -o, --output DIR    Output directory (default: trace_output)"
            echo "  -h, --help          Show this help"
            echo ""
            echo "Examples:"
            echo "  $0 -- ls -la"
            echo "  $0 -o trace_ls -- ls"
            echo "  $0 -o trace_cat -- cat /etc/passwd"
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage"
            exit 1
            ;;
    esac
done

if [ $# -eq 0 ]; then
    echo "ERROR: No program specified"
    echo "Usage: $0 [options] -- program [args...]"
    exit 1
fi

# Note: DynamoRIO creates output directory automatically as <appname>-<pid>
# The -o option is ignored but kept for compatibility
echo "Running DynamoRIO Peekaboo tracer..."
echo "Output will be in: $(basename "$1")-<PID>/"
"$DYNAMORIO_PATH/bin64/drrun" -c "$PEEKABOO_LIB" -- "$@" &
DRRUN_PID=$!
wait $DRRUN_PID

if [ $? -ne 0 ]; then
    echo "ERROR: DynamoRIO execution failed"
    exit 1
fi

# Move output to specified directory
if [ "$OUTPUT_DIR" != "." ]; then
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
    fi
    echo "Moving output to: $OUTPUT_DIR"
    mv "$(basename "$1")-$DRRUN_PID" "$OUTPUT_DIR/"
fi
