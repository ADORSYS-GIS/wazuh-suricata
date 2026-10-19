#!/usr/bin/env bats

setup() {
    # Directory setup
    TEST_DIR="$(mktemp -d)"
    export TMP_DIR="$TEST_DIR"
    
    # Source the shared utilities
    REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
    # shellcheck source=scripts/shared/utils.sh
    source "$REPO_ROOT/scripts/shared/utils.sh"
}

teardown() {
    rm -rf "$TEST_DIR"
}

@test "command_exists detects existing commands" {
    run command_exists bash
    [ "$status" -eq 0 ]
    
    run command_exists sh
    [ "$status" -eq 0 ]
}

@test "command_exists returns non-zero for nonexistent commands" {
    run command_exists nonexistent_cmd_xyz_98765
    [ "$status" -ne 0 ]
}

@test "calculate_sha256 computes correct hash for empty file" {
    local empty_file="$TEST_DIR/empty.txt"
    touch "$empty_file"
    
    run calculate_sha256 "$empty_file"
    [ "$status" -eq 0 ]
    [ "$output" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]
}

@test "calculate_sha256 computes correct hash for known content" {
    local sample_file="$TEST_DIR/sample.txt"
    printf "hello world" > "$sample_file"
    
    run calculate_sha256 "$sample_file"
    [ "$status" -eq 0 ]
    # sha256 of "hello world" is b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    [ "$output" = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" ]
}

@test "verify_checksum succeeds on matching sha256" {
    local sample_file="$TEST_DIR/sample.txt"
    printf "hello world" > "$sample_file"
    local expected="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    
    run verify_checksum "$sample_file" "$expected"
    [ "$status" -eq 0 ]
}

@test "verify_checksum fails on mismatched sha256" {
    local sample_file="$TEST_DIR/sample.txt"
    printf "hello world" > "$sample_file"
    local wrong_hash="0000000000000000000000000000000000000000000000000000000000000000"
    
    run verify_checksum "$sample_file" "$wrong_hash"
    [ "$status" -ne 0 ]
    [[ "$output" =~ "Checksum verification FAILED" ]]
}

@test "info_message outputs formatted INFO log" {
    run info_message "Test informational message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[INFO]" ]]
    [[ "$output" =~ "Test informational message" ]]
}

@test "warn_message outputs formatted WARNING log" {
    run warn_message "Test warning message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[WARNING]" ]]
    [[ "$output" =~ "Test warning message" ]]
}

@test "error_message outputs formatted ERROR log" {
    run error_message "Test error message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[ERROR]" ]]
    [[ "$output" =~ "Test error message" ]]
}

@test "success_message outputs formatted SUCCESS log" {
    run success_message "Test success message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[SUCCESS]" ]]
    [[ "$output" =~ "Test success message" ]]
}

@test "print_step outputs formatted STEP log" {
    run print_step "1/5" "Initialize environment"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[STEP]" ]]
    [[ "$output" =~ "1/5: Initialize environment" ]]
}

@test "detect_architecture returns normalized architecture" {
    run detect_architecture
    [ "$status" -eq 0 ]
    [[ "$output" = "amd64" || "$output" = "arm64" ]]
}

@test "detect_distro detects current Linux distro or redhat/debian" {
    if [ "$(uname)" = "Linux" ]; then
        run detect_distro
        [ "$status" -eq 0 ]
        [ -n "$output" ]
    else
        skip "Linux-only test"
    fi
}

@test "create_file writes content to target file" {
    local target="$TEST_DIR/created_file.txt"
    local content="line1\nline2\nline3"
    
    # Mock maybe_sudo to allow testing without sudo
    maybe_sudo() {
        "$@"
    }
    
    run create_file "$target" "$content"
    [ "$status" -eq 0 ]
    [ -f "$target" ]
    run cat "$target"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "line1" ]]
    [[ "$output" =~ "line2" ]]
}

@test "download_file fails when url or dest is missing" {
    run download_file "" "$TEST_DIR/dest.txt"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Usage: download_file" ]]
    
    run download_file "http://example.com" ""
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Usage: download_file" ]]
}

@test "download_file succeeds with mock curl" {
    local dest="$TEST_DIR/downloaded.txt"
    
    # Mock curl and maybe_sudo
    curl() {
        echo "mock download content"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_file "http://example.com/test.tar.gz" "$dest" "test package"
    [ "$status" -eq 0 ]
    [ -f "$dest" ]
    run cat "$dest"
    [[ "$output" =~ "mock download content" ]]
}

@test "error_exit prints error message and exits with code 1" {
    run error_exit "Fatal error occurred"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "[ERROR]" ]]
    [[ "$output" =~ "Fatal error occurred" ]]
}

@test "cleanup removes TMP_DIR" {
    local dummy_dir="$TEST_DIR/dummy_tmp"
    mkdir -p "$dummy_dir"
    TMP_DIR="$dummy_dir"
    
    run cleanup
    [ "$status" -eq 0 ]
    [ ! -d "$dummy_dir" ]
}

@test "calculate_sha256 falls back to shasum if sha256sum is not available" {
    local sample_file="$TEST_DIR/sample.txt"
    printf "hello world" > "$sample_file"
    
    # Mock command_exists to simulate sha256sum missing
    command_exists() {
        if [ "$1" = "sha256sum" ]; then
            return 1
        fi
        command -v "$1" >/dev/null 2>&1
    }
    
    if command -v shasum >/dev/null 2>&1; then
        run calculate_sha256 "$sample_file"
        [ "$status" -eq 0 ]
        [ "$output" = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" ]
    else
        skip "shasum not available"
    fi
}

@test "calculate_sha256 returns error if neither sha256sum nor shasum is available" {
    local sample_file="$TEST_DIR/sample.txt"
    printf "hello world" > "$sample_file"
    
    command_exists() {
        return 1
    }
    
    run calculate_sha256 "$sample_file"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "No SHA256 tool available" ]]
}

@test "download_and_verify_file fails if checksum file does not exist" {
    local dest="$TEST_DIR/dest.txt"
    
    curl() {
        printf "content"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_and_verify_file "http://example.com/test" "$dest" "test" "test_item" "" "$TEST_DIR/nonexistent.sha256"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Checksum file not found" ]]
}

@test "download_and_verify_file fails if pattern not in checksum file" {
    local dest="$TEST_DIR/dest.txt"
    local csum="$TEST_DIR/checksums.sha256"
    printf "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  other-file\n" > "$csum"
    
    curl() {
        printf "content"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_and_verify_file "http://example.com/test" "$dest" "missing-pattern" "test_item" "" "$csum"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "No checksum found for test_item" ]]
}

@test "download_and_verify_file succeeds with valid checksum" {
    local dest="$TEST_DIR/dest.txt"
    local csum="$TEST_DIR/checksums.sha256"
    local hash="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    printf "%s  dest.txt\n" "$hash" > "$csum"
    
    curl() {
        printf "hello world"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_and_verify_file "http://example.com/dest.txt" "$dest" "dest.txt" "dest.txt" "" "$csum"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "downloaded and verified successfully" ]]
}

@test "download_and_verify_file fails when checksum verification fails" {
    local dest="$TEST_DIR/dest.txt"
    local csum="$TEST_DIR/checksums.sha256"
    printf "0000000000000000000000000000000000000000000000000000000000000000  dest.txt\n" > "$csum"
    
    curl() {
        printf "hello world"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_and_verify_file "http://example.com/dest.txt" "$dest" "dest.txt" "dest.txt" "" "$csum"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "checksum verification failed" ]]
}

@test "download_and_verify_file downloads external checksum_url" {
    local dest="$TEST_DIR/dest.txt"
    local hash="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    
    curl() {
        if [[ "$*" =~ "checksums.sha256" ]]; then
            printf "%s  dest.txt\n" "$hash"
        else
            printf "hello world"
        fi
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_and_verify_file "http://example.com/dest.txt" "$dest" "dest.txt" "dest.txt" "http://example.com/checksums.sha256"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "downloaded and verified successfully" ]]
}

@test "detect_architecture handles aarch64 and arm64" {
    uname() {
        if [ "$1" = "-m" ]; then
            echo "aarch64"
        else
            command uname "$@"
        fi
    }
    
    run detect_architecture
    [ "$status" -eq 0 ]
    [ "$output" = "arm64" ]
}

@test "detect_architecture fails on unsupported architecture" {
    uname() {
        if [ "$1" = "-m" ]; then
            echo "riscv64"
        else
            command uname "$@"
        fi
    }
    
    run detect_architecture
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Unsupported architecture" ]]
}

@test "maybe_sudo runs directly when running as root (uid 0)" {
    id() {
        if [ "$1" = "-u" ]; then
            echo 0
        else
            command id "$@"
        fi
    }
    
    run maybe_sudo echo "running as root"
    [ "$status" -eq 0 ]
    [ "$output" = "running as root" ]
}

@test "maybe_sudo fails when non-root and sudo is unavailable" {
    id() {
        if [ "$1" = "-u" ]; then
            echo 1000
        else
            command id "$@"
        fi
    }
    command_exists() {
        if [ "$1" = "sudo" ]; then
            return 1
        fi
        command -v "$1" >/dev/null 2>&1
    }
    
    run maybe_sudo echo "should fail"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "requires root privileges" ]]
}

@test "download_file falls back to wget if curl is unavailable" {
    local dest="$TEST_DIR/dest.txt"
    command_exists() {
        if [ "$1" = "curl" ]; then return 1; fi
        if [ "$1" = "wget" ]; then return 0; fi
        command -v "$1" >/dev/null 2>&1
    }
    wget() {
        printf "content from wget"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_file "http://example.com/file" "$dest" "wget-file"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "downloaded successfully" ]]
}

@test "download_file fails when neither curl nor wget is available" {
    local dest="$TEST_DIR/dest.txt"
    command_exists() {
        if [ "$1" = "curl" ] || [ "$1" = "wget" ]; then return 1; fi
        command -v "$1" >/dev/null 2>&1
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_file "http://example.com/file" "$dest" "no-client-file"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Neither curl nor wget is available" ]]
}



