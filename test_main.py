"""Test suite for NmapMCP input validation."""
import sys
import re
import shlex
import pytest

# Extract validation functions to avoid nmap3 dependency
def validate_target(target: str) -> str:
    """Validate target to prevent command injection."""
    if not target or not target.strip():
        raise ValueError("Target cannot be empty")

    target = target.strip()

    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
    for char in dangerous_chars:
        if char in target:
            raise ValueError(f"Target contains dangerous character: {char}")

    if not re.match(r'^[a-zA-Z0-9\.\-\:\/]+$', target):
        raise ValueError("Target contains invalid characters")

    return target


def validate_args(args: str) -> str:
    """Validate and sanitize args to prevent command injection."""
    if not args:
        return ""

    try:
        parsed = shlex.split(args)
    except ValueError as e:
        raise ValueError(f"Invalid args format: {e}")

    dangerous_options = ['--script', '-oN', '-oX', '-oG', '-oA', '>', '<', '|', ';', '&']
    for opt in parsed:
        for dangerous in dangerous_options:
            if dangerous in opt:
                raise ValueError(f"Blocked dangerous option in args: {opt}")

    return args.strip()


class TestValidateTarget:
    """Test cases for target validation."""

    def test_valid_ip_address(self):
        """Test valid IP addresses."""
        assert validate_target("192.168.1.1") == "192.168.1.1"
        assert validate_target("10.0.0.1") == "10.0.0.1"
        assert validate_target("127.0.0.1") == "127.0.0.1"

    def test_valid_hostname(self):
        """Test valid hostnames."""
        assert validate_target("example.com") == "example.com"
        assert validate_target("subdomain.example.com") == "subdomain.example.com"
        assert validate_target("scanme.nmap.org") == "scanme.nmap.org"

    def test_valid_subnet(self):
        """Test valid subnet notation."""
        assert validate_target("192.168.1.0/24") == "192.168.1.0/24"
        assert validate_target("10.0.0.0/16") == "10.0.0.0/16"

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_target("::1") == "::1"
        assert validate_target("2001:db8::1") == "2001:db8::1"

    def test_empty_target_raises_error(self):
        """Test empty target raises ValueError."""
        with pytest.raises(ValueError, match="Target cannot be empty"):
            validate_target("")
        with pytest.raises(ValueError, match="Target cannot be empty"):
            validate_target("   ")

    def test_command_injection_semicolon(self):
        """Test command injection with semicolon."""
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("127.0.0.1; rm -rf /")

    def test_command_injection_pipe(self):
        """Test command injection with pipe."""
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("127.0.0.1 | cat /etc/passwd")

    def test_command_injection_ampersand(self):
        """Test command injection with ampersand."""
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("127.0.0.1 && whoami")

    def test_command_injection_dollar(self):
        """Test command injection with dollar sign."""
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("$(cat /etc/shadow)")

    def test_command_injection_backtick(self):
        """Test command injection with backtick."""
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("`whoami`")

    def test_command_injection_parentheses(self):
        """Test command injection with parentheses."""
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("127.0.0.1$(command)")

    def test_command_injection_braces(self):
        """Test command injection with braces."""
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("127.0.0.1{command}")

    def test_command_injection_redirect(self):
        """Test command injection with redirection."""
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("127.0.0.1 > /tmp/output")
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("127.0.0.1 < /etc/passwd")

    def test_command_injection_newline(self):
        """Test command injection with newline."""
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("127.0.0.1\nrm -rf /")
        with pytest.raises(ValueError, match="dangerous character"):
            validate_target("127.0.0.1\rm -rf /")

    def test_whitespace_handling(self):
        """Test whitespace is stripped."""
        assert validate_target("  192.168.1.1  ") == "192.168.1.1"


class TestValidateArgs:
    """Test cases for args validation."""

    def test_empty_args(self):
        """Test empty args returns empty string."""
        assert validate_args("") == ""
        assert validate_args("   ") == ""

    def test_valid_port_range(self):
        """Test valid port range arguments."""
        assert validate_args("-p 1-1000") == "-p 1-1000"
        assert validate_args("-p 80,443,8080") == "-p 80,443,8080"

    def test_valid_scan_options(self):
        """Test valid scan options."""
        assert validate_args("-sV") == "-sV"
        assert validate_args("-O") == "-O"
        assert validate_args("-A") == "-A"
        assert validate_args("-T4") == "-T4"

    def test_block_script_option(self):
        """Test --script option is blocked."""
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("--script vuln")
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("--script=http-title")

    def test_block_output_file_options(self):
        """Test output file options are blocked."""
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("-oN output.txt")
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("-oX output.xml")
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("-oG output.grep")
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("-oA all_formats")

    def test_block_shell_operators(self):
        """Test shell operators are blocked."""
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("-p 80 > output.txt")
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("-p 80 < input.txt")
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("-p 80 | grep http")
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("-p 80 ; rm -rf /")
        with pytest.raises(ValueError, match="Blocked dangerous option"):
            validate_args("-p 80 && whoami")

    def test_whitespace_handling(self):
        """Test whitespace is stripped."""
        assert validate_args("  -p 80  ") == "-p 80"

    def test_complex_valid_args(self):
        """Test complex but valid arguments."""
        assert validate_args("-sV -O -T4 -p 1-1000") == "-sV -O -T4 -p 1-1000"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
