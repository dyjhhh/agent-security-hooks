.PHONY: test scan demo
scan:      ## fail if anything secret-shaped or personal-looking is in the tree
	bash tools/sensitivity-scan.sh
test:      ## run the containment, guard and scanner tests
	bash tests/test_pdf_screen.sh
	bash tests/test_guard_regressions.sh
	PYTHONDONTWRITEBYTECODE=1 python3 tools/test_sensitivity_scan.py
demo:      ## run the safe deny-hook example; the hook only inspects the string and deletes nothing
	@echo '{"tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"rm /tmp/demo-protected/notes.md"}}' \
	  | AGENT_GUARD_PROTECTED_ROOTS=/tmp/demo-protected SECURITY_DENY_LOG=/dev/null bash security/hook-security-deny.sh; \
	  echo "exit $$? (2 = blocked)"
