.PHONY: test scan
scan:      ## fail if anything secret-shaped or personal-looking is in the tree
	bash tools/sensitivity-scan.sh
test:      ## run the containment test
	bash tests/test_pdf_screen.sh
	PYTHONDONTWRITEBYTECODE=1 python3 tools/test_sensitivity_scan.py
