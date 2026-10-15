PYTHON ?= python3

.PHONY: validate test reports

validate:
	$(PYTHON) scripts/validate_playbooks.py
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) scripts/render_reports.py --check

test:
	$(PYTHON) -m unittest discover -s tests -v

reports:
	$(PYTHON) scripts/render_reports.py
