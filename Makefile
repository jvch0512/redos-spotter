build:
	chmod +x bin/redos-spotter

test:
	sbcl --script tests/test.lisp

sample: build
	mkdir -p docs site
	./bin/redos-spotter examples/patterns.txt > docs/sample-output.txt; true
	./bin/redos-spotter examples/patterns.txt --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "redos-spotter" "Finds regular expressions that can blow up (ReDoS) and proves it with a step-counting matcher. Common Lisp." "A mix of well-known vulnerable patterns and safe ones."
