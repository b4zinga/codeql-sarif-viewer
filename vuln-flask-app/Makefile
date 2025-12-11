.PHONY: help clean

help: ## displays this help message.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)


clean: ## clean useless files
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +
	find . -name '*.log' -exec rm -f {} +


run-dev: ## run server in debug mode
	export FLASK_ENV=dev && python wsgi.py


run-prod: ## run server in prod mode
	export FLASK_ENV=prod && python wsgi.py