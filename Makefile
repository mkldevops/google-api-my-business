include .env
ifneq ("$(wildcard .env.local)","")
	include .env.local
endif

isContainerRunning := $(shell docker info > /dev/null 2>&1 && docker ps | grep "${PROJECT_NAME}-api" > /dev/null 2>&1 && echo 1 || echo 0)

env			= dev
DOCKER		= docker compose
COMPOSER	= symfony composer
CONSOLE		= APP_ENV=$(env) symfony console
GIT			= @git

.DEFAULT_GOAL := sync

sync: composer-install docker-up sf-serve doctrine-reset fixtures-load ## Install and load

help: ## Outputs this help screen
	@grep -E '(^[a-zA-Z0-9_-]+:.*?## .*$$)|(^## )' Makefile | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

sf-serve:
	symfony server:stop
	symfony serve -d

sf-cc:
	@chmod -R 777 ./
	$(CONSOLE) c:c

composer-install:
	$(COMPOSER) install

composer-update:
	$(COMPOSER) update --with-all-dependencies

database-drop:
	$(CONSOLE) doctrine:schema:drop --force --full-database -q

doctrine-migration:
	$(CONSOLE) make:migration

doctrine-migrate: ## Apply doctrine migrate
	$(CONSOLE) doctrine:migrations:migrate -n -q --allow-no-migration

doctrine-schema-create:
	$(CONSOLE) doctrine:schema:create

doctrine-reset: database-drop doctrine-migrate
doctrine-apply-migration: doctrine-reset doctrine-migration doctrine-reset  ## Apply doctrine migrate and reset database

fixtures-load: #doctrine-reset ## Load fixtures
	@test -d ./vendor/hautelook/alice-bundle && $(CONSOLE) hautelook:fixtures:load -n $q || echo 'no fixtures'

lint:
	$(CONSOLE) lint:container $q
	$(CONSOLE) lint:yaml --parse-tags config/ $q
	$(CONSOLE) lint:twig templates/ $q
	$(CONSOLE) doctrine:schema:validate --skip-sync $q

stan:
	@./vendor/bin/phpstan analyse $q --memory-limit 256M

cs-fix:
	@test -f ./vendor/bin/php-cs-fixer && ./vendor/bin/php-cs-fixer fix $q --allow-risky=yes || echo 'no cs-fix'

rector:
	@test -f ./vendor/bin/rector && ./vendor/bin/rector --no-progress-bar process $q || echo 'no rector'

infection: ## Run infection tests
	@./vendor/bin/infection --min-msi=80 --min-covered-msi=80 --threads=4 --only-covered --show-mutations --log-verbosity=none || echo 'no infection'

analyze: lint stan cs-fix rector       #infection ## Run all analysis tools

test: ## Run tests
	APP_ENV=test ./vendor/bin/phpunit $q $(c)

test-all: ## Run all tests
	@$(MAKE) --no-print-directory database-drop env=test
	@$(MAKE) --no-print-directory doctrine-schema-create env=test
	@$(MAKE) --no-print-directory fixtures-load env=test
	@$(MAKE) --no-print-directory test env=test

## —— Git ————————————————————————————————————————————————————————————————
git-clean-branches: ## Clean merged branches
	git remote prune origin
	(git branch --merged | egrep -v "(^\*|main|master|dev)" | xargs git branch -d) || true

git-rebase: ## Rebase the current branch
	$(GIT) pull --rebase $q
	$(GIT) pull --rebase origin main $q

message ?= $(shell git branch --show-current | sed -E 's/^([0-9]+)-([^-]+)-(.+)/\2: \#\1 \3/' | sed "s/-/ /g")
git-auto-commit:
	$(GIT) add .
	$(GIT) commit -m "${message}" -q || true

current_branch=$(shell git rev-parse --abbrev-ref HEAD)
git-push:
	$(GIT) push origin "$(current_branch)" --force-with-lease --force-if-includes

#commit: q=-q
commit: ## Commit and push the current branch
	@$(MAKE) --no-print-directory analyze
	@$(MAKE) --no-print-directory test-all
	@$(MAKE) --no-print-directory git-auto-commit git-rebase git-push ## Commit and push the current branch

## —— Docker ————————————————————————————————————————————————————————————————
docker-install: Dockerfile compose.yaml docker-down docker-build docker-up docker-ps docker-logs ## Reset and install your environment

docker-is-running:
ifeq ($(isContainerRunning), 1)
	@echo "Docker not running"
	@exit 1
endif

docker-up: ## Start the docker container
	$(DOCKER) up -d

docker-logs: ## List the docker containers
	$(DOCKER) logs -f

docker-ps: ## List the docker containers
	$(DOCKER) ps -a

docker-build: ## Build the docker container
	$(DOCKER) build

docker-down: ## down the stack
	$(DOCKER) down --remove-orphans

docker-sh: docker-up ## Connect to the docker container
	$(DOCKER) exec -it api zsh

docker-restart: docker-down docker-up docker-ps ## Reset the docker container

deploy: git-rebase docker-down docker-build docker-up docker-ps docker-logs ## Deploy the application
