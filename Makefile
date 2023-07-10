ENV=.env

GOBIN=$(shell pwd)/.bin
DATA_DIR=$(shell pwd)/.data
FRONT_PATH=$(shell pwd)/front
COMPOSE_FILE=docker-compose.yml
PROD_COMPOSE_FILE=docker-compose-prod.yml

$(GOBIN):
	mkdir -p $@

$(DATA_DIR):
	mkdir -p $@

$(GOBIN)/air:
	GOBIN=$(GOBIN) go install github.com/cosmtrek/air@latest

.PHONY: dev
dev: $(GOBIN)/air $(DATA_DIR)
	air --build.cmd "go build -o $(GOBIN)/backend main.go" \
		--build.bin ".bin/backend" \
		--build.exclude_dir "$(FRONT_PATH)" \
		--tmp_dir .data \
		--build.include_file ".env"

.bin:
	mkdir -p $(shell pwd)/.bin

.PHONY: build
build: $(GOBIN)
	go build -o .bin/backend main.go

.PHONY: build-docker
build-docker:
	NODE_ENV=production docker build --platform linux/amd64 -t "docker.io/brisouamaury/check-certs:latest" --push .

.PHONY: start
start:
	docker-compose --env-file $(ENV) -f $(COMPOSE_FILE) up -d

.PHONY: start-prod
start-prod: pull
	docker-compose --env-file $(ENV) -f $(PROD_COMPOSE_FILE) up -d

.PHONY: stop
stop:
	docker-compose --env-file $(ENV) down

.PHONY: pull
pull:
	docker-compose --env-file $(ENV) pull

.PHONY: clean
clean:
	docker system prune -f
	docker volume prune -f

.PHONY: logs
logs:
	docker-compose --env-file $(ENV) logs -f

.PHONY: shell
shell:
	docker exec -it gateway-test-service_backend_1 /bin/bash

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: test
test:
	@go test -count=1 -timeout 3m -v ./...

#################################### FRONT ###########################################

.PHONY: install-front
install-front:
	cd $(FRONT_PATH) && npm i

.PHONY: lint-front
lint-front: install-front
	cd $(FRONT_PATH) && npm run lint


.PHONY: dev-front
dev-front: install-front
	cd $(FRONT_PATH) && npm run dev
