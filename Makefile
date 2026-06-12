.PHONY: install up down seed embed analyze analyze-sp test clean

## install — install the package and all dependencies
install:
	pip install -e .

## up — start Neo4j (and optionally Ollama with: make up PROFILES=ollama)
up:
	docker compose $(if $(PROFILES),--profile $(PROFILES),) up -d neo4j $(if $(PROFILES),ollama,)
	@echo "Neo4j Browser: http://localhost:7474 (user: neo4j / pass: secret)"

## down — stop all services
down:
	docker compose down

## seed — load mock IAM data (demo, no AWS/SailPoint needed)
seed:
	iamdbagent seed --neo4j-pass secret

## embed — vectorize graph nodes + seed RAG knowledge base (OpenAI)
embed:
	iamdbagent embed --neo4j-pass secret --embed-backend openai

## analyze — run analysis with Anthropic backend, preview IaC (dry run)
analyze:
	iamdbagent analyze --neo4j-pass secret --backend anthropic --dry-run

## analyze-sp — full SailPoint workflow (requires .env with SailPoint creds)
analyze-sp:
	iamdbagent fetch-sailpoint --neo4j-pass secret
	iamdbagent analyze --neo4j-pass secret --backend anthropic --dry-run

## doctor — pre-flight checks
doctor:
	iamdbagent doctor --neo4j-pass secret --backend anthropic

## test — run the test suite
test:
	python -m pytest tests/ -v

## clean — remove generated IaC output
clean:
	rm -rf staged_changes/
