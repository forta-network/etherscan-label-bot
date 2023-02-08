.PHONY: build push-dev push publish-dev publish

TAG = go-agent:latest
DEV_REPO = disco-dev.forta.network
REPO = disco.forta.network

build-cli:
	rm -f publish-cli
	wget https://github.com/forta-network/go-bot-publish-cli/releases/download/v0.0.1/publish-cli
	chmod 755 publish-cli

publish-manifest-dev: build-cli
	$(eval manifest = $(shell ./publish-cli publish --manifest manifest-template.json --env dev))
	@echo ${manifest}

publish-manifest-prod: build-cli
	$(eval manifest = $(shell ./publish-cli publish --manifest manifest-template.json --env prod))
	@echo ${manifest}

build:
	@docker build -t ${TAG} .

init-id:
	@./publish-cli generate-id
	$(eval botId = $(shell cat ./.settings/botId))
	@echo publishing ${botId}

push-dev:
	@docker tag ${TAG} ${DEV_REPO}/${TAG}
	$(eval imageDigest = $(shell docker push ${DEV_REPO}/${TAG} | grep -E -o '[0-9a-f]{64}'))
	$(eval cid = $(shell docker pull -a ${DEV_REPO}/${imageDigest} | grep -E -o 'bafy[0-9a-z]+'))
	@echo ${cid}@sha256:${imageDigest}
	$(eval manifest = $(shell ./publish-cli publish-metadata --image "${cid}@sha256:${imageDigest}" --doc-file docs/README.md --env dev))
	@echo "pushed metadata to dev: ${manifest}"
	./publish-cli publish --manifest  ${manifest} --env dev

push: init-id
	@docker tag ${TAG} ${DEV_REPO}/${TAG}
	$(eval imageDigest = $(shell docker push ${DEV_REPO}/${TAG} | grep -E -o '[0-9a-f]{64}'))
	$(eval cid = $(shell docker pull -a ${DEV_REPO}/${imageDigest} | grep -E -o 'bafy[0-9a-z]+'))
	@echo ${cid}@sha256:${imageDigest}
	$(eval manifest = $(shell ./publish-cli publish-metadata --image "${cid}@sha256:${imageDigest}" --doc-file docs/README.md --env prod))
	@echo "pushed metadata to prod: ${manifest}"
	./publish-cli publish --manifest ${manifest} --env prod

disable-dev:
	./publish-cli disable --env dev

disable:
	./publish-cli disable --env prod

enable-dev:
	./publish-cli enable --env dev

enable:
	./publish-cli enable --env prod

publish-dev: build push-dev

publish: build push