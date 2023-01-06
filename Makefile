.PHONY: build push-dev push publish-dev publish

TAG = go-agent:latest
DEV_REPO = disco-dev.forta.network
REPO = disco.forta.network

build:
	@docker build -t ${TAG} .

push-dev:
	@docker tag ${TAG} ${DEV_REPO}/${TAG}
	$(eval imageDigest = $(shell docker push ${DEV_REPO}/${TAG} | grep -E -o '[0-9a-f]{64}'))
	$(eval cid = $(shell docker pull -a ${DEV_REPO}/${imageDigest} | grep -E -o 'bafy[0-9a-z]+'))
	echo ${cid}@sha256:${imageDigest}

push:
	@docker tag ${TAG} ${REPO}/${TAG}
	$(eval imageDigest = $(shell docker push ${REPO}/${TAG} | grep -E -o '[0-9a-f]{64}'))
	$(eval cid = $(shell docker pull -a ${REPO}/${imageDigest} | grep -E -o 'bafy[0-9a-z]+'))
	@echo ${cid}@sha256:${imageDigest}

publish-dev: build push-dev

publish: build push