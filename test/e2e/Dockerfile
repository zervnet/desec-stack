FROM node:8

RUN apt-get update && apt-get install -y \
		dnsutils \
		net-tools \
		dirmngr gnupg \
	--no-install-recommends && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN npm install -g mocha

RUN mkdir /usr/src/app
WORKDIR /usr/src/app

COPY ./package.json ./
RUN npm install

COPY setup.js ./setup.js
COPY tools.js ./tools.js
COPY ./spec ./spec
COPY ./apiwait ./apiwait

CMD ./apiwait 45 && mocha ./spec
