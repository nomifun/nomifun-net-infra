# 多阶段构建：node（前端）→ golang（后端）→ distroless（运行）
#
# 最终镜像用 distroless/static 而不是 alpine：没有 shell、没有包管理器、
# 非 root 运行。中继是公网暴露的进程，一个能 exec 进去的容器等于给攻陷者
# 送一个现成的工作台。
#
# 本仓不使用 GitHub Actions（见 AGENTS.md），镜像构建靠本地 make。

FROM node:22-alpine AS web
WORKDIR /src
# 先只拷依赖清单，让 bun install 这一层能被缓存。
COPY web/package.json web/bun.lock ./
RUN npm install -g bun@1.3.14 && bun install --frozen-lockfile
COPY web/ ./
RUN bun run build

FROM golang:1.26-alpine AS build
WORKDIR /src
# 同理：先拷 go.mod/go.sum，依赖层可缓存。
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/dist ./web/dist

ARG VERSION=dev
ARG COMMIT=none
# CGO_ENABLED=0 是产品承诺的一部分：单静态二进制、无运行时依赖。
# 这也是为什么存储层必须用 modernc.org/sqlite（纯 Go）而不是 mattn/go-sqlite3。
ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/nfrelay ./cmd/nfrelay && \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/nfagent ./cmd/nfagent

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/nfrelay /nfrelay
COPY --from=build /out/nfagent /nfagent

# 数据卷：SQLite 与证书。证书**必须**持久化 ——
# 不持久化的话每次重启 SPKI 指纹都变，等于把整个机队踢下线。
VOLUME ["/data"]

# 8443/udp  QUIC 承载（agent 连这里）
# 9443/tcp  控制台
# 业务入口端口按隧道配置，需在编排层额外发布。
EXPOSE 8443/udp 9443/tcp

USER nonroot:nonroot
ENTRYPOINT ["/nfrelay"]
CMD ["-data-dir", "/data", "-bind", "0.0.0.0:8443", "-console", "0.0.0.0:9443"]
