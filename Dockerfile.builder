FROM 47.97.67.233:5000/deepshield/rust-build AS base

WORKDIR /build

# Configure cargo to use cli for git to avoid libgit2 SSL issues
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# 安装 cargo-chef 用于依赖缓存，指定版本兼容 rust 1.83.0
RUN cargo install cargo-chef --version 0.1.68 --locked

# ==============================================================================
# 第一阶段：分析项目结构，提取所有的 Cargo.toml 和依赖信息
FROM base AS planner
COPY ./agent /build/agent
WORKDIR /build/agent
RUN cargo chef prepare --recipe-path recipe.json

# ==============================================================================
# 第二阶段：预编译依赖
FROM base AS cacher
WORKDIR /build/agent
COPY --from=planner /build/agent/recipe.json recipe.json
# 这一步仅下载并编译依赖，由于我们没有修改 recipe.json，只要 Cargo.toml/Cargo.lock 不变，这层就会缓存
RUN cargo chef cook --recipe-path recipe.json

# ==============================================================================
# 第三阶段：准备带有已编译依赖的最终编译镜像
FROM base AS builder
WORKDIR /zerotrace

# 复制第二阶段编译好的 cargo registry 和 target 缓存
COPY --from=cacher /usr/local/cargo/registry /usr/local/cargo/registry
COPY --from=cacher /usr/local/cargo/git /usr/local/cargo/git
# 此时该镜像中已经包含了 agent 项目的所有依赖缓存（下载+部分预编译）

CMD ["bash"]
