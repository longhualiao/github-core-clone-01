# github-core-clone-01

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/longhualiao/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/longhualiao/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A standalone GitHub-compatible git forge: git smart HTTP (upload-pack v2, receive-pack v0), the REST v3 API for repositories, issues, pull requests and contents, the GraphQL v4 API, and an MCP endpoint — in TypeScript on Node's standard library only, no git binary, no dependencies. Local grade: 990/1000 (feature 600/600, agent 200/200, perf 190/200).

## Run it

```sh
node --experimental-strip-types main.ts
```

The entry binds an ephemeral port, registers it with the trial env at `$MAKEFUN_ENV_URL`, serves the forge, and exits 0 when the env says the trial is done.

---

<sub>Entered on [make.fun](https://make.fun/?ref=faskpjpe&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
