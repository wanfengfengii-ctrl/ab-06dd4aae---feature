# fMP4 音频归档审计服务

在接收分片 MP4（fMP4/CMAF）音频前，对初始化片段与媒体片段的解码时间线做严格审计，
避免播放器自动容错掩盖**音频重叠、空洞或载荷错配**。任何盒结构、参数继承、载荷
边界或时间衔接不合法的提交都会以稳定错误码拒收。

## 快速开始

```sh
# 构建并启动 API（宿主机端口默认 8080，可用 API_PORT 覆盖）
API_PORT=9000 docker compose up -d api

# 一次性验证：等待 API 健康后执行单元测试、构建检查、连续/断裂时间线 HTTP 冒烟，
# 以退出码报告结果（0 = 全部通过）
docker compose up --exit-code-from verify --abort-on-container-exit verify
echo "verify exit code: $?"
```

本地开发（需 Go ≥ 1.23）：

```sh
go test ./...          # 单元测试
go vet ./...           # 静态检查
PORT=8080 go run ./cmd/server &          # 启动 API
go run ./cmd/smoke -url http://127.0.0.1:8080   # HTTP 冒烟
```

## API

### `POST /api/fmp4/audit`

`multipart/form-data`，**按顺序**上传：

1. 第 1 个 part：初始化片段（init segment，含 `moov`/`mvex`）
2. 第 2..33 个 part：1–32 个媒体片段（media segment，含 `moof`+`mdat`）

part 字段名不限，顺序即语义。所有 part 合计不得超过 **16 MiB**。

服务端从初始化片段解析轨道时标（`mdhd`）、轨道 ID（`tkhd`）、`trex` 默认采样参数，
从每个媒体片段的 `tfhd`/`tfdt`/`trun` 解析实际采样时长与载荷范围，并校验：

- 仅单音轨（`hdlr` = `soun`）且含 `mvex`/`trex`；
- 每个 `moof` 恰好一个 `traf`，`tfhd.track_ID` 与初始化片段一致；
- `mfhd` 片段序号严格递增；
- 采样时长/大小按 `trun` → `tfhd` → `trex` 继承且可解析；
- 每个 `trun` 的载荷区间落在本片段 `mdat` 内、互不重叠、且 `mdat` 字节被完全消费；
- 相邻片段的解码区间**精确衔接**（`next.start == prev.end`，无空洞、无重叠）。

#### 成功响应 `200 OK`

按提交顺序给出各片段的序号、起止解码刻度（timescale 单位）、采样数，以及整段时长：

```json
{
  "ok": true,
  "timescale": 48000,
  "trackId": 1,
  "fragmentCount": 2,
  "totalDuration": 6144,
  "fragments": [
    {"index": 0, "segmentIndex": 0, "sequenceNumber": 1, "start": 0,    "end": 3072, "duration": 3072, "samples": 3},
    {"index": 1, "segmentIndex": 1, "sequenceNumber": 2, "start": 3072, "end": 6144, "duration": 3072, "samples": 3}
  ]
}
```

#### 失败响应 `4xx`（内容审计失败为 `422`）

返回对应片段索引与稳定错误码，归档人员可据此拒收：

```json
{
  "ok": false,
  "error": {
    "code": "TIMELINE_GAP",
    "message": "fragment 2 starts at decode tick 6656 but previous fragment ends at 6144 (gap of 512 ticks)",
    "segmentIndex": 2,
    "fragmentIndex": 2
  }
}
```

`segmentIndex` 为媒体片段在上传顺序中的 0 基序号；`fragmentIndex` 为所有 `moof`
在提交顺序中的 0 基序号；初始化片段或请求级错误两者均为 `-1`。

### `GET /healthz`

健康检查，返回 `200 {"status":"ok"}`。容器内健康检查由二进制自身完成
（`/server healthcheck`，读取 `PORT` 环境变量）。

## 稳定错误码

| 错误码 | HTTP | 含义 |
| --- | --- | --- |
| `BAD_MULTIPART` | 400 | multipart 结构非法或缺少 part |
| `NO_MEDIA_SEGMENTS` | 400 | 只有初始化片段，没有媒体片段 |
| `TOO_MANY_SEGMENTS` | 400 | 媒体片段超过 32 个 |
| `PAYLOAD_TOO_LARGE` | 413 | 合计超过 16 MiB |
| `METHOD_NOT_ALLOWED` | 405 | 非 POST 请求 |
| `BOX_STRUCTURE_INVALID` | 422 | 盒大小/截断/版本等结构非法 |
| `MISSING_MOOV` / `MISSING_MVEX` / `MISSING_TREX` | 422 | 初始化片段缺少必需盒 |
| `TRACK_COUNT_INVALID` | 422 | 轨道数不为 1 |
| `NOT_AUDIO_TRACK` | 422 | 轨道 handler 非 `soun` |
| `MISSING_TIMESCALE` / `MISSING_TRACK_ID` | 422 | `mdhd`/`tkhd` 缺失或时标为 0 |
| `MISSING_MOOF` / `MISSING_TRAF` / `MISSING_MFHD` / `MISSING_TFHD` / `MISSING_TFDT` / `MISSING_TRUN` / `MISSING_MDAT` | 422 | 媒体片段缺少必需盒 |
| `MULTI_TRAF_UNSUPPORTED` | 422 | 单 `moof` 含多个 `traf` |
| `TRACK_MISMATCH` | 422 | `tfhd.track_ID` 与初始化片段不一致 |
| `SEQUENCE_NOT_INCREASING` | 422 | 片段序号未严格递增 |
| `SAMPLE_DURATION_UNRESOLVABLE` / `SAMPLE_SIZE_UNRESOLVABLE` | 422 | 采样时长/大小在 trun→tfhd→trex 链上均缺失 |
| `PAYLOAD_OUT_OF_RANGE` | 422 | trun 载荷区间超出本片段 mdat |
| `PAYLOAD_OVERLAP` | 422 | trun 载荷区间互相重叠 |
| `PAYLOAD_NOT_CONSUMED` | 422 | mdat 存在未被引用的字节 |
| `TIMELINE_GAP` | 422 | 相邻解码区间存在空洞 |
| `TIMELINE_OVERLAP` | 422 | 相邻解码区间存在重叠 |

## 交付结构

```
Dockerfile            # 多阶段：build / runtime(scratch) / verify
docker-compose.yml    # api（健康检查、API_PORT 可配宿主机端口）+ verify（一次性）
cmd/server            # API 服务（含 healthcheck 子命令）
cmd/smoke             # HTTP 冒烟客户端（连续 + 断裂时间线）
internal/fmp4         # ISO BMFF 解析与审计逻辑
internal/fixture      # 测试用 fMP4 构造器（单测与冒烟共用）
scripts/verify.sh     # verify 服务入口：go test → vet/build → 等待健康 → 冒烟
```

`verify` 服务通过 `depends_on: service_healthy` 等待 API 健康，随后执行
`go test ./...`、`go vet ./...`、`go build`，再对活动 API 跑连续与断裂时间线的
HTTP 冒烟，全部通过以退出码 0 结束，任一失败以非 0 结束。
