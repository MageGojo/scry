//! Scry 存储层 —— **请求先保存(save-first)+ 去重**。
//!
//! 抓到 [`HttpFlow`] 的第一件事就是 [`Store::save`] 落盘,再做分析 / 推 UI,绝不只留内存。
//! 去重靠 `fp`(见 [`scry_core::HttpFlow::fingerprint`])唯一索引 + `INSERT OR IGNORE`。

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use scry_core::{Header, HttpFlow, WsDirection, WsMessage};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

/// SQLite 落盘句柄(单连接;跨线程请各开各的或加锁)。
pub struct Store {
    conn: Connection,
    /// 可选实时推流通道:每条**新插入**(去重命中不发)的流会 clone 一份发给订阅者(UI),
    /// 免去 UI 轮询全量 `recent()`。落盘永远先发生,推流只是顺带通知。
    tx: Option<Sender<HttpFlow>>,
    /// WebSocket 消息推流通道(与 `tx` 独立;ws 消息不去重,逐条推)。
    ws_tx: Option<Sender<WsMessage>>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS flows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    fp           TEXT    NOT NULL UNIQUE,
    method       TEXT    NOT NULL,
    scheme       TEXT    NOT NULL,
    host         TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    path         TEXT    NOT NULL,
    url          TEXT    NOT NULL,
    req_headers  TEXT    NOT NULL,
    req_body     BLOB    NOT NULL,
    status       INTEGER NOT NULL,
    resp_headers TEXT    NOT NULL,
    resp_body    BLOB    NOT NULL,
    duration_ms  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);

CREATE TABLE IF NOT EXISTS ws_messages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    conn_id   INTEGER NOT NULL,
    host      TEXT    NOT NULL,
    path      TEXT    NOT NULL,
    direction TEXT    NOT NULL,
    opcode    TEXT    NOT NULL,
    payload   BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ws_conn ON ws_messages(conn_id);
"#;

impl Store {
    /// 打开 / 创建指定路径的库并建表。
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path).context("打开 SQLite 失败")?;
        conn.execute_batch(SCHEMA).context("建表失败")?;
        Ok(Self {
            conn,
            tx: None,
            ws_tx: None,
        })
    }

    /// 默认落盘位置:`~/.scry/scry.sqlite`。
    pub fn open_default() -> Result<Self> {
        Self::open(default_db_path())
    }

    /// 内存库(测试用)。
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("打开内存 SQLite 失败")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn,
            tx: None,
            ws_tx: None,
        })
    }

    /// 挂上实时推流通道:此后每条新插入的流都会 clone 发到 `tx`(UI 侧 `try_recv` 增量追加)。
    pub fn set_sender(&mut self, tx: Sender<HttpFlow>) {
        self.tx = Some(tx);
    }

    /// 挂上 WebSocket 消息推流通道(UI 侧 `try_recv` 增量追加)。
    pub fn set_ws_sender(&mut self, tx: Sender<WsMessage>) {
        self.ws_tx = Some(tx);
    }

    /// 落盘一条流。返回 `true` 表示新插入,`false` 表示指纹已存在(去重命中)。
    pub fn save(&self, flow: &HttpFlow) -> Result<bool> {
        let req_headers = serde_json::to_string(&flow.req_headers)?;
        let resp_headers = serde_json::to_string(&flow.resp_headers)?;
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO flows \
             (ts, fp, method, scheme, host, port, path, url, req_headers, req_body, status, resp_headers, resp_body, duration_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                flow.ts,
                flow.fingerprint(),
                flow.method,
                flow.scheme,
                flow.host,
                flow.port as i64,
                flow.path,
                flow.url(),
                req_headers,
                flow.req_body,
                flow.status as i64,
                resp_headers,
                flow.resp_body,
                flow.duration_ms as i64,
            ],
        )?;
        let inserted = n > 0;
        // 仅新插入(非去重命中)才推流,避免重复条目灌进 UI。
        if inserted {
            if let Some(tx) = &self.tx {
                let _ = tx.send(flow.clone());
            }
        }
        Ok(inserted)
    }

    /// 最近 N 条(按时间倒序)。
    pub fn recent(&self, limit: usize) -> Result<Vec<HttpFlow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, method, scheme, host, port, path, req_headers, req_body, status, resp_headers, resp_body, duration_ms \
             FROM flows ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], row_to_flow)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 落盘一条 WebSocket 消息(**不去重**——心跳 / 重复消息都是真实流量)。
    pub fn save_ws(&self, m: &WsMessage) -> Result<()> {
        let dir = match m.direction {
            WsDirection::ClientToServer => "c2s",
            WsDirection::ServerToClient => "s2c",
        };
        self.conn.execute(
            "INSERT INTO ws_messages (ts, conn_id, host, path, direction, opcode, payload) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![m.ts, m.conn_id, m.host, m.path, dir, m.opcode, m.payload],
        )?;
        if let Some(tx) = &self.ws_tx {
            let _ = tx.send(m.clone());
        }
        Ok(())
    }

    /// 最近 N 条 WebSocket 消息(按 id 倒序)。
    pub fn recent_ws(&self, limit: usize) -> Result<Vec<WsMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, conn_id, host, path, direction, opcode, payload \
             FROM ws_messages ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], row_to_ws)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 总条数。
    pub fn count(&self) -> Result<i64> {
        let n = self
            .conn
            .query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))?;
        Ok(n)
    }

    /// 清空所有流量(Clear 按钮:真清库,不只是清界面)。
    pub fn clear(&self) -> Result<()> {
        self.conn
            .execute("DELETE FROM flows", [])
            .context("清空 flows 表失败")?;
        self.conn
            .execute("DELETE FROM ws_messages", [])
            .context("清空 ws_messages 表失败")?;
        Ok(())
    }
}

fn row_to_flow(row: &rusqlite::Row<'_>) -> rusqlite::Result<HttpFlow> {
    let req_headers: String = row.get(6)?;
    let resp_headers: String = row.get(9)?;
    let port: i64 = row.get(4)?;
    let status: i64 = row.get(8)?;
    let duration_ms: i64 = row.get(11)?;
    Ok(HttpFlow {
        ts: row.get(0)?,
        method: row.get(1)?,
        scheme: row.get(2)?,
        host: row.get(3)?,
        port: port as u16,
        path: row.get(5)?,
        req_headers: parse_headers(&req_headers),
        req_body: row.get(7)?,
        status: status as u16,
        resp_headers: parse_headers(&resp_headers),
        resp_body: row.get(10)?,
        duration_ms: duration_ms as u64,
    })
}

fn row_to_ws(row: &rusqlite::Row<'_>) -> rusqlite::Result<WsMessage> {
    let dir: String = row.get(4)?;
    Ok(WsMessage {
        ts: row.get(0)?,
        conn_id: row.get(1)?,
        host: row.get(2)?,
        path: row.get(3)?,
        direction: if dir == "c2s" {
            WsDirection::ClientToServer
        } else {
            WsDirection::ServerToClient
        },
        opcode: row.get(5)?,
        payload: row.get(6)?,
    })
}

fn parse_headers(json: &str) -> Vec<Header> {
    serde_json::from_str(json).unwrap_or_default()
}

/// `~/.scry/scry.sqlite`(取不到 HOME 时退回当前目录)。
pub fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".scry").join("scry.sqlite")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(path: &str, body: &[u8]) -> HttpFlow {
        HttpFlow::request(
            "GET",
            "https",
            "example.com",
            443,
            path,
            vec![("Host".into(), "example.com".into())],
            body.to_vec(),
        )
        .with_response(200, vec![], b"ok".to_vec(), 12)
    }

    #[test]
    fn save_is_deduped_and_readable() {
        let store = Store::open_memory().unwrap();
        assert!(store.save(&sample("/a", b"x")).unwrap()); // 新插入
        assert!(!store.save(&sample("/a", b"x")).unwrap()); // 指纹重复 → 去重
        assert!(store.save(&sample("/b", b"x")).unwrap()); // 不同路径 → 新插入
        assert_eq!(store.count().unwrap(), 2);

        let recent = store.recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].status, 200);
    }

    #[test]
    fn clear_empties_the_table() {
        let store = Store::open_memory().unwrap();
        store.save(&sample("/a", b"x")).unwrap();
        store.save(&sample("/b", b"y")).unwrap();
        assert_eq!(store.count().unwrap(), 2);
        store.clear().unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.recent(10).unwrap().is_empty());
    }

    #[test]
    fn ws_messages_saved_and_read_back() {
        let store = Store::open_memory().unwrap();
        store
            .save_ws(&WsMessage::new(
                1,
                "example.com",
                "/chat",
                WsDirection::ClientToServer,
                "Text",
                b"hi".to_vec(),
            ))
            .unwrap();
        store
            .save_ws(&WsMessage::new(
                1,
                "example.com",
                "/chat",
                WsDirection::ServerToClient,
                "Text",
                b"yo".to_vec(),
            ))
            .unwrap();
        // 不去重:相同内容再存一条仍然计入。
        store
            .save_ws(&WsMessage::new(
                1,
                "example.com",
                "/chat",
                WsDirection::ClientToServer,
                "Text",
                b"hi".to_vec(),
            ))
            .unwrap();
        let got = store.recent_ws(10).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].payload, b"hi"); // 最新一条在前
    }

    #[test]
    fn sender_pushes_only_new_inserts() {
        use std::sync::mpsc::channel;
        let (tx, rx) = channel();
        let mut store = Store::open_memory().unwrap();
        store.set_sender(tx);
        assert!(store.save(&sample("/a", b"x")).unwrap()); // 新插入 → 推一条
        assert!(!store.save(&sample("/a", b"x")).unwrap()); // 去重命中 → 不推
        assert!(store.save(&sample("/b", b"x")).unwrap()); // 新插入 → 再推一条
        let got: Vec<_> = rx.try_iter().collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].path, "/a");
        assert_eq!(got[1].path, "/b");
    }
}
