//! Lists gathered from every server that may show something of their kind:
//! resources, resource templates and prompts. What each server's allowlist
//! lets it show is answered as one page in config order, each entry naming
//! its server in `_meta`. An entry two servers show is shown once, from the
//! first, and a request for it goes there.
use super::{deny_reason, lock, Gateway, Governance, Slot, Upstream, CACHE_SCOPE, CACHE_TTL_MS};
use mcpdef_core::wire::{error_code, WireModel};
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::uri;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

/// How many pages of one server's list are followed.
pub(super) const MAX_PAGES: usize = 20;
/// How many entries one server's list may add.
pub(super) const MAX_ENTRIES: usize = 10_000;
/// How many URIs or names each route map remembers.
const ROUTES_KEPT: usize = 10_000;
/// How long a URI or a name is remembered after the list or link that showed
/// it.
const ROUTE_TTL: Duration = Duration::from_secs(600);

/// A list the gateway gathers from its servers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Listing {
    Resources,
    Templates,
    Prompts,
}

impl Listing {
    fn method(self) -> &'static str {
        match self {
            Listing::Resources => method::RESOURCES_LIST,
            Listing::Templates => method::RESOURCES_TEMPLATES_LIST,
            Listing::Prompts => method::PROMPTS_LIST,
        }
    }

    /// The member of a result that holds the entries.
    fn key(self) -> &'static str {
        match self {
            Listing::Resources => "resources",
            Listing::Templates => "resourceTemplates",
            Listing::Prompts => "prompts",
        }
    }

    /// The member of an entry that says what it is.
    fn field(self) -> &'static str {
        match self {
            Listing::Resources => "uri",
            Listing::Templates => "uriTemplate",
            Listing::Prompts => "name",
        }
    }
}

/// Which server recently showed each resource URI, in its list or as a
/// `resource_link` in one of its tool results, each resource template, and
/// each prompt name.
#[derive(Default)]
pub(super) struct Routes {
    pub(super) resources: Remembered,
    pub(super) links: Remembered,
    pub(super) templates: Remembered,
    pub(super) prompts: Remembered,
}

/// URI or name → server id, each for [`ROUTE_TTL`], the oldest forgotten first
/// once [`ROUTES_KEPT`] are held.
#[derive(Default)]
pub(super) struct Remembered {
    servers: HashMap<String, (String, Instant)>,
    order: VecDeque<String>,
}

impl Remembered {
    pub(super) fn remember(&mut self, key: &str, server: &str, now: Instant) {
        if let Some(entry) = self.servers.get_mut(key) {
            *entry = (server.to_string(), now);
            return;
        }
        while self.order.len() >= ROUTES_KEPT {
            if let Some(oldest) = self.order.pop_front() {
                self.servers.remove(&oldest);
            }
        }
        self.order.push_back(key.to_string());
        self.servers
            .insert(key.to_string(), (server.to_string(), now));
    }

    pub(super) fn server(&self, key: &str, now: Instant) -> Option<&str> {
        self.servers
            .get(key)
            .filter(|(_, seen)| now.duration_since(*seen) < ROUTE_TTL)
            .map(|(server, _)| server.as_str())
    }
}

impl Gateway {
    /// `resources/list`, `resources/templates/list` or `prompts/list`. Every
    /// server that exposes something of the kind is asked at once, and what
    /// its allowlist lets it show is answered as one page. A server that
    /// fails to answer adds nothing.
    pub(super) async fn handle_list(
        &self,
        g: &Governance,
        id: Id,
        msg: &Message,
        era: WireModel,
        listing: Listing,
    ) -> Message {
        if msg
            .params
            .as_ref()
            .and_then(|p| p.get("cursor"))
            .is_some_and(|c| !c.is_null())
        {
            return Message::error(
                id,
                error_code::INVALID_PARAMS,
                "mcpdef answers a list in one page, and gave no cursor to continue from",
            );
        }

        let exposes = |server: &str| match listing {
            Listing::Resources => g
                .policy
                .resources(server)
                .is_some_and(|r| !r.uris.is_empty()),
            Listing::Templates => g
                .policy
                .resources(server)
                .is_some_and(|r| !r.templates.is_empty()),
            Listing::Prompts => g.policy.prompts(server).is_some(),
        };
        let mut asks = JoinSet::new();
        for (index, slot) in g.upstreams.iter().enumerate() {
            let Some(up) = slot.conn.as_ref().filter(|_| exposes(&slot.id)) else {
                continue;
            };
            let (slot, up) = (slot.clone(), Arc::clone(up));
            let client = Arc::clone(&self.inner.client_info);
            let timeout = g.upstream_timeout;
            asks.spawn(async move {
                let entries = gather(&slot, &up, &client, listing, timeout).await;
                (index, entries)
            });
        }
        let mut gathered = Vec::new();
        while let Some(joined) = asks.join_next().await {
            if let Ok(pair) = joined {
                gathered.push(pair);
            }
        }
        // In config order, whichever answered first.
        gathered.sort_by_key(|(index, _)| *index);

        let now = Instant::now();
        let mut shown = HashSet::new();
        let mut out = Vec::new();
        let mut routes = lock(&self.inner.routes);
        for (index, entries) in gathered {
            let server = g.upstreams[index].id.as_str();
            for mut entry in entries {
                let Some(text) = entry.get(listing.field()).and_then(Value::as_str) else {
                    continue;
                };
                // What the entry is known by once judged: a URI in normal form.
                let key = match listing {
                    Listing::Resources => {
                        // A URI that cannot be put in normal form cannot be
                        // read either, so it is not shown.
                        let Ok(uri) = uri::normalize(text) else {
                            continue;
                        };
                        if !g.policy.resources(server).is_some_and(|r| r.allows(&uri)) {
                            continue;
                        }
                        uri.as_str().to_string()
                    }
                    Listing::Templates => {
                        if !g
                            .policy
                            .resources(server)
                            .is_some_and(|r| r.shows_template(text))
                        {
                            continue;
                        }
                        text.to_string()
                    }
                    Listing::Prompts => {
                        if !g.policy.shows_prompt(server, text) {
                            continue;
                        }
                        text.to_string()
                    }
                };
                // The first server in config order to show it has it: the
                // entry a later one shows is not shown again.
                if shown.contains(&key) {
                    continue;
                }
                match listing {
                    Listing::Resources => {
                        routes.resources.remember(&key, server, now);
                        // Shown as it will be judged and sent.
                        if let Some(entry) = entry.as_object_mut() {
                            entry.insert("uri".into(), Value::from(key.as_str()));
                        }
                    }
                    Listing::Prompts => routes.prompts.remember(&key, server, now),
                    Listing::Templates => routes.templates.remember(&key, server, now),
                }
                attribute(&mut entry, server);
                out.push(entry);
                shown.insert(key);
            }
        }
        drop(routes);

        let mut result = Map::new();
        if era == WireModel::Modern {
            result.insert("resultType".into(), Value::from("complete"));
        }
        result.insert(listing.key().into(), Value::Array(out));
        if era == WireModel::Modern {
            result.insert("ttlMs".into(), Value::from(CACHE_TTL_MS));
            result.insert("cacheScope".into(), Value::from(CACHE_SCOPE));
        }
        Message::result(id, Value::Object(result))
    }
}

/// Every page of one server's list, up to [`MAX_PAGES`] pages and
/// [`MAX_ENTRIES`] entries. A server that does not do the kind answers
/// `-32601` and adds nothing; any other failure adds nothing and is logged.
async fn gather(
    slot: &Slot,
    up: &Upstream,
    client: &Value,
    listing: Listing,
    timeout: Option<Duration>,
) -> Vec<Value> {
    let method = listing.method();
    let mut entries = Vec::new();
    let mut cursor: Option<Value> = None;
    for _ in 0..MAX_PAGES {
        let params = cursor.take().map(|c| serde_json::json!({ "cursor": c }));
        let mut req = Message::request(Id::Num(0), method, params);
        up.stamp(&mut req, client);
        let resp = match up.handle.call(req, timeout).await {
            Ok(resp) => {
                slot.answered(up);
                resp
            }
            Err(error) => {
                let dec = slot.failure(&error, method, timeout);
                eprintln!("mcpdef: {method} on '{}': {}", slot.id, deny_reason(&dec));
                break;
            }
        };
        let Some(result) = resp.result else {
            let code = resp.error.as_ref().and_then(|e| e["code"].as_i64());
            if code != Some(error_code::METHOD_NOT_FOUND) {
                eprintln!(
                    "mcpdef: {method} on '{}' failed: {}",
                    slot.id,
                    resp.error.unwrap_or_default()
                );
            }
            break;
        };
        let page = match result.get(listing.key()) {
            Some(Value::Array(page)) => page.clone(),
            _ => Vec::new(),
        };
        let room = MAX_ENTRIES - entries.len();
        entries.extend(page.into_iter().take(room));
        match next_cursor(&result) {
            Some(next) if entries.len() < MAX_ENTRIES => cursor = Some(next),
            _ => break,
        }
    }
    entries
}

/// The cursor of the page after the one a list's `result` holds, if it names
/// one.
pub(super) fn next_cursor(result: &Value) -> Option<Value> {
    result
        .get("nextCursor")
        .filter(|next| !next.is_null())
        .cloned()
}

/// Name the server an entry came from in its `_meta`, over whatever the
/// server itself put under that key: no upstream can claim another's entries.
/// The rest of its `_meta` is kept; a `_meta` that is not an object is not
/// one the spec allows, and is replaced.
pub(super) fn attribute(entry: &mut Value, server: &str) {
    let Some(entry) = entry.as_object_mut() else {
        return;
    };
    let meta = entry
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    if !meta.is_object() {
        *meta = Value::Object(Map::new());
    }
    if let Some(meta) = meta.as_object_mut() {
        meta.insert("mcpdef/server".into(), Value::from(server));
    }
}
