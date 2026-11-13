// Fallback for post pages when Reddit blocks the `/comments/` JSON API
// (403 "blocked by network security" since 2026-10-20; `client::request`
// currently gets past it by encoding a slash).
//
// The post itself still comes from the JSON API (`/by_id`). Comments are scraped
// from the HTML fragments reddit.com loads them from (`/svc/shreddit/...`) and
// converted into the shape of the `/comments/` JSON response, so post.rs and the
// templates work unchanged.
//
// Since November 2026 Reddit also refuses logged-in sessions most subreddit
// listings (hot, new, rising, r/all) as JSON, and `/by_id` too. `feed` builds
// them from the HTML fragments reddit.com's subreddit pages load their posts
// from, in the shape of the listing JSON, so subreddit.rs works unchanged.

use crate::client::{json, reddit_get, CLIENT};
use crate::utils::{format_url, param};
use cached::proc_macro::cached;
use chrono::DateTime;
use log::{error, warn};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use scraper::{ElementRef, Html, Node, Selector};
use serde_json::{json as json_value, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;

const SVC_BASE: &str = "https://www.reddit.com/svc/shreddit";

static COMMENT: LazyLock<Selector> = LazyLock::new(|| Selector::parse("shreddit-comment").unwrap());
static MORE: LazyLock<Selector> = LazyLock::new(|| Selector::parse(r#"faceplate-partial[src*="/more-comments/"]"#).unwrap());
static CURSOR: LazyLock<Selector> = LazyLock::new(|| Selector::parse(r#"input[name="cursor"]"#).unwrap());
static MORE_COUNT: LazyLock<Selector> = LazyLock::new(|| Selector::parse("faceplate-number[number]").unwrap());

static POST: LazyLock<Selector> = LazyLock::new(|| Selector::parse("shreddit-post").unwrap());
static MORE_POSTS: LazyLock<Selector> = LazyLock::new(|| Selector::parse(r#"faceplate-partial[src*="-more-posts/"]"#).unwrap());
static FLAIR: LazyLock<Selector> = LazyLock::new(|| Selector::parse("shreddit-post-flair").unwrap());
static PRIMARY_IMAGE: LazyLock<Selector> = LazyLock::new(|| Selector::parse("img[data-post-media-primary]").unwrap());
static PLAYER: LazyLock<Selector> = LazyLock::new(|| Selector::parse("shreddit-player, shreddit-player-2").unwrap());
static GALLERY_IMAGE: LazyLock<Selector> = LazyLock::new(|| Selector::parse("gallery-carousel img").unwrap());

/// Sorts of the listings `feed` reads.
const SORTS: [&str; 6] = ["hot", "best", "new", "rising", "top", "controversial"];

/// Posts per page of a merged listing, as many as the JSON API's.
const PAGE_SIZE: usize = 25;

/// Set once a listing has been read from a page, to log that it works only once.
static LISTING_WORKS: AtomicBool = AtomicBool::new(false);

/// Builds a `/comments/` JSON response for `path` (a `/comments/` API path, as
/// built by `post::item`). Supports the `sort` and `cursor` query parameters
/// and single comment threads.
pub async fn thread(path: &str, quarantine: bool) -> Result<Value, String> {
	let (id, comment_id) = parse_path(path).ok_or_else(|| format!("Couldn't parse post path | {path}"))?;

	let post = json(format!("/by_id/t3_{id}.json?raw_json=1"), quarantine).await?;
	let sub = post["data"]["children"][0]["data"]["subreddit"]
		.as_str()
		.ok_or_else(|| format!("Post not found | {path}"))?
		.to_string();

	let comments = if let Some(comment_id) = comment_id {
		// The comment itself, then its replies through a cursor naming it as the parent
		let mut html = get(&format!("{SVC_BASE}/comment/t1_{comment_id}?depth=0&subredditName={sub}"), quarantine).await?;
		html += &more(&sub, &id, &cursor_for(&comment_id), quarantine).await?;
		html
	} else if let Some(cursor) = param(path, "cursor") {
		more(&sub, &id, &cursor, quarantine).await?
	} else {
		let sort = param(path, "sort").filter(|s| !s.is_empty()).unwrap_or_else(|| "confidence".to_string());
		get(&format!("{SVC_BASE}/comments/r/{sub}/t3_{id}?sort={}", sort.to_uppercase()), quarantine).await?
	};

	Ok(json_value!([post, listing(parse_comments(&comments, &id))]))
}

/// Extracts the post ID and optional comment ID from paths like
/// `/r/{sub}/comments/{id}/{title}/{comment_id}.json?...`.
fn parse_path(path: &str) -> Option<(String, Option<String>)> {
	let path = path.split('?').next()?.trim_end_matches(".json");
	let mut segments = path.split('/').skip_while(|s| *s != "comments").skip(1);
	let id = segments.next().filter(|s| !s.is_empty())?.to_string();
	let comment_id = segments.nth(1).filter(|s| !s.is_empty()).map(str::to_string);
	Some((id, comment_id))
}

/// Cursor for the replies of a comment. Reddit's own cursors carry a hash
/// before the comma, but an empty one is accepted.
fn cursor_for(comment_id: &str) -> String {
	use base64::{engine::general_purpose::STANDARD, Engine as _};
	STANDARD.encode(format!("commenttree:,::1:d1:t1_{comment_id}"))
}

fn cookies(quarantine: bool) -> String {
	let mut cookies = "over18=1".to_string();
	if quarantine {
		cookies += "; _options=%7B%22pref_quarantine_optin%22%3A%20true%2C%20%22pref_gated_sr_optin%22%3A%20true%7D";
	}
	cookies
}

async fn get(url: &str, quarantine: bool) -> Result<String, String> {
	let res = CLIENT.get(url).header("Cookie", cookies(quarantine)).send().await.map_err(|e| e.to_string())?;
	if !res.status().is_success() {
		return Err(format!("Reddit returned {} for comments | {url}", res.status()));
	}
	res.text().await.map_err(|e| e.to_string())
}

/// Loads the comments behind a cursor, like reddit.com's "more replies" buttons.
async fn more(sub: &str, id: &str, cursor: &str, quarantine: bool) -> Result<String, String> {
	let url = format!("{SVC_BASE}/more-comments/{sub}/t3_{id}");
	// Double-submit CSRF check: any token works as long as cookie and form match
	let csrf = format!("{:032x}", fastrand::u128(..));
	let body = serde_urlencoded::to_string([("cursor", cursor), ("csrf_token", &csrf)]).map_err(|e| e.to_string())?;
	let res = CLIENT
		.post(&url)
		.header("Cookie", format!("{}; csrf_token={csrf}", cookies(quarantine)))
		.header("Content-Type", "application/x-www-form-urlencoded")
		.body(body)
		.send()
		.await
		.map_err(|e| e.to_string())?;
	if !res.status().is_success() {
		return Err(format!("Reddit returned {} for more comments | {url}", res.status()));
	}
	res.text().await.map_err(|e| e.to_string())
}

/// Whether `path` is a subreddit listing API path, `/r/{subs}/{sort}.json?...`
/// as built by `subreddit::community`.
pub fn is_feed(path: &str) -> bool {
	feed_parts(path).is_some()
}

/// The subreddits and sort of a listing API path.
fn feed_parts(path: &str) -> Option<(Vec<String>, &str)> {
	let rest = path.split('?').next()?.strip_prefix("/r/")?.strip_suffix(".json")?;
	let (subs, sort) = rest.split_once('/')?;
	let subs: Vec<String> = subs
		.replace("%2B", "+")
		.replace("%2b", "+")
		.split('+')
		.filter(|s| !s.is_empty())
		.map(str::to_string)
		.collect();
	(!subs.is_empty() && SORTS.contains(&sort)).then_some((subs, sort))
}

/// Builds a listing JSON response for `path` (see `is_feed`) from the HTML
/// fragments reddit.com's subreddit pages load their posts from, for the
/// listings Reddit no longer gives logged-in sessions as JSON.
///
/// reddit.com has no such feed for several subreddits at once, so a
/// multireddit merges its subreddits' feeds and its `after` holds a cursor per
/// subreddit.
pub async fn feed(path: &str, quarantine: bool) -> Result<Value, String> {
	let Some((subs, sort)) = feed_parts(path) else {
		return Err(format!("Unknown listing | {path}"));
	};
	let t = param(path, "t").filter(|t| !t.is_empty()).unwrap_or_else(|| "day".to_string()).to_uppercase();
	let cursors = parse_cursors(&param(path, "after").unwrap_or_default(), &subs);

	// Load the subreddits' feeds in parallel
	let tasks: Vec<_> = subs
		.iter()
		.map(|sub| {
			let (sub, sort, t) = (sub.clone(), sort.to_string(), t.clone());
			let after = cursors.get(&sub.to_lowercase()).cloned().unwrap_or_default();
			tokio::spawn(async move {
				let posts = batch(sub.clone(), sort, t, after, quarantine).await;
				(sub, posts)
			})
		})
		.collect();

	let mut feeds = Vec::new();
	let mut errors = Vec::new();
	for task in tasks {
		match task.await {
			Ok((sub, Ok((posts, more)))) => feeds.push((sub, posts, more)),
			Ok((sub, Err(e))) => {
				error!("Couldn't read the r/{sub} listing from reddit.com: {e} | {path}");
				errors.push(format!("r/{sub}: {e}"));
			}
			Err(e) => errors.push(e.to_string()),
		}
	}
	if feeds.is_empty() {
		return Err(format!(
			"Reddit blocked this listing, and reading it from reddit.com failed: {} | {path}",
			errors.join("; ")
		));
	}

	let (children, next) = merge(feeds, sort, cursors);
	let after = if next.is_empty() {
		String::new()
	} else if subs.len() == 1 {
		// A single subreddit's cursor is a post, like the JSON API's
		next.into_values().next().unwrap_or_default()
	} else {
		subs
			.iter()
			.filter_map(|sub| next.get(&sub.to_lowercase()).map(|id| format!("{sub}:{id}")))
			.collect::<Vec<_>>()
			.join(",")
	};

	if !LISTING_WORKS.swap(true, Ordering::Relaxed) {
		warn!("Reading listings from reddit.com's feeds, as Reddit refuses them to the session as JSON");
	}
	Ok(json_value!({ "kind": "Listing", "data": { "children": children, "after": after } }))
}

/// The cursor of each subreddit in a listing's `after`, keyed by lowercase
/// name: `sub:t3_id,sub:t3_id`, or a bare `t3_id` for a single subreddit.
fn parse_cursors(after: &str, subs: &[String]) -> HashMap<String, String> {
	after
		.split(',')
		.filter_map(|cursor| {
			let (sub, id) = match cursor.split_once(':') {
				Some((sub, id)) => (sub.to_lowercase(), id),
				None if subs.len() == 1 => (subs[0].to_lowercase(), cursor),
				None => return None,
			};
			id.starts_with("t3_").then(|| (sub, id.to_string()))
		})
		.collect()
}

/// Merges subreddits' feeds (name, posts, whether more follow) into a page,
/// keeping each feed's own order: the next post is the best of the feeds' next
/// ones, so each feed's cursor stays the last post taken from it. Stops early
/// when a feed with more pages runs out, as its next posts are unknown.
/// Returns the page and the cursors for the next one, empty at the end.
fn merge(feeds: Vec<(String, Vec<Value>, bool)>, sort: &str, mut cursors: HashMap<String, String>) -> (Vec<Value>, HashMap<String, String>) {
	let key = |post: &Value| -> f64 {
		let data = &post["data"];
		let score = data["score"].as_f64().unwrap_or_default();
		let created = data["created_utc"].as_f64().unwrap_or_default();
		match sort {
			"new" => created,
			"hot" | "rising" => hot(score, created),
			_ => score,
		}
	};

	let mut taken = vec![0; feeds.len()];
	let mut page = Vec::new();
	while page.len() < PAGE_SIZE {
		let next = (0..feeds.len())
			.filter(|&i| taken[i] < feeds[i].1.len())
			.max_by(|&a, &b| key(&feeds[a].1[taken[a]]).total_cmp(&key(&feeds[b].1[taken[b]])).then(b.cmp(&a)));
		let Some(i) = next else { break };
		let post = &feeds[i].1[taken[i]];
		cursors.insert(feeds[i].0.to_lowercase(), post["data"]["name"].as_str().unwrap_or_default().to_string());
		page.push(post.clone());
		taken[i] += 1;
		if taken[i] == feeds[i].1.len() && feeds[i].2 {
			break;
		}
	}

	let more = feeds.iter().zip(&taken).any(|((_, posts, more), &taken)| taken < posts.len() || *more);
	(page, if more { cursors } else { HashMap::new() })
}

/// Reddit's hot ranking: the order of magnitude of the score plus the age,
/// where 12.5 hours are worth a tenfold score.
fn hot(score: f64, created: f64) -> f64 {
	score.signum() * score.abs().max(1.0).log10() + (created - 1_134_028_003.0) / 45_000.0
}

/// A subreddit's posts after `after` (a post, empty for the first) from the
/// fragment its reddit.com page loads them from, and whether more follow.
/// Cached briefly, as a merged listing loads every subreddit for each page.
#[cached(size = 256, time = 120, result = true)]
async fn batch(sub: String, sort: String, t: String, after: String, quarantine: bool) -> Result<(Vec<Value>, bool), String> {
	let mut path = format!("/svc/shreddit/community-more-posts/{sort}/?name={}&t={t}", utf8_percent_encode(&sub, NON_ALPHANUMERIC));
	if !after.is_empty() {
		use base64::{engine::general_purpose::STANDARD, Engine as _};
		path += &format!("&after={}", utf8_percent_encode(&STANDARD.encode(&after), NON_ALPHANUMERIC));
	}
	let res = reddit_get(path, quarantine).await?;
	if !res.status().is_success() {
		return Err(format!("reddit.com returned {}", res.status()));
	}
	let html = res.text().await.map_err(|e| e.to_string())?;
	let (posts, more) = parse_feed(&html);
	if posts.is_empty() && after.is_empty() {
		return Err("0 posts in reddit.com's feed".to_string());
	}
	Ok((posts, more))
}

/// The posts of a feed fragment in order, and whether it links to more.
fn parse_feed(html: &str) -> (Vec<Value>, bool) {
	let doc = Html::parse_document(html);
	let mut seen = std::collections::HashSet::new();
	let posts = doc
		.select(&POST)
		// Leave out the original posts shown inside crossposts
		.filter(|el| !el.ancestors().any(|a| a.value().as_element().is_some_and(|e| e.name() == "shreddit-post")))
		.filter_map(post_json)
		.filter(|post| seen.insert(post["data"]["name"].as_str().unwrap_or_default().to_string()))
		.collect();
	(posts, doc.select(&MORE_POSTS).next().is_some())
}

/// A feed's `<shreddit-post>` as a post of the listing JSON, with the fields
/// `Post::fetch` and `Media::parse` read.
fn post_json(el: ElementRef) -> Option<Value> {
	let attr = |name: &str| el.value().attr(name).unwrap_or_default();
	let fullname = attr("id");
	let id = fullname.strip_prefix("t3_")?;
	let created = DateTime::parse_from_str(attr("created-timestamp"), "%Y-%m-%dT%H:%M:%S%.f%z").map_or(0, |t| t.timestamp());

	let mut data = json_value!({
		"id": id,
		"name": fullname,
		"title": attr("post-title"),
		"author": attr("author"),
		"subreddit": attr("subreddit-name"),
		"permalink": attr("permalink"),
		"url": attr("content-href"),
		"domain": attr("domain"),
		"score": attr("score").parse::<i64>().unwrap_or_default(),
		"upvote_ratio": attr("upvote-ratio").parse::<f64>().unwrap_or(1.0),
		"num_comments": attr("comment-count").parse::<i64>().unwrap_or_default(),
		"created_utc": created,
		"over_18": el.value().attr("nsfw").is_some(),
		"spoiler": el.value().attr("spoiler").is_some(),
	});

	if let Some(flair) = el.select(&FLAIR).next() {
		let text = flair.text().collect::<Vec<_>>().join(" ").split_whitespace().collect::<Vec<_>>().join(" ");
		if !text.is_empty() {
			data["link_flair_type"] = "text".into();
			data["link_flair_text"] = text.into();
		}
	}

	let primary = el.select(&PRIMARY_IMAGE).next();
	let source = |img: ElementRef| {
		let size = |name: &str| img.value().attr(name).and_then(|v| v.parse::<i64>().ok()).unwrap_or_default();
		json_value!({ "url": img.value().attr("src").unwrap_or_default(), "width": size("width"), "height": size("height") })
	};

	match attr("post-type") {
		"text" => {
			data["is_self"] = true.into();
			let body = Selector::parse(&format!(r#"[id="{fullname}-post-rtjson-content"]"#))
				.ok()
				.and_then(|s| el.select(&s).next())
				.map(clean_html)
				.unwrap_or_default();
			if !body.is_empty() {
				data["selftext_html"] = format!("<div class=\"md\">{body}</div>").into();
			}
		}
		"image" => {
			data["post_hint"] = "image".into();
			if let Some(img) = primary {
				data["preview"] = json_value!({ "images": [{ "source": source(img) }] });
			}
		}
		"gallery" => {
			let (items, metadata) = gallery(el);
			data["is_gallery"] = true.into();
			data["gallery_data"] = json_value!({ "items": items });
			data["media_metadata"] = metadata;
		}
		"video" => {
			if let Some(player) = el.select(&PLAYER).next() {
				// The feed names no MP4 but a 96p preview, so the HLS stream stands in for it
				let hls = player.value().attr("src").unwrap_or_default();
				data["secure_media"] = json_value!({ "reddit_video": { "fallback_url": hls, "hls_url": hls, "is_gif": false } });
				data["preview"] = json_value!({ "images": [{ "source": { "url": player.value().attr("poster").unwrap_or_default() } }] });
			}
		}
		_ => {
			data["post_hint"] = "link".into();
			if let Some(img) = primary {
				let thumbnail = source(img);
				data["thumbnail"] = thumbnail["url"].clone();
				data["thumbnail_width"] = thumbnail["width"].clone();
				data["thumbnail_height"] = thumbnail["height"].clone();
			}
		}
	}

	Some(json_value!({ "kind": "t3", "data": data }))
}

/// The `gallery_data` items and `media_metadata` of a gallery post. Each
/// slide's full image is an i.redd.it `<img>`, after preview images that carry
/// its size.
fn gallery(el: ElementRef) -> (Vec<Value>, Value) {
	let mut items = Vec::new();
	let mut metadata = serde_json::Map::new();
	let (mut width, mut height) = (0, 0);
	for img in el.select(&GALLERY_IMAGE) {
		let size = |name: &str| img.value().attr(name).and_then(|v| v.parse::<i64>().ok());
		if let (Some(w), Some(h)) = (size("width"), size("height")) {
			(width, height) = (w, h);
		}
		let src = img.value().attr("src").unwrap_or_default();
		let Some(file) = src.strip_prefix("https://i.redd.it/") else { continue };
		let Some((media_id, ext)) = file.split('?').next().and_then(|f| f.split_once('.')) else {
			continue;
		};
		if metadata.contains_key(media_id) {
			continue;
		}
		let mime = if ext == "gif" { "image/gif".to_string() } else { format!("image/{ext}") };
		items.push(json_value!({ "media_id": media_id }));
		metadata.insert(media_id.to_string(), json_value!({ "m": mime, "s": { "u": src, "gif": src, "x": width, "y": height } }));
	}
	(items, Value::Object(metadata))
}

fn listing(children: Vec<Value>) -> Value {
	json_value!({ "kind": "Listing", "data": { "children": children } })
}

/// Converts `<shreddit-comment>` elements and "more replies" partials into the
/// comment tree of the JSON API.
fn parse_comments(html: &str, post_id: &str) -> Vec<Value> {
	let doc = Html::parse_document(html);
	let post_fullname = format!("t3_{post_id}");

	// (parent fullname, item) in document order
	let mut items: Vec<(String, Value)> = Vec::new();

	for el in doc.select(&COMMENT) {
		let attr = |name: &str| el.value().attr(name).unwrap_or_default();
		let fullname = attr("thingid");
		let Some(id) = fullname.strip_prefix("t1_") else { continue };
		let parent = el.value().attr("parentid").unwrap_or(&post_fullname).to_string();

		let body = if el.value().attr("is-comment-deleted").is_some() {
			"<p>[deleted]</p>".to_string()
		} else {
			// Select the body by ID so a reply's body is never picked up for a comment without one
			Selector::parse(&format!(r#"[id="{fullname}-comment-rtjson-content"]"#))
				.ok()
				.and_then(|s| el.select(&s).next())
				.map(clean_html)
				.unwrap_or_default()
		};

		let created = DateTime::parse_from_str(attr("created"), "%Y-%m-%dT%H:%M:%S%.f%z").map_or(0, |t| t.timestamp());

		items.push((
			parent.clone(),
			json_value!({
				"kind": "t1",
				"data": {
					"id": id,
					"name": fullname,
					"author": attr("author"),
					"body_html": format!("<div class=\"md\">{body}</div>"),
					"created_utc": created,
					"score": attr("score").parse::<i64>().unwrap_or_default(),
					"parent_id": parent,
					"replies": "",
				}
			}),
		));
	}

	for el in doc.select(&MORE) {
		let src = el.value().attr("src").unwrap_or_default();
		let Some(cursor) = el.select(&CURSOR).next().and_then(|i| i.value().attr("value")) else {
			continue;
		};

		if src.contains("top-level=1") {
			// More top-level comments: rendered as a link to the next page of comments
			let count = param(src, "comments-remaining").and_then(|c| c.parse::<i64>().ok()).unwrap_or_default();
			items.push((
				post_fullname.clone(),
				json_value!({
					"kind": "more_comments",
					"data": { "id": utf8_percent_encode(cursor, NON_ALPHANUMERIC).to_string(), "count": count, "parent_id": post_fullname }
				}),
			));
			continue;
		}

		// More replies: the cursor ends with the parent comment, e.g. "commenttree:abc,::1:d1:t1_xyz"
		use base64::{engine::general_purpose::STANDARD, Engine as _};
		let Some(parent) = STANDARD
			.decode(cursor)
			.ok()
			.and_then(|c| String::from_utf8(c).ok())
			.and_then(|c| c.rsplit(':').next().filter(|p| p.starts_with("t1_")).map(str::to_string))
		else {
			continue;
		};
		let count = el
			.select(&MORE_COUNT)
			.next()
			.and_then(|n| n.value().attr("number"))
			.and_then(|n| n.parse::<i64>().ok())
			.unwrap_or_default();
		items.push((parent.clone(), json_value!({ "kind": "more", "data": { "id": "", "count": count, "parent_id": parent } })));
	}

	// Build the tree. Items whose parent isn't on the page are top-level.
	let names: std::collections::HashSet<String> = items.iter().filter_map(|(_, v)| v["data"]["name"].as_str().map(str::to_string)).collect();
	let mut children: HashMap<String, Vec<Value>> = HashMap::new();
	let mut top = Vec::new();
	for (parent, item) in items {
		if names.contains(&parent) {
			children.entry(parent).or_default().push(item);
		} else {
			top.push(item);
		}
	}
	top.into_iter().map(|item| attach_replies(item, &mut children)).collect()
}

fn attach_replies(mut item: Value, children: &mut HashMap<String, Vec<Value>>) -> Value {
	let name = item["data"]["name"].as_str().unwrap_or_default().to_string();
	if let Some(replies) = children.remove(&name) {
		let replies = replies.into_iter().map(|r| attach_replies(r, children)).collect();
		item["data"]["replies"] = listing(replies);
	}
	item
}

const ALLOWED_TAGS: &[&str] = &[
	"p",
	"br",
	"hr",
	"a",
	"em",
	"strong",
	"b",
	"i",
	"del",
	"s",
	"sup",
	"sub",
	"code",
	"pre",
	"blockquote",
	"ul",
	"ol",
	"li",
	"h1",
	"h2",
	"h3",
	"h4",
	"h5",
	"h6",
	"table",
	"thead",
	"tbody",
	"tr",
	"th",
	"td",
	"span",
	"img",
	"figure",
];
const VOID_TAGS: &[&str] = &["br", "hr", "img"];

/// Rebuilds comment body HTML with only markdown tags and the attributes
/// links, images and tables need, dropping Reddit's wrappers and styling.
/// Media URLs are rewritten to Redlib's proxy here, as rewrite_urls only
/// handles Reddit media in the link format of the JSON API.
fn clean_html(el: ElementRef) -> String {
	let mut out = String::new();
	for child in el.children() {
		match child.value() {
			Node::Text(text) => out += &htmlescape::encode_minimal(text),
			Node::Element(e) => {
				let tag = e.name();
				if matches!(tag, "script" | "style" | "svg") {
					continue;
				}
				let inner = ElementRef::wrap(child).map(clean_html).unwrap_or_default();
				match tag {
					"shreddit-spoiler" => out += &format!("<span class=\"md-spoiler-text\">{inner}</span>"),
					// GIFs and videos in comments
					"shreddit-player" => {
						let src = url_attr(e.attr("src"));
						if !src.is_empty() {
							let play = if e.attr("gif").is_some() { "autoplay loop muted playsinline" } else { "controls" };
							out += &format!("<video src=\"{src}\" {play}></video>");
						}
					}
					_ if !ALLOWED_TAGS.contains(&tag) => out += &inner,
					_ => {
						out += &format!("<{tag}");
						for name in ["href", "src", "alt", "title", "align"] {
							let Some(value) = e.attr(name) else { continue };
							let value = if matches!(name, "href" | "src") {
								url_attr(Some(value))
							} else {
								htmlescape::encode_minimal(value)
							};
							if !value.is_empty() {
								out += &format!(" {name}=\"{value}\"");
							}
						}
						if tag == "img" {
							out += " loading=\"lazy\"";
						}
						out += ">";
						if !VOID_TAGS.contains(&tag) {
							out += &format!("{inner}</{tag}>");
						}
					}
				}
			}
			_ => {}
		}
	}
	out
}

/// Escaped URL attribute value, proxied through Redlib for Reddit media. Empty for `javascript:` URLs.
fn url_attr(value: Option<&str>) -> String {
	let value = value.unwrap_or_default().trim();
	if value.to_lowercase().starts_with("javascript:") {
		return String::new();
	}
	htmlescape::encode_minimal(&format_url(value))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_path() {
		assert_eq!(parse_path("/r/linux/comments/1xaxcyl/some_title/.json?&raw_json=1"), Some(("1xaxcyl".into(), None)));
		assert_eq!(parse_path("/r/linux/comments/1xaxcyl.json?sort=new&raw_json=1"), Some(("1xaxcyl".into(), None)));
		assert_eq!(
			parse_path("/r/linux/comments/1xaxcyl/some_title/19re6tdr7osth.json?&raw_json=1"),
			Some(("1xaxcyl".into(), Some("19re6tdr7osth".into())))
		);
		assert_eq!(parse_path("/comments/1xaxcyl/comments/abc.json?"), Some(("1xaxcyl".into(), Some("abc".into()))));
		assert_eq!(parse_path("/user/spez/comments/1xaxcyl.json?"), Some(("1xaxcyl".into(), None)));
		assert_eq!(parse_path("/r/linux/hot.json"), None);
	}

	#[test]
	fn test_is_feed() {
		assert!(is_feed("/r/2007scape/hot.json?&raw_json=1"));
		assert!(is_feed("/r/2007scape%2BBankTabs/rising.json?&raw_json=1"));
		assert!(is_feed("/r/2007scape%2Bironscape/new.json?sort=new&t=&after=&raw_json=1"));
		assert!(is_feed("/r/all/top.json?t=week&raw_json=1"));
		assert!(!is_feed("/r/2007scape/about.json?raw_json=1"));
		assert!(!is_feed("/r/2007scape/comments/1xtx10k.json?raw_json=1"));
		assert!(!is_feed("/r/2007scape/search.json?q=birds"));
		assert!(!is_feed("/by_id/t3_a,t3_b.json?raw_json=1"));
		assert!(!is_feed("/user/spez/hot.json"));
	}

	#[test]
	fn test_feed_parts() {
		let subs = |path: &str| feed_parts(path).map(|(subs, sort)| (subs.join(" "), sort.to_string()));
		assert_eq!(subs("/r/2007scape/hot.json?&raw_json=1"), Some(("2007scape".into(), "hot".into())));
		assert_eq!(subs("/r/2007scape%2Bironscape/new.json?after="), Some(("2007scape ironscape".into(), "new".into())));
		assert_eq!(subs("/r/a+b/rising.json"), Some(("a b".into(), "rising".into())));
	}

	#[test]
	fn test_parse_cursors() {
		let one = vec!["2007scape".to_string()];
		let two = vec!["2007scape".to_string(), "BankTabs".to_string()];
		assert_eq!(parse_cursors("t3_a", &one), HashMap::from([("2007scape".into(), "t3_a".into())]));
		assert_eq!(parse_cursors("", &one), HashMap::new());
		assert_eq!(
			parse_cursors("2007scape:t3_a,BankTabs:t3_b", &two),
			HashMap::from([("2007scape".into(), "t3_a".into()), ("banktabs".into(), "t3_b".into())])
		);
		// A bare post or a JSON API cursor can't be told apart between subreddits
		assert_eq!(parse_cursors("t3_a", &two), HashMap::new());
		assert_eq!(parse_cursors("2007scape:xyz", &two), HashMap::new());
	}

	#[test]
	fn test_merge() {
		let post = |name: &str, score: i64, created: i64| json_value!({ "kind": "t3", "data": { "name": name, "score": score, "created_utc": created } });
		let names = |page: &[Value]| page.iter().map(|p| p["data"]["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
		let day = 86_400;
		let a = ("a".to_string(), vec![post("t3_a1", 5000, 10 * day), post("t3_a2", 10, 10 * day)], true);
		let b = ("b".to_string(), vec![post("t3_b1", 100, 10 * day + day / 4), post("t3_b2", 1, 9 * day)], false);

		// Hot: a1's score outweighs b1's 6 hours; each feed keeps its own order
		let (page, next) = merge(vec![a.clone(), b.clone()], "hot", HashMap::new());
		assert_eq!(names(&page), ["t3_a1", "t3_b1", "t3_a2"]);
		// a ran out and has more pages, so the page stops there
		assert_eq!(next, HashMap::from([("a".into(), "t3_a2".into()), ("b".into(), "t3_b1".into())]));

		let (page, _) = merge(vec![a, b.clone()], "new", HashMap::new());
		assert_eq!(names(&page), ["t3_b1", "t3_a1", "t3_a2"]);

		// The end of every feed: no cursor
		let (page, next) = merge(vec![b], "hot", HashMap::from([("a".into(), "t3_a9".into())]));
		assert_eq!(names(&page), ["t3_b1", "t3_b2"]);
		assert!(next.is_empty());
	}

	/// Trimmed from a reddit.com feed fragment (`/svc/shreddit/community-more-posts/hot/?name=2007scape`)
	const FEED: &str = r#"
<article><shreddit-post permalink="/r/2007scape/comments/1xtvofg/for_the_first_time_in_years_scythe_has_dropped/" content-href="https://i.redd.it/69w23zll721i1.jpeg" comment-count="93" created-timestamp="2026-11-11T22:27:08.239000+0000" domain="i.redd.it" id="t3_1xtvofg" post-title="For the first time in years, Scythe has dropped below 1b" post-type="image" score="504" upvote-ratio="0.9701492537313433" subreddit-prefixed-name="r/2007scape" author="alice" subreddit-name="2007scape">
  <shreddit-post-flair slot="post-flair" post-id="t3_1xtvofg"><a href="/r/2007scape/?f=flair_name%3A%22Other%22"><span><div aria-label="Flair: Other" dir="auto"> Other </div></span></a></shreddit-post-flair>
  <div slot="post-media-container"><shreddit-aspect-ratio><img alt="" role="presentation" src="https://preview.redd.it/x-v0-69w23zll721i1.jpeg?width=640&amp;crop=smart&amp;auto=webp&amp;s=ea58" width="640" height="383"><img data-post-media-primary alt="r/2007scape - For the first time in years" src="https://preview.redd.it/x-v0-69w23zll721i1.jpeg?width=640&amp;crop=smart&amp;auto=webp&amp;s=ea58" width="640" height="383"></shreddit-aspect-ratio></div>
</shreddit-post></article>
<shreddit-ad-post id="t3_ad"><img data-post-media-primary src="https://preview.redd.it/ad.jpeg"></shreddit-ad-post>
<article><shreddit-post permalink="/r/2007scape/comments/1xtxzng/psa_duo_tfa/" content-href="https://www.reddit.com/r/2007scape/comments/1xtxzng/psa_duo_tfa/" comment-count="71" created-timestamp="2026-11-12T00:06:59.149000+0000" domain="self.2007scape" id="t3_1xtxzng" post-title="PSA: Duo TFA" post-type="text" score="335" upvote-ratio="0.85" subreddit-prefixed-name="r/2007scape" author="bob" subreddit-name="2007scape" spoiler>
  <a href="/r/2007scape/comments/1xtxzng/psa_duo_tfa/" slot="text-body"><div data-post-click-location="text-body"><div id="t3_1xtxzng-post-rtjson-content" about="t3_1xtxzng" property="schema:articleBody" dir="auto"><p class="mb-sm"> Grab a guy from the lobby. </p><p> purples are 28% better </p></div></div></a>
</shreddit-post></article>
<article><shreddit-post permalink="/r/2007scape/comments/1xtrqx2/sick_nerd/" content-href="https://www.twitch.tv/sick_nerd/clip/Joyous?tt_content=clip&amp;tt_medium=mobile_web_share" comment-count="352" created-timestamp="2026-11-11T19:51:22.404000+0000" domain="twitch.tv" id="t3_1xtrqx2" post-title="Sick_Nerd Disconnects and Dies" post-type="link" score="993" upvote-ratio="0.94" subreddit-prefixed-name="r/2007scape" author="carol" subreddit-name="2007scape" nsfw>
  <shreddit-post-flair slot="post-flair"><a href="/r/2007scape/?f=flair_name%3A%22HC%20Worlds%22"><span><div aria-label="Flair: :hcworlds: HC Worlds" dir="auto"><img src="https://emoji.redditmedia.com/hcworlds" alt=":hcworlds:"> HC Worlds </div></span></a></shreddit-post-flair>
  <div slot="post-media-container"><img data-post-media-primary alt="r/2007scape - Sick_Nerd" src="https://external-preview.redd.it/sick-nerd-v0-xlxm.jpeg?width=640&amp;crop=smart&amp;auto=webp&amp;s=42a5" width="640" height="360"></div>
</shreddit-post></article>
<article><shreddit-post permalink="/r/2007scape/comments/1xtpeop/3d_printed/" content-href="https://www.reddit.com/gallery/1xtpeop" comment-count="24" created-timestamp="2026-11-11T18:23:38.884000+0000" domain="reddit.com" id="t3_1xtpeop" post-title="3D Printed &amp; Painted Figures" post-type="gallery" score="232" upvote-ratio="0.964" subreddit-prefixed-name="r/2007scape" author="dan" subreddit-name="2007scape">
  <gallery-carousel>
    <li><figure><img src="https://preview.redd.it/fig-v0-lixum2uqs01i1.jpeg?width=640&amp;s=1199" width="2252" height="4000" alt=""><img src="https://preview.redd.it/fig-v0-lixum2uqs01i1.jpeg?width=640&amp;s=1199" width="2252" height="4000" alt="r/2007scape - 3D Printed"></figure><img src="https://i.redd.it/lixum2uqs01i1.jpeg" alt="r/2007scape - 3D Printed"></li>
    <li><figure><img width="800" height="1422" data-lazy-src="https://preview.redd.it/fig-v0-qto3uiliv01i1.gif?width=640&amp;s=2c89" alt=""></figure><img src="https://i.redd.it/qto3uiliv01i1.gif" alt="r/2007scape - 3D Printed"></li>
  </gallery-carousel>
</shreddit-post></article>
<article><shreddit-post permalink="/r/2007scape/comments/1xtc5jk/rhys_dcs/" content-href="https://v.redd.it/bzjptkahxx0i1" comment-count="616" created-timestamp="2026-11-11T08:04:34.765000+0000" domain="v.redd.it" id="t3_1xtc5jk" post-title="Rhys DCs on HC Worlds" post-type="video" score="1394" upvote-ratio="0.94" subreddit-prefixed-name="r/2007scape" author="eve" subreddit-name="2007scape">
  <div slot="post-media-container"><shreddit-player src="https://v.redd.it/bzjptkahxx0i1/HLSPlaylist.m3u8?f=hd%2CsubsAll&amp;v=1&amp;a=1797" post-type="video" poster="https://external-preview.redd.it/rhys-v0-cG04.png?width=640&amp;s=aa9f" preview="https://v.redd.it/bzjptkahxx0i1/CMAF_96.mp4"><img alt="media poster" src="https://external-preview.redd.it/rhys-v0-cG04.png?width=640&amp;s=aa9f" slot="poster"></shreddit-player></div>
</shreddit-post></article>
<article><shreddit-post id="t3_1xtvofg" post-type="image"></shreddit-post></article>
<faceplate-partial slot="load-after" id="partial-more-posts-dDNfMXh0a3BzMA" loading="programmatic" src="/svc/shreddit/community-more-posts/hot/?after=dDNfMXh0a3BzMA%3D%3D&amp;t=DAY&amp;name=2007scape&amp;feedLength=33" method="GET"></faceplate-partial>
"#;

	#[test]
	fn test_parse_feed() {
		let (posts, more) = parse_feed(FEED);
		assert!(more);
		// The ad and the repeated post are left out
		let names: Vec<_> = posts.iter().map(|p| p["data"]["name"].as_str().unwrap()).collect();
		assert_eq!(names, ["t3_1xtvofg", "t3_1xtxzng", "t3_1xtrqx2", "t3_1xtpeop", "t3_1xtc5jk"]);

		let image = &posts[0]["data"];
		assert_eq!(image["id"], "1xtvofg");
		assert_eq!(image["title"], "For the first time in years, Scythe has dropped below 1b");
		assert_eq!(image["author"], "alice");
		assert_eq!(image["subreddit"], "2007scape");
		assert_eq!(image["permalink"], "/r/2007scape/comments/1xtvofg/for_the_first_time_in_years_scythe_has_dropped/");
		assert_eq!(image["url"], "https://i.redd.it/69w23zll721i1.jpeg");
		assert_eq!(image["score"], 504);
		assert_eq!(image["num_comments"], 93);
		assert_eq!(image["upvote_ratio"], 0.9701492537313433);
		assert_eq!(image["created_utc"], 1794436028);
		assert_eq!(image["link_flair_text"], "Other");
		assert_eq!(image["over_18"], false);
		assert_eq!(image["post_hint"], "image");
		assert_eq!(
			image["preview"]["images"][0]["source"],
			json_value!({ "url": "https://preview.redd.it/x-v0-69w23zll721i1.jpeg?width=640&crop=smart&auto=webp&s=ea58", "width": 640, "height": 383 })
		);

		let text = &posts[1]["data"];
		assert_eq!(text["is_self"], true);
		assert_eq!(text["spoiler"], true);
		assert_eq!(
			text["selftext_html"],
			r#"<div class="md"><p> Grab a guy from the lobby. </p><p> purples are 28% better </p></div>"#
		);

		let link = &posts[2]["data"];
		assert_eq!(link["over_18"], true);
		assert_eq!(link["url"], "https://www.twitch.tv/sick_nerd/clip/Joyous?tt_content=clip&tt_medium=mobile_web_share");
		assert_eq!(link["link_flair_text"], "HC Worlds");
		assert_eq!(
			link["thumbnail"],
			"https://external-preview.redd.it/sick-nerd-v0-xlxm.jpeg?width=640&crop=smart&auto=webp&s=42a5"
		);
		assert_eq!(link["thumbnail_width"], 640);

		let gallery = &posts[3]["data"];
		assert_eq!(gallery["title"], "3D Printed & Painted Figures");
		assert_eq!(gallery["is_gallery"], true);
		assert_eq!(
			gallery["gallery_data"]["items"],
			json_value!([{ "media_id": "lixum2uqs01i1" }, { "media_id": "qto3uiliv01i1" }])
		);
		assert_eq!(gallery["media_metadata"]["lixum2uqs01i1"]["s"]["u"], "https://i.redd.it/lixum2uqs01i1.jpeg");
		assert_eq!(gallery["media_metadata"]["lixum2uqs01i1"]["s"]["x"], 2252);
		assert_eq!(gallery["media_metadata"]["qto3uiliv01i1"]["m"], "image/gif");
		assert_eq!(gallery["media_metadata"]["qto3uiliv01i1"]["s"]["y"], 1422);

		let video = &posts[4]["data"];
		let hls = "https://v.redd.it/bzjptkahxx0i1/HLSPlaylist.m3u8?f=hd%2CsubsAll&v=1&a=1797";
		assert_eq!(video["secure_media"]["reddit_video"]["hls_url"], hls);
		assert_eq!(video["secure_media"]["reddit_video"]["fallback_url"], hls);
		assert_eq!(
			video["preview"]["images"][0]["source"]["url"],
			"https://external-preview.redd.it/rhys-v0-cG04.png?width=640&s=aa9f"
		);

		// Not a feed
		assert_eq!(parse_feed("<html><body>Please wait for verification</body></html>"), (vec![], false));
	}

	#[tokio::test]
	async fn test_feed_media() {
		// The posts read as Redlib's JSON parsing expects
		let (posts, _) = parse_feed(FEED);
		let mut kinds = Vec::new();
		for post in &posts {
			let (kind, media, gallery) = crate::utils::Media::parse(&post["data"]).await;
			kinds.push((kind, media.url, media.alt_url, gallery.len()));
		}
		assert_eq!(
			kinds,
			[
				("image".to_string(), "/img/69w23zll721i1.jpeg".to_string(), String::new(), 0),
				("self".into(), "/r/2007scape/comments/1xtxzng/psa_duo_tfa/".into(), String::new(), 0),
				(
					"link".into(),
					"https://www.twitch.tv/sick_nerd/clip/Joyous?tt_content=clip&tt_medium=mobile_web_share".into(),
					String::new(),
					0
				),
				("gallery".into(), "/gallery/1xtpeop".into(), String::new(), 2),
				(
					"video".into(),
					"/hls/bzjptkahxx0i1/HLSPlaylist.m3u8?f=hd%2CsubsAll&v=1&a=1797".into(),
					"/hls/bzjptkahxx0i1/HLSPlaylist.m3u8?f=hd%2CsubsAll&v=1&a=1797".into(),
					0
				),
			]
		);
	}

	#[test]
	fn test_parse_comments() {
		let html = r#"
<shreddit-comment thingId="t1_a" author="alice" created="2026-10-20T17:00:53.706000+0000" score="18" depth="0">
  <div id="t1_a-comment-rtjson-content" slot="comment"><div class="x" dir="auto"><p rpl class="y">Hi <a class="z" href="https://www.reddit.com/r/rust" target="_blank">r/rust</a> &amp; <script>x</script></p></div></div>
  <div id="comment-children">
    <shreddit-comment thingId="t1_b" author="bob" created="2026-10-20T17:01:00.000000+0000" score="-2" depth="1" parentId="t1_a">
      <div id="t1_b-comment-rtjson-content" slot="comment"><p>reply</p></div>
    </shreddit-comment>
    <faceplate-partial src="/svc/shreddit/more-comments/linux/t3_p?startingDepth=1" method="post" slot="children">
      <input type="hidden" name="cursor" value="Y29tbWVudHRyZWU6NGFmMDViYzcsOjoxOmQxOnQxX2E="><faceplate-number number="7"></faceplate-number> more replies
    </faceplate-partial>
  </div>
</shreddit-comment>
<shreddit-comment thingId="t1_c" author="[deleted]" created="" score="1" depth="0" is-comment-deleted>
  <div id="comment-children"><shreddit-comment thingId="t1_d" author="dan" created="" score="3" depth="1" parentId="t1_c"><div id="t1_d-comment-rtjson-content" slot="comment"><p>orphan body</p></div></shreddit-comment></div>
</shreddit-comment>
<shreddit-comment thingId="t1_e" author="eve" created="" score="1" depth="0">
  <div id="t1_e-comment-rtjson-content" slot="comment"><p><shreddit-spoiler>secret</shreddit-spoiler></p><figure class="rte-media"><a href="https://preview.redd.it/x-v0-abc.jpeg?width=400&amp;s=1" class="w-fit"><img src="https://preview.redd.it/x-v0-abc.jpeg?width=400&amp;s=1" alt="Comment Image" srcset="a 1x" style="x"></a></figure><figure class="rte-media"><shreddit-player src="https://external-preview.redd.it/g.gif?width=356&amp;format=mp4&amp;s=2" gif autoplay><source src="https://external-preview.redd.it/g.gif"></shreddit-player></figure></div>
</shreddit-comment>
<faceplate-partial src="/svc/shreddit/more-comments/linux/t3_p?top-level=1&amp;comments-remaining=90&amp;commentPositionOffset=10" method="post"><input type="hidden" name="cursor" value="ab+/="></faceplate-partial>
"#;
		let comments = parse_comments(html, "p");
		assert_eq!(comments.len(), 4);

		let a = &comments[0]["data"];
		assert_eq!(a["author"], "alice");
		assert_eq!(a["parent_id"], "t3_p");
		assert_eq!(a["score"], 18);
		assert_eq!(a["created_utc"], 1792515653);
		assert_eq!(a["body_html"], r#"<div class="md"><p>Hi <a href="/r/rust">r/rust</a> &amp; </p></div>"#);

		let replies = a["replies"]["data"]["children"].as_array().unwrap();
		assert_eq!(replies.len(), 2);
		assert_eq!(replies[0]["data"]["author"], "bob");
		assert_eq!(replies[0]["data"]["score"], -2);
		assert_eq!(replies[1]["kind"], "more");
		assert_eq!(replies[1]["data"]["parent_id"], "t1_a");
		assert_eq!(replies[1]["data"]["count"], 7);

		// A deleted comment must not show its reply's body
		let c = &comments[1]["data"];
		assert_eq!(c["body_html"], r#"<div class="md"><p>[deleted]</p></div>"#);
		assert_eq!(c["replies"]["data"]["children"][0]["data"]["author"], "dan");

		assert_eq!(
			comments[2]["data"]["body_html"],
			concat!(
				r#"<div class="md"><p><span class="md-spoiler-text">secret</span></p>"#,
				r#"<figure><a href="/preview/pre/x-v0-abc.jpeg?width=400&amp;s=1"><img src="/preview/pre/x-v0-abc.jpeg?width=400&amp;s=1" alt="Comment Image" loading="lazy"></a></figure>"#,
				r#"<figure><video src="/preview/external-pre/g.gif?width=356&amp;format=mp4&amp;s=2" autoplay loop muted playsinline></video></figure></div>"#
			)
		);

		assert_eq!(comments[3]["kind"], "more_comments");
		assert_eq!(comments[3]["data"]["count"], 90);
		assert_eq!(comments[3]["data"]["id"], "ab%2B%2F%3D");
	}
}
