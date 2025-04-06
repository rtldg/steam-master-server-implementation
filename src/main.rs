// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025 rtldg <rtldg@protonmail.com>

// Going to be using a simple synchronous threaded approach for this...
//   new connection -> spawn thread...

// https://developer.valvesoftware.com/wiki/Master_Server_Query_Protocol

use anyhow::{Context, ensure};
use r2d2::Pool;
use r2d2_sqlite::rusqlite::ToSql;
use r2d2_sqlite::{SqliteConnectionManager, rusqlite::params};
use rand::{TryRngCore, rngs::OsRng};

use std::fmt::Write as FmtWrite;

use std::net::Ipv4Addr;
use std::{
	collections::HashMap,
	io::{Cursor, Write as IoWrite},
	net::{SocketAddr, SocketAddrV4, UdpSocket},
	sync::mpsc,
	time::{Duration, Instant},
};

fn simple_tag_cleaner(tags: &str) -> Vec<String> {
	tags.split(',')
		.filter(|s| !s.is_empty())
		.map(|s| {
			s.chars()
				.filter(|c| c.is_ascii_alphanumeric())
				.map(|c| c.to_ascii_lowercase())
				.collect()
		})
		.collect()
}

fn process_join(server_challenge: i32, msg: &[u8], peer_addr: SocketAddr, pool: &Pool<SqliteConnectionManager>) -> Option<()> {
	if &msg[0..2] != b"\x30\x0A" {
		return None;
	}

	let ip = match peer_addr.ip() {
		std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.to_bits(),
		std::net::IpAddr::V6(_) => 0,
	};
	let port = peer_addr.port();

	let mut protocol = 0u8;
	let mut challenge = -1i32;
	let mut players = 0u8;
	let mut maxplayers = 0u8;
	let mut bots = 0u8;
	let mut gamedir = "";
	let mut map = "";
	let mut password = false;
	let mut linux = false;
	let mut region = 0xFFu8;
	let mut dedicated = true;
	let mut secure = false;
	let mut version = String::new();
	//let mut product = "";
	// custom...
	let mut appid = 0u64;
	let mut gametype = String::new();
	let mut gamedata = String::new();
	let mut hostname = "";

	// utf8 here will break some server names that use funky ascii characters
	let msg = std::str::from_utf8(&msg[2..]).ok()?;
	let mut splits = msg.split('\\');

	while let Some(key) = splits.next() {
		let value = splits.next()?;
		if key == "protocol" {
			protocol = value.parse().ok()?;
		} else if key == "challenge" {
			challenge = value.parse().ok()?;
		} else if key == "players" {
			players = value.parse().ok()?;
		} else if key == "max" {
			maxplayers = value.parse().ok()?;
		} else if key == "bots" {
			bots = value.parse().ok()?;
		} else if key == "gamedir" {
			gamedir = value;
		} else if key == "map" {
			map = value;
		} else if key == "password" {
			password = value.parse::<u8>().ok()? == 1;
		} else if key == "os" {
			linux = value != "w";
		} else if key == "lan" {
			// we don't care
		} else if key == "region" {
			region = match value.parse().ok()? {
				v @ 0..=7 => v,
				0xFF => 0xFF,
				_ => return None,
			};
		} else if key == "type" {
			dedicated = value == "d";
		} else if key == "secure" {
			secure = value.parse::<u8>().ok()? == 1;
		} else if key == "version" {
			version = value.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
		} /*else if key == "product" {
		product = value;
		}*/
		// custom fields now:
		if key == "appid" {
			appid = value.parse().ok()?;
		} else if key == "gametype" {
			// for sv_tags
			let mut easily_searchable_tags = simple_tag_cleaner(value).join(",");
			easily_searchable_tags.insert(0, ',');
			easily_searchable_tags.push(',');
			gametype = easily_searchable_tags;
		} else if key == "gamedata" {
			// 'hidden' tags (L4D2.. what are these?)
			let mut easily_searchable_tags = simple_tag_cleaner(value).join(",");
			easily_searchable_tags.insert(0, ',');
			easily_searchable_tags.push(',');
			gamedata = easily_searchable_tags;
		} else if key == "hostname" {
			// server name
			hostname = value;
		}
	}

	if challenge != server_challenge {
		return None;
	}

	// TODO: should we just bump the protocol lol? If we were to then more of the protocol should be changed since it kind of sucks in couple ways.
	if protocol != 7 {
		return None;
	}

	let now = jiff::Timestamp::now().as_second();

	pool.get()
		.ok()?
		.execute(
			"
			INSERT OR REPLACE INTO servers (
			addr
			, ip
			, region
			, port
			, time_registered
			, dedicated
			, secure
			, linux
			, password
			, players
			, maxplayers
			, bots
			, proxy
			, appid
			, white
			, gamedir
			, map
			, gametype
			, gamedata
			, hostname
			, version
			)
			VALUES
			(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		",
			params![
				peer_addr.to_string(),
				ip,
				region,
				port,
				now,
				dedicated,
				secure,
				linux,
				password,
				players,
				maxplayers,
				bots,
				0, // hltv proxy
				appid,
				0, // whitelisted
				gamedir,
				map,
				gametype,
				gamedata,
				hostname,
				version,
			],
		)
		.ok()?;

	Some(())
}

fn convert_filter_to_sql(filter: &str, region: u8) -> Option<(String, Vec<String>)> {
	let mut sql = "SELECT ip, port FROM servers WHERE".to_string();
	let mut params = vec![];

	if region == 0xFF {
		let _ = write!(sql, " region >= 0"); // catchall just so we always have a WHERE...
	} else {
		let _ = write!(sql, " region = {region}");
	}

	let mut nor_count = 0;
	let mut nand_count = 0;
	let mut collapse_addr_hash = false;

	let mut splits = filter.split('\\');
	let simple_ints = ["dedicated", "secure", "linux", "password", "proxy", "white", "appid"];
	let simple_strings = ["gamedir", "map"];

	let mut op = "AND";

	while let Some(key) = splits.next() {
		let value = splits.next()?;
		if key == "nor" {
			if nor_count != 0 || nand_count != 0 {
				return None;
			}
			nor_count = value.parse::<u32>().ok()?;
			op = "OR";
			let _ = write!(sql, "AND NOT (");
		} else if key == "nand" {
			if nor_count != 0 || nand_count != 0 {
				return None;
			}
			nand_count = value.parse::<u32>().ok()?;
			let _ = write!(sql, "AND NOT (");
		} else if simple_ints.contains(&key) {
			let _ = write!(sql, " {op} {key} = {}", value.parse::<u64>().ok()?);
		} else if simple_strings.contains(&key) {
			let _ = write!(sql, " {op} {key} = ?");
			params.push(value.to_string());
		} else if key == "empty" {
			let _ = write!(sql, " {op} players = 0");
		} else if key == "full" {
			let _ = write!(sql, " {op} (players+bots) >= maxplayers");
		} else if key == "napp" {
			let _ = write!(sql, " {op} appid != {}", value.parse::<u64>().ok()?);
		} else if key == "noplayers" {
			let _ = write!(sql, " {op} players = 0");
		} else if key == "gametype" || key == "gamedata" || key == "gamedataor" {
			let inner_op = if key == "gamedataor" { "OR" } else { "AND" };
			let tags = simple_tag_cleaner(value);
			if tags.is_empty() {
				return None;
			}
			let _ = write!(sql, " {op} (instr({key}, ',{},')", tags[0]);
			for tag in tags {
				let _ = write!(sql, " {inner_op} instr({key}, ',{tag},')");
			}
			let _ = write!(sql, ")");
		} else if key == "name_match" || key == "version_match" {
			let _ = write!(sql, " {op} {key} LIKE ?");
			params.push(value.replace('*', "%"));
		} else if key == "collapse_addr_hash" {
			collapse_addr_hash = true;
		} else if key == "gameaddr" {
			let (ip, port) = if value.contains(':') {
				let addr = value.parse::<SocketAddrV4>().ok()?;
				(addr.ip().to_bits(), addr.port())
			} else {
				let ip = value.parse::<Ipv4Addr>().ok()?;
				(ip.to_bits(), 0)
			};
			let _ = write!(sql, " {op} (ip = {ip}");
			if port != 0 {
				let _ = write!(sql, " AND port = {port}");
			}
			let _ = write!(sql, ")");
		}

		if nor_count > 0 && key != "nor" {
			nor_count -= 1;
			if nor_count == 0 {
				op = "AND";
				let _ = write!(sql, ")");
			}
		}
		if nand_count > 0 && key != "nand" {
			nand_count -= 1;
			if nand_count == 0 {
				let _ = write!(sql, ")");
			}
		}
	}

	if collapse_addr_hash {
		let _ = write!(sql, " GROUP BY ip");
	}

	// filter was missing filters...
	if nor_count > 0 || nand_count > 0 {
		return None;
	}

	sql.push(';');
	Some((sql, params))
}

fn handle_connection(
	receiver: mpsc::Receiver<Vec<u8>>,
	socket: UdpSocket,
	peer_addr: SocketAddr,
	pool: Pool<SqliteConnectionManager>,
) -> anyhow::Result<()> {
	println!("connection from {}", peer_addr);

	let mut msg: Vec<u8> = receiver.recv()?;

	if msg == b"version" {
		socket.send_to(
			concat!(env!("CARGO_PKG_REPOSITORY"), " ", env!("CARGO_PKG_VERSION"), "\0").as_bytes(),
			peer_addr,
		)?;
		return Ok(());
	}

	// join list
	if msg == b"q" {
		loop {
			let challenge = OsRng.try_next_u32()? as i32 & i32::MAX;
			let mut challenge_msg = [0xFF, 0xFF, 0xFF, 0xFF, 0x73, 0x0A, 0, 0, 0, 0];
			let (_, r) = challenge_msg.split_at_mut(6);
			r.copy_from_slice(&challenge.to_le_bytes());
			let _ = socket.send_to(&challenge_msg, peer_addr)?;
			let msg = receiver.recv()?;
			if let Some(_) = process_join(challenge, &msg, peer_addr, &pool) {
				return Ok(());
			}
		}
	}

	let mut results: Option<Vec<SocketAddrV4>> = None;
	// query servers
	loop {
		assert!(msg[0] == b'1');
		let region = *msg.get(1).context("not enough buffer for the region")?;
		ensure!(region == 0xFF || (0..=7).contains(&region));

		let mut splits = (&msg[2..]).split_inclusive(|&v| v == b'\0');
		let _query_addr: SocketAddrV4 = std::str::from_utf8(splits.next().context("malformed query")?)?.parse()?;
		let filter = std::str::from_utf8(splits.next().context("malformed query filter")?)?;

		let mut buf = [0u8; 1500];
		let mut cur = Cursor::new(buf.as_mut());

		if results.is_none() {
			let (query, string_params) = convert_filter_to_sql(filter, region).context("failed to convert filter to sql")?;
			let sql_params: Vec<&dyn ToSql> = string_params.iter().map(|x| x as &dyn ToSql).collect();
			let pool = pool.get().unwrap();
			let mut stmt = pool.prepare(&query)?;
			let mut addrs = vec![];
			let mut rows = stmt.query(&*sql_params)?;
			while let Ok(Some(r)) = rows.next() {
				addrs.push(SocketAddrV4::new(Ipv4Addr::from_bits(r.get(0)?), r.get(1)?));
			}
			// 0.0.0.0:0 is used to flag the end of the list
			addrs.push(SocketAddrV4::new(Ipv4Addr::from_bits(0), 0));
			// we pop items off the end of the vec, so we want it reversed...
			addrs.reverse();
			results = Some(addrs);
		}

		if let Some(results) = &mut results {
			// random header
			let _ = cur.write(b"\xFF\xFF\xFF\xFF\x66\x0A");

			// Fits under 6*232 (1392) + header (6) fits nicely under 1500 which is a nice number to be less than.
			// I think the Steam master servers actually use 232 also but I'm too lazy to recheck.
			const MAX_SERVERS_PER_DATAGRAM: usize = 232;

			let mut servers_pushed = 0;
			for result in results.iter().rev().take(MAX_SERVERS_PER_DATAGRAM) {
				let _ = cur.write(&result.ip().to_bits().to_le_bytes());
				let _ = cur.write(&result.port().to_be_bytes());
				servers_pushed += 1;
			}
			results.truncate(results.len() - servers_pushed);

			let buflen = cur.position() as usize;
			drop(cur);
			socket.send_to(&buf[..buflen], peer_addr)?;

			if results.len() == 0 {
				// die
				return Ok(());
			}
		}

		msg = receiver.recv()?;
	}
}

fn database_cleaner(pool: Pool<SqliteConnectionManager>) {
	loop {
		std::thread::sleep(Duration::from_secs(30));
		let now = jiff::Timestamp::now();
		pool.get()
			.unwrap()
			.execute(
				"DELETE FROM servers WHERE (?-time_registered) > (60*7);",
				params![now.as_second()],
			)
			.unwrap();
	}
}

fn stale_client_remover() {
	let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
	loop {
		std::thread::sleep(Duration::from_secs(10));
		let _ = socket.send_to(b"clear", "127.0.0.1:27011").unwrap();
	}
}

fn main() -> anyhow::Result<()> {
	let socket = UdpSocket::bind("0.0.0.0:27011")?;

	let pool = r2d2::Pool::new(SqliteConnectionManager::memory())?;
	pool.get()?.execute_batch(
		"
		CREATE TABLE IF NOT EXISTS servers (
		  addr TEXT PRIMARY KEY
		, ip INT NOT NULL
		, region INT NOT NULL
		, port INT NOT NULL
		, time_registered INT NOT NULL
		, dedicated INT NOT NULL
		, secure INT NOT NULL
		, linux INT NOT NULL
		, password INT NOT NULL
		, players INT NOT NULL
		, maxplayers INT NOT NULL
		, bots INT NOT NULL
		, proxy INT NOT NULL
		, appid INT NOT NULL
		, white INT NOT NULL
		, gamedir TEXT NOT NULL
		, map TEXT NOT NULL
		, gametype TEXT NOT NULL
		, gamedata TEXT NOT NULL
		, hostname TEXT NOT NULL
		, version TEXT NOT NULL
		);

		CREATE INDEX IF NOT EXISTS ip ON servers (ip);
		CREATE INDEX IF NOT EXISTS region ON servers (region);
		CREATE INDEX IF NOT EXISTS dedicated ON servers (dedicated);
		CREATE INDEX IF NOT EXISTS secure ON servers (secure);
		CREATE INDEX IF NOT EXISTS linux ON servers (linux);
		CREATE INDEX IF NOT EXISTS password ON servers (password);
		CREATE INDEX IF NOT EXISTS proxy ON servers (proxy);
		CREATE INDEX IF NOT EXISTS appid ON servers (appid);
		CREATE INDEX IF NOT EXISTS white ON servers (white);
		CREATE INDEX IF NOT EXISTS gamedir ON servers (gamedir);
		CREATE INDEX IF NOT EXISTS version ON servers (version);
		",
	)?;

	std::thread::spawn({
		let pool = pool.clone();
		move || {
			database_cleaner(pool);
		}
	});
	std::thread::spawn({
		move || {
			stale_client_remover();
		}
	});

	struct ClientInfo {
		sender: mpsc::Sender<Vec<u8>>,
		last_msg: Instant,
	}
	let mut clients: HashMap<SocketAddr, ClientInfo> = Default::default();

	let mut buf = [0u8; 10000];
	loop {
		let (count, peer_addr) = socket.recv_from(&mut buf)?;
		let buf = &buf[..count];

		// how?
		if peer_addr.is_ipv6() {
			continue;
		}

		if peer_addr.ip().is_loopback() {
			if buf == b"clear" {
				clients.retain(|_k, v| v.last_msg.elapsed() < Duration::from_secs(6));
			}
		}

		if let Some(client) = clients.get_mut(&peer_addr) {
			if let Ok(_) = client.sender.send(Vec::from(buf)) {
				client.last_msg = Instant::now();
			} else {
				let _ = clients.remove(&peer_addr).unwrap();
			}
		} else {
			if buf != b"q" && buf != b"version" && buf[0] != b'1' {
				continue;
			}
			let (sender, receiver) = mpsc::channel();
			let _ = std::thread::spawn({
				let socket = socket.try_clone()?;
				let pool = pool.clone();
				move || {
					if let Err(e) = handle_connection(receiver, socket, peer_addr, pool) {
						eprintln!("{e:?}");
					}
				}
			});
			let _ = clients.insert(
				peer_addr,
				ClientInfo {
					sender,
					last_msg: Instant::now(),
				},
			);
		}
	}
}
