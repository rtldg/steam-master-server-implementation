// Going to be using a simple synchronous threaded approach for this...
//   new connection -> spawn thread...

use atoi::atoi;
use r2d2::Pool;
use r2d2_sqlite::{SqliteConnectionManager, rusqlite::params};
use rand::{TryRngCore, rngs::OsRng};

use std::{
	collections::HashMap,
	net::{SocketAddr, UdpSocket},
	sync::{LazyLock, mpsc},
	time::{Duration, Instant},
};

fn process_join(server_challenge: i32, msg: &[u8], peer_addr: SocketAddr, pool: &Pool<SqliteConnectionManager>) -> Option<()> {
	static RE: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
		regex::bytes::Regex::new(r"\x30\x0A\\protocol\\7\\challenge\\(\d+)\\players\\(\d+)\\max\\(\d+)\\bots\\(\d+)\\gamedir\\([^\\]+)\\map\\([^\\]+)\\password\\(\d)\\os\\(.)\\lan\\(\d)\\region\\(\d+)\\type\\(.)\\secure\\(\d)\\version\\([\\d\.]+)\\product\\([^\\]+)\x0A").unwrap()
	});

	let (
		_full,
		[
			challenge,
			players,
			maxplayers,
			bots,
			gamedir,
			map,
			password,
			os,
			_lan,
			region,
			server_type,
			secure,
			version,
			product,
		],
	) = RE.captures(msg)?.extract();

	if challenge != format!("{server_challenge}").as_bytes() {
		return None;
	}

	let ip = match peer_addr.ip() {
		std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.to_bits(),
		std::net::IpAddr::V6(_) => 0,
	};

	let players = atoi::<u8>(players)?;
	let maxplayers = atoi::<u8>(maxplayers)?;
	let bots = atoi::<u8>(bots)?;
	let gamedir = std::str::from_utf8(gamedir).ok()?;
	let map = std::str::from_utf8(map).ok()?;
	let password = match atoi::<u8>(password)? {
		v @ (0 | 1) => v,
		_ => return None,
	};
	let linux = os == b"l";
	let region = match atoi::<u8>(region)? {
		v @ 0..=7 => v,
		0xFF => 0xFF,
		_ => return None,
	};
	let dedicated = server_type == b"d";
	let secure = atoi::<u8>(secure)? == 1;
	let version = std::str::from_utf8(version).ok()?;
	let product = std::str::from_utf8(product).ok()?;

	let appid = match product {
		"cstrike" => 240,
		_ => return None,
	};

	let now = jiff::Timestamp::now().as_second();

	pool.get()
		.ok()?
		.execute(
			"
			INSERT OR REPLACE INTO servers (
			addr
			, ip
			, region
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
			, name
			, version
			)
			VALUES
			(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		",
			params![
				peer_addr.to_string(),
				ip,
				region,
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
				"", // gametype
				"", // gamedata
				"", // name
				version
			],
		)
		.ok()?;

	Some(())
}

fn handle_connection(
	receiver: mpsc::Receiver<Vec<u8>>,
	socket: UdpSocket,
	peer_addr: SocketAddr,
	pool: Pool<SqliteConnectionManager>,
) -> anyhow::Result<()> {
	println!("connection from {}", peer_addr);

	let first_msg = receiver.recv()?;

	if first_msg == b"q" {
		// join list
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
	} else {
		// query servers
	}

	loop {
		let msg = receiver.recv()?;
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
		, name TEXT NOT NULL
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
			if buf != b"q" && buf[0] != b'1' {
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
