// Going to be using a simple synchronous threaded approach for this...
//   new connection -> spawn thread...

use r2d2::Pool;
use r2d2_sqlite::{SqliteConnectionManager, rusqlite::params};
use rand::{TryRngCore, rngs::OsRng};

use std::{
	collections::HashMap,
	net::{SocketAddr, UdpSocket},
	sync::mpsc,
	time::{Duration, Instant},
};

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
			let challenge = OsRng.try_next_u32()?;
			let mut challenge_msg = [0xFF, 0xFF, 0xFF, 0xFF, 0x73, 0x0A, 0, 0, 0, 0];
			let (_, r) = challenge_msg.split_at_mut(6);
			r.copy_from_slice(&challenge.to_le_bytes());
			let _ = socket.send_to(&challenge_msg, peer_addr)?;
			let msg = receiver.recv()?;
			// validate here...
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
	pool.get()?.execute(
		"CREATE TABLE IF NOT EXISTS servers (
			  time_registered INT NOT NULL
			, dedicated INT NOT NULL
			, region INT NOT NULL
			, secure INT NOT NULL
			, linux INT NOT NULL
			, password INT NOT NULL
			, connected INT NOT NULL
			, proxy INT NOT NULL
			, appid INT NOT NULL
			, white INT NOT NULL
			, gamedir TEXT NOT NULL
			, map TEXT NOT NULL
			, gametype TEXT NOT NULL
			, gamedata TEXT NOT NULL
			, name TEXT NOT NULL,
			, version TEXT NOT NULL
			, addr TEXT NOT NULL
			);",
		params![],
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
