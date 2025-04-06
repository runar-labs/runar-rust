use anyhow::Result;
use std::net::UdpSocket;

pub fn start_stun_like_server(port: u16) -> Result<()> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))?;
    tokio::spawn(async move {
        let mut buf = [0; 1024];
        while let Ok((_amt, src)) = socket.recv_from(&mut buf) {
            let response = format!("Your public endpoint is {}", src);
            socket.send_to(response.as_bytes(), src).unwrap();
        }
    });
    Ok(())
}

pub async fn get_public_endpoint(stun_addr: &str) -> Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.send_to(b"binding request", stun_addr)?;
    let mut buf = [0; 1024];
    let (amt, _) = socket.recv_from(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..amt]).into_owned())
}
