use anyhow::Context;
use serde_json::{json, Value};
use std::{net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
};

pub struct Fixtures {
    pub dns: std::net::SocketAddr,
    tcp: std::net::SocketAddr,
    udp: std::net::SocketAddr,
    tasks: JoinSet<()>,
}

impl Fixtures {
    pub async fn start() -> anyhow::Result<Self> {
        let dns = UdpSocket::bind("127.0.0.1:0").await?;
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let mut fixtures = Self {
            dns: dns.local_addr()?,
            tcp: tcp.local_addr()?,
            udp: udp.local_addr()?,
            tasks: JoinSet::new(),
        };
        fixtures.tasks.spawn(async move {
            let mut request = [0u8; 512];
            while let Ok((length, source)) = dns.recv_from(&mut request).await {
                if length < 16 {
                    continue;
                }
                let mut end = 12;
                while end < length && request[end] != 0 {
                    end += 1 + usize::from(request[end]);
                }
                end += 5;
                if end > length {
                    continue;
                }
                let question = &request[..end];
                let a = question[end - 4..end - 2] == [0, 1];
                let mut answer = question.to_vec();
                answer[2] = 0x81;
                answer[3] = 0x80;
                answer[6..12].fill(0);
                answer[7] = u8::from(a);
                if a {
                    answer.extend_from_slice(b"\xc0\x0c\0\x01\0\x01\0\0\0\x3c\0\x04\x7f\0\0\x01");
                }
                if dns.send_to(&answer, source).await.is_err() {
                    break;
                }
            }
        });
        fixtures.tasks.spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                let mut request = [0u8; 4];
                if stream.read_exact(&mut request).await.is_ok() {
                    let _ = stream.write_all(&request).await;
                }
            }
        });
        fixtures.tasks.spawn(async move {
            let mut request = [0u8; 512];
            while let Ok((length, source)) = udp.recv_from(&mut request).await {
                if udp.send_to(&request[..length], source).await.is_err() {
                    break;
                }
            }
        });
        Ok(fixtures)
    }

    async fn dns_query(&self, record_type: u8) -> anyhow::Result<Vec<u8>> {
        let peer = UdpSocket::bind("0.0.0.0:0").await?;
        let mut request =
            b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x06native\x07example\0\0\x01\0\x01".to_vec();
        let index = request.len() - 3;
        request[index] = record_type;
        peer.send_to(&request, "198.18.0.1:53")
            .await
            .context("Sending DNS probe through TUN")?;
        let mut answer = [0u8; 512];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut answer)).await??;
        anyhow::ensure!(
            length >= 12 && answer[..2] == [0x12, 0x34] && answer[3] & 15 == 0,
            "Invalid native DNS response"
        );
        Ok(answer[..length].to_vec())
    }

    pub async fn verify(&self) -> anyhow::Result<Value> {
        let answer = self.dns_query(1).await.context("TUN fake-IP DNS probe")?;
        anyhow::ensure!(answer[7] > 0 && answer.len() >= 16, "No fake-IP answer");
        let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&answer[answer.len() - 4..])?);
        anyhow::ensure!(
            ip.octets()[..2] == [198, 18],
            "DNS did not allocate a fake IP: {ip}"
        );
        let tcp = async |address: std::net::SocketAddr| -> anyhow::Result<()> {
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(b"meow").await?;
            let mut reply = [0u8; 4];
            stream.read_exact(&mut reply).await?;
            anyhow::ensure!(&reply == b"meow", "TCP origin reply mismatch");
            Ok(())
        };
        tokio::time::timeout(Duration::from_secs(10), tcp((ip, self.tcp.port()).into()))
            .await
            .context("TUN fake-IP TCP echo deadline")??;
        let udp = async |address: std::net::SocketAddr| -> anyhow::Result<()> {
            let peer = UdpSocket::bind("0.0.0.0:0").await?;
            peer.send_to(b"meow", address).await?;
            let mut reply = [0u8; 4];
            let (length, _) = peer.recv_from(&mut reply).await?;
            anyhow::ensure!(
                length == 4 && &reply == b"meow",
                "UDP origin reply mismatch"
            );
            Ok(())
        };
        tokio::time::timeout(Duration::from_secs(10), udp((ip, self.udp.port()).into()))
            .await
            .context("TUN fake-IP UDP echo deadline")??;
        tokio::time::timeout(Duration::from_secs(5), tcp(self.tcp)).await??;
        tokio::time::timeout(Duration::from_secs(5), udp(self.udp)).await??;
        let ipv6 = self.dns_query(28).await?;
        anyhow::ensure!(
            ipv6[6..8] == [0, 0],
            "IPv4-only fake-IP DNS must return AAAA NODATA"
        );
        Ok(
            json!({"fakeIp":ip.to_string(),"tcpOrigin":self.tcp.to_string(),"udpOrigin":self.udp.to_string(),"tcp":"echoPassed","udp":"echoPassed","ipLiteralLoopback":"passedOutsideFakeIpCapture","ipv6":"AAAA NODATA with no configured IPv6 pool or TUN address"}),
        )
    }
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}
