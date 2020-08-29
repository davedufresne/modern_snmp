use crate::session::{Session, Step};
use snmp_mp::{self, SnmpMsg};
use snmp_usm::{Digest, PrivKey, SecurityParams};
use std::{
    io::{Error, ErrorKind, Result},
    net::{ToSocketAddrs, UdpSocket},
    time::Duration,
};

const MAX_RETRIES: u32 = 2;
// Timeout in seconds.
const TIMEOUT: u64 = 3;

// Client to send and receive SNMP messages. Only supports IPv4.
pub struct Client {
    socket: UdpSocket,
    buf: [u8; SnmpMsg::MAX_UDP_PACKET_SIZE],
}

impl Client {
    // Constructs a new `Client` and connect it to the remote address using UDP.
    pub fn new<A: ToSocketAddrs>(remote_addr: A) -> Result<Client> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;

        let timeout = Some(Duration::from_secs(TIMEOUT));
        socket.set_read_timeout(timeout)?;
        socket.set_write_timeout(timeout)?;
        socket.connect(remote_addr)?;

        let buf = [0; SnmpMsg::MAX_UDP_PACKET_SIZE];

        Ok(Self { socket, buf })
    }

    // Sends a request and returns the response on success.
    pub fn send_request<D, P, S>(
        &mut self,
        msg: &mut SnmpMsg,
        session: &mut Session<D, P, S>,
    ) -> Result<SnmpMsg>
    where
        D: Digest,
        P: PrivKey<Salt = S>,
        S: Step + Copy,
    {
        self.send_msg(msg, session)?;
        let response_msg = self.recv_msg(msg.id(), session)?;
        Ok(response_msg)
    }

    fn send_msg<D, P, S>(&self, msg: &mut SnmpMsg, session: &mut Session<D, P, S>) -> Result<usize>
    where
        D: Digest,
        P: PrivKey<Salt = S>,
        S: Step + Copy,
    {
        let mut security_params = SecurityParams::new();
        security_params
            .set_auth_params_placeholder()
            .set_username(session.username())
            .set_engine_id(session.engine_id())
            .set_engine_boots(session.engine_boots())
            .set_engine_time(session.engine_time());

        if let Some((priv_key, salt)) = session.priv_key_and_salt() {
            msg.encrypt_scoped_pdu(|encoded_scoped_pdu| {
                let (encrypted_scoped_pdu, priv_params) =
                    priv_key.encrypt(encoded_scoped_pdu, &security_params, salt);
                security_params.set_priv_params(&priv_params);

                encrypted_scoped_pdu
            });
        }

        msg.set_security_params(&security_params.encode());

        if session.auth_key().is_some() {
            msg.set_auth_flag();
        }

        let mut encoded_msg = msg.encode();

        if let Some(auth_key) = session.auth_key() {
            auth_key.auth_out_msg(&mut encoded_msg)?;
        }

        for _ in 0..MAX_RETRIES {
            let result = self.socket.send(&encoded_msg);
            if let Err(ref error) = result {
                if error.kind() == ErrorKind::WouldBlock {
                    continue;
                }
            }

            return result;
        }

        Err(Error::new(ErrorKind::TimedOut, "unable to send message"))
    }

    fn recv_msg<D, P, S>(
        &mut self,
        sent_msg_id: u32,
        session: &mut Session<D, P, S>,
    ) -> Result<SnmpMsg>
    where
        D: Digest,
        P: PrivKey,
    {
        for _ in 0..MAX_RETRIES {
            let result = self.socket.recv(&mut self.buf);

            match result {
                Err(error) => {
                    if error.kind() == ErrorKind::WouldBlock {
                        continue;
                    }

                    return Err(error);
                }
                Ok(len) => {
                    let encoded_msg = &mut self.buf[..len];
                    if let Some(auth_key) = session.auth_key() {
                        auth_key.auth_in_msg(
                            encoded_msg,
                            session.engine_id(),
                            session.engine_boots(),
                            session.engine_time(),
                        )?;
                    }

                    let mut msg = SnmpMsg::decode(encoded_msg)?;

                    if msg.id() != sent_msg_id {
                        continue;
                    }

                    let security_params = SecurityParams::decode(msg.security_params())?;
                    if let Some(priv_key) = session.priv_key() {
                        msg.decrypt_scoped_pdu(|encrypted_scoped_pdu| {
                            priv_key
                                .decrypt(encrypted_scoped_pdu, &security_params)
                                .ok()
                        })?;
                    }

                    session
                        .set_engine_boots(security_params.engine_boots())
                        .set_engine_time(security_params.engine_time());

                    return Ok(msg);
                }
            }
        }

        Err(Error::new(ErrorKind::TimedOut, "unable to receive message"))
    }
}
