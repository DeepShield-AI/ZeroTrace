/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::fmt;
use std::net::SocketAddr;
use std::net::UdpSocket;

use bincode::config::Configuration;
use bincode::{Decode, Encode};

use crate::metric::network::{collect_netdev, NetDevStat};
use public::debug::send_to;

#[derive(Debug, Encode, Decode, PartialEq)]
pub enum NetworkMessage {
    Show,
    Context(Vec<NetDevStat>),
    Err(String),
}

impl fmt::Display for NetworkMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkMessage::Context(stats) => {
                for stat in stats {
                    writeln!(f, "{}", stat)?;
                }
                Ok(())
            }
            NetworkMessage::Err(e) => write!(f, "Error: {}", e),
            _ => Ok(()),
        }
    }
}

pub struct NetworkDebugger;

impl NetworkDebugger {
    pub fn new() -> Self {
        Self
    }

    pub fn show(&self, sock: &UdpSocket, addr: SocketAddr, conf: Configuration) {
        let msg = match collect_netdev() {
            Ok(stats) => NetworkMessage::Context(stats),
            Err(e) => NetworkMessage::Err(e.to_string()),
        };
        let _ = send_to(sock, addr, msg, conf);
    }
}
