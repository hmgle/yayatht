// SPDX-FileCopyrightText: 2026 hmgle
// SPDX-License-Identifier: GPL-3.0-only

//! DNS `proxy-tcp` transaction engine (design §9 mode 1).
//!
//! Pure message logic: UDP queries are validated, given a private upstream
//! transaction ID, and forwarded as DNS-over-TCP; responses are matched,
//! validated against the stored question, and translated back to UDP with
//! the original ID, truncating with TC when the client's advertised
//! payload limit is exceeded. The reactor owns the sockets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Hard bound on concurrently outstanding queries; excess answers SERVFAIL.
pub const MAX_TRANSACTIONS: usize = 512;
/// RFC 1035 UDP payload limit for clients without EDNS0.
pub const DEFAULT_UDP_PAYLOAD_LIMIT: usize = 512;
/// Question sections longer than this are treated as malformed.
const MAX_QUESTION_BYTES: usize = 512;
/// Per-query deadline before a SERVFAIL is synthesized.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

const HEADER_LEN: usize = 12;
const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_TRUNCATED: u16 = 0x0200;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;
const OPT_RECORD_TYPE: u16 = 41;

#[derive(Debug)]
pub struct Transaction {
    /// Namespace endpoint the query came from and the reply returns to.
    pub client: SocketAddr,
    /// Gateway endpoint the query was addressed to (reply source).
    pub gateway: SocketAddr,
    original_id: u16,
    query_flags: u16,
    question: Vec<u8>,
    /// Client-advertised UDP payload capacity (EDNS0 or the 512 default).
    pub payload_limit: usize,
    deadline: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum QueryDisposition {
    /// Forward the query upstream after rewriting its ID.
    Forward { upstream_id: u16 },
    /// Answer the client immediately with this DNS message.
    Respond(Vec<u8>),
    /// Not a well-formed query; drop it silently.
    Drop,
}

/// A response translated for the original client.
#[derive(Debug)]
pub struct Reply {
    pub transaction: Transaction,
    pub payload: Vec<u8>,
    pub truncated: bool,
}

pub struct Engine {
    transactions: HashMap<u16, Transaction>,
    next_id: u16,
    query_timeout: Duration,
}

impl Default for Engine {
    fn default() -> Self {
        Self::with_query_timeout(QUERY_TIMEOUT)
    }
}

impl Engine {
    #[must_use]
    pub fn with_query_timeout(query_timeout: Duration) -> Self {
        Self {
            transactions: HashMap::new(),
            next_id: 0,
            query_timeout,
        }
    }

    /// Classifies a namespace UDP query. `resolver_available` reflects
    /// whether an upstream resolver is configured and reachable enough to
    /// try; without one every valid query is answered SERVFAIL.
    pub fn accept_query(
        &mut self,
        client: SocketAddr,
        gateway: SocketAddr,
        message: &[u8],
        resolver_available: bool,
        now: Instant,
    ) -> QueryDisposition {
        if message.len() < HEADER_LEN {
            return QueryDisposition::Drop;
        }
        let id = u16::from_be_bytes([message[0], message[1]]);
        let flags = u16::from_be_bytes([message[2], message[3]]);
        if flags & FLAG_RESPONSE != 0 {
            return QueryDisposition::Drop;
        }
        let Some(question) = question_section(message) else {
            return QueryDisposition::Respond(synthesize_failure(id, flags, &[], RCODE_FORMERR));
        };
        if question.len() > MAX_QUESTION_BYTES {
            return QueryDisposition::Respond(synthesize_failure(id, flags, &[], RCODE_FORMERR));
        }
        if !resolver_available || self.transactions.len() >= MAX_TRANSACTIONS {
            return QueryDisposition::Respond(synthesize_failure(
                id,
                flags,
                question,
                RCODE_SERVFAIL,
            ));
        }
        let payload_limit = edns_payload_limit(message, HEADER_LEN + question.len());
        let upstream_id = self.allocate_id();
        self.transactions.insert(
            upstream_id,
            Transaction {
                client,
                gateway,
                original_id: id,
                query_flags: flags,
                question: question.to_vec(),
                payload_limit,
                deadline: now + self.query_timeout,
            },
        );
        QueryDisposition::Forward { upstream_id }
    }

    /// Matches an upstream response frame to its transaction. Returns the
    /// transaction and the UDP payload for the client, with the original
    /// ID restored and TC truncation applied against `frame_limit` (the
    /// TAP frame capacity available for the DNS payload). Unmatched or
    /// question-mismatched responses are ignored; the transaction stays
    /// pending until its deadline.
    pub fn accept_response(&mut self, message: &[u8], frame_limit: usize) -> Option<Reply> {
        if message.len() < HEADER_LEN {
            return None;
        }
        let upstream_id = u16::from_be_bytes([message[0], message[1]]);
        let flags = u16::from_be_bytes([message[2], message[3]]);
        if flags & FLAG_RESPONSE == 0 {
            return None;
        }
        let question = question_section(message)?;
        let matches = self
            .transactions
            .get(&upstream_id)
            .is_some_and(|transaction| question_matches(&transaction.question, question));
        if !matches {
            return None;
        }
        let transaction = self
            .transactions
            .remove(&upstream_id)
            .expect("presence checked above");
        let limit = transaction.payload_limit.min(frame_limit);
        let truncated = message.len() > limit;
        let mut payload;
        if truncated {
            // Too big for the client's UDP capacity: return the header and
            // question with TC set so the client retries over TCP/53.
            payload = Vec::with_capacity(HEADER_LEN + question.len());
            payload.extend_from_slice(&transaction.original_id.to_be_bytes());
            payload.extend_from_slice(&(flags | FLAG_TRUNCATED).to_be_bytes());
            payload.extend_from_slice(&1u16.to_be_bytes());
            payload.extend_from_slice(&[0u8; 6]);
            payload.extend_from_slice(question);
        } else {
            payload = message.to_vec();
            payload[..2].copy_from_slice(&transaction.original_id.to_be_bytes());
        }
        Some(Reply {
            transaction,
            payload,
            truncated,
        })
    }

    /// Removes transactions past their deadline and returns the SERVFAIL
    /// replies owed to their clients.
    pub fn expire(&mut self, now: Instant) -> Vec<(Transaction, Vec<u8>)> {
        let expired: Vec<u16> = self
            .transactions
            .iter()
            .filter(|(_, transaction)| transaction.deadline <= now)
            .map(|(&id, _)| id)
            .collect();
        expired
            .into_iter()
            .map(|id| {
                let transaction = self.transactions.remove(&id).expect("collected above");
                let reply = synthesize_failure(
                    transaction.original_id,
                    transaction.query_flags,
                    &transaction.question,
                    RCODE_SERVFAIL,
                );
                (transaction, reply)
            })
            .collect()
    }

    /// Withdraws a just-forwarded transaction that could not be queued
    /// upstream, returning the SERVFAIL owed to its client.
    pub fn abort(&mut self, upstream_id: u16) -> Option<(Transaction, Vec<u8>)> {
        let transaction = self.transactions.remove(&upstream_id)?;
        let reply = synthesize_failure(
            transaction.original_id,
            transaction.query_flags,
            &transaction.question,
            RCODE_SERVFAIL,
        );
        Some((transaction, reply))
    }

    /// Fails every outstanding transaction, for an upstream connection
    /// that died before answering.
    pub fn fail_all(&mut self) -> Vec<(Transaction, Vec<u8>)> {
        self.transactions
            .drain()
            .map(|(_, transaction)| {
                let reply = synthesize_failure(
                    transaction.original_id,
                    transaction.query_flags,
                    &transaction.question,
                    RCODE_SERVFAIL,
                );
                (transaction, reply)
            })
            .collect()
    }

    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.transactions.is_empty()
    }

    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.transactions.len()
    }

    /// Earliest pending deadline, for timer scheduling.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.transactions
            .values()
            .map(|transaction| transaction.deadline)
            .min()
    }

    fn allocate_id(&mut self) -> u16 {
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if !self.transactions.contains_key(&id) {
                return id;
            }
        }
    }
}

/// Builds a minimal answer with the given RCODE, echoing the question when
/// one was parsable.
fn synthesize_failure(id: u16, query_flags: u16, question: &[u8], rcode: u16) -> Vec<u8> {
    let flags = FLAG_RESPONSE
        | (query_flags & FLAG_RECURSION_DESIRED)
        | FLAG_RECURSION_AVAILABLE
        | (rcode & 0x000f);
    let mut message = Vec::with_capacity(HEADER_LEN + question.len());
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&u16::from(!question.is_empty()).to_be_bytes());
    message.extend_from_slice(&[0u8; 6]);
    message.extend_from_slice(question);
    message
}

/// Returns the question section bytes for a single-question message.
fn question_section(message: &[u8]) -> Option<&[u8]> {
    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    if qdcount != 1 {
        return None;
    }
    let name_end = skip_name(message, HEADER_LEN)?;
    let end = name_end.checked_add(4)?;
    if end > message.len() {
        return None;
    }
    Some(&message[HEADER_LEN..end])
}

/// Skips a possibly compressed name starting at `offset`, returning the
/// offset just past it.
fn skip_name(message: &[u8], mut offset: usize) -> Option<usize> {
    for _ in 0..128 {
        let length = *message.get(offset)?;
        match length {
            0 => return Some(offset + 1),
            // A compression pointer terminates the name in place.
            _ if length & 0xc0 == 0xc0 => {
                return (offset + 2 <= message.len()).then_some(offset + 2);
            }
            _ if length & 0xc0 != 0 => return None,
            _ => offset = offset.checked_add(usize::from(length) + 1)?,
        }
    }
    None
}

/// Compares question sections: the name case-insensitively (0x20-style
/// clients randomize label case), qtype and qclass exactly.
fn question_matches(stored: &[u8], received: &[u8]) -> bool {
    if stored.len() != received.len() || stored.len() < 4 {
        return false;
    }
    let name_len = stored.len() - 4;
    stored[name_len..] == received[name_len..]
        && stored[..name_len].eq_ignore_ascii_case(&received[..name_len])
}

/// Walks the query's records for an EDNS0 OPT and returns the advertised
/// UDP payload capacity, never below the 512-byte default.
fn edns_payload_limit(message: &[u8], mut offset: usize) -> usize {
    let ancount = u16::from_be_bytes([message[6], message[7]]);
    let nscount = u16::from_be_bytes([message[8], message[9]]);
    let arcount = u16::from_be_bytes([message[10], message[11]]);
    let records = usize::from(ancount) + usize::from(nscount) + usize::from(arcount);
    for _ in 0..records.min(32) {
        let Some(name_end) = skip_name(message, offset) else {
            break;
        };
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        let Some(fixed_end) = name_end.checked_add(10) else {
            break;
        };
        if fixed_end > message.len() {
            break;
        }
        let record_type = u16::from_be_bytes([message[name_end], message[name_end + 1]]);
        let class = u16::from_be_bytes([message[name_end + 2], message[name_end + 3]]);
        if record_type == OPT_RECORD_TYPE {
            return usize::from(class).max(DEFAULT_UDP_PAYLOAD_LIMIT);
        }
        let rdlength = usize::from(u16::from_be_bytes([
            message[fixed_end - 2],
            message[fixed_end - 1],
        ]));
        let Some(next) = fixed_end.checked_add(rdlength) else {
            break;
        };
        if next > message.len() {
            break;
        }
        offset = next;
    }
    DEFAULT_UDP_PAYLOAD_LIMIT
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn client() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 40000)
    }

    fn gateway() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53)
    }

    /// A query for example.com A IN with the given ID.
    fn query(id: u16) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&id.to_be_bytes());
        message.extend_from_slice(&FLAG_RECURSION_DESIRED.to_be_bytes());
        message.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        message.extend_from_slice(b"\x07example\x03com\x00");
        message.extend_from_slice(&[0, 1, 0, 1]);
        message
    }

    fn query_with_opt(id: u16, payload: u16) -> Vec<u8> {
        let mut message = query(id);
        message[11] = 1; // ARCOUNT = 1
        message.push(0); // root name
        message.extend_from_slice(&OPT_RECORD_TYPE.to_be_bytes());
        message.extend_from_slice(&payload.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // TTL + RDLENGTH
        message
    }

    fn response_for(query: &[u8], answer_len: usize) -> Vec<u8> {
        let mut message = query.to_vec();
        let flags = u16::from_be_bytes([message[2], message[3]]) | FLAG_RESPONSE;
        message[2..4].copy_from_slice(&flags.to_be_bytes());
        message[7] = 1; // ANCOUNT
        message.extend_from_slice(&vec![0xab; answer_len]);
        message
    }

    fn forward(engine: &mut Engine, message: &[u8], now: Instant) -> u16 {
        match engine.accept_query(client(), gateway(), message, true, now) {
            QueryDisposition::Forward { upstream_id } => upstream_id,
            other => panic!("expected forward, got {other:?}"),
        }
    }

    #[test]
    fn forwards_a_query_and_restores_the_original_id() {
        let mut engine = Engine::default();
        let now = Instant::now();
        let message = query(0x1234);
        let upstream_id = forward(&mut engine, &message, now);
        let mut upstream = response_for(&message, 16);
        upstream[..2].copy_from_slice(&upstream_id.to_be_bytes());
        let reply = engine.accept_response(&upstream, 1400).unwrap();
        assert_eq!(reply.transaction.client, client());
        assert!(!reply.truncated);
        assert_eq!(&reply.payload[..2], &0x1234u16.to_be_bytes());
        assert_eq!(reply.payload.len(), upstream.len());
        assert!(engine.is_idle());
    }

    #[test]
    fn concurrent_same_id_queries_get_distinct_upstream_ids() {
        let mut engine = Engine::default();
        let now = Instant::now();
        let first = forward(&mut engine, &query(7), now);
        let second = forward(&mut engine, &query(7), now);
        assert_ne!(first, second);
        assert_eq!(engine.outstanding(), 2);
    }

    #[test]
    fn oversized_responses_are_truncated_with_tc() {
        let mut engine = Engine::default();
        let now = Instant::now();
        let message = query(9);
        let upstream_id = forward(&mut engine, &message, now);
        let mut upstream = response_for(&message, 800);
        upstream[..2].copy_from_slice(&upstream_id.to_be_bytes());
        let reply = engine.accept_response(&upstream, 1400).unwrap();
        assert!(reply.truncated);
        assert!(reply.payload.len() <= DEFAULT_UDP_PAYLOAD_LIMIT);
        let flags = u16::from_be_bytes([reply.payload[2], reply.payload[3]]);
        assert_ne!(flags & FLAG_TRUNCATED, 0);
        assert_eq!(&reply.payload[..2], &9u16.to_be_bytes());
        // Header + original question only, counts zeroed.
        assert_eq!(reply.payload.len(), message.len());
        assert_eq!(&reply.payload[6..12], &[0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn edns0_payload_size_raises_the_truncation_limit() {
        let mut engine = Engine::default();
        let now = Instant::now();
        let message = query_with_opt(11, 4096);
        let upstream_id = forward(&mut engine, &message, now);
        let mut upstream = response_for(&message, 800);
        upstream[..2].copy_from_slice(&upstream_id.to_be_bytes());
        let reply = engine.accept_response(&upstream, 8192).unwrap();
        assert!(!reply.truncated);
        let flags = u16::from_be_bytes([reply.payload[2], reply.payload[3]]);
        assert_eq!(flags & FLAG_TRUNCATED, 0);
        assert_eq!(reply.payload.len(), upstream.len());
    }

    #[test]
    fn frame_capacity_still_truncates_edns0_responses() {
        let mut engine = Engine::default();
        let now = Instant::now();
        let message = query_with_opt(12, 4096);
        let upstream_id = forward(&mut engine, &message, now);
        let mut upstream = response_for(&message, 2000);
        upstream[..2].copy_from_slice(&upstream_id.to_be_bytes());
        let reply = engine.accept_response(&upstream, 1400).unwrap();
        assert!(reply.truncated);
    }

    #[test]
    fn mismatched_question_leaves_the_transaction_pending() {
        let mut engine = Engine::default();
        let now = Instant::now();
        let message = query(13);
        let upstream_id = forward(&mut engine, &message, now);
        let other = query(13).splice_name();
        let mut upstream = response_for(&other, 16);
        upstream[..2].copy_from_slice(&upstream_id.to_be_bytes());
        assert!(engine.accept_response(&upstream, 1400).is_none());
        assert_eq!(engine.outstanding(), 1);
    }

    #[test]
    fn case_randomized_question_still_matches() {
        let mut engine = Engine::default();
        let now = Instant::now();
        let message = query(14);
        let upstream_id = forward(&mut engine, &message, now);
        let mut upstream = response_for(&message, 16);
        upstream[..2].copy_from_slice(&upstream_id.to_be_bytes());
        // Upper-case the qname labels as a 0x20-normalizing resolver would.
        upstream[HEADER_LEN + 1..HEADER_LEN + 8].make_ascii_uppercase();
        assert!(engine.accept_response(&upstream, 1400).is_some());
    }

    #[test]
    fn malformed_queries_get_formerr_and_headerless_junk_is_dropped() {
        let mut engine = Engine::default();
        let now = Instant::now();
        assert_eq!(
            engine.accept_query(client(), gateway(), &[0u8; 4], true, now),
            QueryDisposition::Drop
        );
        let mut two_questions = query(15);
        two_questions[5] = 2;
        match engine.accept_query(client(), gateway(), &two_questions, true, now) {
            QueryDisposition::Respond(reply) => {
                assert_eq!(
                    u16::from_be_bytes([reply[2], reply[3]]) & 0x000f,
                    RCODE_FORMERR
                );
            }
            other => panic!("expected FORMERR, got {other:?}"),
        }
    }

    #[test]
    fn no_resolver_answers_servfail_with_the_question_echoed() {
        let mut engine = Engine::default();
        let now = Instant::now();
        let message = query(16);
        match engine.accept_query(client(), gateway(), &message, false, now) {
            QueryDisposition::Respond(reply) => {
                assert_eq!(
                    u16::from_be_bytes([reply[2], reply[3]]) & 0x000f,
                    RCODE_SERVFAIL
                );
                assert_eq!(&reply[HEADER_LEN..], &message[HEADER_LEN..]);
                assert_eq!(&reply[..2], &16u16.to_be_bytes());
            }
            other => panic!("expected SERVFAIL, got {other:?}"),
        }
        assert!(engine.is_idle());
    }

    #[test]
    fn expiry_synthesizes_servfail_for_the_original_client() {
        let mut engine = Engine::default();
        let now = Instant::now();
        forward(&mut engine, &query(17), now);
        assert!(engine.expire(now).is_empty());
        let failures = engine.expire(now + QUERY_TIMEOUT);
        assert_eq!(failures.len(), 1);
        let (transaction, reply) = &failures[0];
        assert_eq!(transaction.client, client());
        assert_eq!(&reply[..2], &17u16.to_be_bytes());
        assert_eq!(
            u16::from_be_bytes([reply[2], reply[3]]) & 0x000f,
            RCODE_SERVFAIL
        );
        assert!(engine.is_idle());
    }

    #[test]
    fn transaction_limit_answers_servfail() {
        let mut engine = Engine::default();
        let now = Instant::now();
        for _ in 0..MAX_TRANSACTIONS {
            forward(&mut engine, &query(1), now);
        }
        match engine.accept_query(client(), gateway(), &query(1), true, now) {
            QueryDisposition::Respond(reply) => {
                assert_eq!(
                    u16::from_be_bytes([reply[2], reply[3]]) & 0x000f,
                    RCODE_SERVFAIL
                );
            }
            other => panic!("expected SERVFAIL, got {other:?}"),
        }
    }

    trait SpliceName {
        fn splice_name(self) -> Vec<u8>;
    }

    impl SpliceName for Vec<u8> {
        /// Same shape, different qname content.
        fn splice_name(mut self) -> Vec<u8> {
            self[HEADER_LEN + 1] = b'x';
            self
        }
    }
}
