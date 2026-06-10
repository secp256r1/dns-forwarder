use std::net::Ipv4Addr;

use anyhow::{Result, bail};

use crate::config::config;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_CLASS_IN: u16 = 1;

pub struct QueryInfo {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl QueryInfo {
    pub fn parse(data: &[u8]) -> Result<QueryInfo> {
        if data.len() < 12 {
            bail!("query too short");
        }

        let mut offset = 12;
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut end_offset = offset;

        loop {
            if offset >= data.len() {
                bail!("name extends past end of packet");
            }
            let len = data[offset];
            if len == 0 {
                if !jumped {
                    end_offset = offset + 1;
                }
                break;
            }
            if len & 0xC0 == 0xC0 {
                if offset + 1 >= data.len() {
                    bail!("compression pointer truncated");
                }
                let pointer = u16::from_be_bytes([data[offset], data[offset + 1]]) & 0x3FFF;
                if !jumped {
                    end_offset = offset + 2;
                    jumped = true;
                }
                offset = pointer as usize;
            } else {
                offset += 1;
                if offset + len as usize > data.len() {
                    bail!("label extends past end of packet");
                }
                labels.push(std::str::from_utf8(&data[offset..offset + len as usize])?.to_string());
                offset += len as usize;
            }
        }

        if end_offset + 4 > data.len() {
            bail!("query truncated");
        }

        Ok(QueryInfo {
            qname: labels.join("."),
            qtype: u16_be(data, end_offset),
            qclass: u16_be(data, end_offset + 2),
        })
    }

    pub fn new_qname(&self, qname: &str) -> QueryInfo {
        QueryInfo {
            qname: qname.to_string(),
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }
}

/// Build a DNS query packet for the given target domain, QTYPE and QCLASS.
pub fn build_query(query_id: u16, info: &QueryInfo) -> Vec<u8> {
    let qname = encode_domain_to_labels(&info.qname);
    let mut buf = Vec::with_capacity(12 + qname.len() + 4);
    buf.extend_from_slice(&query_id.to_be_bytes());
    buf.push(0x01); // QR=0, RD=1
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&qname);
    buf.extend_from_slice(&info.qtype.to_be_bytes());
    buf.extend_from_slice(&info.qclass.to_be_bytes());
    buf
}

fn encode_domain_to_labels(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0x00);
    encoded
}

pub enum Response {
    A(Vec<Ipv4Addr>),
    Aaaa,
    Cname(String),
}

fn u16_be(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn skip_name(data: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        if offset >= data.len() {
            bail!("name extends past end of packet");
        }
        let len = data[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Ok(offset + 2);
        }
        offset += 1 + len as usize;
    }
}

/// Read a domain name at any offset, handling DNS name compression.
/// Returns (name, offset_after_name).
pub fn read_domain_name(data: &[u8], mut offset: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_offset = offset;

    loop {
        if offset >= data.len() {
            bail!("name extends past end of packet");
        }
        let len = data[offset];
        if len == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                bail!("compression pointer truncated");
            }
            let pointer = u16::from_be_bytes([data[offset], data[offset + 1]]) & 0x3FFF;
            if !jumped {
                end_offset = offset + 2;
                jumped = true;
            }
            offset = pointer as usize;
        } else {
            offset += 1;
            if offset + len as usize > data.len() {
                bail!("label extends past end of packet");
            }
            labels.push(std::str::from_utf8(&data[offset..offset + len as usize])?.to_string());
            offset += len as usize;
        }
    }

    Ok((labels.join("."), end_offset))
}

/// Copy a section of DNS resource records, decompressing owner names and
/// re-encoding them uncompressed to avoid broken compression pointers.
fn copy_rr_section(
    buf: &mut Vec<u8>,
    data: &[u8],
    mut off: usize,
    count: u16,
) -> Result<usize> {
    for _ in 0..count {
        let (name, next) = read_domain_name(data, off)?;
        if next + 10 > data.len() {
            bail!("resource record truncated");
        }
        let rtype = u16_be(data, next);
        let rclass = u16_be(data, next + 2);
        let ttl = u32::from_be_bytes([
            data[next + 4],
            data[next + 5],
            data[next + 6],
            data[next + 7],
        ]);
        let rdlength = u16_be(data, next + 8) as usize;
        let rdata_off = next + 10;
        if rdata_off + rdlength > data.len() {
            bail!("rdata truncated");
        }
        let name_encoded = encode_domain_to_labels(&name);
        buf.extend_from_slice(&name_encoded);
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&rclass.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&(rdlength as u16).to_be_bytes());
        buf.extend_from_slice(&data[rdata_off..rdata_off + rdlength]);
        off = rdata_off + rdlength;
    }
    Ok(off)
}

/// Build a complete DNS response that includes the original question, a CNAME
/// chain and final A/AAAA records from source_response.
/// CNAME records are written without compression to avoid pointer issues.
pub fn build_cname_chase_response(
    query: &[u8],
    cname_chain: &[(String, u32)],
    source_response: &[u8],
    response: &Response,
    ttl: u32,
) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("query too short");
    }

    let qdcount = u16_be(query, 4);

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(query, offset)?;
        offset += 4;
    }
    let question = &query[12..offset];

    let src_qdcount = u16_be(source_response, 4);
    let src_ancount = u16_be(source_response, 6);
    let src_nscount = u16_be(source_response, 8);
    let src_arcount = u16_be(source_response, 10);

    let mut src_off = 12;
    for _ in 0..src_qdcount {
        src_off = skip_name(source_response, src_off)?;
        src_off += 4;
    }
    let src_answers_start = src_off;

    for _ in 0..src_ancount {
        src_off = skip_name(source_response, src_off)?;
        src_off += 10 + u16_be(source_response, src_off + 8) as usize;
    }
    let src_ns_start = src_off;

    for _ in 0..src_nscount {
        src_off = skip_name(source_response, src_off)?;
        src_off += 10 + u16_be(source_response, src_off + 8) as usize;
    }
    let src_additional_start = src_off;

    let extra_a_count = if src_ancount == 0
        && let Response::A(ips) = response
        && !ips.is_empty()
    {
        ips.len()
    } else {
        0
    };
    let total_ancount = cname_chain.len() as u16 + src_ancount + extra_a_count as u16;

    let rcode = source_response[3] & 0x0F;

    let cap =
        12 + question.len() + cname_chain.len() * 64 + (source_response.len() - src_answers_start);

    let qname = QueryInfo::parse(query)?.qname;

    let mut buf = Vec::with_capacity(cap);
    buf.extend_from_slice(&query[..2]);
    buf.push(0x80 | (query[2] & 0x01));
    buf.push(0x80 | rcode);
    buf.extend_from_slice(&qdcount.to_be_bytes());
    buf.extend_from_slice(&total_ancount.to_be_bytes());
    buf.extend_from_slice(&src_nscount.to_be_bytes());
    buf.extend_from_slice(&src_arcount.to_be_bytes());
    buf.extend_from_slice(question);

    let mut current_name = qname;
    for (target, ttl) in cname_chain {
        let name_encoded = encode_domain_to_labels(&current_name);
        let target_encoded = encode_domain_to_labels(target);
        buf.extend_from_slice(&name_encoded);
        buf.extend_from_slice(&DNS_TYPE_CNAME.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&(target_encoded.len() as u16).to_be_bytes());
        buf.extend_from_slice(&target_encoded);
        current_name = target.clone();
    }

    if src_ancount == 0
        && let Response::A(ips) = response
        && !ips.is_empty()
    {
        for ip in ips {
            let name_encoded = encode_domain_to_labels(&current_name);
            buf.extend_from_slice(&name_encoded);
            buf.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
            buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
            buf.extend_from_slice(&ttl.to_be_bytes());
            buf.extend_from_slice(&4u16.to_be_bytes());
            buf.extend_from_slice(ip.octets().as_slice());
        }
    } else {
        copy_rr_section(&mut buf, source_response, src_answers_start, src_ancount)?;
    }

    copy_rr_section(&mut buf, source_response, src_ns_start, src_nscount)?;
    copy_rr_section(&mut buf, source_response, src_additional_start, src_arcount)?;

    Ok(buf)
}

pub fn analyze_response(data: &[u8]) -> Result<(Response, u32)> {
    if data.len() < 12 {
        bail!("response too short");
    }

    let qdcount = u16_be(data, 4);
    let ancount = u16_be(data, 6);

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(data, offset)?;
        offset += 4;
    }

    let config = config()?;

    let mut max_ttl = 0;
    let mut has_aaaa = false;
    let mut a_records = Vec::new();
    let mut cname_target = None;
    for _ in 0..ancount {
        offset = skip_name(data, offset)?;
        if offset + 10 > data.len() {
            bail!("answer record truncated");
        }

        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        max_ttl = max_ttl.max(ttl);

        let rtype = u16_be(data, offset);
        let rdlength = u16_be(data, offset + 8) as usize;
        let rdata_off = offset + 10;

        match rtype {
            DNS_TYPE_A if rdlength == 4 && rdata_off + 4 <= data.len() => {
                let ip = format!(
                    "{}.{}.{}.{}",
                    data[rdata_off],
                    data[rdata_off + 1],
                    data[rdata_off + 2],
                    data[rdata_off + 3],
                );
                a_records.push(ip.parse()?);
            }
            DNS_TYPE_AAAA => {
                has_aaaa = true;
            }
            DNS_TYPE_CNAME if cname_target.is_none() => {
                let (target, _) = read_domain_name(data, rdata_off)?;
                cname_target = Some(target);
            }
            _ => {}
        }

        offset = rdata_off + rdlength;
    }

    if !a_records.is_empty() || has_aaaa {
        Ok((
            if has_aaaa {
                Response::Aaaa
            } else {
                Response::A(a_records)
            },
            config.cache.normalize_ttl(max_ttl as u64) as u32,
        ))
    } else if let Some(target) = cname_target {
        Ok((
            Response::Cname(target),
            config.cache.normalize_ttl(max_ttl as u64) as u32,
        ))
    } else {
        Ok((
            Response::A(Vec::new()),
            config.cache.normalize_ttl(max_ttl as u64) as u32,
        ))
    }
}

pub fn cap_response_ttl(response: &mut [u8], max_ttl: u32) -> Result<()> {
    if response.len() < 12 {
        bail!("response too short");
    }

    let qdcount = u16_be(response, 4);
    let ancount = u16_be(response, 6);

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(response, offset)?;
        offset += 4;
    }

    for _ in 0..ancount {
        offset = skip_name(response, offset)?;
        if offset + 10 > response.len() {
            bail!("answer record truncated");
        }
        response[offset + 4..offset + 4 + 4].copy_from_slice(&max_ttl.to_be_bytes());
        let rdlength = u16_be(response, offset + 8) as usize;
        offset += 10 + rdlength;
    }

    Ok(())
}

pub fn build_nxdomain_response(query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("query too short");
    }

    let qdcount = u16_be(query, 4);
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(query, offset)?;
        offset += 4;
    }
    let question = &query[12..offset];

    let total = 12 + question.len();
    let mut resp = Vec::with_capacity(total);

    resp.extend_from_slice(&query[..2]);

    let rd_bit = query[2] & 0x01;
    resp.push(0x80 | rd_bit);
    // RA=1, RCODE=3 (NXDOMAIN)
    resp.push(0x83);

    resp.extend_from_slice(&[0x00, qdcount as u8]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);

    resp.extend_from_slice(question);

    Ok(resp)
}

pub fn build_empty_response(query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("query too short");
    }

    let qdcount = u16_be(query, 4);
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(query, offset)?;
        offset += 4;
    }
    let question = &query[12..offset];

    let total = 12 + question.len();
    let mut resp = Vec::with_capacity(total);

    resp.extend_from_slice(&query[..2]);

    let rd_bit = query[2] & 0x01;
    resp.push(0x80 | rd_bit);
    // RA=1, RCODE=0 (NOERROR)
    resp.push(0x80);

    resp.extend_from_slice(&[0x00, qdcount as u8]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);

    resp.extend_from_slice(question);

    Ok(resp)
}

pub fn build_a_response(query: &[u8], ip: &[u8; 4]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("query too short");
    }

    let qdcount = u16_be(query, 4);
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(query, offset)?;
        offset += 4;
    }
    let question = &query[12..offset];

    let answer_len = 2 + 2 + 2 + 2 + 4 + 2 + 4;
    let total = 12 + question.len() + answer_len;

    let mut resp = Vec::with_capacity(total);

    resp.extend_from_slice(&query[..2]);

    let rd_bit = query[2] & 0x01;
    resp.push(0x80 | rd_bit);
    resp.push(0x80);

    resp.extend_from_slice(&[0x00, qdcount as u8]);
    resp.extend_from_slice(&[0x00, qdcount as u8]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);

    resp.extend_from_slice(question);

    resp.push(0xC0);
    resp.push(0x0C);
    resp.extend_from_slice(&[0x00, DNS_TYPE_A as u8]);
    resp.extend_from_slice(&[0x00, DNS_CLASS_IN as u8]);
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
    resp.extend_from_slice(&[0x00, 0x04]);
    resp.extend_from_slice(ip);

    Ok(resp)
}
