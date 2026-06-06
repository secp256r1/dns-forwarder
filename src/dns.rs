use std::net::Ipv4Addr;

use anyhow::{Result, bail};

use crate::config::config;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_OPT: u16 = 41;
const DNS_CLASS_IN: u16 = 1;

/// Parse the first question's QNAME from a DNS query.
pub fn parse_qname(data: &[u8]) -> Result<String> {
    if data.len() < 12 {
        bail!("query too short");
    }

    let mut offset = 12;
    let mut labels = Vec::new();
    let mut jumped = false;

    loop {
        if offset >= data.len() {
            bail!("name extends past end of packet");
        }
        let len = data[offset];
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                bail!("compression pointer truncated");
            }
            let pointer = u16::from_be_bytes([data[offset], data[offset + 1]]) & 0x3FFF;
            if !jumped {
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

    Ok(labels.join("."))
}

/// Parse the QTYPE (query type) from a DNS query.
/// Parse both QTYPE and QCLASS from a DNS query.
pub fn parse_query_type_and_class(data: &[u8]) -> Result<(u16, u16)> {
    if data.len() < 16 {
        bail!("query too short");
    }
    let mut offset = 12;
    offset = skip_name(data, offset)?;
    if offset + 4 > data.len() {
        bail!("query truncated");
    }
    Ok((u16_be(data, offset), u16_be(data, offset + 2)))
}

/// Build a DNS query packet for the given target domain, QTYPE and QCLASS.
pub fn build_query(target: &str, qtype: u16, qclass: u16, query_id: u16) -> Vec<u8> {
    let qname = encode_domain_to_labels(target);
    let mut buf = Vec::with_capacity(12 + qname.len() + 4);
    buf.extend_from_slice(&query_id.to_be_bytes());
    buf.push(0x01); // QR=0, RD=1
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&qname);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&qclass.to_be_bytes());
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
}

fn u16_be(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

static DNS_HEADER_LEN: usize = 12;

/// Remove the EDNS0 OPT pseudo-record from the additional section of a DNS query.
/// Returns the stripped query. If no OPT record is present, returns the original.
pub fn strip_edns0(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < DNS_HEADER_LEN {
        return Ok(data.to_vec());
    }

    let qdcount = u16_be(data, 4);
    let ancount = u16_be(data, 6);
    let nscount = u16_be(data, 8);
    let arcount = u16_be(data, 10);

    let mut offset = DNS_HEADER_LEN;

    for _ in 0..qdcount {
        offset = skip_name(data, offset)?;
        offset += 4;
    }
    for _ in 0..ancount {
        offset = skip_name(data, offset)?;
        if offset + 10 > data.len() {
            bail!("answer section truncated");
        }
        let rdlength = u16_be(data, offset + 8) as usize;
        offset += 10 + rdlength;
    }
    for _ in 0..nscount {
        offset = skip_name(data, offset)?;
        if offset + 10 > data.len() {
            bail!("authority section truncated");
        }
        let rdlength = u16_be(data, offset + 8) as usize;
        offset += 10 + rdlength;
    }

    let mut opt_count = 0;
    let mut tmp = offset;
    for _ in 0..arcount {
        let saved = tmp;
        tmp = skip_name(data, tmp)?;
        if tmp + 10 > data.len() {
            bail!("additional section truncated");
        }
        let rtype = u16_be(data, tmp);
        let rdlength = u16_be(data, tmp + 8) as usize;
        if rtype == DNS_TYPE_OPT {
            opt_count += 1;
        } else {
            tmp = saved;
            break;
        }
        tmp += 10 + rdlength;
    }

    if opt_count == 0 {
        return Ok(data.to_vec());
    }

    let new_arcount = arcount - opt_count;
    let mut buf = Vec::with_capacity(data.len());
    buf.extend_from_slice(&data[..10]);
    buf.extend_from_slice(&new_arcount.to_be_bytes());
    buf.extend_from_slice(&data[DNS_HEADER_LEN..offset]);

    // Copy non-OPT additional records
    let mut remaining = tmp;
    for _ in opt_count..arcount {
        let start = remaining;
        remaining = skip_name(data, remaining)?;
        if remaining + 10 > data.len() {
            bail!("additional section truncated");
        }
        let rdlength = u16_be(data, remaining + 8) as usize;
        remaining += 10 + rdlength;
        buf.extend_from_slice(&data[start..remaining]);
    }

    Ok(buf)
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

/// Extract the CNAME target domain and TTL from a DNS response.
/// Returns `Ok(Some((target, ttl)))` if a CNAME record matching qname is found.
pub fn extract_cname_target_and_ttl(data: &[u8], qname: &str) -> Result<Option<(String, u32)>> {
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

    for _ in 0..ancount {
        let (name, new_offset) = read_domain_name(data, offset)?;
        offset = new_offset;

        if offset + 10 > data.len() {
            bail!("answer record truncated");
        }

        let rtype = u16_be(data, offset);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16_be(data, offset + 8) as usize;
        let rdata_off = offset + 10;

        if rtype == DNS_TYPE_CNAME && name.eq_ignore_ascii_case(qname) {
            let (target, _) = read_domain_name(data, rdata_off)?;
            return Ok(Some((target, ttl)));
        }

        offset = rdata_off + rdlength;
    }

    Ok(None)
}

/// Build a complete DNS response that includes the original question, a CNAME
/// chain and final A/AAAA records from source_response.
/// CNAME records are written without compression to avoid pointer issues.
pub fn build_cname_chase_response(
    query: &[u8],
    cname_chain: &[(String, u32)],
    source_response: &[u8],
    a_records: &[Ipv4Addr],
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

    let total_ancount = cname_chain.len() as u16 + src_ancount;

    let rcode = source_response[3] & 0x0F;

    let cap =
        12 + question.len() + cname_chain.len() * 64 + (source_response.len() - src_answers_start);

    let qname = parse_qname(query)?;

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

    if src_ancount == 0 && !a_records.is_empty() {
        let final_ttl = cname_chain.last().map(|(_, t)| *t).unwrap_or(300);
        for ip in a_records {
            let name_encoded = encode_domain_to_labels(&current_name);
            buf.extend_from_slice(&name_encoded);
            buf.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
            buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
            buf.extend_from_slice(&final_ttl.to_be_bytes());
            buf.extend_from_slice(&4u16.to_be_bytes());
            buf.extend_from_slice(ip.octets().as_slice());
        }
    } else {
        buf.extend_from_slice(&source_response[src_answers_start..src_ns_start]);
    }

    buf.extend_from_slice(&source_response[src_ns_start..src_additional_start]);
    buf.extend_from_slice(&source_response[src_additional_start..]);

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

    let mut min_ttl = config.cache.max_ttl as u32;
    let mut has_aaaa = false;
    let mut a_records = Vec::new();
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
        min_ttl = min_ttl.min(ttl);

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
                break;
            }
            _ => {}
        }

        offset = rdata_off + rdlength;
    }

    Ok((
        if has_aaaa {
            Response::Aaaa
        } else {
            Response::A(a_records)
        },
        min_ttl,
    ))
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
