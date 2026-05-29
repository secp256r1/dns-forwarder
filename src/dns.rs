use anyhow::{Result, bail};

use crate::config::config;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_SOA: u16 = 6;
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

pub enum Response {
    A(Vec<String>),
    Aaaa,
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
                a_records.push(ip);
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

pub fn build_soa_response(query: &[u8]) -> Result<Vec<u8>> {
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

    const MNAME: &[u8] = b"\x02ns\x05local\x00";
    const RNAME: &[u8] = b"\x05admin\x02ns\x05local\x00";
    const SOA_VALUES: &[u8] = &[
        0x78, 0x96, 0xE5, 0x65, // SERIAL  = 2024010101
        0x00, 0x00, 0x0E, 0x10, // REFRESH = 3600
        0x00, 0x00, 0x03, 0x84, // RETRY   = 900
        0x00, 0x01, 0x51, 0x80, // EXPIRE  = 86400
        0x00, 0x00, 0x00, 0x3C, // MINIMUM = 60
    ];

    let soa_rdata_len = MNAME.len() + RNAME.len() + SOA_VALUES.len();
    let soa_rr_len = 2 + 2 + 2 + 4 + 2 + soa_rdata_len;
    let total = 12 + question.len() + soa_rr_len;

    let mut resp = Vec::with_capacity(total);

    resp.extend_from_slice(&query[..2]);

    let rd_bit = query[2] & 0x01;
    resp.push(0x80 | rd_bit);
    resp.push(0x00);

    resp.extend_from_slice(&[0x00, qdcount as u8]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x00]);

    resp.extend_from_slice(question);

    resp.push(0xC0);
    resp.push(0x0C);
    resp.extend_from_slice(&[0x00, DNS_TYPE_SOA as u8]);
    resp.extend_from_slice(&[0x00, DNS_CLASS_IN as u8]);
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
    resp.extend_from_slice(&[(soa_rdata_len >> 8) as u8, soa_rdata_len as u8]);
    resp.extend_from_slice(MNAME);
    resp.extend_from_slice(RNAME);
    resp.extend_from_slice(SOA_VALUES);

    Ok(resp)
}
