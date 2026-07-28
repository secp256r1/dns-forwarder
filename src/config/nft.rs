use anyhow::{Result, anyhow, bail};

const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;

pub fn family_to_nfproto(family: &str) -> Result<u8> {
    match family {
        "ip" => Ok(NFPROTO_IPV4),
        "ip6" => Ok(NFPROTO_IPV6),
        "inet" => Ok(NFPROTO_INET),
        _ => bail!("unsupported nftables family '{family}', expected ip/ip6/inet"),
    }
}

pub(super) async fn fetch_existing_nft_elements(
    family: &str,
    table: &str,
    set: &str,
) -> Result<(Vec<nft_set_elem::nl::Elem>, bool)> {
    use nft_set_elem::nl;

    let family_num = family_to_nfproto(family)?;

    let flags = nl::dump_set_flags(family_num, table, set)
        .await
        .map_err(|e| anyhow!("nft_set_elem dump_set_flags failed: {e}"))?;
    let is_interval = (flags & nl::NFT_SET_INTERVAL) != 0;

    let elems = nl::dump_set_elements(family_num, table, set)
        .await
        .map_err(|e| anyhow!("nft_set_elem dump_set_elements failed: {e}"))?;

    Ok((elems, is_interval))
}
