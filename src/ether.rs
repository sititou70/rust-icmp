use crate::util::*;

pub fn create_ethernet_frame(
    protocol_type: u16,
    dest_hwaddr_str: &str,
    src_hwaddr_str: &str,
    data: &Vec<u8>,
) -> Vec<u8> {
    if data.len() > 1500 {
        panic!("too long data is not supported.");
    }

    let dest_hwaddr = parse_hwaddr(dest_hwaddr_str);
    let src_hwaddr = parse_hwaddr(src_hwaddr_str);
    let protocol_type = protocol_type.to_be_bytes().to_vec();

    let mut padding: Vec<u8> = vec![];
    if data.len() < 46 {
        padding.resize(46 - data.len(), 0);
    }

    return [
        dest_hwaddr,
        src_hwaddr,
        protocol_type,
        data.clone(),
        padding,
    ]
    .concat();
}

pub fn get_ethernet_frame_data(frame: &Vec<u8>) -> Vec<u8> {
    return frame[14..].to_vec();
}
