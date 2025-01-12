use crate::util::*;

pub fn create_icmp_echo_request_message(
    identifire: u16,
    sequence_number: u16,
    data: &Vec<u8>,
) -> Vec<u8> {
    let message_type = vec![8_u8]; // echo request
    let code = vec![0_u8];
    let identifire_vec = identifire.to_be_bytes().to_vec();
    let sequence_number_vec = sequence_number.to_be_bytes().to_vec();

    let header_checksum = checksum16(
        &[
            message_type.clone(),
            code.clone(),
            identifire_vec.clone(),
            sequence_number_vec.clone(),
            data.clone(),
        ]
        .concat(),
        0,
    )
    .to_be_bytes()
    .to_vec();

    return [
        message_type,
        code,
        header_checksum,
        identifire_vec,
        sequence_number_vec,
        data.clone(),
    ]
    .concat();
}

pub fn get_icmp_message_data(message: &Vec<u8>) -> Vec<u8> {
    return message[8..].to_vec();
}
