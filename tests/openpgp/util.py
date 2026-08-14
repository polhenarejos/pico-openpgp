def skip_tag_if_any(tagh, tagl, data):
    if data == None:
        return None
    if len(data) == 0:
        return b''
    # No tag, return DATA itself
    if tagh == 0x00:
        if tagl != data[0]:
            return data
    else:
        if tagh != data[0]:
            return data
        elif tagl != data[1]:
            raise ValueError(data)
    data_len_b0 = data[1 if tagh==0 else 2]
    if data_len_b0 == 0x81:
        data_len = data[2 if tagh==0 else 3]
    elif data_len_b0 == 0x82:
        data_len = (data[2 if tagh==0 else 3] << 8)| data[3 if tagh==0 else 4]
    else:
        data_len = data_len_b0
    return data[len(data)-data_len:]

def get_data_object(card, tag):
    tagh = tag >> 8
    tagl = tag & 0xff
    result = card.cmd_get_data(tagh, tagl)
    if card.is_yubikey:
        return skip_tag_if_any(tagh, tagl, result)
    else:
        return result

def check_null(data_object):
    return data_object == None or len(data_object) == 0
